from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyntra.core.scheduler.routing import KernelConfig
from cyntra.cognition.planner.action_space import NA, ActionSpace, BudgetBin, is_valid_action
from cyntra.cognition.planner.artifacts import (
    build_executed_plan_v1,
    build_planner_action_v1,
    build_planner_input_v1,
)


def _as_bin(value: Any) -> BudgetBin:
    if value == NA:
        return NA
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str) and value.strip().upper() == "NA":
        return NA
    return NA


def _extract_predicted_tuple(
    action: dict[str, Any],
) -> tuple[str, BudgetBin, BudgetBin, BudgetBin] | None:
    swarm_id = action.get("swarm_id")
    if not isinstance(swarm_id, str) or not swarm_id:
        return None
    budgets = action.get("budgets")
    budgets = budgets if isinstance(budgets, dict) else {}
    return (
        swarm_id,
        _as_bin(budgets.get("max_candidates_bin")),
        _as_bin(budgets.get("max_minutes_bin")),
        _as_bin(budgets.get("max_iterations_bin")),
    )


def _mode(value: str) -> str:
    value = str(value or "").strip().lower()
    return value if value in {"off", "log", "enforce"} else "off"


@dataclass(frozen=True)
class PlannerSelection:
    """
    Global planning decision for a single kernel issue dispatch.

    `planner_action` always exists (either predicted or a synthetic abstain record).
    """

    planner_input: dict[str, Any]
    planner_action: dict[str, Any]
    max_candidates_executed: int
    timeout_seconds_override: int | None
    fallback_applied: bool
    fallback_reason: str | None


class KernelPlannerIntegration:
    """
    Kernel-level planner integration.

    - Loads an ONNX bundle when configured.
    - Runs inference (optional) and produces a manifest-ready `planner` section.
    - Enforces only when safe and enabled; otherwise falls back deterministically.
    """

    def __init__(self, config: KernelConfig) -> None:
        self.config = config
        self.mode = _mode(getattr(config.planner, "mode", "off"))
        self.bundle_dir = getattr(config.planner, "bundle_dir", None)
        self.conf_threshold = float(getattr(config.planner, "confidence_threshold", 0.2) or 0.0)

        self._planner: Any | None = None
        self._planner_error: str | None = None

    def _load_planner(self) -> Any | None:
        if self._planner is not None or self._planner_error is not None:
            return self._planner

        if self.bundle_dir is None:
            self._planner_error = "bundle_dir_missing"
            return None

        bundle_dir = Path(self.bundle_dir).resolve()
        if not bundle_dir.exists():
            self._planner_error = f"bundle_dir_not_found:{bundle_dir}"
            return None

        try:
            from cyntra.cognition.planner.inference import OnnxPlanner
        except Exception as exc:
            self._planner_error = f"onnx_import_failed:{exc}"
            return None

        try:
            self._planner = OnnxPlanner(bundle_dir)
            return self._planner
        except Exception as exc:
            self._planner_error = f"bundle_load_failed:{exc}"
            return None

    def _predict_action(
        self, planner_input: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str | None]:
        if self.mode == "off":
            return None, "planner_off"

        planner = self._load_planner()
        if planner is None:
            return None, self._planner_error or "planner_unavailable"

        try:
            action = planner.predict_action(planner_input)
        except Exception as exc:
            return None, f"inference_failed:{exc}"

        if isinstance(action, dict):
            return action, None
        return None, "invalid_action_type"

    def decide(
        self,
        *,
        issue: Any,
        job_type: str,
        universe_id: str,
        universe_defaults: dict[str, Any],
        action_space: ActionSpace,
        history_candidates: list[dict[str, Any]],
        system_state: dict[str, Any] | None,
        now_ms: int,
        baseline_swarm_id: str,
        baseline_max_candidates: int,
        baseline_timeout_cap_seconds: int,
        max_iterations: int | None,
    ) -> PlannerSelection:
        planner_input = build_planner_input_v1(
            issue=issue,
            job_type=job_type,
            universe_id=universe_id,
            universe_defaults=universe_defaults,
            action_space=action_space,
            history_candidates=history_candidates,
            system_state=system_state,
            now_ms=now_ms,
        )

        # Baseline heuristic action (used when planner is off).
        baseline_action = build_planner_action_v1(
            swarm_id=baseline_swarm_id,
            max_candidates=int(baseline_max_candidates),
            max_minutes=int(baseline_timeout_cap_seconds / 60),
            max_iterations=max_iterations,
            action_space=action_space,
            planner_input=planner_input,
            now_ms=now_ms,
            checkpoint_id="baseline_heuristic_v0",
        )

        if self.mode == "off":
            return PlannerSelection(
                planner_input=planner_input,
                planner_action=baseline_action,
                max_candidates_executed=int(baseline_max_candidates),
                timeout_seconds_override=None,
                fallback_applied=False,
                fallback_reason=None,
            )

        predicted, pred_error = self._predict_action(planner_input)
        if predicted is None:
            planner_action = dict(baseline_action)
            planner_action["confidence"] = 0.0
            planner_action["abstain_to_default"] = True
            planner_action["reason"] = pred_error or "inference_failed"
            planner_action["model"] = {"checkpoint_id": "unavailable"}

            return PlannerSelection(
                planner_input=planner_input,
                planner_action=planner_action,
                max_candidates_executed=int(baseline_max_candidates),
                timeout_seconds_override=None,
                fallback_applied=True,
                fallback_reason=pred_error or "inference_failed",
            )

        predicted_tuple = _extract_predicted_tuple(predicted)
        confidence_raw = predicted.get("confidence")
        confidence = float(confidence_raw) if isinstance(confidence_raw, (int, float)) else 0.0

        fallback_applied = False
        fallback_reason: str | None = None
        timeout_override: int | None = None
        max_candidates_executed = int(baseline_max_candidates)

        if self.mode == "log":
            fallback_applied = True
            fallback_reason = "log_only"
        elif confidence < self.conf_threshold:
            fallback_applied = True
            fallback_reason = "low_confidence"
        elif predicted_tuple is None:
            fallback_applied = True
            fallback_reason = "malformed_prediction"
        else:
            swarm_id, max_candidates_bin, max_minutes_bin, max_iterations_bin = predicted_tuple
            if (
                swarm_id not in action_space.swarm_ids
                or max_candidates_bin not in action_space.max_candidates_bins
                or max_minutes_bin not in action_space.max_minutes_bins
                or max_iterations_bin not in action_space.max_iterations_bins
            ):
                fallback_applied = True
                fallback_reason = "prediction_out_of_space"
            elif not is_valid_action(
                job_type=job_type,
                swarm_id=swarm_id,
                max_candidates_bin=max_candidates_bin,
                max_minutes_bin=max_minutes_bin,
                max_iterations_bin=max_iterations_bin,
            ):
                fallback_applied = True
                fallback_reason = "prediction_invalid"
            elif swarm_id != baseline_swarm_id:
                fallback_applied = True
                fallback_reason = "swarm_mismatch"
            else:
                # Enforce only reductions (never exceed baseline caps).
                if isinstance(max_candidates_bin, int):
                    if int(max_candidates_bin) > int(baseline_max_candidates):
                        fallback_applied = True
                        fallback_reason = "max_candidates_exceeds_cap"
                    else:
                        max_candidates_executed = int(max_candidates_bin)

                if not fallback_applied and isinstance(max_minutes_bin, int):
                    requested = int(max_minutes_bin) * 60
                    if requested > int(baseline_timeout_cap_seconds):
                        fallback_applied = True
                        fallback_reason = "timeout_exceeds_cap"
                    else:
                        timeout_override = requested

        planner_action = dict(predicted)
        if fallback_applied:
            planner_action["abstain_to_default"] = True
            planner_action["reason"] = fallback_reason
        else:
            planner_action["abstain_to_default"] = False
            planner_action["reason"] = None

        return PlannerSelection(
            planner_input=planner_input,
            planner_action=planner_action,
            max_candidates_executed=max_candidates_executed,
            timeout_seconds_override=timeout_override,
            fallback_applied=fallback_applied,
            fallback_reason=fallback_reason,
        )

    def build_manifest_planner_bundle(
        self,
        *,
        selection: PlannerSelection,
        swarm_id_executed: str,
        timeout_seconds_default: int,
        max_iterations_executed: int | None,
    ) -> dict[str, Any]:
        timeout_seconds = (
            int(selection.timeout_seconds_override)
            if isinstance(selection.timeout_seconds_override, int)
            else int(timeout_seconds_default)
        )

        executed_plan = build_executed_plan_v1(
            swarm_id=swarm_id_executed,
            max_candidates=int(selection.max_candidates_executed),
            timeout_seconds=timeout_seconds,
            max_iterations=max_iterations_executed,
            fallback_applied=bool(selection.fallback_applied),
            fallback_reason=selection.fallback_reason,
        )

        return {
            "planner_input": selection.planner_input,
            "planner_action": selection.planner_action,
            "executed_plan": executed_plan,
            "timeout_seconds_override": selection.timeout_seconds_override,
        }
