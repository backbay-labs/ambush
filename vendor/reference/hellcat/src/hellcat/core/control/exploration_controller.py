"""
Exploration controller based on dynamics reports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

from hellcat.core.scheduler.routing import KernelConfig

logger = structlog.get_logger()


@dataclass(frozen=True)
class ControlDecision:
    mode: str
    action_rate: float | None
    temperature: float | None
    top_p: float | None
    speculate_parallelism: int | None
    priority_rank: int
    reason: str


class ExplorationController:
    def __init__(self, config: KernelConfig) -> None:
        self.config = config
        self._report = self._load_report()

    def _load_report(self) -> dict[str, Any] | None:
        kernel_dir = getattr(self.config, "kernel_dir", None)
        if not isinstance(kernel_dir, Path):
            return None
        report_path = kernel_dir / "dynamics" / "dynamics_report.json"
        if not report_path.exists():
            return None
        try:
            raw = report_path.read_text()
            if not isinstance(raw, str):
                return None
            return json.loads(raw)
        except (OSError, TypeError, json.JSONDecodeError) as exc:
            logger.warning("Failed to parse dynamics report", error=str(exc))
            return None

    def _domain_for_issue(self, tags: list[str]) -> str:
        if "asset:world" in tags:
            return "fab_world"
        if any(t.startswith("asset:") for t in tags):
            return "fab_asset"
        return "code"

    def _action_rate_for_domain(self, domain: str) -> float | None:
        if not self._report:
            return None
        summary = self._report.get("action_summary") or {}
        by_domain = summary.get("by_domain") or {}
        if domain in by_domain:
            return float(by_domain.get(domain))
        global_rate = summary.get("global_action_rate")
        if global_rate is None:
            return None
        return float(global_rate)

    def _get_trap_state_ids(self) -> set[str]:
        if not self._report:
            return set()
        return set(self._report.get("trap_state_ids") or [])

    def _get_controller_recommendations(self) -> dict[str, Any]:
        if not self._report:
            return {}
        return self._report.get("controller_recommendations") or {}

    @property
    def trap_count(self) -> int:
        return len(self._get_trap_state_ids())

    @property
    def recommended_mode(self) -> str:
        recs = self._get_controller_recommendations()
        return recs.get("mode", "balanced")

    def decide(self, issue: Any) -> ControlDecision:
        tags = issue.tags or []
        domain = self._domain_for_issue(tags)
        action_rate = self._action_rate_for_domain(domain)

        if not self.config.control.enabled or action_rate is None:
            return ControlDecision(
                mode="disabled",
                action_rate=action_rate,
                temperature=None,
                top_p=None,
                speculate_parallelism=None,
                priority_rank=0,
                reason="no_dynamics_report",
            )

        low = self.config.control.action_low
        high = self.config.control.action_high
        default_parallelism = self.config.speculation.default_parallelism
        temperature = self.config.control.temperature_base

        # Check for active traps - override normal action-rate logic
        trap_state_ids = self._get_trap_state_ids()
        recommendations = self._get_controller_recommendations()
        if trap_state_ids and recommendations.get("mode") == "explore":
            temp_adj = recommendations.get("temperature_adjustment", 0.1)
            para_boost = recommendations.get("parallelism_boost", 1)
            new_temp = min(
                self.config.control.temperature_max,
                temperature + temp_adj,
            )
            new_parallelism = min(
                self.config.speculation.max_parallelism,
                default_parallelism + para_boost,
            )
            logger.info(
                "Exploration controller forcing explore mode due to traps",
                trap_count=len(trap_state_ids),
                temperature=new_temp,
                parallelism=new_parallelism,
            )
            return ControlDecision(
                mode="trap_explore",
                action_rate=action_rate,
                temperature=new_temp,
                top_p=None,
                speculate_parallelism=new_parallelism,
                priority_rank=-2,
                reason=f"active_traps={len(trap_state_ids)}",
            )

        if action_rate < low:
            new_parallelism = min(
                self.config.speculation.max_parallelism,
                default_parallelism + self.config.control.parallelism_step,
            )
            new_temp = min(
                self.config.control.temperature_max,
                temperature + self.config.control.temperature_step,
            )
            return ControlDecision(
                mode="trap",
                action_rate=action_rate,
                temperature=new_temp,
                top_p=None,
                speculate_parallelism=new_parallelism,
                priority_rank=-1,
                reason="action_below_low",
            )

        if action_rate > high:
            new_parallelism = max(
                1,
                default_parallelism - self.config.control.parallelism_step,
            )
            new_temp = max(
                self.config.control.temperature_min,
                temperature - self.config.control.temperature_step,
            )
            return ControlDecision(
                mode="chaos",
                action_rate=action_rate,
                temperature=new_temp,
                top_p=None,
                speculate_parallelism=new_parallelism,
                priority_rank=1,
                reason="action_above_high",
            )

        return ControlDecision(
            mode="balanced",
            action_rate=action_rate,
            temperature=temperature,
            top_p=None,
            speculate_parallelism=default_parallelism,
            priority_rank=0,
            reason="action_in_band",
        )

    def speculate_parallelism(self, issue: Any, default: int) -> int:
        decision = self.decide(issue)
        if decision.speculate_parallelism is None:
            return default
        return decision.speculate_parallelism

    def sampling_for_issue(self, issue: Any) -> dict[str, Any] | None:
        decision = self.decide(issue)
        if decision.temperature is None and decision.top_p is None:
            return None
        return {"temperature": decision.temperature, "top_p": decision.top_p}
