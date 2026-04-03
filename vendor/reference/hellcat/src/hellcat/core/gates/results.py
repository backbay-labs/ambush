"""
Gate result normalization and summaries.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hellcat.core.gates.runner import GateConfig, GateResult
from hellcat.infra.observability.events import EventEmitter


def _coerce_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return default


def default_blocking_for_gate_type(gate_type: str) -> bool:
    normalized = (gate_type or "code").strip().lower()
    return normalized not in {"llm-eval", "llm_eval", "llm", "informational"}


def normalize_gate_result(
    *,
    name: str,
    result: Any,
    gate_type: str,
    cached: bool = False,
    blocking_default: bool | None = None,
) -> dict[str, Any]:
    """Normalize gate result into a shared schema."""
    if isinstance(result, GateConfig):
        result = {
            "passed": False,
            "reason": "invalid_gate_result",
            "error": "GateConfig is not a result",
            "duration_ms": 0,
        }

    if isinstance(result, GateResult):
        base: dict[str, Any] = {
            "passed": result.passed,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "output_path": result.output_path,
            "failure_summary": result.failure_summary,
            "attempt": result.attempt,
            "flaky_detected": result.flaky_detected,
        }
    elif isinstance(result, dict):
        base = dict(result)
    else:
        base = {
            "passed": False,
            "reason": "invalid_gate_result",
            "error": str(result),
            "duration_ms": 0,
        }

    passed = bool(base.get("passed", False))
    skipped = bool(base.get("skipped", False))
    blocking_default = (
        default_blocking_for_gate_type(gate_type)
        if blocking_default is None
        else blocking_default
    )
    blocking = _coerce_bool(base.get("blocking"), blocking_default)
    duration_ms = int(base.get("duration_ms") or 0)
    attempt = int(base.get("attempt") or 1)
    flaky = bool(base.get("flaky_detected", False))
    output_path = base.get("output_path") or base.get("log_path")
    log_paths = base.get("log_paths")
    if isinstance(log_paths, str) and log_paths:
        log_paths = [log_paths]
    if not isinstance(log_paths, list):
        log_paths = [output_path] if output_path else []

    failure_summary = base.get("failure_summary")
    if not failure_summary and not passed:
        failure_summary = base.get("error") or base.get("reason") or base.get("stderr")

    normalized: dict[str, Any] = {
        "passed": passed,
        "skipped": skipped,
        "reason": base.get("reason"),
        "exit_code": base.get("exit_code"),
        "duration_ms": duration_ms,
        "output_path": output_path,
        "log_paths": log_paths,
        "failure_summary": failure_summary,
        "attempt": attempt,
        "flaky_detected": flaky,
        "cached": cached,
        "gate_type": gate_type,
        "blocking": blocking,
    }

    known_keys = {
        "passed",
        "skipped",
        "reason",
        "exit_code",
        "duration_ms",
        "output_path",
        "log_path",
        "log_paths",
        "failure_summary",
        "attempt",
        "flaky_detected",
        "cached",
        "gate_type",
        "blocking",
    }
    for key, value in base.items():
        if key in known_keys:
            continue
        if key not in normalized:
            normalized[key] = value

    normalized["gate"] = name
    return normalized


def summarize_gate_results(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "blocking_failed": 0,
        "informational_failed": 0,
        "flaky_detected": 0,
        "duration_ms": 0,
        "by_type": {},
        "failed_blocking": [],
        "failed_informational": [],
    }

    for name, result in results.items():
        if not isinstance(result, dict):
            continue
        gate_type = str(result.get("gate_type") or "code")
        passed = bool(result.get("passed"))
        skipped = bool(result.get("skipped"))
        blocking = _coerce_bool(
            result.get("blocking"),
            default_blocking_for_gate_type(gate_type),
        )
        duration_ms = int(result.get("duration_ms") or 0)

        summary["total"] += 1
        summary["duration_ms"] += duration_ms
        if skipped:
            summary["skipped"] += 1
        elif passed:
            summary["passed"] += 1
        else:
            summary["failed"] += 1
            if blocking:
                summary["blocking_failed"] += 1
                summary["failed_blocking"].append(name)
            else:
                summary["informational_failed"] += 1
                summary["failed_informational"].append(name)

        if result.get("flaky_detected"):
            summary["flaky_detected"] += 1

        by_type = summary["by_type"].setdefault(
            gate_type,
            {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "blocking_failed": 0,
                "duration_ms": 0,
            },
        )
        by_type["total"] += 1
        by_type["duration_ms"] += duration_ms
        if skipped:
            by_type["skipped"] += 1
        elif passed:
            by_type["passed"] += 1
        else:
            by_type["failed"] += 1
            if blocking:
                by_type["blocking_failed"] += 1

    return summary


def build_verification_payload(results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    blocking_failures = [
        name
        for name, result in results.items()
        if isinstance(result, dict)
        and not result.get("passed")
        and _coerce_bool(
            result.get("blocking"),
            default_blocking_for_gate_type(str(result.get("gate_type") or "code")),
        )
    ]
    summary = summarize_gate_results(results)
    return {
        "gates": results,
        "blocking_failures": blocking_failures,
        "all_passed": len(blocking_failures) == 0,
        "gate_summary": summary,
    }


def resolve_logs_dir(work_dir: Path | str | None) -> Path | None:
    if work_dir is None:
        return None
    candidate = Path(work_dir)
    for parent in [candidate, *candidate.parents]:
        logs_dir = parent / ".hellcat" / "logs"
        if logs_dir.exists():
            return logs_dir
    return candidate / ".hellcat" / "logs"


def emit_gates_event(
    *,
    logs_dir: Path | None,
    workcell_id: str,
    passed: bool,
    results: dict[str, Any],
    summary: dict[str, Any] | None = None,
) -> None:
    if logs_dir is None or not workcell_id:
        return
    emitter = EventEmitter(logs_dir)
    emitter.gates_result(workcell_id=workcell_id, passed=passed, results=results, summary=summary)
