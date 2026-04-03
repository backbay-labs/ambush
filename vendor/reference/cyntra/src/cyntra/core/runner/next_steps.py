from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class NextStepsCandidate:
    """A single candidate list of next steps for a failing gate."""

    gate: str
    source: str
    steps: list[str]


@dataclass(frozen=True)
class NextStepsBundle:
    """Merged next-step suggestions for a verification failure."""

    gate_failures: list[str]
    candidates: list[NextStepsCandidate]
    merged_steps: list[str]


def _normalize_step(step: str) -> str:
    return " ".join(str(step or "").strip().split()).casefold()


def _extract_debug_specialist_by_gate(gates: dict[str, Any]) -> dict[str, list[str]]:
    """
    Extract per-gate suggestions from debug-specialist hook output (if present).

    Expected shapes:
    - gates["debug_analysis"] = {"debug-specialist": {"diagnostics": [...]}}
    - gates["debug_analysis"] = {"debug-specialist": {"output": {...}, "recommendations": [...]}}
    """
    debug_analysis = gates.get("debug_analysis")
    if not isinstance(debug_analysis, dict):
        return {}

    debug_specialist = debug_analysis.get("debug-specialist")
    if not isinstance(debug_specialist, dict):
        return {}

    output = debug_specialist.get("output") if "output" in debug_specialist else debug_specialist
    if not isinstance(output, dict):
        return {}

    diagnostics = output.get("diagnostics")
    if not isinstance(diagnostics, list):
        return {}

    by_gate: dict[str, list[str]] = {}
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict):
            continue
        gate_name = diagnostic.get("gate")
        if not isinstance(gate_name, str) or not gate_name.strip():
            continue
        suggestions = diagnostic.get("suggestions")
        if not isinstance(suggestions, list):
            continue
        normalized: list[str] = []
        for suggestion in suggestions:
            if isinstance(suggestion, str) and suggestion.strip():
                normalized.append(suggestion.strip())
        if normalized:
            by_gate[gate_name] = normalized
    return by_gate


def _extract_gate_next_actions(gate_result: dict[str, Any]) -> list[str]:
    next_actions = gate_result.get("next_actions")
    if not isinstance(next_actions, list):
        return []

    steps: list[str] = []
    for action in next_actions:
        if not isinstance(action, dict):
            continue
        instructions = str(action.get("instructions") or "").strip()
        if not instructions:
            continue
        fail_code = str(action.get("fail_code") or "").strip()
        priority = action.get("priority")
        priority_str = f"P{int(priority)}" if isinstance(priority, int) else None

        if fail_code and priority_str:
            steps.append(f"[{priority_str}] `{fail_code}`: {instructions}")
        elif fail_code:
            steps.append(f"`{fail_code}`: {instructions}")
        elif priority_str:
            steps.append(f"[{priority_str}] {instructions}")
        else:
            steps.append(instructions)

    return steps


def _heuristic_steps_for_gate(gate_name: str) -> list[str]:
    """
    Provide a cheap, deterministic baseline set of steps for common gates.

    This is intentionally generic: it should help a next attempt even without
    LLM-based diagnostics.
    """
    gate = gate_name.strip().lower()
    if gate in {"test", "pytest"}:
        return [
            "Open `logs/test.log` and identify the first failing test and traceback.",
            "Fix the failing code path; add/adjust a regression test if needed.",
            "Re-run the test gate locally to confirm it passes.",
        ]
    if gate in {"typecheck", "mypy"}:
        return [
            "Open `logs/typecheck.log` and fix the first type error reported.",
            "Prefer tightening types over `Any`; add explicit annotations where needed.",
            "Re-run the typecheck gate locally to confirm it passes.",
        ]
    if gate in {"lint", "ruff"}:
        return [
            "Open `logs/lint.log` and fix the first lint violation.",
            "If appropriate, run ruff with auto-fix and then re-check.",
            "Re-run the lint gate locally to confirm it passes.",
        ]
    if gate in {"forbidden-paths"}:
        return [
            "Revert edits in forbidden paths; move changes into allowed files.",
            "Re-run verification to confirm forbidden-path checks pass.",
        ]
    if gate.startswith("fab-"):
        return [
            "Review the fab gate report/artifacts and address the top failing criteria.",
            "Re-run the fab gate(s) to confirm the asset passes.",
        ]
    if gate.startswith("psn-"):
        return [
            "Inspect the PSN gate output in `logs/` and address the reported failures.",
            "Re-run the PSN gate to confirm it passes.",
        ]

    return [
        f"Open `logs/{gate_name}.log` and identify the first failure.",
        f"Fix the issue and re-run the `{gate_name}` gate locally.",
    ]


def generate_next_steps_bundle(
    verification: dict[str, Any],
    *,
    candidates_per_gate: int,
    max_steps: int,
) -> NextStepsBundle:
    gates = verification.get("gates")
    gates = gates if isinstance(gates, dict) else {}

    blocking_failures = verification.get("blocking_failures")
    failures = [str(x) for x in blocking_failures] if isinstance(blocking_failures, list) else []
    failures = [x for x in failures if x.strip()]

    debug_by_gate = _extract_debug_specialist_by_gate(gates)

    candidates: list[NextStepsCandidate] = []
    for gate_name in failures:
        if not gate_name:
            continue
        gate_result = gates.get(gate_name)
        gate_result = gate_result if isinstance(gate_result, dict) else {}

        per_gate: list[NextStepsCandidate] = []

        next_actions_steps = _extract_gate_next_actions(gate_result)
        if next_actions_steps:
            per_gate.append(
                NextStepsCandidate(gate=gate_name, source="gate_next_actions", steps=next_actions_steps)
            )

        debug_steps = debug_by_gate.get(gate_name) or []
        if debug_steps:
            per_gate.append(
                NextStepsCandidate(gate=gate_name, source="debug_specialist", steps=debug_steps)
            )

        heuristic_steps = _heuristic_steps_for_gate(gate_name)
        if heuristic_steps:
            per_gate.append(
                NextStepsCandidate(gate=gate_name, source="heuristic", steps=heuristic_steps)
            )

        candidates.extend(per_gate[: max(0, int(candidates_per_gate))])

    merged: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        for step in candidate.steps:
            norm = _normalize_step(step)
            if not norm or norm in seen:
                continue
            seen.add(norm)
            merged.append(step.strip())
            if len(merged) >= int(max_steps):
                break
        if len(merged) >= int(max_steps):
            break

    return NextStepsBundle(
        gate_failures=failures,
        candidates=candidates,
        merged_steps=merged,
    )


def render_next_steps_markdown(bundle: NextStepsBundle, *, attempt: int) -> str:
    """
    Render a markdown block suitable for appending to an issue description.
    """
    lines: list[str] = []
    lines.append(f"## Kernel Next Steps (Attempt {attempt})")
    if bundle.gate_failures:
        failures = ", ".join(bundle.gate_failures)
        lines.append(f"Gate failures: `{failures}`")
    lines.append("")

    if bundle.merged_steps:
        lines.append("### Merged Plan")
        for step in bundle.merged_steps:
            lines.append(f"- [ ] {step}")
        lines.append("")

    if bundle.candidates:
        lines.append("### Candidate Ideas (per gate)")
        current_gate: str | None = None
        for candidate in bundle.candidates:
            if candidate.gate != current_gate:
                current_gate = candidate.gate
                lines.append(f"#### {current_gate}")
            lines.append(f"- Source: `{candidate.source}`")
            for step in candidate.steps[:12]:
                lines.append(f"  - {step}")
        lines.append("")

    return "\n".join(lines).strip()
