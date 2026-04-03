"""
Pre-flight validation for autonomous specs.

Validates that specs have all required elements before execution begins.
Catches "built but not wired" issues at the spec level.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml

logger = structlog.get_logger()


@dataclass
class PreFlightResult:
    """Result of pre-flight validation."""

    passed: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class PreFlightChecker:
    """
    Validates autonomous specs before execution begins.

    Checks for:
    - Required outcomes (user-observable goals)
    - Integration workstream (wiring tasks)
    - Explicit integration points (export → target mappings)
    - L3+ acceptance criteria (integration verification)
    """

    def check_spec(self, spec: dict[str, Any]) -> PreFlightResult:
        """Validate a spec dictionary."""
        errors: list[str] = []
        warnings: list[str] = []

        # Check for outcomes
        outcomes = spec.get("outcomes", [])
        if not outcomes:
            errors.append(
                "Missing 'outcomes' - specs must define user-observable goals. "
                "Add outcomes like 'User sees X in Y location'"
            )
        else:
            # Check outcome format
            for outcome in outcomes:
                if not outcome.get("id"):
                    errors.append("Outcome missing 'id' field")
                if not outcome.get("description"):
                    errors.append("Outcome missing 'description' field")
                if not outcome.get("verification"):
                    warnings.append(
                        f"Outcome '{outcome.get('id')}' missing 'verification' method"
                    )

        # Check for workstreams
        workstreams = spec.get("workstreams", [])
        if not workstreams:
            errors.append("Missing 'workstreams' - specs must define work to be done")
        else:
            # Check for integration workstream
            has_integration = any(
                w.get("type") == "integration" for w in workstreams
            )
            if not has_integration:
                errors.append(
                    "Missing integration workstream - specs must include a workstream "
                    "with type='integration' that wires new code into existing code"
                )

            # Check workstream dependencies
            ws_ids = {w.get("id") for w in workstreams}
            for ws in workstreams:
                depends_on = ws.get("depends_on", [])
                for dep in depends_on:
                    if dep not in ws_ids:
                        errors.append(
                            f"Workstream '{ws.get('id')}' depends on unknown "
                            f"workstream '{dep}'"
                        )

        # Check for integration points
        integrations = spec.get("integrations", [])
        if not integrations:
            errors.append(
                "Missing 'integrations' - specs must declare explicit integration "
                "points mapping new exports to their target files"
            )
        else:
            for integration in integrations:
                if not integration.get("new_export"):
                    errors.append("Integration missing 'new_export' field")
                if not integration.get("target_file"):
                    errors.append("Integration missing 'target_file' field")
                if not integration.get("usage"):
                    warnings.append(
                        f"Integration for '{integration.get('new_export')}' "
                        "missing 'usage' description"
                    )

        # Check for acceptance criteria
        acceptance = spec.get("acceptance", {})
        if not acceptance:
            errors.append("Missing 'acceptance' criteria")
        else:
            if not acceptance.get("L3_integrated"):
                errors.append(
                    "Missing L3 (integrated) acceptance criteria - "
                    "specs must define integration verification"
                )
            if not acceptance.get("L4_functional"):
                errors.append(
                    "Missing L4 (functional) acceptance criteria - "
                    "specs must define end-to-end verification"
                )

        # Check for verification
        verification = spec.get("verification", {})
        if not verification:
            warnings.append(
                "Missing 'verification' section - consider adding canary test config"
            )

        return PreFlightResult(
            passed=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )

    def check_file(self, path: Path) -> PreFlightResult:
        """Validate a spec YAML file."""
        try:
            content = yaml.safe_load(path.read_text())
            return self.check_spec(content)
        except yaml.YAMLError as e:
            return PreFlightResult(
                passed=False,
                errors=[f"Invalid YAML: {e}"],
            )
        except Exception as e:
            return PreFlightResult(
                passed=False,
                errors=[f"Failed to read spec: {e}"],
            )


# Escape hatch detection patterns
ESCAPE_HATCH_PATTERNS = [
    (r"(can|could|should|will) be added later", "deferral"),
    (r"out of scope for (this|current|the) (task|pr|change)", "scope-creep"),
    (r"leaving (this )?for (future|follow-up|later)", "deferral"),
    (r"(optional|nice-to-have) for now", "minimization"),
    (r"skipping (this )?(for now|temporarily)", "skip"),
    (r"TODO:.*later", "todo-deferral"),
    (r"not (strictly )?necessary", "minimization"),
    (r"will (address|fix|handle) (this )?later", "deferral"),
    (r"beyond the scope", "scope-creep"),
    (r"can be improved later", "deferral"),
]


@dataclass
class EscapeHatchMatch:
    """A detected escape hatch in agent output."""

    text: str
    pattern_type: str
    context: str


def detect_escape_hatches(text: str) -> list[EscapeHatchMatch]:
    """
    Detect when agent output contains rationalization for skipping work.

    Returns list of matched escape hatch patterns with context.
    """
    matches: list[EscapeHatchMatch] = []

    lines = text.split("\n")
    for i, line in enumerate(lines):
        for pattern, pattern_type in ESCAPE_HATCH_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                # Get surrounding context
                start = max(0, i - 1)
                end = min(len(lines), i + 2)
                context = "\n".join(lines[start:end])

                matches.append(EscapeHatchMatch(
                    text=line.strip(),
                    pattern_type=pattern_type,
                    context=context,
                ))

    return matches


def run_preflight_gate(spec_path: Path) -> PreFlightResult:
    """Run pre-flight validation as a gate."""
    checker = PreFlightChecker()
    result = checker.check_file(spec_path)

    if result.passed:
        logger.info("Pre-flight check passed", spec=str(spec_path))
    else:
        logger.error(
            "Pre-flight check failed",
            spec=str(spec_path),
            errors=result.errors,
        )

    return result
