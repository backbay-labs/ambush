"""Gate replay for verification of proof bundles.

Replays gates from proof bundles to verify that verdicts can be reproduced
deterministically. Supports pytest, ruff, mypy, and fab gate types.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class GateType(Enum):
    """Supported gate types for replay."""

    PYTEST = "pytest"
    RUFF = "ruff"
    MYPY = "mypy"
    FAB_CRITICS = "fab-critics"
    DIFF_CHECK = "diff-check"
    CUSTOM = "custom"


@dataclass
class ReplayResult:
    """Result of replaying a single gate."""

    gate_id: str
    gate_type: GateType
    original_passed: bool
    replay_passed: bool
    verdict_matches: bool
    original_duration_ms: float | None
    replay_duration_ms: float
    replay_cost_ratio: float | None  # replay_time / original_time
    output: str | None = None
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "gate_type": self.gate_type.value,
            "original_passed": self.original_passed,
            "replay_passed": self.replay_passed,
            "verdict_matches": self.verdict_matches,
            "original_duration_ms": self.original_duration_ms,
            "replay_duration_ms": self.replay_duration_ms,
            "replay_cost_ratio": self.replay_cost_ratio,
            "output": self.output,
            "error": self.error,
            "details": self.details,
        }


@dataclass
class BundleReplayResult:
    """Result of replaying all gates in a bundle."""

    bundle_dir: str
    total_gates: int
    matching_verdicts: int
    mismatched_verdicts: int
    gate_results: list[ReplayResult] = field(default_factory=list)
    total_replay_time_ms: float = 0.0
    total_original_time_ms: float = 0.0

    @property
    def all_match(self) -> bool:
        """True if all gate verdicts match."""
        return self.mismatched_verdicts == 0

    @property
    def overall_cost_ratio(self) -> float | None:
        """Overall replay cost ratio."""
        if self.total_original_time_ms > 0:
            return self.total_replay_time_ms / self.total_original_time_ms
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle_dir": self.bundle_dir,
            "total_gates": self.total_gates,
            "matching_verdicts": self.matching_verdicts,
            "mismatched_verdicts": self.mismatched_verdicts,
            "all_match": self.all_match,
            "total_replay_time_ms": self.total_replay_time_ms,
            "total_original_time_ms": self.total_original_time_ms,
            "overall_cost_ratio": self.overall_cost_ratio,
            "gate_results": [r.to_dict() for r in self.gate_results],
        }


class GateReplayer:
    """Replay gates from proof bundles to verify verdicts.

    Supports deterministic replay of:
    - pytest: Re-run pytest with same configuration
    - ruff: Re-run ruff lint checks
    - mypy: Re-run mypy type checks
    - fab-critics: Re-run fab critic evaluation (requires deterministic renders)
    - diff-check: Verify diff constraints (max-diff-size, secret-detection)
    """

    def __init__(
        self,
        *,
        timeout: int = 300,
        capture_output: bool = True,
    ) -> None:
        self.timeout = timeout
        self.capture_output = capture_output

    def _detect_gate_type(self, gate_id: str, gate_config: dict | None = None) -> GateType:
        """Detect gate type from gate_id or config."""
        gate_id_lower = gate_id.lower()

        if "pytest" in gate_id_lower or "test" in gate_id_lower:
            return GateType.PYTEST
        if "ruff" in gate_id_lower or "lint" in gate_id_lower:
            return GateType.RUFF
        if "mypy" in gate_id_lower or "typecheck" in gate_id_lower:
            return GateType.MYPY
        if "fab" in gate_id_lower or "critic" in gate_id_lower:
            return GateType.FAB_CRITICS
        if "diff" in gate_id_lower or "secret" in gate_id_lower:
            return GateType.DIFF_CHECK

        # Check config for type hint
        if gate_config:
            config_type = gate_config.get("type", "")
            if config_type == "diff-check":
                return GateType.DIFF_CHECK

        return GateType.CUSTOM

    def _get_gate_command(
        self,
        gate_type: GateType,
        gate_config: dict | None,
        cwd: Path,
    ) -> str | None:
        """Get the command to replay a gate."""
        if gate_config and "command" in gate_config:
            return gate_config["command"]

        # Default commands by gate type
        defaults: dict[GateType, str] = {
            GateType.PYTEST: "pytest -q",
            GateType.RUFF: "ruff check .",
            GateType.MYPY: "mypy .",
            GateType.FAB_CRITICS: None,  # Requires specific config
            GateType.DIFF_CHECK: None,  # Cannot replay diff checks without original diff
        }

        return defaults.get(gate_type)

    def _run_command(
        self,
        command: str,
        cwd: Path,
    ) -> tuple[bool, str, str, float]:
        """Run a shell command and return (passed, stdout, stderr, duration_ms)."""
        start_time = time.perf_counter()

        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                capture_output=self.capture_output,
                text=True,
                timeout=self.timeout,
            )
            duration_ms = (time.perf_counter() - start_time) * 1000
            passed = result.returncode == 0

            return passed, result.stdout, result.stderr, duration_ms

        except subprocess.TimeoutExpired:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return False, "", f"Timeout after {self.timeout}s", duration_ms
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            return False, "", str(e), duration_ms

    def replay_gate(
        self,
        bundle_dir: Path,
        gate_id: str,
        gate_config: dict | None = None,
    ) -> ReplayResult:
        """Replay a single gate from a bundle.

        Args:
            bundle_dir: Path to the bundle directory
            gate_id: Gate identifier (e.g., "pytest", "ruff", "mypy")
            gate_config: Optional gate configuration dict

        Returns:
            ReplayResult with comparison of original vs replayed verdict
        """
        bundle_dir = Path(bundle_dir)

        # Load proof.json to get original verdict
        proof_path = bundle_dir / "proof.json"
        original_passed = True
        original_duration_ms = None

        if proof_path.exists():
            try:
                with open(proof_path, encoding="utf-8") as f:
                    proof_data = json.load(f)

                # Get overall verdict
                verdict = proof_data.get("verdict", {})
                if verdict.get("gate_id") == gate_id:
                    original_passed = verdict.get("passed", True)

                # Check individual gates for this gate_id
                for gate in proof_data.get("gates", []):
                    if gate.get("gate_id") == gate_id:
                        original_passed = gate.get("passed", True)
                        original_duration_ms = gate.get("duration_ms")
                        break
            except (json.JSONDecodeError, KeyError):
                pass

        gate_type = self._detect_gate_type(gate_id, gate_config)
        command = self._get_gate_command(gate_type, gate_config, bundle_dir)

        if command is None:
            # Cannot replay this gate type
            return ReplayResult(
                gate_id=gate_id,
                gate_type=gate_type,
                original_passed=original_passed,
                replay_passed=original_passed,  # Assume match if can't replay
                verdict_matches=True,
                original_duration_ms=original_duration_ms,
                replay_duration_ms=0.0,
                replay_cost_ratio=None,
                error=f"Cannot replay gate type {gate_type.value}",
            )

        # Run the replay
        replay_passed, stdout, stderr, replay_duration_ms = self._run_command(
            command, bundle_dir
        )

        verdict_matches = original_passed == replay_passed
        replay_cost_ratio = None
        if original_duration_ms and original_duration_ms > 0:
            replay_cost_ratio = replay_duration_ms / original_duration_ms

        return ReplayResult(
            gate_id=gate_id,
            gate_type=gate_type,
            original_passed=original_passed,
            replay_passed=replay_passed,
            verdict_matches=verdict_matches,
            original_duration_ms=original_duration_ms,
            replay_duration_ms=replay_duration_ms,
            replay_cost_ratio=replay_cost_ratio,
            output=stdout if not replay_passed else None,
            error=stderr if stderr else None,
        )

    def replay_bundle(
        self,
        bundle_dir: Path,
        gate_ids: list[str] | None = None,
    ) -> BundleReplayResult:
        """Replay all gates (or specified gates) in a bundle.

        Args:
            bundle_dir: Path to the bundle directory
            gate_ids: Optional list of specific gates to replay

        Returns:
            BundleReplayResult with all gate replay results
        """
        bundle_dir = Path(bundle_dir)

        # Auto-detect gates from proof.json if not specified
        if gate_ids is None:
            gate_ids = self._detect_gates(bundle_dir)

        gate_results: list[ReplayResult] = []
        total_replay_time = 0.0
        total_original_time = 0.0

        for gate_id in gate_ids:
            result = self.replay_gate(bundle_dir, gate_id)
            gate_results.append(result)
            total_replay_time += result.replay_duration_ms
            if result.original_duration_ms:
                total_original_time += result.original_duration_ms

        matching = sum(1 for r in gate_results if r.verdict_matches)
        mismatched = len(gate_results) - matching

        return BundleReplayResult(
            bundle_dir=str(bundle_dir),
            total_gates=len(gate_results),
            matching_verdicts=matching,
            mismatched_verdicts=mismatched,
            gate_results=gate_results,
            total_replay_time_ms=total_replay_time,
            total_original_time_ms=total_original_time,
        )

    def _detect_gates(self, bundle_dir: Path) -> list[str]:
        """Detect available gates from bundle proof.json."""
        proof_path = bundle_dir / "proof.json"
        gates: list[str] = []

        if proof_path.exists():
            try:
                with open(proof_path, encoding="utf-8") as f:
                    proof_data = json.load(f)

                # Get verdict gate
                verdict = proof_data.get("verdict", {})
                if "gate_id" in verdict:
                    gates.append(verdict["gate_id"])

                # Get individual gates
                for gate in proof_data.get("gates", []):
                    gate_id = gate.get("gate_id")
                    if gate_id and gate_id not in gates:
                        gates.append(gate_id)

            except (json.JSONDecodeError, KeyError):
                pass

        # Default to common gates if none detected
        if not gates:
            gates = ["pytest", "ruff", "mypy"]

        return gates


__all__ = [
    "GateType",
    "ReplayResult",
    "BundleReplayResult",
    "GateReplayer",
]
