"""
Quality control: random re-verification with mismatch penalties.

Implements:
- Random sampling of PASS verdicts for re-verification
- Mismatch detection and penalty enforcement
- Anti-correlation constraints for T2+ quorum selection
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from cyntra.trust.protocol.task_protocol import (
    TaskRegistry,
    TaskState,
    Verdict,
    VerificationTask,
)

logger = logging.getLogger(__name__)


class MismatchType(str, Enum):
    """Type of verdict mismatch detected."""

    OUTCOME_MISMATCH = "outcome_mismatch"  # PASS vs FAIL
    HASH_MISMATCH = "hash_mismatch"  # Different receipt/manifest hashes
    GATE_COUNT_MISMATCH = "gate_count_mismatch"  # Different number of gates checked
    GATE_RESULT_MISMATCH = "gate_result_mismatch"  # Same gate, different result
    TRANSCRIPT_MISMATCH = "transcript_mismatch"  # Different replay transcript


@dataclass
class ReVerificationConfig:
    """Quality control configuration."""

    sample_rate: float = 0.05  # 5% of PASS verdicts
    mismatch_penalty_wei: int = 100_000_000_000_000_000  # 0.1 ETH
    anti_correlation_window_hours: int = 168  # 1 week
    min_re_verifiers: int = 2  # For T2+ quorum
    max_verifier_overlap_ratio: float = 0.5  # Flag if >50% same verifiers

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_rate": self.sample_rate,
            "mismatch_penalty_wei": self.mismatch_penalty_wei,
            "anti_correlation_window_hours": self.anti_correlation_window_hours,
            "min_re_verifiers": self.min_re_verifiers,
            "max_verifier_overlap_ratio": self.max_verifier_overlap_ratio,
        }


@dataclass
class QCResult:
    """Result of a QC re-verification."""

    task_id: str
    original_verdict: Verdict
    reverified_verdict: Verdict
    match: bool
    mismatch_type: MismatchType | None = None
    mismatch_details: str | None = None
    penalty_applied: bool = False
    penalty_wei: int = 0
    re_verifier: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "original_verdict": self.original_verdict.to_dict(),
            "reverified_verdict": self.reverified_verdict.to_dict(),
            "match": self.match,
            "mismatch_type": self.mismatch_type.value if self.mismatch_type else None,
            "mismatch_details": self.mismatch_details,
            "penalty_applied": self.penalty_applied,
            "penalty_wei": self.penalty_wei,
            "re_verifier": self.re_verifier,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class QCSelectionResult:
    """Result of QC sample selection."""

    selected_tasks: list[VerificationTask]
    total_eligible: int
    sample_rate: float
    selection_seed: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "selected_task_ids": [t.task_id for t in self.selected_tasks],
            "selected_count": len(self.selected_tasks),
            "total_eligible": self.total_eligible,
            "sample_rate": self.sample_rate,
            "selection_seed": self.selection_seed,
        }


@dataclass
class AntiCorrelationCheck:
    """Result of anti-correlation check for verifier selection."""

    verifier: str
    recent_tasks_with_original: int
    agreement_rate_with_original: float
    is_correlated: bool
    window_hours: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "verifier": self.verifier,
            "recent_tasks_with_original": self.recent_tasks_with_original,
            "agreement_rate_with_original": self.agreement_rate_with_original,
            "is_correlated": self.is_correlated,
            "window_hours": self.window_hours,
        }


class QualityController:
    """
    Random re-verification of PASS verdicts.

    Detects rubber-stamping by re-verifying a random sample of
    PASS verdicts and comparing outcomes. Mismatches trigger
    penalties for the original verifier.
    """

    def __init__(
        self,
        config: ReVerificationConfig | None = None,
        task_registry: TaskRegistry | None = None,
    ) -> None:
        self.config = config or ReVerificationConfig()
        self.task_registry = task_registry or TaskRegistry()
        self._qc_results: list[QCResult] = []
        self._verifier_history: dict[str, list[tuple[str, datetime, bool]]] = {}  # verifier -> [(task_id, time, passed)]

    def select_for_reverification(
        self,
        finalized_tasks: list[VerificationTask] | None = None,
        seed: int | None = None,
    ) -> QCSelectionResult:
        """
        Select random sample of finalized PASS verdicts for QC.

        Uses deterministic selection when seed is provided for reproducibility.
        """
        if finalized_tasks is None:
            # Get all finalized tasks from registry
            finalized_tasks = [
                t
                for t in self.task_registry._tasks.values()
                if t.state == TaskState.FINALIZED and t.verdict and t.verdict.is_pass
            ]

        # Filter to PASS verdicts only
        eligible = [t for t in finalized_tasks if t.verdict and t.verdict.is_pass]

        if not eligible:
            return QCSelectionResult(
                selected_tasks=[],
                total_eligible=0,
                sample_rate=self.config.sample_rate,
                selection_seed=seed or 0,
            )

        # Deterministic selection
        actual_seed = seed if seed is not None else int(datetime.now(UTC).timestamp())
        rng = random.Random(actual_seed)

        sample_size = max(1, int(len(eligible) * self.config.sample_rate))
        selected = rng.sample(eligible, min(sample_size, len(eligible)))

        return QCSelectionResult(
            selected_tasks=selected,
            total_eligible=len(eligible),
            sample_rate=self.config.sample_rate,
            selection_seed=actual_seed,
        )

    def check_for_mismatch(
        self,
        original: Verdict,
        reverified: Verdict,
    ) -> tuple[bool, MismatchType | None, str | None]:
        """
        Detect mismatch between original and re-verified verdicts.

        Returns (is_match, mismatch_type, details).
        """
        # Check outcome mismatch
        if original.outcome != reverified.outcome:
            return (
                False,
                MismatchType.OUTCOME_MISMATCH,
                f"Original: {original.outcome.value}, Re-verified: {reverified.outcome.value}",
            )

        # Check hash verification mismatch
        if original.receipt_hash_verified != reverified.receipt_hash_verified:
            return (
                False,
                MismatchType.HASH_MISMATCH,
                f"Receipt hash: original={original.receipt_hash_verified}, reverified={reverified.receipt_hash_verified}",
            )

        if original.manifest_hash_verified != reverified.manifest_hash_verified:
            return (
                False,
                MismatchType.HASH_MISMATCH,
                f"Manifest hash: original={original.manifest_hash_verified}, reverified={reverified.manifest_hash_verified}",
            )

        # Check gate count mismatch
        if original.gates_checked != reverified.gates_checked:
            return (
                False,
                MismatchType.GATE_COUNT_MISMATCH,
                f"Gates checked: original={original.gates_checked}, reverified={reverified.gates_checked}",
            )

        # Check gate results
        if original.gates_passed != reverified.gates_passed:
            return (
                False,
                MismatchType.GATE_RESULT_MISMATCH,
                f"Gates passed: original={original.gates_passed}, reverified={reverified.gates_passed}",
            )

        if original.gates_failed != reverified.gates_failed:
            return (
                False,
                MismatchType.GATE_RESULT_MISMATCH,
                f"Gates failed: original={original.gates_failed}, reverified={reverified.gates_failed}",
            )

        # Check transcript hash (if both have it)
        if (
            original.transcript_hash
            and reverified.transcript_hash
            and original.transcript_hash != reverified.transcript_hash
        ):
            return (
                False,
                MismatchType.TRANSCRIPT_MISMATCH,
                f"Transcript: original={original.transcript_hash[:16]}..., reverified={reverified.transcript_hash[:16]}...",
            )

        return (True, None, None)

    def record_qc_result(
        self,
        task: VerificationTask,
        reverified_verdict: Verdict,
        re_verifier: str,
    ) -> QCResult:
        """
        Record a QC re-verification result.

        Applies penalties on mismatch.
        """
        if not task.verdict:
            raise ValueError(f"Task {task.task_id} has no original verdict")

        match, mismatch_type, details = self.check_for_mismatch(task.verdict, reverified_verdict)

        result = QCResult(
            task_id=task.task_id,
            original_verdict=task.verdict,
            reverified_verdict=reverified_verdict,
            match=match,
            mismatch_type=mismatch_type,
            mismatch_details=details,
            re_verifier=re_verifier,
        )

        # Apply penalty on mismatch
        if not match:
            result.penalty_applied = True
            result.penalty_wei = self.config.mismatch_penalty_wei
            logger.warning(
                f"QC mismatch detected for task {task.task_id}: {mismatch_type.value if mismatch_type else 'unknown'}"
            )

        self._qc_results.append(result)

        # Update verifier history
        if task.verifier:
            if task.verifier not in self._verifier_history:
                self._verifier_history[task.verifier] = []
            self._verifier_history[task.verifier].append((task.task_id, datetime.now(UTC), match))

        return result

    def check_anti_correlation(
        self,
        original_verifier: str,
        candidate_verifier: str,
    ) -> AntiCorrelationCheck:
        """
        Check if a candidate verifier is correlated with the original.

        High correlation suggests potential collusion or rubber-stamping.
        """
        window_start = datetime.now(UTC) - timedelta(hours=self.config.anti_correlation_window_hours)

        # Get recent tasks where both verifiers participated
        original_tasks = {
            task_id
            for task_id, time, _ in self._verifier_history.get(original_verifier, [])
            if time > window_start
        }
        candidate_tasks = {
            (task_id, passed)
            for task_id, time, passed in self._verifier_history.get(candidate_verifier, [])
            if time > window_start
        }

        # Find overlapping tasks
        overlap_tasks = [(tid, passed) for tid, passed in candidate_tasks if tid in original_tasks]

        if not overlap_tasks:
            return AntiCorrelationCheck(
                verifier=candidate_verifier,
                recent_tasks_with_original=0,
                agreement_rate_with_original=0.0,
                is_correlated=False,
                window_hours=self.config.anti_correlation_window_hours,
            )

        # Calculate agreement rate
        original_results = {
            task_id: passed
            for task_id, _, passed in self._verifier_history.get(original_verifier, [])
        }
        agreements = sum(1 for tid, passed in overlap_tasks if original_results.get(tid) == passed)
        agreement_rate = agreements / len(overlap_tasks)

        is_correlated = (
            len(overlap_tasks) >= 3
            and agreement_rate > 1 - self.config.max_verifier_overlap_ratio
        )

        return AntiCorrelationCheck(
            verifier=candidate_verifier,
            recent_tasks_with_original=len(overlap_tasks),
            agreement_rate_with_original=agreement_rate,
            is_correlated=is_correlated,
            window_hours=self.config.anti_correlation_window_hours,
        )

    def select_uncorrelated_verifiers(
        self,
        original_verifier: str,
        candidates: list[str],
        count: int = 1,
    ) -> list[str]:
        """
        Select verifiers that are not correlated with the original.

        Used for T2+ quorum selection to prevent collusion.
        """
        # Exclude original verifier
        candidates = [c for c in candidates if c != original_verifier]

        # Check anti-correlation
        uncorrelated = []
        for candidate in candidates:
            check = self.check_anti_correlation(original_verifier, candidate)
            if not check.is_correlated:
                uncorrelated.append(candidate)

        if len(uncorrelated) < count:
            logger.warning(
                f"Insufficient uncorrelated verifiers: need {count}, found {len(uncorrelated)}"
            )
            # Fall back to least correlated
            all_checks = [
                (c, self.check_anti_correlation(original_verifier, c))
                for c in candidates
            ]
            all_checks.sort(key=lambda x: x[1].agreement_rate_with_original)
            return [c for c, _ in all_checks[:count]]

        return uncorrelated[:count]

    def generate_qc_report(self) -> dict[str, Any]:
        """Generate QC statistics report."""
        if not self._qc_results:
            return {
                "total_checks": 0,
                "matches": 0,
                "mismatches": 0,
                "match_rate": 0.0,
                "penalties_applied": 0,
                "total_penalties_wei": 0,
                "mismatch_types": {},
            }

        matches = sum(1 for r in self._qc_results if r.match)
        mismatches = len(self._qc_results) - matches

        mismatch_types: dict[str, int] = {}
        for r in self._qc_results:
            if r.mismatch_type:
                key = r.mismatch_type.value
                mismatch_types[key] = mismatch_types.get(key, 0) + 1

        return {
            "total_checks": len(self._qc_results),
            "matches": matches,
            "mismatches": mismatches,
            "match_rate": matches / len(self._qc_results),
            "penalties_applied": sum(1 for r in self._qc_results if r.penalty_applied),
            "total_penalties_wei": sum(r.penalty_wei for r in self._qc_results),
            "mismatch_types": mismatch_types,
            "results": [r.to_dict() for r in self._qc_results[-100:]],  # Last 100
        }

    @property
    def qc_results(self) -> list[QCResult]:
        """All QC results."""
        return list(self._qc_results)

    @property
    def mismatch_rate(self) -> float:
        """Rate of mismatches in QC checks."""
        if not self._qc_results:
            return 0.0
        mismatches = sum(1 for r in self._qc_results if not r.match)
        return mismatches / len(self._qc_results)


def run_qc_batch(
    task_registry: TaskRegistry,
    config: ReVerificationConfig | None = None,
    seed: int | None = None,
) -> QCSelectionResult:
    """
    Convenience function to select tasks for QC.

    Returns selected tasks; actual re-verification must be
    performed externally (e.g., by dispatching to verifiers).
    """
    qc = QualityController(config=config, task_registry=task_registry)
    return qc.select_for_reverification(seed=seed)
