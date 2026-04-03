"""
Verifier task protocol with state machine.

Implements the verification task lifecycle:
OPEN -> CLAIMED -> SUBMITTED -> FINALIZED
                |
            DISPUTED -> RESOLVED
                |
            SLASHED (on liveness/mismatch failure)
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TaskState(str, Enum):
    """State of a verification task."""

    OPEN = "open"  # Available for claiming
    CLAIMED = "claimed"  # Verifier has claimed, clock running
    SUBMITTED = "submitted"  # Verifier submitted verdict
    FINALIZED = "finalized"  # Verdict accepted, payout ready
    DISPUTED = "disputed"  # Challenge in progress
    SLASHED = "slashed"  # Verifier failed (liveness or mismatch)


class VerdictOutcome(str, Enum):
    """Possible outcomes of a verification verdict."""

    PASS = "pass"  # All gates passed, work accepted
    FAIL = "fail"  # At least one gate failed
    SKIP = "skip"  # Verification skipped (e.g., non-deterministic gate)
    ERROR = "error"  # Verification could not complete


@dataclass
class Verdict:
    """
    A verification verdict submitted by a verifier.

    Contains the outcome of verifying a proof bundle,
    including hash checks and gate replays.
    """

    outcome: VerdictOutcome
    receipt_hash_verified: bool
    manifest_hash_verified: bool
    gates_checked: int
    gates_passed: int
    gates_failed: int
    verification_time_ms: float
    transcript_hash: str | None = None  # Hash of replay transcript
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "receipt_hash_verified": self.receipt_hash_verified,
            "manifest_hash_verified": self.manifest_hash_verified,
            "gates_checked": self.gates_checked,
            "gates_passed": self.gates_passed,
            "gates_failed": self.gates_failed,
            "verification_time_ms": self.verification_time_ms,
            "transcript_hash": self.transcript_hash,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Verdict:
        return cls(
            outcome=VerdictOutcome(data["outcome"]),
            receipt_hash_verified=data["receipt_hash_verified"],
            manifest_hash_verified=data["manifest_hash_verified"],
            gates_checked=data["gates_checked"],
            gates_passed=data["gates_passed"],
            gates_failed=data["gates_failed"],
            verification_time_ms=data["verification_time_ms"],
            transcript_hash=data.get("transcript_hash"),
            notes=data.get("notes"),
        )

    @property
    def is_pass(self) -> bool:
        """Verdict indicates successful verification."""
        return self.outcome == VerdictOutcome.PASS


class TaskStateError(Exception):
    """Invalid state transition."""

    pass


@dataclass
class VerificationTask:
    """
    A verification task in the protocol.

    Tracks the lifecycle of a verification request from
    creation through claim, submission, and finalization.
    """

    task_id: str
    bundle_hash: str
    tier: int  # 0=spot-check, 1=full replay, 2=multi-verifier
    state: TaskState = TaskState.OPEN
    verifier: str | None = None  # Public key of claimer
    claimed_at: datetime | None = None
    deadline: datetime | None = None  # Liveness deadline
    verdict: Verdict | None = None
    submitted_at: datetime | None = None
    finalized_at: datetime | None = None
    slashed_at: datetime | None = None
    slash_reason: str | None = None

    # Configuration
    liveness_deadline_hours: int = 24  # Hours to submit after claim
    reward_wei: int = 0  # Payment for successful verification
    stake_wei: int = 0  # Stake required for claiming

    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    job_family: str = ""  # Job family for routing/pricing

    def __post_init__(self) -> None:
        if not self.task_id:
            unique_str = f"{self.bundle_hash}:{self.created_at.isoformat()}"
            self.task_id = "task_" + hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    @property
    def is_claimable(self) -> bool:
        """Task can be claimed by a verifier."""
        return self.state == TaskState.OPEN

    @property
    def is_submittable(self) -> bool:
        """Verifier can submit a verdict."""
        return self.state == TaskState.CLAIMED

    @property
    def is_finalizable(self) -> bool:
        """Verdict can be finalized."""
        return self.state == TaskState.SUBMITTED

    @property
    def is_overdue(self) -> bool:
        """Liveness deadline has passed."""
        if self.state != TaskState.CLAIMED or self.deadline is None:
            return False
        return datetime.now(UTC) > self.deadline

    def claim(self, verifier: str) -> None:
        """
        Claim the task for verification.

        Args:
            verifier: Public key of the claiming verifier

        Raises:
            TaskStateError: If task is not in OPEN state
        """
        if self.state != TaskState.OPEN:
            raise TaskStateError(f"Cannot claim task in state {self.state}")

        self.verifier = verifier
        self.claimed_at = datetime.now(UTC)
        self.deadline = self.claimed_at + timedelta(hours=self.liveness_deadline_hours)
        self.state = TaskState.CLAIMED
        logger.info(f"Task {self.task_id} claimed by {verifier}")

    def submit(self, verdict: Verdict) -> None:
        """
        Submit a verification verdict.

        Args:
            verdict: The verification verdict

        Raises:
            TaskStateError: If task is not in CLAIMED state
        """
        if self.state != TaskState.CLAIMED:
            raise TaskStateError(f"Cannot submit to task in state {self.state}")

        if self.is_overdue:
            raise TaskStateError("Liveness deadline passed, task must be slashed")

        self.verdict = verdict
        self.submitted_at = datetime.now(UTC)
        self.state = TaskState.SUBMITTED
        logger.info(f"Task {self.task_id} verdict submitted: {verdict.outcome.value}")

    def finalize(self) -> None:
        """
        Finalize the task, accepting the verdict.

        Raises:
            TaskStateError: If task is not in SUBMITTED or DISPUTED state
        """
        # Can finalize from SUBMITTED (normal flow) or DISPUTED (challenge rejected)
        if self.state not in (TaskState.SUBMITTED, TaskState.DISPUTED):
            raise TaskStateError(f"Cannot finalize task in state {self.state}")

        self.finalized_at = datetime.now(UTC)
        self.state = TaskState.FINALIZED
        logger.info(f"Task {self.task_id} finalized")

    def dispute(self) -> None:
        """
        Mark task as disputed (challenge received).

        Raises:
            TaskStateError: If task is not in SUBMITTED state
        """
        if self.state != TaskState.SUBMITTED:
            raise TaskStateError(f"Cannot dispute task in state {self.state}")

        self.state = TaskState.DISPUTED
        logger.info(f"Task {self.task_id} disputed")

    def slash(self, reason: str) -> None:
        """
        Slash the verifier for failure.

        Args:
            reason: Reason for slashing (liveness, mismatch, etc.)

        Raises:
            TaskStateError: If task cannot be slashed
        """
        # Can slash from CLAIMED (liveness) or DISPUTED (mismatch)
        if self.state not in (TaskState.CLAIMED, TaskState.DISPUTED):
            raise TaskStateError(f"Cannot slash task in state {self.state}")

        self.slashed_at = datetime.now(UTC)
        self.slash_reason = reason
        self.state = TaskState.SLASHED
        logger.warning(f"Task {self.task_id} slashed: {reason}")

    def resolve_dispute(self, upheld: bool) -> None:
        """
        Resolve a dispute.

        Args:
            upheld: If True, challenge was upheld (verifier slashed).
                   If False, challenge rejected (verifier finalized).
        """
        if self.state != TaskState.DISPUTED:
            raise TaskStateError(f"Cannot resolve dispute in state {self.state}")

        if upheld:
            self.slash("Challenge upheld: verdict mismatch")
        else:
            self.finalize()

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "bundle_hash": self.bundle_hash,
            "tier": self.tier,
            "state": self.state.value,
            "verifier": self.verifier,
            "claimed_at": self.claimed_at.isoformat() if self.claimed_at else None,
            "deadline": self.deadline.isoformat() if self.deadline else None,
            "verdict": self.verdict.to_dict() if self.verdict else None,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "finalized_at": self.finalized_at.isoformat() if self.finalized_at else None,
            "slashed_at": self.slashed_at.isoformat() if self.slashed_at else None,
            "slash_reason": self.slash_reason,
            "liveness_deadline_hours": self.liveness_deadline_hours,
            "reward_wei": self.reward_wei,
            "stake_wei": self.stake_wei,
            "created_at": self.created_at.isoformat(),
            "job_family": self.job_family,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationTask:
        task = cls(
            task_id=data["task_id"],
            bundle_hash=data["bundle_hash"],
            tier=data["tier"],
            state=TaskState(data["state"]),
            verifier=data.get("verifier"),
            liveness_deadline_hours=data.get("liveness_deadline_hours", 24),
            reward_wei=data.get("reward_wei", 0),
            stake_wei=data.get("stake_wei", 0),
            created_at=datetime.fromisoformat(data["created_at"]),
            job_family=data.get("job_family", ""),
        )

        if data.get("claimed_at"):
            task.claimed_at = datetime.fromisoformat(data["claimed_at"])
        if data.get("deadline"):
            task.deadline = datetime.fromisoformat(data["deadline"])
        if data.get("verdict"):
            task.verdict = Verdict.from_dict(data["verdict"])
        if data.get("submitted_at"):
            task.submitted_at = datetime.fromisoformat(data["submitted_at"])
        if data.get("finalized_at"):
            task.finalized_at = datetime.fromisoformat(data["finalized_at"])
        if data.get("slashed_at"):
            task.slashed_at = datetime.fromisoformat(data["slashed_at"])
        task.slash_reason = data.get("slash_reason")

        return task


class TaskRegistry:
    """
    In-memory task registry.

    Production implementation would use a database.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, VerificationTask] = {}
        self._by_bundle: dict[str, list[str]] = {}  # bundle_hash -> task_ids
        self._by_verifier: dict[str, list[str]] = {}  # verifier -> task_ids

    def create_task(
        self,
        bundle_hash: str,
        tier: int = 0,
        reward_wei: int = 0,
        stake_wei: int = 0,
        liveness_deadline_hours: int = 24,
        job_family: str = "",
    ) -> VerificationTask:
        """Create a new verification task."""
        task = VerificationTask(
            task_id="",  # Will be generated
            bundle_hash=bundle_hash,
            tier=tier,
            reward_wei=reward_wei,
            stake_wei=stake_wei,
            liveness_deadline_hours=liveness_deadline_hours,
            job_family=job_family,
        )

        self._tasks[task.task_id] = task

        if bundle_hash not in self._by_bundle:
            self._by_bundle[bundle_hash] = []
        self._by_bundle[bundle_hash].append(task.task_id)

        logger.info(f"Created task {task.task_id} for bundle {bundle_hash}")
        return task

    def get_task(self, task_id: str) -> VerificationTask | None:
        """Get task by ID."""
        return self._tasks.get(task_id)

    def get_tasks_for_bundle(self, bundle_hash: str) -> list[VerificationTask]:
        """Get all tasks for a bundle."""
        task_ids = self._by_bundle.get(bundle_hash, [])
        return [self._tasks[tid] for tid in task_ids if tid in self._tasks]

    def get_tasks_for_verifier(self, verifier: str) -> list[VerificationTask]:
        """Get all tasks for a verifier."""
        task_ids = self._by_verifier.get(verifier, [])
        return [self._tasks[tid] for tid in task_ids if tid in self._tasks]

    def claim_task(self, task_id: str, verifier: str) -> VerificationTask:
        """Claim a task for verification."""
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")

        task.claim(verifier)

        if verifier not in self._by_verifier:
            self._by_verifier[verifier] = []
        self._by_verifier[verifier].append(task_id)

        return task

    def submit_verdict(self, task_id: str, verdict: Verdict) -> VerificationTask:
        """Submit a verdict for a task."""
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")

        task.submit(verdict)
        return task

    def finalize_task(self, task_id: str) -> VerificationTask:
        """Finalize a task."""
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")

        task.finalize()
        return task

    def slash_task(self, task_id: str, reason: str) -> VerificationTask:
        """Slash a verifier for a task."""
        task = self._tasks.get(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")

        task.slash(reason)
        return task

    def get_open_tasks(self) -> list[VerificationTask]:
        """Get all open (claimable) tasks."""
        return [t for t in self._tasks.values() if t.state == TaskState.OPEN]

    def get_overdue_tasks(self) -> list[VerificationTask]:
        """Get all tasks past their liveness deadline."""
        return [t for t in self._tasks.values() if t.is_overdue]

    def process_overdue(self) -> list[VerificationTask]:
        """Process overdue tasks by slashing them."""
        overdue = self.get_overdue_tasks()
        for task in overdue:
            task.slash("Liveness deadline exceeded")
        return overdue

    @property
    def tasks_by_state(self) -> dict[TaskState, int]:
        """Count of tasks by state."""
        counts: dict[TaskState, int] = dict.fromkeys(TaskState, 0)
        for task in self._tasks.values():
            counts[task.state] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tasks": {k: v.to_dict() for k, v in self._tasks.items()},
            "tasks_by_state": {k.value: v for k, v in self.tasks_by_state.items()},
            "total_tasks": len(self._tasks),
        }


# Default configuration by tier
DEFAULT_LIVENESS_HOURS = {
    0: 4,  # T0: 4 hours for spot-check
    1: 24,  # T1: 24 hours for full replay
    2: 72,  # T2: 72 hours for multi-verifier
}

DEFAULT_REWARD_WEI = {
    0: 1_000_000_000_000_000,  # 0.001 ETH for T0
    1: 10_000_000_000_000_000,  # 0.01 ETH for T1
    2: 100_000_000_000_000_000,  # 0.1 ETH for T2
}

DEFAULT_STAKE_WEI = {
    0: 10_000_000_000_000_000,  # 0.01 ETH for T0
    1: 100_000_000_000_000_000,  # 0.1 ETH for T1
    2: 1_000_000_000_000_000_000,  # 1 ETH for T2
}
