"""
Challenger incentives and challenge flow.

Implements:
- Challenge submission with bond escrow
- Challenge resolution and reward distribution
- Spam prevention through calibrated bonds
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from cyntra.trust.protocol.task_protocol import TaskRegistry, TaskState

logger = logging.getLogger(__name__)


class ChallengeStatus(str, Enum):
    """Status of a challenge."""

    PENDING = "pending"  # Challenge submitted, awaiting resolution
    UPHELD = "upheld"  # Challenge successful, original verifier penalized
    REJECTED = "rejected"  # Challenge failed, challenger loses bond
    EXPIRED = "expired"  # Challenge window closed
    WITHDRAWN = "withdrawn"  # Challenger withdrew


@dataclass
class ChallengeConfig:
    """Challenge incentive configuration."""

    challenge_bond_wei: int = 50_000_000_000_000_000  # 0.05 ETH base bond
    reward_multiplier: float = 2.0  # 2x bond on success
    challenge_window_hours: int = 48  # Window to submit challenges
    max_challenges_per_task: int = 3  # Prevent spam
    min_evidence_size_bytes: int = 100  # Minimum evidence required
    resolution_deadline_hours: int = 72  # Time to resolve challenge

    # Tier-specific bond multipliers
    tier_bond_multipliers: dict[int, float] = field(
        default_factory=lambda: {0: 0.5, 1: 1.0, 2: 2.0}
    )

    def get_bond_for_tier(self, tier: int) -> int:
        """Get challenge bond for a specific tier."""
        multiplier = self.tier_bond_multipliers.get(tier, 1.0)
        return int(self.challenge_bond_wei * multiplier)

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_bond_wei": self.challenge_bond_wei,
            "reward_multiplier": self.reward_multiplier,
            "challenge_window_hours": self.challenge_window_hours,
            "max_challenges_per_task": self.max_challenges_per_task,
            "min_evidence_size_bytes": self.min_evidence_size_bytes,
            "resolution_deadline_hours": self.resolution_deadline_hours,
            "tier_bond_multipliers": self.tier_bond_multipliers,
        }


@dataclass
class ChallengeEvidence:
    """Evidence submitted with a challenge."""

    evidence_hash: str  # SHA-256 of evidence bundle
    evidence_uri: str | None = None  # URI to fetch evidence
    evidence_type: str = "bundle"  # Type of evidence
    description: str = ""  # Human-readable description

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_hash": self.evidence_hash,
            "evidence_uri": self.evidence_uri,
            "evidence_type": self.evidence_type,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChallengeEvidence:
        return cls(
            evidence_hash=data["evidence_hash"],
            evidence_uri=data.get("evidence_uri"),
            evidence_type=data.get("evidence_type", "bundle"),
            description=data.get("description", ""),
        )


@dataclass
class Challenge:
    """
    A challenge against a verification verdict.

    Challengers post a bond and evidence that the original
    verdict was incorrect. If upheld, challenger receives
    reward from verifier's stake.
    """

    challenge_id: str
    task_id: str
    challenger: str  # Public key
    challenge_bond_wei: int
    evidence: ChallengeEvidence
    status: ChallengeStatus = ChallengeStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None
    resolution_reason: str | None = None
    payout_wei: int = 0

    # Resolution details
    resolution_evidence_hash: str | None = None
    arbiter: str | None = None  # Who resolved the challenge

    def __post_init__(self) -> None:
        if not self.challenge_id:
            unique_str = f"{self.task_id}:{self.challenger}:{self.created_at.isoformat()}"
            self.challenge_id = "ch_" + hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    @property
    def is_pending(self) -> bool:
        """Challenge is awaiting resolution."""
        return self.status == ChallengeStatus.PENDING

    @property
    def is_resolved(self) -> bool:
        """Challenge has been resolved."""
        return self.status in (ChallengeStatus.UPHELD, ChallengeStatus.REJECTED)

    def uphold(self, reason: str, payout_wei: int, arbiter: str | None = None) -> None:
        """
        Uphold the challenge (original verifier was wrong).

        Args:
            reason: Reason for upholding
            payout_wei: Amount to pay challenger
            arbiter: Who made the resolution
        """
        if self.status != ChallengeStatus.PENDING:
            raise ValueError(f"Cannot uphold challenge in status {self.status}")

        self.status = ChallengeStatus.UPHELD
        self.resolved_at = datetime.now(UTC)
        self.resolution_reason = reason
        self.payout_wei = payout_wei
        self.arbiter = arbiter
        logger.info(f"Challenge {self.challenge_id} upheld: {reason}")

    def reject(self, reason: str, arbiter: str | None = None) -> None:
        """
        Reject the challenge (original verifier was correct).

        Args:
            reason: Reason for rejection
            arbiter: Who made the resolution
        """
        if self.status != ChallengeStatus.PENDING:
            raise ValueError(f"Cannot reject challenge in status {self.status}")

        self.status = ChallengeStatus.REJECTED
        self.resolved_at = datetime.now(UTC)
        self.resolution_reason = reason
        self.arbiter = arbiter
        logger.info(f"Challenge {self.challenge_id} rejected: {reason}")

    def withdraw(self) -> None:
        """Withdraw the challenge (challenger forfeits bond)."""
        if self.status != ChallengeStatus.PENDING:
            raise ValueError(f"Cannot withdraw challenge in status {self.status}")

        self.status = ChallengeStatus.WITHDRAWN
        self.resolved_at = datetime.now(UTC)
        self.resolution_reason = "Withdrawn by challenger"
        logger.info(f"Challenge {self.challenge_id} withdrawn")

    def expire(self) -> None:
        """Mark challenge as expired."""
        if self.status != ChallengeStatus.PENDING:
            return

        self.status = ChallengeStatus.EXPIRED
        self.resolved_at = datetime.now(UTC)
        self.resolution_reason = "Challenge window expired"
        logger.info(f"Challenge {self.challenge_id} expired")

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "task_id": self.task_id,
            "challenger": self.challenger,
            "challenge_bond_wei": self.challenge_bond_wei,
            "evidence": self.evidence.to_dict(),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_reason": self.resolution_reason,
            "payout_wei": self.payout_wei,
            "resolution_evidence_hash": self.resolution_evidence_hash,
            "arbiter": self.arbiter,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Challenge:
        challenge = cls(
            challenge_id=data["challenge_id"],
            task_id=data["task_id"],
            challenger=data["challenger"],
            challenge_bond_wei=data["challenge_bond_wei"],
            evidence=ChallengeEvidence.from_dict(data["evidence"]),
            status=ChallengeStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            payout_wei=data.get("payout_wei", 0),
        )
        if data.get("resolved_at"):
            challenge.resolved_at = datetime.fromisoformat(data["resolved_at"])
        challenge.resolution_reason = data.get("resolution_reason")
        challenge.resolution_evidence_hash = data.get("resolution_evidence_hash")
        challenge.arbiter = data.get("arbiter")
        return challenge


@dataclass
class BondEscrow:
    """Escrow record for a challenge bond."""

    challenge_id: str
    challenger: str
    amount_wei: int
    escrowed_at: datetime
    released_at: datetime | None = None
    released_to: str | None = None  # challenger or verifier

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "challenger": self.challenger,
            "amount_wei": self.amount_wei,
            "escrowed_at": self.escrowed_at.isoformat(),
            "released_at": self.released_at.isoformat() if self.released_at else None,
            "released_to": self.released_to,
        }


class ChallengeRegistry:
    """
    Challenge registry with bond escrow.

    Manages challenge lifecycle:
    1. Submission with bond escrow
    2. Resolution (uphold/reject)
    3. Payout distribution
    """

    def __init__(
        self,
        config: ChallengeConfig | None = None,
        task_registry: TaskRegistry | None = None,
    ) -> None:
        self.config = config or ChallengeConfig()
        self.task_registry = task_registry
        self._challenges: dict[str, Challenge] = {}
        self._by_task: dict[str, list[str]] = {}  # task_id -> challenge_ids
        self._by_challenger: dict[str, list[str]] = {}  # challenger -> challenge_ids
        self._escrows: dict[str, BondEscrow] = {}  # challenge_id -> escrow

    def submit_challenge(
        self,
        task_id: str,
        challenger: str,
        evidence: ChallengeEvidence,
        bond_wei: int | None = None,
    ) -> Challenge:
        """
        Submit a challenge against a task.

        Args:
            task_id: ID of the task to challenge
            challenger: Public key of challenger
            evidence: Evidence supporting the challenge
            bond_wei: Bond amount (defaults to config)

        Returns:
            The created challenge

        Raises:
            ValueError: If challenge is invalid
        """
        # Validate task exists and is challengeable
        if self.task_registry:
            task = self.task_registry.get_task(task_id)
            if not task:
                raise ValueError(f"Task not found: {task_id}")
            if task.state not in (TaskState.SUBMITTED, TaskState.FINALIZED):
                raise ValueError(f"Task not challengeable in state {task.state}")

            # Check challenge window
            if task.submitted_at:
                window_end = task.submitted_at + timedelta(hours=self.config.challenge_window_hours)
                if datetime.now(UTC) > window_end:
                    raise ValueError("Challenge window has closed")

            # Check max challenges
            existing = self._by_task.get(task_id, [])
            if len(existing) >= self.config.max_challenges_per_task:
                raise ValueError(f"Maximum challenges ({self.config.max_challenges_per_task}) already submitted")

            # Calculate bond based on tier
            if bond_wei is None:
                bond_wei = self.config.get_bond_for_tier(task.tier)
        else:
            bond_wei = bond_wei or self.config.challenge_bond_wei

        # Create challenge
        challenge = Challenge(
            challenge_id="",  # Will be generated
            task_id=task_id,
            challenger=challenger,
            challenge_bond_wei=bond_wei,
            evidence=evidence,
        )

        # Create escrow
        escrow = BondEscrow(
            challenge_id=challenge.challenge_id,
            challenger=challenger,
            amount_wei=bond_wei,
            escrowed_at=datetime.now(UTC),
        )

        # Store
        self._challenges[challenge.challenge_id] = challenge
        self._escrows[challenge.challenge_id] = escrow

        if task_id not in self._by_task:
            self._by_task[task_id] = []
        self._by_task[task_id].append(challenge.challenge_id)

        if challenger not in self._by_challenger:
            self._by_challenger[challenger] = []
        self._by_challenger[challenger].append(challenge.challenge_id)

        # Mark task as disputed
        if self.task_registry:
            task = self.task_registry.get_task(task_id)
            if task and task.state == TaskState.SUBMITTED:
                task.dispute()

        logger.info(f"Challenge {challenge.challenge_id} submitted for task {task_id}")
        return challenge

    def get_challenge(self, challenge_id: str) -> Challenge | None:
        """Get challenge by ID."""
        return self._challenges.get(challenge_id)

    def get_challenges_for_task(self, task_id: str) -> list[Challenge]:
        """Get all challenges for a task."""
        challenge_ids = self._by_task.get(task_id, [])
        return [self._challenges[cid] for cid in challenge_ids if cid in self._challenges]

    def get_challenges_for_challenger(self, challenger: str) -> list[Challenge]:
        """Get all challenges by a challenger."""
        challenge_ids = self._by_challenger.get(challenger, [])
        return [self._challenges[cid] for cid in challenge_ids if cid in self._challenges]

    def resolve_challenge(
        self,
        challenge_id: str,
        upheld: bool,
        reason: str,
        arbiter: str | None = None,
    ) -> Challenge:
        """
        Resolve a challenge.

        Args:
            challenge_id: ID of challenge to resolve
            upheld: True if challenge is upheld (verifier wrong)
            reason: Reason for resolution
            arbiter: Who resolved the challenge

        Returns:
            The resolved challenge
        """
        challenge = self._challenges.get(challenge_id)
        if not challenge:
            raise ValueError(f"Challenge not found: {challenge_id}")

        if upheld:
            # Calculate payout: bond + reward
            payout = int(challenge.challenge_bond_wei * self.config.reward_multiplier)
            challenge.uphold(reason, payout, arbiter)

            # Release escrow to challenger with reward
            self._release_escrow(challenge_id, challenge.challenger, include_reward=True)

            # Slash original verifier if task registry available
            if self.task_registry:
                task = self.task_registry.get_task(challenge.task_id)
                if task:
                    task.resolve_dispute(upheld=True)
        else:
            challenge.reject(reason, arbiter)

            # Forfeit escrow (goes to verifier or protocol)
            self._release_escrow(challenge_id, "protocol", include_reward=False)

            # Finalize task if task registry available
            if self.task_registry:
                task = self.task_registry.get_task(challenge.task_id)
                if task:
                    task.resolve_dispute(upheld=False)

        return challenge

    def _release_escrow(
        self,
        challenge_id: str,
        to: str,
        include_reward: bool,
    ) -> None:
        """Release escrowed bond."""
        escrow = self._escrows.get(challenge_id)
        if not escrow:
            return

        escrow.released_at = datetime.now(UTC)
        escrow.released_to = to
        logger.info(f"Escrow for {challenge_id} released to {to}")

    def process_expired_challenges(self) -> list[Challenge]:
        """Process challenges past their resolution deadline."""
        now = datetime.now(UTC)
        expired = []

        for challenge in self._challenges.values():
            if challenge.status != ChallengeStatus.PENDING:
                continue

            deadline = challenge.created_at + timedelta(hours=self.config.resolution_deadline_hours)
            if now > deadline:
                challenge.expire()
                # Return bond to challenger on expiry (no resolution is not their fault)
                self._release_escrow(challenge.challenge_id, challenge.challenger, include_reward=False)
                expired.append(challenge)

        return expired

    def get_pending_challenges(self) -> list[Challenge]:
        """Get all pending challenges."""
        return [c for c in self._challenges.values() if c.status == ChallengeStatus.PENDING]

    def generate_stats(self) -> dict[str, Any]:
        """Generate challenge statistics."""
        total = len(self._challenges)
        by_status: dict[str, int] = {}
        for c in self._challenges.values():
            by_status[c.status.value] = by_status.get(c.status.value, 0) + 1

        upheld = [c for c in self._challenges.values() if c.status == ChallengeStatus.UPHELD]
        rejected = [c for c in self._challenges.values() if c.status == ChallengeStatus.REJECTED]

        return {
            "total_challenges": total,
            "by_status": by_status,
            "upheld_count": len(upheld),
            "rejected_count": len(rejected),
            "upheld_rate": len(upheld) / max(len(upheld) + len(rejected), 1),
            "total_payouts_wei": sum(c.payout_wei for c in upheld),
            "total_escrowed_wei": sum(e.amount_wei for e in self._escrows.values() if e.released_at is None),
            "pending_count": len(self.get_pending_challenges()),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenges": {k: v.to_dict() for k, v in self._challenges.items()},
            "escrows": {k: v.to_dict() for k, v in self._escrows.items()},
            "stats": self.generate_stats(),
        }


# Default challenge rewards by outcome
DEFAULT_CHALLENGER_REWARDS = {
    # Tier -> (bond_wei, reward_multiplier)
    0: (25_000_000_000_000_000, 2.0),  # 0.025 ETH bond, 2x reward
    1: (50_000_000_000_000_000, 2.0),  # 0.05 ETH bond, 2x reward
    2: (100_000_000_000_000_000, 2.5),  # 0.1 ETH bond, 2.5x reward
}
