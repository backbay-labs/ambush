"""
Settlement court for verification market.

Implements single-court settlement with:
- Off-chain escrow (first iteration)
- Dispute resolution flow
- Payout distribution
- Settlement receipts for auditability

Future iterations can add on-chain settlement via Ethereum/Solana.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from cyntra.trust.availability.obligation import DABondRegistry
from cyntra.trust.protocol.challenges import Challenge, ChallengeRegistry, ChallengeStatus
from cyntra.trust.protocol.task_protocol import TaskRegistry, TaskState, VerificationTask

logger = logging.getLogger(__name__)


class CourtType(str, Enum):
    """Type of settlement court."""

    OFFCHAIN = "offchain"  # Off-chain arbiter
    ETHEREUM = "ethereum"  # Ethereum mainnet
    SOLANA = "solana"  # Solana
    BASE = "base"  # Base L2


@dataclass
class CourtConfig:
    """Settlement court configuration."""

    court_type: CourtType = CourtType.OFFCHAIN
    escrow_address: str | None = None  # For on-chain
    arbiter_pubkey: str | None = None  # For off-chain
    finality_blocks: int = 12  # For on-chain
    settlement_delay_hours: int = 24  # Delay before finalization
    min_challenge_period_hours: int = 48  # Minimum time to allow challenges

    def to_dict(self) -> dict[str, Any]:
        return {
            "court_type": self.court_type.value,
            "escrow_address": self.escrow_address,
            "arbiter_pubkey": self.arbiter_pubkey,
            "finality_blocks": self.finality_blocks,
            "settlement_delay_hours": self.settlement_delay_hours,
            "min_challenge_period_hours": self.min_challenge_period_hours,
        }


@dataclass
class EscrowAccount:
    """In-memory escrow account."""

    account_id: str
    owner: str  # Public key
    balance_wei: int = 0
    locked_wei: int = 0  # Locked for pending operations
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def available_wei(self) -> int:
        """Available balance (not locked)."""
        return self.balance_wei - self.locked_wei

    def deposit(self, amount_wei: int) -> None:
        """Deposit funds."""
        if amount_wei <= 0:
            raise ValueError("Deposit must be positive")
        self.balance_wei += amount_wei
        logger.info(f"Deposited {amount_wei} wei to {self.account_id}")

    def lock(self, amount_wei: int) -> None:
        """Lock funds for pending operation."""
        if amount_wei > self.available_wei:
            raise ValueError(f"Insufficient funds: {self.available_wei} < {amount_wei}")
        self.locked_wei += amount_wei

    def unlock(self, amount_wei: int) -> None:
        """Unlock previously locked funds."""
        if amount_wei > self.locked_wei:
            raise ValueError(f"Cannot unlock more than locked: {self.locked_wei} < {amount_wei}")
        self.locked_wei -= amount_wei

    def withdraw(self, amount_wei: int) -> None:
        """Withdraw funds."""
        if amount_wei > self.available_wei:
            raise ValueError(f"Insufficient available funds: {self.available_wei} < {amount_wei}")
        self.balance_wei -= amount_wei
        logger.info(f"Withdrew {amount_wei} wei from {self.account_id}")

    def transfer(self, to_account: EscrowAccount, amount_wei: int) -> None:
        """Transfer funds to another account."""
        self.withdraw(amount_wei)
        to_account.deposit(amount_wei)

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "owner": self.owner,
            "balance_wei": self.balance_wei,
            "locked_wei": self.locked_wei,
            "available_wei": self.available_wei,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class SettlementReceipt:
    """
    Receipt for a finalized settlement.

    Provides audit trail for payouts and dispute resolutions.
    """

    receipt_id: str
    task_id: str
    settlement_type: str  # "verdict", "dispute", "slash"
    verifier: str
    payout_wei: int
    settled_at: datetime
    court_type: CourtType
    arbiter: str | None = None
    transaction_hash: str | None = None  # For on-chain
    notes: str | None = None

    def __post_init__(self) -> None:
        if not self.receipt_id:
            unique_str = f"{self.task_id}:{self.settlement_type}:{self.settled_at.isoformat()}"
            self.receipt_id = "sr_" + hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    def compute_receipt_hash(self) -> str:
        """Compute hash of receipt for verification."""
        content = f"{self.task_id}:{self.verifier}:{self.payout_wei}:{self.settled_at.isoformat()}"
        return "0x" + hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "task_id": self.task_id,
            "settlement_type": self.settlement_type,
            "verifier": self.verifier,
            "payout_wei": self.payout_wei,
            "settled_at": self.settled_at.isoformat(),
            "court_type": self.court_type.value,
            "arbiter": self.arbiter,
            "transaction_hash": self.transaction_hash,
            "notes": self.notes,
            "receipt_hash": self.compute_receipt_hash(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SettlementReceipt:
        return cls(
            receipt_id=data["receipt_id"],
            task_id=data["task_id"],
            settlement_type=data["settlement_type"],
            verifier=data["verifier"],
            payout_wei=data["payout_wei"],
            settled_at=datetime.fromisoformat(data["settled_at"]),
            court_type=CourtType(data["court_type"]),
            arbiter=data.get("arbiter"),
            transaction_hash=data.get("transaction_hash"),
            notes=data.get("notes"),
        )


@dataclass
class DisputeResolution:
    """Resolution of a dispute."""

    resolution_id: str
    challenge_id: str
    task_id: str
    upheld: bool  # Challenge was upheld
    verifier_slashed: bool
    challenger_rewarded: bool
    slash_amount_wei: int
    reward_amount_wei: int
    resolved_at: datetime
    arbiter: str
    evidence_reviewed: list[str] = field(default_factory=list)
    reasoning: str = ""

    def __post_init__(self) -> None:
        if not self.resolution_id:
            unique_str = f"{self.challenge_id}:{self.resolved_at.isoformat()}"
            self.resolution_id = "dr_" + hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolution_id": self.resolution_id,
            "challenge_id": self.challenge_id,
            "task_id": self.task_id,
            "upheld": self.upheld,
            "verifier_slashed": self.verifier_slashed,
            "challenger_rewarded": self.challenger_rewarded,
            "slash_amount_wei": self.slash_amount_wei,
            "reward_amount_wei": self.reward_amount_wei,
            "resolved_at": self.resolved_at.isoformat(),
            "arbiter": self.arbiter,
            "evidence_reviewed": self.evidence_reviewed,
            "reasoning": self.reasoning,
        }


class SettlementCourt:
    """
    Single authoritative court for disputes and payouts.

    Implements off-chain settlement with:
    - Escrow management
    - Verdict finalization
    - Dispute resolution
    - Payout distribution
    """

    def __init__(
        self,
        config: CourtConfig | None = None,
        task_registry: TaskRegistry | None = None,
        challenge_registry: ChallengeRegistry | None = None,
        da_bond_registry: DABondRegistry | None = None,
    ) -> None:
        self.config = config or CourtConfig()
        self.task_registry = task_registry
        self.challenge_registry = challenge_registry
        self.da_bond_registry = da_bond_registry

        # In-memory escrow accounts
        self._accounts: dict[str, EscrowAccount] = {}
        self._protocol_account: EscrowAccount = self._get_or_create_account("protocol")

        # Settlement history
        self._receipts: list[SettlementReceipt] = []
        self._resolutions: list[DisputeResolution] = []

        # Blocked settlements (due to DA failure)
        self._blocked_tasks: set[str] = set()

    def _get_or_create_account(self, owner: str) -> EscrowAccount:
        """Get or create an escrow account."""
        account_id = f"ea_{hashlib.sha256(owner.encode()).hexdigest()[:12]}"
        if account_id not in self._accounts:
            self._accounts[account_id] = EscrowAccount(
                account_id=account_id,
                owner=owner,
            )
        return self._accounts[account_id]

    def deposit(self, owner: str, amount_wei: int) -> EscrowAccount:
        """Deposit funds to escrow."""
        account = self._get_or_create_account(owner)
        account.deposit(amount_wei)
        return account

    def get_balance(self, owner: str) -> int:
        """Get escrow balance for an owner."""
        account = self._get_or_create_account(owner)
        return account.balance_wei

    def block_settlement(self, task_id: str, reason: str) -> None:
        """Block settlement for a task (e.g., DA failure)."""
        self._blocked_tasks.add(task_id)
        logger.warning(f"Settlement blocked for task {task_id}: {reason}")

    def unblock_settlement(self, task_id: str) -> None:
        """Unblock settlement for a task."""
        self._blocked_tasks.discard(task_id)
        logger.info(f"Settlement unblocked for task {task_id}")

    def is_settlement_blocked(self, task_id: str) -> bool:
        """Check if settlement is blocked for a task."""
        return task_id in self._blocked_tasks

    def can_finalize(self, task: VerificationTask) -> tuple[bool, str]:
        """
        Check if a task can be finalized.

        Returns (can_finalize, reason).
        """
        # Check state
        if task.state != TaskState.SUBMITTED:
            return False, f"Task in state {task.state}, expected SUBMITTED"

        # Check DA block
        if self.is_settlement_blocked(task.task_id):
            return False, "Settlement blocked due to DA failure"

        # Check challenge period
        if task.submitted_at:
            challenge_end = task.submitted_at + timedelta(
                hours=self.config.min_challenge_period_hours
            )
            if datetime.now(UTC) < challenge_end:
                return False, f"Challenge period not ended (ends at {challenge_end.isoformat()})"

        # Check for pending challenges
        if self.challenge_registry:
            pending = self.challenge_registry.get_challenges_for_task(task.task_id)
            pending_active = [c for c in pending if c.status == ChallengeStatus.PENDING]
            if pending_active:
                return False, f"{len(pending_active)} pending challenge(s)"

        return True, "OK"

    def finalize_verdict(self, task: VerificationTask) -> SettlementReceipt:
        """
        Finalize verdict and trigger payout.

        Args:
            task: The task to finalize

        Returns:
            Settlement receipt

        Raises:
            ValueError: If task cannot be finalized
        """
        can_finalize, reason = self.can_finalize(task)
        if not can_finalize:
            raise ValueError(f"Cannot finalize task {task.task_id}: {reason}")

        # Finalize task state
        task.finalize()

        # Calculate payout
        payout_wei = task.reward_wei

        # Create receipt
        receipt = SettlementReceipt(
            receipt_id="",  # Generated
            task_id=task.task_id,
            settlement_type="verdict",
            verifier=task.verifier or "",
            payout_wei=payout_wei,
            settled_at=datetime.now(UTC),
            court_type=self.config.court_type,
            arbiter=self.config.arbiter_pubkey,
            notes=f"Verdict: {task.verdict.outcome.value if task.verdict else 'unknown'}",
        )

        # Process payout
        if task.verifier and payout_wei > 0:
            verifier_account = self._get_or_create_account(task.verifier)
            self._protocol_account.transfer(verifier_account, payout_wei)

        self._receipts.append(receipt)
        logger.info(f"Finalized task {task.task_id}, payout {payout_wei} wei to {task.verifier}")

        return receipt

    def resolve_dispute(self, challenge: Challenge) -> DisputeResolution:
        """
        Resolve a challenge/dispute.

        This is the arbiter's action to determine if the challenge
        is upheld or rejected.

        Args:
            challenge: The challenge to resolve

        Returns:
            Dispute resolution record
        """
        if challenge.status != ChallengeStatus.PENDING:
            raise ValueError(f"Challenge {challenge.challenge_id} not pending")

        # Get associated task
        task = None
        if self.task_registry:
            task = self.task_registry.get_task(challenge.task_id)

        # For now, implement simple resolution logic
        # In production, this would involve arbiter review
        upheld = False  # Default to reject; real logic would analyze evidence

        slash_amount_wei = 0
        reward_amount_wei = 0

        if upheld:
            # Slash verifier
            if task and task.verifier:
                slash_amount_wei = task.stake_wei
                verifier_account = self._get_or_create_account(task.verifier)
                if verifier_account.balance_wei >= slash_amount_wei:
                    verifier_account.withdraw(slash_amount_wei)
                    self._protocol_account.deposit(slash_amount_wei)

            # Reward challenger
            reward_amount_wei = int(challenge.challenge_bond_wei * 2)  # 2x bond
            challenger_account = self._get_or_create_account(challenge.challenger)
            self._protocol_account.transfer(challenger_account, reward_amount_wei)

            # Update challenge
            if self.challenge_registry:
                self.challenge_registry.resolve_challenge(
                    challenge.challenge_id,
                    upheld=True,
                    reason="Evidence supports challenge",
                    arbiter=self.config.arbiter_pubkey,
                )
        else:
            # Reject challenge - challenger loses bond
            challenge.reject("Evidence does not support challenge", self.config.arbiter_pubkey)

            # Bond goes to verifier as compensation
            if task and task.verifier:
                verifier_account = self._get_or_create_account(task.verifier)
                self._protocol_account.transfer(verifier_account, challenge.challenge_bond_wei)

        resolution = DisputeResolution(
            resolution_id="",  # Generated
            challenge_id=challenge.challenge_id,
            task_id=challenge.task_id,
            upheld=upheld,
            verifier_slashed=upheld and slash_amount_wei > 0,
            challenger_rewarded=upheld and reward_amount_wei > 0,
            slash_amount_wei=slash_amount_wei,
            reward_amount_wei=reward_amount_wei,
            resolved_at=datetime.now(UTC),
            arbiter=self.config.arbiter_pubkey or "unknown",
            evidence_reviewed=[challenge.evidence.evidence_hash],
            reasoning="Automated resolution" if not upheld else "Challenge evidence verified",
        )

        self._resolutions.append(resolution)
        logger.info(
            f"Resolved dispute {challenge.challenge_id}: "
            f"{'upheld' if upheld else 'rejected'}"
        )

        return resolution

    def slash_verifier(
        self,
        task: VerificationTask,
        reason: str,
    ) -> SettlementReceipt:
        """
        Slash a verifier for failure (liveness, DA, mismatch).

        Args:
            task: The failed task
            reason: Reason for slashing

        Returns:
            Settlement receipt
        """
        if not task.verifier:
            raise ValueError("Task has no verifier to slash")

        # Slash stake
        slash_amount = task.stake_wei
        verifier_account = self._get_or_create_account(task.verifier)

        if verifier_account.balance_wei >= slash_amount:
            verifier_account.withdraw(slash_amount)
            self._protocol_account.deposit(slash_amount)

        # Update task state
        task.slash(reason)

        # Create receipt
        receipt = SettlementReceipt(
            receipt_id="",  # Generated
            task_id=task.task_id,
            settlement_type="slash",
            verifier=task.verifier,
            payout_wei=-slash_amount,  # Negative = slashed
            settled_at=datetime.now(UTC),
            court_type=self.config.court_type,
            arbiter=self.config.arbiter_pubkey,
            notes=f"Slashed: {reason}",
        )

        self._receipts.append(receipt)
        logger.warning(f"Slashed verifier {task.verifier} for task {task.task_id}: {reason}")

        return receipt

    def process_liveness_failures(self) -> list[SettlementReceipt]:
        """Process all overdue tasks by slashing verifiers."""
        receipts = []

        if self.task_registry:
            overdue = self.task_registry.get_overdue_tasks()
            for task in overdue:
                try:
                    receipt = self.slash_verifier(task, "Liveness deadline exceeded")
                    receipts.append(receipt)
                except Exception as e:
                    logger.error(f"Failed to slash task {task.task_id}: {e}")

        return receipts

    def get_receipts(
        self,
        task_id: str | None = None,
        verifier: str | None = None,
        limit: int = 100,
    ) -> list[SettlementReceipt]:
        """Get settlement receipts with optional filters."""
        receipts = self._receipts

        if task_id:
            receipts = [r for r in receipts if r.task_id == task_id]
        if verifier:
            receipts = [r for r in receipts if r.verifier == verifier]

        return receipts[-limit:]

    def get_resolutions(
        self,
        challenge_id: str | None = None,
        limit: int = 100,
    ) -> list[DisputeResolution]:
        """Get dispute resolutions with optional filters."""
        resolutions = self._resolutions

        if challenge_id:
            resolutions = [r for r in resolutions if r.challenge_id == challenge_id]

        return resolutions[-limit:]

    def generate_audit_log(self) -> dict[str, Any]:
        """Generate audit log of all court activity."""
        return {
            "config": self.config.to_dict(),
            "accounts": {k: v.to_dict() for k, v in self._accounts.items()},
            "protocol_balance_wei": self._protocol_account.balance_wei,
            "total_receipts": len(self._receipts),
            "total_resolutions": len(self._resolutions),
            "blocked_tasks": list(self._blocked_tasks),
            "receipts": [r.to_dict() for r in self._receipts[-100:]],
            "resolutions": [r.to_dict() for r in self._resolutions[-100:]],
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize court state."""
        return self.generate_audit_log()


def create_court(
    court_type: CourtType = CourtType.OFFCHAIN,
    arbiter_pubkey: str | None = None,
    task_registry: TaskRegistry | None = None,
    challenge_registry: ChallengeRegistry | None = None,
) -> SettlementCourt:
    """
    Factory function to create a settlement court.

    Args:
        court_type: Type of court (offchain, ethereum, solana)
        arbiter_pubkey: Public key of arbiter (for offchain)
        task_registry: Optional task registry
        challenge_registry: Optional challenge registry

    Returns:
        Configured SettlementCourt
    """
    config = CourtConfig(
        court_type=court_type,
        arbiter_pubkey=arbiter_pubkey,
    )

    return SettlementCourt(
        config=config,
        task_registry=task_registry,
        challenge_registry=challenge_registry,
    )
