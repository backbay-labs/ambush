"""
Tranching for the verification market capitalization layer.

Implements loss waterfall and tranche structures for risk stratification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class TrancheSeniority(str, Enum):
    """Seniority levels for tranches."""

    SENIOR = "senior"  # First loss protection, lowest yield
    MEZZANINE = "mezzanine"  # Middle tranche
    JUNIOR = "junior"  # Last loss, highest yield
    EQUITY = "equity"  # First loss, highest risk/reward


class TrancheStatus(str, Enum):
    """Status of a tranche."""

    OPEN = "open"  # Accepting deposits
    CLOSED = "closed"  # Not accepting deposits
    IMPAIRED = "impaired"  # Losses have occurred
    LIQUIDATING = "liquidating"  # Being wound down


@dataclass
class TrancheConfig:
    """
    Configuration for a tranche.

    Defines the risk/reward profile for a slice of the capital stack.
    """

    tranche_id: str
    name: str
    seniority: TrancheSeniority

    # Size limits
    min_size_wei: int = 0  # Minimum tranche size
    max_size_wei: int = 0  # Maximum tranche size (0 = unlimited)
    target_size_wei: int = 0  # Target size for optimal operation

    # Loss allocation (as % of tranche, in bps)
    attachment_point_bps: int = 0  # Losses above this % affect this tranche
    detachment_point_bps: int = 10000  # Losses above this % don't affect

    # Yield configuration
    base_yield_bps: int = 0  # Base annual yield in bps
    performance_fee_bps: int = 0  # Performance fee on excess returns
    hurdle_rate_bps: int = 0  # Minimum return before performance fee

    # Lock-up
    lock_period_days: int = 0  # Minimum lock-up period
    withdrawal_notice_days: int = 0  # Notice required for withdrawal

    @property
    def thickness_bps(self) -> int:
        """Thickness of the tranche (detachment - attachment)."""
        return self.detachment_point_bps - self.attachment_point_bps

    @property
    def base_yield(self) -> float:
        """Base yield as decimal."""
        return self.base_yield_bps / 10_000

    def loss_to_tranche(self, total_loss_bps: int) -> int:
        """
        Calculate how much of a loss affects this tranche.

        Args:
            total_loss_bps: Total loss as % of pool in bps

        Returns:
            Loss to this tranche in bps of tranche size
        """
        if total_loss_bps <= self.attachment_point_bps:
            return 0  # Loss below attachment point

        if total_loss_bps >= self.detachment_point_bps:
            return 10_000  # Entire tranche wiped out

        # Partial loss
        loss_in_tranche = total_loss_bps - self.attachment_point_bps
        return int(10_000 * loss_in_tranche / self.thickness_bps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tranche_id": self.tranche_id,
            "name": self.name,
            "seniority": self.seniority.value,
            "min_size_wei": self.min_size_wei,
            "max_size_wei": self.max_size_wei,
            "target_size_wei": self.target_size_wei,
            "attachment_point_bps": self.attachment_point_bps,
            "detachment_point_bps": self.detachment_point_bps,
            "base_yield_bps": self.base_yield_bps,
            "performance_fee_bps": self.performance_fee_bps,
            "hurdle_rate_bps": self.hurdle_rate_bps,
            "lock_period_days": self.lock_period_days,
            "withdrawal_notice_days": self.withdrawal_notice_days,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrancheConfig:
        return cls(
            tranche_id=data["tranche_id"],
            name=data["name"],
            seniority=TrancheSeniority(data["seniority"]),
            min_size_wei=data.get("min_size_wei", 0),
            max_size_wei=data.get("max_size_wei", 0),
            target_size_wei=data.get("target_size_wei", 0),
            attachment_point_bps=data.get("attachment_point_bps", 0),
            detachment_point_bps=data.get("detachment_point_bps", 10000),
            base_yield_bps=data.get("base_yield_bps", 0),
            performance_fee_bps=data.get("performance_fee_bps", 0),
            hurdle_rate_bps=data.get("hurdle_rate_bps", 0),
            lock_period_days=data.get("lock_period_days", 0),
            withdrawal_notice_days=data.get("withdrawal_notice_days", 0),
        )


@dataclass
class TranchePosition:
    """
    A position in a tranche.

    Represents an investor's share in a specific tranche.
    """

    position_id: str
    tranche_id: str
    investor: str  # Public key of investor
    amount_wei: int

    # Timing
    deposited_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    lock_expires_at: datetime | None = None
    withdrawal_requested_at: datetime | None = None
    withdrawn_at: datetime | None = None

    # Returns tracking
    accrued_yield_wei: int = 0
    realized_yield_wei: int = 0
    loss_absorbed_wei: int = 0

    # Status
    is_active: bool = True

    @property
    def is_locked(self) -> bool:
        if self.lock_expires_at is None:
            return False
        return datetime.now(UTC) < self.lock_expires_at

    @property
    def is_withdrawn(self) -> bool:
        return self.withdrawn_at is not None

    @property
    def current_value_wei(self) -> int:
        """Current value after yields and losses."""
        return max(0, self.amount_wei + self.accrued_yield_wei - self.loss_absorbed_wei)

    @property
    def net_return_bps(self) -> int:
        """Net return in basis points."""
        if self.amount_wei == 0:
            return 0
        net = self.accrued_yield_wei + self.realized_yield_wei - self.loss_absorbed_wei
        return int(10_000 * net / self.amount_wei)

    def accrue_yield(self, amount_wei: int) -> None:
        """Add accrued yield."""
        self.accrued_yield_wei += amount_wei

    def absorb_loss(self, amount_wei: int) -> int:
        """
        Absorb a loss.

        Args:
            amount_wei: Loss amount to absorb

        Returns:
            Amount actually absorbed (capped at position value)
        """
        available = self.current_value_wei
        absorbed = min(amount_wei, available)
        self.loss_absorbed_wei += absorbed
        return absorbed

    def to_dict(self) -> dict[str, Any]:
        return {
            "position_id": self.position_id,
            "tranche_id": self.tranche_id,
            "investor": self.investor,
            "amount_wei": self.amount_wei,
            "deposited_at": self.deposited_at.isoformat(),
            "lock_expires_at": self.lock_expires_at.isoformat() if self.lock_expires_at else None,
            "withdrawal_requested_at": self.withdrawal_requested_at.isoformat() if self.withdrawal_requested_at else None,
            "withdrawn_at": self.withdrawn_at.isoformat() if self.withdrawn_at else None,
            "accrued_yield_wei": self.accrued_yield_wei,
            "realized_yield_wei": self.realized_yield_wei,
            "loss_absorbed_wei": self.loss_absorbed_wei,
            "is_active": self.is_active,
            "current_value_wei": self.current_value_wei,
            "net_return_bps": self.net_return_bps,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TranchePosition:
        position = cls(
            position_id=data["position_id"],
            tranche_id=data["tranche_id"],
            investor=data["investor"],
            amount_wei=data["amount_wei"],
            deposited_at=datetime.fromisoformat(data["deposited_at"]),
            accrued_yield_wei=data.get("accrued_yield_wei", 0),
            realized_yield_wei=data.get("realized_yield_wei", 0),
            loss_absorbed_wei=data.get("loss_absorbed_wei", 0),
            is_active=data.get("is_active", True),
        )
        if data.get("lock_expires_at"):
            position.lock_expires_at = datetime.fromisoformat(data["lock_expires_at"])
        if data.get("withdrawal_requested_at"):
            position.withdrawal_requested_at = datetime.fromisoformat(data["withdrawal_requested_at"])
        if data.get("withdrawn_at"):
            position.withdrawn_at = datetime.fromisoformat(data["withdrawn_at"])
        return position


@dataclass
class WaterfallAllocation:
    """Result of a waterfall loss allocation."""

    total_loss_wei: int
    total_loss_bps: int  # As % of total pool
    allocations: dict[str, int]  # tranche_id -> loss_wei
    impaired_tranches: list[str]  # Tranches with losses
    wiped_tranches: list[str]  # Tranches fully wiped out
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_loss_wei": self.total_loss_wei,
            "total_loss_bps": self.total_loss_bps,
            "allocations": self.allocations,
            "impaired_tranches": self.impaired_tranches,
            "wiped_tranches": self.wiped_tranches,
            "timestamp": self.timestamp.isoformat(),
        }


class LossWaterfall:
    """
    Loss waterfall for allocating losses across tranches.

    Implements the standard credit waterfall where losses flow
    from junior to senior tranches.
    """

    def __init__(self, tranches: list[TrancheConfig]) -> None:
        # Sort by attachment point (junior first)
        self.tranches = sorted(tranches, key=lambda t: t.attachment_point_bps)

    def allocate_loss(
        self,
        loss_wei: int,
        tranche_balances: dict[str, int],
    ) -> WaterfallAllocation:
        """
        Allocate a loss across tranches.

        Args:
            loss_wei: Total loss amount
            tranche_balances: Current balance by tranche_id

        Returns:
            WaterfallAllocation with per-tranche losses
        """
        total_pool = sum(tranche_balances.values())
        if total_pool == 0:
            return WaterfallAllocation(
                total_loss_wei=loss_wei,
                total_loss_bps=10_000,
                allocations={},
                impaired_tranches=[],
                wiped_tranches=[],
            )

        total_loss_bps = int(10_000 * loss_wei / total_pool)
        allocations: dict[str, int] = {}
        impaired: list[str] = []
        wiped: list[str] = []
        remaining_loss = loss_wei

        # Allocate from junior to senior
        for tranche in self.tranches:
            if remaining_loss <= 0:
                allocations[tranche.tranche_id] = 0
                continue

            balance = tranche_balances.get(tranche.tranche_id, 0)
            if balance == 0:
                allocations[tranche.tranche_id] = 0
                continue

            # Calculate loss for this tranche
            tranche_loss_bps = tranche.loss_to_tranche(total_loss_bps)
            tranche_loss_wei = int(balance * tranche_loss_bps / 10_000)
            tranche_loss_wei = min(tranche_loss_wei, remaining_loss, balance)

            allocations[tranche.tranche_id] = tranche_loss_wei
            remaining_loss -= tranche_loss_wei

            if tranche_loss_wei > 0:
                impaired.append(tranche.tranche_id)

            if tranche_loss_wei >= balance:
                wiped.append(tranche.tranche_id)

        return WaterfallAllocation(
            total_loss_wei=loss_wei,
            total_loss_bps=total_loss_bps,
            allocations=allocations,
            impaired_tranches=impaired,
            wiped_tranches=wiped,
        )


class TranchingEngine:
    """
    Main engine for tranche management.

    Handles tranche configuration, position tracking, and loss allocation.
    """

    def __init__(self) -> None:
        self._tranches: dict[str, TrancheConfig] = {}
        self._positions: dict[str, TranchePosition] = {}
        self._by_tranche: dict[str, list[str]] = {}  # tranche_id -> position_ids
        self._by_investor: dict[str, list[str]] = {}  # investor -> position_ids
        self._tranche_status: dict[str, TrancheStatus] = {}

    def configure_tranche(self, config: TrancheConfig) -> None:
        """Configure a tranche."""
        self._tranches[config.tranche_id] = config
        self._tranche_status[config.tranche_id] = TrancheStatus.OPEN
        if config.tranche_id not in self._by_tranche:
            self._by_tranche[config.tranche_id] = []
        logger.info(f"Configured tranche: {config.tranche_id} - {config.name}")

    def get_tranche(self, tranche_id: str) -> TrancheConfig | None:
        """Get tranche configuration."""
        return self._tranches.get(tranche_id)

    def get_tranche_status(self, tranche_id: str) -> TrancheStatus | None:
        """Get tranche status."""
        return self._tranche_status.get(tranche_id)

    def set_tranche_status(self, tranche_id: str, status: TrancheStatus) -> None:
        """Set tranche status."""
        if tranche_id in self._tranches:
            self._tranche_status[tranche_id] = status
            logger.info(f"Tranche {tranche_id} status changed to {status.value}")

    def deposit(
        self,
        tranche_id: str,
        investor: str,
        amount_wei: int,
    ) -> TranchePosition:
        """
        Create a new position in a tranche.

        Args:
            tranche_id: Target tranche
            investor: Investor public key
            amount_wei: Deposit amount

        Returns:
            The created position

        Raises:
            ValueError: If tranche not found, closed, or limits exceeded
        """
        tranche = self._tranches.get(tranche_id)
        if not tranche:
            raise ValueError(f"Tranche not found: {tranche_id}")

        status = self._tranche_status.get(tranche_id)
        if status != TrancheStatus.OPEN:
            raise ValueError(f"Tranche is not open: {status}")

        # Check limits
        current_size = self.tranche_balance(tranche_id)
        if tranche.max_size_wei and current_size + amount_wei > tranche.max_size_wei:
            raise ValueError(f"Would exceed tranche max size: {tranche.max_size_wei}")

        # Create position with unique ID
        now = datetime.now(UTC)
        position_id = f"pos_{investor[:8]}_{tranche_id}_{now.strftime('%Y%m%d%H%M%S%f')}"
        position = TranchePosition(
            position_id=position_id,
            tranche_id=tranche_id,
            investor=investor,
            amount_wei=amount_wei,
        )

        # Apply lock period
        if tranche.lock_period_days > 0:
            from datetime import timedelta
            position.lock_expires_at = position.deposited_at + timedelta(days=tranche.lock_period_days)

        # Store
        self._positions[position_id] = position
        self._by_tranche.setdefault(tranche_id, []).append(position_id)
        self._by_investor.setdefault(investor, []).append(position_id)

        logger.info(f"Position created: {position_id} - {amount_wei} wei in {tranche_id}")
        return position

    def request_withdrawal(self, position_id: str) -> TranchePosition:
        """
        Request withdrawal of a position.

        Args:
            position_id: Position to withdraw

        Returns:
            Updated position

        Raises:
            ValueError: If position not found, locked, or already withdrawn
        """
        position = self._positions.get(position_id)
        if not position:
            raise ValueError(f"Position not found: {position_id}")

        if position.is_locked:
            raise ValueError(f"Position is locked until {position.lock_expires_at}")

        if position.is_withdrawn:
            raise ValueError("Position already withdrawn")

        position.withdrawal_requested_at = datetime.now(UTC)
        return position

    def complete_withdrawal(self, position_id: str) -> TranchePosition:
        """
        Complete a withdrawal.

        Args:
            position_id: Position to complete

        Returns:
            Updated position
        """
        position = self._positions.get(position_id)
        if not position:
            raise ValueError(f"Position not found: {position_id}")

        tranche = self._tranches.get(position.tranche_id)
        if tranche and position.withdrawal_requested_at:
            # Check notice period
            from datetime import timedelta
            notice_end = position.withdrawal_requested_at + timedelta(days=tranche.withdrawal_notice_days)
            if datetime.now(UTC) < notice_end:
                raise ValueError(f"Notice period not complete until {notice_end}")

        position.realized_yield_wei += position.accrued_yield_wei
        position.accrued_yield_wei = 0
        position.withdrawn_at = datetime.now(UTC)
        position.is_active = False

        return position

    def get_position(self, position_id: str) -> TranchePosition | None:
        """Get a position by ID."""
        return self._positions.get(position_id)

    def get_positions_by_investor(self, investor: str) -> list[TranchePosition]:
        """Get all positions for an investor."""
        position_ids = self._by_investor.get(investor, [])
        return [self._positions[pid] for pid in position_ids if pid in self._positions]

    def get_positions_by_tranche(self, tranche_id: str) -> list[TranchePosition]:
        """Get all positions in a tranche."""
        position_ids = self._by_tranche.get(tranche_id, [])
        return [self._positions[pid] for pid in position_ids if pid in self._positions]

    def tranche_balance(self, tranche_id: str) -> int:
        """Get total balance of active positions in a tranche."""
        positions = self.get_positions_by_tranche(tranche_id)
        return sum(p.current_value_wei for p in positions if p.is_active)

    def total_balance(self) -> int:
        """Get total balance across all tranches."""
        return sum(
            p.current_value_wei
            for p in self._positions.values()
            if p.is_active
        )

    def distribute_yield(self, tranche_id: str, yield_wei: int) -> dict[str, int]:
        """
        Distribute yield to positions in a tranche.

        Yield is distributed proportionally to position size.

        Args:
            tranche_id: Target tranche
            yield_wei: Total yield to distribute

        Returns:
            Dict of position_id -> yield_wei
        """
        positions = [p for p in self.get_positions_by_tranche(tranche_id) if p.is_active]
        if not positions:
            return {}

        total = sum(p.amount_wei for p in positions)
        if total == 0:
            return {}

        distribution: dict[str, int] = {}
        for position in positions:
            share = int(yield_wei * position.amount_wei / total)
            position.accrue_yield(share)
            distribution[position.position_id] = share

        return distribution

    def process_loss(self, loss_wei: int) -> WaterfallAllocation:
        """
        Process a loss through the waterfall.

        Args:
            loss_wei: Total loss amount

        Returns:
            WaterfallAllocation showing how loss was distributed
        """
        # Get current balances
        balances = {tid: self.tranche_balance(tid) for tid in self._tranches}

        # Create waterfall and allocate
        waterfall = LossWaterfall(list(self._tranches.values()))
        allocation = waterfall.allocate_loss(loss_wei, balances)

        # Apply losses to positions
        for tranche_id, tranche_loss in allocation.allocations.items():
            if tranche_loss <= 0:
                continue

            positions = [p for p in self.get_positions_by_tranche(tranche_id) if p.is_active]
            if not positions:
                continue

            tranche_total = sum(p.current_value_wei for p in positions)
            if tranche_total == 0:
                continue

            # Distribute loss proportionally
            remaining = tranche_loss
            for position in positions:
                share = int(tranche_loss * position.current_value_wei / tranche_total)
                absorbed = position.absorb_loss(min(share, remaining))
                remaining -= absorbed

        # Update tranche statuses
        for tranche_id in allocation.impaired_tranches:
            if tranche_id not in allocation.wiped_tranches:
                self.set_tranche_status(tranche_id, TrancheStatus.IMPAIRED)

        for tranche_id in allocation.wiped_tranches:
            self.set_tranche_status(tranche_id, TrancheStatus.LIQUIDATING)

        logger.info(f"Loss processed: {loss_wei} wei across {len(allocation.impaired_tranches)} tranches")
        return allocation

    def get_tranche_summary(self, tranche_id: str) -> dict[str, Any]:
        """Get summary statistics for a tranche."""
        tranche = self._tranches.get(tranche_id)
        if not tranche:
            return {}

        positions = [p for p in self.get_positions_by_tranche(tranche_id) if p.is_active]
        balance = self.tranche_balance(tranche_id)

        return {
            "tranche_id": tranche_id,
            "name": tranche.name,
            "seniority": tranche.seniority.value,
            "status": self._tranche_status.get(tranche_id, TrancheStatus.OPEN).value,
            "balance_wei": balance,
            "position_count": len(positions),
            "attachment_point_bps": tranche.attachment_point_bps,
            "detachment_point_bps": tranche.detachment_point_bps,
            "base_yield_bps": tranche.base_yield_bps,
            "utilization_bps": int(10_000 * balance / tranche.target_size_wei) if tranche.target_size_wei else 0,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tranches": {k: v.to_dict() for k, v in self._tranches.items()},
            "tranche_status": {k: v.value for k, v in self._tranche_status.items()},
            "positions": {k: v.to_dict() for k, v in self._positions.items()},
            "total_balance_wei": self.total_balance(),
        }
