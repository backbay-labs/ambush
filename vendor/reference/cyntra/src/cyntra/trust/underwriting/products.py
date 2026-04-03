"""
Coverage products for the verification market.

Defines coverage types, limits, and circuit breaker logic
for the insurance layer.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class CoverageType(str, Enum):
    """Types of verification coverage."""

    SLASH_PROTECTION = "slash_protection"  # Covers verifier slashing
    DISPUTE_DEFENSE = "dispute_defense"  # Covers dispute resolution costs
    LIVENESS_GUARANTEE = "liveness_guarantee"  # Covers liveness failures
    COMPREHENSIVE = "comprehensive"  # All coverage types


class CircuitBreakerState(str, Enum):
    """State of a circuit breaker."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Tripped, blocking new coverage
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CoverageLimit:
    """Coverage limit configuration."""

    max_per_task_wei: int  # Maximum coverage per task
    max_per_bundle_wei: int  # Maximum coverage per bundle
    max_per_verifier_wei: int  # Maximum coverage per verifier
    max_total_wei: int  # Maximum total outstanding coverage

    # Concentration limits
    max_job_family_share_bps: int = 5000  # Max 50% to one job family
    max_tier_share_bps: int = 5000  # Max 50% to one tier

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_per_task_wei": self.max_per_task_wei,
            "max_per_bundle_wei": self.max_per_bundle_wei,
            "max_per_verifier_wei": self.max_per_verifier_wei,
            "max_total_wei": self.max_total_wei,
            "max_job_family_share_bps": self.max_job_family_share_bps,
            "max_tier_share_bps": self.max_tier_share_bps,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CoverageLimit:
        return cls(**data)


@dataclass
class CircuitBreakerConfig:
    """Configuration for a circuit breaker."""

    name: str
    description: str = ""

    # Trip conditions (any triggers the breaker)
    max_loss_rate_bps: int = 500  # Trip if loss rate > 5%
    max_dispute_rate_bps: int = 1000  # Trip if dispute rate > 10%
    max_consecutive_losses: int = 5  # Trip on 5 consecutive losses
    max_loss_amount_wei: int = 0  # Trip on single large loss (0 = disabled)

    # Recovery parameters
    cooldown_seconds: int = 3600  # 1 hour cooldown
    recovery_threshold_tasks: int = 10  # Tasks without issues to recover
    auto_reset: bool = True  # Automatically attempt recovery

    # Severity
    pause_new_coverage: bool = True  # Block new coverage when tripped
    pause_claims: bool = False  # Block claim payouts when tripped
    require_manual_reset: bool = False  # Require admin intervention

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "max_loss_rate_bps": self.max_loss_rate_bps,
            "max_dispute_rate_bps": self.max_dispute_rate_bps,
            "max_consecutive_losses": self.max_consecutive_losses,
            "max_loss_amount_wei": self.max_loss_amount_wei,
            "cooldown_seconds": self.cooldown_seconds,
            "recovery_threshold_tasks": self.recovery_threshold_tasks,
            "auto_reset": self.auto_reset,
            "pause_new_coverage": self.pause_new_coverage,
            "pause_claims": self.pause_claims,
            "require_manual_reset": self.require_manual_reset,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CircuitBreakerConfig:
        return cls(**data)


@dataclass
class CircuitBreaker:
    """
    Circuit breaker for coverage products.

    Monitors metrics and trips to halt operations when
    thresholds are exceeded, protecting the pool from
    cascading losses.
    """

    config: CircuitBreakerConfig
    state: CircuitBreakerState = CircuitBreakerState.CLOSED

    # Tracking
    tripped_at: datetime | None = None
    trip_reason: str = ""
    consecutive_losses: int = 0
    recent_loss_rate_bps: int = 0
    recent_dispute_rate_bps: int = 0

    # Recovery tracking
    recovery_started_at: datetime | None = None
    successful_tasks_since_trip: int = 0

    def check_and_trip(
        self,
        loss_rate_bps: int = 0,
        dispute_rate_bps: int = 0,
        loss_amount_wei: int = 0,
        is_loss: bool = False,
    ) -> bool:
        """
        Check conditions and trip if needed.

        Args:
            loss_rate_bps: Current loss rate
            dispute_rate_bps: Current dispute rate
            loss_amount_wei: Amount of current loss
            is_loss: Whether this check is for a loss event

        Returns:
            True if breaker tripped
        """
        if self.state == CircuitBreakerState.OPEN:
            return False  # Already tripped

        self.recent_loss_rate_bps = loss_rate_bps
        self.recent_dispute_rate_bps = dispute_rate_bps

        # Track consecutive losses
        if is_loss:
            self.consecutive_losses += 1
        else:
            self.consecutive_losses = 0

        # Check trip conditions
        trip_reason = None

        if loss_rate_bps > self.config.max_loss_rate_bps:
            trip_reason = f"Loss rate {loss_rate_bps} bps exceeds max {self.config.max_loss_rate_bps} bps"

        elif dispute_rate_bps > self.config.max_dispute_rate_bps:
            trip_reason = f"Dispute rate {dispute_rate_bps} bps exceeds max {self.config.max_dispute_rate_bps} bps"

        elif self.consecutive_losses >= self.config.max_consecutive_losses:
            trip_reason = f"Consecutive losses ({self.consecutive_losses}) exceeded threshold"

        elif self.config.max_loss_amount_wei and loss_amount_wei > self.config.max_loss_amount_wei:
            trip_reason = f"Single loss {loss_amount_wei} wei exceeds max {self.config.max_loss_amount_wei} wei"

        if trip_reason:
            self._trip(trip_reason)
            return True

        return False

    def _trip(self, reason: str) -> None:
        """Trip the circuit breaker."""
        self.state = CircuitBreakerState.OPEN
        self.tripped_at = datetime.now(UTC)
        self.trip_reason = reason
        self.successful_tasks_since_trip = 0
        logger.warning(f"Circuit breaker {self.config.name} tripped: {reason}")

    def attempt_recovery(self) -> bool:
        """
        Attempt to recover from tripped state.

        Returns:
            True if recovery started or completed
        """
        if self.state == CircuitBreakerState.CLOSED:
            return True  # Already recovered

        if self.config.require_manual_reset:
            return False  # Manual intervention required

        now = datetime.now(UTC)

        # Check cooldown
        if self.tripped_at:
            elapsed = (now - self.tripped_at).total_seconds()
            if elapsed < self.config.cooldown_seconds:
                return False  # Still in cooldown

        # Enter half-open state to test recovery
        if self.state == CircuitBreakerState.OPEN:
            self.state = CircuitBreakerState.HALF_OPEN
            self.recovery_started_at = now
            logger.info(f"Circuit breaker {self.config.name} entering half-open state")
            return True

        return False

    def record_successful_task(self) -> bool:
        """
        Record a successful task during recovery.

        Returns:
            True if breaker fully recovered
        """
        if self.state != CircuitBreakerState.HALF_OPEN:
            return self.state == CircuitBreakerState.CLOSED

        self.successful_tasks_since_trip += 1

        if self.successful_tasks_since_trip >= self.config.recovery_threshold_tasks:
            self.reset()
            return True

        return False

    def record_failure(self) -> None:
        """Record a failure during recovery - re-trip the breaker."""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self._trip("Failure during recovery period")

    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        self.state = CircuitBreakerState.CLOSED
        self.tripped_at = None
        self.trip_reason = ""
        self.consecutive_losses = 0
        self.recovery_started_at = None
        self.successful_tasks_since_trip = 0
        logger.info(f"Circuit breaker {self.config.name} reset")

    @property
    def is_accepting_coverage(self) -> bool:
        """Check if new coverage can be issued."""
        if self.state == CircuitBreakerState.CLOSED:
            return True
        if self.state == CircuitBreakerState.HALF_OPEN:
            return True  # Allow limited coverage during recovery
        return not self.config.pause_new_coverage

    @property
    def is_processing_claims(self) -> bool:
        """Check if claims can be processed."""
        if self.state == CircuitBreakerState.CLOSED:
            return True
        return not self.config.pause_claims

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "state": self.state.value,
            "tripped_at": self.tripped_at.isoformat() if self.tripped_at else None,
            "trip_reason": self.trip_reason,
            "consecutive_losses": self.consecutive_losses,
            "recent_loss_rate_bps": self.recent_loss_rate_bps,
            "recent_dispute_rate_bps": self.recent_dispute_rate_bps,
            "recovery_started_at": self.recovery_started_at.isoformat() if self.recovery_started_at else None,
            "successful_tasks_since_trip": self.successful_tasks_since_trip,
        }


@dataclass
class CoverageProduct:
    """
    A verification coverage product.

    Defines the terms, pricing, and limits for a type of coverage
    offered to verifiers.
    """

    product_id: str
    name: str
    coverage_type: CoverageType
    description: str = ""

    # Pricing
    premium_rate_bps: int = 100  # Premium as % of coverage (1%)
    deductible_bps: int = 500  # Deductible as % of coverage (5%)

    # Limits
    limits: CoverageLimit = field(default_factory=lambda: CoverageLimit(
        max_per_task_wei=100_000_000_000_000_000,  # 0.1 ETH
        max_per_bundle_wei=1_000_000_000_000_000_000,  # 1 ETH
        max_per_verifier_wei=10_000_000_000_000_000_000,  # 10 ETH
        max_total_wei=100_000_000_000_000_000_000,  # 100 ETH
    ))

    # Circuit breaker
    circuit_breaker: CircuitBreaker | None = None

    # Eligibility
    min_verifier_reputation: int = 0  # Minimum reputation score
    min_stake_wei: int = 0  # Minimum stake requirement
    allowed_tiers: list[int] = field(default_factory=lambda: [0, 1, 2])
    allowed_job_families: list[str] = field(default_factory=list)  # Empty = all

    # Status
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    effective_from: datetime = field(default_factory=lambda: datetime.now(UTC))
    effective_until: datetime | None = None

    # Tracking
    total_coverage_issued_wei: int = 0
    total_claims_paid_wei: int = 0
    active_coverage_count: int = 0

    def __post_init__(self) -> None:
        if self.circuit_breaker is None:
            self.circuit_breaker = CircuitBreaker(
                config=CircuitBreakerConfig(name=f"cb_{self.product_id}")
            )

    @property
    def loss_ratio_bps(self) -> int:
        """Loss ratio (claims paid / premiums collected) in basis points."""
        if self.total_coverage_issued_wei == 0:
            return 0
        premiums = int(self.total_coverage_issued_wei * self.premium_rate_bps / 10_000)
        if premiums == 0:
            return 0
        return int(10_000 * self.total_claims_paid_wei / premiums)

    @property
    def is_expired(self) -> bool:
        if self.effective_until is None:
            return False
        return datetime.now(UTC) > self.effective_until

    def can_issue_coverage(
        self,
        amount_wei: int,
        tier: int,
        job_family: str,
        verifier_reputation: int = 0,
        verifier_stake_wei: int = 0,
    ) -> tuple[bool, str | None]:
        """
        Check if coverage can be issued.

        Args:
            amount_wei: Coverage amount requested
            tier: Verification tier
            job_family: Job family
            verifier_reputation: Verifier's reputation score
            verifier_stake_wei: Verifier's current stake

        Returns:
            Tuple of (can_issue, reason_if_not)
        """
        if not self.is_active:
            return False, "Product is not active"

        if self.is_expired:
            return False, "Product has expired"

        if self.circuit_breaker and not self.circuit_breaker.is_accepting_coverage:
            return False, f"Circuit breaker tripped: {self.circuit_breaker.trip_reason}"

        # Check tier eligibility
        if tier not in self.allowed_tiers:
            return False, f"Tier {tier} not eligible for this product"

        # Check job family eligibility
        if self.allowed_job_families and job_family not in self.allowed_job_families:
            return False, f"Job family {job_family} not eligible for this product"

        # Check verifier eligibility
        if verifier_reputation < self.min_verifier_reputation:
            return False, f"Verifier reputation {verifier_reputation} below minimum {self.min_verifier_reputation}"

        if verifier_stake_wei < self.min_stake_wei:
            return False, f"Verifier stake below minimum {self.min_stake_wei}"

        # Check limits
        if amount_wei > self.limits.max_per_task_wei:
            return False, f"Amount exceeds per-task limit of {self.limits.max_per_task_wei}"

        # Check total coverage capacity
        remaining = self.limits.max_total_wei - self.total_coverage_issued_wei
        if amount_wei > remaining:
            return False, f"Amount exceeds remaining capacity of {remaining}"

        return True, None

    def calculate_premium(self, coverage_wei: int) -> int:
        """Calculate premium for coverage amount."""
        return int(coverage_wei * self.premium_rate_bps / 10_000)

    def calculate_deductible(self, coverage_wei: int) -> int:
        """Calculate deductible for coverage amount."""
        return int(coverage_wei * self.deductible_bps / 10_000)

    def issue_coverage(self, amount_wei: int) -> None:
        """Record coverage issuance."""
        self.total_coverage_issued_wei += amount_wei
        self.active_coverage_count += 1

    def expire_coverage(self, amount_wei: int) -> None:
        """Record coverage expiration (no claim)."""
        self.active_coverage_count = max(0, self.active_coverage_count - 1)

    def pay_claim(self, coverage_wei: int, claim_wei: int) -> None:
        """Record claim payment."""
        self.total_claims_paid_wei += claim_wei
        self.active_coverage_count = max(0, self.active_coverage_count - 1)

        # Update circuit breaker
        if self.circuit_breaker:
            loss_rate = int(10_000 * self.total_claims_paid_wei / max(1, self.total_coverage_issued_wei))
            self.circuit_breaker.check_and_trip(
                loss_rate_bps=loss_rate,
                loss_amount_wei=claim_wei,
                is_loss=True,
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "product_id": self.product_id,
            "name": self.name,
            "coverage_type": self.coverage_type.value,
            "description": self.description,
            "premium_rate_bps": self.premium_rate_bps,
            "deductible_bps": self.deductible_bps,
            "limits": self.limits.to_dict(),
            "circuit_breaker": self.circuit_breaker.to_dict() if self.circuit_breaker else None,
            "min_verifier_reputation": self.min_verifier_reputation,
            "min_stake_wei": self.min_stake_wei,
            "allowed_tiers": self.allowed_tiers,
            "allowed_job_families": self.allowed_job_families,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "effective_from": self.effective_from.isoformat(),
            "effective_until": self.effective_until.isoformat() if self.effective_until else None,
            "total_coverage_issued_wei": self.total_coverage_issued_wei,
            "total_claims_paid_wei": self.total_claims_paid_wei,
            "active_coverage_count": self.active_coverage_count,
            "loss_ratio_bps": self.loss_ratio_bps,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CoverageProduct:
        product = cls(
            product_id=data["product_id"],
            name=data["name"],
            coverage_type=CoverageType(data["coverage_type"]),
            description=data.get("description", ""),
            premium_rate_bps=data.get("premium_rate_bps", 100),
            deductible_bps=data.get("deductible_bps", 500),
            min_verifier_reputation=data.get("min_verifier_reputation", 0),
            min_stake_wei=data.get("min_stake_wei", 0),
            allowed_tiers=data.get("allowed_tiers", [0, 1, 2]),
            allowed_job_families=data.get("allowed_job_families", []),
            is_active=data.get("is_active", True),
            created_at=datetime.fromisoformat(data["created_at"]),
            effective_from=datetime.fromisoformat(data["effective_from"]),
            total_coverage_issued_wei=data.get("total_coverage_issued_wei", 0),
            total_claims_paid_wei=data.get("total_claims_paid_wei", 0),
            active_coverage_count=data.get("active_coverage_count", 0),
        )

        if data.get("limits"):
            product.limits = CoverageLimit.from_dict(data["limits"])
        if data.get("effective_until"):
            product.effective_until = datetime.fromisoformat(data["effective_until"])
        if data.get("circuit_breaker"):
            cb_data = data["circuit_breaker"]
            product.circuit_breaker = CircuitBreaker(
                config=CircuitBreakerConfig.from_dict(cb_data["config"]),
                state=CircuitBreakerState(cb_data["state"]),
            )

        return product


class ProductRegistry:
    """
    Registry of coverage products.

    Manages product lifecycle and lookup.
    """

    def __init__(self) -> None:
        self._products: dict[str, CoverageProduct] = {}

    def register(self, product: CoverageProduct) -> None:
        """Register a new product."""
        self._products[product.product_id] = product
        logger.info(f"Registered product: {product.product_id} - {product.name}")

    def get(self, product_id: str) -> CoverageProduct | None:
        """Get a product by ID."""
        return self._products.get(product_id)

    def get_by_type(self, coverage_type: CoverageType) -> list[CoverageProduct]:
        """Get all products of a type."""
        return [
            p for p in self._products.values()
            if p.coverage_type == coverage_type
        ]

    def get_active(self) -> list[CoverageProduct]:
        """Get all active, non-expired products."""
        return [
            p for p in self._products.values()
            if p.is_active and not p.is_expired
        ]

    def get_eligible_products(
        self,
        tier: int,
        job_family: str,
        amount_wei: int,
    ) -> list[CoverageProduct]:
        """Get products eligible for given parameters."""
        eligible = []
        for product in self.get_active():
            can_issue, _ = product.can_issue_coverage(
                amount_wei=amount_wei,
                tier=tier,
                job_family=job_family,
            )
            if can_issue:
                eligible.append(product)
        return eligible

    def deactivate(self, product_id: str) -> CoverageProduct | None:
        """Deactivate a product."""
        product = self._products.get(product_id)
        if product:
            product.is_active = False
            logger.info(f"Deactivated product: {product_id}")
        return product

    def check_circuit_breakers(self) -> list[tuple[str, str]]:
        """
        Check all circuit breakers for tripped products.

        Returns:
            List of (product_id, trip_reason) for tripped breakers
        """
        tripped = []
        for product in self._products.values():
            if product.circuit_breaker and product.circuit_breaker.state == CircuitBreakerState.OPEN:
                tripped.append((product.product_id, product.circuit_breaker.trip_reason))
        return tripped

    def attempt_recoveries(self) -> list[str]:
        """
        Attempt recovery on all tripped circuit breakers.

        Returns:
            List of product_ids that started/completed recovery
        """
        recovered = []
        for product in self._products.values():
            if product.circuit_breaker and product.circuit_breaker.state == CircuitBreakerState.OPEN:
                if product.circuit_breaker.config.auto_reset:
                    if product.circuit_breaker.attempt_recovery():
                        recovered.append(product.product_id)
        return recovered

    def to_dict(self) -> dict[str, Any]:
        return {
            "products": {k: v.to_dict() for k, v in self._products.items()},
            "active_count": len(self.get_active()),
            "tripped_breakers": self.check_circuit_breakers(),
        }
