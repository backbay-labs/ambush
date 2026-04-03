"""
Loss curve modeling for verification market pricing.

Loss curves model the relationship between verification tier,
job complexity, and expected dispute/slash rates over time.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class LossSeverity(str, Enum):
    """Severity levels for loss events."""

    LOW = "low"  # Minor dispute, partial resolution
    MEDIUM = "medium"  # Standard dispute, full resolution
    HIGH = "high"  # Severe mismatch, slashing
    CRITICAL = "critical"  # Systemic failure, emergency response


@dataclass
class LossCurvePoint:
    """
    A single point on a loss curve.

    Represents the expected loss rate at a specific time horizon
    for a given tier and job family combination.
    """

    horizon_days: int  # Time horizon in days
    loss_rate_bps: int  # Loss rate in basis points (1 bps = 0.01%)
    confidence_lower_bps: int = 0  # Lower bound of confidence interval
    confidence_upper_bps: int = 0  # Upper bound of confidence interval
    sample_size: int = 0  # Number of observations used

    @property
    def loss_rate(self) -> float:
        """Loss rate as a decimal (e.g., 0.0015 for 15 bps)."""
        return self.loss_rate_bps / 10_000

    @property
    def confidence_interval(self) -> tuple[float, float]:
        """Confidence interval as decimals."""
        return (
            self.confidence_lower_bps / 10_000,
            self.confidence_upper_bps / 10_000,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon_days": self.horizon_days,
            "loss_rate_bps": self.loss_rate_bps,
            "confidence_lower_bps": self.confidence_lower_bps,
            "confidence_upper_bps": self.confidence_upper_bps,
            "sample_size": self.sample_size,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LossCurvePoint:
        return cls(
            horizon_days=data["horizon_days"],
            loss_rate_bps=data["loss_rate_bps"],
            confidence_lower_bps=data.get("confidence_lower_bps", 0),
            confidence_upper_bps=data.get("confidence_upper_bps", 0),
            sample_size=data.get("sample_size", 0),
        )


@dataclass
class LossCurveData:
    """
    Loss curve data for a specific tier and job family.

    Loss curves are built from historical dispute data and used
    to price verification coverage. Each curve contains points
    at various time horizons (7d, 30d, 90d, 365d).
    """

    curve_id: str
    tier: int  # Verification tier (0=spot-check, 1=full replay, 2=multi-verifier)
    job_family: str  # Job family (e.g., "smart_contract_audit", "ml_model_training")
    points: list[LossCurvePoint] = field(default_factory=list)

    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    version: int = 1
    is_active: bool = True

    # Actuarial parameters
    base_loss_rate_bps: int = 50  # Base loss rate (50 bps = 0.5%)
    volatility_multiplier: float = 1.0  # Adjusts for uncertainty
    tail_risk_factor: float = 1.5  # For extreme loss scenarios

    def get_loss_rate_at_horizon(self, days: int) -> float | None:
        """
        Get the loss rate at a specific horizon.

        Returns None if no exact match; use interpolate_loss_rate for estimates.
        """
        for point in self.points:
            if point.horizon_days == days:
                return point.loss_rate
        return None

    def add_point(self, point: LossCurvePoint) -> None:
        """Add a point to the curve, replacing any existing point at same horizon."""
        self.points = [p for p in self.points if p.horizon_days != point.horizon_days]
        self.points.append(point)
        self.points.sort(key=lambda p: p.horizon_days)
        self.updated_at = datetime.now(UTC)
        self.version += 1

    @property
    def horizons(self) -> list[int]:
        """List of available time horizons."""
        return [p.horizon_days for p in self.points]

    @property
    def max_horizon(self) -> int:
        """Maximum available time horizon."""
        return max(self.horizons) if self.horizons else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "curve_id": self.curve_id,
            "tier": self.tier,
            "job_family": self.job_family,
            "points": [p.to_dict() for p in self.points],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version,
            "is_active": self.is_active,
            "base_loss_rate_bps": self.base_loss_rate_bps,
            "volatility_multiplier": self.volatility_multiplier,
            "tail_risk_factor": self.tail_risk_factor,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LossCurveData:
        curve = cls(
            curve_id=data["curve_id"],
            tier=data["tier"],
            job_family=data["job_family"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            version=data.get("version", 1),
            is_active=data.get("is_active", True),
            base_loss_rate_bps=data.get("base_loss_rate_bps", 50),
            volatility_multiplier=data.get("volatility_multiplier", 1.0),
            tail_risk_factor=data.get("tail_risk_factor", 1.5),
        )
        curve.points = [LossCurvePoint.from_dict(p) for p in data.get("points", [])]
        return curve


@dataclass
class PremiumTier:
    """Premium tier with rate and limits."""

    tier_name: str
    base_rate_bps: int  # Premium rate in basis points
    min_coverage_wei: int = 0  # Minimum coverage amount
    max_coverage_wei: int = 0  # Maximum coverage amount (0 = unlimited)
    deductible_bps: int = 0  # Deductible as percentage of coverage
    coverage_multiplier: float = 1.0  # Coverage limit multiplier

    @property
    def base_rate(self) -> float:
        """Base rate as a decimal."""
        return self.base_rate_bps / 10_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier_name": self.tier_name,
            "base_rate_bps": self.base_rate_bps,
            "min_coverage_wei": self.min_coverage_wei,
            "max_coverage_wei": self.max_coverage_wei,
            "deductible_bps": self.deductible_bps,
            "coverage_multiplier": self.coverage_multiplier,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PremiumTier:
        return cls(
            tier_name=data["tier_name"],
            base_rate_bps=data["base_rate_bps"],
            min_coverage_wei=data.get("min_coverage_wei", 0),
            max_coverage_wei=data.get("max_coverage_wei", 0),
            deductible_bps=data.get("deductible_bps", 0),
            coverage_multiplier=data.get("coverage_multiplier", 1.0),
        )


@dataclass
class PremiumSchedule:
    """
    Premium schedule for a job family.

    Defines the premium tiers and pricing rules for verification coverage.
    """

    schedule_id: str
    job_family: str
    tiers: list[PremiumTier] = field(default_factory=list)

    # Schedule parameters
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    effective_from: datetime = field(default_factory=lambda: datetime.now(UTC))
    effective_until: datetime | None = None
    is_active: bool = True

    # Risk adjustments
    experience_modifier: float = 1.0  # Based on historical performance
    volume_discount_threshold: int = 100  # Tasks before discount applies
    volume_discount_rate: float = 0.9  # 10% discount above threshold

    def get_tier(self, tier_name: str) -> PremiumTier | None:
        """Get a premium tier by name."""
        for tier in self.tiers:
            if tier.tier_name == tier_name:
                return tier
        return None

    def add_tier(self, tier: PremiumTier) -> None:
        """Add or replace a premium tier."""
        self.tiers = [t for t in self.tiers if t.tier_name != tier.tier_name]
        self.tiers.append(tier)

    def calculate_premium(
        self,
        tier_name: str,
        coverage_wei: int,
        task_count: int = 0,
    ) -> int:
        """
        Calculate premium for coverage.

        Args:
            tier_name: Name of the premium tier
            coverage_wei: Coverage amount in wei
            task_count: Number of previous tasks (for volume discount)

        Returns:
            Premium amount in wei
        """
        tier = self.get_tier(tier_name)
        if not tier:
            raise ValueError(f"Unknown tier: {tier_name}")

        # Validate coverage limits
        if tier.min_coverage_wei and coverage_wei < tier.min_coverage_wei:
            raise ValueError(f"Coverage below minimum: {tier.min_coverage_wei}")
        if tier.max_coverage_wei and coverage_wei > tier.max_coverage_wei:
            raise ValueError(f"Coverage above maximum: {tier.max_coverage_wei}")

        # Base premium
        base_premium = int(coverage_wei * tier.base_rate)

        # Apply experience modifier
        adjusted_premium = int(base_premium * self.experience_modifier)

        # Apply volume discount if applicable
        if task_count >= self.volume_discount_threshold:
            adjusted_premium = int(adjusted_premium * self.volume_discount_rate)

        return adjusted_premium

    @property
    def is_expired(self) -> bool:
        """Check if schedule has expired."""
        if self.effective_until is None:
            return False
        return datetime.now(UTC) > self.effective_until

    def to_dict(self) -> dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "job_family": self.job_family,
            "tiers": [t.to_dict() for t in self.tiers],
            "created_at": self.created_at.isoformat(),
            "effective_from": self.effective_from.isoformat(),
            "effective_until": self.effective_until.isoformat() if self.effective_until else None,
            "is_active": self.is_active,
            "experience_modifier": self.experience_modifier,
            "volume_discount_threshold": self.volume_discount_threshold,
            "volume_discount_rate": self.volume_discount_rate,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PremiumSchedule:
        schedule = cls(
            schedule_id=data["schedule_id"],
            job_family=data["job_family"],
            created_at=datetime.fromisoformat(data["created_at"]),
            effective_from=datetime.fromisoformat(data["effective_from"]),
            effective_until=(
                datetime.fromisoformat(data["effective_until"])
                if data.get("effective_until")
                else None
            ),
            is_active=data.get("is_active", True),
            experience_modifier=data.get("experience_modifier", 1.0),
            volume_discount_threshold=data.get("volume_discount_threshold", 100),
            volume_discount_rate=data.get("volume_discount_rate", 0.9),
        )
        schedule.tiers = [PremiumTier.from_dict(t) for t in data.get("tiers", [])]
        return schedule


def interpolate_loss_rate(curve: LossCurveData, target_days: int) -> float:
    """
    Interpolate loss rate for a target horizon.

    Uses linear interpolation between adjacent curve points.
    Extrapolates using the tail risk factor for horizons beyond the curve.

    Args:
        curve: Loss curve data
        target_days: Target time horizon in days

    Returns:
        Interpolated loss rate as a decimal
    """
    if not curve.points:
        return curve.base_loss_rate_bps / 10_000

    # Find bracketing points
    lower: LossCurvePoint | None = None
    upper: LossCurvePoint | None = None

    for point in sorted(curve.points, key=lambda p: p.horizon_days):
        if point.horizon_days <= target_days:
            lower = point
        elif upper is None:
            upper = point

    # Exact match
    if lower and lower.horizon_days == target_days:
        return lower.loss_rate

    # Extrapolate below minimum horizon
    if lower is None and upper:
        # Scale down proportionally from the first point
        ratio = target_days / upper.horizon_days
        return upper.loss_rate * ratio

    # Extrapolate beyond maximum horizon
    if lower and upper is None:
        # Apply tail risk factor for extrapolation
        extra_days = target_days - lower.horizon_days
        base_rate = lower.loss_rate
        # Assume loss rate grows with square root of time beyond horizon
        growth_factor = 1 + (extra_days / lower.horizon_days) ** 0.5 * (curve.tail_risk_factor - 1)
        return base_rate * growth_factor

    # Linear interpolation
    if lower and upper:
        ratio = (target_days - lower.horizon_days) / (upper.horizon_days - lower.horizon_days)
        return lower.loss_rate + ratio * (upper.loss_rate - lower.loss_rate)

    # Fallback to base rate
    return curve.base_loss_rate_bps / 10_000


def compute_expected_loss(
    curve: LossCurveData,
    coverage_wei: int,
    horizon_days: int,
    confidence_level: float = 0.95,
) -> tuple[int, int, int]:
    """
    Compute expected loss with confidence bounds.

    Args:
        curve: Loss curve data
        coverage_wei: Coverage amount in wei
        horizon_days: Time horizon in days
        confidence_level: Confidence level for bounds (e.g., 0.95)

    Returns:
        Tuple of (expected_loss_wei, lower_bound_wei, upper_bound_wei)
    """
    base_rate = interpolate_loss_rate(curve, horizon_days)

    # Apply volatility multiplier for confidence bounds
    volatility = curve.volatility_multiplier

    # Simple normal approximation for confidence interval
    # In production, would use more sophisticated actuarial methods
    z_score = 1.96 if confidence_level >= 0.95 else 1.645  # 95% or 90%

    expected_loss = int(coverage_wei * base_rate)
    margin = int(expected_loss * volatility * z_score)

    lower_bound = max(0, expected_loss - margin)
    upper_bound = expected_loss + margin

    return expected_loss, lower_bound, upper_bound
