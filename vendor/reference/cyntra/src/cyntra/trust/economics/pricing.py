"""
Pricing engine for verification market.

Calculates dispute rates, aggregates historical losses,
and determines verification pricing by job family.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from cyntra.trust.economics.loss_curves import (
    LossCurveData,
    LossCurvePoint,
    PremiumSchedule,
    compute_expected_loss,
    interpolate_loss_rate,
)

logger = logging.getLogger(__name__)


class DisputeOutcome(str, Enum):
    """Outcome of a dispute."""

    UPHELD = "upheld"  # Challenger won, verifier slashed
    REJECTED = "rejected"  # Verifier won, challenger lost bond
    SETTLED = "settled"  # Mutual resolution
    EXPIRED = "expired"  # No resolution, default outcome


@dataclass
class DisputeRecord:
    """Record of a single dispute event."""

    dispute_id: str
    task_id: str
    bundle_hash: str
    tier: int
    job_family: str
    outcome: DisputeOutcome
    verifier_pubkey: str
    challenger_pubkey: str | None = None

    # Amounts
    stake_wei: int = 0
    reward_wei: int = 0
    slash_amount_wei: int = 0
    payout_wei: int = 0

    # Timing
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    resolved_at: datetime | None = None
    resolution_time_hours: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "dispute_id": self.dispute_id,
            "task_id": self.task_id,
            "bundle_hash": self.bundle_hash,
            "tier": self.tier,
            "job_family": self.job_family,
            "outcome": self.outcome.value,
            "verifier_pubkey": self.verifier_pubkey,
            "challenger_pubkey": self.challenger_pubkey,
            "stake_wei": self.stake_wei,
            "reward_wei": self.reward_wei,
            "slash_amount_wei": self.slash_amount_wei,
            "payout_wei": self.payout_wei,
            "created_at": self.created_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_time_hours": self.resolution_time_hours,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DisputeRecord:
        return cls(
            dispute_id=data["dispute_id"],
            task_id=data["task_id"],
            bundle_hash=data["bundle_hash"],
            tier=data["tier"],
            job_family=data["job_family"],
            outcome=DisputeOutcome(data["outcome"]),
            verifier_pubkey=data["verifier_pubkey"],
            challenger_pubkey=data.get("challenger_pubkey"),
            stake_wei=data.get("stake_wei", 0),
            reward_wei=data.get("reward_wei", 0),
            slash_amount_wei=data.get("slash_amount_wei", 0),
            payout_wei=data.get("payout_wei", 0),
            created_at=datetime.fromisoformat(data["created_at"]),
            resolved_at=(
                datetime.fromisoformat(data["resolved_at"])
                if data.get("resolved_at")
                else None
            ),
            resolution_time_hours=data.get("resolution_time_hours", 0.0),
        )


@dataclass
class DisputeRateMetrics:
    """Aggregated dispute rate metrics for a period."""

    period_start: datetime
    period_end: datetime
    tier: int
    job_family: str

    # Counts
    total_tasks: int = 0
    disputed_tasks: int = 0
    upheld_disputes: int = 0
    rejected_disputes: int = 0

    # Rates (in basis points)
    dispute_rate_bps: int = 0  # Disputes per task
    upheld_rate_bps: int = 0  # Upheld per dispute
    loss_rate_bps: int = 0  # Losses per task (upheld disputes)

    # Amounts
    total_stake_wei: int = 0
    total_slash_wei: int = 0
    total_payout_wei: int = 0

    # Timing
    avg_resolution_hours: float = 0.0

    @property
    def dispute_rate(self) -> float:
        """Dispute rate as decimal."""
        return self.dispute_rate_bps / 10_000

    @property
    def loss_rate(self) -> float:
        """Loss rate as decimal."""
        return self.loss_rate_bps / 10_000

    @property
    def severity_ratio(self) -> float:
        """Ratio of slashed to staked (loss severity)."""
        if self.total_stake_wei == 0:
            return 0.0
        return self.total_slash_wei / self.total_stake_wei

    def to_dict(self) -> dict[str, Any]:
        return {
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "tier": self.tier,
            "job_family": self.job_family,
            "total_tasks": self.total_tasks,
            "disputed_tasks": self.disputed_tasks,
            "upheld_disputes": self.upheld_disputes,
            "rejected_disputes": self.rejected_disputes,
            "dispute_rate_bps": self.dispute_rate_bps,
            "upheld_rate_bps": self.upheld_rate_bps,
            "loss_rate_bps": self.loss_rate_bps,
            "total_stake_wei": self.total_stake_wei,
            "total_slash_wei": self.total_slash_wei,
            "total_payout_wei": self.total_payout_wei,
            "avg_resolution_hours": self.avg_resolution_hours,
        }


@dataclass
class HistoricalLossAggregator:
    """
    Aggregates historical loss data to build loss curves.

    Collects dispute records and computes metrics for actuarial analysis.
    """

    records: list[DisputeRecord] = field(default_factory=list)

    # Task counts by (tier, job_family) for rate calculation
    _task_counts: dict[tuple[int, str], int] = field(default_factory=lambda: defaultdict(int))

    def add_record(self, record: DisputeRecord) -> None:
        """Add a dispute record."""
        self.records.append(record)

    def register_task(self, tier: int, job_family: str) -> None:
        """Register a task for rate calculation (called for all tasks, not just disputed)."""
        self._task_counts[(tier, job_family)] += 1

    def register_tasks(self, tier: int, job_family: str, count: int) -> None:
        """Register multiple tasks at once."""
        self._task_counts[(tier, job_family)] += count

    def get_task_count(self, tier: int, job_family: str) -> int:
        """Get total task count for a tier/family combination."""
        return self._task_counts.get((tier, job_family), 0)

    def compute_metrics(
        self,
        tier: int,
        job_family: str,
        period_start: datetime,
        period_end: datetime,
    ) -> DisputeRateMetrics:
        """
        Compute dispute metrics for a specific tier and job family over a period.

        Args:
            tier: Verification tier
            job_family: Job family name
            period_start: Start of period
            period_end: End of period

        Returns:
            DisputeRateMetrics for the period
        """
        # Filter records for this tier/family/period
        relevant = [
            r for r in self.records
            if r.tier == tier
            and r.job_family == job_family
            and period_start <= r.created_at < period_end
        ]

        metrics = DisputeRateMetrics(
            period_start=period_start,
            period_end=period_end,
            tier=tier,
            job_family=job_family,
        )

        # Get total task count
        metrics.total_tasks = self._task_counts.get((tier, job_family), 0)

        if not relevant:
            return metrics

        metrics.disputed_tasks = len(relevant)

        # Count outcomes
        for record in relevant:
            if record.outcome == DisputeOutcome.UPHELD:
                metrics.upheld_disputes += 1
                metrics.total_slash_wei += record.slash_amount_wei
            elif record.outcome == DisputeOutcome.REJECTED:
                metrics.rejected_disputes += 1

            metrics.total_stake_wei += record.stake_wei
            metrics.total_payout_wei += record.payout_wei

            if record.resolution_time_hours > 0:
                metrics.avg_resolution_hours += record.resolution_time_hours

        # Compute rates
        if metrics.total_tasks > 0:
            metrics.dispute_rate_bps = int(10_000 * metrics.disputed_tasks / metrics.total_tasks)
            metrics.loss_rate_bps = int(10_000 * metrics.upheld_disputes / metrics.total_tasks)

        if metrics.disputed_tasks > 0:
            metrics.upheld_rate_bps = int(10_000 * metrics.upheld_disputes / metrics.disputed_tasks)
            metrics.avg_resolution_hours /= metrics.disputed_tasks

        return metrics

    def build_loss_curve(
        self,
        tier: int,
        job_family: str,
        horizons: list[int] | None = None,
    ) -> LossCurveData:
        """
        Build a loss curve from historical data.

        Args:
            tier: Verification tier
            job_family: Job family name
            horizons: Time horizons in days (default: [7, 30, 90, 365])

        Returns:
            LossCurveData populated with historical loss rates
        """
        if horizons is None:
            horizons = [7, 30, 90, 365]

        curve_id = f"curve_{tier}_{job_family}_{datetime.now(UTC).strftime('%Y%m%d')}"
        curve = LossCurveData(
            curve_id=curve_id,
            tier=tier,
            job_family=job_family,
        )

        now = datetime.now(UTC)

        for horizon in horizons:
            period_start = now - timedelta(days=horizon)
            metrics = self.compute_metrics(tier, job_family, period_start, now)

            if metrics.total_tasks > 0:
                # Compute confidence interval based on sample size
                # Using Wilson score interval approximation
                n = metrics.total_tasks
                p = metrics.loss_rate
                z = 1.96  # 95% confidence

                if n > 0:
                    denominator = 1 + z * z / n
                    center = (p + z * z / (2 * n)) / denominator
                    margin = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denominator

                    lower_bps = max(0, int((center - margin) * 10_000))
                    upper_bps = int((center + margin) * 10_000)
                else:
                    lower_bps = 0
                    upper_bps = 0

                point = LossCurvePoint(
                    horizon_days=horizon,
                    loss_rate_bps=metrics.loss_rate_bps,
                    confidence_lower_bps=lower_bps,
                    confidence_upper_bps=upper_bps,
                    sample_size=n,
                )
                curve.add_point(point)

        return curve

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [r.to_dict() for r in self.records],
            "task_counts": {f"{k[0]}:{k[1]}": v for k, v in self._task_counts.items()},
        }


@dataclass
class JobFamilyPricing:
    """Pricing configuration for a specific job family."""

    job_family: str
    base_reward_wei: int  # Base reward per task
    base_stake_wei: int  # Base stake requirement
    coverage_limit_wei: int  # Maximum coverage per task

    # Risk factors
    complexity_factor: float = 1.0  # Multiplier for complex jobs
    urgency_factor: float = 1.0  # Multiplier for urgent jobs
    history_factor: float = 1.0  # Based on historical performance

    # Tier multipliers (applied to base values)
    tier_multipliers: dict[int, float] = field(
        default_factory=lambda: {0: 1.0, 1: 2.0, 2: 5.0}
    )

    def get_reward(self, tier: int, complexity: float = 1.0, urgent: bool = False) -> int:
        """
        Calculate reward for a task.

        Args:
            tier: Verification tier
            complexity: Complexity multiplier (1.0 = normal)
            urgent: Whether this is an urgent task

        Returns:
            Reward amount in wei
        """
        base = self.base_reward_wei
        tier_mult = self.tier_multipliers.get(tier, 1.0)
        complexity_mult = self.complexity_factor * complexity
        urgency_mult = self.urgency_factor if urgent else 1.0

        return int(base * tier_mult * complexity_mult * urgency_mult * self.history_factor)

    def get_stake(self, tier: int) -> int:
        """
        Calculate required stake for a task.

        Args:
            tier: Verification tier

        Returns:
            Stake amount in wei
        """
        tier_mult = self.tier_multipliers.get(tier, 1.0)
        return int(self.base_stake_wei * tier_mult)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_family": self.job_family,
            "base_reward_wei": self.base_reward_wei,
            "base_stake_wei": self.base_stake_wei,
            "coverage_limit_wei": self.coverage_limit_wei,
            "complexity_factor": self.complexity_factor,
            "urgency_factor": self.urgency_factor,
            "history_factor": self.history_factor,
            "tier_multipliers": self.tier_multipliers,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> JobFamilyPricing:
        return cls(
            job_family=data["job_family"],
            base_reward_wei=data["base_reward_wei"],
            base_stake_wei=data["base_stake_wei"],
            coverage_limit_wei=data["coverage_limit_wei"],
            complexity_factor=data.get("complexity_factor", 1.0),
            urgency_factor=data.get("urgency_factor", 1.0),
            history_factor=data.get("history_factor", 1.0),
            tier_multipliers=data.get("tier_multipliers", {0: 1.0, 1: 2.0, 2: 5.0}),
        )


@dataclass
class PricingConfig:
    """Global pricing configuration."""

    # Default values
    default_reward_wei: int = 10_000_000_000_000_000  # 0.01 ETH
    default_stake_wei: int = 100_000_000_000_000_000  # 0.1 ETH
    default_coverage_wei: int = 1_000_000_000_000_000_000  # 1 ETH

    # Global multipliers
    market_adjustment: float = 1.0  # Supply/demand adjustment
    volatility_buffer: float = 1.2  # Safety margin

    # Minimum viable economics
    min_reward_wei: int = 1_000_000_000_000_000  # 0.001 ETH
    min_stake_wei: int = 10_000_000_000_000_000  # 0.01 ETH

    # Circuit breakers
    max_loss_rate_bps: int = 500  # 5% - halt if exceeded
    max_dispute_rate_bps: int = 1000  # 10% - review trigger

    def to_dict(self) -> dict[str, Any]:
        return {
            "default_reward_wei": self.default_reward_wei,
            "default_stake_wei": self.default_stake_wei,
            "default_coverage_wei": self.default_coverage_wei,
            "market_adjustment": self.market_adjustment,
            "volatility_buffer": self.volatility_buffer,
            "min_reward_wei": self.min_reward_wei,
            "min_stake_wei": self.min_stake_wei,
            "max_loss_rate_bps": self.max_loss_rate_bps,
            "max_dispute_rate_bps": self.max_dispute_rate_bps,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PricingConfig:
        return cls(**data)


class PricingEngine:
    """
    Main pricing engine for the verification market.

    Combines loss curves, job family pricing, and premium schedules
    to calculate comprehensive pricing for verification tasks.
    """

    def __init__(
        self,
        config: PricingConfig | None = None,
        loss_aggregator: HistoricalLossAggregator | None = None,
    ) -> None:
        self.config = config or PricingConfig()
        self.loss_aggregator = loss_aggregator or HistoricalLossAggregator()

        self._job_pricing: dict[str, JobFamilyPricing] = {}
        self._loss_curves: dict[str, LossCurveData] = {}
        self._premium_schedules: dict[str, PremiumSchedule] = {}

    def register_job_family(self, pricing: JobFamilyPricing) -> None:
        """Register pricing for a job family."""
        self._job_pricing[pricing.job_family] = pricing
        logger.info(f"Registered pricing for job family: {pricing.job_family}")

    def register_loss_curve(self, curve: LossCurveData) -> None:
        """Register a loss curve."""
        key = f"{curve.tier}:{curve.job_family}"
        self._loss_curves[key] = curve

    def register_premium_schedule(self, schedule: PremiumSchedule) -> None:
        """Register a premium schedule."""
        self._premium_schedules[schedule.job_family] = schedule

    def get_job_pricing(self, job_family: str) -> JobFamilyPricing:
        """Get pricing for a job family, using defaults if not registered."""
        if job_family in self._job_pricing:
            return self._job_pricing[job_family]

        # Return default pricing
        return JobFamilyPricing(
            job_family=job_family,
            base_reward_wei=self.config.default_reward_wei,
            base_stake_wei=self.config.default_stake_wei,
            coverage_limit_wei=self.config.default_coverage_wei,
        )

    def get_loss_curve(self, tier: int, job_family: str) -> LossCurveData | None:
        """Get loss curve for a tier/family combination."""
        key = f"{tier}:{job_family}"
        return self._loss_curves.get(key)

    def calculate_task_pricing(
        self,
        tier: int,
        job_family: str,
        complexity: float = 1.0,
        urgent: bool = False,
    ) -> dict[str, int]:
        """
        Calculate comprehensive pricing for a verification task.

        Args:
            tier: Verification tier
            job_family: Job family name
            complexity: Complexity multiplier
            urgent: Whether task is urgent

        Returns:
            Dictionary with reward_wei, stake_wei, coverage_limit_wei
        """
        pricing = self.get_job_pricing(job_family)

        reward = pricing.get_reward(tier, complexity, urgent)
        stake = pricing.get_stake(tier)
        coverage = pricing.coverage_limit_wei

        # Apply global adjustments
        reward = int(reward * self.config.market_adjustment)
        stake = int(stake * self.config.volatility_buffer)

        # Enforce minimums
        reward = max(reward, self.config.min_reward_wei)
        stake = max(stake, self.config.min_stake_wei)

        return {
            "reward_wei": reward,
            "stake_wei": stake,
            "coverage_limit_wei": coverage,
        }

    def calculate_premium(
        self,
        tier: int,
        job_family: str,
        coverage_wei: int,
        horizon_days: int = 30,
    ) -> dict[str, Any]:
        """
        Calculate insurance premium for verification coverage.

        Args:
            tier: Verification tier
            job_family: Job family name
            coverage_wei: Desired coverage amount
            horizon_days: Coverage period in days

        Returns:
            Dictionary with premium details
        """
        # Get loss curve
        curve = self.get_loss_curve(tier, job_family)
        if not curve:
            # Build from historical data
            curve = self.loss_aggregator.build_loss_curve(tier, job_family)

        # Compute expected loss
        expected, lower, upper = compute_expected_loss(
            curve, coverage_wei, horizon_days
        )

        # Add risk margin
        risk_margin = int((upper - expected) * 0.5)
        premium = expected + risk_margin

        # Add expense loading (operational costs)
        expense_loading = int(premium * 0.15)  # 15% expense ratio
        total_premium = premium + expense_loading

        return {
            "premium_wei": total_premium,
            "expected_loss_wei": expected,
            "risk_margin_wei": risk_margin,
            "expense_loading_wei": expense_loading,
            "coverage_wei": coverage_wei,
            "horizon_days": horizon_days,
            "loss_rate_bps": int(interpolate_loss_rate(curve, horizon_days) * 10_000),
        }

    def check_circuit_breakers(self, tier: int, job_family: str) -> tuple[bool, str | None]:
        """
        Check if circuit breakers are triggered for a tier/family.

        Returns:
            Tuple of (ok, reason_if_not_ok)
        """
        curve = self.get_loss_curve(tier, job_family)
        if not curve:
            return True, None

        # Check 30-day loss rate
        loss_rate = interpolate_loss_rate(curve, 30)
        loss_bps = int(loss_rate * 10_000)

        if loss_bps > self.config.max_loss_rate_bps:
            return False, f"Loss rate {loss_bps} bps exceeds max {self.config.max_loss_rate_bps} bps"

        return True, None

    def update_from_history(self) -> None:
        """Update all loss curves from historical data."""
        # Get unique tier/family combinations from task counts
        for (tier, job_family) in self.loss_aggregator._task_counts.keys():
            curve = self.loss_aggregator.build_loss_curve(tier, job_family)
            self.register_loss_curve(curve)

        logger.info(f"Updated {len(self._loss_curves)} loss curves from history")

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "job_pricing": {k: v.to_dict() for k, v in self._job_pricing.items()},
            "loss_curves": {k: v.to_dict() for k, v in self._loss_curves.items()},
            "premium_schedules": {k: v.to_dict() for k, v in self._premium_schedules.items()},
        }
