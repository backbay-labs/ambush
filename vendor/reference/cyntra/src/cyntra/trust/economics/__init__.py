"""Economics module for Aegis Net capitalization layer.

Provides loss curve modeling and premium pricing for the verification market.

Components:
    loss_curves - LossCurveData, PremiumSchedule for actuarial calculations
    pricing - Dispute rate calculation, historical loss aggregation
"""

from cyntra.trust.economics.loss_curves import (
    LossCurveData,
    LossCurvePoint,
    PremiumSchedule,
    PremiumTier,
    compute_expected_loss,
    interpolate_loss_rate,
)
from cyntra.trust.economics.pricing import (
    DisputeRateMetrics,
    HistoricalLossAggregator,
    JobFamilyPricing,
    PricingConfig,
    PricingEngine,
)

__all__ = [
    # Loss curves
    "LossCurveData",
    "LossCurvePoint",
    "PremiumSchedule",
    "PremiumTier",
    "compute_expected_loss",
    "interpolate_loss_rate",
    # Pricing
    "DisputeRateMetrics",
    "HistoricalLossAggregator",
    "JobFamilyPricing",
    "PricingEngine",
    "PricingConfig",
]
