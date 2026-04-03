"""Underwriting module for Aegis Net capitalization layer.

Provides collateral management, coverage products, and tranching
for the verification market insurance layer.

Components:
    collateral - CollateralConfig, haircut calculations
    products - CoverageProduct, circuit breaker logic
    tranches - TrancheConfig, TranchingEngine, loss waterfall
"""

from cyntra.trust.underwriting.collateral import (
    CollateralConfig,
    CollateralDeposit,
    CollateralPool,
    CollateralType,
    calculate_haircut,
    compute_collateral_value,
)
from cyntra.trust.underwriting.products import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerState,
    CoverageLimit,
    CoverageProduct,
    CoverageType,
    ProductRegistry,
)
from cyntra.trust.underwriting.tranches import (
    LossWaterfall,
    TrancheConfig,
    TranchePosition,
    TranchingEngine,
    WaterfallAllocation,
)

__all__ = [
    # Collateral
    "CollateralConfig",
    "CollateralDeposit",
    "CollateralPool",
    "CollateralType",
    "calculate_haircut",
    "compute_collateral_value",
    # Products
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerState",
    "CoverageProduct",
    "CoverageType",
    "CoverageLimit",
    "ProductRegistry",
    # Tranches
    "TrancheConfig",
    "TranchePosition",
    "TranchingEngine",
    "LossWaterfall",
    "WaterfallAllocation",
]
