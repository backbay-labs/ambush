"""
BudgetRouter - OPSEC-aware model routing.

Wraps ModelRouter with budget-awareness: when the stealth budget is low,
downgrades expensive models to cheaper alternatives to conserve budget
and reduce API costs.

Downgrade rules:
  - Budget > 50%: use normal routing
  - Budget 20-50%: downgrade Opus -> Sonnet
  - Budget < 20%: downgrade Opus -> Haiku, Sonnet -> Haiku
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from hellcat.core.routing.model_router import (
    HAIKU,
    SONNET,
    ModelConfig,
    ModelRouter,
)

if TYPE_CHECKING:
    from hellcat.offensive.opsec.stealth_budget import StealthBudget

logger = structlog.get_logger()

# Budget thresholds for model downgrading
_THRESHOLD_MEDIUM = 0.50  # Below 50%: downgrade Opus -> Sonnet
_THRESHOLD_LOW = 0.20     # Below 20%: everything -> Haiku

# Cost tiers for downgrade logic (keyed by model_id prefix)
_OPUS_IDS = frozenset({"claude-opus-4-6"})
_SONNET_IDS = frozenset({"claude-sonnet-4-5-20250929"})


class BudgetRouter:
    """
    OPSEC-aware model router that downgrades to cheaper models when
    the stealth budget is running low.

    Delegates to a ModelRouter for base routing, then applies budget-based
    downgrades when the remaining budget fraction drops below thresholds.
    """

    def __init__(
        self,
        model_router: ModelRouter,
        stealth_budget: StealthBudget | None = None,
    ) -> None:
        self._router = model_router
        self._budget = stealth_budget

    @property
    def model_router(self) -> ModelRouter:
        """The underlying ModelRouter."""
        return self._router

    def get_model(
        self,
        operator_name: str,
        phase: str = "",
    ) -> ModelConfig:
        """
        Get the model for an operator, applying budget-based downgrades.

        If no stealth budget is set, delegates directly to the ModelRouter.
        """
        base = self._router.get_model(operator_name, phase)

        if self._budget is None:
            return base

        remaining = self._budget.remaining_fraction

        if remaining >= _THRESHOLD_MEDIUM:
            return base

        if remaining >= _THRESHOLD_LOW:
            # Medium budget: downgrade Opus -> Sonnet
            downgraded = self._maybe_downgrade(base, target_floor=SONNET)
        else:
            # Low budget: everything -> Haiku
            downgraded = self._maybe_downgrade(base, target_floor=HAIKU)

        if downgraded is not base:
            logger.info(
                "routing.budget_downgrade",
                operator=operator_name,
                original_model=base.model_id,
                downgraded_model=downgraded.model_id,
                budget_remaining_pct=round(remaining * 100, 1),
            )

        return downgraded

    def estimate_cost(
        self,
        operator_name: str,
        phase: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> float:
        """Estimate cost using the budget-aware model selection."""
        model = self.get_model(operator_name, phase)
        return model.estimate_cost(input_tokens, output_tokens)

    def _maybe_downgrade(
        self,
        config: ModelConfig,
        target_floor: ModelConfig,
    ) -> ModelConfig:
        """Downgrade a model config to the target floor if it's more expensive."""
        if config.model_id in _OPUS_IDS:
            return target_floor
        if config.model_id in _SONNET_IDS and target_floor.model_id != SONNET.model_id:
            return target_floor
        return config
