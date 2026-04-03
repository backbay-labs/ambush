"""Routing for Hellcat security operators and toolchain selection."""

from hellcat.core.routing.budget_router import BudgetRouter
from hellcat.core.routing.model_router import ModelConfig, ModelRouter
from hellcat.core.routing.rules import (
    first_matching_rule,
    ordered_toolchain_candidates,
    routing_rule_matches,
    speculate_parallelism,
    speculate_toolchains,
)

__all__ = [
    "BudgetRouter",
    "ModelConfig",
    "ModelRouter",
    "first_matching_rule",
    "ordered_toolchain_candidates",
    "routing_rule_matches",
    "speculate_parallelism",
    "speculate_toolchains",
]
