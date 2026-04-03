"""
Provider Router - Intelligent routing to execution providers.

Routes toolchain manifests to the best available provider based on
capabilities, cost, latency, and other factors.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hellcat.core.manifests.schema import ToolchainManifest
    from hellcat.core.providers.base import ExecutionProvider
    from hellcat.core.providers.capabilities import ExecutionCapabilities

from hellcat.core.providers.registry import (
    get_provider,
    get_providers_by_capability,
    list_providers,
)

logger = logging.getLogger(__name__)


class RoutingStrategy(Enum):
    """Provider selection strategy."""

    # Use first available provider that matches
    FIRST_MATCH = "first_match"

    # Choose cheapest provider
    LOWEST_COST = "lowest_cost"

    # Choose fastest provider (lowest latency)
    LOWEST_LATENCY = "lowest_latency"

    # Choose most capable provider
    HIGHEST_CAPABILITY = "highest_capability"

    # Use explicit provider from manifest
    EXPLICIT = "explicit"

    # Custom scoring function
    CUSTOM = "custom"


@dataclass
class RoutingDecision:
    """
    Result of routing decision.

    Contains the selected provider and reasoning for observability.
    """

    provider_name: str
    provider: ExecutionProvider
    score: float
    reason: str
    alternatives: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProviderScore:
    """Score for a single provider."""

    name: str
    score: float
    capability_match: float
    cost_score: float
    latency_score: float
    preference_score: float
    reason: str


# Cost estimates per provider ($ per minute)
PROVIDER_COSTS = {
    "local": 0.0,
    "e2b": 0.01,  # ~$0.60/hour
    "modal": 0.02,  # Varies by GPU
    "mcp": 0.0,  # Tool calls only
    "gpu-pool": 0.04,  # Depends on pool backend
    "workbench": 0.02,
    "attack_range": 0.03,
    "dagster": 0.0,  # Self-hosted
    "airflow": 0.0,  # Self-hosted
    "ray": 0.05,  # Varies by cluster
}

# Latency estimates per provider (seconds to start)
PROVIDER_LATENCIES = {
    "local": 0.1,
    "e2b": 0.15,  # ~150ms VM startup
    "modal": 2.0,  # Cold start
    "mcp": 0.5,  # Connection overhead
    "gpu-pool": 2.5,  # Lease allocation + worker warmup
    "workbench": 1.0,
    "attack_range": 1.5,
    "dagster": 5.0,  # Job scheduling
    "airflow": 10.0,  # DAG scheduling
    "ray": 3.0,  # Worker allocation
}


class ProviderRouter:
    """
    Routes manifests to execution providers.

    The router evaluates all available providers against the manifest
    requirements and selects the best match based on the routing strategy.

    Example:
        router = ProviderRouter(strategy=RoutingStrategy.LOWEST_COST)

        decision = router.route(manifest)
        result = await decision.provider.execute(manifest, context)
    """

    def __init__(
        self,
        strategy: RoutingStrategy = RoutingStrategy.FIRST_MATCH,
        *,
        custom_scorer: Callable[[str, ToolchainManifest], float] | None = None,
        provider_preferences: dict[str, float] | None = None,
        fallback_provider: str = "local",
    ):
        """
        Initialize the router.

        Args:
            strategy: Routing strategy to use
            custom_scorer: Custom scoring function (for CUSTOM strategy)
            provider_preferences: Provider name -> preference weight
            fallback_provider: Provider to use if no match found
        """
        self.strategy = strategy
        self.custom_scorer = custom_scorer
        self.provider_preferences = provider_preferences or {}
        self.fallback_provider = fallback_provider

        # Routing rules (job_type -> preferred providers)
        self.job_type_routes: dict[str, list[str]] = {
            "code": ["local", "e2b", "modal"],
            "fab-world": ["modal", "ray", "local"],
            "data": ["ray", "dagster", "airflow"],
            "review": ["local", "e2b"],
            "custom": ["local", "e2b", "modal"],
        }

        self.workbench_tags = {"workbench", "artifact-arena", "ghidra"}
        self.range_tags = {"range-raid", "attack-range", "cyber-raid"}

    def route(
        self,
        manifest: ToolchainManifest,
        *,
        exclude_providers: list[str] | None = None,
    ) -> RoutingDecision:
        """
        Route a manifest to the best provider.

        Args:
            manifest: Toolchain manifest to route
            exclude_providers: Providers to exclude from consideration

        Returns:
            RoutingDecision with selected provider

        Raises:
            ValueError: If no suitable provider found
        """
        exclude = set(exclude_providers or [])

        # Check for explicit provider hint
        if (manifest.provider_hint
                and self.strategy != RoutingStrategy.EXPLICIT
                and manifest.provider_hint not in exclude):
            try:
                provider = get_provider(manifest.provider_hint)
                return RoutingDecision(
                    provider_name=manifest.provider_hint,
                    provider=provider,
                    score=1.0,
                    reason=f"Explicit provider hint: {manifest.provider_hint}",
                )
            except KeyError:
                logger.warning(f"Hinted provider '{manifest.provider_hint}' not available")

        # Get matching providers
        requirements = manifest.requirements
        candidates = self._get_candidates(requirements, exclude)

        if not candidates:
            # Try fallback
            if self.fallback_provider not in exclude:
                try:
                    provider = get_provider(self.fallback_provider)
                    return RoutingDecision(
                        provider_name=self.fallback_provider,
                        provider=provider,
                        score=0.0,
                        reason="Fallback provider (no matches for requirements)",
                    )
                except KeyError:
                    pass

            raise ValueError(
                f"No provider matches requirements: {requirements}. "
                f"Available: {list_providers()}"
            )

        # Score candidates
        scores = [
            self._score_provider(name, manifest)
            for name in candidates
        ]

        # Sort by score (descending)
        scores.sort(key=lambda s: s.score, reverse=True)

        best = scores[0]
        provider = get_provider(best.name)

        return RoutingDecision(
            provider_name=best.name,
            provider=provider,
            score=best.score,
            reason=best.reason,
            alternatives=[s.name for s in scores[1:5]],
            metadata={
                "capability_match": best.capability_match,
                "cost_score": best.cost_score,
                "latency_score": best.latency_score,
            },
        )

    def _get_candidates(
        self,
        requirements: ExecutionCapabilities,
        exclude: set[str],
    ) -> list[str]:
        """Get candidate providers matching requirements."""
        matching = get_providers_by_capability(requirements)
        return [name for name, _ in matching if name not in exclude]

    def _score_provider(
        self,
        name: str,
        manifest: ToolchainManifest,
    ) -> ProviderScore:
        """Score a provider for a manifest."""

        # Custom scorer takes precedence
        if self.strategy == RoutingStrategy.CUSTOM and self.custom_scorer:
            score = self.custom_scorer(name, manifest)
            return ProviderScore(
                name=name,
                score=score,
                capability_match=1.0,
                cost_score=0.0,
                latency_score=0.0,
                preference_score=0.0,
                reason="Custom scorer",
            )

        # Calculate component scores
        capability_match = self._capability_score(name, manifest)
        cost_score = self._cost_score(name, manifest)
        latency_score = self._latency_score(name, manifest)
        preference_score = self._preference_score(name, manifest)

        # Weight based on strategy
        if self.strategy == RoutingStrategy.FIRST_MATCH:
            weights = (1.0, 0.0, 0.0, 0.0)
        elif self.strategy == RoutingStrategy.LOWEST_COST:
            weights = (0.3, 0.5, 0.1, 0.1)
        elif self.strategy == RoutingStrategy.LOWEST_LATENCY:
            weights = (0.3, 0.1, 0.5, 0.1)
        elif self.strategy == RoutingStrategy.HIGHEST_CAPABILITY:
            weights = (0.6, 0.1, 0.1, 0.2)
        else:
            weights = (0.4, 0.2, 0.2, 0.2)

        total_score = (
            weights[0] * capability_match +
            weights[1] * cost_score +
            weights[2] * latency_score +
            weights[3] * preference_score
        )

        reasons = []
        if capability_match > 0.8:
            reasons.append("excellent capability match")
        if cost_score > 0.8:
            reasons.append("low cost")
        if latency_score > 0.8:
            reasons.append("low latency")
        if preference_score > 0.5:
            reasons.append("preferred provider")

        reason = ", ".join(reasons) if reasons else "adequate match"

        return ProviderScore(
            name=name,
            score=total_score,
            capability_match=capability_match,
            cost_score=cost_score,
            latency_score=latency_score,
            preference_score=preference_score,
            reason=reason,
        )

    def _capability_score(self, name: str, manifest: ToolchainManifest) -> float:
        """Score based on capability match."""
        # For now, all matching providers get 1.0
        # Could be enhanced to score based on overmatch
        return 1.0

    def _cost_score(self, name: str, manifest: ToolchainManifest) -> float:
        """Score based on cost (inverted - lower is better)."""
        cost = PROVIDER_COSTS.get(name, 0.05)
        # Normalize: $0 = 1.0, $0.10 = 0.0
        return max(0.0, 1.0 - (cost / 0.10))

    def _latency_score(self, name: str, manifest: ToolchainManifest) -> float:
        """Score based on latency (inverted - lower is better)."""
        latency = PROVIDER_LATENCIES.get(name, 5.0)
        # Normalize: 0s = 1.0, 10s = 0.0
        return max(0.0, 1.0 - (latency / 10.0))

    def _preference_score(self, name: str, manifest: ToolchainManifest) -> float:
        """Score based on preferences and job type routing."""
        score = 0.0

        # Check explicit preferences
        if name in self.provider_preferences:
            score += self.provider_preferences[name]

        # Check job type routing
        job_type = manifest.task.job_type
        if job_type in self.job_type_routes:
            preferred = self.job_type_routes[job_type]
            if name in preferred:
                # Higher score for earlier in preference list
                position = preferred.index(name)
                score += (len(preferred) - position) / len(preferred) * 0.5

        # Prefer workbench provider for explicit workbench-tagged tasks
        if name == "workbench" and manifest.task.tags and self.workbench_tags.intersection(set(manifest.task.tags)):
            score += 0.7

        # Prefer attack range provider for explicit range-tagged tasks
        if name == "attack_range" and manifest.task.tags and self.range_tags.intersection(set(manifest.task.tags)):
            score += 0.7

        # Check prefer_local hint
        if manifest.runtime.prefer_local and name == "local":
            score += 0.3

        # Check prefer_gpu hint
        if manifest.runtime.prefer_gpu and name in ("modal", "ray", "gpu-pool"):
            score += 0.2

        return min(1.0, score)

    def add_route(self, job_type: str, providers: list[str]) -> None:
        """Add or update a job type route."""
        self.job_type_routes[job_type] = providers

    def set_preference(self, provider: str, weight: float) -> None:
        """Set preference weight for a provider."""
        self.provider_preferences[provider] = weight


# Default router instance
_default_router: ProviderRouter | None = None


def get_router() -> ProviderRouter:
    """Get the default router instance."""
    global _default_router
    if _default_router is None:
        _default_router = ProviderRouter()
    return _default_router


def set_router(router: ProviderRouter) -> None:
    """Set the default router instance."""
    global _default_router
    _default_router = router


def route(
    manifest: ToolchainManifest,
    **kwargs,
) -> RoutingDecision:
    """Route a manifest using the default router."""
    return get_router().route(manifest, **kwargs)
