"""
Routing helpers for selecting toolchains (and speculate candidates).

This module is intentionally lightweight so it can be used by the scheduler,
dispatcher, and runner without importing adapter implementations.

Supports dynamics-driven routing when a DynamicsRouter is provided, blending
empirical success rates with static configuration rules.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cyntra.core.scheduler.routing import KernelConfig, RoutingRule
    from cyntra.core.dynamics_router import DynamicsRouter
    from cyntra.core.state.models import Issue


def routing_rule_matches(issue: Issue, match: dict[str, Any]) -> bool:
    """Return True if a routing rule's match block matches an issue."""
    if not match:
        return True

    def _match_value(actual: Any, expected: Any) -> bool:
        if expected is None:
            return True
        if isinstance(expected, list):
            return actual in expected
        return actual == expected

    if "dk_tool_hint" in match and not _match_value(issue.dk_tool_hint, match["dk_tool_hint"]):
        return False
    if "dk_risk" in match and not _match_value(issue.dk_risk, match["dk_risk"]):
        return False
    if "dk_size" in match and not _match_value(issue.dk_size, match["dk_size"]):
        return False

    tags = issue.tags or []
    if "tags_any" in match:
        expected = match["tags_any"] or []
        if isinstance(expected, list) and not any(t in tags for t in expected):
            return False
    if "tags_all" in match:
        expected = match["tags_all"] or []
        if isinstance(expected, list) and not all(t in tags for t in expected):
            return False

    import re

    if "title_pattern" in match:
        pat = str(match["title_pattern"])
        if not re.search(pat, issue.title or ""):
            return False
    if "description_pattern" in match:
        pat = str(match["description_pattern"])
        if not re.search(pat, issue.description or ""):
            return False

    return True


def first_matching_rule(
    config: KernelConfig,
    issue: Issue,
    *,
    require_speculate: bool | None = None,
) -> RoutingRule | None:
    """Return the first routing rule that matches the issue."""
    for rule in config.routing.rules:
        if require_speculate is not None and rule.speculate != require_speculate:
            continue
        if routing_rule_matches(issue, rule.match):
            return rule
    return None


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def ordered_toolchain_candidates(
    config: KernelConfig,
    issue: Issue,
    *,
    dynamics_router: DynamicsRouter | None = None,
    state_features: dict[str, Any] | None = None,
    dynamics_weight: float = 0.3,
) -> list[str]:
    """
    Return an ordered list of toolchain candidates for single-dispatch routing.

    The list is built from the first matching routing rule (if any), then its
    configured fallbacks, then `toolchain_priority` as a final fallback.

    When a DynamicsRouter is provided, blends static ordering with empirical
    success rates from the transition database:
    - Static rules provide the candidate pool
    - Dynamics probabilities influence final ordering
    - dynamics_weight controls the blend (0 = pure static, 1 = pure dynamics)
    """
    candidates: list[str] = []

    rule = first_matching_rule(config, issue)
    if rule and rule.use:
        candidates.extend(rule.use)
        for tc in rule.use:
            candidates.extend(config.routing.fallbacks.get(tc, []))

    candidates.extend(config.toolchain_priority)
    candidates = _dedupe_preserve_order([c for c in candidates if c])

    # If no dynamics router, return static ordering
    if not dynamics_router or not candidates:
        return candidates

    # Get dynamics-based probabilities
    domain = _infer_domain(issue)
    job_type = issue.dk_tool_hint or "code"
    features = state_features or {}

    ranked = dynamics_router.rank_toolchains(
        candidates=candidates,
        domain=domain,
        job_type=job_type,
        features=features,
    )

    # Blend static position with dynamics probability
    # Static score: higher is better (first position = highest score)
    static_scores = {tc: len(candidates) - i for i, tc in enumerate(candidates)}

    # Normalize static scores to 0-1 range
    max_static = max(static_scores.values()) if static_scores else 1
    static_normalized = {tc: s / max_static for tc, s in static_scores.items()}

    # Blend: combined = (1 - weight) * static + weight * dynamics
    blended: list[tuple[str, float]] = []
    dynamics_probs = dict(ranked)
    for tc in candidates:
        static_score = static_normalized.get(tc, 0.5)
        dynamics_score = dynamics_probs.get(tc, 0.5)
        combined = (1 - dynamics_weight) * static_score + dynamics_weight * dynamics_score
        blended.append((tc, combined))

    # Sort by blended score descending
    blended.sort(key=lambda x: x[1], reverse=True)

    return [tc for tc, _ in blended]


def _infer_domain(issue: Issue) -> str:
    """Infer domain from issue tags or hints."""
    tags = issue.tags or []
    if "fab" in tags or "asset" in tags:
        return "fab_asset"
    if "world" in tags or "scene" in tags:
        return "fab_world"
    return "code"


def speculate_toolchains(
    config: KernelConfig,
    issue: Issue,
    *,
    dynamics_router: DynamicsRouter | None = None,
    state_features: dict[str, Any] | None = None,
) -> list[str]:
    """
    Return the ordered toolchains to use for speculate+vote for this issue.

    If a matching routing rule has `speculate: true`, returns its `use` list.
    Otherwise returns an empty list (caller can fallback to priority order).

    When a DynamicsRouter is provided, candidates are ranked by historical
    success probability (highest probability first).
    """
    candidates: list[str] = []

    if issue.dk_tool_hint:
        candidates.append(issue.dk_tool_hint)

    rule = first_matching_rule(config, issue, require_speculate=True)
    if rule and rule.use:
        candidates.extend(rule.use)

    candidates = _dedupe_preserve_order([c for c in candidates if c])

    # If no dynamics router or no candidates, return as-is
    if not dynamics_router or not candidates:
        return candidates

    # Rank by dynamics probabilities
    domain = _infer_domain(issue)
    job_type = issue.dk_tool_hint or "code"
    features = state_features or {}

    ranked = dynamics_router.rank_toolchains(
        candidates=candidates,
        domain=domain,
        job_type=job_type,
        features=features,
    )

    return [tc for tc, _ in ranked]


def speculate_parallelism(config: KernelConfig, issue: Issue) -> int:
    """Return the desired speculate parallelism for this issue."""
    rule = first_matching_rule(config, issue, require_speculate=True)
    if rule and isinstance(rule.parallelism, int) and rule.parallelism > 0:
        return rule.parallelism
    return config.speculation.default_parallelism
