"""
Routing helpers for selecting toolchains (and speculate candidates).

This module is intentionally lightweight so it can be used by the scheduler,
dispatcher, and runner without importing adapter implementations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hellcat.core.scheduler.routing import KernelConfig, RoutingRule
    from hellcat.core.state.models import Issue


def routing_rule_matches(issue: Issue, match: dict[str, Any]) -> bool:
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
    **kwargs: Any,
) -> list[str]:
    """
    Return an ordered list of toolchain candidates for single-dispatch routing.

    The list is built from the first matching routing rule (if any), then its
    configured fallbacks, then `toolchain_priority` as a final fallback.
    """
    candidates: list[str] = []

    rule = first_matching_rule(config, issue)
    if rule and rule.use:
        candidates.extend(rule.use)
        for tc in rule.use:
            candidates.extend(config.routing.fallbacks.get(tc, []))

    candidates.extend(config.toolchain_priority)
    candidates = _dedupe_preserve_order([c for c in candidates if c])

    return candidates


def speculate_toolchains(
    config: KernelConfig,
    issue: Issue,
    **kwargs: Any,
) -> list[str]:
    """
    Return the ordered toolchains to use for speculate+vote for this issue.

    If a matching routing rule has `speculate: true`, returns its `use` list.
    Otherwise returns an empty list (caller can fallback to priority order).
    """
    candidates: list[str] = []

    if issue.dk_tool_hint:
        candidates.append(issue.dk_tool_hint)

    rule = first_matching_rule(config, issue, require_speculate=True)
    if rule and rule.use:
        candidates.extend(rule.use)

    candidates = _dedupe_preserve_order([c for c in candidates if c])
    return candidates


def speculate_parallelism(config: KernelConfig, issue: Issue) -> int:
    rule = first_matching_rule(config, issue, require_speculate=True)
    if rule and isinstance(rule.parallelism, int) and rule.parallelism > 0:
        return rule.parallelism
    return config.speculation.default_parallelism
