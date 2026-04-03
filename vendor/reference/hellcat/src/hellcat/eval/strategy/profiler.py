"""
Strategy Profiler - Extract strategy profiles from agent outputs.

Supports multiple extraction methods:
- Self-report: Parse compact strategy string from agent's response
- Heuristic: Analyze tool usage patterns and reasoning structure
"""

from __future__ import annotations

import re
from typing import Any

from hellcat.eval.strategy.profile import DimensionValue, StrategyProfile
from hellcat.eval.strategy.rubric import HELLCAT_V1_RUBRIC, StrategyRubric

# =============================================================================
# Prompt Injection
# =============================================================================

def get_strategy_prompt_section(rubric: StrategyRubric | None = None) -> str:
    """
    Generate the strategy self-report prompt section.

    This section should be appended to agent prompts to request
    strategy introspection after task completion.
    """
    if rubric is None:
        rubric = HELLCAT_V1_RUBRIC

    lines = [
        "## Strategy Self-Report",
        "",
        "After completing the task, add a `<strategy>` block describing your reasoning approach.",
        "For each dimension below, choose which pattern best describes how you approached this task:",
        "",
    ]

    for dim in rubric:
        lines.append(f"- **{dim.name}** (`{dim.id}`): `{dim.pattern_a}` or `{dim.pattern_b}`")
        lines.append(f"  - {dim.pattern_a}: {dim.description_a}")
        lines.append(f"  - {dim.pattern_b}: {dim.description_b}")

    lines.extend([
        "",
        "Format your response as a compact comma-separated list inside `<strategy>` tags.",
        "Preferred format is keyed pairs (`dimension_id:pattern`) so ordering mistakes don't matter:",
        "```",
        "<strategy>",
        f"{', '.join(f'{d.id}:{d.pattern_a}' for d in list(rubric)[:4])}, ...",
        "</strategy>",
        "```",
        "",
        "Include as many dimensions as you can (ideally all). This helps improve future task routing.",
        "",
    ])

    return "\n".join(lines)


def get_strategy_prompt_section_compact(rubric: StrategyRubric | None = None) -> str:
    """
    Generate a compact strategy prompt section (fewer tokens).

    Use this for cost-sensitive deployments.
    """
    if rubric is None:
        rubric = HELLCAT_V1_RUBRIC

    dim_list = ", ".join(f"{d.id}:{d.pattern_a}/{d.pattern_b}" for d in rubric)

    return (
        "## Strategy Telemetry (Compact)\n"
        "After finishing, add one line:\n"
        "`<strategy>dimension_id:pattern, ...</strategy>`\n"
        f"Rubric: `{rubric.version}`\n"
        f"Dimensions: {dim_list}\n"
    )


# =============================================================================
# Self-Report Extraction
# =============================================================================

# Regex patterns for extracting strategy blocks
_STRATEGY_BLOCK_PATTERN = re.compile(
    r"<strategy>\s*(.+?)\s*</strategy>",
    re.IGNORECASE | re.DOTALL,
)

_STRATEGY_INLINE_PATTERN = re.compile(
    r"strategy:\s*(.+?)(?:\n|$)",
    re.IGNORECASE,
)


def extract_from_self_report(
    text: str,
    rubric: StrategyRubric | None = None,
    workcell_id: str | None = None,
    issue_id: str | None = None,
    model: str | None = None,
    toolchain: str | None = None,
) -> StrategyProfile | None:
    """
    Extract a strategy profile from an agent's self-reported response.

    Looks for:
    1. `<strategy>...</strategy>` blocks
    2. `strategy: ...` inline patterns
    3. Comma-separated pattern lists

    Args:
        text: The agent's full response text
        rubric: The rubric to validate against (defaults to HELLCAT_V1_RUBRIC)
        workcell_id: Optional workcell ID to attach
        issue_id: Optional issue ID to attach
        model: Optional model identifier
        toolchain: Optional toolchain name

    Returns:
        StrategyProfile if extraction succeeds, None otherwise
    """
    if rubric is None:
        rubric = HELLCAT_V1_RUBRIC

    # Try to find strategy block
    strategy_text = _extract_strategy_text(text)
    if not strategy_text:
        return None

    # Parse the pattern string
    dimensions = _parse_pattern_string(strategy_text, rubric)
    if not dimensions:
        return None

    return StrategyProfile(
        rubric_version=rubric.version,
        dimensions=dimensions,
        workcell_id=workcell_id,
        issue_id=issue_id,
        model=model,
        toolchain=toolchain,
        extraction_method="self_report",
    )


def _extract_strategy_text(text: str) -> str | None:
    """Extract the raw strategy text from various formats."""
    # Try <strategy>...</strategy> block first
    match = _STRATEGY_BLOCK_PATTERN.search(text)
    if match:
        return match.group(1).strip()

    # Try strategy: ... inline pattern
    match = _STRATEGY_INLINE_PATTERN.search(text)
    if match:
        return match.group(1).strip()

    return None


def _parse_pattern_string(
    pattern_string: str,
    rubric: StrategyRubric,
) -> dict[str, DimensionValue]:
    """
    Parse a comma-separated pattern string into dimension values.

    Handles various formats:
    - "top_down, local, deductive, ..."
    - "top-down, local, deductive, ..."
    - "analytical_perspective:top_down, scope_approach:local, ..."
    """

    # Clean up the string
    pattern_string = pattern_string.strip()

    if ":" in pattern_string and not pattern_string.startswith("http"):
        return _parse_keyed_patterns(pattern_string, rubric)

    return _parse_ordered_patterns(pattern_string, rubric)


def _parse_keyed_patterns(
    pattern_string: str,
    rubric: StrategyRubric,
) -> dict[str, DimensionValue]:
    """Parse key:value pattern format like 'analytical_perspective:top_down, ...'"""
    dimensions: dict[str, DimensionValue] = {}

    # Split on comma, then parse each key:value pair
    parts = [p.strip() for p in pattern_string.split(",")]

    for part in parts:
        if ":" not in part:
            continue

        key, value = part.split(":", 1)
        key = _normalize_pattern(key)
        value = _normalize_pattern(value)

        # Find matching dimension
        dim = rubric.get(key)
        if dim is None:
            # Try fuzzy match on dimension ID
            dim = _fuzzy_match_dimension(key, rubric)

        if dim is None:
            continue

        # Validate pattern
        matched_pattern, confidence = _match_pattern_to_dimension(value, dim)
        if matched_pattern:
            dimensions[dim.id] = DimensionValue(
                value=matched_pattern,
                confidence=confidence,
            )

    return dimensions


def _parse_ordered_patterns(
    pattern_string: str,
    rubric: StrategyRubric,
) -> dict[str, DimensionValue]:
    """Parse ordered pattern list like 'top_down, local, deductive, ...'"""
    dimensions: dict[str, DimensionValue] = {}

    # Split on comma
    patterns = [_normalize_pattern(p) for p in pattern_string.split(",")]

    for i, pattern in enumerate(patterns):
        if i >= len(rubric.dimensions):
            break

        if not pattern:
            continue

        dim = rubric.dimensions[i]
        matched_pattern, confidence = _match_pattern_to_dimension(pattern, dim)

        if matched_pattern:
            dimensions[dim.id] = DimensionValue(
                value=matched_pattern,
                confidence=confidence,
            )

    return dimensions


def _normalize_pattern(pattern: str) -> str:
    """Normalize a pattern string for matching."""
    return pattern.strip().lower().replace("-", "_").replace(" ", "_")


def _match_pattern_to_dimension(
    pattern: str,
    dim: Any,  # StrategyDimension
) -> tuple[str | None, float]:
    """
    Match a pattern string to a dimension's valid patterns.

    Returns (matched_pattern, confidence) or (None, 0.0) if no match.
    """
    pattern_a_norm = _normalize_pattern(dim.pattern_a)
    pattern_b_norm = _normalize_pattern(dim.pattern_b)

    # Exact match
    if pattern == pattern_a_norm:
        return dim.pattern_a, 0.95
    if pattern == pattern_b_norm:
        return dim.pattern_b, 0.95

    # Partial match (pattern is substring)
    if pattern in pattern_a_norm or pattern_a_norm in pattern:
        return dim.pattern_a, 0.75
    if pattern in pattern_b_norm or pattern_b_norm in pattern:
        return dim.pattern_b, 0.75

    # Keyword match
    if _matches_keywords(pattern, dim.keywords_a):
        return dim.pattern_a, 0.6
    if _matches_keywords(pattern, dim.keywords_b):
        return dim.pattern_b, 0.6

    return None, 0.0


def _matches_keywords(pattern: str, keywords: tuple[str, ...]) -> bool:
    """Check if pattern matches any keyword."""
    pattern_words = set(pattern.replace("_", " ").split())
    for kw in keywords:
        kw_norm = kw.lower()
        if kw_norm in pattern or pattern in kw_norm:
            return True
        if kw_norm in pattern_words:
            return True
    return False


def _fuzzy_match_dimension(
    key: str,
    rubric: StrategyRubric,
) -> Any | None:  # StrategyDimension | None
    """Try to fuzzy-match a dimension ID."""
    key_clean = key.replace("_", "")

    for dim in rubric:
        dim_clean = dim.id.replace("_", "")
        if key_clean == dim_clean:
            return dim
        if key_clean in dim_clean or dim_clean in key_clean:
            return dim

    return None


# =============================================================================
# Heuristic Extraction (Tool Usage Analysis)
# =============================================================================

def extract_from_tool_usage(
    commands: list[dict[str, Any]],
    rubric: StrategyRubric | None = None,
    workcell_id: str | None = None,
    issue_id: str | None = None,
    model: str | None = None,
    toolchain: str | None = None,
) -> StrategyProfile:
    """
    Extract strategy profile heuristically from tool usage patterns.

    Analyzes:
    - Read/search tool ratio → context_usage dimension
    - Edit size patterns → diff_strategy dimension
    - Error handling commands → error_handling dimension
    - Planning patterns → planning_depth dimension

    Args:
        commands: List of executed commands with their metadata
        rubric: The rubric to use (defaults to HELLCAT_V1_RUBRIC)
        workcell_id: Optional workcell ID
        issue_id: Optional issue ID
        model: Optional model identifier
        toolchain: Optional toolchain name

    Returns:
        StrategyProfile with heuristically-inferred dimensions
    """
    if rubric is None:
        rubric = HELLCAT_V1_RUBRIC

    dimensions: dict[str, DimensionValue] = {}

    # Analyze tool usage patterns
    stats = _compute_tool_stats(commands)

    # Context usage: heavy vs minimal
    if "context_usage" in rubric:
        dim = rubric["context_usage"]
        read_ratio = stats.get("read_ratio", 0.5)
        if read_ratio > 0.4:
            dimensions["context_usage"] = DimensionValue(
                value=dim.pattern_a,  # heavy_context
                confidence=min(0.8, 0.5 + read_ratio),
                evidence=f"Read ratio: {read_ratio:.2f}",
            )
        else:
            dimensions["context_usage"] = DimensionValue(
                value=dim.pattern_b,  # minimal_context
                confidence=min(0.8, 0.5 + (1 - read_ratio)),
                evidence=f"Read ratio: {read_ratio:.2f}",
            )

    # Tool strategy: targeted vs exploratory
    if "tool_strategy" in rubric:
        dim = rubric["tool_strategy"]
        search_count = stats.get("search_count", 0)
        total_tools = stats.get("total_tools", 1)
        search_ratio = search_count / max(1, total_tools)

        if search_ratio > 0.3:
            dimensions["tool_strategy"] = DimensionValue(
                value=dim.pattern_b,  # exploratory_tools
                confidence=0.7,
                evidence=f"Search ratio: {search_ratio:.2f}",
            )
        else:
            dimensions["tool_strategy"] = DimensionValue(
                value=dim.pattern_a,  # targeted_tools
                confidence=0.7,
                evidence=f"Search ratio: {search_ratio:.2f}",
            )

    # Diff strategy: analyze edit sizes
    if "diff_strategy" in rubric:
        dim = rubric["diff_strategy"]
        avg_edit_size = stats.get("avg_edit_lines", 10)

        if avg_edit_size < 15:
            dimensions["diff_strategy"] = DimensionValue(
                value=dim.pattern_a,  # minimal_surgical
                confidence=0.65,
                evidence=f"Avg edit: {avg_edit_size:.1f} lines",
            )
        else:
            dimensions["diff_strategy"] = DimensionValue(
                value=dim.pattern_b,  # comprehensive_refactor
                confidence=0.65,
                evidence=f"Avg edit: {avg_edit_size:.1f} lines",
            )

    return StrategyProfile(
        rubric_version=rubric.version,
        dimensions=dimensions,
        workcell_id=workcell_id,
        issue_id=issue_id,
        model=model,
        toolchain=toolchain,
        extraction_method="heuristic",
    )


def _compute_tool_stats(commands: list[dict[str, Any]]) -> dict[str, float]:
    """Compute statistics from command execution history."""
    stats: dict[str, float] = {
        "total_tools": len(commands),
        "read_count": 0,
        "search_count": 0,
        "edit_count": 0,
        "total_edit_lines": 0,
    }

    for cmd in commands:
        tool = cmd.get("tool", "").lower()
        cmd.get("command_class", "").lower()

        if "read" in tool or "cat" in tool:
            stats["read_count"] += 1
        elif "search" in tool or "grep" in tool or "find" in tool or "glob" in tool:
            stats["search_count"] += 1
        elif "edit" in tool or "write" in tool:
            stats["edit_count"] += 1
            # Try to estimate edit size
            content = cmd.get("content", "") or cmd.get("new_string", "")
            if isinstance(content, str):
                stats["total_edit_lines"] += content.count("\n") + 1

    # Compute ratios
    total = max(1, stats["total_tools"])
    stats["read_ratio"] = (stats["read_count"] + stats["search_count"]) / total
    stats["edit_ratio"] = stats["edit_count"] / total

    edit_count = max(1, stats["edit_count"])
    stats["avg_edit_lines"] = stats["total_edit_lines"] / edit_count

    return stats


# =============================================================================
# Combined Extraction
# =============================================================================

def extract_profile(
    response_text: str | None = None,
    commands: list[dict[str, Any]] | None = None,
    rubric: StrategyRubric | None = None,
    workcell_id: str | None = None,
    issue_id: str | None = None,
    model: str | None = None,
    toolchain: str | None = None,
    prefer_self_report: bool = True,
) -> StrategyProfile | None:
    """
    Extract a strategy profile using the best available method.

    Tries self-report first if available, falls back to heuristic analysis.

    Args:
        response_text: The agent's response text (for self-report extraction)
        commands: List of executed commands (for heuristic extraction)
        rubric: The rubric to use
        workcell_id: Optional workcell ID
        issue_id: Optional issue ID
        model: Optional model identifier
        toolchain: Optional toolchain name
        prefer_self_report: If True, try self-report first

    Returns:
        StrategyProfile or None if no extraction possible
    """
    if rubric is None:
        rubric = HELLCAT_V1_RUBRIC

    profile: StrategyProfile | None = None

    # Try self-report extraction
    if prefer_self_report and response_text:
        profile = extract_from_self_report(
            text=response_text,
            rubric=rubric,
            workcell_id=workcell_id,
            issue_id=issue_id,
            model=model,
            toolchain=toolchain,
        )

    # Fall back to heuristic if self-report failed
    if profile is None and commands:
        profile = extract_from_tool_usage(
            commands=commands,
            rubric=rubric,
            workcell_id=workcell_id,
            issue_id=issue_id,
            model=model,
            toolchain=toolchain,
        )

    return profile
