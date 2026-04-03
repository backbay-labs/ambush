"""
Strategy Telemetry Module.

Provides infrastructure for analyzing and steering model reasoning strategies
based on the CoT Encyclopedia framework (arXiv:2505.10185).

Core components:
- StrategyRubric: Defines reasoning dimensions and their contrastive patterns
- StrategyProfile: Compact representation of a model's reasoning approach
- HELLCAT_V1_RUBRIC: Default rubric with 12 dimensions tailored to Hellcat
- Profiler: Extract profiles from agent self-reports or tool usage

Usage:
    from hellcat.eval.strategy import StrategyProfile, HELLCAT_V1_RUBRIC

    # Create a profile
    profile = StrategyProfile(
        rubric_version="hellcat-v1",
        dimensions={
            "analytical_perspective": DimensionValue(value="top_down", confidence=0.85),
            ...
        }
    )

    # Serialize for storage
    json_str = profile.to_json()

    # Extract from agent response
    from hellcat.eval.strategy import extract_from_self_report
    profile = extract_from_self_report(agent_response_text)
"""

from hellcat.eval.strategy.profile import (
    DimensionValue,
    StrategyProfile,
)
from hellcat.eval.strategy.profiler import (
    extract_from_self_report,
    extract_from_tool_usage,
    extract_profile,
    get_strategy_prompt_section,
    get_strategy_prompt_section_compact,
)
from hellcat.eval.strategy.rubric import (
    HELLCAT_V1_RUBRIC,
    StrategyDimension,
    StrategyRubric,
)

__all__ = [
    # Rubric
    "StrategyDimension",
    "StrategyRubric",
    "HELLCAT_V1_RUBRIC",
    # Profile
    "DimensionValue",
    "StrategyProfile",
    # Profiler
    "extract_from_self_report",
    "extract_from_tool_usage",
    "extract_profile",
    "get_strategy_prompt_section",
    "get_strategy_prompt_section_compact",
]
