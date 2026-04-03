"""
Strategy Rubric Definitions.

Defines the schema for reasoning strategy dimensions based on the
CoT Encyclopedia framework (arXiv:2505.10185).

Each dimension represents a binary classification criterion with:
- An identifier (snake_case)
- A human-readable name
- Two contrastive patterns (A and B)
- Descriptions for each pattern
- Optional keywords for extraction heuristics
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class StrategyDimension:
    """
    A single reasoning strategy dimension with contrastive patterns.

    Based on the CoT Encyclopedia's rubric structure where each dimension
    has two opposing strategies (Pattern A vs Pattern B).

    Attributes:
        id: Unique identifier (snake_case, e.g., "analytical_perspective")
        name: Human-readable name (e.g., "Analytical Perspective")
        pattern_a: First pattern label (e.g., "top_down")
        pattern_b: Second pattern label (e.g., "bottom_up")
        description_a: Description of pattern A behavior
        description_b: Description of pattern B behavior
        keywords_a: Keywords that suggest pattern A (for extraction heuristics)
        keywords_b: Keywords that suggest pattern B (for extraction heuristics)
        source: Origin of this dimension (e.g., "paper_3.2", "hellcat_specific")
    """

    id: str
    name: str
    pattern_a: str
    pattern_b: str
    description_a: str
    description_b: str
    keywords_a: tuple[str, ...] = field(default_factory=tuple)
    keywords_b: tuple[str, ...] = field(default_factory=tuple)
    source: str = "hellcat_v1"

    def __post_init__(self) -> None:
        if not self.id or not self.id.replace("_", "").isalnum():
            raise ValueError(f"Invalid dimension id: {self.id}")
        if self.pattern_a == self.pattern_b:
            raise ValueError(f"Patterns must be different: {self.pattern_a}")
        if not self.pattern_a or not self.pattern_b:
            raise ValueError("Both patterns must be non-empty")

    def patterns(self) -> tuple[str, str]:
        return (self.pattern_a, self.pattern_b)

    def is_valid_pattern(self, pattern: str) -> bool:
        return pattern in (self.pattern_a, self.pattern_b)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "pattern_a": self.pattern_a,
            "pattern_b": self.pattern_b,
            "description_a": self.description_a,
            "description_b": self.description_b,
            "keywords_a": list(self.keywords_a),
            "keywords_b": list(self.keywords_b),
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategyDimension:
        return cls(
            id=data["id"],
            name=data["name"],
            pattern_a=data["pattern_a"],
            pattern_b=data["pattern_b"],
            description_a=data["description_a"],
            description_b=data["description_b"],
            keywords_a=tuple(data.get("keywords_a", [])),
            keywords_b=tuple(data.get("keywords_b", [])),
            source=data.get("source", "unknown"),
        )


@dataclass(frozen=True)
class StrategyRubric:
    """
    A complete strategy rubric containing multiple dimensions.

    Rubrics are versioned to support backward compatibility as
    dimensions evolve.

    Attributes:
        version: Rubric version identifier (e.g., "hellcat-v1")
        dimensions: Ordered list of strategy dimensions
        description: Human-readable description of the rubric
    """

    version: str
    dimensions: tuple[StrategyDimension, ...]
    description: str = ""

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("Rubric version is required")
        if not self.dimensions:
            raise ValueError("Rubric must have at least one dimension")

        # Check for duplicate dimension IDs
        ids = [d.id for d in self.dimensions]
        if len(ids) != len(set(ids)):
            duplicates = [id for id in ids if ids.count(id) > 1]
            raise ValueError(f"Duplicate dimension IDs: {set(duplicates)}")

    def __len__(self) -> int:
        return len(self.dimensions)

    def __iter__(self):
        return iter(self.dimensions)

    def __getitem__(self, key: str | int) -> StrategyDimension:
        if isinstance(key, int):
            return self.dimensions[key]
        for dim in self.dimensions:
            if dim.id == key:
                return dim
        raise KeyError(f"Dimension not found: {key}")

    def __contains__(self, key: str) -> bool:
        return any(d.id == key for d in self.dimensions)

    def dimension_ids(self) -> list[str]:
        return [d.id for d in self.dimensions]

    def get(self, key: str, default: StrategyDimension | None = None) -> StrategyDimension | None:
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "description": self.description,
            "dimensions": [d.to_dict() for d in self.dimensions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategyRubric:
        return cls(
            version=data["version"],
            description=data.get("description", ""),
            dimensions=tuple(
                StrategyDimension.from_dict(d) for d in data["dimensions"]
            ),
        )

    def to_prompt_section(self) -> str:
        """
        Generate a prompt section describing the rubric for self-reporting.

        Returns a markdown-formatted string suitable for injection into
        agent prompts.
        """
        lines = [
            "## Strategy Self-Report",
            "",
            "After completing the task, briefly describe your reasoning approach.",
            "For each dimension, indicate which pattern best describes your approach:",
            "",
        ]

        for dim in self.dimensions:
            lines.append(f"- **{dim.name}**: {dim.pattern_a} / {dim.pattern_b}")

        lines.extend([
            "",
            "Provide a one-line summary, e.g.:",
            f'"{", ".join(d.pattern_a for d in self.dimensions[:4])}, ..."',
            "",
        ])

        return "\n".join(lines)


# =============================================================================
# HELLCAT_V1_RUBRIC: Default rubric with 12 dimensions
# =============================================================================

# Paper-derived dimensions (Section 3.2)
_ANALYTICAL_PERSPECTIVE = StrategyDimension(
    id="analytical_perspective",
    name="Analytical Perspective",
    pattern_a="top_down",
    pattern_b="bottom_up",
    description_a="Starts with high-level understanding, then drills into specifics. "
                  "Defines overall structure before addressing details.",
    description_b="Starts with specific details and builds up to broader understanding. "
                  "Examines individual components before synthesizing the whole.",
    keywords_a=("overview", "architecture", "design", "high-level", "structure", "plan"),
    keywords_b=("detail", "specific", "component", "piece", "element", "particular"),
    source="paper_3.2",
)

_SCOPE_APPROACH = StrategyDimension(
    id="scope_approach",
    name="Scope of Approach",
    pattern_a="global",
    pattern_b="local",
    description_a="Considers the entire codebase/system context. "
                  "Evaluates cross-cutting concerns and system-wide implications.",
    description_b="Focuses narrowly on the immediate problem area. "
                  "Minimizes scope to the specific code being modified.",
    keywords_a=("system", "codebase", "project", "overall", "everywhere", "all"),
    keywords_b=("focused", "narrow", "specific", "this file", "here", "local"),
    source="paper_3.2",
)

_REASONING_TYPE = StrategyDimension(
    id="reasoning_type",
    name="Reasoning Type",
    pattern_a="deductive",
    pattern_b="inductive",
    description_a="Applies known rules/patterns to reach conclusions. "
                  "Moves from general principles to specific applications.",
    description_b="Derives patterns from specific observations. "
                  "Builds understanding from examples and evidence.",
    keywords_a=("therefore", "follows", "rule", "principle", "must", "implies"),
    keywords_b=("observe", "pattern", "example", "suggests", "appears", "seems"),
    source="paper_3.2",
)

_IDEA_DEVELOPMENT = StrategyDimension(
    id="idea_development",
    name="Idea Development",
    pattern_a="linear",
    pattern_b="iterative",
    description_a="Proceeds step-by-step in sequence. "
                  "Each step builds directly on the previous.",
    description_b="Revisits and refines ideas through multiple passes. "
                  "May backtrack and adjust earlier decisions.",
    keywords_a=("first", "then", "next", "finally", "step", "sequence"),
    keywords_b=("revisit", "refine", "adjust", "reconsider", "iterate", "again"),
    source="paper_3.2",
)

_VERIFICATION_FOCUS = StrategyDimension(
    id="verification_focus",
    name="Verification Focus",
    pattern_a="continuous",
    pattern_b="final",
    description_a="Verifies correctness throughout the process. "
                  "Checks assumptions and intermediate results as they arise.",
    description_b="Verifies correctness at the end. "
                  "Completes work first, then validates the result.",
    keywords_a=("check", "verify", "ensure", "confirm", "validate", "test"),
    keywords_b=("complete", "finish", "done", "final", "end", "last"),
    source="paper_3.2",
)

_CLARIFICATION_APPROACH = StrategyDimension(
    id="clarification_approach",
    name="Clarification Approach",
    pattern_a="proactive",
    pattern_b="reactive",
    description_a="Anticipates ambiguities and addresses them upfront. "
                  "Asks clarifying questions before proceeding.",
    description_b="Addresses ambiguities as they arise during work. "
                  "Makes reasonable assumptions and proceeds.",
    keywords_a=("clarify", "understand", "before", "first", "question", "assume"),
    keywords_b=("proceed", "handle", "encounter", "arise", "when", "if"),
    source="paper_3.2",
)

# Hellcat-specific dimensions
_PLANNING_DEPTH = StrategyDimension(
    id="planning_depth",
    name="Planning Depth",
    pattern_a="detailed_plan",
    pattern_b="immediate_action",
    description_a="Creates a detailed plan before making changes. "
                  "Outlines all steps and their order.",
    description_b="Takes immediate action with minimal upfront planning. "
                  "Discovers the path through doing.",
    keywords_a=("plan", "outline", "steps", "approach", "strategy", "roadmap"),
    keywords_b=("start", "begin", "do", "try", "quick", "direct"),
    source="hellcat_specific",
)

_TOOL_STRATEGY = StrategyDimension(
    id="tool_strategy",
    name="Tool Strategy",
    pattern_a="targeted_tools",
    pattern_b="exploratory_tools",
    description_a="Uses tools with specific intent. "
                  "Each tool call has a clear purpose.",
    description_b="Uses tools to explore and discover. "
                  "Broader searches to understand context.",
    keywords_a=("specific", "exact", "precise", "known", "target", "find"),
    keywords_b=("search", "explore", "look", "discover", "browse", "scan"),
    source="hellcat_specific",
)

_ERROR_HANDLING = StrategyDimension(
    id="error_handling",
    name="Error Handling",
    pattern_a="preventive",
    pattern_b="corrective",
    description_a="Anticipates potential errors and prevents them. "
                  "Defensive coding, input validation upfront.",
    description_b="Handles errors as they occur. "
                  "Fixes issues when tests fail.",
    keywords_a=("prevent", "avoid", "guard", "validate", "check", "ensure"),
    keywords_b=("fix", "handle", "catch", "recover", "repair", "correct"),
    source="hellcat_specific",
)

_CONTEXT_USAGE = StrategyDimension(
    id="context_usage",
    name="Context Usage",
    pattern_a="heavy_context",
    pattern_b="minimal_context",
    description_a="Gathers extensive context before making changes. "
                  "Reads many files, understands patterns.",
    description_b="Uses minimal context necessary. "
                  "Focuses on immediate requirements.",
    keywords_a=("read", "understand", "context", "pattern", "convention", "style"),
    keywords_b=("minimal", "focused", "necessary", "direct", "simple", "basic"),
    source="hellcat_specific",
)

_DIFF_STRATEGY = StrategyDimension(
    id="diff_strategy",
    name="Diff Strategy",
    pattern_a="minimal_surgical",
    pattern_b="comprehensive_refactor",
    description_a="Makes minimal, surgical changes. "
                  "Touches only what's strictly necessary.",
    description_b="Makes comprehensive changes including improvements. "
                  "Refactors and cleans up as needed.",
    keywords_a=("minimal", "small", "focused", "surgical", "precise", "only"),
    keywords_b=("refactor", "improve", "clean", "comprehensive", "thorough", "also"),
    source="hellcat_specific",
)

_GATE_AWARENESS = StrategyDimension(
    id="gate_awareness",
    name="Gate Awareness",
    pattern_a="gate_driven",
    pattern_b="task_driven",
    description_a="Keeps quality gates in mind throughout. "
                  "Designs changes to pass tests/lint from the start.",
    description_b="Focuses on completing the task first. "
                  "Addresses gate failures after implementation.",
    keywords_a=("test", "lint", "type", "gate", "pass", "quality"),
    keywords_b=("implement", "complete", "task", "feature", "work", "code"),
    source="hellcat_specific",
)

# Assemble the default rubric
HELLCAT_V1_RUBRIC = StrategyRubric(
    version="hellcat-v1",
    description=(
        "Default Hellcat strategy rubric with 12 dimensions. "
        "6 dimensions from arXiv:2505.10185 (CoT Encyclopedia) + "
        "6 Hellcat-specific dimensions for software engineering tasks."
    ),
    dimensions=(
        # Paper-derived (6)
        _ANALYTICAL_PERSPECTIVE,
        _SCOPE_APPROACH,
        _REASONING_TYPE,
        _IDEA_DEVELOPMENT,
        _VERIFICATION_FOCUS,
        _CLARIFICATION_APPROACH,
        # Hellcat-specific (6)
        _PLANNING_DEPTH,
        _TOOL_STRATEGY,
        _ERROR_HANDLING,
        _CONTEXT_USAGE,
        _DIFF_STRATEGY,
        _GATE_AWARENESS,
    ),
)
