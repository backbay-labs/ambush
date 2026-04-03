"""
Topology Schema - Core dataclasses for agent topology definition.

Defines the structure of multi-agent execution topologies including:
- TaskTopology: Full execution shape for a task
- TopologyPhase: A stage in the execution with parallel agents
- AgentSpec: Configuration for a single agent in a phase
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SynthesisMode(str, Enum):
    """How to combine outputs from parallel agents in a phase."""

    MERGE = "merge"  # Combine all outputs into a single context
    VOTE = "vote"  # Pick best output based on quality/confidence
    CASCADE = "cascade"  # Each output feeds into next agent
    INDEPENDENT = "independent"  # Each agent produces separate output


class ModelTier(str, Enum):
    """Model capability tier for agent execution."""

    FAST = "fast"  # Haiku, GPT-4o-mini - cheap, quick
    DEFAULT = "default"  # Sonnet, GPT-4o - balanced
    STRONG = "strong"  # Opus, o1 - high capability
    REASONING = "reasoning"  # o1, Claude with extended thinking


@dataclass
class ParallelismConfig:
    """Configuration for agent parallelism in a phase."""

    min: int = 1
    default: int = 1
    max: int = 1

    def resolve(self, budget_factor: float = 1.0) -> int:
        """Resolve to concrete parallelism based on budget factor (0-1)."""
        range_size = self.max - self.min
        return self.min + int(range_size * budget_factor)

    @classmethod
    def fixed(cls, n: int) -> "ParallelismConfig":
        """Create a fixed parallelism config."""
        return cls(min=n, default=n, max=n)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | int) -> "ParallelismConfig":
        """Parse from YAML dict or integer."""
        if isinstance(data, int):
            return cls.fixed(data)
        return cls(
            min=int(data.get("min", 1)),
            default=int(data.get("default", 1)),
            max=int(data.get("max", 1)),
        )


@dataclass
class AgentSpec:
    """Specification for a single agent in a topology phase."""

    role: str  # e.g., "researcher", "writer", "critic", "executor"
    prompt_template: str  # Template string with {placeholders}

    # Execution configuration
    toolchain: str | None = None  # None = auto-select based on role
    model_tier: ModelTier = ModelTier.DEFAULT
    timeout_ms: int = 300_000  # 5 minutes default
    max_tokens: int = 100_000

    # Agent-specific configuration
    tools: list[str] = field(default_factory=list)  # Available tools
    config: dict[str, Any] = field(default_factory=dict)  # Passthrough config

    # Output specification
    output_key: str | None = None  # Key for this agent's output in context
    output_file: str | None = None  # Optional file to write output to

    def with_prompt(self, prompt: str) -> "AgentSpec":
        """Return a copy with a different prompt template."""
        return AgentSpec(
            role=self.role,
            prompt_template=prompt,
            toolchain=self.toolchain,
            model_tier=self.model_tier,
            timeout_ms=self.timeout_ms,
            max_tokens=self.max_tokens,
            tools=list(self.tools),
            config=dict(self.config),
            output_key=self.output_key,
            output_file=self.output_file,
        )


@dataclass
class TopologyPhase:
    """A phase in the topology execution."""

    name: str
    agents: list[AgentSpec]

    # Phase configuration
    parallelism: ParallelismConfig = field(default_factory=lambda: ParallelismConfig.fixed(1))
    wait_for_all: bool = True  # Barrier: wait for all agents before next phase
    synthesis_mode: SynthesisMode = SynthesisMode.MERGE
    timeout_ms: int = 600_000  # 10 minutes default for phase

    # Context passing
    inputs_from: list[str] = field(default_factory=list)  # Phase names to pull context from
    context_keys: list[str] = field(default_factory=list)  # Specific keys to pass

    # Output configuration
    outputs: list[str] = field(default_factory=list)  # Expected output files

    @property
    def agent_count(self) -> int:
        """Number of agents in this phase (uses default parallelism)."""
        return max(len(self.agents), self.parallelism.default)


@dataclass
class TopologyConstraints:
    """Resource constraints for topology execution."""

    max_parallel_agents: int = 6
    max_tokens_per_phase: int = 500_000
    max_total_tokens: int = 2_000_000
    max_duration_ms: int = 1_800_000  # 30 minutes
    token_budget_factor: float = 1.0  # 0-1, scales parallelism


@dataclass
class TopologyMetadata:
    """Metadata about topology derivation."""

    derived_from: str  # "static_rule" | "learned_pattern" | "manual"
    template_name: str | None = None
    confidence: float = 1.0
    created_at: datetime = field(default_factory=datetime.utcnow)

    # Learning signals
    source_patterns: list[str] = field(default_factory=list)
    adjustments_applied: list[str] = field(default_factory=list)


@dataclass
class TaskTopology:
    """
    Complete execution topology for a task.

    Defines the full shape of agent execution including phases,
    parallelism, synthesis strategies, and constraints.
    """

    # Core structure
    name: str
    phases: list[TopologyPhase]

    # Constraints
    constraints: TopologyConstraints = field(default_factory=TopologyConstraints)

    # Metadata
    metadata: TopologyMetadata = field(
        default_factory=lambda: TopologyMetadata(derived_from="manual")
    )

    # Task context
    task_description: str = ""
    domain: str = ""

    @property
    def total_phases(self) -> int:
        return len(self.phases)

    @property
    def total_agents(self) -> int:
        return sum(phase.agent_count for phase in self.phases)

    @property
    def estimated_tokens(self) -> int:
        """Estimate total token usage across all phases."""
        total = 0
        for phase in self.phases:
            agents = phase.agent_count
            avg_tokens = sum(a.max_tokens for a in phase.agents) / max(len(phase.agents), 1)
            total += int(agents * avg_tokens)
        return total

    def get_phase(self, name: str) -> TopologyPhase | None:
        """Get phase by name."""
        for phase in self.phases:
            if phase.name == name:
                return phase
        return None


@dataclass
class PhaseOutput:
    """Output from a single phase execution."""

    phase_name: str
    agent_outputs: list[dict[str, Any]]  # Raw outputs from each agent
    synthesized: Any  # Combined output based on synthesis_mode
    files_written: list[str]
    duration_ms: int
    token_usage: int
    success: bool
    error: str | None = None


@dataclass
class TopologyResult:
    """Result of executing a complete topology."""

    topology_name: str
    phase_outputs: list[PhaseOutput]
    final_output: Any
    total_duration_ms: int
    total_tokens: int
    success: bool
    error: str | None = None

    @property
    def all_files_written(self) -> list[str]:
        """All files written across all phases."""
        files = []
        for phase in self.phase_outputs:
            files.extend(phase.files_written)
        return files

    def get_phase_output(self, phase_name: str) -> PhaseOutput | None:
        """Get output from a specific phase."""
        for output in self.phase_outputs:
            if output.phase_name == phase_name:
                return output
        return None
