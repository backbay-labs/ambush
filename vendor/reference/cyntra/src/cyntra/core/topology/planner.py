"""
Topology Planner - Maps tasks to agent topologies.

Selects and instantiates topology templates based on task characteristics,
learned patterns, and resource constraints.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyntra.core.topology.schema import (
    AgentSpec,
    ModelTier,
    ParallelismConfig,
    SynthesisMode,
    TaskTopology,
    TopologyConstraints,
    TopologyMetadata,
    TopologyPhase,
)
from cyntra.core.topology.templates import (
    TopologyTemplate,
    load_all_templates,
)

if TYPE_CHECKING:
    from cyntra.core.scheduler.routing import KernelConfig
    from cyntra.core.state.models import Issue

logger = logging.getLogger(__name__)


@dataclass
class TopologyAdjustments:
    """
    Learned adjustments to apply to base topology.

    These come from dynamics/memory signals and modify the base
    template to improve execution based on historical data.
    """

    # Parallelism adjustments by phase
    parallelism_boost: dict[str, float] = field(default_factory=dict)

    # Toolchain preferences by role
    toolchain_preferences: dict[str, list[str]] = field(default_factory=dict)

    # Phase weights (0 = skip, 1 = normal, >1 = emphasize)
    phase_weights: dict[str, float] = field(default_factory=dict)

    # Model tier overrides by role
    model_tier_overrides: dict[str, ModelTier] = field(default_factory=dict)

    # Temperature adjustments
    temperature_adjustment: float = 0.0

    # Source of adjustments
    sources: list[str] = field(default_factory=list)


@dataclass
class PlanningContext:
    """Context for topology planning decisions."""

    # Resource constraints
    max_parallel_agents: int = 6
    token_budget: int = 2_000_000
    time_budget_ms: int = 1_800_000

    # Learned signals
    trap_state_ids: set[str] = field(default_factory=set)
    anti_patterns: list[dict[str, Any]] = field(default_factory=list)
    success_patterns: list[dict[str, Any]] = field(default_factory=list)
    priority_weights: dict[str, float] = field(default_factory=dict)

    # Domain context
    domain: str = ""
    project_type: str = ""

    # Domain-specific strategy hints (from DomainProfileStore)
    domain_preferred_toolchain: str | None = None
    domain_estimated_tokens: int | None = None

    # Evolved prompt genome (from auto-evolution)
    evolved_prompt_genome: dict[str, Any] | None = None

    # Additional context for prompt rendering
    extra_context: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_config(cls, config: "KernelConfig") -> "PlanningContext":
        """Create planning context from kernel config."""
        return cls(
            max_parallel_agents=config.max_concurrent_workcells,
            token_budget=config.max_concurrent_tokens * 10,  # Allow multiple cycles
            time_budget_ms=1_800_000,  # 30 minutes default
        )


class TopologyPlanner:
    """
    Plans agent topologies for tasks.

    Takes a task description and returns a TaskTopology that defines
    the optimal agent swarm configuration for executing the task.
    """

    def __init__(
        self,
        templates_dir: Path | None = None,
        config: "KernelConfig | None" = None,
        evolved_prompts_dir: Path | None = None,
    ) -> None:
        self.templates_dir = templates_dir
        self.config = config
        self.evolved_prompts_dir = evolved_prompts_dir
        self._templates: list[TopologyTemplate] | None = None

    @property
    def templates(self) -> list[TopologyTemplate]:
        """Lazy-load templates from directory."""
        if self._templates is None:
            if self.templates_dir and self.templates_dir.exists():
                self._templates = load_all_templates(self.templates_dir)
            else:
                self._templates = []
        return self._templates

    def reload_templates(self) -> None:
        """Force reload of templates from disk."""
        self._templates = None

    def plan(
        self,
        task_description: str,
        context: PlanningContext | None = None,
        *,
        issue: "Issue | None" = None,
        force_template: str | None = None,
    ) -> TaskTopology | None:
        """
        Plan the topology for a task.

        Args:
            task_description: Description of the task
            context: Planning context with constraints and signals
            issue: Optional Issue for additional context
            force_template: Force use of a specific template by name

        Returns:
            TaskTopology if a suitable template is found, None otherwise
        """
        context = context or PlanningContext()

        # Extract task metadata
        task_tags = self._extract_tags(task_description, issue)
        task_type = self._classify_task(task_description, issue)

        # Find matching template
        template = self._find_template(
            task_description=task_description,
            task_tags=task_tags,
            force_template=force_template,
        )

        if not template:
            logger.debug(f"No topology template matched for: {task_description[:50]}...")
            return None

        logger.info(f"Selected topology template: {template.name}")

        # Compute adjustments from learned signals
        adjustments = self._compute_adjustments(
            template=template,
            task_description=task_description,
            context=context,
        )

        # Build constraints from context
        constraints = self._build_constraints(context, adjustments)

        # Merge evolved prompt genome into extra context if available
        extra = dict(context.extra_context)
        if context.evolved_prompt_genome:
            extra["prompt_genome"] = context.evolved_prompt_genome

        # Build render context
        render_context = self._build_render_context(
            task_description=task_description,
            domain=context.domain,
            issue=issue,
            extra=extra,
        )

        # Instantiate topology
        topology = template.instantiate(
            task_description=task_description,
            domain=context.domain,
            context=render_context,
            constraints_override=constraints,
        )

        # Apply adjustments
        topology = self._apply_adjustments(topology, adjustments)

        # Inject evolved prompts if available
        topology = self._apply_evolved_prompts(topology)

        # Update metadata
        topology.metadata.source_patterns = [
            p.get("name", "unknown") for p in context.success_patterns[:3]
        ]
        topology.metadata.adjustments_applied = adjustments.sources

        return topology

    def _find_template(
        self,
        task_description: str,
        task_tags: list[str],
        force_template: str | None = None,
    ) -> TopologyTemplate | None:
        """Find the best matching template for the task."""
        if force_template:
            for template in self.templates:
                if template.name == force_template:
                    return template
            logger.warning(f"Forced template not found: {force_template}")
            return None

        # Check each template's triggers
        for template in self.templates:
            for trigger in template.triggers:
                if trigger.matches(task_description, task_tags):
                    return template

        return None

    def _classify_task(
        self,
        task_description: str,
        issue: "Issue | None" = None,
    ) -> str:
        """Classify the task type."""
        desc_lower = task_description.lower()

        # Research indicators
        if any(kw in desc_lower for kw in ["research", "investigate", "analyze", "study", "explore"]):
            return "research"

        # Implementation indicators
        if any(kw in desc_lower for kw in ["implement", "build", "create", "develop", "add"]):
            return "implementation"

        # Repair/fix indicators
        if any(kw in desc_lower for kw in ["fix", "repair", "debug", "resolve", "patch"]):
            return "repair"

        # Refactor indicators
        if any(kw in desc_lower for kw in ["refactor", "restructure", "reorganize", "clean"]):
            return "refactor"

        # From issue if available
        if issue:
            tags = issue.tags or []
            if "bug" in tags or "fix" in tags:
                return "repair"
            if "feature" in tags or "enhancement" in tags:
                return "implementation"

        return "general"

    def _extract_tags(
        self,
        task_description: str,
        issue: "Issue | None" = None,
    ) -> list[str]:
        """Extract relevant tags from task and issue."""
        tags = []

        # From issue
        if issue and issue.tags:
            tags.extend(issue.tags)

        # Infer from description
        desc_lower = task_description.lower()

        if "research" in desc_lower:
            tags.append("research")
        if "plan" in desc_lower:
            tags.append("planning")
        if any(kw in desc_lower for kw in ["healthcare", "medical", "health"]):
            tags.append("healthcare")
        if any(kw in desc_lower for kw in ["insurance", "deinsure"]):
            tags.append("insurance")
        if any(kw in desc_lower for kw in ["blockchain", "decentralized", "crypto"]):
            tags.append("blockchain")

        return list(set(tags))

    def _compute_adjustments(
        self,
        template: TopologyTemplate,
        task_description: str,
        context: PlanningContext,
    ) -> TopologyAdjustments:
        """Compute topology adjustments from learned signals."""
        adjustments = TopologyAdjustments()

        # Check for trap states - increase parallelism if in trap
        if context.trap_state_ids:
            # Boost parallelism for all phases
            for phase_def in template.phases:
                phase_name = phase_def.get("name", "")
                adjustments.parallelism_boost[phase_name] = 1.2
            adjustments.sources.append("trap_state_boost")

        # Check anti-patterns - adjust toolchains
        desc_lower = task_description.lower()
        for pattern in context.anti_patterns:
            keywords = pattern.get("keywords", [])
            if any(kw.lower() in desc_lower for kw in keywords):
                # Prefer stronger models for anti-pattern matches
                adjustments.model_tier_overrides["researcher"] = ModelTier.STRONG
                adjustments.sources.append(f"anti_pattern:{pattern.get('name', 'unknown')}")
                break

        # Check success patterns - boost matching phases
        for pattern in context.success_patterns:
            keywords = pattern.get("keywords", [])
            phase_boosts = pattern.get("phase_boosts", {})
            if any(kw.lower() in desc_lower for kw in keywords):
                for phase_name, boost in phase_boosts.items():
                    adjustments.parallelism_boost[phase_name] = boost
                adjustments.sources.append(f"success_pattern:{pattern.get('name', 'unknown')}")

        # Apply priority weights
        for key, weight in context.priority_weights.items():
            if key.startswith("phase:"):
                phase_name = key[6:]
                adjustments.phase_weights[phase_name] = weight

        # Apply domain profile toolchain preference
        if context.domain_preferred_toolchain:
            for phase_def in template.phases:
                for agent_def in phase_def.get("agents", []):
                    role = agent_def.get("role", "")
                    if role and role not in adjustments.toolchain_preferences:
                        adjustments.toolchain_preferences[role] = [
                            context.domain_preferred_toolchain,
                        ]
            adjustments.sources.append("domain_profile")

        return adjustments

    def _build_constraints(
        self,
        context: PlanningContext,
        adjustments: TopologyAdjustments,
    ) -> TopologyConstraints:
        """Build topology constraints from context."""
        return TopologyConstraints(
            max_parallel_agents=context.max_parallel_agents,
            max_total_tokens=context.token_budget,
            max_duration_ms=context.time_budget_ms,
            token_budget_factor=1.0,
        )

    def _build_render_context(
        self,
        task_description: str,
        domain: str,
        issue: "Issue | None" = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build context for template rendering."""
        context = {
            "task_description": task_description,
            "domain": domain,
            "concept": self._extract_concept(task_description),
        }

        if issue:
            context["issue_id"] = issue.id
            context["issue_title"] = issue.title

        if extra:
            context.update(extra)

        return context

    def _extract_concept(self, task_description: str) -> str:
        """Extract a short concept name from task description."""
        # Try to find a noun phrase after common verbs
        patterns = [
            r"(?:build|create|develop|implement|research)\s+(?:a\s+)?(.+?)(?:\s+for|\s+with|\s+that|$)",
            r"(?:investigate|analyze|study)\s+(.+?)(?:\s+and|\s+to|$)",
        ]

        for pattern in patterns:
            match = re.search(pattern, task_description.lower())
            if match:
                concept = match.group(1).strip()
                # Clean up and convert to slug
                concept = re.sub(r"[^\w\s-]", "", concept)
                concept = re.sub(r"\s+", "-", concept)
                return concept[:50]

        # Fallback: first few words
        words = task_description.split()[:5]
        return "-".join(words).lower()[:50]

    def _apply_adjustments(
        self,
        topology: TaskTopology,
        adjustments: TopologyAdjustments,
    ) -> TaskTopology:
        """Apply learned adjustments to topology."""
        # Apply parallelism boosts
        for phase in topology.phases:
            boost = adjustments.parallelism_boost.get(phase.name, 1.0)
            if boost != 1.0:
                new_default = int(phase.parallelism.default * boost)
                new_max = int(phase.parallelism.max * boost)
                phase.parallelism = ParallelismConfig(
                    min=phase.parallelism.min,
                    default=min(new_default, topology.constraints.max_parallel_agents),
                    max=min(new_max, topology.constraints.max_parallel_agents),
                )

        # Apply phase weights (skip phases with weight 0)
        if adjustments.phase_weights:
            topology.phases = [
                phase
                for phase in topology.phases
                if adjustments.phase_weights.get(phase.name, 1.0) > 0
            ]

        # Apply model tier overrides
        for phase in topology.phases:
            for agent in phase.agents:
                if agent.role in adjustments.model_tier_overrides:
                    agent.model_tier = adjustments.model_tier_overrides[agent.role]

        # Apply toolchain preferences
        for phase in topology.phases:
            for agent in phase.agents:
                if agent.role in adjustments.toolchain_preferences:
                    prefs = adjustments.toolchain_preferences[agent.role]
                    if prefs and not agent.toolchain:
                        agent.toolchain = prefs[0]

        return topology

    def _apply_evolved_prompts(self, topology: TaskTopology) -> TaskTopology:
        """Inject evolved prompts into agent specs when available."""
        if not self.evolved_prompts_dir or not self.evolved_prompts_dir.exists():
            return topology

        frontier_path = self.evolved_prompts_dir / "frontier.json"
        if not frontier_path.exists():
            return topology

        try:
            import json
            import yaml as _yaml

            frontier_data = json.loads(frontier_path.read_text())
            items = frontier_data.get("items", [])
            if not items:
                return topology

            # Pick the best genome from the frontier (first item, sorted by quality)
            best = items[0]
            genome_path_str = best.get("genome_path")
            if not genome_path_str:
                genome_id = best.get("genome_id", "")
                candidate = self.evolved_prompts_dir / f"{genome_id}.yaml"
                if not candidate.exists():
                    return topology
                genome_path_str = str(candidate)

            genome_path = Path(genome_path_str)
            if not genome_path.is_absolute():
                genome_path = self.evolved_prompts_dir / genome_path
            if not genome_path.exists():
                return topology

            genome = _yaml.safe_load(genome_path.read_text())
            if not isinstance(genome, dict):
                return topology

            system_prompt = genome.get("system_prompt")
            if not system_prompt:
                return topology

            # Inject evolved system prompt as a prefix to agent prompts
            for phase in topology.phases:
                for agent in phase.agents:
                    agent.prompt_template = (
                        f"{system_prompt}\n\n{agent.prompt_template}"
                    )

            topology.metadata.adjustments_applied.append(
                f"evolved_prompt:{best.get('genome_id', 'unknown')}"
            )
            logger.info("Applied evolved prompt from genome %s", best.get("genome_id"))
        except Exception:
            logger.debug("Failed to apply evolved prompts (non-fatal)", exc_info=True)

        return topology

    def list_templates(self) -> list[dict[str, Any]]:
        """List available templates with their triggers."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "triggers": [
                    {
                        "task_type": tr.task_type,
                        "description_contains": tr.description_contains,
                        "tags_any": tr.tags_any,
                        "priority": tr.priority,
                    }
                    for tr in t.triggers
                ],
                "phases": [p.get("name") for p in t.phases],
            }
            for t in self.templates
        ]


def create_single_phase_topology(
    task_description: str,
    role: str = "executor",
    toolchain: str | None = None,
    model_tier: ModelTier = ModelTier.DEFAULT,
) -> TaskTopology:
    """
    Create a simple single-phase, single-agent topology.

    Useful for tasks that don't need multi-agent coordination.
    """
    agent = AgentSpec(
        role=role,
        prompt_template=task_description,
        toolchain=toolchain,
        model_tier=model_tier,
    )

    phase = TopologyPhase(
        name="execute",
        agents=[agent],
        parallelism=ParallelismConfig.fixed(1),
        synthesis_mode=SynthesisMode.MERGE,
    )

    return TaskTopology(
        name=f"single:{task_description[:30]}",
        phases=[phase],
        metadata=TopologyMetadata(derived_from="single_phase"),
        task_description=task_description,
    )
