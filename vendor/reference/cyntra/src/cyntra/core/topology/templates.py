"""
Topology Templates - YAML-based topology definitions.

Provides loading and parsing of topology templates from YAML files,
allowing declarative definition of agent swarm patterns.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

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

logger = logging.getLogger(__name__)


@dataclass
class TopologyTrigger:
    """Condition that triggers a topology template."""

    task_type: str | None = None  # e.g., "research", "implementation", "repair"
    description_contains: list[str] = field(default_factory=list)  # OR match
    description_pattern: str | None = None  # Regex pattern
    tags_any: list[str] = field(default_factory=list)  # OR match on tags
    tags_all: list[str] = field(default_factory=list)  # AND match on tags
    priority: int = 0  # Higher = checked first

    def matches(self, task_description: str, task_tags: list[str] | None = None) -> bool:
        """Check if this trigger matches the given task."""
        task_tags = task_tags or []
        description_lower = task_description.lower()

        # Check description_contains (OR logic)
        if self.description_contains:
            if not any(kw.lower() in description_lower for kw in self.description_contains):
                return False

        # Check description_pattern
        if self.description_pattern:
            if not re.search(self.description_pattern, task_description, re.IGNORECASE):
                return False

        # Check tags_any (OR logic)
        if self.tags_any:
            if not any(tag in task_tags for tag in self.tags_any):
                return False

        # Check tags_all (AND logic)
        if self.tags_all:
            if not all(tag in task_tags for tag in self.tags_all):
                return False

        return True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TopologyTrigger":
        """Parse trigger from YAML dict."""
        return cls(
            task_type=data.get("task_type"),
            description_contains=data.get("description_contains", []),
            description_pattern=data.get("description_pattern"),
            tags_any=data.get("tags_any", []),
            tags_all=data.get("tags_all", []),
            priority=int(data.get("priority", 0)),
        )


@dataclass
class PromptTemplateRef:
    """Reference to a prompt template with variable substitution."""

    template: str
    variables: dict[str, str] = field(default_factory=dict)

    def render(self, context: dict[str, Any]) -> str:
        """Render the template with the given context."""
        result = self.template
        # First apply explicit variable mappings
        for var, key in self.variables.items():
            value = context.get(key, f"{{{var}}}")
            result = result.replace(f"{{{var}}}", str(value))
        # Then apply any remaining context values
        for key, value in context.items():
            result = result.replace(f"{{{key}}}", str(value))
        return result


@dataclass
class TopologyTemplate:
    """
    A topology template loaded from YAML.

    Templates define reusable agent swarm patterns that can be
    instantiated for specific tasks.
    """

    name: str
    description: str
    triggers: list[TopologyTrigger]
    phases: list[dict[str, Any]]  # Raw phase definitions

    # Optional constraints override
    constraints: dict[str, Any] = field(default_factory=dict)

    # Prompt templates
    prompts: dict[str, str] = field(default_factory=dict)

    # Source file
    source_path: Path | None = None

    def instantiate(
        self,
        task_description: str,
        domain: str = "",
        context: dict[str, Any] | None = None,
        constraints_override: TopologyConstraints | None = None,
    ) -> TaskTopology:
        """
        Create a TaskTopology from this template.

        Args:
            task_description: Description of the task to execute
            domain: Domain/industry for the task
            context: Additional context for prompt rendering
            constraints_override: Optional constraints to override template defaults
        """
        context = context or {}
        context["task_description"] = task_description
        context["domain"] = domain

        # Build phases
        phases = []
        for phase_def in self.phases:
            phase = self._build_phase(phase_def, context)
            phases.append(phase)

        # Build constraints
        constraints = constraints_override or self._build_constraints()

        # Build metadata
        metadata = TopologyMetadata(
            derived_from="template",
            template_name=self.name,
            confidence=1.0,
        )

        return TaskTopology(
            name=f"{self.name}:{task_description[:50]}",
            phases=phases,
            constraints=constraints,
            metadata=metadata,
            task_description=task_description,
            domain=domain,
        )

    def _build_phase(self, phase_def: dict[str, Any], context: dict[str, Any]) -> TopologyPhase:
        """Build a TopologyPhase from a phase definition."""
        name = phase_def["name"]

        # Parse parallelism
        parallelism_data = phase_def.get("parallelism", 1)
        parallelism = ParallelismConfig.from_dict(parallelism_data)

        # Parse synthesis mode
        synthesis_str = phase_def.get("synthesis", "merge")
        try:
            synthesis_mode = SynthesisMode(synthesis_str)
        except ValueError:
            synthesis_mode = SynthesisMode.MERGE

        # Build agents
        agents = self._build_agents(phase_def, context, parallelism.default)

        # Parse other fields
        return TopologyPhase(
            name=name,
            agents=agents,
            parallelism=parallelism,
            wait_for_all=phase_def.get("wait_for_all", True),
            synthesis_mode=synthesis_mode,
            timeout_ms=int(phase_def.get("timeout_ms", 600_000)),
            inputs_from=phase_def.get("inputs_from", []),
            context_keys=phase_def.get("context_keys", []),
            outputs=phase_def.get("outputs", []),
        )

    def _build_agents(
        self, phase_def: dict[str, Any], context: dict[str, Any], parallelism: int
    ) -> list[AgentSpec]:
        """Build AgentSpec list from phase definition."""
        agents = []

        # Check for explicit agents list
        if "agents" in phase_def:
            for agent_def in phase_def["agents"]:
                agent = self._build_single_agent(agent_def, context)
                agents.append(agent)
            return agents

        # Build from role + prompts_from pattern
        role = phase_def.get("agent_role", "agent")
        prompts_from = phase_def.get("prompts_from")
        prompt_list = phase_def.get("prompts", [])

        # Get prompts either from reference or inline
        if prompts_from and prompts_from in self.prompts:
            prompt_template = self.prompts[prompts_from]
            # If it's a list of prompts, create one agent per prompt
            if isinstance(prompt_template, list):
                prompt_list = prompt_template
            else:
                prompt_list = [prompt_template]

        # If we have a prompts_from reference to a dimensions list, expand
        if prompts_from:
            dimensions_key = f"{prompts_from}_dimensions"
            if dimensions_key in context:
                prompt_list = context[dimensions_key]

        # Create agents from prompts
        model_tier_str = phase_def.get("model_tier", "default")
        try:
            model_tier = ModelTier(model_tier_str)
        except ValueError:
            model_tier = ModelTier.DEFAULT

        toolchain = phase_def.get("toolchain")
        timeout_ms = int(phase_def.get("agent_timeout_ms", 300_000))
        output_files = phase_def.get("outputs", [])

        if prompt_list:
            for i, prompt in enumerate(prompt_list):
                rendered_prompt = self._render_prompt(prompt, context)
                output_file = output_files[i] if i < len(output_files) else None
                agents.append(
                    AgentSpec(
                        role=role,
                        prompt_template=rendered_prompt,
                        toolchain=toolchain,
                        model_tier=model_tier,
                        timeout_ms=timeout_ms,
                        output_key=f"{role}_{i}",
                        output_file=output_file,
                    )
                )
        else:
            # Create parallelism number of generic agents
            base_prompt = phase_def.get("prompt", f"Execute {role} task for {{task_description}}")
            rendered_prompt = self._render_prompt(base_prompt, context)
            for i in range(parallelism):
                output_file = output_files[i] if i < len(output_files) else None
                agents.append(
                    AgentSpec(
                        role=role,
                        prompt_template=rendered_prompt,
                        toolchain=toolchain,
                        model_tier=model_tier,
                        timeout_ms=timeout_ms,
                        output_key=f"{role}_{i}",
                        output_file=output_file,
                    )
                )

        return agents

    def _build_single_agent(self, agent_def: dict[str, Any], context: dict[str, Any]) -> AgentSpec:
        """Build a single AgentSpec from definition."""
        role = agent_def.get("role", "agent")
        prompt = agent_def.get("prompt", "")
        rendered_prompt = self._render_prompt(prompt, context)

        model_tier_str = agent_def.get("model_tier", "default")
        try:
            model_tier = ModelTier(model_tier_str)
        except ValueError:
            model_tier = ModelTier.DEFAULT

        return AgentSpec(
            role=role,
            prompt_template=rendered_prompt,
            toolchain=agent_def.get("toolchain"),
            model_tier=model_tier,
            timeout_ms=int(agent_def.get("timeout_ms", 300_000)),
            max_tokens=int(agent_def.get("max_tokens", 100_000)),
            tools=agent_def.get("tools", []),
            config=agent_def.get("config", {}),
            output_key=agent_def.get("output_key"),
            output_file=agent_def.get("output_file"),
        )

    def _render_prompt(self, prompt: str, context: dict[str, Any]) -> str:
        """Render a prompt template with context."""
        result = prompt
        for key, value in context.items():
            result = result.replace(f"{{{key}}}", str(value))
        return result

    def _build_constraints(self) -> TopologyConstraints:
        """Build TopologyConstraints from template constraints."""
        if not self.constraints:
            return TopologyConstraints()

        return TopologyConstraints(
            max_parallel_agents=int(self.constraints.get("max_parallel_agents", 6)),
            max_tokens_per_phase=int(self.constraints.get("max_tokens_per_phase", 500_000)),
            max_total_tokens=int(self.constraints.get("max_total_tokens", 2_000_000)),
            max_duration_ms=int(self.constraints.get("max_duration_ms", 1_800_000)),
            token_budget_factor=float(self.constraints.get("token_budget_factor", 1.0)),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any], source_path: Path | None = None) -> "TopologyTemplate":
        """Parse template from YAML dict."""
        name = data.get("name", "unnamed")
        description = data.get("description", "")

        # Parse triggers
        triggers = []
        triggers_data = data.get("triggers", [])
        if isinstance(triggers_data, list):
            for trigger_data in triggers_data:
                if isinstance(trigger_data, dict):
                    triggers.append(TopologyTrigger.from_dict(trigger_data))
        elif isinstance(triggers_data, dict):
            # Single trigger as dict
            triggers.append(TopologyTrigger.from_dict(triggers_data))

        # Parse phases
        phases = data.get("phases", [])

        # Parse prompts
        prompts = data.get("prompts", {})

        # Parse constraints
        constraints = data.get("constraints", {})

        return cls(
            name=name,
            description=description,
            triggers=triggers,
            phases=phases,
            constraints=constraints,
            prompts=prompts,
            source_path=source_path,
        )


def load_template(path: Path) -> TopologyTemplate:
    """
    Load a topology template from a YAML file.

    Args:
        path: Path to the YAML template file

    Returns:
        Parsed TopologyTemplate

    Raises:
        FileNotFoundError: If the template file doesn't exist
        ValueError: If the template is invalid
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Template not found: {path}")

    try:
        with open(path) as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Template must be a YAML dict: {path}")

        return TopologyTemplate.from_dict(data, source_path=path)

    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in template {path}: {e}") from e


def load_all_templates(directory: Path) -> list[TopologyTemplate]:
    """
    Load all topology templates from a directory.

    Args:
        directory: Directory containing YAML template files

    Returns:
        List of loaded templates, sorted by trigger priority (highest first)
    """
    directory = Path(directory)
    if not directory.exists():
        logger.warning(f"Template directory not found: {directory}")
        return []

    templates = []
    for path in directory.glob("*.yaml"):
        try:
            template = load_template(path)
            templates.append(template)
            logger.debug(f"Loaded template: {template.name} from {path}")
        except Exception as e:
            logger.warning(f"Failed to load template {path}: {e}")

    # Also check .yml extension
    for path in directory.glob("*.yml"):
        try:
            template = load_template(path)
            templates.append(template)
            logger.debug(f"Loaded template: {template.name} from {path}")
        except Exception as e:
            logger.warning(f"Failed to load template {path}: {e}")

    # Sort by highest trigger priority
    def max_priority(t: TopologyTemplate) -> int:
        if not t.triggers:
            return 0
        return max(trigger.priority for trigger in t.triggers)

    templates.sort(key=max_priority, reverse=True)

    logger.info(f"Loaded {len(templates)} topology templates from {directory}")
    return templates
