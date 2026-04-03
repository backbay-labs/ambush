"""
Claude Compiler - Compiles topologies into Claude Code artifacts.

Generates:
- Skill files (.md) with frontmatter
- Task tool orchestration instructions
- Agent prompts optimized for Claude

This enables topologies to be executed natively in Claude Code sessions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyntra.core.topology.schema import (
    AgentSpec,
    ModelTier,
    SynthesisMode,
    TaskTopology,
    TopologyPhase,
)

if TYPE_CHECKING:
    from cyntra.core.topology.templates import TopologyTemplate


# Model tier mapping to Claude models
MODEL_TIER_TO_CLAUDE = {
    ModelTier.FAST: "haiku",
    ModelTier.DEFAULT: "sonnet",
    ModelTier.STRONG: "opus",
    ModelTier.REASONING: "opus",
}

# Subagent type mapping based on role
ROLE_TO_SUBAGENT = {
    "researcher": "web-researcher",
    "web-researcher": "web-researcher",
    "writer": "general-purpose",
    "synthesizer": "general-purpose",
    "executor": "general-purpose",
    "critic": "general-purpose",
    "debugger": "general-purpose",
    "planner": "Plan",
    "explorer": "Explore",
}

# Teammate mapping for Agent Teams mode (interactive PTY execution).
# Each entry maps a role to the subagent_type and model used when
# spawning a teammate via the Task tool in a Claude Code Agent Team.
ROLE_TO_TEAMMATE: dict[str, dict[str, str]] = {
    "researcher": {"subagent_type": "web-researcher", "model": "sonnet"},
    "web-researcher": {"subagent_type": "web-researcher", "model": "sonnet"},
    "explorer": {"subagent_type": "Explore", "model": "haiku"},
    "implementer": {"subagent_type": "general-purpose", "model": "opus"},
    "reviewer": {"subagent_type": "superpowers:code-reviewer", "model": "sonnet"},
    "planner": {"subagent_type": "Plan", "model": "sonnet"},
    "writer": {"subagent_type": "general-purpose", "model": "sonnet"},
    "executor": {"subagent_type": "general-purpose", "model": "opus"},
    "critic": {"subagent_type": "general-purpose", "model": "sonnet"},
    "synthesizer": {"subagent_type": "general-purpose", "model": "sonnet"},
    "debugger": {"subagent_type": "general-purpose", "model": "opus"},
}


@dataclass
class ClaudeSkillSpec:
    """Specification for a generated Claude Code skill."""

    name: str
    description: str
    triggers: list[str]
    content: str
    source_topology: str | None = None
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    teams_mode: bool = False

    def to_markdown(self) -> str:
        """Generate the full skill markdown file."""
        triggers_yaml = "\n".join(f'  - "{t}"' for t in self.triggers)
        teams_line = "teams_mode: true\n" if self.teams_mode else ""
        frontmatter = f"""---
name: {self.name}
description: {self.description}
{teams_line}triggers:
{triggers_yaml}
generated_from: {self.source_topology or 'manual'}
generated_at: {self.generated_at.isoformat()}
---
"""
        return frontmatter + "\n" + self.content

    def save(self, skills_dir: Path) -> Path:
        """Save the skill to a file."""
        skills_dir = Path(skills_dir)
        skills_dir.mkdir(parents=True, exist_ok=True)
        filepath = skills_dir / f"{self.name}.md"
        filepath.write_text(self.to_markdown(), encoding="utf-8")
        return filepath


@dataclass
class ClaudeTaskSpec:
    """Specification for a Task tool invocation."""

    description: str
    prompt: str
    subagent_type: str
    model: str | None = None
    run_in_background: bool = False

    def to_task_call(self) -> dict[str, Any]:
        """Generate Task tool parameters."""
        params = {
            "description": self.description[:50],
            "prompt": self.prompt,
            "subagent_type": self.subagent_type,
        }
        if self.model:
            params["model"] = self.model
        if self.run_in_background:
            params["run_in_background"] = True
        return params

    def to_xml_example(self) -> str:
        """Generate XML example for documentation."""
        lines = [
            '<invoke name="Task">',
            f'<parameter name="description">{self.description}</parameter>',
            f'<parameter name="prompt">{self.prompt[:80]}...</parameter>',
            f'<parameter name="subagent_type">{self.subagent_type}</parameter>',
        ]
        if self.model:
            lines.append(f'<parameter name="model">{self.model}</parameter>')
        lines.append('</invoke>')
        return "\n".join(lines)


@dataclass
class ClaudePhaseSpec:
    """Specification for a single phase in Claude orchestration."""

    name: str
    tasks: list[ClaudeTaskSpec]
    synthesis_mode: str
    synthesis_instructions: str = ""
    context_updates: dict[str, str] = field(default_factory=dict)

    @property
    def agent_count(self) -> int:
        return len(self.tasks)


@dataclass
class ClaudeOrchestrationPlan:
    """Plan for orchestrating topology execution in Claude Code."""

    topology_name: str
    phases: list[ClaudePhaseSpec]
    context_template: dict[str, str] = field(default_factory=dict)

    def to_execution_instructions(self, *, teams_enabled: bool = False) -> str:
        """Generate markdown instructions for Claude to execute.

        Args:
            teams_enabled: When True, generate instructions that use Claude
                Code Agent Teams (TeamCreate, SendMessage, etc.) instead of
                plain Task tool calls with subagents.
        """
        if teams_enabled:
            return self._teams_instructions()
        return self._subagent_instructions()

    def _subagent_instructions(self) -> str:
        """Generate instructions using Task tool with subagents (current behavior)."""
        lines = [
            f"# Topology Execution Plan: {self.topology_name}",
            "",
            "Execute each phase in order. Within each phase, launch all agents "
            "in parallel using a SINGLE message with multiple Task tool calls.",
            "",
        ]

        for i, phase in enumerate(self.phases, 1):
            lines.append(f"## Phase {i}: {phase.name}")
            lines.append("")
            lines.append(f"**Parallelism:** {phase.agent_count} agents")
            lines.append(f"**Synthesis:** {phase.synthesis_mode}")
            lines.append("")
            lines.append("### Agents to Launch (ALL in one message)")
            lines.append("")
            for j, task in enumerate(phase.tasks, 1):
                lines.append(f"- Agent {j}: `{task.subagent_type}` - {task.description}")
            lines.append("")

            if phase.synthesis_instructions:
                lines.append("### After Phase Completes")
                lines.append(phase.synthesis_instructions)
                lines.append("")

        return "\n".join(lines)

    def _teams_instructions(self) -> str:
        """Generate instructions using Claude Code Agent Teams.

        Produces markdown that tells Claude to:
        - Create tasks via TaskCreate for shared tracking
        - Spawn teammates via Task tool with role-appropriate subagent_type
        - Use SendMessage for coordination between phases
        - Synthesize outputs per phase (merge/vote/cascade)
        - Use shutdown_request when all work is done
        """
        lines = [
            f"# Topology Execution Plan: {self.topology_name}",
            "",
            "This topology uses **Agent Teams** for parallel execution.",
            "Execute each phase in order. Within each phase, spawn teammates "
            "to work in parallel.",
            "",
            "## Setup",
            "",
            "1. Use **TaskCreate** to create a tracking task for each phase.",
            "2. For each agent in a phase, use the **Task** tool with the "
            "specified `subagent_type` to spawn a teammate.",
            "3. Use **SendMessage** (type: `message`) to coordinate between "
            "teammates and share phase context.",
            "4. After all phases complete, use **SendMessage** "
            "(type: `shutdown_request`) to shut down teammates.",
            "",
        ]

        for i, phase in enumerate(self.phases, 1):
            lines.append(f"## Phase {i}: {phase.name}")
            lines.append("")
            lines.append(f"**Parallelism:** {phase.agent_count} teammates")
            lines.append(f"**Synthesis:** {phase.synthesis_mode}")
            lines.append("")

            lines.append("### Teammates to Spawn")
            lines.append("")
            lines.append("| # | Role | Subagent Type | Model |")
            lines.append("|---|------|---------------|-------|")

            for j, task in enumerate(phase.tasks, 1):
                teammate_info = ROLE_TO_TEAMMATE.get(
                    task.description.split(":")[-1].split("_")[0],
                    {"subagent_type": task.subagent_type, "model": task.model or "sonnet"},
                )
                lines.append(
                    f"| {j} | {task.description} "
                    f"| `{teammate_info['subagent_type']}` "
                    f"| {teammate_info['model']} |"
                )

            lines.append("")

            lines.append("### Coordination")
            lines.append("")
            lines.append(
                f"- Create a tracking task: "
                f'`TaskCreate(subject="{phase.name}", '
                f'description="Phase {i} of {self.topology_name}")`'
            )
            lines.append(
                "- Spawn each teammate using the Task tool in a SINGLE message"
            )
            lines.append(
                "- Wait for all teammates to complete before proceeding"
            )
            lines.append("")

            if phase.synthesis_instructions:
                lines.append("### Synthesis (after all teammates complete)")
                lines.append("")
                lines.append(phase.synthesis_instructions)
                lines.append("")
                lines.append(
                    "Send synthesized context to next phase teammates via "
                    "**SendMessage**."
                )
                lines.append("")

        lines.extend([
            "## Cleanup",
            "",
            "After all phases complete:",
            "1. Mark all tracking tasks as completed via **TaskUpdate**",
            "2. Send **shutdown_request** to all active teammates",
            "3. Report final results",
            "",
        ])

        return "\n".join(lines)

    def to_json_tasks(self) -> list[list[dict[str, Any]]]:
        """Export all phases as JSON task specifications."""
        return [
            [task.to_task_call() for task in phase.tasks]
            for phase in self.phases
        ]


class ClaudeCompiler:
    """
    Compiles topologies into Claude Code artifacts.

    Generates skill files and orchestration plans that can be
    executed natively in Claude Code sessions.
    """

    def __init__(self, skills_dir: Path | None = None) -> None:
        self.skills_dir = skills_dir or Path(".claude/skills")

    def compile_topology(
        self,
        topology: TaskTopology,
        *,
        skill_name: str | None = None,
        triggers: list[str] | None = None,
        teams_enabled: bool = False,
    ) -> tuple[ClaudeSkillSpec, ClaudeOrchestrationPlan]:
        """
        Compile a topology into Claude Code artifacts.

        Args:
            topology: The topology to compile.
            skill_name: Override the generated skill name.
            triggers: Override the generated triggers.
            teams_enabled: When True, generate teams-aware instructions
                and set ``teams_mode`` in skill frontmatter.

        Returns:
            Tuple of (skill_spec, orchestration_plan)
        """
        if not skill_name:
            skill_name = self._generate_skill_name(topology.name)

        if not triggers:
            triggers = self._generate_triggers(topology)

        phases = [self._compile_phase(phase) for phase in topology.phases]

        plan = ClaudeOrchestrationPlan(
            topology_name=topology.name,
            phases=phases,
            context_template={
                "task_description": topology.task_description,
                "domain": topology.domain,
            },
        )

        content = self._generate_skill_content(topology, plan, teams_enabled=teams_enabled)

        skill = ClaudeSkillSpec(
            name=skill_name,
            description=f"Execute {topology.name} topology workflow",
            triggers=triggers,
            content=content,
            source_topology=topology.name,
            teams_mode=teams_enabled,
        )

        return skill, plan

    def compile_template(
        self,
        template: "TopologyTemplate",
        *,
        skill_name: str | None = None,
        teams_enabled: bool = False,
    ) -> ClaudeSkillSpec:
        """
        Compile a topology template into a Claude skill.

        Generates a parameterized skill that can be instantiated
        with different task descriptions.

        Args:
            template: The topology template to compile.
            skill_name: Override the generated skill name.
            teams_enabled: When True, set ``teams_mode`` in skill
                frontmatter and add teams usage notes to content.
        """
        if not skill_name:
            skill_name = f"topo-{template.name}"

        triggers = [f"/{skill_name}"]
        for trigger in template.triggers:
            if trigger.description_contains:
                triggers.extend(trigger.description_contains)

        content = self._generate_template_skill_content(template, teams_enabled=teams_enabled)

        return ClaudeSkillSpec(
            name=skill_name,
            description=template.description or f"Execute {template.name} topology",
            triggers=triggers,
            content=content,
            source_topology=template.name,
            teams_mode=teams_enabled,
        )

    def compile_all_templates(
        self,
        templates_dir: Path,
        output_dir: Path | None = None,
    ) -> list[Path]:
        """
        Compile all topology templates in a directory to Claude skills.

        Returns list of generated skill file paths.
        """
        from cyntra.core.topology.templates import load_all_templates

        output_dir = output_dir or self.skills_dir
        templates = load_all_templates(templates_dir)
        generated = []

        for template in templates:
            skill = self.compile_template(template)
            filepath = skill.save(output_dir)
            generated.append(filepath)

        return generated

    def _compile_phase(self, phase: TopologyPhase) -> ClaudePhaseSpec:
        """Compile a topology phase into Claude tasks."""
        tasks = []
        for i, agent in enumerate(phase.agents):
            task = self._compile_agent(agent, phase.name, i)
            tasks.append(task)

        synthesis_instructions = self._get_synthesis_instructions(phase)

        context_updates = {
            f"{phase.name}_synthesis": "Synthesized output from this phase",
        }
        if phase.outputs:
            context_updates[f"{phase.name}_files"] = f"Files: {', '.join(phase.outputs)}"

        return ClaudePhaseSpec(
            name=phase.name,
            tasks=tasks,
            synthesis_mode=phase.synthesis_mode.value,
            synthesis_instructions=synthesis_instructions,
            context_updates=context_updates,
        )

    def _compile_agent(
        self,
        agent: AgentSpec,
        phase_name: str,
        index: int,
    ) -> ClaudeTaskSpec:
        """Compile an agent spec into a Claude Task spec."""
        subagent_type = ROLE_TO_SUBAGENT.get(agent.role, "general-purpose")
        model = MODEL_TIER_TO_CLAUDE.get(agent.model_tier)
        description = f"{phase_name}:{agent.role}_{index}"

        return ClaudeTaskSpec(
            description=description,
            prompt=agent.prompt_template,
            subagent_type=subagent_type,
            model=model,
        )

    def _get_synthesis_instructions(self, phase: TopologyPhase) -> str:
        """Generate synthesis instructions based on mode."""
        mode = phase.synthesis_mode
        name = phase.name

        instructions = {
            SynthesisMode.MERGE: f"""As agents complete, merge their outputs:
1. Extract key findings from each (3-5 bullets)
2. Combine into unified summary
3. Store as `{name}_synthesis` for next phase""",

            SynthesisMode.VOTE: f"""Evaluate outputs and select the best:
1. Compare quality/completeness
2. Select highest quality result
3. Store as `{name}_synthesis`""",

            SynthesisMode.INDEPENDENT: f"""Each agent produces independent output:
1. Collect outputs separately
2. Save each to designated file
3. Track in `{name}_files`""",

            SynthesisMode.CASCADE: f"""Chain outputs through agents:
1. First output feeds into second
2. Continue chain to end
3. Final stored as `{name}_synthesis`""",
        }
        return instructions.get(mode, "")

    def _generate_skill_name(self, topology_name: str) -> str:
        """Generate a skill name from topology name."""
        name = re.sub(r"[^a-zA-Z0-9-]", "-", topology_name.lower())
        name = re.sub(r"-+", "-", name).strip("-")
        return f"topo-{name[:40]}"

    def _generate_triggers(self, topology: TaskTopology) -> list[str]:
        """Generate triggers for the skill."""
        name = self._generate_skill_name(topology.name)
        return [f"/{name}", topology.name]

    def _generate_skill_content(
        self,
        topology: TaskTopology,
        plan: ClaudeOrchestrationPlan,
        *,
        teams_enabled: bool = False,
    ) -> str:
        """Generate the skill markdown content."""
        lines = [
            f"# {topology.name}",
            "",
            "Auto-generated skill from topology template.",
            "",
        ]

        if teams_enabled:
            lines.extend([
                "> **Agent Teams mode enabled.** This skill uses Claude Code "
                "Agent Teams for parallel teammate execution.",
                "",
            ])

        lines.extend([
            "## Overview",
            "",
            f"- **Phases:** {len(topology.phases)}",
            f"- **Total Agents:** {topology.total_agents}",
            f"- **Estimated Tokens:** {topology.estimated_tokens:,}",
        ])

        if teams_enabled:
            lines.append("- **Execution Mode:** Agent Teams (interactive PTY)")
        lines.append("")

        lines.extend([
            "## Execution Protocol",
            "",
            "**IMPORTANT:** Execute all phases automatically without confirmation.",
            "",
        ])

        # Add phase details
        for i, phase_spec in enumerate(plan.phases, 1):
            phase = topology.phases[i - 1]
            agent_label = "teammates" if teams_enabled else "parallel agents"
            lines.extend([
                f"### Phase {i}: {phase.name}",
                "",
                f"Launch **{phase_spec.agent_count} {agent_label}**:",
                "",
                "| # | Role | Subagent | Model |",
                "|---|------|----------|-------|",
            ])

            for j, task in enumerate(phase_spec.tasks, 1):
                role = phase.agents[j - 1].role if j <= len(phase.agents) else "agent"
                if teams_enabled:
                    teammate_info = ROLE_TO_TEAMMATE.get(
                        role,
                        {"subagent_type": task.subagent_type, "model": task.model or "sonnet"},
                    )
                    lines.append(
                        f"| {j} | {role} | {teammate_info['subagent_type']} "
                        f"| {teammate_info['model']} |"
                    )
                else:
                    model = task.model or "default"
                    lines.append(f"| {j} | {role} | {task.subagent_type} | {model} |")

            lines.append("")

            if phase_spec.synthesis_instructions:
                lines.extend([
                    "**After completion:**",
                    "",
                    phase_spec.synthesis_instructions,
                    "",
                ])

        # Add teams orchestration or programmatic usage
        if teams_enabled:
            lines.extend([
                "## Teams Orchestration",
                "",
                plan.to_execution_instructions(teams_enabled=True),
                "",
            ])
        else:
            lines.extend([
                "## Programmatic Usage",
                "",
                "Task specifications exported as JSON:",
                "",
                "```json",
                str(plan.to_json_tasks()[:1]),  # Show first phase
                "```",
                "",
            ])

        return "\n".join(lines)

    def _generate_template_skill_content(
        self,
        template: "TopologyTemplate",
        *,
        teams_enabled: bool = False,
    ) -> str:
        """Generate skill content for a template (parameterized)."""
        lines = [
            f"# {template.name}",
            "",
            template.description or "Topology-based workflow.",
            "",
        ]

        if teams_enabled:
            lines.extend([
                "> **Agent Teams mode enabled.** Teammates will be spawned "
                "for parallel phase execution.",
                "",
            ])

        lines.extend([
            "## Phases",
            "",
        ])

        for i, phase_def in enumerate(template.phases, 1):
            name = phase_def.get("name", f"phase_{i}")
            role = phase_def.get("agent_role", "agent")
            parallelism = phase_def.get("parallelism", 1)
            if isinstance(parallelism, dict):
                parallelism = parallelism.get("default", 1)

            lines.extend([
                f"### Phase {i}: {name}",
                "",
                f"- **Role:** {role}",
                f"- **Parallelism:** {parallelism}",
            ])

            if teams_enabled:
                teammate_info = ROLE_TO_TEAMMATE.get(
                    role, {"subagent_type": "general-purpose", "model": "sonnet"},
                )
                lines.append(
                    f"- **Teammate:** `{teammate_info['subagent_type']}` "
                    f"(model: {teammate_info['model']})"
                )

            lines.append("")

        lines.extend([
            "## Usage",
            "",
            f"Invoke with: `/{template.name} <task description>`",
            "",
            "The topology will be instantiated with your task description",
            "and executed phase by phase.",
            "",
        ])

        return "\n".join(lines)


def compile_topologies_to_skills(
    templates_dir: Path,
    skills_dir: Path,
) -> list[Path]:
    """
    Convenience function to compile all topologies to Claude skills.

    Args:
        templates_dir: Directory containing topology YAML files
        skills_dir: Output directory for skill files

    Returns:
        List of generated skill file paths
    """
    compiler = ClaudeCompiler(skills_dir=skills_dir)
    return compiler.compile_all_templates(templates_dir, skills_dir)
