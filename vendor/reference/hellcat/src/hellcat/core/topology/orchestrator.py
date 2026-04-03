"""
Phased Orchestrator - Executes multi-phase agent topologies.

Coordinates parallel agent execution within phases, handles phase barriers,
and synthesizes results between phases.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hellcat.core.topology.schema import (
    AgentSpec,
    PhaseOutput,
    SynthesisMode,
    TaskTopology,
    TopologyPhase,
    TopologyResult,
)
from hellcat.core.verifier import Verifier
try:
    from hellcat.core.workcell.manager import WorkcellManager
except ImportError:
    WorkcellManager = None  # type: ignore[assignment,misc]

if TYPE_CHECKING:
    from hellcat.core.dispatcher.dispatcher import Dispatcher
    from hellcat.core.scheduler.routing import KernelConfig
    from hellcat.core.state.models import Issue

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorConfig:
    """Configuration for the phased orchestrator."""

    # Execution settings
    max_concurrent_agents: int = 6
    default_agent_timeout_ms: int = 300_000
    phase_timeout_ms: int = 600_000

    # Output settings
    output_dir: Path = field(default_factory=lambda: Path("docs"))
    write_intermediate_outputs: bool = True
    keep_workcell_logs: bool = True

    # Synthesis settings
    merge_separator: str = "\n\n---\n\n"
    vote_threshold: float = 0.7

    # Progress callbacks
    on_phase_start: Callable[[str, int], None] | None = None
    on_phase_complete: Callable[[str, PhaseOutput], None] | None = None
    on_agent_complete: Callable[[str, str, dict[str, Any]], None] | None = None


@dataclass
class AgentResult:
    """Result from a single agent execution."""

    agent_spec: AgentSpec
    output: str
    success: bool
    duration_ms: int
    token_usage: int = 0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentExecutionResult:
    """Raw execution result from an agent runner."""

    output: str
    success: bool
    token_usage: int = 0
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class PhasedOrchestrator:
    """
    Executes multi-phase agent topologies.

    Manages parallel agent execution within each phase, handles
    synchronization barriers between phases, and synthesizes
    results for context passing.
    """

    def __init__(
        self,
        config: OrchestratorConfig | None = None,
        kernel_config: KernelConfig | None = None,
        dispatcher: Dispatcher | None = None,
    ) -> None:
        self.config = config or OrchestratorConfig()
        self.kernel_config = kernel_config
        self.dispatcher = dispatcher

        # Execution state
        self._context: dict[str, Any] = {}
        self._phase_outputs: dict[str, PhaseOutput] = {}
        self._aborted = False
        self._issue: Issue | None = None
        self._workcell_manager: WorkcellManager | None = None
        self._verifier: Verifier | None = None
        if self.dispatcher and self.kernel_config:
            self._workcell_manager = WorkcellManager(self.kernel_config, self.kernel_config.repo_root)
            self._verifier = Verifier(self.kernel_config)

    async def execute(
        self,
        topology: TaskTopology,
        initial_context: dict[str, Any] | None = None,
        *,
        issue: Issue | None = None,
    ) -> TopologyResult:
        """
        Execute a complete topology.

        Args:
            topology: The topology to execute
            initial_context: Initial context for prompt rendering
            issue: Optional issue for tracking

        Returns:
            TopologyResult with all phase outputs and final result
        """
        start_time = time.time()
        self._context = dict(initial_context or {})
        self._context["task_description"] = topology.task_description
        self._context["domain"] = topology.domain
        self._phase_outputs = {}
        self._aborted = False
        self._issue = issue
        if self.dispatcher and self.kernel_config and not self._workcell_manager:
            self._workcell_manager = WorkcellManager(self.kernel_config, self.kernel_config.repo_root)
        if self.dispatcher and self.kernel_config and not self._verifier:
            self._verifier = Verifier(self.kernel_config)

        phase_outputs: list[PhaseOutput] = []
        total_tokens = 0

        try:
            for phase in topology.phases:
                if self._aborted:
                    break

                # Check timeout
                elapsed_ms = int((time.time() - start_time) * 1000)
                if elapsed_ms > topology.constraints.max_duration_ms:
                    logger.warning(f"Topology timeout reached, stopping at phase {phase.name}")
                    break

                # Execute phase
                phase_output = await self._execute_phase(
                    phase=phase,
                    constraints=topology.constraints,
                )
                phase_outputs.append(phase_output)
                self._phase_outputs[phase.name] = phase_output
                total_tokens += phase_output.token_usage

                if not phase_output.success:
                    logger.error(f"Phase {phase.name} failed: {phase_output.error}")
                    break

                # Update context with phase results
                self._update_context_from_phase(phase, phase_output)

            # Build final output
            duration_ms = int((time.time() - start_time) * 1000)
            final_output = self._build_final_output(phase_outputs)
            success = all(p.success for p in phase_outputs) and len(phase_outputs) == len(
                topology.phases
            )

            return TopologyResult(
                topology_name=topology.name,
                phase_outputs=phase_outputs,
                final_output=final_output,
                total_duration_ms=duration_ms,
                total_tokens=total_tokens,
                success=success,
                error=None if success else "One or more phases failed",
            )

        except Exception as e:
            logger.exception(f"Topology execution failed: {e}")
            duration_ms = int((time.time() - start_time) * 1000)
            return TopologyResult(
                topology_name=topology.name,
                phase_outputs=phase_outputs,
                final_output=None,
                total_duration_ms=duration_ms,
                total_tokens=total_tokens,
                success=False,
                error=str(e),
            )
        finally:
            self._issue = None

    def prepare_execution(
        self,
        topology: TaskTopology,
        *,
        initial_context: dict[str, Any] | None = None,
        issue: Issue | None = None,
    ) -> None:
        """Initialize context for phase-by-phase execution."""
        self._context = dict(initial_context or {})
        self._context["task_description"] = topology.task_description
        self._context["domain"] = topology.domain
        self._phase_outputs = {}
        self._aborted = False
        self._issue = issue
        if self.dispatcher and self.kernel_config and not self._workcell_manager:
            self._workcell_manager = WorkcellManager(self.kernel_config, self.kernel_config.repo_root)
        if self.dispatcher and self.kernel_config and not self._verifier:
            self._verifier = Verifier(self.kernel_config)

    def update_context(self, updates: dict[str, Any]) -> None:
        """Merge additional context for prompt rendering."""
        if not updates:
            return
        self._context.update(updates)

    async def execute_phase(
        self,
        *,
        topology: TaskTopology,
        phase: TopologyPhase,
        context_updates: dict[str, Any] | None = None,
        issue: Issue | None = None,
    ) -> PhaseOutput:
        """Execute a single phase with optional context updates."""
        if not self._context:
            self.prepare_execution(topology, initial_context=None, issue=issue)
        if issue is not None:
            self._issue = issue
        if context_updates:
            self.update_context(context_updates)

        phase_output = await self._execute_phase(
            phase=phase,
            constraints=topology.constraints,
        )
        self._phase_outputs[phase.name] = phase_output
        self._update_context_from_phase(phase, phase_output)
        return phase_output

    async def _execute_phase(
        self,
        phase: TopologyPhase,
        constraints: Any,
    ) -> PhaseOutput:
        """Execute a single phase with parallel agents."""
        start_time = time.time()
        logger.info(f"Starting phase: {phase.name} with {len(phase.agents)} agents")

        if self.config.on_phase_start:
            self.config.on_phase_start(phase.name, len(phase.agents))

        # Prepare agents with rendered prompts
        prepared_agents = self._prepare_agents(phase)

        # Execute agents in parallel (respecting concurrency limit)
        agent_results = await self._execute_agents_parallel(
            agents=prepared_agents,
            max_concurrent=min(constraints.max_parallel_agents, self.config.max_concurrent_agents),
            timeout_ms=phase.timeout_ms,
        )

        # Synthesize results
        synthesized = self._synthesize_results(agent_results, phase.synthesis_mode)

        # Write output files if specified
        files_written = await self._write_phase_outputs(phase, agent_results)

        duration_ms = int((time.time() - start_time) * 1000)
        total_tokens = sum(r.token_usage for r in agent_results)
        success = any(r.success for r in agent_results)
        error = None if success else "; ".join(r.error or "Unknown error" for r in agent_results if not r.success)

        phase_output = PhaseOutput(
            phase_name=phase.name,
            agent_outputs=[
                {
                    "role": r.agent_spec.role,
                    "output": r.output,
                    "success": r.success,
                    "duration_ms": r.duration_ms,
                    "output_key": r.agent_spec.output_key,
                    "output_file": r.agent_spec.output_file,
                    "metadata": r.metadata,
                }
                for r in agent_results
            ],
            synthesized=synthesized,
            files_written=files_written,
            duration_ms=duration_ms,
            token_usage=total_tokens,
            success=success,
            error=error,
        )

        if self.config.on_phase_complete:
            self.config.on_phase_complete(phase.name, phase_output)

        return phase_output

    def _prepare_agents(self, phase: TopologyPhase) -> list[AgentSpec]:
        """Prepare agents with rendered prompts."""
        prepared = []
        for agent in phase.agents:
            # Render prompt with current context
            rendered_prompt = self._render_prompt(agent.prompt_template)
            prepared.append(agent.with_prompt(rendered_prompt))
        return prepared

    def _render_prompt(self, template: str) -> str:
        """Render a prompt template with current context."""
        result = template

        # Replace context variables
        for key, value in self._context.items():
            placeholder = f"{{{key}}}"
            if placeholder in result:
                result = result.replace(placeholder, str(value))

        # Replace phase synthesis references
        for phase_name, phase_output in self._phase_outputs.items():
            synthesis_key = f"{{{phase_name}_synthesis}}"
            if synthesis_key in result:
                result = result.replace(synthesis_key, str(phase_output.synthesized))

            files_key = f"{{{phase_name}_files}}"
            if files_key in result:
                files_str = "\n".join(f"- {f}" for f in phase_output.files_written)
                result = result.replace(files_key, files_str)

        return result

    async def _execute_agents_parallel(
        self,
        agents: list[AgentSpec],
        max_concurrent: int,
        timeout_ms: int,
    ) -> list[AgentResult]:
        """Execute agents in parallel with concurrency limit."""
        semaphore = asyncio.Semaphore(max_concurrent)
        results: list[AgentResult] = []

        async def execute_with_semaphore(agent: AgentSpec, index: int) -> AgentResult:
            async with semaphore:
                return await self._execute_single_agent(agent, index, timeout_ms)

        # Create tasks for all agents
        tasks = [execute_with_semaphore(agent, i) for i, agent in enumerate(agents)]

        # Wait for all with overall timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout_ms / 1000,
            )

            # Convert exceptions to failed results
            final_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    final_results.append(
                        AgentResult(
                            agent_spec=agents[i],
                            output="",
                            success=False,
                            duration_ms=0,
                            error=str(result),
                        )
                    )
                else:
                    final_results.append(result)
            return final_results

        except TimeoutError:
            logger.warning("Phase timeout reached, returning partial results")
            return results if results else [
                AgentResult(
                    agent_spec=agent,
                    output="",
                    success=False,
                    duration_ms=0,
                    error="Timeout",
                )
                for agent in agents
            ]

    async def _execute_single_agent(
        self,
        agent: AgentSpec,
        index: int,
        timeout_ms: int,
    ) -> AgentResult:
        """Execute a single agent."""
        start_time = time.time()

        try:
            # If we have a dispatcher, use it
            if self.dispatcher:
                result = await self._execute_via_dispatcher(agent, timeout_ms)
            else:
                # Fallback: simulate execution (for testing)
                result = await self._simulate_agent_execution(agent)

            duration_ms = int((time.time() - start_time) * 1000)

            if self.config.on_agent_complete:
                self.config.on_agent_complete(
                    agent.role,
                    f"agent_{index}",
                    {"success": result.success, "duration_ms": duration_ms},
                )

            return AgentResult(
                agent_spec=agent,
                output=result.output,
                success=result.success,
                duration_ms=duration_ms,
                token_usage=result.token_usage,
                error=result.error,
                metadata=result.metadata,
            )

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.exception(f"Agent execution failed: {e}")
            return AgentResult(
                agent_spec=agent,
                output="",
                success=False,
                duration_ms=duration_ms,
                error=str(e),
            )

    async def _execute_via_dispatcher(
        self,
        agent: AgentSpec,
        timeout_ms: int,
    ) -> AgentExecutionResult:
        """Execute agent via the kernel dispatcher."""
        if not self.dispatcher or not self.kernel_config:
            return AgentExecutionResult(
                output="",
                success=False,
                error="Dispatcher not configured",
            )

        issue = self._issue
        if issue is None:
            return AgentExecutionResult(
                output="",
                success=False,
                error="Issue context required for dispatcher execution",
            )

        if not self._workcell_manager:
            self._workcell_manager = WorkcellManager(self.kernel_config, self.kernel_config.repo_root)

        toolchain = agent.toolchain or self.dispatcher._route_toolchain(issue)
        tag = f"hsm-{agent.role}" if agent.role else "hsm"

        workcell_path = None
        try:
            workcell_path = self._workcell_manager.create(issue.id, speculate_tag=tag)
            workcell_id = workcell_path.name

            cycle_context = self._context.get("cycle_context")
            description_parts = []
            if isinstance(cycle_context, str) and cycle_context.strip():
                description_parts.append(cycle_context.strip())
            if agent.prompt_template:
                description_parts.append(agent.prompt_template)
            description = "\n\n".join(description_parts) if description_parts else agent.prompt_template

            override_title = issue.title
            if agent.role:
                override_title = f"{issue.title} [{agent.role}]"

            manifest_overrides: dict[str, Any] = {
                "issue": {
                    "title": override_title,
                    "description": description,
                },
                "planner": {"timeout_seconds_override": max(1, int(timeout_ms / 1000))},
            }

            result = await self.dispatcher.dispatch_async(
                issue,
                workcell_path,
                speculate_tag=tag,
                toolchain_override=toolchain,
                manifest_overrides=manifest_overrides,
            )

            verified = None
            verification_summary: dict[str, Any] | None = None
            if result.proof and self._verifier:
                verified = await self._verifier.verify_async(result.proof, workcell_path)
                verification_summary = (
                    result.proof.verification
                    if isinstance(result.proof.verification, dict)
                    else None
                )

            tokens_used = 0
            diff_stats = None
            files_modified: list[str] = []
            proof_status = None
            proof_review = None
            proof_follow_ups = None
            proof_commands = None
            proof_risk = None
            if result.proof:
                proof_status = result.proof.status
                if isinstance(result.proof.metadata, dict):
                    tokens_used = int(result.proof.metadata.get("tokens_used") or 0)
                if isinstance(result.proof.patch, dict):
                    diff_stats = result.proof.patch.get("diff_stats")
                    files_modified = result.proof.patch.get("files_modified", []) or []
                proof_review = result.proof.review
                proof_follow_ups = result.proof.follow_ups
                proof_commands = result.proof.commands_executed
                proof_risk = result.proof.risk_classification

            output = self._format_agent_output(
                workcell_id=workcell_id,
                proof_status=proof_status,
                diff_stats=diff_stats,
                files_modified=files_modified,
                verification=verification_summary,
                review=proof_review,
                follow_ups=proof_follow_ups,
                commands_executed=proof_commands,
                risk_classification=proof_risk,
                tokens_used=tokens_used,
            )

            metadata = {
                "workcell_id": workcell_id,
                "toolchain": result.toolchain,
                "proof_status": proof_status,
                "diff_stats": diff_stats,
                "files_modified": files_modified,
                "verified": verified,
                "verification": verification_summary,
            }

            return AgentExecutionResult(
                output=output,
                success=result.success if verified is None else (result.success and verified),
                token_usage=tokens_used,
                error=result.error,
                metadata=metadata,
            )
        finally:
            if workcell_path and self._workcell_manager:
                self._workcell_manager.cleanup(
                    workcell_path,
                    keep_logs=self.config.keep_workcell_logs,
                )

    def _format_agent_output(
        self,
        *,
        workcell_id: str,
        proof_status: str | None,
        diff_stats: dict[str, Any] | None,
        files_modified: list[str],
        verification: dict[str, Any] | None,
        review: dict[str, Any] | None,
        follow_ups: list[dict[str, Any]] | None,
        commands_executed: list[dict[str, Any]] | None,
        risk_classification: str | None,
        tokens_used: int,
    ) -> str:
        """Format dispatcher output into a synthesized string."""
        status = proof_status or "unknown"
        summary_parts = [f"Workcell {workcell_id} status: {status}"]
        if risk_classification:
            summary_parts.append(f"Risk classification: {risk_classification}")
        if tokens_used:
            summary_parts.append(f"Tokens used: {tokens_used}")
        if verification:
            all_passed = verification.get("all_passed")
            blocking = verification.get("blocking_failures") or []
            summary_parts.append(f"Gates passed: {all_passed}")
            if blocking:
                summary_parts.append("Blocking failures:")
                summary_parts.extend([f"- {name}" for name in blocking[:10]])
        if diff_stats:
            files_changed = diff_stats.get("files_changed")
            insertions = diff_stats.get("insertions")
            deletions = diff_stats.get("deletions")
            summary_parts.append(
                f"Diff stats: files={files_changed} insertions={insertions} deletions={deletions}"
            )
        if files_modified:
            summary_parts.append("Files modified:")
            summary_parts.extend([f"- {path}" for path in files_modified[:20]])
        if commands_executed:
            summary_parts.append("Commands executed:")
            for command in commands_executed[:10]:
                cmd = command.get("command")
                exit_code = command.get("exit_code")
                if cmd:
                    summary_parts.append(f"- {cmd} (exit={exit_code})")
            log_tail = self._read_command_log_tail(commands_executed)
            if log_tail:
                summary_parts.append("Log tail:")
                summary_parts.extend([f"- {line}" for line in log_tail])
        if review:
            summary_parts.append("Review notes:")
            if isinstance(review, dict):
                for key, value in list(review.items())[:5]:
                    summary_parts.append(f"- {key}: {value}")
        if follow_ups:
            summary_parts.append("Follow ups:")
            for follow_up in follow_ups[:5]:
                title = follow_up.get("title") if isinstance(follow_up, dict) else None
                action = follow_up.get("action") if isinstance(follow_up, dict) else None
                summary_parts.append(f"- {title or action or str(follow_up)}")
        return "\n".join(summary_parts)

    def _read_command_log_tail(self, commands: list[dict[str, Any]]) -> list[str]:
        """Read a short tail of the first available command log."""
        log_paths: list[str] = []
        for command in commands:
            stdout_path = command.get("stdout_path")
            stderr_path = command.get("stderr_path")
            if isinstance(stdout_path, str) and stdout_path:
                log_paths.append(stdout_path)
            if isinstance(stderr_path, str) and stderr_path:
                log_paths.append(stderr_path)
            if log_paths:
                break

        for path_str in log_paths:
            path = Path(path_str)
            if not path.exists():
                continue
            try:
                lines = path.read_text(errors="ignore").splitlines()
            except Exception:
                continue
            if not lines:
                continue
            tail = lines[-20:]
            trimmed: list[str] = []
            remaining_chars = 2000
            for line in tail:
                if remaining_chars <= 0:
                    break
                snippet = line.strip()
                if not snippet:
                    continue
                trimmed.append(snippet[:200])
                remaining_chars -= len(snippet)
            if trimmed:
                return trimmed
        return []

    async def _simulate_agent_execution(self, agent: AgentSpec) -> AgentExecutionResult:
        """Simulate agent execution for testing."""
        # Simulate some processing time
        await asyncio.sleep(0.1)

        output = f"[Simulated output for {agent.role}]\n\nPrompt: {agent.prompt_template[:200]}..."

        return AgentExecutionResult(
            output=output,
            success=True,
            token_usage=1000,
        )

    def _synthesize_results(
        self,
        results: list[AgentResult],
        mode: SynthesisMode,
    ) -> Any:
        """Synthesize agent results based on mode."""
        successful_results = [r for r in results if r.success]

        if not successful_results:
            return None

        if mode == SynthesisMode.MERGE:
            # Combine all outputs with separator
            outputs = [r.output for r in successful_results]
            return self.config.merge_separator.join(outputs)

        elif mode == SynthesisMode.VOTE:
            # Select best by some heuristic (length for now, could be quality score)
            best = max(successful_results, key=lambda r: len(r.output))
            return best.output

        elif mode == SynthesisMode.CASCADE:
            # Each feeds into next - return last successful
            return successful_results[-1].output

        elif mode == SynthesisMode.INDEPENDENT:
            # Return as list for independent processing
            return [r.output for r in successful_results]

        return None

    async def _write_phase_outputs(
        self,
        phase: TopologyPhase,
        results: list[AgentResult],
    ) -> list[str]:
        """Write output files for the phase."""
        if not self.config.write_intermediate_outputs:
            return []

        files_written = []

        for result in results:
            if not result.success or not result.agent_spec.output_file:
                continue

            output_path = self._resolve_output_path(result.agent_spec.output_file)

            try:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(result.output, encoding="utf-8")
                files_written.append(str(output_path))
                logger.info(f"Wrote output file: {output_path}")
            except Exception as e:
                logger.warning(f"Failed to write output file {output_path}: {e}")

        return files_written

    def _resolve_output_path(self, output_file: str) -> Path:
        """Resolve output file path with context substitution."""
        # Substitute context variables in path
        resolved = output_file
        for key, value in self._context.items():
            resolved = resolved.replace(f"{{{key}}}", str(value))

        path = Path(resolved)
        if not path.is_absolute():
            path = self.config.output_dir / path

        return path

    def _update_context_from_phase(self, phase: TopologyPhase, output: PhaseOutput) -> None:
        """Update context with phase results for use in subsequent phases."""
        # Add synthesized output
        self._context[f"{phase.name}_synthesis"] = output.synthesized
        self._context[f"{phase.name}_files"] = output.files_written

        # Add individual agent outputs if independent mode
        if phase.synthesis_mode == SynthesisMode.INDEPENDENT:
            for i, agent_output in enumerate(output.agent_outputs):
                key = agent_output.get("output_key", f"{phase.name}_{i}")
                self._context[key] = agent_output.get("output", "")

    def _build_final_output(self, phase_outputs: list[PhaseOutput]) -> Any:
        """Build the final output from all phases."""
        if not phase_outputs:
            return None

        # Return the last phase's synthesized output
        return phase_outputs[-1].synthesized

    def abort(self) -> None:
        """Abort the current execution."""
        self._aborted = True
        logger.warning("Orchestrator abort requested")


class SyncOrchestrator:
    """Synchronous wrapper around PhasedOrchestrator."""

    def __init__(self, orchestrator: PhasedOrchestrator) -> None:
        self._orchestrator = orchestrator

    def execute(
        self,
        topology: TaskTopology,
        initial_context: dict[str, Any] | None = None,
        *,
        issue: Issue | None = None,
    ) -> TopologyResult:
        """Execute topology synchronously."""
        return asyncio.run(
            self._orchestrator.execute(topology, initial_context, issue=issue)
        )


def create_orchestrator(
    config: KernelConfig | None = None,
    output_dir: Path | None = None,
) -> PhasedOrchestrator:
    """Create a configured orchestrator instance."""
    orch_config = OrchestratorConfig()

    if config:
        orch_config.max_concurrent_agents = config.max_concurrent_workcells

    if output_dir:
        orch_config.output_dir = output_dir

    return PhasedOrchestrator(config=orch_config, kernel_config=config)
