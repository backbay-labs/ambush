"""
Claude Code Adapter - Anthropic Claude Code toolchain integration.

https://github.com/anthropics/claude-code

Supports two execution modes:
- **print** (default): ``claude --print`` subprocess, one-shot non-interactive.
- **interactive**: PTY-based session with Agent Teams support for L/XL tasks.

Topology Integration:
When dispatching tasks to Claude workcells, this adapter can compile
topology templates into Claude-native skills and copy them to the
workcell's .claude/skills/ directory. This enables Claude Code to
use topology-defined workflows (like research-to-plan) natively.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from cyntra.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter
from cyntra.core.adapters.telemetry import TelemetryWriter, resolve_kernel_events_path

if TYPE_CHECKING:
    from cyntra.core.adapters.pty_output_parser import TurnResult
    from cyntra.core.topology.claude_compiler import ClaudeCompiler, ClaudeOrchestrationPlan
    from cyntra.core.topology.planner import TopologyPlanner

logger = structlog.get_logger()

CLAUDE_SONNET_4_5 = "claude-sonnet-4-5-20250929"
CLAUDE_OPUS_4_5 = "claude-opus-4-5-20251101"
CLAUDE_OPUS_4_6 = "claude-opus-4-6"
CLAUDE_HAIKU_4_5 = "claude-haiku-4-5-20251001"


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


class ClaudeAdapter(ToolchainAdapter):
    """
    Adapter for Claude Code CLI.

    Claude Code is an agentic coding tool that can:
    - Understand and navigate codebases
    - Make changes across multiple files
    - Run commands and verify changes
    """

    name = "claude"
    supports_mcp = True
    supports_streaming = True
    _mirror_event_types = {
        "started",
        "prompt_sent",
        "response_chunk",
        "response_complete",
        "tool_call",
        "tool_result",
        "file_read",
        "file_write",
        "bash_command",
        "bash_output",
        "thinking",
        "completed",
        "error",
    }

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.executable = str(self.config.get("path") or "claude")
        self.env = dict(self.config.get("env") or {})
        # Keep a stable default ("opus") and allow pinning via config.
        # "opus" alias resolves to claude-opus-4-6 in the CLI.
        self.default_model = self.config.get("model", "opus")
        # Effort level controls thinking depth. Values: low, medium, high.
        # "high" is default in Claude Code; use "medium" for simple tasks.
        self.default_effort_level = self.config.get("default_effort_level", "high")
        self.effort_level_map: dict[str, str] = self.config.get("effort_level_map", {})
        self.skip_permissions = self.config.get("skip_permissions", True)
        self._available: bool | None = None

        # Teams integration (experimental, requires interactive mode)
        self.teams_enabled = self.config.get("teams", {}).get("enabled", False)
        self.teams_env: dict[str, str] = self.config.get("teams", {}).get("env", {})
        self.teams_teammate_mode: str = self.config.get("teams", {}).get(
            "teammate_mode", "in-process"
        )

        # Interactive PTY execution (for agent teams)
        self.interactive_config: dict[str, Any] = self.config.get("interactive", {})
        self.interactive_enabled: bool = self.interactive_config.get("enabled", False)
        self.interactive_mode: str = self.interactive_config.get("mode", "never")
        self.quiescence_seconds: float = self.interactive_config.get(
            "quiescence_timeout_seconds", 10.0
        )
        self.max_turn_seconds: int = self.interactive_config.get(
            "max_turn_duration_seconds", 1800
        )

        # Topology integration
        self.enable_topology = self.config.get("enable_topology", True)
        self.topologies_dir = self.config.get("topologies_dir")
        self._topology_planner: "TopologyPlanner | None" = None
        self._claude_compiler: "ClaudeCompiler | None" = None

    def _get_topology_planner(self, workcell_path: Path | None = None) -> "TopologyPlanner | None":
        """Get or create the topology planner."""
        if not self.enable_topology:
            return None

        if self._topology_planner is not None:
            return self._topology_planner

        try:
            from cyntra.core.topology.planner import TopologyPlanner

            # Find topologies directory
            topologies_dir = None
            if self.topologies_dir:
                topologies_dir = Path(self.topologies_dir)
            elif workcell_path:
                # Look for .cyntra/topologies in the workcell or parent repos
                for candidate in [
                    workcell_path / ".cyntra" / "topologies",
                    workcell_path.parent / ".cyntra" / "topologies",
                    workcell_path.parent.parent / ".cyntra" / "topologies",
                ]:
                    if candidate.exists():
                        topologies_dir = candidate
                        break

            if topologies_dir and topologies_dir.exists():
                self._topology_planner = TopologyPlanner(templates_dir=topologies_dir)
                logger.debug("Topology planner initialized", templates_dir=str(topologies_dir))
            else:
                self._topology_planner = TopologyPlanner(templates_dir=None)
                logger.debug("Topology planner initialized without templates")

            return self._topology_planner
        except ImportError:
            logger.debug("Topology module not available")
            return None

    def _get_claude_compiler(self) -> "ClaudeCompiler | None":
        """Get or create the Claude compiler."""
        if not self.enable_topology:
            return None

        if self._claude_compiler is not None:
            return self._claude_compiler

        try:
            from cyntra.core.topology.claude_compiler import ClaudeCompiler
            self._claude_compiler = ClaudeCompiler()
            return self._claude_compiler
        except ImportError:
            logger.debug("ClaudeCompiler not available")
            return None

    def _prepare_topology_skills(
        self,
        manifest: dict,
        workcell_path: Path,
        execution_mode: str | None = None,
    ) -> list[Path]:
        """
        Prepare topology-based skills for the workcell.

        Compiles matching topology templates into Claude skills and copies
        them to the workcell's .claude/skills/ directory.

        Returns:
            List of generated skill file paths
        """
        if not self.enable_topology:
            return []

        planner = self._get_topology_planner(workcell_path)
        compiler = self._get_claude_compiler()
        if not planner or not compiler:
            return []

        generated: list[Path] = []
        skills_dir = workcell_path / ".claude" / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)

        # Only compile with teams instructions when this task will actually
        # run in interactive mode (teams are unsupported in --print mode).
        resolved_mode = execution_mode or self._resolve_execution_mode(manifest, workcell_path)
        teams_active = resolved_mode == "interactive"
        for template in planner.templates:
            try:
                skill = compiler.compile_template(template, teams_enabled=teams_active)
                filepath = skill.save(skills_dir)
                generated.append(filepath)
                logger.debug(
                    "Generated topology skill",
                    skill_name=skill.name,
                    template=template.name,
                )
            except Exception as e:
                logger.warning(
                    "Failed to compile topology template",
                    template=template.name,
                    error=str(e),
                )

        if generated:
            logger.info(
                "Topology skills prepared for workcell",
                workcell_path=str(workcell_path),
                skill_count=len(generated),
            )

        return generated

    def _get_topology_orchestration_hint(
        self,
        manifest: dict,
        workcell_path: Path | None,
        execution_mode: str | None = None,
    ) -> str | None:
        """
        Get orchestration hint if task matches a topology.

        Returns markdown section to inject into the prompt if a matching
        topology is found.
        """
        if not self.enable_topology:
            return None

        planner = self._get_topology_planner(workcell_path)
        compiler = self._get_claude_compiler()
        if not planner or not compiler:
            return None

        issue = manifest.get("issue", {})
        task_description = issue.get("description", "")
        if not task_description:
            return None

        # Check if any topology template matches the task
        try:
            # Use planner's internal method to find matching template
            tags = issue.get("tags", [])
            matching_template = planner._find_template(task_description, tags)

            if matching_template:
                # Use the template skill name (not task-specific)
                resolved_mode = execution_mode or self._resolve_execution_mode(manifest, workcell_path)
                teams_active = resolved_mode == "interactive"
                skill = compiler.compile_template(
                    matching_template, teams_enabled=teams_active,
                )
                # Get phase/agent counts from template
                total_phases = len(matching_template.phases)
                total_agents = 0
                for p in matching_template.phases:
                    parallelism = p.get("parallelism", 1)
                    if isinstance(parallelism, dict):
                        total_agents += parallelism.get("default", parallelism.get("fixed", 1))
                    elif isinstance(parallelism, int):
                        total_agents += parallelism
                    else:
                        total_agents += 1

                return self._format_topology_hint_from_template(
                    skill.name,
                    total_phases,
                    total_agents,
                    matching_template.name,
                )
        except Exception as e:
            logger.debug("Topology planning failed", error=str(e))

        return None

    def _format_topology_hint_from_template(
        self,
        skill_name: str,
        total_phases: int,
        total_agents: int,
        template_name: str,
    ) -> str:
        """Format the topology hint from template info."""
        lines = [
            "## Topology Workflow Available",
            "",
            f"A matching topology workflow is available: **`/{skill_name}`**",
            f"(Based on template: `{template_name}`)",
            "",
            "This task matches patterns that indicate a multi-phase workflow could be beneficial:",
            "",
            f"- **Phases:** {total_phases}",
            f"- **Total agents:** ~{total_agents}",
            "",
            "**Consider using the topology workflow** if this is a research, planning, or ",
            "multi-step task. Invoke it with:",
            "",
            f"```",
            f"/{skill_name}",
            f"```",
            "",
            "Or proceed with direct execution if this is a focused coding task.",
            "",
        ]
        return "\n".join(lines)

    @property
    def available(self) -> bool:
        """Check if claude CLI is available."""
        if self._available is None:
            if "/" in self.executable:
                self._available = Path(self.executable).exists()
            else:
                self._available = shutil.which(self.executable) is not None
        return self._available

    # ------------------------------------------------------------------
    # Execution mode resolution
    # ------------------------------------------------------------------

    def _resolve_execution_mode(
        self, manifest: dict, workcell_path: Path | None = None,
    ) -> str:
        """Determine whether to use interactive PTY or --print mode.

        Returns:
            ``"interactive"`` or ``"print"``.
        """
        # Explicit override from routing / manifest
        toolchain_config = manifest.get("toolchain_config", {}) or {}
        explicit_mode = toolchain_config.get("execution_mode")
        if explicit_mode in ("interactive", "print"):
            # Still gated on interactive being enabled for "interactive"
            if explicit_mode == "interactive" and not self.interactive_enabled:
                return "print"
            return explicit_mode

        # Interactive must be enabled in config
        if not self.interactive_enabled:
            return "print"

        # Config-level mode knob
        if self.interactive_mode == "never":
            return "print"
        if self.interactive_mode == "always":
            return "interactive"

        # "auto": use interactive for L/XL tasks or when a topology matches
        issue = manifest.get("issue", {})
        # Manifest uses "tags" (from dispatcher), but Issue objects use "labels"
        tags = issue.get("tags", []) or issue.get("labels", [])
        dk_size = None
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("dk_size:"):
                dk_size = tag.split(":", 1)[1]

        if dk_size in ("L", "XL"):
            return "interactive"

        if self._has_topology_match(manifest, workcell_path):
            return "interactive"

        return "print"

    def _has_topology_match(
        self, manifest: dict, workcell_path: Path | None = None,
    ) -> bool:
        """Check whether a topology template matches this manifest's issue."""
        if not self.enable_topology:
            return False

        planner = self._get_topology_planner(workcell_path)
        if not planner:
            return False

        issue = manifest.get("issue", {})
        description = issue.get("description", "")
        if not description:
            return False

        tags = issue.get("tags", []) or issue.get("labels", [])
        try:
            return planner._find_template(description, tags) is not None
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Shared execution context
    # ------------------------------------------------------------------

    def _prepare_execution_context(
        self,
        manifest: dict,
        workcell_path: Path,
        execution_mode: str | None = None,
    ) -> dict[str, Any]:
        """Prepare shared context used by both print and interactive paths.

        Args:
            execution_mode: If provided, overrides the auto-resolved mode so
                that topology skills and prompt hints are compiled for the
                correct execution path (e.g. ``"print"`` for sync callers).

        Returns a dict with: ``prompt``, ``prompt_file``, ``model``,
        ``logs_dir``, ``topology_skills``, ``workcell_id``, ``issue_id``,
        ``toolchain_config``.
        """
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        # Ensure logs directory exists
        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        # Prepare topology skills for the workcell
        topology_skills = self._prepare_topology_skills(
            manifest, workcell_path, execution_mode=execution_mode,
        )

        # Build and write prompt
        prompt = self._build_prompt(manifest, workcell_path, execution_mode=execution_mode)
        prompt_file = workcell_path / "prompt.md"
        prompt_file.write_text(prompt)

        # Get configuration
        toolchain_config = manifest.get("toolchain_config", {}) or {}
        model = toolchain_config.get("model", self.default_model)

        return {
            "workcell_id": workcell_id,
            "issue_id": issue_id,
            "prompt": prompt,
            "prompt_file": prompt_file,
            "model": model,
            "logs_dir": logs_dir,
            "topology_skills": topology_skills,
            "toolchain_config": toolchain_config,
        }

    def execute_sync(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout_seconds: int = 1800,
    ) -> PatchProof:
        """Execute task synchronously using Claude CLI (always --print mode)."""
        started_at = _utc_now()
        ctx = self._prepare_execution_context(manifest, workcell_path, execution_mode="print")
        workcell_id = ctx["workcell_id"]
        logs_dir = ctx["logs_dir"]
        model = ctx["model"]

        # Build command
        cmd = self._build_command(ctx["prompt_file"], model)

        logger.info(
            "Executing Claude",
            workcell_id=workcell_id,
            issue_id=ctx["issue_id"],
            model=model,
        )

        aegis_run = self._start_aegis_run_sync(manifest, workcell_path)
        proof = None

        try:
            result = subprocess.run(
                cmd,
                cwd=workcell_path,
                capture_output=True,
                text=True,
                env=self._build_env(manifest, workcell_path),
                timeout=timeout_seconds,
            )

            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            # Save logs
            self._save_logs(logs_dir, result.stdout, result.stderr)

            # Parse and return proof
            proof = self._parse_output(
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                manifest=manifest,
                workcell_path=workcell_path,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

            logger.info(
                "Claude execution completed",
                workcell_id=workcell_id,
                status=proof.status,
                duration_ms=duration_ms,
            )

        except subprocess.TimeoutExpired:
            logger.error(
                "Claude execution timed out",
                workcell_id=workcell_id,
                timeout=timeout_seconds,
            )
            proof = self._create_timeout_proof(manifest, started_at)

        except Exception as e:
            logger.error(
                "Claude execution failed",
                workcell_id=workcell_id,
                error=str(e),
            )
            proof = self._create_error_proof(manifest, started_at, str(e))

        if proof is None:
            proof = self._create_error_proof(manifest, started_at, "missing_proof")

        aegis_metadata = self._finalize_aegis_run_sync(aegis_run, proof.status)
        self._refresh_proof_metadata(proof, manifest, workcell_path, aegis_metadata)

        # Write proof to file
        proof_path = workcell_path / "proof.json"
        proof_path.write_text(json.dumps(proof.to_dict(), indent=2))

        return proof

    async def execute(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout: timedelta,
    ) -> PatchProof:
        """Execute task asynchronously, dispatching to print or interactive path."""
        mode = self._resolve_execution_mode(manifest, workcell_path)
        if mode == "interactive":
            return await self._execute_interactive(manifest, workcell_path, timeout)
        return await self._execute_print(manifest, workcell_path, timeout)

    # ------------------------------------------------------------------
    # --print execution path (existing behavior, moved from execute())
    # ------------------------------------------------------------------

    async def _execute_print(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout: timedelta,
    ) -> PatchProof:
        """Execute task via ``claude --print`` subprocess (non-interactive)."""
        started_at = _utc_now()
        ctx = self._prepare_execution_context(manifest, workcell_path, execution_mode="print")
        workcell_id = ctx["workcell_id"]
        issue_id = ctx["issue_id"]
        logs_dir = ctx["logs_dir"]
        model = ctx["model"]
        prompt = ctx["prompt"]
        toolchain_config = ctx["toolchain_config"]

        aegis_run = await self._start_aegis_run(manifest, workcell_path)
        proof: PatchProof | None = None

        # Initialize telemetry
        telemetry_path = workcell_path / "telemetry.jsonl"
        telemetry = TelemetryWriter(
            telemetry_path,
            context={
                "issue_id": issue_id,
                "workcell_id": workcell_id,
                "toolchain": self.name,
                "model": model,
            },
            mirror_path=resolve_kernel_events_path(workcell_path),
            mirror_event_types=self._mirror_event_types,
        )

        # Build command
        cmd = self._build_command(ctx["prompt_file"], model)

        logger.info(
            "Executing Claude (async/print)",
            workcell_id=workcell_id,
            model=model,
        )

        # Emit start event
        telemetry.started(
            toolchain=self.name,
            model=model,
            issue_id=issue_id,
            workcell_id=workcell_id,
            prompt_genome_id=toolchain_config.get("prompt_genome_id")
            if isinstance(toolchain_config, dict)
            else None,
            sampling=toolchain_config.get("sampling")
            if isinstance(toolchain_config, dict)
            else None,
        )
        telemetry.prompt_sent(prompt=prompt)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=workcell_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._build_env(manifest, workcell_path),
            )

            # Stream output with telemetry
            stdout, stderr = await self._stream_output_with_telemetry(
                process,
                telemetry,
                timeout.total_seconds(),
            )

            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            # Save logs
            self._save_logs(logs_dir, stdout, stderr)

            proof = self._parse_output(
                stdout=stdout,
                stderr=stderr,
                exit_code=process.returncode or 0,
                manifest=manifest,
                workcell_path=workcell_path,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

            # Emit completion event
            telemetry.completed(
                status=proof.status,
                exit_code=process.returncode or 0,
                duration_ms=duration_ms,
            )

        except TimeoutError:
            logger.error("Claude execution timed out", workcell_id=workcell_id)
            telemetry.error("Execution timed out")
            proof = self._create_timeout_proof(manifest, started_at)

        except Exception as e:
            logger.error("Claude execution failed", workcell_id=workcell_id, error=str(e))
            telemetry.error(str(e))
            proof = self._create_error_proof(manifest, started_at, str(e))

        if proof is None:
            proof = self._create_error_proof(manifest, started_at, "missing_proof")

        aegis_metadata = await self._finalize_aegis_run(aegis_run, proof.status)
        self._refresh_proof_metadata(proof, manifest, workcell_path, aegis_metadata)

        # Write proof to file
        proof_path = workcell_path / "proof.json"
        proof_path.write_text(json.dumps(proof.to_dict(), indent=2))

        telemetry.close()
        return proof

    # ------------------------------------------------------------------
    # Interactive PTY execution path (new)
    # ------------------------------------------------------------------

    async def _execute_interactive(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout: timedelta,
    ) -> PatchProof:
        """Execute task via interactive PTY session with Agent Teams support."""
        from cyntra.core.adapters.pty_session import PTYSession

        started_at = _utc_now()
        ctx = self._prepare_execution_context(
            manifest, workcell_path, execution_mode="interactive",
        )
        workcell_id = ctx["workcell_id"]
        issue_id = ctx["issue_id"]
        logs_dir = ctx["logs_dir"]
        model = ctx["model"]
        prompt = ctx["prompt"]
        toolchain_config = ctx["toolchain_config"]

        aegis_run = await self._start_aegis_run(manifest, workcell_path)
        proof: PatchProof | None = None

        # Initialize telemetry
        telemetry_path = workcell_path / "telemetry.jsonl"
        telemetry = TelemetryWriter(
            telemetry_path,
            context={
                "issue_id": issue_id,
                "workcell_id": workcell_id,
                "toolchain": self.name,
                "model": model,
                "execution_mode": "interactive",
            },
            mirror_path=resolve_kernel_events_path(workcell_path),
            mirror_event_types=self._mirror_event_types,
        )

        logger.info(
            "Executing Claude (async/interactive)",
            workcell_id=workcell_id,
            model=model,
        )

        telemetry.started(
            toolchain=self.name,
            model=model,
            issue_id=issue_id,
            workcell_id=workcell_id,
            execution_mode="interactive",
            prompt_genome_id=toolchain_config.get("prompt_genome_id")
            if isinstance(toolchain_config, dict)
            else None,
        )

        log_path = logs_dir / "claude-pty.log" if self.interactive_config.get(
            "log_raw_output", True
        ) else None

        session = PTYSession(
            executable=self.executable,
            cwd=workcell_path,
            env=self._build_env(manifest, workcell_path),
            model=model,
            timeout=int(timeout.total_seconds()),
            log_path=log_path,
            quiescence_seconds=self.quiescence_seconds,
            max_turn_seconds=self.max_turn_seconds,
            skip_permissions=self.skip_permissions,
        )

        pid_file = logs_dir / "pty_pid"

        try:
            async with session:
                # Write PID to disk so workcell cleanup can find orphaned processes
                if session.pid is not None:
                    pid_file.write_text(str(session.pid))

                telemetry.prompt_sent(prompt=prompt)

                turn_result = await session.send_prompt(prompt)

                completed_at = _utc_now()
                duration_ms = int((completed_at - started_at).total_seconds() * 1000)

                # Emit response data
                if turn_result.clean_output:
                    telemetry.response_complete(
                        content=turn_result.clean_output,
                        tokens=None,
                    )

                proof = self._build_proof_from_interactive(
                    turn_result=turn_result,
                    manifest=manifest,
                    workcell_path=workcell_path,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                )

                telemetry.completed(
                    status=proof.status,
                    exit_code=0 if proof.status == "success" else 1,
                    duration_ms=duration_ms,
                )

                logger.info(
                    "Claude interactive execution completed",
                    workcell_id=workcell_id,
                    status=proof.status,
                    duration_ms=duration_ms,
                    files_modified=len(turn_result.files_modified),
                )

        except TimeoutError:
            logger.error(
                "Claude interactive execution timed out",
                workcell_id=workcell_id,
            )
            telemetry.error("Interactive execution timed out")
            proof = self._create_timeout_proof(manifest, started_at)

        except Exception as e:
            logger.error(
                "Claude interactive execution failed",
                workcell_id=workcell_id,
                error=str(e),
            )
            telemetry.error(str(e))
            proof = self._create_error_proof(manifest, started_at, str(e))

        finally:
            telemetry.close()
            # Remove PID file after shutdown to prevent stale-PID kills
            pid_file.unlink(missing_ok=True)

        if proof is None:
            proof = self._create_error_proof(manifest, started_at, "missing_proof")

        aegis_metadata = await self._finalize_aegis_run(aegis_run, proof.status)
        self._refresh_proof_metadata(proof, manifest, workcell_path, aegis_metadata)

        # Write proof to file
        proof_path = workcell_path / "proof.json"
        proof_path.write_text(json.dumps(proof.to_dict(), indent=2))

        return proof

    def _build_proof_from_interactive(
        self,
        turn_result: TurnResult,
        manifest: dict,
        workcell_path: Path,
        started_at: datetime,
        completed_at: datetime,
        duration_ms: int,
    ) -> PatchProof:
        """Convert a PTY TurnResult into a PatchProof."""
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        # Get git patch info
        patch_info = self._get_patch_info(workcell_path, manifest)

        # Map turn_result.status to PatchProof status
        status_map = {
            "completed": "success",
            "error": "failed",
            "timeout": "timeout",
            "waiting": "partial",
        }
        status = status_map.get(turn_result.status, "failed")

        # Confidence based on status
        confidence_map = {
            "success": 0.8,
            "partial": 0.5,
            "failed": 0.2,
            "timeout": 0.0,
        }
        confidence = confidence_map.get(status, 0.2)

        metadata: dict[str, Any] = {
            "toolchain": self.name,
            "model": manifest.get("toolchain_config", {}).get("model", self.default_model),
            "execution_mode": "interactive",
            "prompt_genome_id": (manifest.get("toolchain_config") or {}).get(
                "prompt_genome_id"
            ),
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "duration_ms": duration_ms,
            "files_modified_pty": turn_result.files_modified,
            "tool_calls_pty": turn_result.tool_calls,
        }

        if turn_result.teams_activity:
            metadata["teams_activity"] = turn_result.teams_activity

        if turn_result.error:
            metadata["error"] = turn_result.error

        metadata = self._augment_metadata(metadata, manifest, workcell_path)

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=workcell_id,
            issue_id=issue_id,
            status=status,
            patch=patch_info,
            verification={
                "gates": {},
                "all_passed": False,
                "blocking_failures": [],
            },
            metadata=metadata,
            commands_executed=[
                {
                    "command": "claude (interactive/pty)",
                    "duration_ms": duration_ms,
                    "pty_log_path": str(workcell_path / "logs" / "claude-pty.log"),
                }
            ],
            confidence=confidence,
            risk_classification=self._classify_risk(patch_info),
        )

    async def health_check(self) -> bool:
        """Check if Claude CLI is available."""
        if not self.available:
            return False

        try:
            process = await asyncio.create_subprocess_exec(
                self.executable,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            return process.returncode == 0
        except Exception:
            return False

    def health_check_sync(self) -> bool:
        """Check if Claude CLI is available (sync version)."""
        if not self.available:
            return False

        try:
            result = subprocess.run(
                [self.executable, "--version"],
                capture_output=True,
                timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    def estimate_cost(self, manifest: dict) -> CostEstimate:
        """Estimate cost for Claude execution."""
        model = manifest.get("toolchain_config", {}).get("model", self.default_model)
        estimated_tokens = manifest.get("issue", {}).get("dk_estimated_tokens", 50000)

        # Cost per 1M tokens (blended input + output estimate)
        # Opus 4.6: $5/M input, $25/M output (~$15/M blended)
        # Sonnet 4.5: $3/M input, $15/M output (~$9/M blended)
        cost_per_1m = {
            # Model aliases (Claude Code CLI)
            "sonnet": 9.0,
            "opus": 15.0,  # Opus 4.6 pricing
            "haiku": 0.75,
            # Claude 4.6
            CLAUDE_OPUS_4_6: 15.0,
            # Claude 4.5
            CLAUDE_SONNET_4_5: 9.0,
            CLAUDE_OPUS_4_5: 45.0,
            CLAUDE_HAIKU_4_5: 0.75,
        }.get(model, 9.0)

        estimated_cost = (estimated_tokens / 1_000_000) * cost_per_1m

        return CostEstimate(
            estimated_tokens=estimated_tokens,
            estimated_cost_usd=estimated_cost,
            model=model,
        )

    def _build_command(self, prompt_file: Path, model: str) -> list[str]:
        """Build the claude command."""
        cmd = [self.executable]

        # Add prompt
        cmd.extend(["--print", f"@{prompt_file}"])

        # Add model if specified
        if model:
            cmd.extend(["--model", model])

        output_format = self.config.get("output_format")
        if output_format:
            cmd.extend(["--output-format", str(output_format)])

        allowed_tools = self.config.get("allowed_tools")
        if isinstance(allowed_tools, list) and allowed_tools:
            cmd.append("--allowedTools")
            cmd.extend([str(t) for t in allowed_tools])

        # Skip permissions for autonomous mode
        if self.skip_permissions:
            cmd.append("--dangerously-skip-permissions")

        extra_args = self.config.get("extra_args")
        if isinstance(extra_args, list):
            cmd.extend([str(a) for a in extra_args])

        return cmd

    def _resolve_effort_level(self, manifest: dict) -> str:
        """Resolve effort level from issue tags/labels or config defaults."""
        issue = manifest.get("issue", {})
        # Manifest uses "tags" (from dispatcher), Issue objects use "labels"
        labels = issue.get("tags", []) or issue.get("labels", [])
        dk_risk = None
        dk_size = None
        for label in labels:
            if isinstance(label, str):
                if label.startswith("dk_risk:"):
                    dk_risk = label.split(":", 1)[1]
                elif label.startswith("dk_size:"):
                    dk_size = label.split(":", 1)[1]

        # Check explicit effort in toolchain_config
        tc_config = manifest.get("toolchain_config", {}) or {}
        if tc_config.get("effort_level"):
            return str(tc_config["effort_level"])

        # Map from effort_level_map config
        if dk_risk and f"dk_risk_{dk_risk}" in self.effort_level_map:
            return self.effort_level_map[f"dk_risk_{dk_risk}"]
        if dk_size and f"dk_size_{dk_size}" in self.effort_level_map:
            return self.effort_level_map[f"dk_size_{dk_size}"]

        # Defaults based on risk/size
        if dk_risk == "low" and dk_size in ("XS", "S"):
            return "medium"
        if dk_risk == "high" or dk_size in ("L", "XL"):
            return "high"

        return self.default_effort_level

    def _build_env(
        self,
        manifest: dict,
        workcell_path: Path | None,
    ) -> dict[str, str]:
        """Build env with Claude-specific effort level and teams config."""
        env = super()._build_env(manifest, workcell_path)

        # Inject effort level
        effort = self._resolve_effort_level(manifest)
        env["CLAUDE_CODE_EFFORT_LEVEL"] = effort

        # Determine if this execution is interactive from the manifest
        is_interactive = self._resolve_execution_mode(manifest, workcell_path) == "interactive"

        # Inject teams env vars if enabled or in interactive mode
        if self.teams_enabled or is_interactive:
            env.update(self.teams_env)
            # Ensure the agent teams flag is always set for interactive
            if is_interactive:
                env["CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS"] = "1"
                env["CLAUDE_CODE_TEAMMATE_MODE"] = self.teams_teammate_mode

        return env

    def _build_prompt(
        self,
        manifest: dict,
        workcell_path: Path | None = None,
        execution_mode: str | None = None,
    ) -> str:
        prompt = super()._build_prompt(manifest, workcell_path)

        # Add topology orchestration hint if task matches a topology
        topology_hint = self._get_topology_orchestration_hint(
            manifest, workcell_path, execution_mode=execution_mode,
        )
        if topology_hint:
            insertion_marker = "## Execution Guidelines"
            if insertion_marker in prompt:
                parts = prompt.split(insertion_marker, 1)
                prompt = f"{parts[0]}{topology_hint}\n{insertion_marker}{parts[1]}"
            else:
                prompt = f"{topology_hint}\n\n{prompt}"

        return prompt

    async def _stream_output_with_telemetry(
        self,
        process: asyncio.subprocess.Process,
        telemetry: TelemetryWriter,
        timeout_seconds: float,
    ) -> tuple[str, str]:
        """
        Stream process output while emitting telemetry events.

        Returns accumulated stdout and stderr.
        """
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        async def read_stdout() -> None:
            """Read stdout line by line."""
            if not process.stdout:
                return
            async for line in process.stdout:
                decoded = line.decode("utf-8", errors="replace")
                stdout_lines.append(decoded)
                # Emit as response chunk (Claude CLI output is mostly LLM responses)
                telemetry.response_chunk(content=decoded.rstrip())

        async def read_stderr() -> None:
            """Read stderr line by line."""
            if not process.stderr:
                return
            async for line in process.stderr:
                decoded = line.decode("utf-8", errors="replace")
                stderr_lines.append(decoded)

        # Run both readers in parallel with timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(read_stdout(), read_stderr(), process.wait()),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            # Kill the process
            process.kill()
            await process.wait()
            raise

        return "".join(stdout_lines), "".join(stderr_lines)

    def _save_logs(self, logs_dir: Path, stdout: str, stderr: str) -> None:
        """Save stdout and stderr to log files."""
        if stdout:
            (logs_dir / "claude-stdout.log").write_text(stdout)
        if stderr:
            (logs_dir / "claude-stderr.log").write_text(stderr)

    def _parse_output(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
        manifest: dict,
        workcell_path: Path,
        started_at: datetime,
        completed_at: datetime,
        duration_ms: int,
    ) -> PatchProof:
        """Parse Claude output into PatchProof."""
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        # Try to extract any JSON from output
        claude_output: dict = {}
        if stdout.strip():
            for line in reversed(stdout.strip().split("\n")):
                try:
                    claude_output = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

        # Get git patch info
        patch_info = self._get_patch_info(workcell_path, manifest)

        # Determine status
        if exit_code == 0:
            status = "success"
            confidence = claude_output.get("confidence", 0.8)
        elif exit_code == 1:
            status = "partial"
            confidence = claude_output.get("confidence", 0.5)
        else:
            status = "failed"
            confidence = claude_output.get("confidence", 0.2)

        metadata = {
            "toolchain": self.name,
            "toolchain_version": claude_output.get("version", "unknown"),
            "model": manifest.get("toolchain_config", {}).get("model", self.default_model),
            "prompt_genome_id": (manifest.get("toolchain_config") or {}).get(
                "prompt_genome_id"
            ),
            "sampling": (manifest.get("toolchain_config") or {}).get("sampling"),
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
            "tokens_used": claude_output.get("tokens_used"),
            "cost_usd": claude_output.get("cost"),
        }
        metadata = self._augment_metadata(metadata, manifest, workcell_path)

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=workcell_id,
            issue_id=issue_id,
            status=status,
            patch=patch_info,
            verification={
                "gates": {},
                "all_passed": False,
                "blocking_failures": [],
            },
            metadata=metadata,
            commands_executed=[
                {
                    "command": "claude",
                    "exit_code": exit_code,
                    "duration_ms": duration_ms,
                    "stdout_path": str(workcell_path / "logs" / "claude-stdout.log"),
                    "stderr_path": str(workcell_path / "logs" / "claude-stderr.log"),
                }
            ],
            confidence=confidence,
            risk_classification=self._classify_risk(patch_info),
        )

