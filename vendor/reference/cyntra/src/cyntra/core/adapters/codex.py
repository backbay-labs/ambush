"""
Codex CLI Adapter - OpenAI Codex toolchain integration.

https://github.com/openai/codex
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog

from cyntra.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter
from cyntra.core.adapters.telemetry import TelemetryWriter, resolve_kernel_events_path

logger = structlog.get_logger()
_ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


def _has_meaningful_output(chunk: str) -> bool:
    """
    Return True when stdout content reflects semantic progress.

    Codex can emit spinner/control frames that should not reset quiescence timers.
    """
    if not chunk:
        return False
    sanitized = _ANSI_ESCAPE_RE.sub("", chunk)
    sanitized = sanitized.replace("\r", "")
    return bool(sanitized.strip())


class CodexOutputStallError(TimeoutError):
    """Raised when a Codex subprocess emits no output for too long."""

    def __init__(self, timeout_seconds: float) -> None:
        self.timeout_seconds = float(timeout_seconds)
        super().__init__(
            f"No Codex output observed for {self.timeout_seconds:.1f}s after prompt dispatch"
        )


class CodexAdapter(ToolchainAdapter):
    """
    Adapter for OpenAI Codex CLI.

    Codex is a CLI tool for agentic coding that can:
    - Read and understand codebases
    - Make code changes autonomously
    - Run tests and verify changes
    """

    name = "codex"
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
        self.executable = str(self.config.get("path") or "codex")
        self.env = dict(self.config.get("env") or {})
        self.default_model = self.config.get("model", "gpt-5.3-codex")
        self.default_reasoning_effort = self.config.get(
            "default_reasoning_effort",
            self.config.get("model_reasoning_effort",
                           self.config.get("reasoning_effort", "xhigh")),
        )
        self.reasoning_effort_map: dict[str, str] = self.config.get(
            "reasoning_effort_map", {}
        )
        heartbeat_timeout_raw = self.config.get(
            "quiescence_timeout_seconds",
            self.config.get("heartbeat_timeout_seconds", 300),
        )
        try:
            self.quiescence_timeout_seconds = float(heartbeat_timeout_raw)
        except (TypeError, ValueError):
            self.quiescence_timeout_seconds = 300.0
        if self.quiescence_timeout_seconds < 0:
            self.quiescence_timeout_seconds = 0.0
        self.quiescence_timeout_seconds_by_model = self._parse_timeout_map(
            self.config.get("quiescence_timeout_seconds_by_model")
        )
        self.quiescence_timeout_seconds_by_reasoning_effort = self._parse_timeout_map(
            self.config.get("quiescence_timeout_seconds_by_reasoning_effort")
        )
        stall_confirmation_raw = self.config.get("stall_confirmation_seconds", 3.0)
        try:
            self.stall_confirmation_seconds = float(stall_confirmation_raw)
        except (TypeError, ValueError):
            self.stall_confirmation_seconds = 3.0
        if self.stall_confirmation_seconds < 0:
            self.stall_confirmation_seconds = 0.0
        stall_exit_grace_raw = self.config.get("stall_exit_grace_seconds", 15.0)
        try:
            self.stall_exit_grace_seconds = float(stall_exit_grace_raw)
        except (TypeError, ValueError):
            self.stall_exit_grace_seconds = 15.0
        if self.stall_exit_grace_seconds < 0:
            self.stall_exit_grace_seconds = 0.0
        post_exit_drain_raw = self.config.get("post_exit_stream_drain_seconds", 30.0)
        try:
            self.post_exit_stream_drain_seconds = float(post_exit_drain_raw)
        except (TypeError, ValueError):
            self.post_exit_stream_drain_seconds = 30.0
        if self.post_exit_stream_drain_seconds < 0:
            self.post_exit_stream_drain_seconds = 0.0
        # Codex CLI v0.77+ uses `--sandbox` and `--full-auto`. Keep `approval_mode` as a
        # backward-compatible alias for config.
        self.approval_mode = self.config.get("approval_mode", "full-auto")
        self.sandbox_mode = self.config.get("sandbox", "workspace-write")
        self.ask_for_approval = self.config.get("ask_for_approval")
        if not self.ask_for_approval:
            if self.approval_mode == "full-auto":
                self.ask_for_approval = "never"
            elif self.approval_mode == "ask":
                self.ask_for_approval = "on-request"
            else:
                self.ask_for_approval = "never"
        self.use_json_output = bool(self.config.get("json_output", True))
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        """Check if codex CLI is available."""
        if self._available is None:
            if "/" in self.executable:
                self._available = Path(self.executable).exists()
            else:
                self._available = shutil.which(self.executable) is not None
        return self._available

    def execute_sync(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout_seconds: int = 1800,
    ) -> PatchProof:
        """
        Execute task synchronously using Codex CLI.

        This is the primary method for non-async contexts.
        """
        started_at = _utc_now()
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        # Ensure logs directory exists
        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        # Build and write prompt
        prompt = self._build_prompt(manifest, workcell_path)
        prompt_file = workcell_path / "prompt.md"
        prompt_file.write_text(prompt)

        # Get configuration
        toolchain_config = manifest.get("toolchain_config", {}) or {}
        model = toolchain_config.get("model", self.default_model)
        sampling = toolchain_config.get("sampling") if isinstance(toolchain_config, dict) else None

        # Build command
        cmd = self._build_command(model, sampling=sampling, manifest=manifest)

        logger.info(
            "Executing Codex",
            workcell_id=workcell_id,
            issue_id=issue_id,
            model=model,
            sandbox=self.sandbox_mode,
            ask_for_approval=self.ask_for_approval,
        )

        aegis_run = self._start_aegis_run_sync(manifest, workcell_path)
        proof = None

        try:
            result = subprocess.run(
                cmd,
                cwd=workcell_path,
                input=prompt,
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
                "Codex execution completed",
                workcell_id=workcell_id,
                status=proof.status,
                duration_ms=duration_ms,
            )

        except subprocess.TimeoutExpired:
            logger.error(
                "Codex execution timed out",
                workcell_id=workcell_id,
                timeout=timeout_seconds,
            )
            proof = self._create_timeout_proof(manifest, started_at)

        except Exception as e:
            logger.error(
                "Codex execution failed",
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
        """Execute task asynchronously using Codex CLI."""
        started_at = _utc_now()
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        # Ensure logs directory exists
        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        # Build and write prompt
        prompt = self._build_prompt(manifest, workcell_path)
        prompt_file = workcell_path / "prompt.md"
        prompt_file.write_text(prompt)

        # Get configuration
        toolchain_config = manifest.get("toolchain_config", {}) or {}
        model = toolchain_config.get("model", self.default_model)
        sampling = toolchain_config.get("sampling") if isinstance(toolchain_config, dict) else None

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
        cmd = self._build_command(model, sampling=sampling, manifest=manifest)
        quiescence_timeout_seconds = self._resolve_quiescence_timeout_seconds(manifest)

        logger.info(
            "Executing Codex (async)",
            workcell_id=workcell_id,
            model=model,
            quiescence_timeout_seconds=quiescence_timeout_seconds,
        )

        aegis_run = await self._start_aegis_run(manifest, workcell_path)
        proof: PatchProof | None = None

        # Emit start event
        telemetry.started(
            toolchain=self.name,
            model=model,
            issue_id=issue_id,
            workcell_id=workcell_id,
            prompt_genome_id=toolchain_config.get("prompt_genome_id")
            if isinstance(toolchain_config, dict)
            else None,
            sampling=sampling if isinstance(sampling, dict) else None,
        )
        telemetry.prompt_sent(prompt=prompt)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=workcell_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._build_env(manifest, workcell_path),
            )

            # Stream output with telemetry
            stdout, stderr = await self._stream_output_with_telemetry(
                process,
                telemetry,
                prompt.encode(),
                timeout.total_seconds(),
                quiescence_timeout_seconds=quiescence_timeout_seconds,
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

        except CodexOutputStallError as exc:
            logger.error(
                "Codex execution stalled after prompt dispatch",
                workcell_id=workcell_id,
                heartbeat_timeout_seconds=exc.timeout_seconds,
            )
            telemetry.error("prompt_stall_no_output")
            proof = self._create_stall_timeout_proof(
                manifest,
                started_at,
                heartbeat_timeout_seconds=exc.timeout_seconds,
            )

        except TimeoutError:
            logger.error("Codex execution timed out", workcell_id=workcell_id)
            telemetry.error("Execution timed out")
            proof = self._create_timeout_proof(manifest, started_at)

        except Exception as e:
            logger.error("Codex execution failed", workcell_id=workcell_id, error=str(e))
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

    async def health_check(self) -> bool:
        """Check if Codex CLI is available."""
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
        """Check if Codex CLI is available (sync version)."""
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
        """Estimate cost for Codex execution."""
        model = manifest.get("toolchain_config", {}).get("model", self.default_model)
        estimated_tokens = manifest.get("issue", {}).get("dk_estimated_tokens", 50000)

        # Cost per 1M tokens (approximate, blended input + output)
        # Codex uses subscription pricing, costs here are for budget estimation
        cost_per_1m = {
            "gpt-5.3-codex": 10.0,
            "gpt-5.2-codex": 10.0,
            "gpt-5.2": 10.0,
            "gpt-5-nano": 1.0,
            "o3": 20.0,
            "o3-mini": 5.0,
        }.get(model, 10.0)

        estimated_cost = (estimated_tokens / 1_000_000) * cost_per_1m

        return CostEstimate(
            estimated_tokens=estimated_tokens,
            estimated_cost_usd=estimated_cost,
            model=model,
        )

    @staticmethod
    def _parse_timeout_map(raw: object) -> dict[str, float]:
        """Parse timeout override maps from adapter config."""
        if not isinstance(raw, dict):
            return {}
        parsed: dict[str, float] = {}
        for key, value in raw.items():
            if not isinstance(key, str):
                continue
            try:
                timeout = float(value)
            except (TypeError, ValueError):
                continue
            if timeout <= 0:
                continue
            parsed[key] = timeout
        return parsed

    def _resolve_quiescence_timeout_seconds(self, manifest: dict | None = None) -> float:
        """
        Resolve quiescence timeout using optional model/effort policy overrides.

        Resolution order:
        1. base adapter timeout
        2. reasoning-effort override (if configured)
        3. model override (if configured)
        """
        resolved = self.quiescence_timeout_seconds
        manifest = manifest or {}

        reasoning_effort = self._resolve_reasoning_effort(manifest)
        effort_override = self.quiescence_timeout_seconds_by_reasoning_effort.get(reasoning_effort)
        if effort_override is not None:
            resolved = effort_override

        tc_config = manifest.get("toolchain_config", {}) if isinstance(manifest, dict) else {}
        model = self.default_model
        if isinstance(tc_config, dict):
            model = str(tc_config.get("model") or self.default_model)
        model_override = self.quiescence_timeout_seconds_by_model.get(model)
        if model_override is not None:
            resolved = model_override

        if resolved < 0:
            return 0.0
        return float(resolved)

    def _resolve_reasoning_effort(self, manifest: dict) -> str:
        """Resolve reasoning effort from issue tags/labels or config defaults."""
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
        if tc_config.get("reasoning_effort"):
            return str(tc_config["reasoning_effort"])

        # Map from reasoning_effort_map config
        if dk_risk and f"dk_risk_{dk_risk}" in self.reasoning_effort_map:
            return self.reasoning_effort_map[f"dk_risk_{dk_risk}"]
        if dk_size and f"dk_size_{dk_size}" in self.reasoning_effort_map:
            return self.reasoning_effort_map[f"dk_size_{dk_size}"]

        # Smart defaults: medium for easy tasks, xhigh for anything non-trivial
        if dk_risk == "low" and dk_size in ("XS", "S"):
            return "medium"

        return self.default_reasoning_effort

    def _build_command(self, model: str, sampling: dict | None = None, manifest: dict | None = None) -> list[str]:
        """Build the codex command."""
        cmd = [
            self.executable,
            "exec",
            "-",  # read prompt from stdin
            "--sandbox",
            str(self.sandbox_mode),
        ]

        if self.ask_for_approval == "never":
            if self.sandbox_mode == "danger-full-access":
                cmd.append("--dangerously-bypass-approvals-and-sandbox")
            else:
                cmd.append("--full-auto")

        if self.use_json_output:
            cmd.append("--json")

        reasoning_effort = self._resolve_reasoning_effort(manifest or {})
        if reasoning_effort:
            cmd.extend(
                [
                    "--config",
                    f"model_reasoning_effort={json.dumps(str(reasoning_effort))}",
                ]
            )

        if model:
            cmd.extend(["--model", model])

        if isinstance(sampling, dict):
            temperature = sampling.get("temperature")
            if isinstance(temperature, (int, float)):
                cmd.extend(["--config", f"temperature={float(temperature)}"])
            top_p = sampling.get("top_p")
            if isinstance(top_p, (int, float)):
                cmd.extend(["--config", f"top_p={float(top_p)}"])

        extra_args = self.config.get("extra_args")
        if isinstance(extra_args, list):
            cmd.extend([str(a) for a in extra_args])

        return cmd

    async def _stream_output_with_telemetry(
        self,
        process: asyncio.subprocess.Process,
        telemetry: TelemetryWriter,
        stdin_data: bytes,
        timeout_seconds: float,
        *,
        quiescence_timeout_seconds: float | None = None,
    ) -> tuple[str, str]:
        """
        Stream process output while emitting telemetry events.

        Returns accumulated stdout and stderr.
        """
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []
        loop = asyncio.get_running_loop()
        effective_quiescence_timeout = (
            self.quiescence_timeout_seconds
            if quiescence_timeout_seconds is None
            else float(quiescence_timeout_seconds)
        )
        if effective_quiescence_timeout < 0:
            effective_quiescence_timeout = 0.0
        last_output_at = loop.time()

        def mark_activity() -> None:
            nonlocal last_output_at
            last_output_at = loop.time()

        async def write_stdin() -> None:
            """Write prompt to stdin and close."""
            if process.stdin:
                try:
                    process.stdin.write(stdin_data)
                    await process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    # Process may exit before prompt write completes.
                    return
                process.stdin.close()

        async def read_stdout() -> None:
            """Read stdout in chunks to avoid line-length overrun errors."""
            if not process.stdout:
                return
            while True:
                chunk = await process.stdout.read(8192)
                if not chunk:
                    break
                decoded = chunk.decode("utf-8", errors="replace")
                stdout_lines.append(decoded)
                if _has_meaningful_output(decoded):
                    mark_activity()
                telemetry.response_chunk(content=decoded.rstrip())

        async def read_stderr() -> None:
            """Read stderr in chunks to avoid line-length overrun errors."""
            if not process.stderr:
                return
            while True:
                chunk = await process.stderr.read(8192)
                if not chunk:
                    break
                decoded = chunk.decode("utf-8", errors="replace")
                stderr_lines.append(decoded)
                if _has_meaningful_output(decoded):
                    mark_activity()

        async def monitor_stall(
            stdout_task: asyncio.Task[None],
            stderr_task: asyncio.Task[None],
            wait_task: asyncio.Task[int],
        ) -> None:
            """Fail fast when no output is observed after prompt dispatch."""
            if effective_quiescence_timeout <= 0:
                return
            check_interval = min(1.0, max(0.2, effective_quiescence_timeout / 5.0))
            process_exit_observed_at: float | None = None
            while True:
                # Treat stream completion as terminal; otherwise keep watching for stalls
                # even if the direct process handle exits but descendants hold pipes open.
                if stdout_task.done() and stderr_task.done() and wait_task.done():
                    return
                if wait_task.done() and process_exit_observed_at is None:
                    process_exit_observed_at = loop.time()
                    # Direct process exit is progress; allow a bounded drain window for
                    # stdout/stderr readers to consume final buffered output.
                    mark_activity()
                if process_exit_observed_at is not None and not (stdout_task.done() and stderr_task.done()):
                    drain_idle_for = loop.time() - process_exit_observed_at
                    if drain_idle_for >= self.post_exit_stream_drain_seconds:
                        raise CodexOutputStallError(self.post_exit_stream_drain_seconds)
                    await asyncio.sleep(min(check_interval, 1.0))
                    continue
                idle_for = loop.time() - last_output_at
                if idle_for >= effective_quiescence_timeout:
                    # Confirm stall before failing to avoid races where output arrives near
                    # timeout boundary but has not yet been reflected in last_output_at.
                    if self.stall_confirmation_seconds > 0:
                        prior_activity_at = last_output_at
                        await asyncio.sleep(self.stall_confirmation_seconds)
                        idle_for = loop.time() - last_output_at
                        if last_output_at > prior_activity_at:
                            continue
                        if idle_for < effective_quiescence_timeout:
                            continue
                        if stdout_task.done() and stderr_task.done() and wait_task.done():
                            return
                    raise CodexOutputStallError(effective_quiescence_timeout)
                await asyncio.sleep(check_interval)

        stdin_task = asyncio.create_task(write_stdin())
        stdout_task = asyncio.create_task(read_stdout())
        stderr_task = asyncio.create_task(read_stderr())
        wait_task = asyncio.create_task(process.wait())
        monitor_task = asyncio.create_task(
            monitor_stall(
                stdout_task=stdout_task,
                stderr_task=stderr_task,
                wait_task=wait_task,
            )
        )

        tasks = [stdin_task, stdout_task, stderr_task, wait_task, monitor_task]

        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=timeout_seconds)
        except CodexOutputStallError:
            # If the process is about to finish, give it a short grace period so we
            # do not discard valid completions that arrive near the stall boundary.
            if self.stall_exit_grace_seconds > 0:
                with contextlib.suppress(asyncio.TimeoutError, Exception):
                    await asyncio.wait_for(
                        asyncio.shield(wait_task), timeout=self.stall_exit_grace_seconds
                    )
                if wait_task.done() and process.returncode is not None:
                    streams_drained = False
                    with contextlib.suppress(asyncio.TimeoutError, Exception):
                        await asyncio.wait_for(
                            asyncio.gather(stdout_task, stderr_task),
                            timeout=self.stall_exit_grace_seconds,
                        )
                        streams_drained = stdout_task.done() and stderr_task.done()
                    if streams_drained:
                        return "".join(stdout_lines), "".join(stderr_lines)
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            with contextlib.suppress(Exception):
                await process.wait()
            raise
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            with contextlib.suppress(Exception):
                await process.wait()
            raise
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            for task in tasks:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task

        return "".join(stdout_lines), "".join(stderr_lines)

    def _create_stall_timeout_proof(
        self,
        manifest: dict,
        started_at: datetime,
        *,
        heartbeat_timeout_seconds: float,
    ) -> PatchProof:
        """Build timeout proof with deterministic deadlock reason metadata."""
        proof = self._create_timeout_proof(manifest, started_at)

        metadata = proof.metadata if isinstance(proof.metadata, dict) else {}
        metadata.update(
            {
                "error": "Execution stalled after prompt dispatch (no output heartbeat)",
                "timeout_reason": "prompt_stall_no_output",
                "heartbeat_timeout_seconds": float(heartbeat_timeout_seconds),
            }
        )
        proof.metadata = metadata

        verification = proof.verification if isinstance(proof.verification, dict) else {}
        verification["blocking_failures"] = ["prompt_stall_no_output"]
        proof.verification = verification

        return proof

    def _save_logs(self, logs_dir: Path, stdout: str, stderr: str) -> None:
        """Save stdout and stderr to log files."""
        if stdout:
            (logs_dir / "codex-stdout.log").write_text(stdout)
        if stderr:
            (logs_dir / "codex-stderr.log").write_text(stderr)

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
        """Parse Codex output into PatchProof."""
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        # Try to parse JSON output from stdout (if codex outputs JSON)
        codex_output: dict = {}
        if stdout.strip():
            # First, attempt JSONL event parsing (used by codex --json).
            parsed_events: list[dict] = []
            for line in stdout.splitlines():
                candidate = line.strip()
                if not candidate:
                    continue
                try:
                    event = json.loads(candidate)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    parsed_events.append(event)

            if parsed_events:
                for event in parsed_events:
                    if event.get("type") == "turn.completed" and isinstance(event.get("usage"), dict):
                        usage = event["usage"]
                        codex_output["tokens_used"] = usage.get(
                            "output_tokens", usage.get("total_tokens")
                        )
                        codex_output["usage"] = usage
                    item = event.get("item")
                    if (
                        event.get("type") == "item.completed"
                        and isinstance(item, dict)
                        and item.get("type") == "agent_message"
                    ):
                        codex_output["final_message"] = item.get("text")

            # Fallback for non-JSONL output.
            if not codex_output:
                for candidate in [stdout.strip(), stdout.strip().split("\n")[-1]]:
                    try:
                        codex_output = json.loads(candidate)
                        break
                    except json.JSONDecodeError:
                        continue

        # Get git patch info
        patch_info = self._get_patch_info(workcell_path, manifest)

        # Determine status based on exit code and output
        if exit_code == 0:
            status = "success"
            confidence = codex_output.get("confidence", 0.8)
        elif exit_code == 1:
            status = "partial"  # Completed but with issues
            confidence = codex_output.get("confidence", 0.5)
        else:
            status = "failed"
            confidence = codex_output.get("confidence", 0.2)

        metadata = {
            "toolchain": self.name,
            "toolchain_version": codex_output.get("version", "unknown"),
            "model": manifest.get("toolchain_config", {}).get("model", self.default_model),
            "prompt_genome_id": (manifest.get("toolchain_config") or {}).get(
                "prompt_genome_id"
            ),
            "sampling": (manifest.get("toolchain_config") or {}).get("sampling"),
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
            "tokens_used": codex_output.get("tokens_used"),
            "cost_usd": codex_output.get("cost"),
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
                "all_passed": False,  # Will be updated by verifier
                "blocking_failures": [],
            },
            metadata=metadata,
            commands_executed=[
                {
                    "command": "codex",
                    "exit_code": exit_code,
                    "duration_ms": duration_ms,
                    "stdout_path": str(workcell_path / "logs" / "codex-stdout.log"),
                    "stderr_path": str(workcell_path / "logs" / "codex-stderr.log"),
                }
            ],
            confidence=confidence,
            risk_classification=self._classify_risk(patch_info, manifest),
        )
