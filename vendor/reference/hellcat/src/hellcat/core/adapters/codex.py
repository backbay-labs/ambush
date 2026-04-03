"""
Codex CLI Adapter - OpenAI Codex toolchain integration.

https://github.com/openai/codex
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog

from hellcat.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter
from hellcat.core.adapters.telemetry import TelemetryWriter, resolve_kernel_events_path

logger = structlog.get_logger()


def _utc_now() -> datetime:
    return datetime.now(UTC)


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
        self._available: bool | None = None

    @property
    def available(self) -> bool:
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
        started_at = _utc_now()
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")
        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        prompt = self._build_prompt(manifest, workcell_path)
        prompt_file = workcell_path / "prompt.md"
        prompt_file.write_text(prompt)

        toolchain_config = manifest.get("toolchain_config", {}) or {}
        model = toolchain_config.get("model", self.default_model)
        sampling = toolchain_config.get("sampling") if isinstance(toolchain_config, dict) else None

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

            self._save_logs(logs_dir, result.stdout, result.stderr)

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

        proof_path = workcell_path / "proof.json"
        proof_path.write_text(json.dumps(proof.to_dict(), indent=2))

        return proof

    async def execute(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout: timedelta,
    ) -> PatchProof:
        started_at = _utc_now()
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")
        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        prompt = self._build_prompt(manifest, workcell_path)
        prompt_file = workcell_path / "prompt.md"
        prompt_file.write_text(prompt)

        toolchain_config = manifest.get("toolchain_config", {}) or {}
        model = toolchain_config.get("model", self.default_model)
        sampling = toolchain_config.get("sampling") if isinstance(toolchain_config, dict) else None

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

        cmd = self._build_command(model, sampling=sampling, manifest=manifest)

        logger.info(
            "Executing Codex (async)",
            workcell_id=workcell_id,
            model=model,
        )

        aegis_run = await self._start_aegis_run(manifest, workcell_path)
        proof: PatchProof | None = None

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

            stdout, stderr = await self._stream_output_with_telemetry(
                process,
                telemetry,
                prompt.encode(),
                timeout.total_seconds(),
            )

            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

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

            telemetry.completed(
                status=proof.status,
                exit_code=process.returncode or 0,
                duration_ms=duration_ms,
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

        proof_path = workcell_path / "proof.json"
        proof_path.write_text(json.dumps(proof.to_dict(), indent=2))

        telemetry.close()
        return proof

    async def health_check(self) -> bool:
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
    ) -> tuple[str, str]:
        """
        Stream process output while emitting telemetry events.

        Returns accumulated stdout and stderr.
        """
        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        async def write_stdin() -> None:
            """Write prompt to stdin and close."""
            if process.stdin:
                process.stdin.write(stdin_data)
                await process.stdin.drain()
                process.stdin.close()

        async def read_stdout() -> None:
            """Read stdout line by line."""
            if not process.stdout:
                return
            async for line in process.stdout:
                decoded = line.decode("utf-8", errors="replace")
                stdout_lines.append(decoded)
                # Emit as response chunk
                telemetry.response_chunk(content=decoded.rstrip())

        async def read_stderr() -> None:
            """Read stderr line by line."""
            if not process.stderr:
                return
            async for line in process.stderr:
                decoded = line.decode("utf-8", errors="replace")
                stderr_lines.append(decoded)

        try:
            await asyncio.wait_for(
                asyncio.gather(write_stdin(), read_stdout(), read_stderr(), process.wait()),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            process.kill()
            await process.wait()
            raise

        return "".join(stdout_lines), "".join(stderr_lines)

    def _save_logs(self, logs_dir: Path, stdout: str, stderr: str) -> None:
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
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        codex_output: dict = {}
        if stdout.strip():
            # Look for JSON in the last line or the entire output
            for candidate in [stdout.strip(), stdout.strip().split("\n")[-1]]:
                try:
                    codex_output = json.loads(candidate)
                    break
                except json.JSONDecodeError:
                    continue

        patch_info = self._get_patch_info(workcell_path, manifest)

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

