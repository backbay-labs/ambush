"""
OpenCode Adapter - OpenCode toolchain integration.

OpenCode is a terminal/TUI agent that can run in a headless, non-interactive mode via
`opencode run`. It supports multiple providers/models via `--model provider/model`.
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

logger = structlog.get_logger()


def _utc_now() -> datetime:
    return datetime.now(UTC)


class OpenCodeAdapter(ToolchainAdapter):
    """
    Adapter for OpenCode CLI (`opencode`).

    OpenCode runs a coding agent inside the current working directory and can
    emit structured JSON event streams (`--format json`).
    """

    name = "opencode"
    supports_mcp = False
    supports_streaming = True

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.executable = str(self.config.get("path") or "opencode")
        self.env = dict(self.config.get("env") or {})
        self.default_model = self.config.get("model", "")
        self.agent = self.config.get("agent", "")
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
        cmd = self._build_command(model=model, prompt_file=prompt_file)

        logger.info(
            "Executing OpenCode",
            workcell_id=workcell_id,
            issue_id=issue_id,
            model=model,
            agent=self.agent or None,
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

        except subprocess.TimeoutExpired:
            logger.error(
                "OpenCode execution timed out", workcell_id=workcell_id, timeout=timeout_seconds
            )
            proof = self._create_timeout_proof(manifest, started_at)
        except Exception as e:
            logger.error("OpenCode execution failed", workcell_id=workcell_id, error=str(e))
            proof = self._create_error_proof(manifest, started_at, str(e))

        if proof is None:
            proof = self._create_error_proof(manifest, started_at, "missing_proof")

        aegis_metadata = self._finalize_aegis_run_sync(aegis_run, proof.status)
        self._refresh_proof_metadata(proof, manifest, workcell_path, aegis_metadata)

        (workcell_path / "proof.json").write_text(json.dumps(proof.to_dict(), indent=2))
        return proof

    async def execute(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout: timedelta,
    ) -> PatchProof:
        started_at = _utc_now()
        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        prompt = self._build_prompt(manifest, workcell_path)
        prompt_file = workcell_path / "prompt.md"
        prompt_file.write_text(prompt)

        toolchain_config = manifest.get("toolchain_config", {}) or {}
        model = toolchain_config.get("model", self.default_model)
        cmd = self._build_command(model=model, prompt_file=prompt_file)

        aegis_run = await self._start_aegis_run(manifest, workcell_path)
        proof: PatchProof | None = None

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=workcell_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._build_env(manifest, workcell_path),
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout.total_seconds(),
            )

            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            stdout_text = stdout.decode()
            stderr_text = stderr.decode()
            self._save_logs(logs_dir, stdout_text, stderr_text)

            proof = self._parse_output(
                stdout=stdout_text,
                stderr=stderr_text,
                exit_code=process.returncode or 0,
                manifest=manifest,
                workcell_path=workcell_path,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        except TimeoutError:
            logger.error(
                "OpenCode execution timed out", workcell_id=manifest.get("workcell_id", "unknown")
            )
            proof = self._create_timeout_proof(manifest, started_at)
        except Exception as e:
            logger.error(
                "OpenCode execution failed",
                workcell_id=manifest.get("workcell_id", "unknown"),
                error=str(e),
            )
            proof = self._create_error_proof(manifest, started_at, str(e))

        if proof is None:
            proof = self._create_error_proof(manifest, started_at, "missing_proof")

        aegis_metadata = await self._finalize_aegis_run(aegis_run, proof.status)
        self._refresh_proof_metadata(proof, manifest, workcell_path, aegis_metadata)

        (workcell_path / "proof.json").write_text(json.dumps(proof.to_dict(), indent=2))
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

        # Cost per 1M tokens is highly model/provider-specific; keep conservative defaults.
        cost_per_1m = {
            # OpenAI (common when using opencode as a router)
            "openai/gpt-5.2": 20.0,
            "openai/gpt-5.2-pro": 30.0,
            "openai/o3": 20.0,
            "openai/o3-mini": 5.0,
        }.get(model, 5.0)

        return CostEstimate(
            estimated_tokens=estimated_tokens,
            estimated_cost_usd=(estimated_tokens / 1_000_000) * cost_per_1m,
            model=model,
        )

    def _build_command(self, model: str, prompt_file: Path) -> list[str]:
        # Prefer file attachment to avoid shell/argv limits for large prompts.
        cmd = [
            self.executable,
            "run",
            "--format",
            "json",
            "--file",
            str(prompt_file),
            "Execute the task described in prompt.md",
        ]

        if model:
            cmd.extend(["--model", model])

        if self.agent:
            cmd.extend(["--agent", self.agent])

        extra_args = self.config.get("extra_args")
        if isinstance(extra_args, list):
            cmd.extend([str(a) for a in extra_args])

        return cmd

    def _save_logs(self, logs_dir: Path, stdout: str, stderr: str) -> None:
        if stdout:
            (logs_dir / "opencode-stdout.log").write_text(stdout)
        if stderr:
            (logs_dir / "opencode-stderr.log").write_text(stderr)

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

        opencode_output: dict[str, object] = {}
        if stdout.strip():
            # opencode --format json emits JSON event stream; grab last valid JSON object.
            for line in reversed(stdout.strip().split("\n")):
                try:
                    opencode_output = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

        patch_info = self._get_patch_info(workcell_path, manifest)

        if exit_code == 0:
            status = "success"
            confidence = float(opencode_output.get("confidence", 0.7) or 0.7)
        elif exit_code == 1:
            status = "partial"
            confidence = float(opencode_output.get("confidence", 0.5) or 0.5)
        else:
            status = "failed"
            confidence = float(opencode_output.get("confidence", 0.2) or 0.2)

        metadata = {
            "toolchain": self.name,
            "toolchain_version": opencode_output.get("version", "unknown"),
            "model": manifest.get("toolchain_config", {}).get("model", self.default_model),
            "prompt_genome_id": (manifest.get("toolchain_config") or {}).get("prompt_genome_id"),
            "sampling": (manifest.get("toolchain_config") or {}).get("sampling"),
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
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
                    "command": "opencode run",
                    "exit_code": exit_code,
                    "duration_ms": duration_ms,
                    "stdout_path": str(workcell_path / "logs" / "opencode-stdout.log"),
                    "stderr_path": str(workcell_path / "logs" / "opencode-stderr.log"),
                }
            ],
            confidence=confidence,
            risk_classification=self._classify_risk(patch_info),
        )

