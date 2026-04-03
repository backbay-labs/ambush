"""
Crush Adapter - Charmbracelet Crush toolchain integration.

https://github.com/charmbracelet/crush

Crush is "the glamourous AI coding agent for your favourite terminal"
from Charmbracelet. It supports multiple providers including OpenAI,
Anthropic, Bedrock, Vertex AI, and local models via Ollama/LM Studio.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog

from cyntra.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter

logger = structlog.get_logger()


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


class CrushAdapter(ToolchainAdapter):
    """
    Adapter for Charmbracelet Crush CLI.

    Crush is a terminal-based AI coding agent that supports:
    - Multiple providers (OpenAI, Anthropic, Bedrock, Vertex, local)
    - Project-level configuration via crush.json
    - Autonomous coding with file editing capabilities
    - MCP tool integration
    """

    name = "crush"
    supports_mcp = True
    supports_streaming = True

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.executable = str(self.config.get("path") or "crush")
        self.env = dict(self.config.get("env") or {})
        self.default_model = self.config.get("model", "claude-sonnet-4-5-20250929")
        self.provider = self.config.get("provider", "anthropic")
        self.auto_approve = self.config.get("auto_approve", True)
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        """Check if crush CLI is available."""
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
        Execute task synchronously using Crush CLI.
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

        # Build command
        cmd = self._build_command()

        logger.info(
            "Executing Crush",
            workcell_id=workcell_id,
            issue_id=issue_id,
            model=model,
            provider=self.provider,
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
                "Crush execution completed",
                workcell_id=workcell_id,
                status=proof.status,
                duration_ms=duration_ms,
            )

        except subprocess.TimeoutExpired:
            logger.error(
                "Crush execution timed out",
                workcell_id=workcell_id,
                timeout=timeout_seconds,
            )
            proof = self._create_timeout_proof(manifest, started_at)

        except Exception as e:
            logger.error(
                "Crush execution failed",
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
        """Execute task asynchronously using Crush CLI."""
        started_at = _utc_now()
        workcell_id = manifest.get("workcell_id", "unknown")

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

        # Build command
        cmd = self._build_command()

        logger.info(
            "Executing Crush (async)",
            workcell_id=workcell_id,
            model=model,
        )

        aegis_run = await self._start_aegis_run(manifest, workcell_path)
        proof: PatchProof | None = None

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=workcell_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._build_env(manifest, workcell_path),
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=prompt.encode()),
                timeout=timeout.total_seconds(),
            )

            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            # Save logs
            self._save_logs(logs_dir, stdout.decode(), stderr.decode())

            proof = self._parse_output(
                stdout=stdout.decode(),
                stderr=stderr.decode(),
                exit_code=process.returncode or 0,
                manifest=manifest,
                workcell_path=workcell_path,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
            )

        except TimeoutError:
            logger.error("Crush execution timed out", workcell_id=workcell_id)
            proof = self._create_timeout_proof(manifest, started_at)

        except Exception as e:
            logger.error("Crush execution failed", workcell_id=workcell_id, error=str(e))
            proof = self._create_error_proof(manifest, started_at, str(e))

        if proof is None:
            proof = self._create_error_proof(manifest, started_at, "missing_proof")

        aegis_metadata = await self._finalize_aegis_run(aegis_run, proof.status)
        self._refresh_proof_metadata(proof, manifest, workcell_path, aegis_metadata)

        # Write proof to file
        proof_path = workcell_path / "proof.json"
        proof_path.write_text(json.dumps(proof.to_dict(), indent=2))

        return proof

    async def health_check(self) -> bool:
        """Check if Crush CLI is available."""
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
        """Check if Crush CLI is available (sync version)."""
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
        """Estimate cost for Crush execution."""
        model = manifest.get("toolchain_config", {}).get("model", self.default_model)
        estimated_tokens = manifest.get("issue", {}).get("dk_estimated_tokens", 50000)

        # Cost per 1M tokens (varies by provider/model)
        # Based on Crush's catwalk provider database
        cost_per_1m = {
            # Anthropic
            "sonnet": 9.0,
            "opus": 45.0,
            "haiku": 0.75,
            "claude-sonnet-4-5-20250929": 9.0,
            "claude-opus-4-5-20251101": 45.0,
            "claude-haiku-4-5-20251001": 0.75,
            "claude-sonnet-4-20250514": 9.0,
            "claude-opus-4-20250514": 45.0,
            "claude-3-5-sonnet-20241022": 9.0,
            "claude-3-opus-20240229": 45.0,
            "claude-3-haiku-20240307": 0.75,
            # OpenAI
            "gpt-4o": 7.5,
            "gpt-4o-mini": 0.45,
            "o3": 20.0,
            "o1": 15.0,
            # Deepseek
            "deepseek-chat": 0.7,
            "deepseek-reasoner": 2.0,
        }.get(model, 9.0)

        estimated_cost = (estimated_tokens / 1_000_000) * cost_per_1m

        return CostEstimate(
            estimated_tokens=estimated_tokens,
            estimated_cost_usd=estimated_cost,
            model=model,
        )

    def _build_command(self) -> list[str]:
        """Build the crush command."""
        cmd = [self.executable]

        # Auto-approve for autonomous mode (Crush calls this "yolo" mode).
        if self.auto_approve:
            cmd.append("-y")

        # Non-interactive single prompt.
        cmd.extend(["run", "--quiet"])

        extra_args = self.config.get("extra_args")
        if isinstance(extra_args, list):
            cmd.extend([str(a) for a in extra_args])
        return cmd

    def _save_logs(self, logs_dir: Path, stdout: str, stderr: str) -> None:
        """Save stdout and stderr to log files."""
        if stdout:
            (logs_dir / "crush-stdout.log").write_text(stdout)
        if stderr:
            (logs_dir / "crush-stderr.log").write_text(stderr)

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
        """Parse Crush output into PatchProof."""
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        # Try to extract any JSON from output
        crush_output: dict = {}
        if stdout.strip():
            for line in reversed(stdout.strip().split("\n")):
                try:
                    crush_output = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue

        # Get git patch info
        patch_info = self._get_patch_info(workcell_path, manifest)

        # Determine status
        if exit_code == 0:
            status = "success"
            confidence = crush_output.get("confidence", 0.8)
        elif exit_code == 1:
            status = "partial"
            confidence = crush_output.get("confidence", 0.5)
        else:
            status = "failed"
            confidence = crush_output.get("confidence", 0.2)

        metadata = {
            "toolchain": self.name,
            "toolchain_version": crush_output.get("version", "unknown"),
            "model": manifest.get("toolchain_config", {}).get("model", self.default_model),
            "prompt_genome_id": (manifest.get("toolchain_config") or {}).get("prompt_genome_id"),
            "sampling": (manifest.get("toolchain_config") or {}).get("sampling"),
            "provider": self.provider,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
            "tokens_used": crush_output.get("tokens_used"),
            "cost_usd": crush_output.get("cost"),
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
                    "command": "crush",
                    "exit_code": exit_code,
                    "duration_ms": duration_ms,
                    "stdout_path": str(workcell_path / "logs" / "crush-stdout.log"),
                    "stderr_path": str(workcell_path / "logs" / "crush-stderr.log"),
                }
            ],
            confidence=confidence,
            risk_classification=self._classify_risk(patch_info),
        )

