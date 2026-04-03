"""
Youtu-Agent Adapter - Tencent Youtu-Agent integration.

Runs Youtu-Agent's SimpleAgent against a workcell using a fixed YAML config.
Requires a local Youtu-Agent checkout or installed module (utu).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog

from cyntra.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter

logger = structlog.get_logger()


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


class YoutuAgentAdapter(ToolchainAdapter):
    """
    Adapter for the Tencent Youtu-Agent SimpleAgent.

    Executes a Python runner script inside the workcell, which in turn
    loads a Youtu-Agent config and runs SimpleAgent on the prompt.
    """

    name = "youtu-agent"
    supports_mcp = True
    supports_streaming = False

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.python_bin = str(self.config.get("python") or self.config.get("python_bin") or "python")
        self.agent_root = self.config.get("agent_root")
        self.config_path = self.config.get("config_path")
        self.config_name = self.config.get("config_name")
        self.default_model = self.config.get("model", "youtu-llm")
        self.mcp_servers = self.config.get("mcp_servers")
        self.env = dict(self.config.get("env") or {})
        self._available: bool | None = None

    @property
    def available(self) -> bool:
        """Check if Youtu-Agent is available (module or repo path)."""
        if self._available is None:
            if "/" in self.python_bin:
                self._available = Path(self.python_bin).exists()
            else:
                self._available = shutil.which(self.python_bin) is not None

            if not self._available:
                return False

            agent_root = Path(self.agent_root).expanduser() if self.agent_root else None
            if agent_root and agent_root.exists():
                self._available = True
            else:
                try:
                    import importlib.util

                    self._available = importlib.util.find_spec("utu") is not None
                except Exception:
                    self._available = False
        return self._available

    def execute_sync(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout_seconds: int = 1800,
    ) -> PatchProof:
        """Execute task synchronously using Youtu-Agent."""
        started_at = _utc_now()
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        aegis_run = self._start_aegis_run_sync(manifest, workcell_path)
        proof = None

        prompt = self._build_prompt(manifest, workcell_path)
        prompt_file = workcell_path / "prompt.md"
        prompt_file.write_text(prompt)

        toolchain_config = manifest.get("toolchain_config", {}) or {}
        model = toolchain_config.get("model", self.default_model)

        config_name = toolchain_config.get("config_name") or self.config_name
        config_path = toolchain_config.get("config_path") or self.config_path
        agent_root = toolchain_config.get("agent_root") or self.agent_root
        mcp_servers = toolchain_config.get("mcp_servers") or self.mcp_servers

        runner_path = self._resolve_runner_path(workcell_path)
        output_path = workcell_path / "youtu_agent_output.json"
        if not runner_path.exists():
            proof = self._create_error_proof(
                manifest,
                started_at,
                f"Runner not found at {runner_path}",
            )
            aegis_metadata = self._finalize_aegis_run_sync(aegis_run, proof.status)
            self._refresh_proof_metadata(proof, manifest, workcell_path, aegis_metadata)
            (workcell_path / "proof.json").write_text(json.dumps(proof.to_dict(), indent=2))
            return proof

        cmd = self._build_command(
            runner_path=runner_path,
            prompt_path=prompt_file,
            output_path=output_path,
            config_path=config_path,
            config_name=config_name,
            model=model,
            mcp_servers=mcp_servers,
        )

        logger.info(
            "Executing Youtu-Agent",
            workcell_id=workcell_id,
            issue_id=issue_id,
            model=model,
        )

        try:
            result = subprocess.run(
                cmd,
                cwd=workcell_path,
                capture_output=True,
                text=True,
                env=self._build_env(manifest, workcell_path, agent_root),
                timeout=timeout_seconds,
            )

            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            self._save_logs(logs_dir, result.stdout, result.stderr)

            runner_output = self._read_runner_output(output_path, result.stdout)

            proof = self._parse_output(
                runner_output=runner_output,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                manifest=manifest,
                workcell_path=workcell_path,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                model=model,
                config_name=config_name,
                config_path=config_path,
                agent_root=agent_root,
                mcp_servers=mcp_servers,
            )

        except subprocess.TimeoutExpired:
            logger.error(
                "Youtu-Agent execution timed out",
                workcell_id=workcell_id,
                timeout=timeout_seconds,
            )
            proof = self._create_timeout_proof(manifest, started_at)
        except Exception as e:
            logger.error(
                "Youtu-Agent execution failed",
                workcell_id=workcell_id,
                error=str(e),
            )
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
        """Execute task asynchronously using Youtu-Agent."""
        started_at = _utc_now()
        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        aegis_run = await self._start_aegis_run(manifest, workcell_path)
        proof: PatchProof | None = None

        prompt = self._build_prompt(manifest, workcell_path)
        prompt_file = workcell_path / "prompt.md"
        prompt_file.write_text(prompt)

        toolchain_config = manifest.get("toolchain_config", {}) or {}
        model = toolchain_config.get("model", self.default_model)
        config_name = toolchain_config.get("config_name") or self.config_name
        config_path = toolchain_config.get("config_path") or self.config_path
        agent_root = toolchain_config.get("agent_root") or self.agent_root
        mcp_servers = toolchain_config.get("mcp_servers") or self.mcp_servers

        runner_path = self._resolve_runner_path(workcell_path)
        output_path = workcell_path / "youtu_agent_output.json"
        if not runner_path.exists():
            proof = self._create_error_proof(
                manifest,
                started_at,
                f"Runner not found at {runner_path}",
            )
            aegis_metadata = await self._finalize_aegis_run(aegis_run, proof.status)
            self._refresh_proof_metadata(proof, manifest, workcell_path, aegis_metadata)
            (workcell_path / "proof.json").write_text(json.dumps(proof.to_dict(), indent=2))
            return proof
        cmd = self._build_command(
            runner_path=runner_path,
            prompt_path=prompt_file,
            output_path=output_path,
            config_path=config_path,
            config_name=config_name,
            model=model,
            mcp_servers=mcp_servers,
        )

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=workcell_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._build_env(manifest, workcell_path, agent_root),
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout.total_seconds(),
            )

            completed_at = _utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            stdout_text = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")
            self._save_logs(logs_dir, stdout_text, stderr_text)

            runner_output = self._read_runner_output(output_path, stdout_text)

            proof = self._parse_output(
                runner_output=runner_output,
                stdout=stdout_text,
                stderr=stderr_text,
                exit_code=process.returncode or 0,
                manifest=manifest,
                workcell_path=workcell_path,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                model=model,
                config_name=config_name,
                config_path=config_path,
                agent_root=agent_root,
                mcp_servers=mcp_servers,
            )

        except TimeoutError:
            logger.error(
                "Youtu-Agent execution timed out",
                workcell_id=manifest.get("workcell_id", "unknown"),
            )
            proof = self._create_timeout_proof(manifest, started_at)
        except Exception as e:
            logger.error(
                "Youtu-Agent execution failed",
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
        """Check if Youtu-Agent is available."""
        return self.available

    def estimate_cost(self, manifest: dict) -> CostEstimate:
        """Estimate cost for Youtu-Agent runs (placeholder)."""
        issue = manifest.get("issue", {}) if isinstance(manifest, dict) else {}
        estimated_tokens = int(issue.get("dk_estimated_tokens") or 0)
        return CostEstimate(
            estimated_tokens=estimated_tokens,
            estimated_cost_usd=0.0,
            model=(manifest.get("toolchain_config") or {}).get("model", self.default_model),
        )

    def _resolve_runner_path(self, workcell_path: Path) -> Path:
        """Resolve the runner path inside the workcell."""
        return workcell_path / "kernel" / "src" / "cyntra" / "adapters" / "youtu_agent_runner.py"

    def _build_env(
        self,
        manifest: dict,
        workcell_path: Path,
        agent_root: str | None,
    ) -> dict[str, str]:
        env = super()._build_env(manifest, workcell_path)
        if agent_root:
            agent_root_path = str(Path(agent_root).expanduser())
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = (
                f"{agent_root_path}{os.pathsep}{existing}" if existing else agent_root_path
            )
            env.setdefault("YOUTU_AGENT_ROOT", agent_root_path)
        return env

    def _build_command(
        self,
        *,
        runner_path: Path,
        prompt_path: Path,
        output_path: Path,
        config_path: str | None,
        config_name: str | None,
        model: str | None,
        mcp_servers: Any,
    ) -> list[str]:
        cmd = [self.python_bin, str(runner_path), "--prompt", str(prompt_path), "--output", str(output_path)]
        if config_path:
            cmd.extend(["--config-path", str(config_path)])
        if config_name:
            cmd.extend(["--config-name", str(config_name)])
        if model:
            cmd.extend(["--model", str(model)])
        if mcp_servers is not None:
            cmd.extend(["--mcp-servers", json.dumps(mcp_servers)])
        extra_args = self.config.get("extra_args")
        if isinstance(extra_args, list):
            cmd.extend([str(a) for a in extra_args])
        return cmd

    def _save_logs(self, logs_dir: Path, stdout: str, stderr: str) -> None:
        if stdout:
            (logs_dir / "youtu-agent-stdout.log").write_text(stdout)
        if stderr:
            (logs_dir / "youtu-agent-stderr.log").write_text(stderr)

    def _read_runner_output(self, output_path: Path, stdout: str) -> dict[str, Any]:
        if output_path.exists():
            try:
                return json.loads(output_path.read_text())
            except Exception:
                pass

        if stdout.strip():
            for line in reversed(stdout.strip().split("\n")):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return {}

    def _parse_output(
        self,
        *,
        runner_output: dict[str, Any],
        stdout: str,
        stderr: str,
        exit_code: int,
        manifest: dict,
        workcell_path: Path,
        started_at: datetime,
        completed_at: datetime,
        duration_ms: int,
        model: str | None,
        config_name: str | None,
        config_path: str | None,
        agent_root: str | None,
        mcp_servers: Any,
    ) -> PatchProof:
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        patch_info = self._get_patch_info(workcell_path, manifest)

        if exit_code == 0:
            status = "success"
            confidence = float(runner_output.get("confidence", 0.6) or 0.6)
        elif exit_code == 1:
            status = "partial"
            confidence = float(runner_output.get("confidence", 0.4) or 0.4)
        else:
            status = "failed"
            confidence = float(runner_output.get("confidence", 0.2) or 0.2)

        metadata: dict[str, Any] = {
            "toolchain": self.name,
            "toolchain_version": runner_output.get("version", "unknown"),
            "model": model,
            "agent_config_name": config_name,
            "agent_config_path": config_path,
            "agent_root": agent_root,
            "mcp_servers": mcp_servers,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "duration_ms": duration_ms,
            "exit_code": exit_code,
        }

        metrics = runner_output.get("metrics")
        if isinstance(metrics, dict):
            for key in (
                "tokens_used",
                "total_tokens",
                "prompt_tokens",
                "completion_tokens",
                "cost_usd",
            ):
                if key in metrics:
                    metadata[key] = metrics[key]

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
                    "command": " ".join([self.python_bin, str(self._resolve_runner_path(workcell_path))]),
                    "exit_code": exit_code,
                    "duration_ms": duration_ms,
                    "stdout_path": str(workcell_path / "logs" / "youtu-agent-stdout.log"),
                    "stderr_path": str(workcell_path / "logs" / "youtu-agent-stderr.log"),
                }
            ],
            confidence=confidence,
            risk_classification=self._classify_risk(patch_info, manifest),
        )

    def _get_patch_info(self, workcell_path: Path, manifest: dict) -> dict:
        base_result = subprocess.run(
            ["git", "merge-base", "main", "HEAD"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        base_commit = base_result.stdout.strip() if base_result.returncode == 0 else ""

        head_result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        head_commit = head_result.stdout.strip() if head_result.returncode == 0 else ""

        stat_result = subprocess.run(
            ["git", "diff", "--stat", "main...HEAD"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        files_changed, insertions, deletions = self._parse_diff_stats(stat_result.stdout)

        files_result = subprocess.run(
            ["git", "diff", "--name-only", "main...HEAD"],
            cwd=workcell_path,
            capture_output=True,
            text=True,
        )
        files_modified = [line.strip() for line in files_result.stdout.split("\n") if line.strip()]

        forbidden = manifest.get("issue", {}).get("forbidden_paths", [])
        violations = self._check_forbidden_paths(files_modified, forbidden)

        return {
            "branch": manifest.get("branch_name", ""),
            "base_commit": base_commit,
            "head_commit": head_commit,
            "diff_stats": {
                "files_changed": files_changed,
                "insertions": insertions,
                "deletions": deletions,
            },
            "files_modified": files_modified,
            "forbidden_path_violations": violations,
        }

    def _parse_diff_stats(self, stat_output: str) -> tuple[int, int, int]:
        import re

        files_changed = 0
        insertions = 0
        deletions = 0

        if not stat_output:
            return files_changed, insertions, deletions

        lines = stat_output.strip().split("\n")
        if lines:
            summary = lines[-1]
            files_match = re.search(r"(\d+) files? changed", summary)
            ins_match = re.search(r"(\d+) insertions?", summary)
            del_match = re.search(r"(\d+) deletions?", summary)

            files_changed = int(files_match.group(1)) if files_match else 0
            insertions = int(ins_match.group(1)) if ins_match else 0
            deletions = int(del_match.group(1)) if del_match else 0

        return files_changed, insertions, deletions

    def _check_forbidden_paths(self, files_modified: list[str], forbidden: list[str]) -> list[str]:
        violations = []
        for file in files_modified:
            for pattern in forbidden:
                if pattern.endswith("/"):
                    if file.startswith(pattern):
                        violations.append(file)
                elif pattern.endswith("*"):
                    if file.startswith(pattern[:-1]):
                        violations.append(file)
                else:
                    if file == pattern or file.startswith(pattern + "/"):
                        violations.append(file)
        return violations

    def _classify_risk(self, patch_info: dict, manifest: dict) -> str:
        if patch_info.get("forbidden_path_violations"):
            return "critical"

        files = patch_info.get("files_modified", [])
        high_risk_patterns = [
            "auth",
            "security",
            "password",
            "secret",
            "key",
            "migration",
            "schema",
            "database",
            "payment",
            "billing",
            "stripe",
        ]

        for file in files:
            file_lower = file.lower()
            if any(pattern in file_lower for pattern in high_risk_patterns):
                return "high"

        stats = patch_info.get("diff_stats", {})
        total_changes = stats.get("insertions", 0) + stats.get("deletions", 0)

        if total_changes > 500:
            return "high"
        if total_changes > 100:
            return "medium"

        return "low"

    def _create_timeout_proof(self, manifest: dict, started_at: datetime) -> PatchProof:
        completed_at = _utc_now()
        metadata = {
            "toolchain": self.name,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "error": "Execution timed out",
        }
        metadata = self._augment_metadata(metadata, manifest, None)

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=manifest.get("workcell_id", "unknown"),
            issue_id=manifest.get("issue", {}).get("id", "unknown"),
            status="timeout",
            patch={
                "branch": manifest.get("branch_name", ""),
                "base_commit": "",
                "head_commit": "",
                "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
                "files_modified": [],
                "forbidden_path_violations": [],
            },
            verification={
                "gates": {},
                "all_passed": False,
                "blocking_failures": ["timeout"],
            },
            metadata=metadata,
            confidence=0,
            risk_classification="high",
        )

    def _create_error_proof(self, manifest: dict, started_at: datetime, error: str) -> PatchProof:
        completed_at = _utc_now()
        metadata = {
            "toolchain": self.name,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "error": error,
        }
        metadata = self._augment_metadata(metadata, manifest, None)

        return PatchProof(
            schema_version="1.0.0",
            workcell_id=manifest.get("workcell_id", "unknown"),
            issue_id=manifest.get("issue", {}).get("id", "unknown"),
            status="error",
            patch={
                "branch": manifest.get("branch_name", ""),
                "base_commit": "",
                "head_commit": "",
                "diff_stats": {"files_changed": 0, "insertions": 0, "deletions": 0},
                "files_modified": [],
                "forbidden_path_violations": [],
            },
            verification={
                "gates": {},
                "all_passed": False,
                "blocking_failures": ["error"],
            },
            metadata=metadata,
            confidence=0,
            risk_classification="high",
        )
