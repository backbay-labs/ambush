"""
Workbench Provider - Controlled reverse engineering workbench execution.

This provider is scaffolding for Ghidra-style workbenches. It is intended
for future container-backed execution with strict policy enforcement.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cyntra.core.providers.base import ExecutionContext, ExecutionResult, SandboxProvider
from cyntra.core.providers.capabilities import ExecutionCapabilities
from cyntra.core.gates.results import (
    build_verification_payload,
    emit_gates_event,
    normalize_gate_result,
    resolve_logs_dir,
)
from cyntra.core.providers.sandbox.runtime import (
    SandboxMount,
    SandboxRuntimeConfig,
    SandboxRuntimeFactory,
)

logger = logging.getLogger(__name__)


class WorkbenchProvider(SandboxProvider):
    """
    Workbench execution provider (scaffolding).

    Intended for controlled RE environments (Ghidra, pwnboxes) with
    strict policy envelopes and telemetry capture.
    """

    name = "workbench"
    capabilities = ExecutionCapabilities(
        gpu=False,
        isolation_level="container",
        max_runtime=timedelta(hours=6),
        max_concurrent=4,
        persistent_volume=True,
        network_egress=False,
        network_policy=True,
        process_telemetry=True,
        file_telemetry=True,
        network_telemetry=True,
        gui_access=True,
    )

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.workbench_root = Path(self.config.get("workbench_root", ".cyntra/workbenches"))
        self.workbench_root.mkdir(parents=True, exist_ok=True)
        self._sandboxes: dict[str, Path] = {}
        self._runtime_factory = self.config.get("runtime_factory") or SandboxRuntimeFactory(
            default_backend=self.config.get("runtime_backend", "container")
        )
        self._sessions: dict[str, Any] = {}

    async def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        """Execute a workbench session."""
        start_time = datetime.utcnow()
        ctx.ensure_shields()
        owned_ledger_writer = False

        if ctx.ledger_writer or ctx.shield_manager:
            from cyntra.trust.ledger.events import StepStartedEvent
            await ctx.emit_event(StepStartedEvent(
                run_id=ctx.run_id,
                step_id=ctx.step_id,
                provider=self.name,
                manifest_id=ctx.manifest.manifest_id if ctx.manifest else "",
            ))

        try:
            sandbox_id = await self.create_sandbox(ctx)
            sandbox_path = self._sandboxes.get(sandbox_id)
            if not sandbox_path:
                raise RuntimeError("Failed to create workbench sandbox")

            if not ctx.ledger_writer:
                from cyntra.trust.ledger.writer import JSONLSink, LedgerWriter

                ledger_path_value = ctx.metadata.get("ledger_path")
                if not ledger_path_value:
                    ledger_path_value = str(sandbox_path / "ledger.jsonl")
                ctx.ledger_writer = LedgerWriter([JSONLSink(Path(ledger_path_value))])
                owned_ledger_writer = True

            self._write_run_artifacts(ctx, sandbox_path)
            self._write_challenge_inputs(ctx, sandbox_path)

            mode = str(ctx.metadata.get("workbench_mode") or self.config.get("workbench_mode") or "headless")
            runtime_config = self._build_runtime_config(ctx, sandbox_path)

            artifacts: dict[str, Path | bytes] = {}
            score_path: Path | None = None

            if mode == "gui":
                runtime = self._runtime_factory.build(runtime_config)
                handle = await runtime.start(workdir=sandbox_path)
                self._sessions[sandbox_id] = {
                    "handle": handle,
                    "runtime_config": runtime_config,
                    "sandbox_path": sandbox_path,
                }
                session_info = {
                    "schema_version": "1.0",
                    "run_id": ctx.run_id,
                    "sandbox_id": sandbox_id,
                    "backend": handle.backend,
                    "identifier": handle.identifier,
                    "gui_endpoint": ctx.metadata.get("gui_endpoint"),
                    "started_at": handle.started_at.isoformat() + "Z",
                }
                session_path = sandbox_path / "workbench_session.json"
                session_path.write_text(json.dumps(session_info, indent=2))
                artifacts["session"] = session_path
                status = "success"
                exit_code = 0
            else:
                exit_code = await self._run_headless(ctx, sandbox_path, runtime_config)
                status = "success" if exit_code == 0 else "failed"

                score_path = await self._run_workbench_score(ctx, sandbox_path)
                if score_path:
                    artifacts["workbench_score"] = score_path

            proof_path = self._write_proof(ctx, sandbox_path, status, score_path)
            if proof_path:
                artifacts["proof"] = proof_path

        except Exception as exc:
            logger.exception("Workbench execution failed")
            status = "error"
            exit_code = 1
            artifacts = {}
            error_message = str(exc)
        else:
            error_message = None

        if ctx.ledger_writer or ctx.shield_manager:
            from cyntra.trust.ledger.events import StepCompletedEvent
            await ctx.emit_event(StepCompletedEvent(
                run_id=ctx.run_id,
                step_id=ctx.step_id,
                status=status,
                duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000),
                exit_code=exit_code,
            ))

        if owned_ledger_writer and ctx.ledger_writer:
            await ctx.ledger_writer.flush()

        return ExecutionResult(
            status=status,
            exit_code=exit_code,
            artifacts=artifacts,
            error_message=error_message,
            started_at=start_time,
            completed_at=datetime.utcnow(),
        )

    async def stream_logs(self, ctx: ExecutionContext) -> AsyncIterator[str]:
        """Stream logs from a running execution (stub)."""
        return
        yield  # pragma: no cover

    async def cancel(self, ctx: ExecutionContext) -> bool:
        """Cancel a running execution (stub)."""
        sandbox_id = f"workbench-{ctx.run_id}"
        session = self._sessions.get(sandbox_id)
        if isinstance(session, dict):
            handle = session.get("handle")
            runtime_config = session.get("runtime_config")
            if handle and runtime_config:
                runtime = self._runtime_factory.build(runtime_config)
                await runtime.stop(handle)
            self._sessions.pop(sandbox_id, None)
            return True
        return False

    async def health_check(self) -> bool:
        """Check provider health (stub)."""
        return self.workbench_root.exists()

    async def create_sandbox(self, ctx: ExecutionContext) -> str:
        """Create a sandbox directory for the workbench session."""
        sandbox_id = f"workbench-{ctx.run_id}"
        run_dir = ctx.metadata.get("run_dir") or ctx.metadata.get("artifacts_dir")
        if run_dir:
            sandbox_path = Path(run_dir)
        else:
            sandbox_path = self.workbench_root / sandbox_id
        sandbox_path.mkdir(parents=True, exist_ok=True)
        self._sandboxes[sandbox_id] = sandbox_path
        return sandbox_id

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """Destroy a sandbox (stub cleanup)."""
        session = self._sessions.pop(sandbox_id, None)
        if isinstance(session, dict):
            handle = session.get("handle")
            runtime_config = session.get("runtime_config")
            if handle and runtime_config:
                runtime = self._runtime_factory.build(runtime_config)
                await runtime.stop(handle)
        self._sandboxes.pop(sandbox_id, None)

    def _write_run_artifacts(self, ctx: ExecutionContext, sandbox_path: Path) -> None:
        if ctx.metadata.get("write_run_artifacts") is False:
            return
        if ctx.manifest:
            (sandbox_path / "manifest.json").write_text(
                json.dumps(ctx.manifest.to_dict(), indent=2)
            )
            if ctx.manifest.security:
                (sandbox_path / "security_policy.json").write_text(
                    json.dumps(ctx.manifest.security.to_dict(), indent=2)
                )

        context = {
            "universe_id": ctx.metadata.get("universe_id", "aegis-artifact-arenas"),
            "universe_name": ctx.metadata.get("universe_name", "Aegis Artifact Arenas"),
            "world_id": ctx.metadata.get("world_id", "workbench"),
            "world_name": ctx.metadata.get("world_name", "Workbench Arena"),
            "world_version": ctx.metadata.get("world_version"),
            "toolchain": ctx.manifest.toolchain if ctx.manifest else "workbench",
            "provider": self.name,
            "git_sha": ctx.metadata.get("git_sha"),
            "receipt_id": ctx.metadata.get("receipt_id"),
        }
        extra_context = ctx.metadata.get("run_context")
        if isinstance(extra_context, dict):
            context.update(extra_context)
        (sandbox_path / "context.json").write_text(json.dumps(context, indent=2))

    def _write_challenge_inputs(self, ctx: ExecutionContext, sandbox_path: Path) -> None:
        challenge_spec = ctx.metadata.get("challenge_spec")
        if isinstance(challenge_spec, dict):
            (sandbox_path / "challenge_spec.json").write_text(
                json.dumps(challenge_spec, indent=2)
            )
        challenge_path = ctx.metadata.get("challenge_spec_path")
        if challenge_path:
            source = Path(challenge_path)
            if source.exists():
                (sandbox_path / "challenge_spec.json").write_text(source.read_text())

        submission = ctx.metadata.get("submission")
        if isinstance(submission, dict):
            (sandbox_path / "submission.json").write_text(json.dumps(submission, indent=2))
        submission_path = ctx.metadata.get("submission_path")
        if submission_path:
            source = Path(submission_path)
            if source.exists():
                (sandbox_path / "submission.json").write_text(source.read_text())

    def _build_runtime_config(
        self,
        ctx: ExecutionContext,
        sandbox_path: Path,
    ) -> SandboxRuntimeConfig:
        runtime_cfg: dict[str, Any] = {}
        if isinstance(self.config.get("runtime"), dict):
            runtime_cfg.update(self.config.get("runtime", {}))
        if isinstance(ctx.metadata.get("runtime"), dict):
            runtime_cfg.update(ctx.metadata.get("runtime", {}))

        backend = runtime_cfg.get("backend") or self.config.get("runtime_backend", "container")
        image = runtime_cfg.get("image") or self.config.get("container_image")
        command = runtime_cfg.get("command") or ctx.metadata.get("workbench_command")
        if isinstance(command, str):
            import shlex
            command = shlex.split(command)
        env = {}
        if isinstance(runtime_cfg.get("env"), dict):
            env.update(runtime_cfg.get("env", {}))
        if isinstance(ctx.metadata.get("runtime_env"), dict):
            env.update(ctx.metadata.get("runtime_env", {}))

        env.setdefault("CYNTRA_RUN_ID", ctx.run_id)
        env.setdefault("CYNTRA_RUN_DIR", str(sandbox_path))

        mounts: list[SandboxMount] = []
        raw_mounts = runtime_cfg.get("mounts") or []
        if isinstance(raw_mounts, list):
            for mount in raw_mounts:
                if not isinstance(mount, dict):
                    continue
                host = mount.get("host_path")
                container = mount.get("container_path")
                if not host or not container:
                    continue
                mounts.append(
                    SandboxMount(
                        host_path=Path(host),
                        container_path=str(container),
                        mode=str(mount.get("mode", "rw")),
                    )
                )

        backend_value = str(backend)
        if backend_value == "container":
            if not image:
                logger.warning("Container backend selected without image; falling back to process")
                backend_value = "process"
            else:
                runtime_bin = runtime_cfg.get("runtime_bin")
                if not runtime_bin and not (shutil.which("docker") or shutil.which("podman")):
                    logger.warning("Container backend selected without runtime; falling back to process")
                    backend_value = "process"

        return SandboxRuntimeConfig(
            backend=backend_value,
            image=str(image) if image else None,
            command=command if isinstance(command, list) else None,
            env=env,
            mounts=mounts,
            network_mode=str(runtime_cfg.get("network_mode", "none")),
            workdir=runtime_cfg.get("workdir"),
            cpu_limit=runtime_cfg.get("cpu_limit"),
            memory_mb=runtime_cfg.get("memory_mb"),
            runtime_bin=runtime_cfg.get("runtime_bin"),
            name_prefix=str(runtime_cfg.get("name_prefix", "cyntra-workbench")),
        )

    async def _run_headless(
        self,
        ctx: ExecutionContext,
        sandbox_path: Path,
        runtime_config: SandboxRuntimeConfig,
    ) -> int:
        command = runtime_config.command
        if not command:
            entrypoint = ctx.manifest.task.entrypoint if ctx.manifest else None
            if entrypoint:
                command = [entrypoint, *(ctx.manifest.task.entrypoint_args or [])]
        if not command:
            raise RuntimeError("No headless command provided for workbench run")

        if runtime_config.backend == "container":
            runtime_bin = runtime_config.runtime_bin or shutil.which("docker") or shutil.which("podman")
            if not runtime_bin:
                raise RuntimeError("No container runtime available for workbench")
            run_cmd = [runtime_bin, "run", "--rm"]
            if runtime_config.network_mode == "none":
                run_cmd.extend(["--network", "none"])
            workdir = runtime_config.workdir or "/workspace"
            run_cmd.extend(["-w", workdir])
            run_cmd.extend(["-v", f"{sandbox_path}:{workdir}:rw"])
            for key, value in runtime_config.env.items():
                run_cmd.extend(["-e", f"{key}={value}"])
            if runtime_config.image:
                run_cmd.append(runtime_config.image)
            else:
                raise RuntimeError("Container image is required for headless workbench")
            run_cmd.extend(command)
            process = await asyncio.create_subprocess_exec(
                *run_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            env = os.environ.copy()
            env.update(runtime_config.env)
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=str(sandbox_path),
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        stdout, stderr = await process.communicate()
        (sandbox_path / "workbench_stdout.log").write_text(stdout.decode())
        (sandbox_path / "workbench_stderr.log").write_text(stderr.decode())
        return process.returncode or 0

    async def _run_workbench_score(
        self,
        ctx: ExecutionContext,
        sandbox_path: Path,
    ) -> Path | None:
        """Run workbench score gate if inputs exist."""
        if not (sandbox_path / "challenge_spec.json").exists():
            return None
        if not (sandbox_path / "submission.json").exists():
            return None

        try:
            from cyntra.core.gates.workbench_score import main as score_main
            import sys

            orig_argv = sys.argv
            try:
                sys.argv = [
                    "workbench_score",
                    str(sandbox_path),
                    "--output",
                    str(sandbox_path / "workbench_score.json"),
                ]
                score_main()
            finally:
                sys.argv = orig_argv

            return sandbox_path / "workbench_score.json"
        except Exception as exc:
            logger.warning("Failed to run workbench score gate: %s", exc)
            return None

    def _write_proof(
        self,
        ctx: ExecutionContext,
        sandbox_path: Path,
        status: str,
        score_path: Path | None,
    ) -> Path | None:
        if ctx.metadata.get("write_run_artifacts") is False:
            return None

        score_data: dict[str, Any] = {}
        if score_path and score_path.exists():
            try:
                score_data = json.loads(score_path.read_text())
            except json.JSONDecodeError:
                score_data = {}

        verdict = {
            "passed": score_data.get("passed", status == "success"),
            "gate_id": score_data.get("gate_id", "workbench-score"),
            "scores": {"overall": score_data.get("score")},
            "threshold": score_data.get("thresholds", {}).get("overall_threshold"),
        }
        verification = self._build_gate_verification(status, score_data, verdict)

        proof = {
            "schema_version": "1.0",
            "run_id": ctx.run_id,
            "provider": self.name,
            "status": status,
            "verdict": verdict,
            "verification": verification,
            "artifacts": {
                "challenge_spec": "challenge_spec.json",
                "submission": "submission.json",
                "workbench_score": score_path.name if score_path else None,
            },
            "completed_at": datetime.utcnow().isoformat() + "Z",
        }
        path = sandbox_path / "proof.json"
        path.write_text(json.dumps(proof, indent=2))
        if verification.get("gates"):
            emit_gates_event(
                logs_dir=resolve_logs_dir(self.workbench_root),
                workcell_id=ctx.run_id,
                passed=bool(verification.get("all_passed", False)),
                results=verification.get("gates", {}),
                summary=verification.get("gate_summary"),
            )
        return path


    def _build_gate_verification(
        self,
        status: str,
        score_data: dict[str, Any],
        verdict: dict[str, Any],
    ) -> dict[str, Any]:
        gate_name = score_data.get("gate_id") or verdict.get("gate_id") or "workbench-score"
        passed = bool(score_data.get("passed", verdict.get("passed", status == "success")))
        timing = score_data.get("timing") if isinstance(score_data.get("timing"), dict) else {}
        duration_ms = int(timing.get("duration_ms") or 0)
        errors = score_data.get("errors")
        failure_summary = None
        if not passed:
            if isinstance(errors, list) and errors:
                failure_summary = "; ".join(str(e) for e in errors[:3])
            else:
                failure_summary = score_data.get("verdict") or "gate_failed"

        raw_result: dict[str, Any] = {
            "passed": passed,
            "duration_ms": duration_ms,
            "blocking": True,
            "gate_type": "provider",
            "score": score_data.get("score"),
            "threshold": verdict.get("threshold"),
            "metrics": score_data.get("metrics"),
            "verdict": score_data.get("verdict") or verdict.get("verdict"),
            "failure_summary": failure_summary,
        }

        if not score_data:
            raw_result.update(
                {
                    "passed": status == "success",
                    "skipped": True,
                    "reason": "score_missing",
                }
            )

        normalized = normalize_gate_result(
            name=str(gate_name),
            result=raw_result,
            gate_type="provider",
        )
        verification = build_verification_payload({str(gate_name): normalized})
        if status != "success":
            blocking = verification.get("blocking_failures")
            if not isinstance(blocking, list):
                blocking = []
            status_marker = f"status:{status}"
            if status_marker not in blocking:
                blocking.append(status_marker)
            verification["blocking_failures"] = blocking
            verification["all_passed"] = False
        return verification
