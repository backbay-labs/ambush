"""
Local Provider - Execute toolchains on the local machine.

The local provider runs toolchains directly on the host machine,
optionally within git worktree isolation (workcells).

Integrates with aegis-daemon for security policy enforcement.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import subprocess
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyntra.core.providers.base import (
    ExecutionContext,
    ExecutionResult,
    SandboxProvider,
)
from cyntra.core.providers.capabilities import ExecutionCapabilities
from cyntra.core.gates.results import (
    build_verification_payload,
    emit_gates_event,
    normalize_gate_result,
    resolve_logs_dir,
)

if TYPE_CHECKING:
    from cyntra.core.manifests.schema import ToolchainManifest

logger = logging.getLogger(__name__)

# Aegis client for security checks (lazy import)
_aegis_client = None


def _get_aegis_client():
    """Get or create the Aegis client."""
    global _aegis_client
    if _aegis_client is None:
        try:
            from cyntra.trust.aegis.client import AegisClient
            _aegis_client = AegisClient(fallback_to_local=True)
        except ImportError:
            logger.warning("Aegis client not available, security checks disabled")
            _aegis_client = False  # Sentinel to avoid repeated attempts
    return _aegis_client if _aegis_client else None


class LocalProvider(SandboxProvider):
    """
    Local execution provider.

    Executes toolchains directly on the local machine. Supports:
    - Direct execution (no isolation)
    - Workcell isolation (git worktree)
    - Process-level resource limits
    - Filesystem sandboxing via working directory

    This is the default provider for development and simple deployments.
    """

    name = "local"
    capabilities = ExecutionCapabilities(
        gpu=False,  # Could be True if GPU available
        isolation_level="process",
        max_runtime=timedelta(hours=24),
        max_memory_gb=None,  # No limit
        persistent_volume=True,
        network_egress=True,
        max_concurrent=os.cpu_count() or 4,
    )

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the local provider.

        Args:
            config: Provider configuration
                - working_dir: Base working directory
                - use_workcells: Enable workcell isolation
                - workcell_base: Base directory for workcells
                - max_concurrent: Max concurrent executions
                - env_vars: Additional environment variables
        """
        self.config = config or {}
        self.working_dir = Path(self.config.get("working_dir", ".")).resolve()
        self.use_workcells = self.config.get("use_workcells", False)
        self.workcell_base = Path(self.config.get("workcell_base", ".workcells"))
        self.max_concurrent = self.config.get("max_concurrent", os.cpu_count() or 4)
        self.extra_env = self.config.get("env_vars", {})

        # Active processes for cancellation
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._sandboxes: dict[str, Path] = {}

    async def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        """
        Execute a toolchain locally.

        Args:
            ctx: Execution context with manifest and secrets

        Returns:
            Execution result
        """
        start_time = datetime.utcnow()
        manifest = ctx.manifest
        run_id = ctx.run_id
        ctx.ensure_shields()
        
        # Create Aegis run with policy from manifest (kernel-level enforcement)
        aegis = _get_aegis_client()
        execution_handle = None
        if aegis and aegis.is_daemon_available():
            try:
                from cyntra.trust.aegis.client import SecurityPolicy, ExecutionMode
                
                # Extract security policy from manifest
                policy = SecurityPolicy.from_manifest(manifest)
                
                # Determine working directory for the run
                work_dir = ctx.working_dir or self.working_dir

                # MicroVM-first switch:
                # - Provider config: aegis_mode: "local" | "microvm"
                # - Env override: CYNTRA_AEGIS_MODE=local|microvm
                aegis_mode = os.environ.get(
                    "CYNTRA_AEGIS_MODE",
                    str(self.config.get("aegis_mode", "local")),
                ).lower()
                mode = ExecutionMode.MICROVM if aegis_mode in {"microvm", "micro_vm", "micro-vm"} else ExecutionMode.LOCAL
                
                # Create run with policy - returns execution handle with sandboxing config
                execution_handle = await aegis.create_run(
                    run_id=run_id,
                    policy=policy,
                    mode=mode,
                    workdir=str(work_dir),
                )
                logger.debug(f"Created Aegis run {run_id} with scope {execution_handle.scope_name}")
            except Exception as e:
                logger.warning(f"Failed to create Aegis run (continuing without enforcement): {e}")
                # Fallback to legacy start_run for telemetry only
                try:
                    await aegis.start_run(run_id)
                except Exception as e2:
                    logger.debug(f"Failed to start Aegis run: {e2}")

        # Determine working directory
        if self.use_workcells:
            sandbox_id = await self.create_sandbox(ctx)
            work_dir = self._sandboxes.get(sandbox_id, self.working_dir)
        else:
            work_dir = ctx.working_dir or self.working_dir

        # Build environment
        env = os.environ.copy()
        env.update(self.extra_env)
        env.update(manifest.runtime.env_vars)

        # Inject secrets
        for secret_name in manifest.runtime.secrets:
            if secret_name in ctx.secrets:
                env[secret_name] = ctx.secrets[secret_name]
        run_dir = (work_dir / ".cyntra" / "runs" / run_id).resolve()
        env.setdefault("CYNTRA_RUN_ID", run_id)
        env.setdefault("CYNTRA_RUN_DIR", str(run_dir))

        # Emit step started event
        if ctx.ledger_writer or ctx.shield_manager:
            from cyntra.trust.ledger.events import StepStartedEvent
            await ctx.emit_event(StepStartedEvent(
                run_id=run_id,
                step_id=ctx.step_id,
                provider=self.name,
                manifest_id=manifest.manifest_id,
            ))

        try:
            # Execute based on job type
            if manifest.task.entrypoint:
                # Custom entrypoint
                command = manifest.task.entrypoint
                args = manifest.task.entrypoint_args
            else:
                # Default: run the toolchain adapter
                command = self._get_toolchain_command(manifest)
                args = []

            if ctx.ledger_writer or ctx.shield_manager:
                from cyntra.trust.ledger.events import EventType, LedgerEvent
                command_str = " ".join([command] + args)
                await ctx.emit_event(LedgerEvent(
                    type=EventType.BASH_COMMAND,
                    run_id=run_id,
                    step_id=ctx.step_id,
                    data={"command": command_str},
                    provider=self.name,
                ))

            # Run the command (with systemd sandboxing if execution_handle available)
            result = await self._run_command(
                command=command,
                args=args,
                cwd=work_dir,
                env=env,
                timeout=manifest.runtime.timeout,
                run_id=run_id,
                execution_handle=execution_handle,
            )

            # Run quality gates if execution succeeded
            gate_results = []
            if result["exit_code"] == 0:
                gate_results = await self._run_gates(
                    manifest=manifest,
                    cwd=work_dir,
                    env=env,
                    run_id=run_id,
                )

            verification = self._build_gate_verification(gate_results)
            all_gates_passed = bool(verification.get("all_passed", False))
            if result["exit_code"] != 0:
                status = "failed"
            elif not all_gates_passed:
                status = "failed"  # gate_failed maps to failed
            else:
                status = "success"

            # Build proof artifact
            proof = self._build_proof(manifest, result, gate_results, verification, work_dir)
            if gate_results:
                emit_gates_event(
                    logs_dir=resolve_logs_dir(work_dir),
                    workcell_id=run_id,
                    passed=all_gates_passed,
                    results=verification.get("gates", {}),
                    summary=verification.get("gate_summary"),
                )
            
            # Complete Aegis run and get ledger root
            aegis_ledger_root = None
            aegis_attestation = None
            if aegis and aegis.is_daemon_available():
                try:
                    ledger_root = await aegis.complete_run(run_id, status)
                    aegis_ledger_root = ledger_root.root_hash
                    proof["aegis_ledger_root"] = aegis_ledger_root
                    proof["aegis_violation_count"] = ledger_root.violation_count
                    
                    # Get system attestation for provenance
                    attestation = await aegis.get_system_attestation()
                    aegis_attestation = {
                        "nixos_system_hash": attestation.nixos_system_hash,
                        "kernel_version": attestation.kernel_version,
                        "daemon_version": attestation.aegis_daemon_version,
                        "is_nixos": attestation.is_nixos(),
                    }
                    proof["system_attestation"] = aegis_attestation
                    
                    # Close run to clean up resources (proxy mappings, scope tracking)
                    if execution_handle:
                        await aegis.close_run(run_id)
                        proof["execution_scope"] = execution_handle.scope_name
                except Exception as e:
                    logger.debug(f"Failed to complete Aegis run: {e}")

            return ExecutionResult(
                status=status,
                exit_code=result["exit_code"],
                artifacts=self._collect_artifacts(work_dir, ctx.artifact_store),
                stdout=result["stdout"],
                stderr=result["stderr"],
                metrics={
                    "duration_ms": (datetime.utcnow() - start_time).total_seconds() * 1000,
                    "gates_run": len(gate_results),
                    "gates_passed": sum(1 for g in gate_results if g["passed"]),
                },
                proof=proof,
                started_at=start_time,
                completed_at=datetime.utcnow(),
            )

        except TimeoutError:
            # Close run on timeout
            if aegis and aegis.is_daemon_available() and execution_handle:
                try:
                    await aegis.close_run(run_id)
                except Exception:
                    pass
            return ExecutionResult(
                status="timeout",
                exit_code=-1,
                error_message=f"Execution timed out after {manifest.runtime.timeout}",
                metrics={"duration_ms": manifest.runtime.timeout.total_seconds() * 1000},
            )

        except asyncio.CancelledError:
            # Close run on cancellation
            if aegis and aegis.is_daemon_available() and execution_handle:
                try:
                    await aegis.close_run(run_id)
                except Exception:
                    pass
            return ExecutionResult(
                status="cancelled",
                exit_code=-2,
                error_message="Execution was cancelled",
            )

        except Exception as e:
            logger.exception(f"Local execution failed: {e}")
            # Close run on error
            if aegis and aegis.is_daemon_available() and execution_handle:
                try:
                    await aegis.close_run(run_id)
                except Exception:
                    pass
            return ExecutionResult(
                status="error",
                exit_code=-3,
                error_type=type(e).__name__,
                error_message=str(e),
            )

        finally:
            # Cleanup process tracking
            self._processes.pop(run_id, None)

            # Cleanup workcell if ephemeral
            if self.use_workcells and not self.config.get("persist_workcells"):
                await self.destroy_sandbox(run_id)

    async def _run_command(
        self,
        command: str,
        args: list[str],
        cwd: Path,
        env: dict[str, str],
        timeout: timedelta,
        run_id: str,
        execution_handle: Any | None = None,
    ) -> dict[str, Any]:
        """
        Run a command and capture output.
        
        If execution_handle is provided (from aegis.create_run), wraps the
        command with systemd-run for kernel-level sandboxing.
        """
        full_command = [command] + args if args else command
        
        # Check with Aegis before execution
        aegis = _get_aegis_client()
        if aegis and aegis.is_daemon_available():
            try:
                from cyntra.trust.aegis.client import CommandEventData, EventType, ExecutionEvent
                
                # Build command string for checking
                cmd_str = full_command if isinstance(full_command, str) else " ".join(full_command)
                event = ExecutionEvent(
                    event_type=EventType.COMMAND_EXEC,
                    data=CommandEventData(
                        command=command,
                        args=args,
                        working_dir=str(cwd),
                    ),
                    run_id=run_id,
                )
                
                check_result = await aegis.check_execution(event)
                
                if not check_result.allowed:
                    # Command blocked by policy
                    denied = [r for r in check_result.results if r.status == "deny"]
                    reasons = [r.reason or f"Blocked by {r.guard}" for r in denied]
                    logger.warning(f"Command blocked by Aegis: {', '.join(reasons)}")
                    
                    return {
                        "exit_code": 126,  # Permission denied
                        "stdout": "",
                        "stderr": f"Aegis policy violation: {', '.join(reasons)}",
                        "blocked_by_aegis": True,
                    }
                    
            except Exception as e:
                logger.debug(f"Aegis check failed (continuing): {e}")

        # Build final command list
        if isinstance(full_command, str):
            # For shell commands, wrap differently
            cmd_list = ["sh", "-c", full_command]
        else:
            cmd_list = list(full_command)
        
        # Apply execution_handle sandboxing (systemd-run prefix)
        if execution_handle and execution_handle.exec_prefix:
            # Wrap with systemd-run for kernel-level enforcement
            cmd_list = execution_handle.wrap_command(cmd_list)
            logger.debug(f"Wrapped command with sandbox: {' '.join(cmd_list[:5])}...")
            
            # Merge execution handle env vars
            if execution_handle.env:
                env = {**env, **execution_handle.env}

        # Execute the command
        if isinstance(full_command, str) and not (execution_handle and execution_handle.exec_prefix):
            # Shell command without sandbox wrapper
            process = await asyncio.create_subprocess_shell(
                full_command,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            # Direct execution (or sandboxed)
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                cwd=cwd,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        self._processes[run_id] = process

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout.total_seconds(),
            )
            
            result = {
                "exit_code": process.returncode or 0,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
            }
            
            # Record event to Aegis ledger
            if aegis and aegis.is_daemon_available():
                try:
                    from cyntra.trust.aegis.client import CommandEventData, EventType, ExecutionEvent
                    
                    event = ExecutionEvent(
                        event_type=EventType.COMMAND_EXEC,
                        data=CommandEventData(
                            command=command,
                            args=args,
                            working_dir=str(cwd),
                        ),
                        run_id=run_id,
                    )
                    await aegis.record_event(event)
                except Exception as e:
                    logger.debug(f"Failed to record event to Aegis: {e}")

            return result

        except TimeoutError:
            process.kill()
            await process.wait()
            raise

    async def _run_gates(
        self,
        manifest: ToolchainManifest,
        cwd: Path,
        env: dict[str, str],
        run_id: str,
    ) -> list[dict[str, Any]]:
        """Run quality gates."""
        results = []

        for gate in manifest.gates:
            gate_cwd = Path(gate.working_dir) if gate.working_dir else cwd
            gate_env = {**env, **gate.env_vars}

            try:
                started = datetime.utcnow()
                result = await self._run_command(
                    command=gate.command,
                    args=[],
                    cwd=gate_cwd,
                    env=gate_env,
                    timeout=gate.timeout,
                    run_id=f"{run_id}:gate:{gate.name}",
                )
                duration_ms = int((datetime.utcnow() - started).total_seconds() * 1000)

                passed = result["exit_code"] == gate.expected_exit_code

                # Check patterns if specified
                if passed and gate.fail_pattern:
                    import re
                    if re.search(gate.fail_pattern, result["stdout"] + result["stderr"]):
                        passed = False

                if passed and gate.pass_pattern:
                    import re
                    if not re.search(gate.pass_pattern, result["stdout"] + result["stderr"]):
                        passed = False

                results.append({
                    "name": gate.name,
                    "passed": passed,
                    "exit_code": result["exit_code"],
                    "duration_ms": duration_ms,
                    "blocking": gate.blocking,
                    "stdout": result["stdout"][:10000],  # Truncate
                    "stderr": result["stderr"][:10000],
                })

                # Stop on blocking gate failure
                if not passed and gate.blocking:
                    break

            except TimeoutError:
                results.append({
                    "name": gate.name,
                    "passed": False,
                    "exit_code": -1,
                    "blocking": gate.blocking,
                    "duration_ms": int(gate.timeout.total_seconds() * 1000),
                    "error": f"Gate timed out after {gate.timeout}",
                })

                if gate.blocking:
                    break

            except Exception as e:
                results.append({
                    "name": gate.name,
                    "passed": False,
                    "exit_code": -1,
                    "blocking": gate.blocking,
                    "duration_ms": 0,
                    "error": str(e),
                })

                if gate.blocking:
                    break

        return results

    def _get_toolchain_command(self, manifest: ToolchainManifest) -> str:
        """Get the command to run for a toolchain."""
        toolchain = manifest.toolchain

        # Map toolchain names to commands
        toolchain_commands = {
            "claude": "claude-code",
            "codex": "codex",
            "opencode": "opencode",
            "crush": "crush",
            "blender-agent": "blender --background --python",
        }

        return toolchain_commands.get(toolchain, toolchain)

    def _build_proof(
        self,
        manifest: ToolchainManifest,
        result: dict[str, Any],
        gate_results: list[dict[str, Any]],
        verification: dict[str, Any],
        work_dir: Path,
    ) -> dict[str, Any]:
        """Build execution proof."""
        return {
            "manifest_id": manifest.manifest_id,
            "provider": self.name,
            "exit_code": result["exit_code"],
            "gates": gate_results,
            "verification": verification,
            "security_policy": manifest.security.to_dict() if manifest.security else None,
            "working_dir": str(work_dir),
            "completed_at": datetime.utcnow().isoformat(),
        }

    def _build_gate_verification(self, gate_results: list[dict[str, Any]]) -> dict[str, Any]:
        normalized: dict[str, dict[str, Any]] = {}
        for idx, gate in enumerate(gate_results):
            name = gate.get("name") if isinstance(gate, dict) else None
            gate_name = str(name) if name else f"gate-{idx}"
            normalized[gate_name] = normalize_gate_result(
                name=gate_name,
                result=gate,
                gate_type="code",
            )
        return build_verification_payload(normalized)

    def _collect_artifacts(
        self,
        work_dir: Path,
        artifact_store: Path | None,
    ) -> dict[str, str]:
        """Collect output artifacts."""
        artifacts = {}

        # Look for standard artifact patterns
        artifact_patterns = [
            "*.patch",
            "*.diff",
            "proof.json",
            "output/*.json",
            "output/*.glb",
        ]

        for pattern in artifact_patterns:
            for path in work_dir.glob(pattern):
                if path.is_file():
                    artifacts[path.name] = str(path)

        return artifacts

    async def stream_logs(self, ctx: ExecutionContext) -> AsyncIterator[str]:
        """Stream logs from a running execution."""
        # For local execution, we'd need to capture logs differently
        # This is a placeholder that yields nothing
        return
        yield  # Make this a generator

    async def cancel(self, ctx: ExecutionContext) -> bool:
        """Cancel a running execution."""
        process = self._processes.get(ctx.run_id)
        if process:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except TimeoutError:
                process.kill()
            return True
        return False

    async def health_check(self) -> bool:
        """Check if local execution is available."""
        return True

    # SandboxProvider methods

    async def create_sandbox(self, ctx: ExecutionContext) -> str:
        """Create a workcell for isolated execution."""
        sandbox_id = ctx.run_id
        manifest = ctx.manifest
        workcell_path = self.workcell_base / sandbox_id
        workcell_path.mkdir(parents=True, exist_ok=True)

        # If repo_url specified, clone or create worktree
        if manifest and manifest.task.repo_url:
            # Check if we're in a git repo
            try:
                result = subprocess.run(
                    ["git", "rev-parse", "--git-dir"],
                    cwd=self.working_dir,
                    capture_output=True,
                    text=True,
                )

                if result.returncode == 0:
                    # Create worktree
                    branch = manifest.task.branch
                    subprocess.run(
                        ["git", "worktree", "add", "-B", f"workcell-{sandbox_id}", str(workcell_path), branch],
                        cwd=self.working_dir,
                        check=True,
                        capture_output=True,
                    )
                    logger.info(f"Created worktree at {workcell_path}")
                else:
                    # Clone fresh
                    subprocess.run(
                        ["git", "clone", "--branch", manifest.task.branch, manifest.task.repo_url, str(workcell_path)],
                        check=True,
                        capture_output=True,
                    )
                    logger.info(f"Cloned repo to {workcell_path}")

            except subprocess.CalledProcessError as e:
                logger.warning(f"Git operation failed: {e}")
                # Continue with empty directory

        self._sandboxes[sandbox_id] = workcell_path
        return sandbox_id

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """Destroy a workcell."""
        workcell_path = self._sandboxes.pop(sandbox_id, None)
        if workcell_path and workcell_path.exists():
            # Remove worktree if it is one
            with contextlib.suppress(Exception):
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(workcell_path)],
                    capture_output=True,
                )

            # Fallback: remove directory
            import shutil
            try:
                shutil.rmtree(workcell_path)
            except Exception as e:
                logger.warning(f"Failed to remove workcell: {e}")

    async def create_snapshot(
        self,
        sandbox_id: str,
        snapshot_id: str,
    ) -> str:
        """Create a git commit snapshot."""
        workcell_path = self._sandboxes.get(sandbox_id)
        if not workcell_path:
            raise ValueError(f"Sandbox {sandbox_id} not found")

        try:
            # Stage all changes
            subprocess.run(
                ["git", "add", "-A"],
                cwd=workcell_path,
                check=True,
                capture_output=True,
            )

            # Create commit
            subprocess.run(
                ["git", "commit", "-m", f"Snapshot {snapshot_id}", "--allow-empty"],
                cwd=workcell_path,
                check=True,
                capture_output=True,
            )

            # Get commit hash
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=workcell_path,
                check=True,
                capture_output=True,
                text=True,
            )

            return result.stdout.strip()

        except subprocess.CalledProcessError as e:
            logger.warning(f"Snapshot creation failed: {e}")
            return snapshot_id

    async def restore_snapshot(
        self,
        sandbox_id: str,
        snapshot_id: str,
    ) -> None:
        """Restore from a git commit."""
        workcell_path = self._sandboxes.get(sandbox_id)
        if not workcell_path:
            raise ValueError(f"Sandbox {sandbox_id} not found")

        try:
            subprocess.run(
                ["git", "checkout", snapshot_id],
                cwd=workcell_path,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Snapshot restore failed: {e}")
            raise

    async def install_packages(
        self,
        sandbox_id: str,
        packages: list[str],
        package_manager: str = "pip",
    ) -> None:
        """Install packages in the workcell."""
        workcell_path = self._sandboxes.get(sandbox_id)
        if not workcell_path:
            raise ValueError(f"Sandbox {sandbox_id} not found")

        if package_manager == "pip":
            cmd = ["pip", "install"] + packages
        elif package_manager == "npm":
            cmd = ["npm", "install"] + packages
        elif package_manager == "bun":
            cmd = ["bun", "add"] + packages
        else:
            raise ValueError(f"Unknown package manager: {package_manager}")

        try:
            subprocess.run(
                cmd,
                cwd=workcell_path,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Package installation failed: {e}")
            raise
