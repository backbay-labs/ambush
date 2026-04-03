"""
E2B Provider - Execute toolchains in E2B cloud sandboxes.

E2B provides fast-starting (~150ms) isolated VM environments with
full Linux capabilities, filesystem persistence, and network access.

Requires: e2b package
API Key: E2B_API_KEY environment variable
"""

from __future__ import annotations

import asyncio
import logging
import os
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

# Check if e2b is available
try:
    from e2b import Sandbox
    E2B_AVAILABLE = True
except ImportError:
    E2B_AVAILABLE = False
    Sandbox = None


class E2BProvider(SandboxProvider):
    """
    E2B sandbox execution provider.

    Executes toolchains in isolated E2B VM sandboxes. Features:
    - ~150ms VM startup time
    - Full Linux environment
    - Persistent filesystem within session
    - Network access
    - Python/Node/shell execution

    Requires the e2b package and E2B_API_KEY environment variable.
    """

    name = "e2b"
    # E2B sandboxes use /home/user as home; all workspace paths are relative to this.
    WORKSPACE_BASE = "/home/user/workspace"
    capabilities = ExecutionCapabilities(
        gpu=False,  # E2B sandboxes don't have GPU
        isolation_level="vm",
        max_runtime=timedelta(hours=1),  # Default max session
        max_memory_gb=4,  # Depends on plan
        persistent_volume=True,  # Within session
        network_egress=True,
        max_concurrent=10,  # Rate limited
        filesystem_snapshot=True,
        code_interpreter=True,
    )

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the E2B provider.

        Args:
            config: Provider configuration
                - api_key: E2B API key (or use E2B_API_KEY env var)
                - template: Sandbox template ID
                - timeout: Default sandbox timeout in seconds
                - max_sandboxes: Maximum concurrent sandboxes
        """
        if not E2B_AVAILABLE:
            raise ImportError(
                "e2b package required for E2BProvider. "
                "Install with: pip install e2b-code-interpreter"
            )

        self.config = config or {}
        self.api_key = self.config.get("api_key") or os.environ.get("E2B_API_KEY")
        self.template = self.config.get("template", "base")
        self.default_timeout = self.config.get("timeout", 300)  # 5 minutes
        self.max_sandboxes = self.config.get("max_sandboxes", 10)

        # Active sandboxes
        self._sandboxes: dict[str, Any] = {}  # sandbox_id -> Sandbox instance
        self._sandbox_envs: dict[str, dict[str, str]] = {}  # sandbox_id -> env vars
        self._semaphore = asyncio.Semaphore(self.max_sandboxes)

    async def execute(
        self,
        manifest: ToolchainManifest,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """
        Execute a toolchain in an E2B sandbox.

        Args:
            manifest: Toolchain manifest
            context: Execution context

        Returns:
            Execution result
        """
        start_time = datetime.utcnow()
        run_id = context.run_id
        sandbox = None
        context.ensure_shields()

        async with self._semaphore:
            try:
                # Create sandbox
                sandbox = await self._create_sandbox(run_id, manifest)

                # Emit step started event
                if context.ledger_writer or context.shield_manager:
                    from cyntra.trust.ledger.events import StepStartedEvent
                    await context.emit_event(StepStartedEvent(
                        run_id=run_id,
                        step_id=context.step_id,
                        provider=self.name,
                        manifest_id=manifest.manifest_id,
                    ))

                # Set up environment
                await self._setup_environment(sandbox, manifest, context)

                # Clone repository if specified
                if manifest.task.repo_url:
                    await self._clone_repo(sandbox, manifest, run_id)

                # Execute the toolchain
                result = await self._execute_toolchain(sandbox, manifest, context)

                # Run quality gates
                gate_results = []
                if result["exit_code"] == 0:
                    gate_results = await self._run_gates(sandbox, manifest, run_id)

                # Collect artifacts
                artifacts = await self._collect_artifacts(sandbox, context.artifact_store, run_id)

                verification = self._build_gate_verification(gate_results)
                all_gates_passed = bool(verification.get("all_passed", False))
                if result["exit_code"] != 0:
                    status = "failed"
                elif not all_gates_passed:
                    status = "gate_failed"
                else:
                    status = "completed"

                # Build proof
                proof = {
                    "manifest_id": manifest.manifest_id,
                    "provider": self.name,
                    "sandbox_id": run_id,
                    "exit_code": result["exit_code"],
                    "gates": gate_results,
                    "verification": verification,
                    "completed_at": datetime.utcnow().isoformat(),
                }
                if gate_results:
                    emit_gates_event(
                        logs_dir=resolve_logs_dir(Path.cwd()),
                        workcell_id=run_id,
                        passed=all_gates_passed,
                        results=verification.get("gates", {}),
                        summary=verification.get("gate_summary"),
                    )

                return ExecutionResult(
                    status=status,
                    exit_code=result["exit_code"],
                    artifacts=artifacts,
                    logs={
                        "stdout": result.get("stdout", ""),
                        "stderr": result.get("stderr", ""),
                    },
                    metrics={
                        "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
                        "gates_run": len(gate_results),
                        "gates_passed": sum(1 for g in gate_results if g["passed"]),
                    },
                    proof=proof,
                )

            except TimeoutError:
                return ExecutionResult(
                    status="timeout",
                    exit_code=-1,
                    logs={"error": f"Execution timed out after {manifest.runtime.timeout}"},
                    metrics={"duration_seconds": manifest.runtime.timeout.total_seconds()},
                )

            except asyncio.CancelledError:
                return ExecutionResult(
                    status="cancelled",
                    exit_code=-2,
                    logs={"error": "Execution was cancelled"},
                )

            except Exception as e:
                logger.exception(f"E2B execution failed: {e}")
                return ExecutionResult(
                    status="error",
                    exit_code=-3,
                    logs={"error": str(e)},
                )

            finally:
                # Cleanup sandbox
                if sandbox and not self.config.get("persist_sandboxes"):
                    await self._destroy_sandbox(run_id)

    async def _create_sandbox(
        self,
        sandbox_id: str,
        manifest: ToolchainManifest,
    ) -> Any:
        """Create an E2B sandbox."""
        # Run sandbox creation in thread pool (e2b is sync)
        loop = asyncio.get_event_loop()

        def create():
            # Use Sandbox.create() (constructor is deprecated)
            return Sandbox.create(
                template=self.template if self.template != "base" else None,
                timeout=int(manifest.runtime.timeout.total_seconds()),
                api_key=self.api_key,
            )

        sandbox = await loop.run_in_executor(None, create)
        self._sandboxes[sandbox_id] = sandbox
        logger.info(f"Created E2B sandbox: {sandbox_id}")
        return sandbox

    async def _destroy_sandbox(self, sandbox_id: str) -> None:
        """Destroy an E2B sandbox."""
        sandbox = self._sandboxes.pop(sandbox_id, None)
        self._sandbox_envs.pop(sandbox_id, None)
        if sandbox:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, sandbox.kill)
            logger.info(f"Destroyed E2B sandbox: {sandbox_id}")

    async def _setup_environment(
        self,
        sandbox: Any,
        manifest: ToolchainManifest,
        context: ExecutionContext,
    ) -> None:
        """Set up environment variables in sandbox."""
        loop = asyncio.get_event_loop()

        # Create workspace directory (E2B sandboxes use /home/user as home)
        working_dir = manifest.runtime.working_dir
        if working_dir and working_dir.startswith("/workspace"):
            # Remap /workspace to /home/user/workspace for E2B compatibility
            working_dir = working_dir.replace("/workspace", self.WORKSPACE_BASE, 1)
        else:
            working_dir = working_dir or self.WORKSPACE_BASE

        await loop.run_in_executor(
            None,
            lambda wd=working_dir: sandbox.commands.run(f"mkdir -p {wd}")
        )
        # Store the remapped working_dir for later use
        manifest.runtime.working_dir = working_dir

        # Combine env vars
        env_vars = {**manifest.runtime.env_vars}

        # Add secrets
        for secret_name in manifest.runtime.secrets:
            if secret_name in context.secrets:
                env_vars[secret_name] = context.secrets[secret_name]
        run_dir = Path(manifest.runtime.working_dir) / ".cyntra" / "runs" / context.run_id
        env_vars.setdefault("CYNTRA_RUN_ID", context.run_id)
        env_vars.setdefault("CYNTRA_RUN_DIR", str(run_dir))

        # Inject CLI credentials (Claude Keychain, Codex auth.json) into sandbox
        try:
            from cyntra.core.providers.e2b.auth import (
                build_credential_bundle,
                inject_credentials_into_sandbox,
            )

            toolchain_name = getattr(manifest, "toolchain", None)
            toolchains = [toolchain_name] if toolchain_name else None
            bundle = build_credential_bundle(toolchains=toolchains)

            # Merge credential env vars
            env_vars.update(bundle.env_vars)

            # Write credential files (e.g., ~/.codex/auth.json) into sandbox
            if bundle.files:
                await inject_credentials_into_sandbox(sandbox, bundle, context.run_id)

        except Exception as e:
            logger.warning("Failed to inject CLI credentials: %s", e)

        # Store env vars so they can be passed via envs= to all subsequent
        # sandbox.commands.run() calls (export in a subprocess is ephemeral).
        self._sandbox_envs[context.run_id] = env_vars

    def _run_sandbox_cmd(
        self,
        sandbox: Any,
        cmd: str,
        run_id: str | None = None,
    ) -> Any:
        """Run a command in the sandbox with stored environment variables.

        This is a synchronous helper meant to be called inside
        ``loop.run_in_executor``.  It passes the accumulated env vars
        via the ``envs`` parameter so they persist across calls.
        """
        envs = self._sandbox_envs.get(run_id, {}) if run_id else {}
        return sandbox.commands.run(cmd, envs=envs)

    async def _clone_repo(
        self, sandbox: Any, manifest: ToolchainManifest, run_id: str,
    ) -> None:
        """Clone repository in sandbox."""
        loop = asyncio.get_event_loop()

        repo_url = manifest.task.repo_url
        branch = manifest.task.branch
        working_dir = manifest.runtime.working_dir or self.WORKSPACE_BASE

        cmd = f"git clone --depth 1 --branch {branch} {repo_url} {working_dir}"

        await loop.run_in_executor(
            None,
            lambda c=cmd: self._run_sandbox_cmd(sandbox, c, run_id)
        )

        # Checkout specific commit if specified
        if manifest.task.commit:
            await loop.run_in_executor(
                None,
                lambda wd=working_dir, c=manifest.task.commit: self._run_sandbox_cmd(
                    sandbox, f"cd {wd} && git checkout {c}", run_id
                )
            )

    async def _execute_toolchain(
        self,
        sandbox: Any,
        manifest: ToolchainManifest,
        context: ExecutionContext,
    ) -> dict[str, Any]:
        """Execute the toolchain command."""
        loop = asyncio.get_event_loop()

        # Determine command
        if manifest.task.entrypoint:
            cmd = manifest.task.entrypoint
            if manifest.task.entrypoint_args:
                cmd += " " + " ".join(manifest.task.entrypoint_args)
        else:
            cmd = self._get_toolchain_command(manifest)

        working_dir = manifest.runtime.working_dir

        # Execute with timeout
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: self._run_sandbox_cmd(
                        sandbox, f"cd {working_dir} && {cmd}", context.run_id
                    )
                ),
                timeout=manifest.runtime.timeout.total_seconds(),
            )

            return {
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }

        except TimeoutError:
            raise

    def _get_toolchain_command(self, manifest: ToolchainManifest) -> str:
        """Get command for toolchain."""
        toolchain = manifest.toolchain

        toolchain_commands = {
            "claude": "claude-code",
            "codex": "codex",
            "python": "python",
        }

        return toolchain_commands.get(toolchain, toolchain)

    async def _run_gates(
        self,
        sandbox: Any,
        manifest: ToolchainManifest,
        run_id: str,
    ) -> list[dict[str, Any]]:
        """Run quality gates in sandbox."""
        loop = asyncio.get_event_loop()
        results = []

        for gate in manifest.gates:
            working_dir = gate.working_dir or manifest.runtime.working_dir

            try:
                started = datetime.utcnow()
                # Bind loop variables to avoid closure issues
                cmd = f"cd {working_dir} && {gate.command}"
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda c=cmd: self._run_sandbox_cmd(sandbox, c, run_id)
                    ),
                    timeout=gate.timeout.total_seconds(),
                )
                duration_ms = int((datetime.utcnow() - started).total_seconds() * 1000)

                passed = result.exit_code == gate.expected_exit_code

                # Check patterns
                if passed and gate.fail_pattern:
                    import re
                    if re.search(gate.fail_pattern, result.stdout + result.stderr):
                        passed = False

                if passed and gate.pass_pattern:
                    import re
                    if not re.search(gate.pass_pattern, result.stdout + result.stderr):
                        passed = False

                results.append({
                    "name": gate.name,
                    "passed": passed,
                    "exit_code": result.exit_code,
                    "duration_ms": duration_ms,
                    "blocking": gate.blocking,
                    "stdout": result.stdout[:10000],
                    "stderr": result.stderr[:10000],
                })

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

    async def _collect_artifacts(
        self,
        sandbox: Any,
        artifact_store: Path | None,
        run_id: str,
    ) -> dict[str, str]:
        """Collect artifacts from sandbox."""
        loop = asyncio.get_event_loop()
        artifacts = {}
        output_dir = f"{self.WORKSPACE_BASE}/output"

        # List files in output directory
        try:
            result = await loop.run_in_executor(
                None,
                lambda: self._run_sandbox_cmd(
                    sandbox,
                    f"ls -la {output_dir} 2>/dev/null || echo 'No output dir'",
                    run_id,
                )
            )

            # For now, just record that artifacts exist
            # Full download would be done via sandbox.download_file()
            if "No output dir" not in result.stdout:
                artifacts["output_available"] = output_dir

        except Exception as e:
            logger.warning(f"Failed to collect artifacts: {e}")

        return artifacts

    async def stream_logs(self, run_id: str) -> AsyncIterator[str]:
        """Stream logs from sandbox."""
        sandbox = self._sandboxes.get(run_id)
        if not sandbox:
            return

        # E2B doesn't have native streaming, so this is a placeholder
        yield f"[E2B sandbox {run_id}] Log streaming not implemented"

    async def cancel(self, run_id: str) -> bool:
        """Cancel execution by destroying sandbox."""
        if run_id in self._sandboxes:
            await self._destroy_sandbox(run_id)
            return True
        return False

    async def health_check(self) -> bool:
        """Check if E2B is available."""
        if not self.api_key:
            return False

        try:
            # Create a minimal sandbox to test connectivity
            loop = asyncio.get_event_loop()

            def test():
                sandbox = Sandbox.create(timeout=30, api_key=self.api_key)
                result = sandbox.commands.run("echo ok")
                sandbox.kill()
                return result.exit_code == 0

            return await loop.run_in_executor(None, test)

        except Exception as e:
            logger.warning(f"E2B health check failed: {e}")
            return False

    # SandboxProvider methods

    async def create_sandbox(
        self,
        sandbox_id: str,
        manifest: ToolchainManifest,
    ) -> Path:
        """Create sandbox and return workspace path."""
        await self._create_sandbox(sandbox_id, manifest)
        return Path(self.WORKSPACE_BASE)

    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """Destroy sandbox."""
        await self._destroy_sandbox(sandbox_id)

    async def create_snapshot(
        self,
        sandbox_id: str,
        snapshot_id: str,
    ) -> str:
        """Create sandbox snapshot."""
        sandbox = self._sandboxes.get(sandbox_id)
        if not sandbox:
            raise ValueError(f"Sandbox {sandbox_id} not found")

        loop = asyncio.get_event_loop()

        # E2B supports sandbox snapshotting
        # This would use sandbox.snapshot() if available
        try:
            # For now, create a git commit as snapshot
            result = await loop.run_in_executor(
                None,
                lambda: sandbox.commands.run(
                    f"cd {self.WORKSPACE_BASE} && git add -A && git commit -m 'Snapshot {snapshot_id}' --allow-empty && git rev-parse HEAD"
                )
            )
            return result.stdout.strip() or snapshot_id
        except Exception:
            return snapshot_id

    async def restore_snapshot(
        self,
        sandbox_id: str,
        snapshot_id: str,
    ) -> None:
        """Restore sandbox from snapshot."""
        sandbox = self._sandboxes.get(sandbox_id)
        if not sandbox:
            raise ValueError(f"Sandbox {sandbox_id} not found")

        loop = asyncio.get_event_loop()

        await loop.run_in_executor(
            None,
            lambda: sandbox.commands.run(f"cd {self.WORKSPACE_BASE} && git checkout {snapshot_id}")
        )

    async def install_packages(
        self,
        sandbox_id: str,
        packages: list[str],
        package_manager: str = "pip",
    ) -> None:
        """Install packages in sandbox."""
        sandbox = self._sandboxes.get(sandbox_id)
        if not sandbox:
            raise ValueError(f"Sandbox {sandbox_id} not found")

        loop = asyncio.get_event_loop()

        if package_manager == "pip":
            cmd = f"pip install {' '.join(packages)}"
        elif package_manager == "npm":
            cmd = f"npm install {' '.join(packages)}"
        elif package_manager == "apt":
            cmd = f"apt-get update && apt-get install -y {' '.join(packages)}"
        else:
            raise ValueError(f"Unknown package manager: {package_manager}")

        await loop.run_in_executor(
            None,
            lambda: sandbox.commands.run(cmd)
        )
