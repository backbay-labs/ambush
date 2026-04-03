"""
Modal Provider - Execute toolchains on Modal serverless infrastructure.

Modal provides GPU-enabled serverless functions with fast cold starts,
persistent volumes, and built-in secret management.

Requires: modal package
Authentication: modal token new (CLI auth)
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hellcat.core.gates.results import (
    build_verification_payload,
    emit_gates_event,
    normalize_gate_result,
    resolve_logs_dir,
)
from hellcat.core.providers.base import (
    ExecutionContext,
    ExecutionProvider,
    ExecutionResult,
)
from hellcat.core.providers.capabilities import ExecutionCapabilities

if TYPE_CHECKING:
    from hellcat.core.manifests.schema import ToolchainManifest

logger = logging.getLogger(__name__)

# Check if modal is available
try:
    import modal
    MODAL_AVAILABLE = True
except ImportError:
    MODAL_AVAILABLE = False
    modal = None


class ModalProvider(ExecutionProvider):
    """
    Modal serverless execution provider.

    Executes toolchains on Modal's serverless infrastructure. Features:
    - GPU support (A10G, A100, H100)
    - Fast cold starts (~2s)
    - Persistent volumes for caching
    - Built-in secret management
    - Automatic scaling

    Requires the modal package and authentication via `modal token new`.
    """

    name = "modal"
    capabilities = ExecutionCapabilities(
        gpu=True,
        gpu_types=["A10G", "A100", "H100"],
        isolation_level="container",
        max_runtime=timedelta(hours=24),
        max_memory_gb=256,  # Depends on instance type
        persistent_volume=True,  # Via volumes
        network_egress=True,
        max_concurrent=100,  # Highly scalable
        custom_image=True,
    )

    def __init__(self, config: dict[str, Any] | None = None):
        """
        Initialize the Modal provider.

        Args:
            config: Provider configuration
                - app_name: Modal app name
                - gpu: GPU type ("any", "a10g", "a100", "h100", None)
                - memory: Memory in MB
                - timeout: Default timeout in seconds
                - volume_name: Persistent volume name
                - image: Custom container image
        """
        if not MODAL_AVAILABLE:
            raise ImportError(
                "modal package required for ModalProvider. "
                "Install with: pip install modal"
            )

        self.config = config or {}
        self.app_name = self.config.get("app_name", "hellcat")
        self.gpu_type = self.config.get("gpu")
        self.memory = self.config.get("memory", 4096)  # 4GB default
        self.default_timeout = self.config.get("timeout", 1800)  # 30 minutes
        self.volume_name = self.config.get("volume_name")
        self.custom_image = self.config.get("image")

        # Active function handles
        self._functions: dict[str, Any] = {}

    async def execute(
        self,
        manifest: ToolchainManifest,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """
        Execute a toolchain on Modal.

        Args:
            manifest: Toolchain manifest
            context: Execution context

        Returns:
            Execution result
        """
        start_time = datetime.utcnow()
        run_id = context.run_id
        context.ensure_shields()

        try:
            # Emit step started event
            if context.ledger_writer or context.shield_manager:
                from hellcat.trust.ledger.events import StepStartedEvent
                await context.emit_event(StepStartedEvent(
                    run_id=run_id,
                    step_id=context.step_id,
                    provider=self.name,
                    manifest_id=manifest.manifest_id,
                ))

            # Build and deploy Modal function
            func = self._build_function(manifest, context)

            # Execute the function
            result = await self._execute_function(func, manifest, context)

            # Run quality gates if main execution succeeded
            gate_results = []
            if result["exit_code"] == 0:
                gate_results = await self._run_gates(manifest, context)

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
                "run_id": run_id,
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
                artifacts=result.get("artifacts", {}),
                logs={
                    "stdout": result.get("stdout", ""),
                    "stderr": result.get("stderr", ""),
                },
                metrics={
                    "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
                    "gates_run": len(gate_results),
                    "gates_passed": sum(1 for g in gate_results if g["passed"]),
                    "modal_function_id": result.get("function_id"),
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
            logger.exception(f"Modal execution failed: {e}")
            return ExecutionResult(
                status="error",
                exit_code=-3,
                logs={"error": str(e)},
            )

    def _build_function(
        self,
        manifest: ToolchainManifest,
        context: ExecutionContext,
    ) -> Any:
        """Build a Modal function for the manifest."""
        # Determine GPU requirements
        gpu = None
        if manifest.requirements.gpu or manifest.runtime.prefer_gpu:
            gpu_type = self.gpu_type or "any"
            if gpu_type == "a10g":
                gpu = modal.gpu.A10G()
            elif gpu_type == "a100":
                gpu = modal.gpu.A100()
            elif gpu_type == "h100":
                gpu = modal.gpu.H100()
            elif gpu_type == "any":
                gpu = modal.gpu.Any()

        # Build container image
        if self.custom_image:
            image = modal.Image.from_registry(self.custom_image)
        else:
            # Default image with common tools
            image = (
                modal.Image.debian_slim(python_version="3.12")
                .pip_install("git", "curl", "jq")
            )

            # Add toolchain-specific packages
            toolchain = manifest.toolchain
            if toolchain == "claude":
                image = image.pip_install("anthropic")
            elif toolchain == "blender-agent":
                image = image.apt_install("blender")

        # Build secrets
        secrets = []
        for secret_name in manifest.runtime.secrets:
            if secret_name in context.secrets:
                secrets.append(
                    modal.Secret.from_dict({secret_name: context.secrets[secret_name]})
                )

        # Create app and function
        app = modal.App(name=f"{self.app_name}-{context.run_id[:8]}")

        # Attach volume if configured
        volumes = {}
        if self.volume_name:
            volumes["/data"] = modal.Volume.from_name(self.volume_name, create_if_missing=True)

        timeout = int(manifest.runtime.timeout.total_seconds())

        @app.function(
            image=image,
            gpu=gpu,
            memory=self.memory,
            timeout=timeout,
            secrets=secrets,
            volumes=volumes,
        )
        def execute_toolchain(manifest_dict: dict, context_dict: dict) -> dict:
            """Execute toolchain in Modal container."""
            import os
            import subprocess
            from pathlib import Path

            # Reconstruct manifest
            from hellcat.core.manifests.schema import ToolchainManifest
            manifest = ToolchainManifest.from_dict(manifest_dict)

            # Set environment variables
            for key, value in manifest.runtime.env_vars.items():
                os.environ[key] = value
            run_id = context_dict.get("run_id")
            if run_id:
                run_dir = Path(manifest.runtime.working_dir) / ".hellcat" / "runs" / str(run_id)
                os.environ.setdefault("HELLCAT_RUN_ID", str(run_id))
                os.environ.setdefault("HELLCAT_RUN_DIR", str(run_dir))

            # Determine command
            if manifest.task.entrypoint:
                cmd = manifest.task.entrypoint
                if manifest.task.entrypoint_args:
                    cmd = [cmd] + manifest.task.entrypoint_args
            else:
                cmd = manifest.toolchain

            # Execute
            try:
                if isinstance(cmd, str):
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        cwd=manifest.runtime.working_dir,
                        capture_output=True,
                        text=True,
                        timeout=manifest.runtime.timeout.total_seconds(),
                    )
                else:
                    result = subprocess.run(
                        cmd,
                        cwd=manifest.runtime.working_dir,
                        capture_output=True,
                        text=True,
                        timeout=manifest.runtime.timeout.total_seconds(),
                    )

                return {
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }

            except subprocess.TimeoutExpired:
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": "Execution timed out",
                }

            except Exception as e:
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": str(e),
                }

        return execute_toolchain

    async def _execute_function(
        self,
        func: Any,
        manifest: ToolchainManifest,
        context: ExecutionContext,
    ) -> dict[str, Any]:
        """Execute a Modal function."""
        loop = asyncio.get_event_loop()

        # Serialize inputs
        manifest_dict = manifest.to_dict()
        context_dict = {
            "run_id": context.run_id,
            "step_id": context.step_id,
        }

        # Execute remotely
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: func.remote(manifest_dict, context_dict)
                ),
                timeout=manifest.runtime.timeout.total_seconds(),
            )
            return result

        except TimeoutError:
            raise

    async def _run_gates(
        self,
        manifest: ToolchainManifest,
        context: ExecutionContext,
    ) -> list[dict[str, Any]]:
        """Run quality gates on Modal."""
        results = []
        from pathlib import Path
        from shlex import quote

        # For Modal, we run gates as separate functions
        # This is a simplified implementation
        for gate in manifest.gates:
            try:
                started = datetime.utcnow()
                # Build gate function
                gate_func = self._build_gate_function(gate, manifest)
                run_dir = Path(manifest.runtime.working_dir) / ".hellcat" / "runs" / context.run_id
                env_prefix = (
                    f"HELLCAT_RUN_ID={quote(context.run_id)} "
                    f"HELLCAT_RUN_DIR={quote(str(run_dir))}"
                )
                gate_cmd = f"{env_prefix} {gate.command}"

                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda gf=gate_func, gc=gate_cmd: gf.remote(gc)
                    ),
                    timeout=gate.timeout.total_seconds(),
                )
                duration_ms = int((datetime.utcnow() - started).total_seconds() * 1000)

                passed = result["exit_code"] == gate.expected_exit_code

                # Check patterns
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
                    "stdout": result.get("stdout", "")[:10000],
                    "stderr": result.get("stderr", "")[:10000],
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

    def _build_gate_function(self, gate: Any, manifest: ToolchainManifest) -> Any:
        """Build a Modal function for a quality gate."""
        app = modal.App(name=f"{self.app_name}-gate-{gate.name}")

        image = modal.Image.debian_slim(python_version="3.12")

        @app.function(
            image=image,
            timeout=int(gate.timeout.total_seconds()),
        )
        def run_gate(command: str) -> dict:
            import subprocess

            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=gate.timeout.total_seconds(),
                )

                return {
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }

            except subprocess.TimeoutExpired:
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": "Gate timed out",
                }

            except Exception as e:
                return {
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": str(e),
                }

        return run_gate

    async def stream_logs(self, run_id: str) -> AsyncIterator[str]:
        """Stream logs from Modal function."""
        # Modal has real-time log streaming via modal.run_in_executor
        # This is a placeholder
        yield f"[Modal {run_id}] Log streaming via Modal CLI: modal app logs {self.app_name}"

    async def cancel(self, run_id: str) -> bool:
        """Cancel Modal function execution."""
        # Modal functions can be cancelled via the API
        # This would require tracking function calls
        func = self._functions.pop(run_id, None)
        # TODO: Modal cancellation would go here if func is not None
        return func is not None

    async def health_check(self) -> bool:
        """Check if Modal is available."""
        try:
            # Test Modal connection by listing apps
            loop = asyncio.get_event_loop()

            def check():
                # Just import and check if token exists
                import modal
                return modal.config._profile is not None or os.environ.get("MODAL_TOKEN_ID")

            return await loop.run_in_executor(None, check)

        except Exception as e:
            logger.warning(f"Modal health check failed: {e}")
            return False


# GPU-specific variants for convenience
class ModalA10GProvider(ModalProvider):
    """Modal provider configured for A10G GPU."""

    name = "modal-a10g"
    capabilities = ExecutionCapabilities(
        gpu=True,
        gpu_types=["A10G"],
        isolation_level="container",
        max_runtime=timedelta(hours=24),
        max_memory_gb=24,  # A10G has 24GB VRAM
        persistent_volume=True,
        network_egress=True,
        max_concurrent=50,
        custom_image=True,
    )

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        config["gpu"] = "a10g"
        super().__init__(config)


class ModalA100Provider(ModalProvider):
    """Modal provider configured for A100 GPU."""

    name = "modal-a100"
    capabilities = ExecutionCapabilities(
        gpu=True,
        gpu_types=["A100"],
        isolation_level="container",
        max_runtime=timedelta(hours=24),
        max_memory_gb=80,  # A100 has 40/80GB VRAM
        persistent_volume=True,
        network_egress=True,
        max_concurrent=20,
        custom_image=True,
    )

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        config["gpu"] = "a100"
        super().__init__(config)
