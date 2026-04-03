"""
GPU Pool Provider - Execute toolchains via the shared GPU pool manager.

This provider currently acquires a GPU lease and then runs locally while the
remote execution path is wired. The lease is still recorded in the ledger.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from typing import Any

from hellcat.core.providers.base import ExecutionContext, ExecutionProvider, ExecutionResult
from hellcat.core.providers.capabilities import ExecutionCapabilities
from hellcat.core.providers.local.provider import LocalProvider
from hellcat.core.scheduler.routing import GpuPoolConfig, KernelConfig
from hellcat.infra.gpu_pool.manager import GPUPoolManager
try:
    from hellcat.trust.ledger.events import LeaseCreatedEvent
except ImportError:
    LeaseCreatedEvent = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)


class GPUPoolProvider(ExecutionProvider):
    """Execution provider that acquires GPU leases from the pool manager."""

    name = "gpu-pool"
    capabilities = ExecutionCapabilities(
        gpu=True,
        gpu_types=["A10G", "A100", "H100"],
        gpu_count=1,
        isolation_level="container",
        network_egress=True,
        persistent_volume=True,
        secrets_injection=True,
        custom_image=True,
        max_runtime=timedelta(hours=24),
    )

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.kernel_config_path = Path(
            self.config.get("kernel_config_path", ".hellcat/config.yaml")
        )
        self.pool_id = self.config.get("pool_id")
        self.allowed_backends = self.config.get("allowed_backends")
        self.backend_hint = self.config.get("backend_hint")
        self.pool_manager = GPUPoolManager(self._load_gpu_pool_config())

        local_config = self.config.get("local") if isinstance(self.config.get("local"), dict) else {}
        self._local_provider = LocalProvider(local_config)
        self._local_provider.name = self.name

    def _load_gpu_pool_config(self) -> GpuPoolConfig:
        if isinstance(self.config.get("gpu_pool"), dict):
            try:
                kernel_cfg = KernelConfig.from_dict({"gpu_pool": self.config["gpu_pool"]})
                return kernel_cfg.gpu_pool
            except Exception as exc:
                logger.warning("Failed to load gpu_pool config from provider config", exc_info=exc)

        try:
            kernel_cfg = KernelConfig.load(self.kernel_config_path)
            return kernel_cfg.gpu_pool
        except Exception as exc:
            logger.warning("Failed to load kernel config for gpu_pool", exc_info=exc)
            return GpuPoolConfig()

    async def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        manifest = ctx.manifest
        if manifest is None:
            return ExecutionResult(
                status="error",
                exit_code=-1,
                error_message="GPU pool provider requires a manifest in the execution context.",
            )

        requirements = manifest.requirements
        gpu_count = requirements.gpu_count or (1 if requirements.gpu else 0)
        gpu_type = requirements.gpu_types[0] if requirements.gpu_types else None
        ttl_seconds = int(manifest.runtime.timeout.total_seconds())
        profile_id = manifest.runtime.image or manifest.toolchain or manifest.task.job_type

        backend_hint = self.backend_hint
        if isinstance(ctx.metadata, dict):
            backend_hint = ctx.metadata.get("gpu_backend_hint") or backend_hint
        pool_id = self.pool_id
        if isinstance(ctx.metadata, dict):
            pool_id = ctx.metadata.get("gpu_pool_id") or pool_id

        allowed_backends = self.allowed_backends
        if isinstance(allowed_backends, list):
            allowed_backends = [str(b) for b in allowed_backends]

        lease = self.pool_manager.request_worker(
            profile_id=profile_id,
            gpu_type=gpu_type,
            gpu_count=gpu_count,
            ttl_seconds=ttl_seconds,
            backend_hint=backend_hint,
            pool_id=pool_id,
            allowed_backends=allowed_backends,
            metadata={
                "run_id": ctx.run_id,
                "manifest_id": manifest.manifest_id,
                "toolchain": manifest.toolchain,
            },
        )

        if ctx.ledger_writer or ctx.shield_manager:
            await ctx.emit_event(
                LeaseCreatedEvent(
                    run_id=ctx.run_id,
                    lease_hash=lease.lease_id,
                    source=self.name,
                    backend=lease.backend,
                    worker_id=lease.worker_id,
                    state=lease.state,
                )
            )

        if lease.state in {"failed", "error"}:
            return ExecutionResult(
                status="error",
                exit_code=-2,
                error_message="GPU pool lease request failed.",
                proof={"lease": lease.metadata, "backend": lease.backend},
            )

        try:
            result = await self._local_provider.execute(ctx)
        finally:
            if lease.worker_id:
                self.pool_manager.release_worker(lease=lease)

        if result.proof is None:
            result.proof = {}
        result.proof["gpu_pool_lease"] = {
            "lease_id": lease.lease_id,
            "backend": lease.backend,
            "worker_id": lease.worker_id,
            "state": lease.state,
            "metadata": lease.metadata,
        }

        return result

    async def stream_logs(self, ctx: ExecutionContext) -> AsyncIterator[str]:
        return
        yield

    async def cancel(self, ctx: ExecutionContext) -> bool:
        return await self._local_provider.cancel(ctx)

    async def health_check(self) -> bool:
        health = self.pool_manager.health_check()
        if isinstance(health, dict) and "backends" in health:
            return any(backend.get("status") == "ok" for backend in health["backends"].values())
        return True
