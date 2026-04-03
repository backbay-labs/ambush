"""
Sandbox runtime helpers.

Supports lightweight process or container backends for providers that need
an isolated execution surface (range/workbench).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SandboxMount:
    """Host -> container mount."""

    host_path: Path
    container_path: str
    mode: str = "rw"


@dataclass
class SandboxRuntimeConfig:
    """Runtime configuration for a sandbox."""

    backend: str = "process"  # process | container | microvm
    image: str | None = None
    command: list[str] | None = None
    env: dict[str, str] = field(default_factory=dict)
    mounts: list[SandboxMount] = field(default_factory=list)
    network_mode: str = "none"  # none | bridge | isolated
    workdir: str | None = None
    cpu_limit: float | None = None
    memory_mb: int | None = None
    runtime_bin: str | None = None  # docker/podman/etc
    name_prefix: str = "cyntra-sandbox"


@dataclass
class SandboxRuntimeHandle:
    """Handle for a running sandbox."""

    backend: str
    identifier: str
    started_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


class SandboxRuntime:
    """Base class for sandbox runtimes."""

    def __init__(self, config: SandboxRuntimeConfig) -> None:
        self.config = config

    async def start(self, *, workdir: Path) -> SandboxRuntimeHandle:
        raise NotImplementedError

    async def stop(self, handle: SandboxRuntimeHandle) -> None:
        raise NotImplementedError


class ProcessSandboxRuntime(SandboxRuntime):
    """Process-based sandbox (best-effort isolation)."""

    def __init__(self, config: SandboxRuntimeConfig) -> None:
        super().__init__(config)
        self._process: asyncio.subprocess.Process | None = None

    async def start(self, *, workdir: Path) -> SandboxRuntimeHandle:
        command = self.config.command or [
            sys.executable,
            "-c",
            "import time; time.sleep(3600)",
        ]

        env = os.environ.copy()
        env.update(self.config.env)

        logger.info("Starting process sandbox", command=command, workdir=str(workdir))
        self._process = await asyncio.create_subprocess_exec(
            *command,
            cwd=str(workdir),
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )

        return SandboxRuntimeHandle(
            backend="process",
            identifier=str(self._process.pid),
            started_at=datetime.utcnow(),
        )

    async def stop(self, handle: SandboxRuntimeHandle) -> None:
        if not self._process:
            return
        if self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5.0)
            except TimeoutError:
                self._process.kill()
        self._process = None


class ContainerSandboxRuntime(SandboxRuntime):
    """Container-based sandbox (docker/podman)."""

    def __init__(self, config: SandboxRuntimeConfig) -> None:
        super().__init__(config)
        self._runtime_bin = self._resolve_runtime_bin()

    def _resolve_runtime_bin(self) -> str | None:
        if self.config.runtime_bin:
            return self.config.runtime_bin
        for candidate in ("docker", "podman"):
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
        return None

    def _build_run_command(self, *, workdir: Path, name: str) -> list[str]:
        if not self._runtime_bin:
            raise RuntimeError("No container runtime available (docker/podman not found)")
        if not self.config.image:
            raise RuntimeError("Container runtime requires an image to be configured")

        command = [self._runtime_bin, "run", "--rm", "--detach", "--name", name]

        if self.config.network_mode == "none":
            command.extend(["--network", "none"])
        elif self.config.network_mode == "bridge":
            command.extend(["--network", "bridge"])

        if self.config.cpu_limit is not None:
            command.extend(["--cpus", str(self.config.cpu_limit)])
        if self.config.memory_mb is not None:
            command.extend(["--memory", f"{int(self.config.memory_mb)}m"])

        for mount in self.config.mounts:
            command.extend(
                [
                    "-v",
                    f"{mount.host_path}:{mount.container_path}:{mount.mode}",
                ]
            )

        env = self.config.env or {}
        for key, value in env.items():
            command.extend(["-e", f"{key}={value}"])

        container_workdir = self.config.workdir or "/workspace"
        command.extend(["-w", container_workdir])

        # Ensure workdir is mounted
        if not any(m.host_path == workdir for m in self.config.mounts):
            command.extend(["-v", f"{workdir}:{container_workdir}:rw"])

        command.append(self.config.image)
        runtime_command = self.config.command
        if runtime_command is None:
            # Use image default entrypoint/command
            return command
        if not runtime_command:
            runtime_command = ["sleep", "3600"]
        command.extend(runtime_command)
        return command

    async def start(self, *, workdir: Path) -> SandboxRuntimeHandle:
        name = f"{self.config.name_prefix}-{uuid.uuid4().hex[:8]}"
        run_cmd = self._build_run_command(workdir=workdir, name=name)

        logger.info("Starting container sandbox", command=run_cmd)
        result = subprocess.run(
            run_cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            raise RuntimeError(f"Container start failed: {stderr or result.stdout}")

        container_id = result.stdout.strip() or name
        return SandboxRuntimeHandle(
            backend="container",
            identifier=container_id,
            started_at=datetime.utcnow(),
            metadata={"runtime_bin": self._runtime_bin, "name": name},
        )

    async def stop(self, handle: SandboxRuntimeHandle) -> None:
        if not self._runtime_bin:
            return
        subprocess.run(
            [self._runtime_bin, "stop", handle.identifier],
            capture_output=True,
            text=True,
        )


class MicroVMSandboxRuntime(ProcessSandboxRuntime):
    """
    MicroVM runtime stub.

    Uses an external command to launch/terminate microVMs. This expects the
    operator to supply a working microVM command in config.command.
    """

    async def start(self, *, workdir: Path) -> SandboxRuntimeHandle:
        if not self.config.command:
            raise RuntimeError("MicroVM runtime requires a command to launch the VM")
        handle = await super().start(workdir=workdir)
        handle.backend = "microvm"
        return handle


class SandboxRuntimeFactory:
    """Builds sandbox runtimes from config."""

    def __init__(self, *, default_backend: str = "process") -> None:
        self.default_backend = default_backend

    def build(self, config: SandboxRuntimeConfig) -> SandboxRuntime:
        backend = (config.backend or self.default_backend).lower()
        if backend == "container":
            return ContainerSandboxRuntime(config)
        if backend == "microvm":
            return MicroVMSandboxRuntime(config)
        return ProcessSandboxRuntime(config)
