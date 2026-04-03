"""
Execution Capabilities Model.

Defines what an execution environment supports, enabling capability-based
routing decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Literal


@dataclass
class ExecutionCapabilities:
    """
    Declares what an execution environment supports.

    Used for:
    1. Provider self-declaration of what they support
    2. Manifest requirements specification
    3. Routing decisions (match requirements to provider capabilities)

    Example:
        # Provider declares capabilities
        provider.capabilities = ExecutionCapabilities(
            gpu=True,
            gpu_types=["A100", "H100"],
            max_runtime=timedelta(hours=24),
        )

        # Manifest declares requirements
        manifest.requirements = ExecutionCapabilities(
            gpu=True,
            network_egress=True,
        )

        # Router checks compatibility
        if provider.matches_requirements(manifest.requirements):
            ...
    """

    # Compute resources
    gpu: bool = False
    gpu_types: list[str] = field(default_factory=list)
    gpu_count: int = 0
    max_memory_gb: float | None = None
    max_cpu_cores: int | None = None

    # Runtime limits
    max_runtime: timedelta | None = None
    max_concurrent: int | None = None

    # Isolation and security
    isolation_level: Literal["none", "process", "container", "vm"] = "none"
    network_egress: bool = True
    network_ingress: bool = False
    docker_in_docker: bool = False

    # Storage
    persistent_volume: bool = False
    max_storage_gb: float | None = None
    filesystem_snapshot: bool = False

    # Secrets and environment
    secrets_injection: bool = True
    env_vars: bool = True
    custom_image: bool = False

    # Protocol support
    mcp_support: bool = False
    streaming_logs: bool = True
    streaming_output: bool = False

    # Security telemetry and enforcement
    process_telemetry: bool = False
    file_telemetry: bool = False
    network_telemetry: bool = False
    network_policy: bool = False
    secrets_redaction: bool = False
    forensics_snapshot: bool = False
    attestation: bool = False

    # Special features
    browser_access: bool = False
    gui_access: bool = False
    code_interpreter: bool = False

    def matches(self, requirements: ExecutionCapabilities) -> tuple[bool, list[str]]:
        """
        Check if this capability set satisfies the given requirements.

        Returns:
            Tuple of (matches: bool, unmet_requirements: list[str])
        """
        unmet = []

        # GPU requirements
        if requirements.gpu and not self.gpu:
            unmet.append("gpu")
        if requirements.gpu_types:
            missing_gpus = set(requirements.gpu_types) - set(self.gpu_types)
            if missing_gpus and self.gpu_types:  # Only check if we declared specific types
                unmet.append(f"gpu_types:{missing_gpus}")
        if requirements.gpu_count > self.gpu_count:
            unmet.append(f"gpu_count:{requirements.gpu_count}>{self.gpu_count}")

        # Memory/CPU
        if (requirements.max_memory_gb and self.max_memory_gb
                and requirements.max_memory_gb > self.max_memory_gb):
            unmet.append(f"memory:{requirements.max_memory_gb}GB>{self.max_memory_gb}GB")
        if (requirements.max_cpu_cores and self.max_cpu_cores
                and requirements.max_cpu_cores > self.max_cpu_cores):
            unmet.append(f"cpu:{requirements.max_cpu_cores}>{self.max_cpu_cores}")

        # Runtime
        if (requirements.max_runtime and self.max_runtime
                and requirements.max_runtime > self.max_runtime):
            unmet.append(f"runtime:{requirements.max_runtime}>{self.max_runtime}")

        # Isolation
        isolation_levels = ["none", "process", "container", "vm"]
        req_level = isolation_levels.index(requirements.isolation_level)
        self_level = isolation_levels.index(self.isolation_level)
        if req_level > self_level:
            unmet.append(f"isolation:{requirements.isolation_level}")

        # Network
        if requirements.network_egress and not self.network_egress:
            unmet.append("network_egress")
        if requirements.network_ingress and not self.network_ingress:
            unmet.append("network_ingress")
        if requirements.docker_in_docker and not self.docker_in_docker:
            unmet.append("docker_in_docker")

        # Storage
        if requirements.persistent_volume and not self.persistent_volume:
            unmet.append("persistent_volume")
        if requirements.filesystem_snapshot and not self.filesystem_snapshot:
            unmet.append("filesystem_snapshot")
        if (requirements.max_storage_gb and self.max_storage_gb
                and requirements.max_storage_gb > self.max_storage_gb):
            unmet.append(f"storage:{requirements.max_storage_gb}GB>{self.max_storage_gb}GB")

        # Secrets/env
        if requirements.secrets_injection and not self.secrets_injection:
            unmet.append("secrets_injection")
        if requirements.custom_image and not self.custom_image:
            unmet.append("custom_image")

        # Protocols
        if requirements.mcp_support and not self.mcp_support:
            unmet.append("mcp_support")
        if requirements.streaming_logs and not self.streaming_logs:
            unmet.append("streaming_logs")
        if requirements.streaming_output and not self.streaming_output:
            unmet.append("streaming_output")

        # Security telemetry and enforcement
        if requirements.process_telemetry and not self.process_telemetry:
            unmet.append("process_telemetry")
        if requirements.file_telemetry and not self.file_telemetry:
            unmet.append("file_telemetry")
        if requirements.network_telemetry and not self.network_telemetry:
            unmet.append("network_telemetry")
        if requirements.network_policy and not self.network_policy:
            unmet.append("network_policy")
        if requirements.secrets_redaction and not self.secrets_redaction:
            unmet.append("secrets_redaction")
        if requirements.forensics_snapshot and not self.forensics_snapshot:
            unmet.append("forensics_snapshot")
        if requirements.attestation and not self.attestation:
            unmet.append("attestation")

        # Special features
        if requirements.browser_access and not self.browser_access:
            unmet.append("browser_access")
        if requirements.gui_access and not self.gui_access:
            unmet.append("gui_access")
        if requirements.code_interpreter and not self.code_interpreter:
            unmet.append("code_interpreter")

        return len(unmet) == 0, unmet

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "gpu": self.gpu,
            "gpu_types": self.gpu_types,
            "gpu_count": self.gpu_count,
            "max_memory_gb": self.max_memory_gb,
            "max_cpu_cores": self.max_cpu_cores,
            "max_runtime": self.max_runtime.total_seconds() if self.max_runtime else None,
            "max_concurrent": self.max_concurrent,
            "isolation_level": self.isolation_level,
            "network_egress": self.network_egress,
            "network_ingress": self.network_ingress,
            "docker_in_docker": self.docker_in_docker,
            "persistent_volume": self.persistent_volume,
            "max_storage_gb": self.max_storage_gb,
            "filesystem_snapshot": self.filesystem_snapshot,
            "secrets_injection": self.secrets_injection,
            "env_vars": self.env_vars,
            "custom_image": self.custom_image,
            "mcp_support": self.mcp_support,
            "streaming_logs": self.streaming_logs,
            "streaming_output": self.streaming_output,
            "process_telemetry": self.process_telemetry,
            "file_telemetry": self.file_telemetry,
            "network_telemetry": self.network_telemetry,
            "network_policy": self.network_policy,
            "secrets_redaction": self.secrets_redaction,
            "forensics_snapshot": self.forensics_snapshot,
            "attestation": self.attestation,
            "browser_access": self.browser_access,
            "gui_access": self.gui_access,
            "code_interpreter": self.code_interpreter,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ExecutionCapabilities:
        """Deserialize from dictionary."""
        if "max_runtime" in data and data["max_runtime"] is not None:
            data["max_runtime"] = timedelta(seconds=data["max_runtime"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# Preset capability profiles for common scenarios
CAPABILITY_PRESETS = {
    "minimal": ExecutionCapabilities(
        isolation_level="none",
        network_egress=True,
        secrets_injection=True,
    ),
    "sandbox": ExecutionCapabilities(
        isolation_level="vm",
        network_egress=True,
        secrets_injection=True,
        filesystem_snapshot=True,
        code_interpreter=True,
        max_runtime=timedelta(hours=1),
    ),
    "gpu_inference": ExecutionCapabilities(
        gpu=True,
        gpu_types=["A100", "H100", "A10G"],
        isolation_level="container",
        network_egress=True,
        secrets_injection=True,
        max_runtime=timedelta(hours=1),
    ),
    "gpu_training": ExecutionCapabilities(
        gpu=True,
        gpu_types=["A100", "H100"],
        gpu_count=1,
        isolation_level="container",
        network_egress=True,
        persistent_volume=True,
        secrets_injection=True,
        max_runtime=timedelta(hours=24),
    ),
    "distributed": ExecutionCapabilities(
        gpu=True,
        isolation_level="process",
        network_egress=True,
        network_ingress=True,
        persistent_volume=True,
        secrets_injection=True,
    ),
}


def get_preset(name: str) -> ExecutionCapabilities:
    """Get a capability preset by name."""
    if name not in CAPABILITY_PRESETS:
        raise ValueError(f"Unknown capability preset: {name}. Available: {list(CAPABILITY_PRESETS.keys())}")
    return CAPABILITY_PRESETS[name]
