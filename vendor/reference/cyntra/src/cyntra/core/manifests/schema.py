"""
Toolchain Manifest Schema.

Defines the portable specification for running toolchains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from cyntra.core.providers.capabilities import ExecutionCapabilities


@dataclass
class TaskSpec:
    """
    What to execute - the task definition.

    Contains the issue reference, code context, and job type
    that defines the work to be done.
    """

    # Issue reference
    issue_id: str
    title: str
    description: str = ""
    acceptance_criteria: list[str] = field(default_factory=list)

    # Code context
    repo_url: str | None = None
    branch: str = "main"
    commit: str | None = None  # Pin to specific commit
    context_files: list[str] = field(default_factory=list)
    forbidden_paths: list[str] = field(default_factory=list)

    # Job type
    job_type: Literal["code", "fab-world", "data", "review", "custom"] = "code"

    # Custom entrypoint (for non-code jobs)
    entrypoint: str | None = None  # e.g., "python scripts/run.py"
    entrypoint_args: list[str] = field(default_factory=list)

    # Tags for routing and categorization
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "issue_id": self.issue_id,
            "title": self.title,
            "description": self.description,
            "acceptance_criteria": self.acceptance_criteria,
            "repo_url": self.repo_url,
            "branch": self.branch,
            "commit": self.commit,
            "context_files": self.context_files,
            "forbidden_paths": self.forbidden_paths,
            "job_type": self.job_type,
            "entrypoint": self.entrypoint,
            "entrypoint_args": self.entrypoint_args,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> TaskSpec:
        """Deserialize from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class RuntimeConfig:
    """
    How to execute - runtime configuration.

    Contains model settings, execution limits, and environment configuration.
    """

    # Model configuration
    model: str | None = None  # e.g., "claude-opus-4-5-20251101"
    prompt_genome_id: str | None = None  # For prompt evolution
    sampling: dict = field(default_factory=lambda: {"temperature": 0.7, "top_p": 0.95})

    # Execution limits
    timeout: timedelta = field(default_factory=lambda: timedelta(minutes=30))
    max_tokens: int | None = None
    max_retries: int = 3
    retry_delay: timedelta = field(default_factory=lambda: timedelta(seconds=5))

    # Environment
    env_vars: dict[str, str] = field(default_factory=dict)
    secrets: list[str] = field(default_factory=list)  # Secret names to inject

    # Container (if applicable)
    image: str | None = None
    dockerfile: str | None = None
    working_dir: str = "/workspace"

    # Resource hints (for routing)
    prefer_gpu: bool = False
    prefer_local: bool = False

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "model": self.model,
            "prompt_genome_id": self.prompt_genome_id,
            "sampling": self.sampling,
            "timeout": self.timeout.total_seconds(),
            "max_tokens": self.max_tokens,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay.total_seconds(),
            "env_vars": self.env_vars,
            "secrets": self.secrets,
            "image": self.image,
            "dockerfile": self.dockerfile,
            "working_dir": self.working_dir,
            "prefer_gpu": self.prefer_gpu,
            "prefer_local": self.prefer_local,
        }

    @classmethod
    def from_dict(cls, data: dict) -> RuntimeConfig:
        """Deserialize from dictionary."""
        data = data.copy()
        if "timeout" in data:
            data["timeout"] = timedelta(seconds=data["timeout"])
        if "retry_delay" in data:
            data["retry_delay"] = timedelta(seconds=data["retry_delay"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class GateSpec:
    """
    Quality gate definition.

    Gates are verification steps that run after execution to validate
    the output (tests, type checks, linting, etc.).
    """

    name: str  # "pytest", "mypy", "ruff", "fab-realism"
    command: str  # "pytest -v", "mypy ."
    blocking: bool = True  # If True, failure stops the run
    timeout: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    working_dir: str | None = None  # Override working directory
    env_vars: dict[str, str] = field(default_factory=dict)

    # Pass criteria
    expected_exit_code: int = 0
    pass_pattern: str | None = None  # Regex to match in output for pass
    fail_pattern: str | None = None  # Regex to match in output for fail

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "command": self.command,
            "blocking": self.blocking,
            "timeout": self.timeout.total_seconds(),
            "working_dir": self.working_dir,
            "env_vars": self.env_vars,
            "expected_exit_code": self.expected_exit_code,
            "pass_pattern": self.pass_pattern,
            "fail_pattern": self.fail_pattern,
        }

    @classmethod
    def from_dict(cls, data: dict) -> GateSpec:
        """Deserialize from dictionary."""
        data = data.copy()
        if "timeout" in data:
            data["timeout"] = timedelta(seconds=data["timeout"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ContextSpec:
    """
    Injected context for the toolchain.

    Contains learned patterns, strategy directives, and control signals
    that customize toolchain behavior.
    """

    # Memory context (learned patterns and warnings)
    memory_context: dict | None = None

    # Strategy directives (from evolution)
    strategy: dict | None = None

    # Swarm planner decisions
    planner: dict | None = None

    # Exploration control signals
    control: dict | None = None

    # Additional context (free-form)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "memory_context": self.memory_context,
            "strategy": self.strategy,
            "planner": self.planner,
            "control": self.control,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ContextSpec:
        """Deserialize from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class SecurityPolicy:
    """
    Security policy for execution.

    Defines runtime enforcement rules for network, filesystem, tools, and secrets.
    """

    # Network
    egress_mode: Literal["deny_all", "allowlist", "open"] = "open"
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ip_cidrs: list[str] = field(default_factory=list)
    deny_domains: list[str] = field(default_factory=list)

    # Filesystem
    allowed_write_roots: list[str] = field(default_factory=lambda: ["./"])
    forbidden_paths: list[str] = field(default_factory=list)

    # Commands / tooling
    deny_exec_patterns: list[str] = field(default_factory=list)
    allow_tools: list[str] = field(default_factory=list)

    # Secrets
    secret_scopes: dict[str, dict[str, Any]] = field(default_factory=dict)
    redact_in_logs: bool = True

    # Escalation
    on_violation: Literal[
        "cancel", "isolate", "revoke", "escalate", "speculate_vote"
    ] = "escalate"

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "egress_mode": self.egress_mode,
            "allowed_domains": self.allowed_domains,
            "allowed_ip_cidrs": self.allowed_ip_cidrs,
            "deny_domains": self.deny_domains,
            "allowed_write_roots": self.allowed_write_roots,
            "forbidden_paths": self.forbidden_paths,
            "deny_exec_patterns": self.deny_exec_patterns,
            "allow_tools": self.allow_tools,
            "secret_scopes": self.secret_scopes,
            "redact_in_logs": self.redact_in_logs,
            "on_violation": self.on_violation,
        }

    @classmethod
    def from_dict(cls, data: dict) -> SecurityPolicy:
        """Deserialize from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ShieldSpec:
    """
    Shield configuration for telemetry/export/ingest integrations.
    """

    name: str
    enabled: bool = True
    mode: Literal["inline", "export", "ingest"] | None = None
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "enabled": self.enabled,
            "mode": self.mode,
            "config": self.config,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ShieldSpec:
        """Deserialize from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ToolchainManifest:
    """
    Portable toolchain specification.

    A manifest is the complete specification for running a toolchain
    on any execution provider. It combines:
    - Task definition (what to do)
    - Requirements (what's needed)
    - Runtime config (how to do it)
    - Gates (how to verify)
    - Context (domain knowledge)
    """

    # Identity
    schema_version: str = "2.0.0"
    manifest_id: str = field(default_factory=lambda: str(uuid4()))

    # Execution target
    toolchain: str = "claude"  # "claude", "codex", "crush", etc.
    provider_hint: str | None = None  # Force specific provider

    # Task definition
    task: TaskSpec = field(default_factory=lambda: TaskSpec(issue_id="", title=""))

    # Requirements
    requirements: ExecutionCapabilities = field(default_factory=ExecutionCapabilities)

    # Runtime configuration
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)

    # Quality gates
    gates: list[GateSpec] = field(default_factory=list)

    # Context injection
    context: ContextSpec | None = None

    # Security policy
    security: SecurityPolicy = field(default_factory=SecurityPolicy)

    # Shield integrations
    shields: list[ShieldSpec] = field(default_factory=list)

    # Speculate+Vote configuration
    speculate: bool = False
    speculate_parallelism: int = 2

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str | None = None

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "schema_version": self.schema_version,
            "manifest_id": self.manifest_id,
            "toolchain": self.toolchain,
            "provider_hint": self.provider_hint,
            "task": self.task.to_dict(),
            "requirements": self.requirements.to_dict(),
            "runtime": self.runtime.to_dict(),
            "gates": [g.to_dict() for g in self.gates],
            "context": self.context.to_dict() if self.context else None,
            "security": self.security.to_dict(),
            "shields": [s.to_dict() for s in self.shields],
            "speculate": self.speculate,
            "speculate_parallelism": self.speculate_parallelism,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ToolchainManifest:
        """Deserialize from dictionary."""
        data = data.copy()

        # Convert nested objects
        if "task" in data and isinstance(data["task"], dict):
            data["task"] = TaskSpec.from_dict(data["task"])
        if "requirements" in data and isinstance(data["requirements"], dict):
            data["requirements"] = ExecutionCapabilities.from_dict(data["requirements"])
        if "runtime" in data and isinstance(data["runtime"], dict):
            data["runtime"] = RuntimeConfig.from_dict(data["runtime"])
        if "gates" in data and isinstance(data["gates"], list):
            data["gates"] = [
                GateSpec.from_dict(g) if isinstance(g, dict) else g
                for g in data["gates"]
            ]
        if "context" in data and isinstance(data["context"], dict):
            data["context"] = ContextSpec.from_dict(data["context"])
        if "security" in data and isinstance(data["security"], dict):
            data["security"] = SecurityPolicy.from_dict(data["security"])
        if "shields" in data and isinstance(data["shields"], list):
            data["shields"] = [
                ShieldSpec.from_dict(s) if isinstance(s, dict) else s
                for s in data["shields"]
            ]

        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def with_task(self, task: TaskSpec) -> ToolchainManifest:
        """Create a copy with a different task."""
        import copy
        new = copy.deepcopy(self)
        new.task = task
        new.manifest_id = str(uuid4())
        return new

    def with_provider(self, provider: str) -> ToolchainManifest:
        """Create a copy with a specific provider hint."""
        import copy
        new = copy.deepcopy(self)
        new.provider_hint = provider
        return new

    def add_gate(self, gate: GateSpec) -> ToolchainManifest:
        """Add a gate to the manifest (mutates)."""
        self.gates.append(gate)
        return self


# Default gates for common use cases
DEFAULT_CODE_GATES = [
    GateSpec(name="ruff", command="ruff check .", blocking=False),
    GateSpec(name="mypy", command="mypy .", blocking=True),
    GateSpec(name="pytest", command="pytest -v", blocking=True),
]

DEFAULT_FAB_GATES = [
    GateSpec(name="fab-realism", command="fab-critics --config realism.yaml", blocking=True),
    GateSpec(name="fab-geometry", command="fab-critics --config geometry.yaml", blocking=True),
]

DEFAULT_DRILL_GATES = [
    GateSpec(
        name="drill-score",
        command="python -m cyntra.gates.drill_score \"$CYNTRA_RUN_DIR\"",
        blocking=True,
    ),
]

DEFAULT_WORKBENCH_GATES = [
    GateSpec(
        name="workbench-score",
        command="python -m cyntra.gates.workbench_score \"$CYNTRA_RUN_DIR\"",
        blocking=True,
    ),
]


def create_code_manifest(
    issue_id: str,
    title: str,
    description: str,
    toolchain: str = "claude",
    **kwargs
) -> ToolchainManifest:
    """
    Create a manifest for a code task.

    Helper function for common code task setup.
    """
    return ToolchainManifest(
        toolchain=toolchain,
        task=TaskSpec(
            issue_id=issue_id,
            title=title,
            description=description,
            job_type="code",
        ),
        gates=DEFAULT_CODE_GATES.copy(),
        **kwargs
    )


def create_fab_manifest(
    issue_id: str,
    title: str,
    description: str,
    **kwargs
) -> ToolchainManifest:
    """
    Create a manifest for a fab/asset task.

    Helper function for 3D asset pipeline tasks.
    """
    return ToolchainManifest(
        toolchain="blender-agent",
        task=TaskSpec(
            issue_id=issue_id,
            title=title,
            description=description,
            job_type="fab-world",
        ),
        requirements=ExecutionCapabilities(
            gpu=True,
            max_runtime=timedelta(hours=1),
        ),
        gates=DEFAULT_FAB_GATES.copy(),
        **kwargs
    )


def create_drill_manifest(
    issue_id: str,
    title: str,
    description: str,
    toolchain: str = "claude",
    **kwargs
) -> ToolchainManifest:
    """
    Create a manifest for a range drill task.
    """
    return ToolchainManifest(
        toolchain=toolchain,
        task=TaskSpec(
            issue_id=issue_id,
            title=title,
            description=description,
            job_type="custom",
        ),
        gates=DEFAULT_DRILL_GATES.copy(),
        **kwargs
    )


def create_workbench_manifest(
    issue_id: str,
    title: str,
    description: str,
    toolchain: str = "workbench",
    **kwargs
) -> ToolchainManifest:
    """
    Create a manifest for a workbench challenge task.
    """
    return ToolchainManifest(
        toolchain=toolchain,
        provider_hint="workbench",
        task=TaskSpec(
            issue_id=issue_id,
            title=title,
            description=description,
            job_type="custom",
            tags=["workbench"],
        ),
        requirements=ExecutionCapabilities(
            isolation_level="container",
            network_egress=False,
            gui_access=True,
            process_telemetry=True,
            file_telemetry=True,
            network_telemetry=True,
        ),
        gates=DEFAULT_WORKBENCH_GATES.copy(),
        **kwargs
    )
