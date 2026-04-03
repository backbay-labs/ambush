"""
Base Execution Provider Interface.

Defines the abstract base classes for all execution providers.
"""

from __future__ import annotations

import inspect
import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from uuid import uuid4

if TYPE_CHECKING:
    from hellcat.core.manifests.schema import ToolchainManifest
    from hellcat.core.providers.capabilities import ExecutionCapabilities
    from hellcat.trust.ledger.events import LedgerEvent
    from hellcat.trust.ledger.writer import LedgerWriter
    from hellcat.trust.shields.manager import ShieldManager
    from hellcat.trust.shields.models import ShieldAction

logger = logging.getLogger(__name__)


@dataclass
class ExecutionContext:
    """
    Runtime context passed to a provider for execution.

    Contains everything the provider needs to execute a step:
    - Identifiers for correlation (run_id, step_id)
    - The manifest describing what to do
    - Resolved secrets ready for injection
    - Artifact store for reading/writing files
    - Event bus for ledger events
    - Shield manager for policy enforcement and telemetry export
    """

    # Identifiers
    run_id: str
    step_id: str = field(default_factory=lambda: str(uuid4()))

    # Task specification
    manifest: ToolchainManifest = None  # type: ignore

    # Secrets (already resolved, provider just injects)
    secrets: dict[str, str] = field(default_factory=dict)

    # I/O handles
    artifact_store: Any = None  # ArtifactStore instance
    ledger_writer: LedgerWriter = None  # type: ignore
    shield_manager: ShieldManager | None = None

    # Execution parameters
    timeout: timedelta = field(default_factory=lambda: timedelta(minutes=30))

    # Working directory (for local provider, or temp path)
    working_dir: Path | None = None

    # Trace context for distributed tracing
    trace_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None

    # Metadata for provider-specific options
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_step(self, step_id: str) -> ExecutionContext:
        """Create a new context for a sub-step."""
        return ExecutionContext(
            run_id=self.run_id,
            step_id=step_id,
            manifest=self.manifest,
            secrets=self.secrets,
            artifact_store=self.artifact_store,
            ledger_writer=self.ledger_writer,
            shield_manager=self.shield_manager,
            timeout=self.timeout,
            working_dir=self.working_dir,
            trace_id=self.trace_id,
            span_id=str(uuid4()),
            parent_span_id=self.span_id,
            metadata=self.metadata.copy(),
        )

    async def emit_event(self, event: LedgerEvent) -> list[ShieldAction]:
        """
        Emit an event to shields (control/export) and the ledger (audit).

        Shield evaluation is best-effort; failures should not break execution.
        """
        actions: list[ShieldAction] = []

        self.ensure_shields()

        if self.shield_manager:
            try:
                result = self.shield_manager.handle_event(event, self)
                if inspect.isawaitable(result):
                    actions = await result
                elif isinstance(result, list):
                    actions = result
            except Exception as exc:
                logger.warning("Shield manager failed to handle event", exc_info=exc)

        if self.ledger_writer:
            await self.ledger_writer.emit(event)
            if actions:
                from hellcat.trust.ledger.events import (
                    ContainmentActionEvent,
                    PolicyViolationEvent,
                    ShieldActionEvent,
                )

                for action in actions:
                    await self.ledger_writer.emit(
                        ShieldActionEvent(
                            run_id=event.run_id,
                            step_id=event.step_id,
                            shield=action.shield,
                            action=action.action,
                            reason=action.reason,
                            severity=action.severity,
                            metadata=action.metadata,
                        )
                    )
                    guard_id = action.metadata.get("guard_id")
                    if guard_id:
                        await self.ledger_writer.emit(
                            PolicyViolationEvent(
                                run_id=event.run_id,
                                step_id=event.step_id,
                                guard=str(guard_id),
                                severity=action.severity or "unknown",
                                message=action.reason,
                                action=action.action,
                                metadata=action.metadata,
                            )
                        )
                        await self.ledger_writer.emit(
                            ContainmentActionEvent(
                                run_id=event.run_id,
                                step_id=event.step_id,
                                action=action.action,
                                status="requested",
                                guard=guard_id,
                            )
                        )

        return actions

    def ensure_shields(self) -> None:
        """Ensure a shield manager is attached to this context."""
        if self.shield_manager is not None:
            return
        if not self.manifest:
            return

        try:
            from hellcat.core.manifests.schema import ShieldSpec
            from hellcat.trust.shields.defaults import register_default_shields
            from hellcat.trust.shields.manager import ShieldManager
            from hellcat.trust.shields.registry import get_registry

            register_default_shields()
            registry = get_registry()

            override_specs = self.metadata.get("shields") if isinstance(self.metadata, dict) else None
            specs: list[ShieldSpec]
            if isinstance(override_specs, list) and override_specs:
                specs = [
                    ShieldSpec.from_dict(s) if isinstance(s, dict) else s
                    for s in override_specs
                ]
            else:
                specs = list(self.manifest.shields)

            if not specs:
                specs = [ShieldSpec(name="aegis")]

            shields = []
            for spec in specs:
                if not getattr(spec, "enabled", True):
                    continue
                try:
                    shield = registry.create(spec, self)
                    if spec.mode and getattr(shield, "mode", None) != spec.mode:
                        logger.warning(
                            "Shield mode mismatch",
                            shield=spec.name,
                            requested=spec.mode,
                            actual=getattr(shield, "mode", None),
                        )
                    shields.append(shield)
                except Exception as exc:
                    logger.warning("Failed to build shield", shield=spec.name, exc_info=exc)

            self.shield_manager = ShieldManager(shields)
        except Exception as exc:
            logger.warning("Failed to initialize shield manager", exc_info=exc)


@dataclass
class ExecutionResult:
    """
    Standardized result from any execution provider.

    Provides a consistent interface for execution outcomes regardless
    of the underlying provider.
    """

    # Outcome
    status: Literal["success", "partial", "failed", "timeout", "cancelled", "error"]
    exit_code: int = 0

    # Outputs
    artifacts: dict[str, Path | bytes] = field(default_factory=dict)
    logs: str = ""
    stdout: str = ""
    stderr: str = ""

    # Metrics
    metrics: dict[str, float] = field(default_factory=dict)
    # Common metrics: duration_ms, tokens_used, cost_usd, memory_peak_mb

    # Provider-specific proof data (for verification)
    proof: dict[str, Any] | None = None

    # Error details (if status is error/failed)
    error_type: str | None = None
    error_message: str | None = None
    error_traceback: str | None = None

    # Timestamps
    started_at: datetime | None = None
    completed_at: datetime | None = None

    @property
    def duration_ms(self) -> float | None:
        """Get execution duration in milliseconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds() * 1000
        return self.metrics.get("duration_ms")

    @property
    def is_success(self) -> bool:
        """Check if execution was successful."""
        return self.status in ("success", "partial")

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "artifacts": {k: str(v) if isinstance(v, Path) else "<bytes>" for k, v in self.artifacts.items()},
            "logs": self.logs[:1000] + "..." if len(self.logs) > 1000 else self.logs,
            "metrics": self.metrics,
            "proof": self.proof,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": self.duration_ms,
        }


class ExecutionProvider(ABC):
    """
    Base class for all execution providers.

    An execution provider is responsible for running a toolchain in a
    specific execution environment (local, sandbox, cloud, etc.).

    Subclasses must implement:
    - execute(): Run the task and return results
    - stream_logs(): Stream logs during execution
    - cancel(): Cancel a running execution
    - health_check(): Verify provider is operational
    """

    # Provider identity
    name: str
    version: str = "1.0.0"

    # What this provider supports
    capabilities: ExecutionCapabilities

    # Provider configuration
    config: dict[str, Any]

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize the provider with configuration."""
        self.config = config or {}
        self._validate_config()

    def _validate_config(self) -> None:  # noqa: B027
        """Validate provider configuration. Override in subclasses."""

    @abstractmethod
    async def execute(self, ctx: ExecutionContext) -> ExecutionResult:
        """
        Execute a step and return result.

        This is the main entry point for running work on this provider.
        Implementations should:
        1. Set up the execution environment
        2. Run the toolchain with the manifest
        3. Collect artifacts and logs
        4. Clean up resources
        5. Return standardized result

        Args:
            ctx: Execution context with manifest, secrets, and I/O handles

        Returns:
            ExecutionResult with status, artifacts, logs, and metrics
        """
        ...

    @abstractmethod
    async def stream_logs(self, ctx: ExecutionContext) -> AsyncIterator[str]:
        """
        Stream logs in real-time during execution.

        Yields log lines as they become available. Used for
        real-time monitoring in the desktop app.

        Args:
            ctx: Execution context identifying the running task

        Yields:
            Log lines as strings
        """
        ...

    @abstractmethod
    async def cancel(self, ctx: ExecutionContext) -> bool:
        """
        Cancel a running execution.

        Args:
            ctx: Execution context identifying the task to cancel

        Returns:
            True if cancellation was successful, False otherwise
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """
        Verify provider is operational.

        Should check:
        - API connectivity (if applicable)
        - Credentials validity
        - Resource availability

        Returns:
            True if provider is healthy and ready to accept work
        """
        ...

    def matches_requirements(self, requirements: ExecutionCapabilities) -> bool:
        """Check if this provider can satisfy the given requirements."""
        matches, _ = self.capabilities.matches(requirements)
        return matches

    def get_unmet_requirements(self, requirements: ExecutionCapabilities) -> list[str]:
        """Get list of requirements this provider cannot satisfy."""
        _, unmet = self.capabilities.matches(requirements)
        return unmet

    async def estimate_cost(self, ctx: ExecutionContext) -> float:
        """
        Estimate cost for executing the given context.

        Override in subclasses to provide cost estimates.

        Args:
            ctx: Execution context to estimate

        Returns:
            Estimated cost in USD
        """
        return 0.0

    async def estimate_duration(self, ctx: ExecutionContext) -> timedelta:
        """
        Estimate duration for executing the given context.

        Override in subclasses to provide duration estimates.

        Args:
            ctx: Execution context to estimate

        Returns:
            Estimated duration
        """
        return ctx.timeout

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name})>"


class SandboxProvider(ExecutionProvider):
    """
    Specialized provider for sandboxed execution environments.

    Extends ExecutionProvider with sandbox-specific operations like
    filesystem snapshots and package installation.
    """

    @abstractmethod
    async def create_sandbox(self, ctx: ExecutionContext) -> str:
        """
        Create a new sandbox instance.

        Args:
            ctx: Execution context with configuration

        Returns:
            Sandbox ID for subsequent operations
        """
        ...

    @abstractmethod
    async def destroy_sandbox(self, sandbox_id: str) -> None:
        """
        Destroy a sandbox instance.

        Args:
            sandbox_id: ID of sandbox to destroy
        """
        ...

    async def create_snapshot(self, sandbox_id: str, name: str) -> str:
        """
        Create filesystem snapshot of a sandbox.

        Args:
            sandbox_id: ID of sandbox to snapshot
            name: Name for the snapshot

        Returns:
            Snapshot ID
        """
        raise NotImplementedError("Snapshots not supported by this provider")

    async def restore_snapshot(self, snapshot_id: str) -> str:
        """
        Restore a sandbox from snapshot.

        Args:
            snapshot_id: ID of snapshot to restore

        Returns:
            New sandbox ID
        """
        raise NotImplementedError("Snapshots not supported by this provider")

    async def install_packages(
        self,
        sandbox_id: str,
        packages: list[str],
        manager: Literal["pip", "npm", "apt"] = "pip"
    ) -> None:
        """
        Install packages in a sandbox.

        Args:
            sandbox_id: ID of sandbox
            packages: List of packages to install
            manager: Package manager to use
        """
        raise NotImplementedError("Package installation not supported by this provider")

    async def upload_file(self, sandbox_id: str, local_path: Path, remote_path: str) -> None:
        """
        Upload a file to the sandbox.

        Args:
            sandbox_id: ID of sandbox
            local_path: Local file path
            remote_path: Destination path in sandbox
        """
        raise NotImplementedError("File upload not supported by this provider")

    async def download_file(self, sandbox_id: str, remote_path: str) -> bytes:
        """
        Download a file from the sandbox.

        Args:
            sandbox_id: ID of sandbox
            remote_path: Path in sandbox

        Returns:
            File contents as bytes
        """
        raise NotImplementedError("File download not supported by this provider")

    async def run_command(
        self,
        sandbox_id: str,
        command: str,
        timeout: timedelta | None = None
    ) -> tuple[int, str, str]:
        """
        Run a command in the sandbox.

        Args:
            sandbox_id: ID of sandbox
            command: Command to run
            timeout: Optional timeout

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        raise NotImplementedError("Command execution not supported by this provider")


class OrchestratorProvider(ExecutionProvider):
    """
    Provider for workflow orchestrators (Dagster, Airflow, etc.).

    Extends ExecutionProvider with job/DAG management operations.
    """

    @abstractmethod
    async def register_job(self, job_spec: dict) -> str:
        """
        Register a job definition.

        Args:
            job_spec: Job specification

        Returns:
            Job ID
        """
        ...

    @abstractmethod
    async def trigger_run(self, job_id: str, config: dict | None = None) -> str:
        """
        Trigger a run of a registered job.

        Args:
            job_id: ID of job to run
            config: Optional run configuration

        Returns:
            Run ID
        """
        ...

    @abstractmethod
    async def get_run_status(self, run_id: str) -> dict:
        """
        Get status of a run.

        Args:
            run_id: ID of run

        Returns:
            Status dictionary with state, timestamps, etc.
        """
        ...

    async def cancel_run(self, run_id: str) -> bool:
        """
        Cancel a running job.

        Args:
            run_id: ID of run to cancel

        Returns:
            True if cancellation was successful
        """
        raise NotImplementedError("Run cancellation not supported by this provider")

    async def get_run_logs(self, run_id: str) -> str:
        """
        Get logs from a run.

        Args:
            run_id: ID of run

        Returns:
            Log content
        """
        raise NotImplementedError("Log retrieval not supported by this provider")


class AgentProvider(ExecutionProvider):
    """
    Provider for autonomous agents (Devin, Cursor, etc.).

    Extends ExecutionProvider with session-based agent interaction.
    """

    @abstractmethod
    async def create_session(self, ctx: ExecutionContext) -> str:
        """
        Create an agent session.

        Args:
            ctx: Execution context with task description

        Returns:
            Session ID
        """
        ...

    @abstractmethod
    async def send_message(self, session_id: str, message: str) -> None:
        """
        Send a follow-up message to an agent session.

        Args:
            session_id: ID of session
            message: Message to send
        """
        ...

    @abstractmethod
    async def get_session_status(self, session_id: str) -> dict:
        """
        Get status of an agent session.

        Args:
            session_id: ID of session

        Returns:
            Status dictionary
        """
        ...

    async def get_artifacts(self, session_id: str) -> dict[str, bytes]:
        """
        Retrieve artifacts from an agent session.

        Args:
            session_id: ID of session

        Returns:
            Dictionary of artifact name to content
        """
        raise NotImplementedError("Artifact retrieval not supported by this provider")

    async def end_session(self, session_id: str) -> None:
        """
        End an agent session.

        Args:
            session_id: ID of session to end
        """
        raise NotImplementedError("Session termination not supported by this provider")


class ToolServerProvider(ExecutionProvider):
    """
    Provider for MCP tool servers.

    Extends ExecutionProvider with tool discovery and invocation.
    """

    @abstractmethod
    async def discover_servers(self) -> list[dict]:
        """
        Discover available MCP servers.

        Returns:
            List of server metadata dictionaries
        """
        ...

    @abstractmethod
    async def list_tools(self, server_url: str) -> list[dict]:
        """
        List tools available on a server.

        Args:
            server_url: URL of MCP server

        Returns:
            List of tool definitions
        """
        ...

    @abstractmethod
    async def call_tool(
        self,
        server_url: str,
        tool_name: str,
        arguments: dict
    ) -> dict:
        """
        Call a tool on an MCP server.

        Args:
            server_url: URL of MCP server
            tool_name: Name of tool to call
            arguments: Tool arguments

        Returns:
            Tool result
        """
        ...

    async def get_server_metadata(self, server_url: str) -> dict:
        """
        Get metadata about an MCP server.

        Args:
            server_url: URL of MCP server

        Returns:
            Server metadata
        """
        raise NotImplementedError("Server metadata not supported by this provider")
