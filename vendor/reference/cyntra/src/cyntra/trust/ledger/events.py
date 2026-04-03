"""
Ledger Event Types.

Defines the event types and structures emitted during execution.
These events provide a consistent audit trail across all providers.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Literal
from uuid import uuid4
import json


class EventType(str, Enum):
    """All possible event types in the ledger."""

    # Run lifecycle
    RUN_STARTED = "run_started"
    RUN_COMPLETED = "run_completed"

    # Step lifecycle
    STEP_STARTED = "step_started"
    STEP_COMPLETED = "step_completed"

    # Provider events
    PROVIDER_SELECTED = "provider_selected"
    PROVIDER_FALLBACK = "provider_fallback"
    PROVIDER_FAILED = "provider_failed"

    # LLM interaction
    PROMPT_SENT = "prompt_sent"
    RESPONSE_CHUNK = "response_chunk"
    RESPONSE_COMPLETE = "response_complete"
    THINKING = "thinking"

    # Tool usage
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"

    # MCP-specific
    MCP_SERVER_DISCOVERED = "mcp_server_discovered"
    MCP_TOOL_DISCOVERED = "mcp_tool_discovered"
    MCP_TOOL_INVOKED = "mcp_tool_invoked"

    # File operations
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    ARTIFACT_WRITTEN = "artifact_written"

    # Security events
    PROCESS_START = "process_start"
    PROCESS_EXIT = "process_exit"
    NET_CONNECT = "net_connect"
    DNS_QUERY = "dns_query"
    SECRET_INJECTED = "secret_injected"
    SECRET_EXPOSED = "secret_exposed"
    POLICY_VIOLATION = "policy_violation"
    CONTAINMENT_ACTION = "containment_action"
    FORENSICS_BUNDLE_WRITTEN = "forensics_bundle_written"
    SHIELD_ALERT = "shield_alert"
    SHIELD_ACTION = "shield_action"
    SHIELD_EXPORT = "shield_export"

    # Lease events
    LEASE_CREATED = "lease_created"
    LEASE_ANCHORED = "lease_anchored"

    # Range/Tournament events
    ATTACK_SIMULATION = "attack_simulation"
    RANGE_STARTED = "range_started"
    RANGE_COMPLETED = "range_completed"
    DRILL_SCORED = "drill_scored"

    # Command execution
    BASH_COMMAND = "bash_command"
    BASH_OUTPUT = "bash_output"

    # Quality gates
    GATE_STARTED = "gate_started"
    GATE_PASSED = "gate_passed"
    GATE_FAILED = "gate_failed"

    # Sandbox events
    SANDBOX_CREATED = "sandbox_created"
    SANDBOX_DESTROYED = "sandbox_destroyed"
    SNAPSHOT_CREATED = "snapshot_created"
    SNAPSHOT_RESTORED = "snapshot_restored"

    # Orchestrator events
    JOB_REGISTERED = "job_registered"
    JOB_TRIGGERED = "job_triggered"
    JOB_STATUS_CHANGED = "job_status_changed"

    # Agent events
    AGENT_SESSION_CREATED = "agent_session_created"
    AGENT_MESSAGE_SENT = "agent_message_sent"
    AGENT_SESSION_ENDED = "agent_session_ended"

    # Verdict and completion
    VERDICT = "verdict"
    PATCH_APPLIED = "patch_applied"

    # Errors and warnings
    ERROR = "error"
    WARNING = "warning"

    # Metrics
    METRIC = "metric"

    # Spine gateway
    SPINE_GATEWAY_FORWARD = "spine_gateway_forward"
    SPINE_GATEWAY_DROP = "spine_gateway_drop"
    SPINE_GATEWAY_BYPASS_RATE_LIMIT = "spine_gateway_bypass_rate_limit"
    SPINE_GATEWAY_SEND_ERROR = "spine_gateway_send_error"


@dataclass
class LedgerEvent:
    """
    Base event structure for all ledger events.

    All events share common fields for correlation and tracing,
    with type-specific data in the `data` field.
    """

    # Event identity
    event_id: str = field(default_factory=lambda: str(uuid4()))
    type: EventType = EventType.ERROR
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Correlation
    run_id: str = ""
    step_id: str | None = None

    # Event data (type-specific)
    data: dict[str, Any] = field(default_factory=dict)

    # Provenance
    provider: str | None = None
    source: str | None = None  # e.g., "e2b-sandbox-xxx", "modal-function-yyy"

    # Distributed tracing
    trace_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None

    def to_dict(self) -> dict:
        """Serialize event to dictionary."""
        return {
            "event_id": self.event_id,
            "type": self.type.value,
            "timestamp": self.timestamp.isoformat(),
            "run_id": self.run_id,
            "step_id": self.step_id,
            "data": self.data,
            "provider": self.provider,
            "source": self.source,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
        }

    def to_json(self) -> str:
        """Serialize event to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> LedgerEvent:
        """Deserialize event from dictionary."""
        data = data.copy()
        data["type"] = EventType(data["type"])
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


# Convenience factory functions for common events

def RunStartedEvent(
    run_id: str,
    manifest_id: str,
    toolchain: str,
    issue_id: str,
    **kwargs
) -> LedgerEvent:
    """Create a run_started event."""
    return LedgerEvent(
        type=EventType.RUN_STARTED,
        run_id=run_id,
        data={
            "manifest_id": manifest_id,
            "toolchain": toolchain,
            "issue_id": issue_id,
            **kwargs,
        },
    )


def RunCompletedEvent(
    run_id: str,
    status: str,
    duration_ms: float,
    **kwargs
) -> LedgerEvent:
    """Create a run_completed event."""
    return LedgerEvent(
        type=EventType.RUN_COMPLETED,
        run_id=run_id,
        data={
            "status": status,
            "duration_ms": duration_ms,
            **kwargs,
        },
    )


def StepStartedEvent(
    run_id: str,
    step_id: str,
    provider: str,
    **kwargs
) -> LedgerEvent:
    """Create a step_started event."""
    return LedgerEvent(
        type=EventType.STEP_STARTED,
        run_id=run_id,
        step_id=step_id,
        provider=provider,
        data=kwargs,
    )


def StepCompletedEvent(
    run_id: str,
    step_id: str,
    status: str,
    duration_ms: float,
    exit_code: int = 0,
    **kwargs
) -> LedgerEvent:
    """Create a step_completed event."""
    return LedgerEvent(
        type=EventType.STEP_COMPLETED,
        run_id=run_id,
        step_id=step_id,
        data={
            "status": status,
            "duration_ms": duration_ms,
            "exit_code": exit_code,
            **kwargs,
        },
    )


def ToolCallEvent(
    run_id: str,
    step_id: str,
    tool: str,
    arguments: dict | None = None,
    **kwargs
) -> LedgerEvent:
    """Create a tool_call event."""
    return LedgerEvent(
        type=EventType.TOOL_CALL,
        run_id=run_id,
        step_id=step_id,
        data={
            "tool": tool,
            "arguments": arguments or {},
            **kwargs,
        },
    )


def ToolResultEvent(
    run_id: str,
    step_id: str,
    tool: str,
    result: Any,
    success: bool = True,
    **kwargs
) -> LedgerEvent:
    """Create a tool_result event."""
    return LedgerEvent(
        type=EventType.TOOL_RESULT,
        run_id=run_id,
        step_id=step_id,
        data={
            "tool": tool,
            "result": result,
            "success": success,
            **kwargs,
        },
    )


def ArtifactWrittenEvent(
    run_id: str,
    step_id: str,
    name: str,
    path: str,
    size_bytes: int,
    **kwargs
) -> LedgerEvent:
    """Create an artifact_written event."""
    return LedgerEvent(
        type=EventType.ARTIFACT_WRITTEN,
        run_id=run_id,
        step_id=step_id,
        data={
            "name": name,
            "path": path,
            "size_bytes": size_bytes,
            **kwargs,
        },
    )


def GateEvent(
    run_id: str,
    step_id: str,
    gate_name: str,
    passed: bool,
    duration_ms: float,
    output: str | None = None,
    **kwargs
) -> LedgerEvent:
    """Create a gate event (started, passed, or failed)."""
    event_type = EventType.GATE_PASSED if passed else EventType.GATE_FAILED
    return LedgerEvent(
        type=event_type,
        run_id=run_id,
        step_id=step_id,
        data={
            "gate": gate_name,
            "passed": passed,
            "duration_ms": duration_ms,
            "output": output,
            **kwargs,
        },
    )


def ErrorEvent(
    run_id: str,
    error_type: str,
    error_message: str,
    step_id: str | None = None,
    traceback: str | None = None,
    **kwargs
) -> LedgerEvent:
    """Create an error event."""
    return LedgerEvent(
        type=EventType.ERROR,
        run_id=run_id,
        step_id=step_id,
        data={
            "error_type": error_type,
            "error_message": error_message,
            "traceback": traceback,
            **kwargs,
        },
    )


def PolicyViolationEvent(
    run_id: str,
    step_id: str | None,
    guard: str,
    severity: str,
    message: str,
    action: str,
    **kwargs
) -> LedgerEvent:
    """Create a policy_violation event."""
    return LedgerEvent(
        type=EventType.POLICY_VIOLATION,
        run_id=run_id,
        step_id=step_id,
        data={
            "guard": guard,
            "severity": severity,
            "message": message,
            "action": action,
            **kwargs,
        },
    )


def ContainmentActionEvent(
    run_id: str,
    step_id: str | None,
    action: str,
    status: str,
    **kwargs
) -> LedgerEvent:
    """Create a containment_action event."""
    return LedgerEvent(
        type=EventType.CONTAINMENT_ACTION,
        run_id=run_id,
        step_id=step_id,
        data={
            "action": action,
            "status": status,
            **kwargs,
        },
    )


def ShieldActionEvent(
    run_id: str,
    step_id: str | None,
    shield: str,
    action: str,
    reason: str,
    **kwargs
) -> LedgerEvent:
    """Create a shield_action event."""
    return LedgerEvent(
        type=EventType.SHIELD_ACTION,
        run_id=run_id,
        step_id=step_id,
        data={
            "shield": shield,
            "action": action,
            "reason": reason,
            **kwargs,
        },
    )


def ShieldAlertEvent(
    run_id: str | None,
    step_id: str | None,
    shield: str,
    severity: str,
    summary: str,
    **kwargs
) -> LedgerEvent:
    """Create a shield_alert event."""
    return LedgerEvent(
        type=EventType.SHIELD_ALERT,
        run_id=run_id or "",
        step_id=step_id,
        data={
            "shield": shield,
            "severity": severity,
            "summary": summary,
            **kwargs,
        },
    )


def ShieldExportEvent(
    run_id: str,
    step_id: str | None,
    shield: str,
    status: str,
    **kwargs
) -> LedgerEvent:
    """Create a shield_export event."""
    return LedgerEvent(
        type=EventType.SHIELD_EXPORT,
        run_id=run_id,
        step_id=step_id,
        data={
            "shield": shield,
            "status": status,
            **kwargs,
        },
    )


def LeaseCreatedEvent(
    run_id: str,
    lease_hash: str,
    source: str = "manifest",
    **kwargs
) -> LedgerEvent:
    """Create a lease_created event."""
    return LedgerEvent(
        type=EventType.LEASE_CREATED,
        run_id=run_id,
        data={
            "lease_hash": lease_hash,
            "source": source,
            **kwargs,
        },
    )


def LeaseAnchoredEvent(
    run_id: str,
    lease_hash: str,
    anchor: str = "receipt",
    **kwargs
) -> LedgerEvent:
    """Create a lease_anchored event."""
    return LedgerEvent(
        type=EventType.LEASE_ANCHORED,
        run_id=run_id,
        data={
            "lease_hash": lease_hash,
            "anchor": anchor,
            **kwargs,
        },
    )


# === Range/Tournament Events ===


def AttackSimulationEvent(
    run_id: str,
    event_id: str,
    event_type: str,
    attack_id: str = "",
    objective_id: str = "",
    severity: str = "medium",
    source: str = "",
    target: str = "",
    timestamp: str | None = None,
    tags: list[str] | None = None,
    **kwargs
) -> LedgerEvent:
    """Create an attack_simulation event for range raids."""
    from datetime import datetime as dt
    
    return LedgerEvent(
        type=EventType.ATTACK_SIMULATION,
        run_id=run_id,
        data={
            "event_id": event_id,
            "event_type": event_type,
            "attack_id": attack_id,
            "objective_id": objective_id,
            "severity": severity,
            "source": source,
            "target": target,
            "simulated_timestamp": timestamp or dt.utcnow().isoformat() + "Z",
            "tags": tags or [],
            **kwargs,
        },
    )


def RangeStartedEvent(
    run_id: str,
    template_id: str,
    drill_id: str = "",
    **kwargs
) -> LedgerEvent:
    """Create a range_started event."""
    return LedgerEvent(
        type=EventType.RANGE_STARTED,
        run_id=run_id,
        data={
            "template_id": template_id,
            "drill_id": drill_id,
            **kwargs,
        },
    )


def RangeCompletedEvent(
    run_id: str,
    template_id: str,
    status: str,
    duration_ms: float,
    events_emitted: int = 0,
    detections: int = 0,
    **kwargs
) -> LedgerEvent:
    """Create a range_completed event."""
    return LedgerEvent(
        type=EventType.RANGE_COMPLETED,
        run_id=run_id,
        data={
            "template_id": template_id,
            "status": status,
            "duration_ms": duration_ms,
            "events_emitted": events_emitted,
            "detections": detections,
            **kwargs,
        },
    )


def DrillScoredEvent(
    run_id: str,
    drill_id: str,
    passed: bool,
    score: float,
    metrics: dict | None = None,
    **kwargs
) -> LedgerEvent:
    """Create a drill_scored event."""
    return LedgerEvent(
        type=EventType.DRILL_SCORED,
        run_id=run_id,
        data={
            "drill_id": drill_id,
            "passed": passed,
            "score": score,
            "metrics": metrics or {},
            **kwargs,
        },
    )
