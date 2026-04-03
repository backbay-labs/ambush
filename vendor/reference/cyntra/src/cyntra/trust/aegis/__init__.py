"""Aegis: runtime execution detection and response."""

from cyntra.trust.aegis.engine import AegisEngine
from cyntra.trust.aegis.state import AegisRunState, AegisViolation
from cyntra.trust.aegis.guards import (
    Guard,
    EgressAllowlistGuard,
    ForbiddenPathGuard,
    MCPToolGuard,
    SecretLeakGuard,
)
from cyntra.trust.aegis.client import (
    AegisClient,
    AegisClientError,
    ExecutionEvent,
    EventType,
    CheckResult,
    RecordResult,
    SystemAttestation,
    LedgerRoot,
    FileEventData,
    CommandEventData,
    NetworkEventData,
    ToolEventData,
    PatchEventData,
    get_client,
    check_execution,
    record_event,
    get_system_attestation,
)

__all__ = [
    # Engine and state
    "AegisEngine",
    "AegisRunState",
    "AegisViolation",
    # Guards
    "Guard",
    "EgressAllowlistGuard",
    "ForbiddenPathGuard",
    "MCPToolGuard",
    "SecretLeakGuard",
    # Client
    "AegisClient",
    "AegisClientError",
    "ExecutionEvent",
    "EventType",
    "CheckResult",
    "RecordResult",
    "SystemAttestation",
    "LedgerRoot",
    "FileEventData",
    "CommandEventData",
    "NetworkEventData",
    "ToolEventData",
    "PatchEventData",
    "get_client",
    "check_execution",
    "record_event",
    "get_system_attestation",
    # Detections
    "compile_detections_from_ledger",
]


def __getattr__(name: str):
    if name == "compile_detections_from_ledger":
        from cyntra.trust.aegis.detections import compile_detections_from_ledger
        return compile_detections_from_ledger
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
