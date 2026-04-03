"""
Aegis state and violation models.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from cyntra.trust.ledger.events import EventType, LedgerEvent


Severity = Literal["low", "medium", "high", "critical"]


@dataclass
class AegisViolation:
    """A single policy violation detected by a guard."""

    guard_id: str
    severity: Severity
    message: str
    action: str
    event: LedgerEvent
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AegisRunState:
    """Minimal derived state for a run."""

    run_id: str | None = None
    step_id: str | None = None
    files_written: set[str] = field(default_factory=set)
    tools_invoked: set[str] = field(default_factory=set)
    net_destinations: set[str] = field(default_factory=set)

    def update(self, event: LedgerEvent) -> None:
        """Update derived state based on an event."""
        if event.run_id:
            self.run_id = event.run_id
        if event.step_id:
            self.step_id = event.step_id

        if event.type == EventType.FILE_WRITE:
            path = event.data.get("path")
            if isinstance(path, str):
                self.files_written.add(path)

        if event.type == EventType.MCP_TOOL_INVOKED:
            tool = event.data.get("tool")
            if isinstance(tool, str):
                self.tools_invoked.add(tool)

        if event.type in (EventType.NET_CONNECT, EventType.DNS_QUERY):
            dest = event.data.get("domain") or event.data.get("host") or event.data.get("destination")
            if isinstance(dest, str):
                self.net_destinations.add(dest)
