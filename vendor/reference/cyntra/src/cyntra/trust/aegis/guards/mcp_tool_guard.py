"""Guard for MCP tool allowlists."""

from __future__ import annotations

import fnmatch

from cyntra.trust.aegis.guards.base import Guard
from cyntra.trust.aegis.state import AegisRunState, AegisViolation
from cyntra.trust.ledger.events import EventType, LedgerEvent
from cyntra.core.manifests.schema import SecurityPolicy


class MCPToolGuard(Guard):
    """Detect MCP tool calls outside the allowed tool list."""

    guard_id = "mcp_tool_guard"

    def evaluate(
        self,
        event: LedgerEvent,
        state: AegisRunState,
        policy: SecurityPolicy,
    ) -> list[AegisViolation]:
        if event.type != EventType.MCP_TOOL_INVOKED:
            return []

        tool = event.data.get("tool")
        if not isinstance(tool, str) or not tool:
            return []

        if not policy.allow_tools:
            return []

        if not any(fnmatch.fnmatch(tool, pattern) for pattern in policy.allow_tools):
            return [
                AegisViolation(
                    guard_id=self.guard_id,
                    severity="medium",
                    message="MCP tool not in allowlist",
                    action=policy.on_violation,
                    event=event,
                    metadata={"tool": tool},
                )
            ]

        return []
