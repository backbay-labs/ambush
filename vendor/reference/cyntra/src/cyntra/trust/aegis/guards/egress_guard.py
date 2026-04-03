"""Guard for network egress allowlist/deny rules."""

from __future__ import annotations

from cyntra.trust.aegis.guards.base import Guard
from cyntra.trust.aegis.state import AegisRunState, AegisViolation
from cyntra.trust.ledger.events import EventType, LedgerEvent
from cyntra.core.manifests.schema import SecurityPolicy


class EgressAllowlistGuard(Guard):
    """Detect outbound destinations outside configured policy."""

    guard_id = "egress_allowlist_guard"

    def evaluate(
        self,
        event: LedgerEvent,
        state: AegisRunState,
        policy: SecurityPolicy,
    ) -> list[AegisViolation]:
        if event.type not in (EventType.NET_CONNECT, EventType.DNS_QUERY):
            return []

        destination = event.data.get("domain") or event.data.get("host") or event.data.get("destination")
        if not isinstance(destination, str) or not destination:
            return []

        if policy.egress_mode == "open":
            return []

        if policy.egress_mode == "deny_all":
            return [self._violation(event, policy, destination, "Egress denied by policy")]

        if self._matches_any(destination, policy.deny_domains):
            return [self._violation(event, policy, destination, "Destination is explicitly denied")]

        if policy.egress_mode == "allowlist":
            if self._matches_any(destination, policy.allowed_domains):
                return []
            if self._matches_any(destination, policy.allowed_ip_cidrs):
                return []
            return [self._violation(event, policy, destination, "Destination not in allowlist")]

        return []

    def _violation(
        self,
        event: LedgerEvent,
        policy: SecurityPolicy,
        destination: str,
        message: str,
    ) -> AegisViolation:
        return AegisViolation(
            guard_id=self.guard_id,
            severity="high",
            message=message,
            action=policy.on_violation,
            event=event,
            metadata={"destination": destination},
        )

    def _matches_any(self, destination: str, patterns: list[str]) -> bool:
        return any(self._matches_destination(destination, pattern) for pattern in patterns)

    def _matches_destination(self, destination: str, pattern: str) -> bool:
        if not pattern:
            return False
        if destination == pattern:
            return True
        if destination.endswith("." + pattern):
            return True
        return False
