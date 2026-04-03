"""Guard for detecting secret leakage in outputs."""

from __future__ import annotations

from cyntra.trust.aegis.guards.base import Guard
from cyntra.trust.aegis.state import AegisRunState, AegisViolation
from cyntra.trust.ledger.events import EventType, LedgerEvent
from cyntra.core.manifests.schema import SecurityPolicy


class SecretLeakGuard(Guard):
    """Detect secret values in output streams."""

    guard_id = "secret_leak_guard"

    def __init__(self, secret_values: list[str]) -> None:
        self._secret_values = [value for value in secret_values if value]

    def evaluate(
        self,
        event: LedgerEvent,
        state: AegisRunState,
        policy: SecurityPolicy,
    ) -> list[AegisViolation]:
        if not self._secret_values:
            return []

        if event.type not in (
            EventType.BASH_OUTPUT,
            EventType.RESPONSE_CHUNK,
            EventType.RESPONSE_COMPLETE,
            EventType.TOOL_RESULT,
        ):
            return []

        text = self._extract_text(event.data)
        if not text:
            return []

        for secret in self._secret_values:
            if secret and secret in text:
                return [
                    AegisViolation(
                        guard_id=self.guard_id,
                        severity="critical",
                        message="Secret value exposed in output",
                        action=policy.on_violation,
                        event=event,
                        metadata={"secret_hint": secret[:4] + "..."},
                    )
                ]

        return []

    def _extract_text(self, data: dict) -> str:
        for key in ("output", "content", "result", "error"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return value
        return ""
