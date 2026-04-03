"""Aegis shield adapter."""

from __future__ import annotations

from cyntra.trust.aegis.engine import AegisEngine
from cyntra.trust.aegis.state import AegisViolation
from cyntra.trust.ledger.events import LedgerEvent
from cyntra.trust.shields.base import Shield
from cyntra.trust.shields.models import ShieldAction


class AegisShield(Shield):
    """Inline Aegis enforcement shield."""

    name = "aegis"
    mode = "inline"

    def __init__(self, engine: AegisEngine) -> None:
        self.engine = engine

    async def handle_event(self, event: LedgerEvent, ctx: object) -> list[ShieldAction]:
        violations = await self.engine.handle_event(event)
        return [self._to_action(v) for v in violations]

    def _to_action(self, violation: AegisViolation) -> ShieldAction:
        return ShieldAction(
            action=violation.action,
            shield=self.name,
            reason=violation.message,
            severity=violation.severity,
            metadata={
                "guard_id": violation.guard_id,
                "message": violation.message,
                **violation.metadata,
            },
        )
