"""Shield manager for inline enforcement and telemetry export."""

from __future__ import annotations

import inspect
from typing import Any

from cyntra.trust.ledger.events import LedgerEvent, ShieldAlertEvent
from cyntra.trust.shields.base import Shield
from cyntra.trust.shields.models import ShieldAction, ShieldAlert


class ShieldManager:
    """Coordinate multiple shield integrations."""

    def __init__(self, shields: list[Shield] | None = None) -> None:
        self.shields = shields or []

    def add_shield(self, shield: Shield) -> None:
        self.shields.append(shield)

    async def handle_event(self, event: LedgerEvent, ctx: Any) -> list[ShieldAction]:
        """Run inline shields and export telemetry."""
        actions: list[ShieldAction] = []

        for shield in self.shields:
            if not shield.enabled:
                continue

            if shield.mode == "inline":
                result = shield.handle_event(event, ctx)
                if inspect.isawaitable(result):
                    result = await result
                if result:
                    actions.extend(result)

            if shield.mode == "export":
                try:
                    result = shield.export_event(event, ctx)
                    if inspect.isawaitable(result):
                        await result
                except Exception:
                    # Export is best-effort
                    continue

        return actions

    async def poll_alerts(self) -> list[ShieldAlert]:
        """Poll alerts from ingest shields."""
        alerts: list[ShieldAlert] = []

        for shield in self.shields:
            if not shield.enabled or shield.mode != "ingest":
                continue

            result = shield.poll_alerts()
            if inspect.isawaitable(result):
                result = await result
            if result:
                alerts.extend(result)

        return alerts

    async def ingest_alerts(self, ledger_writer: Any) -> list[ShieldAlert]:
        """Poll alerts and emit them to the ledger."""
        alerts = await self.poll_alerts()
        if not ledger_writer:
            return alerts

        for alert in alerts:
            await ledger_writer.emit(
                ShieldAlertEvent(
                    run_id=alert.run_id,
                    step_id=alert.step_id,
                    shield=alert.shield,
                    severity=alert.severity,
                    summary=alert.summary,
                    alert_id=alert.alert_id,
                    timestamp=alert.timestamp.isoformat() if alert.timestamp else None,
                    metadata=alert.metadata,
                )
            )

        return alerts
