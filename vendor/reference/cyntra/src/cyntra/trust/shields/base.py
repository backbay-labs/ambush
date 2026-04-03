"""Base shield interfaces."""

from __future__ import annotations

from abc import ABC
from typing import Any, Literal

from cyntra.trust.ledger.events import LedgerEvent
from cyntra.trust.shields.models import ShieldAction, ShieldAlert


ShieldMode = Literal["inline", "export", "ingest"]


class Shield(ABC):
    """Base shield class."""

    name: str
    mode: ShieldMode = "export"
    enabled: bool = True

    def handle_event(self, event: LedgerEvent, ctx: Any) -> list[ShieldAction]:
        """Handle an event inline and optionally return actions."""
        return []

    def export_event(self, event: LedgerEvent, ctx: Any) -> None:
        """Export event to external system (best-effort)."""
        return None

    async def poll_alerts(self) -> list[ShieldAlert]:
        """Poll for alerts (ingest mode)."""
        return []
