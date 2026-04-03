"""File-based shield exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyntra.trust.ledger.events import LedgerEvent
from cyntra.trust.shields.base import Shield


class FileExporterShield(Shield):
    """Write events to a JSONL file."""

    name = "file_exporter"
    mode = "export"

    def __init__(self, path: Path, *, include_raw: bool = True) -> None:
        self.path = path
        self.include_raw = include_raw
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def export_event(self, event: LedgerEvent, ctx: Any) -> None:
        payload = {
            "type": event.type.value,
            "timestamp": event.timestamp.isoformat(),
            "run_id": event.run_id,
            "step_id": event.step_id,
            "data": event.data,
            "provider": event.provider,
        }
        if self.include_raw:
            payload["event"] = event.to_dict()

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload) + "\n")
