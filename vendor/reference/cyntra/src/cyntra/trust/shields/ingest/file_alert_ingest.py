"""File-based alert ingestion shield."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cyntra.trust.shields.base import Shield
from cyntra.trust.shields.models import ShieldAlert


@dataclass
class FileAlertIngestShield(Shield):
    """Read alerts from a JSONL file."""

    name: str = "file_alert_ingest"
    mode: str = "ingest"
    path: Path = Path("alerts.jsonl")
    _offset: int = 0

    async def poll_alerts(self) -> list[ShieldAlert]:
        if not self.path.exists():
            return []

        alerts: list[ShieldAlert] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for idx, line in enumerate(handle):
                if idx < self._offset:
                    continue
                data = json.loads(line)
                alert = ShieldAlert(
                    alert_id=str(data.get("alert_id") or f"{self.name}:{idx}"),
                    shield=str(data.get("shield") or self.name),
                    severity=str(data.get("severity") or "unknown"),
                    summary=str(data.get("summary") or ""),
                    timestamp=_parse_timestamp(data.get("timestamp")),
                    run_id=data.get("run_id"),
                    step_id=data.get("step_id"),
                    metadata=data.get("metadata") or {},
                )
                alerts.append(alert)
            self._offset = idx + 1 if "idx" in locals() else self._offset

        return alerts


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return None
