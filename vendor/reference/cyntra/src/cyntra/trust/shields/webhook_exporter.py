"""Webhook-based shield exporter."""

from __future__ import annotations

import json
from typing import Any
from urllib import request

from cyntra.trust.ledger.events import LedgerEvent
from cyntra.trust.shields.base import Shield


class WebhookExporterShield(Shield):
    """POST events to a webhook endpoint."""

    name = "webhook_exporter"
    mode = "export"

    def __init__(self, url: str, *, timeout_seconds: int = 5, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.timeout_seconds = timeout_seconds
        self.headers = headers or {}

    def export_event(self, event: LedgerEvent, ctx: Any) -> None:
        payload = {
            "type": event.type.value,
            "timestamp": event.timestamp.isoformat(),
            "run_id": event.run_id,
            "step_id": event.step_id,
            "data": event.data,
            "provider": event.provider,
        }

        data = json.dumps(payload).encode("utf-8")
        req = request.Request(self.url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for key, value in self.headers.items():
            req.add_header(key, value)

        with request.urlopen(req, timeout=self.timeout_seconds):
            return None
