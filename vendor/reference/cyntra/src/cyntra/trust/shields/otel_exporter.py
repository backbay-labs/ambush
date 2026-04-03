"""OTLP/HTTP shield exporter."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib import request

from cyntra.trust.ledger.events import EventType, LedgerEvent
from cyntra.trust.shields.base import Shield


_ERROR_EVENTS = {
    EventType.ERROR,
    EventType.GATE_FAILED,
    EventType.PROVIDER_FAILED,
    EventType.CONTAINMENT_ACTION,
}
_WARN_EVENTS = {
    EventType.WARNING,
    EventType.POLICY_VIOLATION,
}


def _normalize_endpoint(endpoint: str) -> str:
    endpoint = endpoint.strip()
    if not endpoint:
        raise ValueError("OTLP endpoint is required")
    if endpoint.endswith("/"):
        endpoint = endpoint[:-1]
    if not endpoint.endswith("/v1/logs"):
        endpoint = f"{endpoint}/v1/logs"
    return endpoint


def _to_unix_nano(timestamp: datetime) -> str:
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return str(int(timestamp.timestamp() * 1_000_000_000))


def _safe_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def _to_otel_value(value: Any) -> dict[str, Any]:
    if value is None:
        return {"stringValue": ""}
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    return {"stringValue": _safe_json(value)}


def _normalize_hex(value: str | None, length: int) -> str | None:
    if not value:
        return None
    candidate = value.strip().lower()
    if len(candidate) != length:
        return None
    try:
        int(candidate, 16)
    except ValueError:
        return None
    return candidate


def _attributes_from_map(values: dict[str, Any]) -> list[dict[str, Any]]:
    attributes: list[dict[str, Any]] = []
    for key, value in values.items():
        if value is None:
            continue
        attributes.append({"key": str(key), "value": _to_otel_value(value)})
    return attributes


def _severity_for_event(event_type: EventType) -> tuple[str, int]:
    if event_type in _ERROR_EVENTS:
        return "ERROR", 17
    if event_type in _WARN_EVENTS:
        return "WARN", 13
    return "INFO", 9


class OtelExporterShield(Shield):
    """Export ledger events to an OTLP/HTTP logs endpoint."""

    name = "otel_exporter"
    mode = "export"

    def __init__(
        self,
        endpoint: str,
        *,
        service_name: str = "cyntra",
        timeout_seconds: int = 5,
        headers: dict[str, str] | None = None,
        resource_attributes: dict[str, Any] | None = None,
        scope_name: str = "cyntra.shields.otel_exporter",
        scope_version: str | None = None,
    ) -> None:
        self.endpoint = _normalize_endpoint(endpoint)
        self.service_name = service_name
        self.timeout_seconds = timeout_seconds
        self.headers = headers or {}
        self.resource_attributes = resource_attributes or {}
        self.scope_name = scope_name
        self.scope_version = scope_version

    def export_event(self, event: LedgerEvent, ctx: Any) -> None:
        payload = self._build_payload(event)
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        req = request.Request(self.endpoint, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        for key, value in self.headers.items():
            req.add_header(key, value)
        with request.urlopen(req, timeout=self.timeout_seconds):
            return None

    def _build_payload(self, event: LedgerEvent) -> dict[str, Any]:
        severity_text, severity_number = _severity_for_event(event.type)
        attributes: dict[str, Any] = {
            "cyntra.event_id": event.event_id,
            "cyntra.event_type": event.type.value,
            "cyntra.run_id": event.run_id,
            "cyntra.step_id": event.step_id,
            "cyntra.provider": event.provider,
            "cyntra.source": event.source,
            "cyntra.parent_span_id": event.parent_span_id,
        }

        if event.data:
            attributes["cyntra.event_data"] = event.data
            for key, value in event.data.items():
                attributes[f"cyntra.data.{key}"] = value

        trace_id = _normalize_hex(event.trace_id, 32)
        span_id = _normalize_hex(event.span_id, 16)
        if not trace_id and event.trace_id:
            attributes["cyntra.trace_id"] = event.trace_id
        if not span_id and event.span_id:
            attributes["cyntra.span_id"] = event.span_id

        log_record: dict[str, Any] = {
            "timeUnixNano": _to_unix_nano(event.timestamp),
            "severityNumber": severity_number,
            "severityText": severity_text,
            "body": {"stringValue": event.type.value},
            "attributes": _attributes_from_map(attributes),
        }
        if trace_id:
            log_record["traceId"] = trace_id
        if span_id:
            log_record["spanId"] = span_id

        resource_attributes = {"service.name": self.service_name}
        resource_attributes.update(self.resource_attributes)

        scope: dict[str, Any] = {"name": self.scope_name}
        if self.scope_version:
            scope["version"] = self.scope_version

        return {
            "resourceLogs": [
                {
                    "resource": {"attributes": _attributes_from_map(resource_attributes)},
                    "scopeLogs": [
                        {
                            "scope": scope,
                            "logRecords": [log_record],
                        }
                    ],
                }
            ]
        }
