"""Default shield registry bindings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cyntra.trust.aegis.engine import AegisEngine
from cyntra.core.manifests.schema import ShieldSpec
from cyntra.trust.shields.aegis_shield import AegisShield
from cyntra.trust.shields.file_exporter import FileExporterShield
from cyntra.trust.shields.ingest.file_alert_ingest import FileAlertIngestShield
from cyntra.trust.shields.otel_exporter import OtelExporterShield
from cyntra.trust.shields.registry import register_shield
from cyntra.trust.shields.webhook_exporter import WebhookExporterShield


def register_default_shields() -> None:
    register_shield("aegis", _build_aegis_shield)
    register_shield("file_exporter", _build_file_exporter)
    register_shield("otel_exporter", _build_otel_exporter)
    register_shield("webhook_exporter", _build_webhook_exporter)
    register_shield("file_alert_ingest", _build_file_alert_ingest)


def _build_aegis_shield(spec: ShieldSpec, ctx: Any) -> AegisShield:
    policy = getattr(ctx.manifest, "security", None)
    if policy is None:
        raise ValueError("Aegis shield requires manifest.security")

    secret_values = list(ctx.secrets.values()) if isinstance(ctx.secrets, dict) else []
    engine = AegisEngine(policy, secret_values=secret_values)
    shield = AegisShield(engine)
    shield.enabled = spec.enabled
    return shield


def _build_file_exporter(spec: ShieldSpec, ctx: Any) -> FileExporterShield:
    path_value = spec.config.get("path") if isinstance(spec.config, dict) else None
    if isinstance(path_value, str) and path_value:
        path = Path(path_value)
    else:
        base = Path(ctx.working_dir) if ctx.working_dir else Path(".")
        path = base / ".cyntra" / "logs" / "shields" / f"{ctx.run_id}.jsonl"

    include_raw = True
    if isinstance(spec.config, dict):
        include_raw = bool(spec.config.get("include_raw", True))

    shield = FileExporterShield(path=path, include_raw=include_raw)
    shield.enabled = spec.enabled
    return shield


def _build_webhook_exporter(spec: ShieldSpec, ctx: Any) -> WebhookExporterShield:
    if not isinstance(spec.config, dict) or not spec.config.get("url"):
        raise ValueError("webhook_exporter requires config.url")

    headers = spec.config.get("headers") if isinstance(spec.config, dict) else None
    shield = WebhookExporterShield(
        url=str(spec.config["url"]),
        timeout_seconds=int(spec.config.get("timeout_seconds", 5)),
        headers=headers if isinstance(headers, dict) else None,
    )
    shield.enabled = spec.enabled
    return shield


def _build_otel_exporter(spec: ShieldSpec, ctx: Any) -> OtelExporterShield:
    config = spec.config if isinstance(spec.config, dict) else {}
    endpoint = str(config.get("endpoint") or "http://localhost:4318")
    headers = config.get("headers") if isinstance(config, dict) else None
    resource_attributes = config.get("resource_attributes") if isinstance(config, dict) else None

    shield = OtelExporterShield(
        endpoint=endpoint,
        timeout_seconds=int(config.get("timeout_seconds", 5)),
        headers=headers if isinstance(headers, dict) else None,
        service_name=str(config.get("service_name") or "cyntra"),
        resource_attributes=resource_attributes if isinstance(resource_attributes, dict) else None,
        scope_name=str(config.get("scope_name") or "cyntra.shields.otel_exporter"),
        scope_version=str(config.get("scope_version")) if config.get("scope_version") else None,
    )
    shield.enabled = spec.enabled
    return shield


def _build_file_alert_ingest(spec: ShieldSpec, ctx: Any) -> FileAlertIngestShield:
    path_value = spec.config.get("path") if isinstance(spec.config, dict) else None
    if isinstance(path_value, str) and path_value:
        path = Path(path_value)
    else:
        base = Path(ctx.working_dir) if ctx.working_dir else Path(".")
        path = base / ".cyntra" / "logs" / "shield_alerts.jsonl"

    shield = FileAlertIngestShield(path=path)
    shield.enabled = spec.enabled
    return shield
