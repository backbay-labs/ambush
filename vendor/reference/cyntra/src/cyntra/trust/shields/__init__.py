"""Shield integrations for telemetry export and alert ingestion."""

from cyntra.trust.shields.base import Shield, ShieldMode
from cyntra.trust.shields.manager import ShieldManager
from cyntra.trust.shields.models import ShieldAction, ShieldAlert
from cyntra.trust.shields.defaults import register_default_shields
from cyntra.trust.shields.registry import ShieldRegistry, get_registry, register_shield
from cyntra.trust.shields.aegis_shield import AegisShield
from cyntra.trust.shields.file_exporter import FileExporterShield
from cyntra.trust.shields.otel_exporter import OtelExporterShield
from cyntra.trust.shields.webhook_exporter import WebhookExporterShield
from cyntra.trust.shields.ingest.file_alert_ingest import FileAlertIngestShield

__all__ = [
    "Shield",
    "ShieldMode",
    "ShieldManager",
    "ShieldAction",
    "ShieldAlert",
    "register_default_shields",
    "ShieldRegistry",
    "get_registry",
    "register_shield",
    "AegisShield",
    "FileExporterShield",
    "OtelExporterShield",
    "WebhookExporterShield",
    "FileAlertIngestShield",
]
