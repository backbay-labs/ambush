"""
Shield Ingest Sentinel - Periodic alert ingestion from external shields.

Responsibilities:
- Poll ingest shields for alerts
- Emit normalized shield alert events to the ledger
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyntra.core.sentinel.base import (
    BaseSentinel,
    SentinelConfig,
    SentinelSchedule,
)

if TYPE_CHECKING:
    from cyntra.core.manifests.schema import ShieldSpec
    from cyntra.trust.ledger.writer import LedgerWriter
    from cyntra.trust.shields.manager import ShieldManager


@dataclass
class ShieldIngestConfig:
    """Configuration for ShieldIngestSentinel."""

    ledger_path: str | None = None
    ledger_buffer_size: int = 10
    shields: list["ShieldSpec"] = field(default_factory=list)


@dataclass
class ShieldIngestContext:
    """Minimal context for building ingest shields."""

    run_id: str
    working_dir: Path | None = None
    manifest: Any = None
    secrets: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class ShieldIngestSentinel(BaseSentinel):
    """
    Periodic alert ingestion from external shields.

    Responsibilities:
    - Poll ingest shields for alerts
    - Emit normalized shield alert events to the ledger
    """

    def __init__(
        self,
        config: SentinelConfig | None = None,
        ingest_config: ShieldIngestConfig | None = None,
        schedule: SentinelSchedule | None = None,
        repo_root: Path | None = None,
    ) -> None:
        super().__init__(config, schedule, repo_root)
        self.ingest_config = ingest_config or ShieldIngestConfig()
        self._shield_manager = self._build_shield_manager()
        self._ledger_writer = self._build_ledger_writer()

    @property
    def name(self) -> str:
        return "shield_ingest"

    @property
    def description(self) -> str:
        return "Shield alert ingestion and normalization"

    async def execute(self) -> None:
        if not self._shield_manager or not self._shield_manager.shields:
            self._log.info("shield_ingest_no_shields")
            return

        ledger_writer = None if self.config.dry_run else self._ledger_writer
        alerts = await self._shield_manager.ingest_alerts(ledger_writer)
        if ledger_writer:
            await ledger_writer.flush()

        if alerts:
            self._log.info(
                "shield_alerts_ingested",
                count=len(alerts),
                dry_run=self.config.dry_run,
            )

    def _build_shield_manager(self) -> "ShieldManager":
        from cyntra.trust.ledger.writer import JSONLSink, LedgerWriter
        from cyntra.core.manifests.schema import ShieldSpec
        from cyntra.trust.shields.defaults import register_default_shields
        from cyntra.trust.shields.manager import ShieldManager
        from cyntra.trust.shields.registry import get_registry

        register_default_shields()
        registry = get_registry()

        specs = list(self.ingest_config.shields)
        if not specs:
            specs = [ShieldSpec(name="file_alert_ingest", mode="ingest")]

        ctx = ShieldIngestContext(run_id="shield_ingest", working_dir=self.repo_root)
        shields = []

        for spec in specs:
            if spec.mode and spec.mode != "ingest":
                self._log.warning(
                    "shield_ingest_mode_mismatch",
                    shield=spec.name,
                    requested=spec.mode,
                )
                continue
            try:
                shield = registry.create(spec, ctx)
            except Exception as exc:
                self._log.warning(
                    "shield_ingest_build_failed",
                    shield=spec.name,
                    error=str(exc),
                )
                continue
            if getattr(shield, "mode", None) != "ingest":
                self._log.warning(
                    "shield_ingest_wrong_mode",
                    shield=spec.name,
                    mode=getattr(shield, "mode", None),
                )
                continue
            if not shield.enabled:
                continue
            shields.append(shield)

        return ShieldManager(shields)

    def _build_ledger_writer(self) -> "LedgerWriter | None":
        from cyntra.trust.ledger.writer import JSONLSink, LedgerWriter

        path_value = self.ingest_config.ledger_path
        if isinstance(path_value, str) and not path_value.strip():
            return None
        if path_value is None:
            path = self.repo_root / ".cyntra" / "logs" / "ledger.jsonl"
        else:
            path = Path(path_value)
            if not path.is_absolute():
                path = self.repo_root / path

        buffer_size = max(1, int(self.ingest_config.ledger_buffer_size))
        return LedgerWriter([JSONLSink(path, buffer_size=buffer_size)])


__all__ = [
    "ShieldIngestConfig",
    "ShieldIngestContext",
    "ShieldIngestSentinel",
]
