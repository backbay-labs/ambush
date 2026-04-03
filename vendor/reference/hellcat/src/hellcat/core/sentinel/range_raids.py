"""
Range Raids Sentinel - Periodic attack range evaluation loop.

Runs configured range raids on a schedule and produces receipts + packs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from hellcat.core.manifests.schema import create_drill_manifest
from hellcat.core.providers.base import ExecutionContext
from hellcat.core.providers.registry import get_provider
from hellcat.core.sentinel.base import BaseSentinel, SentinelConfig, SentinelSchedule
try:
    from hellcat.trust.primitives import finalize_run_artifacts
    from hellcat.trust.primitives.defense_pack import PackArtifact, build_pack
except ImportError:
    finalize_run_artifacts = None  # type: ignore[assignment]
    PackArtifact = None  # type: ignore[assignment,misc]
    build_pack = None  # type: ignore[assignment]

logger = structlog.get_logger()


@dataclass
class RangeRaidConfig:
    """Configuration for RangeRaidsSentinel."""

    targets: list[dict[str, Any]] = field(default_factory=list)
    runs_dir: str = ".hellcat/runs"
    run_id_prefix: str = "range"
    max_runs_per_cycle: int = 1
    emit_defense_packs: bool = True
    emit_detector_packs: bool = True
    provider_config: dict[str, Any] = field(default_factory=dict)
    splunk_hec: dict[str, Any] | None = None


class RangeRaidsSentinel(BaseSentinel):
    """Periodic range raid executor."""

    def __init__(
        self,
        config: SentinelConfig | None = None,
        schedule: SentinelSchedule | None = None,
        repo_root: Path | None = None,
        raid_config: RangeRaidConfig | None = None,
    ) -> None:
        super().__init__(config, schedule, repo_root)
        self.raid_config = raid_config or RangeRaidConfig()

    @property
    def name(self) -> str:
        return "range_raids"

    @property
    def description(self) -> str:
        return "Run scheduled attack range raids and produce receipts + packs"

    async def execute(self) -> None:
        if not self.raid_config.targets:
            self._log.info("no_range_targets_configured")
            return

        runs_dir = (self.repo_root / self.raid_config.runs_dir).resolve()
        runs_dir.mkdir(parents=True, exist_ok=True)

        max_runs = max(1, int(self.raid_config.max_runs_per_cycle))
        targets = self.raid_config.targets[:max_runs]

        for target in targets:
            await self._run_target(target, runs_dir)

    async def _run_target(self, target: dict[str, Any], runs_dir: Path) -> None:
        name = target.get("name") or target.get("template_id") or "range"
        slug = re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{self.raid_config.run_id_prefix}_{slug}_{timestamp}"
        run_dir = runs_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        template_path = target.get("range_template_path") or target.get("template_path")
        drill_path = target.get("drill_spec_path")

        manifest = create_drill_manifest(
            issue_id=f"raid.{slug}",
            title=f"Range Raid - {name}",
            description=target.get("description", "Scheduled range raid"),
            toolchain="attack_range",
        )
        manifest.provider_hint = "attack_range"
        manifest.task.tags = list(set((manifest.task.tags or []) + ["range-raid"]))
        manifest.metadata.update(target.get("manifest_metadata", {}))

        metadata: dict[str, Any] = {
            "range_template_path": template_path,
            "drill_spec_path": drill_path,
            "run_dir": str(run_dir),
            "deterministic": True,
        }
        if target.get("runtime"):
            metadata["runtime"] = target.get("runtime")
        if target.get("runtime_env"):
            metadata["runtime_env"] = target.get("runtime_env")
        if target.get("splunk_hec"):
            metadata["splunk_hec"] = target.get("splunk_hec")

        ctx = ExecutionContext(
            run_id=run_id,
            manifest=manifest,
            working_dir=run_dir,
            metadata=metadata,
        )

        provider_config = dict(self.raid_config.provider_config or {})
        provider_config.update(target.get("provider_config") or {})
        provider = get_provider("attack_range", config=provider_config, cached=False)

        result = await provider.execute(ctx)
        self._log.info(
            "range_raid_completed",
            run_id=run_id,
            status=result.status,
            exit_code=result.exit_code,
        )

        try:
            finalize_run_artifacts(run_dir)
        except Exception as exc:
            logger.warning("Failed to finalize run artifacts", run_id=run_id, error=str(exc))

        # Produce detector/defense packs (best-effort, after receipt exists)
        if self.raid_config.emit_detector_packs:
            build_pack(
                pack_id=f"detector_{slug}_{timestamp}",
                pack_type="detector",
                artifacts=[
                    PackArtifact(kind="detections", path="detections.json"),
                ],
                run_dir=run_dir,
            )
        if self.raid_config.emit_defense_packs:
            build_pack(
                pack_id=f"defense_{slug}_{timestamp}",
                pack_type="hardening_kit",
                artifacts=[
                    PackArtifact(kind="scorecard", path="scorecard.json"),
                ],
                run_dir=run_dir,
            )

        await self._export_to_splunk(run_dir, run_id, target)

    async def _export_to_splunk(
        self,
        run_dir: Path,
        run_id: str,
        target: dict[str, Any],
    ) -> None:
        config = target.get("splunk_hec") or self.raid_config.splunk_hec
        if not config:
            return
        try:
            from hellcat.infra.observability.splunk_hec import SplunkHECConfig, SplunkHECExporter

            exporter = SplunkHECExporter(SplunkHECConfig(**config))
            ground_truth = _read_json(run_dir / "ground_truth.json")
            detections = _read_json(run_dir / "detections.json")
            scorecard = _read_json(run_dir / "scorecard.json")
            await exporter.export_range_run(
                run_id=run_id,
                ground_truth=ground_truth,
                detections=detections,
                scorecard=scorecard,
                metadata={"target": target.get("name") or target.get("template_id")},
            )
        except Exception as exc:
            logger.warning("Splunk export failed", run_id=run_id, error=str(exc))


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
