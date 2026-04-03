"""
Sentinel Manager - Scheduling and lifecycle management for sentinels.

Provides SentinelScheduler for managing periodic execution of sentinels
and factory functions for creating schedulers from config.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from cyntra.core.sentinel.base import (
    BaseSentinel,
    SentinelConfig,
    SentinelRunResult,
    SentinelSchedule,
    SentinelState,
)

if TYPE_CHECKING:
    from cyntra.core.manifests.schema import ShieldSpec

logger = structlog.get_logger()


class SentinelScheduler:
    """
    Manages periodic execution of sentinels.

    Features:
    - Schedule multiple sentinels with different intervals
    - Respect idle-only constraints
    - Jitter to prevent thundering herd
    - Graceful shutdown
    """

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = repo_root or Path.cwd()
        self._sentinels: dict[str, BaseSentinel] = {}
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._log = logger.bind(component="SentinelScheduler")
        self._kernel_idle_since: float | None = None

    def register(self, sentinel: BaseSentinel) -> None:
        """Register a sentinel for scheduling."""
        if sentinel.name in self._sentinels:
            raise ValueError(f"Sentinel {sentinel.name} already registered")
        self._sentinels[sentinel.name] = sentinel
        self._log.info("sentinel_registered", name=sentinel.name)

    def unregister(self, name: str) -> None:
        """Unregister a sentinel."""
        if name in self._sentinels:
            del self._sentinels[name]
            self._log.info("sentinel_unregistered", name=name)

    def set_kernel_idle(self, idle: bool) -> None:
        """Notify scheduler of kernel idle state."""
        if idle and self._kernel_idle_since is None:
            self._kernel_idle_since = time.time()
        elif not idle:
            self._kernel_idle_since = None

    def _is_idle_long_enough(self, sentinel: BaseSentinel) -> bool:
        """Check if kernel has been idle long enough for this sentinel."""
        if not sentinel.schedule.only_during_idle:
            return True
        if self._kernel_idle_since is None:
            return False
        idle_duration = time.time() - self._kernel_idle_since
        return idle_duration >= sentinel.schedule.min_idle_seconds

    async def _run_sentinel_loop(self, sentinel: BaseSentinel) -> None:
        """Run loop for a single sentinel."""
        import random

        # Run on startup if configured
        if sentinel.schedule.run_on_startup:
            await sentinel.run()

        while self._running:
            # Wait for interval with jitter
            jitter = random.uniform(0, sentinel.schedule.jitter_seconds)
            await asyncio.sleep(sentinel.schedule.interval_seconds + jitter)

            if not self._running:
                break

            # Check idle constraint
            if not self._is_idle_long_enough(sentinel):
                self._log.debug(
                    "skipping_not_idle",
                    sentinel=sentinel.name,
                )
                continue

            # Run the sentinel
            await sentinel.run()

    async def start(self) -> None:
        """Start the scheduler."""
        if self._running:
            return

        self._running = True
        self._log.info("scheduler_starting", sentinel_count=len(self._sentinels))

        for sentinel in self._sentinels.values():
            task = asyncio.create_task(
                self._run_sentinel_loop(sentinel),
                name=f"sentinel_{sentinel.name}",
            )
            self._tasks.append(task)

    async def stop(self) -> None:
        """Stop the scheduler gracefully."""
        self._running = False
        self._log.info("scheduler_stopping")

        for task in self._tasks:
            task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        self._tasks.clear()
        self._log.info("scheduler_stopped")

    async def run_once(self, name: str) -> SentinelRunResult | None:
        """Run a specific sentinel immediately (bypasses schedule)."""
        sentinel = self._sentinels.get(name)
        if not sentinel:
            self._log.warning("sentinel_not_found", name=name)
            return None
        return await sentinel.run()

    async def run_all(self, dry_run: bool = True) -> list[SentinelRunResult]:
        """Run all sentinels immediately (useful for testing)."""
        results = []
        for sentinel in self._sentinels.values():
            # Temporarily set dry_run if requested
            original_dry_run = sentinel.config.dry_run
            if dry_run:
                sentinel.config.dry_run = True

            result = await sentinel.run()
            results.append(result)

            # Restore original setting
            sentinel.config.dry_run = original_dry_run

        return results

    def get_status(self) -> dict[str, Any]:
        """Get scheduler and sentinel status."""
        return {
            "running": self._running,
            "kernel_idle_since": self._kernel_idle_since,
            "sentinels": {
                name: {
                    "state": sentinel.state.value,
                    "description": sentinel.description,
                    "schedule_interval": sentinel.schedule.interval_seconds,
                    "metrics": sentinel.metrics.to_dict(),
                }
                for name, sentinel in self._sentinels.items()
            },
        }

    def should_run_any(self) -> bool:
        """
        Check if any sentinel is due to run.

        Returns True if at least one sentinel:
        - Is not in circuit-open state
        - Has passed its interval since last run
        - Meets idle constraints (if applicable)
        """
        now = time.time()

        for sentinel in self._sentinels.values():
            # Skip if circuit is open and not expired
            if (
                sentinel.state == SentinelState.CIRCUIT_OPEN
                and sentinel.metrics.circuit_opened_at
            ):
                elapsed = now - sentinel.metrics.circuit_opened_at
                if elapsed < sentinel.config.circuit_reset_seconds:
                    continue
                # Circuit timeout elapsed, can run

            # Check idle constraint
            if not self._is_idle_long_enough(sentinel):
                continue

            # Check if interval has passed
            if sentinel.metrics.last_run_at is None:
                # Never run, should run if run_on_startup or first check
                return True

            elapsed = now - sentinel.metrics.last_run_at
            if elapsed >= sentinel.schedule.interval_seconds:
                return True

        return False

    async def run_due_sentinels(
        self,
        filter_names: list[str] | None = None,
    ) -> list[SentinelRunResult]:
        """
        Run all sentinels that are due for execution.

        Args:
            filter_names: If provided, only run sentinels with these names

        Returns:
            List of results from sentinels that ran
        """
        results = []
        now = time.time()

        for name, sentinel in self._sentinels.items():
            # Apply name filter if provided
            if filter_names and name not in filter_names:
                continue

            # Skip if circuit is open and not expired
            if (
                sentinel.state == SentinelState.CIRCUIT_OPEN
                and sentinel.metrics.circuit_opened_at
            ):
                elapsed = now - sentinel.metrics.circuit_opened_at
                if elapsed < sentinel.config.circuit_reset_seconds:
                    self._log.debug(
                        "skipping_circuit_open",
                        sentinel=name,
                        remaining=sentinel.config.circuit_reset_seconds - elapsed,
                    )
                    continue

            # Check idle constraint
            if not self._is_idle_long_enough(sentinel):
                self._log.debug("skipping_not_idle_enough", sentinel=name)
                continue

            # Check if due (interval passed or never run)
            should_run = False
            if sentinel.metrics.last_run_at is None:
                should_run = True
            else:
                elapsed = now - sentinel.metrics.last_run_at
                if elapsed >= sentinel.schedule.interval_seconds:
                    should_run = True

            if should_run:
                self._log.info("running_due_sentinel", sentinel=name)
                result = await sentinel.run()
                results.append(result)

        return results

    def get_sentinel(self, name: str) -> BaseSentinel | None:
        """Get a registered sentinel by name."""
        return self._sentinels.get(name)


def create_sentinel_scheduler_from_config(
    sentinels_config: Any,
    repo_root: Path,
) -> SentinelScheduler:
    """
    Create a SentinelScheduler with sentinels configured from KernelConfig.

    Args:
        sentinels_config: SentinelsConfig from kernel config
        repo_root: Repository root path

    Returns:
        Configured SentinelScheduler with registered sentinels
    """
    # Import sentinel implementations here to avoid circular imports
    from cyntra.core.sentinel.bead_gardener import (
        BeadGardenerConfig,
        BeadGardenerSentinel,
    )
    from cyntra.core.sentinel.doc_sync import DocSyncConfig, DocSyncSentinel
    from cyntra.core.sentinel.memory_gardener import MemoryGardenerSentinel
    from cyntra.core.sentinel.security import SecurityConfig, SecuritySentinel
    from cyntra.core.sentinel.shield_ingest import (
        ShieldIngestConfig,
        ShieldIngestSentinel,
    )
    from cyntra.core.sentinel.range_raids import RangeRaidConfig, RangeRaidsSentinel
    from cyntra.core.manifests.schema import ShieldSpec

    scheduler = SentinelScheduler(repo_root=repo_root)

    if not sentinels_config.enabled:
        logger.info("sentinels_disabled")
        return scheduler

    # Global config defaults
    global_dry_run = sentinels_config.dry_run
    global_max_runtime = sentinels_config.max_runtime_seconds
    global_max_changes = sentinels_config.max_changes_per_run

    def _build_sentinel_config(sentinel_data: dict) -> SentinelConfig:
        """Build SentinelConfig from per-sentinel config dict."""
        config_data = sentinel_data.get("config", {})
        return SentinelConfig(
            max_runtime_seconds=config_data.get("max_runtime_seconds", global_max_runtime),
            max_changes_per_run=config_data.get("max_changes_per_run", global_max_changes),
            failure_threshold=config_data.get("failure_threshold", 3),
            circuit_reset_seconds=config_data.get("circuit_reset_seconds", 1800),
            dry_run=config_data.get("dry_run", global_dry_run),
        )

    def _build_schedule(sentinel_data: dict) -> SentinelSchedule:
        """Build SentinelSchedule from per-sentinel config dict."""
        schedule_data = sentinel_data.get("schedule", {})
        return SentinelSchedule(
            interval_seconds=schedule_data.get("interval_seconds", 3600),
            run_on_startup=schedule_data.get("run_on_startup", False),
            only_during_idle=schedule_data.get("only_during_idle", True),
            min_idle_seconds=schedule_data.get("min_idle_seconds", 60),
            jitter_seconds=schedule_data.get("jitter_seconds", 30),
        )

    # BeadGardener
    bead_gardener_data = sentinels_config.bead_gardener or {}
    if bead_gardener_data.get("enabled", True):
        gardener_cfg_data = bead_gardener_data.get("gardener_config", {})
        gardener_config = BeadGardenerConfig(
            stale_days_threshold=gardener_cfg_data.get("stale_days_threshold", 14),
            warn_days_threshold=gardener_cfg_data.get("warn_days_threshold", 7),
            events_lookback_hours=gardener_cfg_data.get("events_lookback_hours", 24),
            check_orphaned_beads=gardener_cfg_data.get("check_orphaned_beads", True),
            check_stale_beads=gardener_cfg_data.get("check_stale_beads", True),
            check_dependency_graph=gardener_cfg_data.get("check_dependency_graph", True),
            check_ready_promotions=gardener_cfg_data.get("check_ready_promotions", True),
            check_completed_updates=gardener_cfg_data.get("check_completed_updates", True),
        )
        scheduler.register(
            BeadGardenerSentinel(
                config=_build_sentinel_config(bead_gardener_data),
                schedule=_build_schedule(bead_gardener_data),
                repo_root=repo_root,
                gardener_config=gardener_config,
            )
        )

    # DocSync
    doc_sync_data = sentinels_config.doc_sync or {}
    if doc_sync_data.get("enabled", True):
        doc_cfg_data = doc_sync_data.get("doc_config", {})
        doc_config = DocSyncConfig(
            check_directory_structure=doc_cfg_data.get("check_directory_structure", True),
            check_file_references=doc_cfg_data.get("check_file_references", True),
            check_mise_version_sync=doc_cfg_data.get("check_mise_version_sync", True),
            check_mise_task_sync=doc_cfg_data.get("check_mise_task_sync", True),
            check_module_existence=doc_cfg_data.get("check_module_existence", True),
            check_dead_doc_links=doc_cfg_data.get("check_dead_doc_links", True),
            expected_directories=doc_cfg_data.get("expected_directories", DocSyncConfig().expected_directories),
            expected_files=doc_cfg_data.get("expected_files", DocSyncConfig().expected_files),
            expected_modules=doc_cfg_data.get("expected_modules", DocSyncConfig().expected_modules),
        )
        scheduler.register(
            DocSyncSentinel(
                config=_build_sentinel_config(doc_sync_data),
                doc_config=doc_config,
                schedule=_build_schedule(doc_sync_data),
                repo_root=repo_root,
            )
        )

    # Security
    security_data = sentinels_config.security or {}
    if security_data.get("enabled", True):
        sec_cfg_data = security_data.get("security_config", {})
        security_config = SecurityConfig(
            check_secrets=sec_cfg_data.get("check_secrets", True),
            check_insecure_patterns=sec_cfg_data.get("check_insecure_patterns", True),
            check_sensitive_files=sec_cfg_data.get("check_sensitive_files", True),
            check_hardcoded_credentials=sec_cfg_data.get("check_hardcoded_credentials", True),
            scan_directories=sec_cfg_data.get("scan_directories", SecurityConfig().scan_directories),
            exclude_patterns=sec_cfg_data.get("exclude_patterns", SecurityConfig().exclude_patterns),
            sensitive_file_patterns=sec_cfg_data.get("sensitive_file_patterns", SecurityConfig().sensitive_file_patterns),
            max_file_size=sec_cfg_data.get("max_file_size", 1_000_000),
        )
        scheduler.register(
            SecuritySentinel(
                config=_build_sentinel_config(security_data),
                security_config=security_config,
                schedule=_build_schedule(security_data),
                repo_root=repo_root,
            )
        )

    # ShieldIngest
    shield_ingest_data = sentinels_config.shield_ingest or {}
    if shield_ingest_data.get("enabled", True):
        ingest_cfg_data = shield_ingest_data.get("shield_ingest_config", {})
        shields: list[ShieldSpec] = []
        shields_data = ingest_cfg_data.get("shields", [])
        if isinstance(shields_data, list):
            for spec in shields_data:
                if isinstance(spec, ShieldSpec):
                    shields.append(spec)
                elif isinstance(spec, dict):
                    shields.append(ShieldSpec.from_dict(spec))

        ingest_config = ShieldIngestConfig(
            ledger_path=ingest_cfg_data.get("ledger_path"),
            ledger_buffer_size=int(ingest_cfg_data.get("ledger_buffer_size", 10)),
            shields=shields,
        )
        scheduler.register(
            ShieldIngestSentinel(
                config=_build_sentinel_config(shield_ingest_data),
                ingest_config=ingest_config,
                schedule=_build_schedule(shield_ingest_data),
                repo_root=repo_root,
            )
        )

    # RangeRaids
    range_raids_data = sentinels_config.range_raids or {}
    if range_raids_data.get("enabled", False):
        raid_cfg_data = range_raids_data.get("raid_config", {})
        raid_config = RangeRaidConfig(
            targets=raid_cfg_data.get("targets", []),
            runs_dir=raid_cfg_data.get("runs_dir", ".cyntra/runs"),
            run_id_prefix=raid_cfg_data.get("run_id_prefix", "range"),
            max_runs_per_cycle=raid_cfg_data.get("max_runs_per_cycle", 1),
            emit_defense_packs=raid_cfg_data.get("emit_defense_packs", True),
            emit_detector_packs=raid_cfg_data.get("emit_detector_packs", True),
            provider_config=raid_cfg_data.get("provider_config", {}),
            splunk_hec=raid_cfg_data.get("splunk_hec"),
        )
        scheduler.register(
            RangeRaidsSentinel(
                config=_build_sentinel_config(range_raids_data),
                schedule=_build_schedule(range_raids_data),
                repo_root=repo_root,
                raid_config=raid_config,
            )
        )

    # MemoryGardener
    memory_gardener_data = sentinels_config.memory_gardener or {}
    if memory_gardener_data.get("enabled", False):  # Disabled by default (stub)
        scheduler.register(
            MemoryGardenerSentinel(
                config=_build_sentinel_config(memory_gardener_data),
                schedule=_build_schedule(memory_gardener_data),
                repo_root=repo_root,
            )
        )

    logger.info(
        "sentinel_scheduler_created",
        registered_count=len(scheduler._sentinels),
        sentinels=list(scheduler._sentinels.keys()),
    )

    return scheduler


__all__ = [
    "SentinelScheduler",
    "create_sentinel_scheduler_from_config",
]
