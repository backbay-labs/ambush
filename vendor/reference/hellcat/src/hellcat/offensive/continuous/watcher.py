"""
EngagementWatcher - Monitors targets and triggers re-engagements.

Ties together triggers, scheduler, differ, and history into the main
continuous engagement loop. Configurable via EngagementConfig + watch
options.
"""

from __future__ import annotations

import signal
import threading
import time
from dataclasses import dataclass
from typing import Any

import structlog

from hellcat.core.config.engagement import EngagementConfig
from hellcat.offensive.continuous.history import EngagementHistory
from hellcat.offensive.continuous.scheduler import ContinuousScheduler, SchedulerConfig
from hellcat.offensive.continuous.triggers import (
    GitTrigger,
    PollingTrigger,
    ScheduleTrigger,
    Trigger,
    WebhookTrigger,
)

logger = structlog.get_logger()


@dataclass
class WatchConfig:
    """Configuration for the EngagementWatcher."""

    trigger_type: str = "polling"  # polling | webhook | git | schedule
    interval_seconds: float = 3600.0
    webhook_port: int = 8080
    webhook_host: str = "0.0.0.0"
    git_repo_url: str = ""
    git_branch: str = "main"
    min_interval_seconds: float = 300.0
    max_cost_usd: float = 50.0
    quiet_hours_start: int | None = None
    quiet_hours_end: int | None = None
    history_db: str = ".hellcat/continuous.db"


class EngagementWatcher:
    """Main continuous engagement controller.

    Manages trigger lifecycle, processes change events, runs targeted
    re-engagements, and records history.

    Usage::

        config = EngagementConfig.from_yaml("engagement.yaml")
        watch_config = WatchConfig(trigger_type="polling", interval_seconds=3600)
        watcher = EngagementWatcher(config, watch_config)
        watcher.start()  # Blocks until SIGINT/SIGTERM
    """

    def __init__(
        self,
        engagement_config: EngagementConfig,
        watch_config: WatchConfig | None = None,
    ) -> None:
        self.engagement_config = engagement_config
        self.watch_config = watch_config or WatchConfig()

        # Build scheduler
        self.scheduler = ContinuousScheduler(SchedulerConfig(
            min_interval_seconds=self.watch_config.min_interval_seconds,
            max_cost_usd=self.watch_config.max_cost_usd,
            quiet_hours_start=self.watch_config.quiet_hours_start,
            quiet_hours_end=self.watch_config.quiet_hours_end,
        ))

        # Build history
        self.history = EngagementHistory(self.watch_config.history_db)

        # State
        self._trigger: Trigger | None = None
        self._shutdown_event = threading.Event()
        self._last_surface_fingerprint: str = ""
        self._change_history: list[dict[str, Any]] = []

    @property
    def running(self) -> bool:
        return self._trigger is not None and self._trigger.running

    def start(self) -> None:
        """Start the watcher. Blocks until shutdown signal received.

        Installs signal handlers for SIGINT/SIGTERM for graceful shutdown.
        """
        self._install_signal_handlers()

        trigger = self._create_trigger()
        trigger.on_change(self._on_change)
        self._trigger = trigger

        logger.info(
            "watcher.starting",
            target=self.engagement_config.target_url,
            trigger_type=self.watch_config.trigger_type,
            interval=self.watch_config.interval_seconds,
        )

        trigger.start()

        try:
            # Block until shutdown
            while not self._shutdown_event.is_set():
                self._shutdown_event.wait(1.0)

                # Check for pending runs that were deferred
                pending = self.scheduler.get_next_pending()
                if pending and self.scheduler.should_run(
                    pending.trigger_type, pending.trigger_data, pending.affected_urls
                ):
                    self._execute_reengagement(
                        pending.trigger_type, pending.trigger_data
                    )

        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop the watcher and clean up resources."""
        self._shutdown_event.set()
        if self._trigger:
            self._trigger.stop()
            self._trigger = None
        self.history.close()
        logger.info("watcher.stopped")

    def _on_change(self, trigger_type: str, trigger_data: dict[str, Any]) -> None:
        """Callback invoked by triggers when a change is detected."""
        logger.info(
            "watcher.change_detected",
            trigger_type=trigger_type,
        )

        self._change_history.append({
            "trigger_type": trigger_type,
            "trigger_data": trigger_data,
            "timestamp": time.time(),
        })

        if self.scheduler.should_run(trigger_type, trigger_data):
            self._execute_reengagement(trigger_type, trigger_data)

    def _execute_reengagement(
        self,
        trigger_type: str,
        trigger_data: dict[str, Any],
    ) -> None:
        """Execute a targeted re-engagement."""
        self.scheduler.record_run_start()

        run_id = self.history.record_run_start(trigger_type, trigger_data)

        logger.info(
            "watcher.reengagement_starting",
            run_id=run_id,
            trigger_type=trigger_type,
            target=self.engagement_config.target_url,
        )

        try:
            from hellcat.core.runner.engagement import EngagementRunner

            runner = EngagementRunner(self.engagement_config)
            result = runner.run()

            self.history.record_run_complete(
                run_id,
                vulns_found=result.vulns_found,
                cost_usd=result.summary.total_cost_usd if result.summary else 0.0,
            )
            self.scheduler.record_run_complete(
                cost_usd=result.summary.total_cost_usd if result.summary else 0.0,
            )

            logger.info(
                "watcher.reengagement_complete",
                run_id=run_id,
                vulns_found=result.vulns_found,
                success=result.success,
            )

        except Exception as exc:
            logger.error(
                "watcher.reengagement_error",
                run_id=run_id,
                error=str(exc),
            )
            self.history.record_run_complete(run_id, error=str(exc))
            self.scheduler.record_run_complete()

    def _create_trigger(self) -> Trigger:
        """Create a trigger instance based on watch config."""
        trigger_type = self.watch_config.trigger_type

        if trigger_type == "webhook":
            return WebhookTrigger(
                host=self.watch_config.webhook_host,
                port=self.watch_config.webhook_port,
            )
        elif trigger_type == "git":
            return GitTrigger(
                repo_url=self.watch_config.git_repo_url,
                branch=self.watch_config.git_branch,
                interval_seconds=self.watch_config.interval_seconds,
            )
        elif trigger_type == "schedule":
            return ScheduleTrigger(
                interval_seconds=self.watch_config.interval_seconds,
            )
        else:
            # Default: polling
            return PollingTrigger(
                url=self.engagement_config.target_url,
                interval_seconds=self.watch_config.interval_seconds,
            )

    def _install_signal_handlers(self) -> None:
        """Install SIGINT/SIGTERM handlers for graceful shutdown."""
        if threading.current_thread() is not threading.main_thread():
            return
        try:
            signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
        except (OSError, ValueError):
            pass

    def _handle_signal(self, signum: int, frame: Any) -> None:
        """Handle shutdown signal."""
        sig_name = signal.Signals(signum).name
        logger.warning("watcher.signal_received", signal=sig_name)
        self._shutdown_event.set()
