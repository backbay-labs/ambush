"""
ContinuousScheduler - Manages timing and prioritization of re-engagements.

Handles:
- Minimum interval enforcement between runs
- Quiet hours (no runs during specified time windows)
- Cost budget enforcement (total USD limit)
- Priority queue: critical changes run before low-priority ones
- Dedup: collapses rapid successive triggers into a single run
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import UTC
from enum import IntEnum
from typing import Any

import structlog

logger = structlog.get_logger()


class ChangePriority(IntEnum):
    """Priority levels for change-triggered re-engagements."""

    CRITICAL = 1   # New auth endpoints, security config changes
    HIGH = 2       # New API endpoints, tech stack changes
    NORMAL = 3     # Content changes, minor updates
    LOW = 4        # Static content, cosmetic changes


@dataclass
class PendingRun:
    """A queued re-engagement waiting to be dispatched."""

    trigger_type: str
    trigger_data: dict[str, Any]
    priority: ChangePriority
    queued_at: float
    affected_urls: list[str] = field(default_factory=list)


@dataclass
class SchedulerConfig:
    """Configuration for the ContinuousScheduler."""

    min_interval_seconds: float = 300.0    # 5 minutes between runs
    max_cost_usd: float = 50.0             # Total cost budget
    quiet_hours_start: int | None = None   # Hour (0-23) to start quiet period
    quiet_hours_end: int | None = None     # Hour (0-23) to end quiet period
    dedup_window_seconds: float = 30.0     # Collapse triggers within this window


class ContinuousScheduler:
    """Manages scheduling and deduplication of continuous re-engagements.

    Usage::

        scheduler = ContinuousScheduler(config)
        if scheduler.should_run(trigger_type, trigger_data, affected_urls):
            # Run re-engagement
            scheduler.record_run_start()
            # ... execute ...
            scheduler.record_run_complete(cost_usd=0.50)
    """

    def __init__(self, config: SchedulerConfig | None = None) -> None:
        self.config = config or SchedulerConfig()
        self._last_run_time: float = 0.0
        self._total_cost_usd: float = 0.0
        self._pending: list[PendingRun] = []
        self._lock = threading.Lock()
        self._run_count: int = 0

    @property
    def total_cost_usd(self) -> float:
        return self._total_cost_usd

    @property
    def run_count(self) -> int:
        return self._run_count

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def should_run(
        self,
        trigger_type: str,
        trigger_data: dict[str, Any],
        affected_urls: list[str] | None = None,
    ) -> bool:
        """Determine whether a re-engagement should proceed.

        Checks:
        1. Budget not exceeded
        2. Minimum interval respected
        3. Not in quiet hours
        4. Not a duplicate trigger (dedup window)

        Args:
            trigger_type: Type of trigger that fired.
            trigger_data: Data from the trigger event.
            affected_urls: URLs affected by the change.

        Returns:
            True if the re-engagement should proceed now.
        """
        now = time.time()

        # Check cost budget
        if self._total_cost_usd >= self.config.max_cost_usd:
            logger.warning(
                "scheduler.budget_exceeded",
                total_cost=self._total_cost_usd,
                max_cost=self.config.max_cost_usd,
            )
            return False

        # Check minimum interval
        elapsed = now - self._last_run_time
        if self._last_run_time > 0 and elapsed < self.config.min_interval_seconds:
            logger.info(
                "scheduler.too_soon",
                elapsed_s=int(elapsed),
                min_interval=self.config.min_interval_seconds,
            )
            # Queue for later instead of dropping
            self._enqueue(trigger_type, trigger_data, affected_urls or [], now)
            return False

        # Check quiet hours
        if self._in_quiet_hours():
            logger.info("scheduler.quiet_hours")
            self._enqueue(trigger_type, trigger_data, affected_urls or [], now)
            return False

        # Check dedup window
        if self._is_duplicate(trigger_type, trigger_data, now):
            logger.info("scheduler.dedup_collapsed", trigger_type=trigger_type)
            return False

        return True

    def get_next_pending(self) -> PendingRun | None:
        """Get the highest-priority pending run, removing it from the queue.

        Returns:
            The highest-priority PendingRun, or None if the queue is empty.
        """
        with self._lock:
            if not self._pending:
                return None
            # Sort by priority (lower = higher priority), then by queue time
            self._pending.sort(key=lambda r: (r.priority, r.queued_at))
            return self._pending.pop(0)

    def record_run_start(self) -> None:
        """Record that a re-engagement run has started."""
        self._last_run_time = time.time()
        self._run_count += 1

    def record_run_complete(self, cost_usd: float = 0.0) -> None:
        """Record that a re-engagement run has completed.

        Args:
            cost_usd: Cost of the completed run.
        """
        self._total_cost_usd += cost_usd
        logger.info(
            "scheduler.run_complete",
            run_number=self._run_count,
            cost_usd=cost_usd,
            total_cost=self._total_cost_usd,
        )

    def classify_priority(
        self,
        trigger_type: str,
        trigger_data: dict[str, Any],
        affected_urls: list[str] | None = None,
    ) -> ChangePriority:
        """Classify the priority of a change based on trigger data.

        Args:
            trigger_type: Type of trigger.
            trigger_data: Data from the trigger.
            affected_urls: URLs affected by the change.

        Returns:
            ChangePriority level.
        """
        urls = affected_urls or []

        # Auth/security changes are critical
        security_patterns = ("auth", "login", "oauth", "security", "admin", "api/key")
        for url in urls:
            lower = url.lower()
            if any(p in lower for p in security_patterns):
                return ChangePriority.CRITICAL

        # New tech stack or multiple changes = high
        if trigger_data.get("new_tech_stacks"):
            return ChangePriority.HIGH
        if len(urls) > 5:
            return ChangePriority.HIGH

        # Git trigger with code changes = high
        if trigger_type == "git":
            return ChangePriority.HIGH

        # Webhook = normal (depends on content)
        if trigger_type == "webhook":
            return ChangePriority.NORMAL

        # Schedule = low (routine check)
        if trigger_type == "schedule":
            return ChangePriority.LOW

        return ChangePriority.NORMAL

    def _enqueue(
        self,
        trigger_type: str,
        trigger_data: dict[str, Any],
        affected_urls: list[str],
        now: float,
    ) -> None:
        """Add a run to the pending queue."""
        priority = self.classify_priority(trigger_type, trigger_data, affected_urls)
        with self._lock:
            self._pending.append(PendingRun(
                trigger_type=trigger_type,
                trigger_data=trigger_data,
                priority=priority,
                queued_at=now,
                affected_urls=affected_urls,
            ))

    def _in_quiet_hours(self) -> bool:
        """Check if the current time falls within quiet hours."""
        start = self.config.quiet_hours_start
        end = self.config.quiet_hours_end
        if start is None or end is None:
            return False

        from datetime import datetime
        current_hour = datetime.now(UTC).hour

        if start <= end:
            return start <= current_hour < end
        else:
            # Wraps midnight (e.g., 22:00 -> 06:00)
            return current_hour >= start or current_hour < end

    def _is_duplicate(
        self,
        trigger_type: str,
        trigger_data: dict[str, Any],
        now: float,
    ) -> bool:
        """Check if this trigger is a duplicate of a recent pending run."""
        with self._lock:
            for pending in self._pending:
                time_diff = now - pending.queued_at
                if (
                    time_diff < self.config.dedup_window_seconds
                    and pending.trigger_type == trigger_type
                ):
                    # Collapse: update the existing pending run
                    pending.trigger_data.update(trigger_data)
                    pending.queued_at = now
                    return True
        return False
