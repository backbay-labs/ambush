"""
Sentinel Protocol - Base Types and Abstract Base Class.

Provides the foundational types and BaseSentinel abstract class that all
sentinel implementations extend.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


class SentinelState(Enum):
    """Sentinel execution states."""

    IDLE = "idle"  # Waiting for next scheduled run
    RUNNING = "running"  # Currently executing
    PAUSED = "paused"  # Manually paused
    CIRCUIT_OPEN = "circuit_open"  # Too many failures, backing off


@dataclass
class SentinelSchedule:
    """Cron-style schedule configuration for a sentinel."""

    # Simple interval-based scheduling (cron expression support can be added later)
    interval_seconds: int = 3600  # Default: hourly
    run_on_startup: bool = False  # Run immediately when scheduler starts

    # Time windows (optional)
    only_during_idle: bool = True  # Only run when kernel is idle
    min_idle_seconds: int = 60  # Minimum idle time before running

    # Jitter to prevent thundering herd
    jitter_seconds: int = 30  # Random delay up to this amount


@dataclass
class SentinelConfig:
    """Configuration for sentinel behavior."""

    # Execution limits
    max_runtime_seconds: int = 300  # Kill if running longer than 5 min
    max_changes_per_run: int = 10  # Limit changes to prevent runaway

    # Circuit breaker for runaway sentinels
    failure_threshold: int = 3  # Open circuit after N consecutive failures
    circuit_reset_seconds: int = 1800  # 30 min before retrying after circuit opens

    # Dry run mode
    dry_run: bool = False  # Preview changes without applying

    # Audit settings
    audit_retention_days: int = 30  # How long to keep audit logs


@dataclass
class SentinelChange:
    """Record of a single change made by a sentinel."""

    change_type: str  # "bead_update", "doc_update", "memory_prune", etc.
    target: str  # What was changed (file path, bead ID, memory ID)
    description: str  # Human-readable description
    diff: str | None = None  # Optional diff of the change
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_type": self.change_type,
            "target": self.target,
            "description": self.description,
            "diff": self.diff,
            "timestamp": self.timestamp,
        }


@dataclass
class SentinelRunResult:
    """Result of a single sentinel execution."""

    sentinel_name: str
    started_at: float
    finished_at: float
    success: bool
    dry_run: bool
    changes: list[SentinelChange] = field(default_factory=list)
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        return self.finished_at - self.started_at

    @property
    def change_count(self) -> int:
        return len(self.changes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sentinel_name": self.sentinel_name,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "success": self.success,
            "dry_run": self.dry_run,
            "change_count": self.change_count,
            "changes": [c.to_dict() for c in self.changes],
            "error": self.error,
        }


@dataclass
class SentinelMetrics:
    """Tracking metrics for a sentinel."""

    total_runs: int = 0
    successful_runs: int = 0
    failed_runs: int = 0
    total_changes: int = 0
    consecutive_failures: int = 0
    last_run_at: float | None = None
    last_success_at: float | None = None
    circuit_opened_at: float | None = None

    def record_success(self, change_count: int) -> None:
        """Record a successful run."""
        self.total_runs += 1
        self.successful_runs += 1
        self.total_changes += change_count
        self.consecutive_failures = 0
        self.last_run_at = time.time()
        self.last_success_at = time.time()
        self.circuit_opened_at = None

    def record_failure(self) -> None:
        """Record a failed run."""
        self.total_runs += 1
        self.failed_runs += 1
        self.consecutive_failures += 1
        self.last_run_at = time.time()

    def open_circuit(self) -> None:
        """Open the circuit breaker."""
        self.circuit_opened_at = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_runs": self.total_runs,
            "successful_runs": self.successful_runs,
            "failed_runs": self.failed_runs,
            "success_rate": self.successful_runs / self.total_runs if self.total_runs > 0 else 0,
            "total_changes": self.total_changes,
            "consecutive_failures": self.consecutive_failures,
            "last_run_at": self.last_run_at,
            "last_success_at": self.last_success_at,
            "circuit_opened_at": self.circuit_opened_at,
        }


class SentinelMaxChangesError(Exception):
    """Raised when a sentinel exceeds max_changes_per_run."""
    pass


class BaseSentinel(ABC):
    """
    Base protocol for all sentinels.

    Subclasses must implement:
    - name: Unique identifier for this sentinel
    - description: Human-readable description
    - execute(): The main sentinel logic

    The base class provides:
    - Dry run support
    - Change tracking and audit trail
    - Circuit breaker integration
    - Metrics collection
    """

    def __init__(
        self,
        config: SentinelConfig | None = None,
        schedule: SentinelSchedule | None = None,
        repo_root: Path | None = None,
    ) -> None:
        self.config = config or SentinelConfig()
        self.schedule = schedule or SentinelSchedule()
        self.repo_root = repo_root or Path.cwd()
        self.metrics = SentinelMetrics()
        self.state = SentinelState.IDLE
        self._pending_changes: list[SentinelChange] = []
        self._log = logger.bind(sentinel=self.name)

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this sentinel."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this sentinel does."""
        ...

    @abstractmethod
    async def execute(self) -> None:
        """
        Main sentinel logic.

        Use self.propose_change() to record changes.
        In dry_run mode, changes are recorded but not applied.
        """
        ...

    def propose_change(
        self,
        change_type: str,
        target: str,
        description: str,
        diff: str | None = None,
    ) -> SentinelChange:
        """
        Propose a change to be made.

        In dry_run mode, changes are recorded but not applied.
        The sentinel should check self.config.dry_run before
        actually making modifications.

        Returns the change record for reference.
        """
        if len(self._pending_changes) >= self.config.max_changes_per_run:
            self._log.warning(
                "max_changes_reached",
                max_changes=self.config.max_changes_per_run,
            )
            raise SentinelMaxChangesError(
                f"Sentinel {self.name} exceeded max changes per run "
                f"({self.config.max_changes_per_run})"
            )

        change = SentinelChange(
            change_type=change_type,
            target=target,
            description=description,
            diff=diff,
        )
        self._pending_changes.append(change)

        self._log.info(
            "change_proposed",
            change_type=change_type,
            target=target,
            dry_run=self.config.dry_run,
        )

        return change

    async def run(self) -> SentinelRunResult:
        """
        Execute the sentinel with full lifecycle management.

        Handles:
        - State transitions
        - Timeout enforcement
        - Error handling
        - Metrics collection
        - Audit trail generation
        """
        # Check circuit breaker
        if self.state == SentinelState.CIRCUIT_OPEN and self.metrics.circuit_opened_at:
            elapsed = time.time() - self.metrics.circuit_opened_at
            if elapsed < self.config.circuit_reset_seconds:
                self._log.info(
                    "circuit_still_open",
                    remaining_seconds=self.config.circuit_reset_seconds - elapsed,
                )
                return SentinelRunResult(
                    sentinel_name=self.name,
                    started_at=time.time(),
                    finished_at=time.time(),
                    success=False,
                    dry_run=self.config.dry_run,
                    error="Circuit breaker open",
                )
            # Circuit timeout elapsed, try again
            self.state = SentinelState.IDLE

        started_at = time.time()
        self.state = SentinelState.RUNNING
        self._pending_changes = []

        try:
            # Run with timeout
            await asyncio.wait_for(
                self.execute(),
                timeout=self.config.max_runtime_seconds,
            )

            finished_at = time.time()
            self.metrics.record_success(len(self._pending_changes))
            self.state = SentinelState.IDLE

            result = SentinelRunResult(
                sentinel_name=self.name,
                started_at=started_at,
                finished_at=finished_at,
                success=True,
                dry_run=self.config.dry_run,
                changes=self._pending_changes.copy(),
            )

            self._log.info(
                "sentinel_completed",
                duration_seconds=result.duration_seconds,
                change_count=result.change_count,
                dry_run=self.config.dry_run,
            )

            return result

        except TimeoutError:
            finished_at = time.time()
            self.metrics.record_failure()
            self._check_circuit_breaker()

            self._log.error(
                "sentinel_timeout",
                max_runtime=self.config.max_runtime_seconds,
            )

            return SentinelRunResult(
                sentinel_name=self.name,
                started_at=started_at,
                finished_at=finished_at,
                success=False,
                dry_run=self.config.dry_run,
                changes=self._pending_changes.copy(),
                error=f"Timeout after {self.config.max_runtime_seconds}s",
            )

        except SentinelMaxChangesError as e:
            finished_at = time.time()
            self.metrics.record_failure()
            self._check_circuit_breaker()

            return SentinelRunResult(
                sentinel_name=self.name,
                started_at=started_at,
                finished_at=finished_at,
                success=False,
                dry_run=self.config.dry_run,
                changes=self._pending_changes.copy(),
                error=str(e),
            )

        except Exception as e:
            finished_at = time.time()
            self.metrics.record_failure()
            self._check_circuit_breaker()

            self._log.exception("sentinel_error", error=str(e))

            return SentinelRunResult(
                sentinel_name=self.name,
                started_at=started_at,
                finished_at=finished_at,
                success=False,
                dry_run=self.config.dry_run,
                changes=self._pending_changes.copy(),
                error=str(e),
            )

    def _check_circuit_breaker(self) -> None:
        """Check if circuit breaker should open."""
        if self.metrics.consecutive_failures >= self.config.failure_threshold:
            self._log.warning(
                "circuit_breaker_opened",
                consecutive_failures=self.metrics.consecutive_failures,
                threshold=self.config.failure_threshold,
            )
            self.state = SentinelState.CIRCUIT_OPEN
            self.metrics.open_circuit()


__all__ = [
    "SentinelState",
    "SentinelSchedule",
    "SentinelConfig",
    "SentinelChange",
    "SentinelRunResult",
    "SentinelMetrics",
    "SentinelMaxChangesError",
    "BaseSentinel",
]
