"""
Ephemeral state for running issues - stored in gitignored .hellcat/state/.

This module tracks transient "running" status separately from the canonical
.hellcat/issues.jsonl file to prevent git dirty state during kernel execution.

Key principles from Aegis architecture:
- Ephemeral state lives in gitignored space (.hellcat/)
- Canonical state (.hellcat/) only changes on terminal transitions (done, failed)
- Memory context injection instead of shared writeable state
- Atomic file writes with locking
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


@dataclass
class RunningIssue:
    """Tracks a currently running issue."""

    issue_id: str
    workcell_id: str
    started_at: datetime
    toolchain: str | None = None
    speculate_tag: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "workcell_id": self.workcell_id,
            "started_at": self.started_at.isoformat() + "Z",
            "toolchain": self.toolchain,
            "speculate_tag": self.speculate_tag,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RunningIssue:
        started_at = data.get("started_at", "")
        try:
            parsed_time = datetime.fromisoformat(str(started_at).rstrip("Z"))
        except (ValueError, TypeError):
            parsed_time = _utc_now()

        return cls(
            issue_id=data["issue_id"],
            workcell_id=data["workcell_id"],
            started_at=parsed_time,
            toolchain=data.get("toolchain"),
            speculate_tag=data.get("speculate_tag"),
        )


@dataclass
class EphemeralState:
    """
    Manages ephemeral running state in gitignored .hellcat/state/.

    This prevents the kernel from dirtying .hellcat/issues.jsonl when
    marking issues as "running", which was causing merge conflicts.

    State is recovered from workcell presence on kernel restart.
    """

    state_dir: Path
    _running: dict[str, RunningIssue] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _loaded: bool = False

    def __post_init__(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._running_path = self.state_dir / "running.json"
        self._lock_path = self.state_dir / "running.lock"

    @classmethod
    def create(cls, hellcat_dir: Path) -> EphemeralState:
        """Create EphemeralState for the given .hellcat directory."""
        state_dir = hellcat_dir / "state"
        return cls(state_dir=state_dir)

    def _acquire_file_lock(self, timeout: float = 30.0) -> Any:
        """
        Acquire file lock for atomic operations with timeout.

        Args:
            timeout: Maximum time to wait for lock acquisition (seconds)

        Returns:
            The lock file handle

        Raises:
            TimeoutError: If lock cannot be acquired within timeout
        """
        import fcntl
        import time

        self._lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = open(self._lock_path, "w")  # noqa: SIM115

        start_time = time.monotonic()
        while True:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return lock_file
            except BlockingIOError as exc:
                if time.monotonic() - start_time >= timeout:
                    lock_file.close()
                    raise TimeoutError(
                        f"Failed to acquire file lock after {timeout}s: {self._lock_path}"
                    ) from exc
                time.sleep(0.1)

    def _release_file_lock(self, lock_file: Any) -> None:
        """Release file lock."""
        import fcntl

        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()

    def _load(self) -> None:
        """Load running state from disk."""
        if self._loaded:
            return

        with self._lock:
            if self._running_path.exists():
                try:
                    with open(self._running_path) as f:
                        data = json.load(f)
                    self._running = {
                        k: RunningIssue.from_dict(v) for k, v in data.items()
                    }
                    logger.debug(
                        "Loaded ephemeral running state",
                        count=len(self._running),
                    )
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning(
                        "Failed to load ephemeral state, starting fresh",
                        error=str(e),
                    )
                    self._running = {}
            self._loaded = True

    def _save(self) -> None:
        """Save running state to disk atomically."""
        data = {k: v.to_dict() for k, v in self._running.items()}

        # Atomic write: write to temp, then rename
        tmp_path = self._running_path.with_suffix(".tmp")
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)

        # Atomic rename
        tmp_path.rename(self._running_path)

    def mark_running(
        self,
        issue_id: str,
        workcell_id: str,
        toolchain: str | None = None,
        speculate_tag: str | None = None,
    ) -> None:
        """
        Mark an issue as running.

        This does NOT modify .hellcat/issues.jsonl - only ephemeral state.
        """
        self._load()

        lock_file = self._acquire_file_lock()
        try:
            with self._lock:
                self._running[issue_id] = RunningIssue(
                    issue_id=issue_id,
                    workcell_id=workcell_id,
                    started_at=_utc_now(),
                    toolchain=toolchain,
                    speculate_tag=speculate_tag,
                )
                self._save()

            logger.info(
                "Marked issue as running (ephemeral)",
                issue_id=issue_id,
                workcell_id=workcell_id,
            )
        finally:
            self._release_file_lock(lock_file)

    def mark_complete(self, issue_id: str) -> RunningIssue | None:
        """
        Mark an issue as no longer running.

        Returns the RunningIssue data if it was tracked, None otherwise.
        """
        self._load()

        lock_file = self._acquire_file_lock()
        try:
            with self._lock:
                running = self._running.pop(issue_id, None)
                if running:
                    self._save()
                    logger.info(
                        "Marked issue as complete (ephemeral)",
                        issue_id=issue_id,
                        workcell_id=running.workcell_id,
                    )
                return running
        finally:
            self._release_file_lock(lock_file)

    def get_running(self, issue_id: str) -> RunningIssue | None:
        """Get running info for an issue, or None if not running."""
        self._load()
        with self._lock:
            return self._running.get(issue_id)

    def is_running(self, issue_id: str) -> bool:
        """Check if an issue is currently running."""
        return self.get_running(issue_id) is not None

    def get_all_running(self) -> dict[str, RunningIssue]:
        """Get all currently running issues."""
        self._load()
        with self._lock:
            return dict(self._running)

    def get_running_count(self) -> int:
        """Get count of running issues."""
        self._load()
        with self._lock:
            return len(self._running)

    def get_running_for_workcell(self, workcell_id: str) -> RunningIssue | None:
        """Get running issue for a specific workcell."""
        self._load()
        with self._lock:
            for running in self._running.values():
                if running.workcell_id == workcell_id:
                    return running
            return None

    def cleanup_stale(self, active_workcell_ids: set[str]) -> list[str]:
        """
        Remove running entries for workcells that no longer exist.

        This recovers from crashed kernels where ephemeral state wasn't cleaned up.

        Args:
            active_workcell_ids: Set of currently active workcell IDs

        Returns:
            List of issue IDs that were cleaned up
        """
        self._load()

        cleaned = []
        lock_file = self._acquire_file_lock()
        try:
            with self._lock:
                stale_ids = [
                    issue_id
                    for issue_id, running in self._running.items()
                    if running.workcell_id not in active_workcell_ids
                ]

                for issue_id in stale_ids:
                    del self._running[issue_id]
                    cleaned.append(issue_id)

                if cleaned:
                    self._save()
                    logger.info(
                        "Cleaned up stale running entries",
                        cleaned_count=len(cleaned),
                        issue_ids=cleaned,
                    )

                return cleaned
        finally:
            self._release_file_lock(lock_file)

    def clear(self) -> None:
        """Clear all running state (for testing or reset)."""
        lock_file = self._acquire_file_lock()
        try:
            with self._lock:
                self._running.clear()
                self._save()
                logger.info("Cleared all ephemeral running state")
        finally:
            self._release_file_lock(lock_file)

    def recover_from_workcells(self, workcells_dir: Path) -> int:
        """
        Recover running state from existing workcell directories.

        This is useful after a kernel crash to restore the running state
        based on which workcells still exist.

        Args:
            workcells_dir: Path to .workcells directory

        Returns:
            Number of running entries recovered
        """
        if not workcells_dir.exists():
            return 0

        recovered = 0
        lock_file = self._acquire_file_lock()
        try:
            with self._lock:
                for wc_dir in workcells_dir.iterdir():
                    if not wc_dir.is_dir() or wc_dir.name.startswith("."):
                        continue

                    manifest_path = wc_dir / "manifest.json"
                    if not manifest_path.exists():
                        continue

                    try:
                        with open(manifest_path) as f:
                            manifest = json.load(f)

                        issue_id = manifest.get("issue_id")
                        workcell_id = manifest.get("workcell_id", wc_dir.name)

                        if issue_id and issue_id not in self._running:
                            self._running[issue_id] = RunningIssue(
                                issue_id=issue_id,
                                workcell_id=workcell_id,
                                started_at=_utc_now(),
                                toolchain=manifest.get("toolchain"),
                            )
                            recovered += 1
                    except (json.JSONDecodeError, KeyError):
                        continue

                if recovered:
                    self._save()
                    logger.info(
                        "Recovered running state from workcells",
                        recovered_count=recovered,
                    )

                return recovered
        finally:
            self._release_file_lock(lock_file)
