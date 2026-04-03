"""
StateManager - Atomic read/write operations for Beads state.

Responsibilities:
- Read issues and dependencies from Beads
- Update issue status atomically
- Create new issues (e.g., fix issues)
- Add dependency edges
- Log events for observability

Supports two modes:
1. bd CLI (preferred) - uses Beads CLI commands
2. Direct file parsing (fallback) - reads .hellcat/*.jsonl files directly

File Locking:
- Uses fcntl.flock() on Unix for cross-process file locking
- Prevents concurrent writes from multiple kernel instances
- Lock files are stored alongside data files with .lock suffix
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import threading
import time
from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
import yaml

from hellcat.core.state.ephemeral import EphemeralState
from hellcat.core.state.models import BeadsGraph, Dep, Issue, VersionConflictError

# =============================================================================
# File Locking Utilities
# =============================================================================


class FileLock:
    """
    Cross-platform file locking for preventing concurrent writes.

    Uses fcntl.flock() on Unix, msvcrt.locking() on Windows.
    Provides both exclusive (write) and shared (read) locks.
    """

    def __init__(self, lock_path: Path, timeout: float = 30.0) -> None:
        """
        Initialize a file lock.

        Args:
            lock_path: Path to the lock file (will be created if needed)
            timeout: Maximum time to wait for lock acquisition (seconds)
        """
        self.lock_path = lock_path
        self.timeout = timeout
        self._lock_file: Any = None
        self._thread_lock = threading.Lock()

    def _acquire_unix(self, exclusive: bool = True) -> bool:
        """Acquire lock on Unix using fcntl.flock()."""
        import fcntl
        import time

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_file = open(self.lock_path, "w")  # noqa: SIM115

        lock_type = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        start_time = time.monotonic()

        while True:
            try:
                fcntl.flock(self._lock_file.fileno(), lock_type | fcntl.LOCK_NB)
                return True
            except BlockingIOError:
                if time.monotonic() - start_time >= self.timeout:
                    self._lock_file.close()
                    self._lock_file = None
                    return False
                time.sleep(0.1)

    def _acquire_windows(self, exclusive: bool = True) -> bool:
        """Acquire lock on Windows using msvcrt.locking()."""
        import msvcrt
        import time

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_file = open(self.lock_path, "w")  # noqa: SIM115

        lock_type = msvcrt.LK_NBLCK if exclusive else msvcrt.LK_NBRLCK
        start_time = time.monotonic()

        while True:
            try:
                msvcrt.locking(self._lock_file.fileno(), lock_type, 1)
                return True
            except OSError:
                if time.monotonic() - start_time >= self.timeout:
                    self._lock_file.close()
                    self._lock_file = None
                    return False
                time.sleep(0.1)

    def acquire(self, exclusive: bool = True) -> bool:
        """
        Acquire the file lock.

        Args:
            exclusive: If True, acquire exclusive (write) lock.
                      If False, acquire shared (read) lock.

        Returns:
            True if lock acquired, False if timeout.
        """
        with self._thread_lock:
            if self._lock_file is not None:
                return True  # Already locked

            if os.name == "nt":
                return self._acquire_windows(exclusive)
            else:
                return self._acquire_unix(exclusive)

    def release(self) -> None:
        """Release the file lock."""
        with self._thread_lock:
            if self._lock_file is not None:
                try:
                    if os.name == "nt":
                        import msvcrt
                        with contextlib.suppress(OSError):
                            msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                finally:
                    self._lock_file.close()
                    self._lock_file = None

    @contextlib.contextmanager
    def locked(self, exclusive: bool = True) -> Generator[bool, None, None]:
        """
        Context manager for file locking.

        Args:
            exclusive: If True, acquire exclusive lock.

        Yields:
            True if lock acquired, False if timeout.

        Example:
            with lock.locked() as acquired:
                if acquired:
                    # Do protected work
                else:
                    # Handle lock failure
        """
        acquired = self.acquire(exclusive)
        try:
            yield acquired
        finally:
            if acquired:
                self.release()


class LockManager:
    """
    Manages file locks for StateManager operations.

    Provides named locks for different resources (issues, deps, events).
    """

    def __init__(self, locks_dir: Path) -> None:
        self.locks_dir = locks_dir
        self._locks: dict[str, FileLock] = {}

    def get_lock(self, name: str, timeout: float = 30.0) -> FileLock:
        """Get or create a lock for the given resource name."""
        if name not in self._locks:
            lock_path = self.locks_dir / f"{name}.lock"
            self._locks[name] = FileLock(lock_path, timeout)
        return self._locks[name]

    @contextlib.contextmanager
    def lock(
        self, name: str, exclusive: bool = True, timeout: float = 30.0
    ) -> Generator[bool, None, None]:
        """
        Context manager for locking a named resource.

        Args:
            name: Resource name (e.g., "issues", "deps", "events")
            exclusive: If True, acquire exclusive lock.
            timeout: Maximum wait time in seconds.

        Yields:
            True if lock acquired, False if timeout.
        """
        file_lock = self.get_lock(name, timeout)
        with file_lock.locked(exclusive) as acquired:
            yield acquired


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


if TYPE_CHECKING:
    from hellcat.core.scheduler.routing import KernelConfig

logger = structlog.get_logger()

# Whitelist of allowed field names for CLI updates to prevent injection
ALLOWED_ISSUE_FIELDS = frozenset({
    "dk_attempts",
    "dk_priority",
    "dk_risk",
    "dk_size",
    "dk_tool_hint",
    "dk_complexity",
    "dk_owner",
    "dk_tags",
    "description",
    "title",
    "assignee",
    "labels",
})


class StateManager:
    """
    Manages Beads state with atomic operations.

    Supports both bd CLI and direct file access modes.

    Features:
    - File locking for concurrent access protection
    - BeadsGraph caching with TTL and mtime validation
    - Optimistic locking with version field
    """

    # Default cache TTL in seconds (5 seconds for watch mode responsiveness)
    DEFAULT_CACHE_TTL = 5.0

    def __init__(
        self,
        config: KernelConfig | None = None,
        repo_root: Path | None = None,
        cache_ttl: float | None = None,
    ) -> None:
        if config:
            self.repo_root = config.repo_root
            self.config = config
        elif repo_root:
            self.repo_root = repo_root
            self.config = None
        else:
            self.repo_root = Path.cwd()
            self.config = None

        if self.config:
            self.hellcat_dir = self.config.hellcat_path
            self.logs_dir = self.config.logs_dir
        else:
            self.hellcat_dir = self.repo_root / ".hellcat"
            self.logs_dir = self.repo_root / ".hellcat" / "logs"
        self._bd_available: bool | None = None

        # File locking for concurrent access protection
        locks_dir = self.repo_root / ".hellcat" / "locks"
        self._lock_manager = LockManager(locks_dir)

        # Graph cache for performance (10-40x speedup in watch mode)
        self._cache_ttl = cache_ttl if cache_ttl is not None else self.DEFAULT_CACHE_TTL
        self._cached_graph: BeadsGraph | None = None
        self._cache_timestamp: float = 0.0
        self._cache_mtime: float = 0.0

        # Ephemeral state for running issues (gitignored, prevents dirty repo)
        hellcat_dir = self.repo_root / ".hellcat"
        self._ephemeral = EphemeralState.create(hellcat_dir)

    @property
    def bd_available(self) -> bool:
        """Check if bd CLI is available."""
        if self._bd_available is None:
            self._bd_available = shutil.which("bd") is not None
        return self._bd_available

    @property
    def ephemeral(self) -> EphemeralState:
        """Access ephemeral state for running issues."""
        return self._ephemeral

    def get_running_count(self) -> int:
        """Get count of currently running issues from ephemeral state."""
        return self._ephemeral.get_running_count()

    def is_issue_running(self, issue_id: str) -> bool:
        """Check if an issue is currently running via ephemeral state."""
        return self._ephemeral.is_running(issue_id)

    def cleanup_stale_running(self, active_workcell_ids: set[str]) -> list[str]:
        """
        Clean up running entries for workcells that no longer exist.

        Call this during kernel startup to recover from crashes.

        Args:
            active_workcell_ids: Set of currently active workcell IDs

        Returns:
            List of issue IDs that were cleaned up
        """
        return self._ephemeral.cleanup_stale(active_workcell_ids)

    def _get_beads_mtime(self) -> float:
        """Get the maximum mtime of beads data files for cache invalidation."""
        max_mtime = 0.0

        for filename in ("issues.jsonl", "deps.jsonl", "issues.yaml", "deps.yaml"):
            filepath = self.hellcat_dir / filename
            if filepath.exists():
                try:
                    mtime = filepath.stat().st_mtime
                    max_mtime = max(max_mtime, mtime)
                except OSError:
                    pass

        return max_mtime

    def _is_cache_valid(self) -> bool:
        """Check if the cached graph is still valid."""
        if self._cached_graph is None:
            return False

        # Check TTL
        now = time.monotonic()
        if now - self._cache_timestamp > self._cache_ttl:
            return False

        # Check file mtime (detect external changes)
        current_mtime = self._get_beads_mtime()
        return current_mtime == self._cache_mtime

    def invalidate_cache(self) -> None:
        """Invalidate the cached BeadsGraph, forcing a reload on next access."""
        self._cached_graph = None
        self._cache_timestamp = 0.0
        self._cache_mtime = 0.0

    def load_graph(self, bypass_cache: bool = False) -> BeadsGraph:
        """
        Load the full Beads work graph with caching.

        Uses cached graph if:
        - Cache exists and TTL hasn't expired
        - Underlying files haven't been modified

        Args:
            bypass_cache: If True, skip cache and reload from source

        Returns:
            The BeadsGraph containing all issues and dependencies.
        """
        # Check cache first
        if not bypass_cache and self._is_cache_valid():
            logger.debug(
                "Using cached Beads graph",
                issues=len(self._cached_graph.issues) if self._cached_graph else 0,
            )
            return self._cached_graph  # type: ignore[return-value]

        # Load fresh data
        issues = self._load_issues()
        deps = self._load_deps()

        graph = BeadsGraph(issues=issues, deps=deps)

        # Update cache
        self._cached_graph = graph
        self._cache_timestamp = time.monotonic()
        self._cache_mtime = self._get_beads_mtime()

        logger.info(
            "Loaded Beads graph",
            issues=len(issues),
            deps=len(deps),
            mode="cli" if self.bd_available else "file",
            cached=True,
        )

        return graph

    def get_ready_issues(self) -> list[Issue]:
        """
        Get issues that are ready to work on.

        An issue is ready when:
        - status is 'open' or 'ready'
        - all blocking dependencies are 'done'
        """
        if self.bd_available:
            result = subprocess.run(
                ["bd", "ready", "--json"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    return [Issue.from_dict(item) for item in data]
                except json.JSONDecodeError:
                    pass

        # Fallback: compute ready set from graph
        graph = self.load_graph()
        ready: list[Issue] = []

        for issue in graph.issues:
            if issue.status not in ("open", "ready"):
                continue

            blockers = graph.get_blocking_deps(issue.id)
            if all(b.status == "done" for b in blockers):
                ready.append(issue)

        return ready

    def update_issue(
        self,
        issue_id: str,
        status: str | None = None,
        tags: list[str] | None = None,
        expected_version: int | None = None,
        workcell_id: str | None = None,
        toolchain: str | None = None,
        speculate_tag: str | None = None,
        **fields: str,
    ) -> bool:
        """
        Update an issue atomically with optional optimistic locking.

        Uses ephemeral state for "running" status to avoid dirtying the repo.
        Only terminal states (done, failed, open) modify .hellcat/issues.jsonl.

        Args:
            issue_id: The issue ID to update
            status: New status value (optional)
            tags: Tags to add to existing tags (optional)
            expected_version: If provided, the update will fail with
                VersionConflictError if the current version doesn't match.
                The version is automatically incremented on successful update.
            workcell_id: Workcell ID (required for status="running")
            toolchain: Toolchain being used (optional, for running status)
            speculate_tag: Speculation tag (optional, for running status)
            **fields: Additional fields to update

        Returns:
            True if update succeeded

        Raises:
            VersionConflictError: If expected_version is provided and doesn't
                match the current version in the file.
        """
        # Handle "running" status via ephemeral state (doesn't dirty repo)
        if status == "running":
            if not workcell_id:
                logger.error(
                    "workcell_id required for running status",
                    issue_id=issue_id,
                )
                return False

            self._ephemeral.mark_running(
                issue_id=issue_id,
                workcell_id=workcell_id,
                toolchain=toolchain,
                speculate_tag=speculate_tag,
            )
            # Invalidate cache so get_issue reflects running status
            self.invalidate_cache()
            return True

        # Terminal states: clear ephemeral and update canonical file
        if status in ("done", "failed", "open"):
            self._ephemeral.mark_complete(issue_id)

        if self.bd_available:
            return self._update_issue_via_cli(issue_id, status, tags, **fields)

        return self._update_issue_via_file(
            issue_id, status, tags, expected_version=expected_version, **fields
        )

    def create_issue(
        self,
        title: str,
        description: str | None = None,
        priority: str = "P2",
        tags: list[str] | None = None,
    ) -> str | None:
        """
        Create a new issue.

        Returns the new issue ID or None on failure.
        """
        if self.bd_available:
            return self._create_issue_via_cli(title, description, priority, tags)

        return self._create_issue_via_file(title, description, priority, tags)

    def close_issue(self, issue_id: str) -> bool:
        """Close an issue."""
        return self.update_issue(issue_id, status="done")

    def add_dep(
        self,
        from_id: str,
        to_id: str,
        dep_type: str = "blocks",
    ) -> bool:
        """
        Add a dependency edge between issues.
        """
        if self.bd_available:
            return self._add_dep_via_cli(from_id, to_id, dep_type)

        return self._add_dep_via_file(from_id, to_id, dep_type)

    # ===== Issue Loading =====

    def _load_issues(self) -> list[Issue]:
        """Load all issues from Beads."""
        # Try bd CLI first
        if self.bd_available:
            issues = self._load_issues_via_cli()
            if issues:
                return issues

        # Fall back to direct file parsing
        return self._load_issues_from_files()

    def _load_issues_via_cli(self) -> list[Issue]:
        """Load issues via bd CLI."""
        result = subprocess.run(
            ["bd", "list", "--json"],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.debug("bd list failed", error=result.stderr)
            return []

        try:
            data = json.loads(result.stdout)
            return [Issue.from_dict(item) for item in data]
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse bd list output", error=str(e))
            return []

    def _load_issues_from_files(self) -> list[Issue]:
        """Load issues directly from .hellcat files, merging ephemeral running state."""
        issues: list[Issue] = []

        # Try issues.jsonl (JSON Lines format)
        jsonl_file = self.hellcat_dir / "issues.jsonl"
        if jsonl_file.exists():
            issues.extend(self._parse_jsonl_file(jsonl_file, Issue.from_dict))
            if issues:
                # Merge ephemeral running state
                issues = self._merge_ephemeral_state(issues)
                return issues

        # Try issues.yaml / issues.yml
        for ext in ("yaml", "yml"):
            yaml_file = self.hellcat_dir / f"issues.{ext}"
            if yaml_file.exists():
                issues.extend(self._parse_yaml_file(yaml_file, Issue.from_dict))
                if issues:
                    return issues

        # Try individual issue files in issues/ directory
        issues_dir = self.hellcat_dir / "issues"
        if issues_dir.exists() and issues_dir.is_dir():
            for path in issues_dir.iterdir():
                if path.suffix in (".json", ".yaml", ".yml"):
                    issue = self._parse_single_issue_file(path)
                    if issue:
                        issues.append(issue)

        return issues

    def _merge_ephemeral_state(self, issues: list[Issue]) -> list[Issue]:
        """
        Merge ephemeral running state into loaded issues.

        Issues marked as running in ephemeral state will have their
        status overridden to "running" regardless of what's in the
        canonical .hellcat/issues.jsonl file.

        This allows the kernel to track running status without dirtying
        the git working tree.
        """
        # Ephemeral state can be left behind after crashes/interruptions. Clean up
        # stale "running" entries whose workcell dirs no longer exist.
        with contextlib.suppress(Exception):
            workcells_dir = (
                getattr(self.config, "workcells_dir", None) if self.config is not None else None
            )
            if not isinstance(workcells_dir, Path):
                workcells_dir = self.repo_root / ".workcells"
            active_workcell_ids: set[str] = set()
            if workcells_dir.exists():
                active_workcell_ids = {
                    p.name for p in workcells_dir.iterdir() if p.is_dir() and not p.name.startswith(".")
                }
            self._ephemeral.cleanup_stale(active_workcell_ids)

        running_map = self._ephemeral.get_all_running()

        if not running_map:
            return issues

        merged = []
        for issue in issues:
            if issue.id in running_map:
                # Override status to "running" from ephemeral state
                issue.status = "running"
                logger.debug(
                    "Merged ephemeral running status",
                    issue_id=issue.id,
                    workcell_id=running_map[issue.id].workcell_id,
                )
            merged.append(issue)

        return merged

    def _parse_jsonl_file(self, path: Path, factory: callable) -> list:
        """Parse a JSON Lines file."""
        items = []

        try:
            with open(path) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        data = json.loads(line)
                        items.append(factory(data))
                    except json.JSONDecodeError as e:
                        logger.warning(
                            "Invalid JSON line",
                            file=str(path),
                            line=line_num,
                            error=str(e),
                        )
                    except Exception as e:
                        logger.warning(
                            "Failed to parse item",
                            file=str(path),
                            line=line_num,
                            error=str(e),
                        )
        except OSError as e:
            logger.warning("Failed to read file", file=str(path), error=str(e))

        return items

    def _parse_yaml_file(self, path: Path, factory: callable) -> list:
        """Parse a YAML file containing a list of items."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)

            if isinstance(data, list):
                return [factory(item) for item in data if isinstance(item, dict)]
            elif isinstance(data, dict) and "issues" in data:
                return [factory(item) for item in data["issues"] if isinstance(item, dict)]

        except yaml.YAMLError as e:
            logger.warning("Invalid YAML", file=str(path), error=str(e))
        except OSError as e:
            logger.warning("Failed to read file", file=str(path), error=str(e))

        return []

    def _parse_single_issue_file(self, path: Path) -> Issue | None:
        """Parse a single issue file (JSON or YAML)."""
        try:
            with open(path) as f:
                data = json.load(f) if path.suffix == ".json" else yaml.safe_load(f)

            if isinstance(data, dict):
                # Use filename (without extension) as ID if not present
                if "id" not in data:
                    data["id"] = path.stem
                return Issue.from_dict(data)

        except (json.JSONDecodeError, yaml.YAMLError) as e:
            logger.warning("Invalid issue file", file=str(path), error=str(e))
        except OSError as e:
            logger.warning("Failed to read file", file=str(path), error=str(e))

        return None

    # ===== Dependency Loading =====

    def _load_deps(self) -> list[Dep]:
        """Load dependencies from Beads."""
        deps: list[Dep] = []

        # Try deps.jsonl
        jsonl_file = self.hellcat_dir / "deps.jsonl"
        if jsonl_file.exists():
            deps = self._parse_jsonl_file(jsonl_file, Dep.from_dict)
            if deps:
                return deps

        # Try deps.yaml / deps.yml
        for ext in ("yaml", "yml"):
            yaml_file = self.hellcat_dir / f"deps.{ext}"
            if yaml_file.exists():
                deps = self._parse_deps_yaml(yaml_file)
                if deps:
                    return deps

        return deps

    def _parse_deps_yaml(self, path: Path) -> list[Dep]:
        """Parse a deps YAML file."""
        try:
            with open(path) as f:
                data = yaml.safe_load(f)

            if isinstance(data, list):
                return [Dep.from_dict(item) for item in data if isinstance(item, dict)]
            elif isinstance(data, dict) and "deps" in data:
                return [Dep.from_dict(item) for item in data["deps"] if isinstance(item, dict)]

        except yaml.YAMLError as e:
            logger.warning("Invalid deps YAML", file=str(path), error=str(e))
        except OSError as e:
            logger.warning("Failed to read deps file", file=str(path), error=str(e))

        return []

    # ===== CLI-based Operations =====

    def _update_issue_via_cli(
        self,
        issue_id: str,
        status: str | None = None,
        tags: list[str] | None = None,
        **fields: str,
    ) -> bool:
        """Update issue via bd CLI."""
        cmd = ["bd", "update", issue_id]

        if status:
            cmd.extend(["--status", status])

        if tags:
            for tag in tags:
                cmd.extend(["--tag", tag])

        for key, value in fields.items():
            if key not in ALLOWED_ISSUE_FIELDS:
                logger.warning(
                    "Rejecting unknown field in CLI update",
                    field=key,
                    issue_id=issue_id,
                )
                continue
            cmd.extend([f"--{key.replace('_', '-')}", str(value)])

        cmd.append("--json")

        result = subprocess.run(
            cmd,
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.error("Failed to update issue", issue_id=issue_id, error=result.stderr)
            return False

        logger.info("Issue updated", issue_id=issue_id, status=status)
        return True

    def _create_issue_via_cli(
        self,
        title: str,
        description: str | None = None,
        priority: str = "P2",
        tags: list[str] | None = None,
    ) -> str | None:
        """Create issue via bd CLI."""
        cmd = ["bd", "create", title]

        if description:
            cmd.extend(["--description", description])

        cmd.extend(["--priority", priority])

        if tags:
            for tag in tags:
                cmd.extend(["--tag", tag])

        cmd.append("--json")

        result = subprocess.run(
            cmd,
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.error("Failed to create issue", title=title, error=result.stderr)
            return None

        try:
            data = json.loads(result.stdout)
            issue_id = data.get("id")
            logger.info("Issue created", issue_id=issue_id, title=title)
            return issue_id
        except json.JSONDecodeError:
            logger.warning("Failed to parse create issue response")
            return None

    def _add_dep_via_cli(self, from_id: str, to_id: str, dep_type: str) -> bool:
        """Add dependency via bd CLI."""
        cmd = ["bd", "dep", "add", from_id, to_id, "--type", dep_type, "--json"]

        result = subprocess.run(
            cmd,
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.error(
                "Failed to add dependency",
                from_id=from_id,
                to_id=to_id,
                error=result.stderr,
            )
            return False

        logger.info("Dependency added", from_id=from_id, to_id=to_id, type=dep_type)
        return True

    # ===== File-based Operations =====

    def _update_issue_via_file(
        self,
        issue_id: str,
        status: str | None = None,
        tags: list[str] | None = None,
        expected_version: int | None = None,
        **fields: str,
    ) -> bool:
        """
        Update issue directly in file with file locking and optional optimistic locking.

        Args:
            issue_id: The issue ID to update
            status: New status value (optional)
            tags: Tags to add (optional)
            expected_version: If provided, check version before update
            **fields: Additional fields to update

        Returns:
            True if update succeeded

        Raises:
            VersionConflictError: If expected_version doesn't match current version
        """
        jsonl_file = self.hellcat_dir / "issues.jsonl"

        if not jsonl_file.exists():
            logger.error("issues.jsonl not found", path=str(jsonl_file))
            return False

        # Acquire exclusive lock for file modification
        with self._lock_manager.lock("issues", exclusive=True) as acquired:
            if not acquired:
                logger.error(
                    "Failed to acquire lock for issue update",
                    issue_id=issue_id,
                    timeout=30.0,
                )
                return False

            # Read all issues
            issues_data: list[dict] = []
            found = False

            with open(jsonl_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if data.get("id") == issue_id:
                            found = True
                            current_version = int(data.get("version", 0))

                            # Optimistic locking: check version if provided
                            if expected_version is not None and current_version != expected_version:
                                raise VersionConflictError(
                                    issue_id=issue_id,
                                    expected_version=expected_version,
                                    actual_version=current_version,
                                )

                            # Apply updates
                            previous_status = data.get("status")
                            if status:
                                data["status"] = status
                            if tags:
                                data["tags"] = list(set(data.get("tags", []) + tags))
                            for key, value in fields.items():
                                # Apply same whitelist validation as CLI path
                                if key not in ALLOWED_ISSUE_FIELDS:
                                    logger.warning(
                                        "Rejecting unknown field in file update",
                                        field=key,
                                        issue_id=issue_id,
                                    )
                                    continue
                                data[key] = value
                            now = _utc_now().isoformat().replace("+00:00", "Z")
                            data["updated"] = now

                            if status:
                                ready_statuses = {"open", "ready"}
                                if status in ready_statuses:
                                    if (
                                        previous_status not in ready_statuses
                                        or not data.get("ready_since")
                                    ):
                                        data["ready_since"] = now
                                elif previous_status in ready_statuses:
                                    data.pop("ready_since", None)

                            # Increment version on every update
                            data["version"] = current_version + 1

                        issues_data.append(data)
                    except json.JSONDecodeError:
                        continue

            if not found:
                logger.error("Issue not found", issue_id=issue_id)
                return False

            # Write back atomically
            tmp_file = jsonl_file.with_suffix(".tmp")
            with open(tmp_file, "w") as f:
                for data in issues_data:
                    f.write(json.dumps(data) + "\n")

            tmp_file.rename(jsonl_file)

            # Invalidate cache after mutation
            self.invalidate_cache()

            logger.info("Issue updated via file", issue_id=issue_id, status=status)
            return True

    def _create_issue_via_file(
        self,
        title: str,
        description: str | None = None,
        priority: str = "P2",
        tags: list[str] | None = None,
    ) -> str | None:
        """Create issue directly in file with file locking."""
        self.hellcat_dir.mkdir(parents=True, exist_ok=True)
        jsonl_file = self.hellcat_dir / "issues.jsonl"

        # Acquire exclusive lock for file modification
        with self._lock_manager.lock("issues", exclusive=True) as acquired:
            if not acquired:
                logger.error(
                    "Failed to acquire lock for issue creation",
                    title=title,
                    timeout=30.0,
                )
                return None

            # Generate ID (must be inside lock to avoid race)
            existing_ids = set()
            if jsonl_file.exists():
                with open(jsonl_file) as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            if "id" in data:
                                existing_ids.add(data["id"])
                        except json.JSONDecodeError:
                            continue

            # Find next available ID
            issue_id = "1"
            counter = 1
            while issue_id in existing_ids:
                counter += 1
                issue_id = str(counter)

            # Create issue data
            now = _utc_now().isoformat().replace("+00:00", "Z")
            issue_data = {
                "id": issue_id,
                "title": title,
                "status": "open",
                "created": now,
                "updated": now,
                "ready_since": now,
                "dk_priority": priority,
                "version": 0,  # Initialize optimistic locking version
            }

            if description:
                issue_data["description"] = description

            if tags:
                issue_data["tags"] = tags

            # Append to file
            with open(jsonl_file, "a") as f:
                f.write(json.dumps(issue_data) + "\n")

            # Invalidate cache after mutation
            self.invalidate_cache()

            logger.info("Issue created via file", issue_id=issue_id, title=title)
            return issue_id

    def _add_dep_via_file(self, from_id: str, to_id: str, dep_type: str) -> bool:
        """Add dependency directly to file with file locking."""
        self.hellcat_dir.mkdir(parents=True, exist_ok=True)
        deps_file = self.hellcat_dir / "deps.jsonl"

        # Acquire exclusive lock for file modification
        with self._lock_manager.lock("deps", exclusive=True) as acquired:
            if not acquired:
                logger.error(
                    "Failed to acquire lock for dependency add",
                    from_id=from_id,
                    to_id=to_id,
                    timeout=30.0,
                )
                return False

            now = _utc_now().isoformat().replace("+00:00", "Z")
            dep_data = {
                "from": from_id,
                "to": to_id,
                "type": dep_type,
                "created": now,
            }

            with open(deps_file, "a") as f:
                f.write(json.dumps(dep_data) + "\n")

            # Invalidate cache after mutation
            self.invalidate_cache()

            logger.info("Dependency added via file", from_id=from_id, to_id=to_id, type=dep_type)
            return True

    # ===== Alias Methods =====

    def load_beads_graph(self) -> BeadsGraph:
        """Alias for load_graph - used by runner."""
        return self.load_graph()

    def update_issue_status(
        self,
        issue_id: str,
        status: str,
        workcell_id: str | None = None,
        toolchain: str | None = None,
    ) -> bool:
        """
        Update just the status of an issue.

        For status="running", pass workcell_id to use ephemeral state
        (avoids dirtying the git working tree).
        """
        return self.update_issue(
            issue_id,
            status=status,
            workcell_id=workcell_id,
            toolchain=toolchain,
        )

    def increment_attempts(self, issue_id: str) -> int:
        """
        Increment the attempt counter for an issue.

        Returns the new attempt count.
        """
        graph = self.load_graph()
        issue = graph.get_issue(issue_id)

        if not issue:
            return 0

        new_attempts = issue.dk_attempts + 1
        self.update_issue(issue_id, dk_attempts=str(new_attempts))
        return new_attempts

    def add_event(
        self,
        issue_id: str | None,
        event_type: str,
        data: dict[str, Any] | None = None,
        *,
        workcell_id: str | None = None,
    ) -> None:
        """Add an event to the event log with file locking."""
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        events_file = self.logs_dir / "events.jsonl"

        # Acquire exclusive lock for file modification
        with self._lock_manager.lock("events", exclusive=True) as acquired:
            if not acquired:
                logger.warning(
                    "Failed to acquire lock for event logging, writing anyway",
                    event_type=event_type,
                    issue_id=issue_id,
                )
                # For events, we still write even if lock fails (best effort)

            event = {
                "type": event_type,
                "timestamp": _utc_now().isoformat().replace("+00:00", "Z"),
                "issue_id": issue_id,
                "data": data or {},
            }
            if workcell_id:
                event["workcell_id"] = workcell_id

            with open(events_file, "a") as f:
                f.write(json.dumps(event) + "\n")

            logger.debug("Event logged", event_type=event_type, issue_id=issue_id)
