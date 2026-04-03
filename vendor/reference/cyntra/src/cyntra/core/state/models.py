"""
Data models for Beads integration.

Includes optimistic locking via version field for concurrent modification detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


class VersionConflictError(Exception):
    """
    Raised when an optimistic locking version conflict is detected.

    This indicates that the issue was modified by another process between
    the time it was read and the time of the attempted update.
    """

    def __init__(
        self,
        issue_id: str,
        expected_version: int,
        actual_version: int,
    ) -> None:
        self.issue_id = issue_id
        self.expected_version = expected_version
        self.actual_version = actual_version
        super().__init__(
            f"Version conflict for issue {issue_id}: "
            f"expected version {expected_version}, found {actual_version}"
        )


def _parse_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y", "on"}:
            return True
        if lowered in {"false", "0", "no", "n", "off"}:
            return False
    return default


@dataclass
class Issue:
    """Represents a Beads issue with Cyntra extensions."""

    id: str
    title: str
    status: str
    created: datetime
    updated: datetime

    # Optional Beads fields
    description: str | None = None
    acceptance_criteria: list[str] | None = None
    context_files: list[str] | None = None
    tags: list[str] = field(default_factory=list)

    # Cyntra extensions (dk_*)
    dk_priority: str = "P2"  # P0=critical, P1=high, P2=medium, P3=low
    dk_risk: str = "medium"  # low, medium, high, critical
    dk_size: str = "M"  # XS, S, M, L, XL
    dk_tool_hint: str | None = None  # codex, claude, opencode, crush
    dk_speculate: bool = False
    dk_max_attempts: int = 3
    dk_forbidden_paths: list[str] = field(default_factory=list)
    dk_required_reviewers: int = 0
    dk_parent: str | None = None
    dk_estimated_tokens: int = 50000
    dk_attempts: int = 0
    dk_starved: bool = False
    dk_apply_patch: bool = True
    dk_prompt_genome_id: str | None = None
    dk_quality_gates: dict[str, Any] = field(default_factory=dict)
    dk_sampling: dict[str, Any] = field(default_factory=dict)
    dk_lease_hash: str | None = None

    # Tracking
    ready_since: datetime | None = None

    # Optimistic locking version - incremented on each update
    # Used to detect concurrent modifications
    version: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Issue:
        """Create Issue from Beads JSON data.

        Note: Some issues in .beads/issues.jsonl carry an inline ``blocked_by``
        list. This field is intentionally NOT parsed here because dependency
        resolution is handled entirely through .beads/deps.jsonl via
        ``BeadsGraph.get_blocking_deps()``. The inline field is dead data.
        """
        # Parse timestamps with fallback to now
        created = cls._parse_timestamp(data.get("created"))
        updated = cls._parse_timestamp(data.get("updated")) or created

        # Parse ready_since if present
        ready_since = None
        if data.get("ready_since"):
            ready_since = cls._parse_timestamp(data["ready_since"])

        # Support both 'tags' and 'labels' fields (some beads use 'labels')
        raw_tags = data.get("tags") or data.get("labels") or []
        tags = [t for t in raw_tags if isinstance(t, str) and t.strip()]

        return cls(
            id=str(data.get("id", "")),
            title=data.get("title", ""),
            status=data.get("status", "open"),
            created=created,
            updated=updated,
            description=data.get("description"),
            acceptance_criteria=data.get("acceptance_criteria"),
            context_files=data.get("context_files"),
            tags=tags,
            dk_priority=data.get("dk_priority") or data.get("priority", "P2"),
            dk_risk=data.get("dk_risk") or data.get("risk", "medium"),
            dk_size=data.get("dk_size") or data.get("size", "M"),
            dk_tool_hint=data.get("dk_tool_hint") or data.get("tool_hint"),
            dk_speculate=bool(data.get("dk_speculate", False)),
            dk_max_attempts=int(data.get("dk_max_attempts", 3)),
            dk_forbidden_paths=data.get("dk_forbidden_paths", []) or [],
            dk_required_reviewers=int(data.get("dk_required_reviewers", 0)),
            dk_parent=data.get("dk_parent") or data.get("parent"),
            dk_estimated_tokens=int(data.get("dk_estimated_tokens", 50000)),
            dk_attempts=int(data.get("dk_attempts", 0)),
            dk_apply_patch=_parse_bool(data.get("dk_apply_patch", data.get("apply_patch")), True),
            dk_prompt_genome_id=data.get("dk_prompt_genome_id") or data.get("prompt_genome_id"),
            dk_quality_gates=dict(data.get("dk_quality_gates") or data.get("quality_gates") or {})
            if isinstance(data.get("dk_quality_gates") or data.get("quality_gates"), dict)
            else {},
            dk_sampling=dict(data.get("dk_sampling") or data.get("sampling") or {})
            if isinstance(data.get("dk_sampling") or data.get("sampling"), dict)
            else {},
            dk_lease_hash=(
                data.get("dk_lease_hash")
                or data.get("lease_hash")
                or data.get("leaseHash")
            ),
            ready_since=ready_since,
            version=int(data.get("version", 0)),
        )

    @staticmethod
    def _parse_timestamp(value: str | datetime | None) -> datetime:
        """Parse a timestamp string or return current time as fallback."""
        if value is None:
            return _utc_now()

        if isinstance(value, datetime):
            return value

        try:
            # Handle ISO format with optional Z suffix
            value = str(value).rstrip("Z").replace("+00:00", "")
            return datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return _utc_now()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "created": self.created.isoformat() + "Z",
            "updated": self.updated.isoformat() + "Z",
            "description": self.description,
            "acceptance_criteria": self.acceptance_criteria,
            "context_files": self.context_files,
            "tags": self.tags,
            "dk_priority": self.dk_priority,
            "dk_risk": self.dk_risk,
            "dk_size": self.dk_size,
            "dk_tool_hint": self.dk_tool_hint,
            "dk_speculate": self.dk_speculate,
            "dk_max_attempts": self.dk_max_attempts,
            "dk_forbidden_paths": self.dk_forbidden_paths,
            "dk_required_reviewers": self.dk_required_reviewers,
            "dk_parent": self.dk_parent,
            "dk_estimated_tokens": self.dk_estimated_tokens,
            "dk_attempts": self.dk_attempts,
            "dk_apply_patch": self.dk_apply_patch,
            "dk_prompt_genome_id": self.dk_prompt_genome_id,
            "dk_quality_gates": self.dk_quality_gates,
            "dk_sampling": self.dk_sampling,
            "dk_lease_hash": self.dk_lease_hash,
            "version": self.version,
        }


@dataclass
class Dep:
    """Represents a dependency edge between issues."""

    from_id: str
    to_id: str
    dep_type: str  # blocks, unblocks, discovered, fix-for, speculate, review-of
    created: datetime

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Dep:
        """Create Dep from Beads JSON data."""
        # Parse timestamp with fallback
        created_str = data.get("created", "")
        try:
            created = datetime.fromisoformat(str(created_str).rstrip("Z"))
        except (ValueError, TypeError):
            created = _utc_now()

        return cls(
            from_id=str(data.get("from", data.get("from_id", ""))),
            to_id=str(data.get("to", data.get("to_id", ""))),
            dep_type=data.get("type", data.get("dep_type", "blocks")),
            created=created,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "from": self.from_id,
            "to": self.to_id,
            "type": self.dep_type,
            "created": self.created.isoformat() + "Z",
        }


@dataclass
class BeadsGraph:
    """Represents the full Beads work graph."""

    issues: list[Issue]
    deps: list[Dep]

    def get_issue(self, issue_id: str) -> Issue | None:
        """Get issue by ID."""
        for issue in self.issues:
            if issue.id == issue_id:
                return issue
        return None

    def get_deps(self, issue_id: str, dep_type: str | None = None) -> list[Dep]:
        """Get dependencies for an issue."""
        deps = [d for d in self.deps if d.from_id == issue_id or d.to_id == issue_id]
        if dep_type:
            deps = [d for d in deps if d.dep_type == dep_type]
        return deps

    def get_blocking_deps(self, issue_id: str) -> list[Issue]:
        """Get issues that block this issue."""
        blocking: list[Issue] = []
        for dep in self.deps:
            if dep.to_id == issue_id and dep.dep_type == "blocks":
                blocker = self.get_issue(dep.from_id)
                if blocker:
                    blocking.append(blocker)
        return blocking

    def get_blocked_by(self, issue_id: str) -> list[Issue]:
        """Get issues blocked by this issue."""
        blocked: list[Issue] = []
        for dep in self.deps:
            if dep.from_id == issue_id and dep.dep_type == "blocks":
                issue = self.get_issue(dep.to_id)
                if issue:
                    blocked.append(issue)
        return blocked

    def filter_to_issue(self, issue_id: str) -> BeadsGraph:
        """Filter graph to only include the specified issue and its dependencies."""
        target = self.get_issue(issue_id)
        if not target:
            return BeadsGraph(issues=[], deps=[])

        # Collect all related issue IDs
        related_ids = {issue_id}

        # Add blocking dependencies (issues this one depends on)
        for blocker in self.get_blocking_deps(issue_id):
            related_ids.add(blocker.id)

        # Add blocked issues (issues that depend on this one)
        for blocked in self.get_blocked_by(issue_id):
            related_ids.add(blocked.id)

        # Filter issues and deps
        filtered_issues = [i for i in self.issues if i.id in related_ids]
        filtered_deps = [
            d for d in self.deps if d.from_id in related_ids and d.to_id in related_ids
        ]

        return BeadsGraph(issues=filtered_issues, deps=filtered_deps)
