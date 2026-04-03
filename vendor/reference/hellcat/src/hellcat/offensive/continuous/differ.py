"""
SurfaceDiffer - Compares TargetGraph snapshots to identify changes.

Detects new, removed, and modified endpoints/services between two
snapshots of the attack surface, enabling targeted re-engagement
of only the affected areas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SurfaceSnapshot:
    """Point-in-time snapshot of the attack surface.

    Built from a TargetGraph's current state, capturing all target
    nodes and their metadata for comparison.
    """

    timestamp: str
    targets: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Maps target_id -> {url, method, tech_stack, status, metadata_json, ...}
    endpoint_count: int = 0
    tech_stack_summary: list[str] = field(default_factory=list)
    graph_hash: str = ""

    @classmethod
    def from_graph(cls, graph: Any, timestamp: str = "") -> SurfaceSnapshot:
        """Build a snapshot from a live TargetGraph.

        Args:
            graph: A TargetGraph instance.
            timestamp: ISO timestamp for the snapshot (auto-generated if empty).

        Returns:
            SurfaceSnapshot with all target nodes captured.
        """
        import hashlib
        import json
        from datetime import UTC, datetime

        if not timestamp:
            timestamp = datetime.now(UTC).isoformat()

        targets: dict[str, dict[str, Any]] = {}
        tech_stacks: set[str] = set()

        # Query all targets from the graph
        rows = graph.conn.execute("SELECT * FROM targets").fetchall()
        for row in rows:
            node = dict(row)
            node_id = node["id"]
            targets[node_id] = node
            tech = node.get("tech_stack", "")
            if tech:
                tech_stacks.add(tech)

        # Compute a hash over all target state for quick equality checks
        hash_input = json.dumps(
            {k: {kk: str(vv) for kk, vv in v.items()} for k, v in sorted(targets.items())},
            sort_keys=True,
            separators=(",", ":"),
        )
        graph_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        return cls(
            timestamp=timestamp,
            targets=targets,
            endpoint_count=len(targets),
            tech_stack_summary=sorted(tech_stacks),
            graph_hash=graph_hash,
        )


@dataclass
class ChangedTarget:
    """A target that exists in both snapshots but with differences."""

    target_id: str
    url: str
    changes: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    # Maps field_name -> (old_value, new_value)


@dataclass
class SurfaceDiff:
    """Result of comparing two SurfaceSnapshots.

    Contains lists of added, removed, and modified targets. Used by
    the ContinuousScheduler to scope re-engagement.
    """

    old_timestamp: str
    new_timestamp: str
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    modified: list[ChangedTarget] = field(default_factory=list)
    new_tech_stacks: list[str] = field(default_factory=list)
    removed_tech_stacks: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    @property
    def change_count(self) -> int:
        return len(self.added) + len(self.removed) + len(self.modified)

    @property
    def affected_urls(self) -> list[str]:
        """URLs that need re-testing."""
        urls: list[str] = []
        for t in self.added:
            url = t.get("url", "")
            if url:
                urls.append(url)
        for ct in self.modified:
            if ct.url:
                urls.append(ct.url)
        return urls


# Fields to compare when detecting modifications
_COMPARE_FIELDS = ("url", "method", "tech_stack", "description", "status")


class SurfaceDiffer:
    """Compares two TargetGraph snapshots to identify changes.

    Usage::

        old = SurfaceSnapshot.from_graph(graph_before)
        # ... time passes, target changes ...
        new = SurfaceSnapshot.from_graph(graph_after)
        diff = SurfaceDiffer.diff(old, new)
        if diff.has_changes:
            print(f"{diff.change_count} changes detected")
    """

    @staticmethod
    def diff(old: SurfaceSnapshot, new: SurfaceSnapshot) -> SurfaceDiff:
        """Compare two snapshots and return a SurfaceDiff.

        Args:
            old: The previous snapshot.
            new: The current snapshot.

        Returns:
            SurfaceDiff with added, removed, and modified targets.
        """
        old_ids = set(old.targets.keys())
        new_ids = set(new.targets.keys())

        added_ids = new_ids - old_ids
        removed_ids = old_ids - new_ids
        common_ids = old_ids & new_ids

        added = [new.targets[tid] for tid in sorted(added_ids)]
        removed = [old.targets[tid] for tid in sorted(removed_ids)]

        modified: list[ChangedTarget] = []
        for tid in sorted(common_ids):
            old_node = old.targets[tid]
            new_node = new.targets[tid]
            changes: dict[str, tuple[Any, Any]] = {}

            for fld in _COMPARE_FIELDS:
                old_val = old_node.get(fld, "")
                new_val = new_node.get(fld, "")
                if str(old_val) != str(new_val):
                    changes[fld] = (old_val, new_val)

            if changes:
                modified.append(ChangedTarget(
                    target_id=tid,
                    url=new_node.get("url", ""),
                    changes=changes,
                ))

        # Tech stack changes
        old_tech = set(old.tech_stack_summary)
        new_tech = set(new.tech_stack_summary)

        return SurfaceDiff(
            old_timestamp=old.timestamp,
            new_timestamp=new.timestamp,
            added=added,
            removed=removed,
            modified=modified,
            new_tech_stacks=sorted(new_tech - old_tech),
            removed_tech_stacks=sorted(old_tech - new_tech),
        )
