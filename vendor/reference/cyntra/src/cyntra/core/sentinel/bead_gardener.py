"""
Bead Gardener Sentinel - Maintains bead hygiene.

Watches completed work and maintains bead hygiene:
- Detect orphaned beads (no parent, not an epic)
- Detect stale beads (open too long with no activity)
- Validate dependency graph (circular deps, missing refs)
- Promote beads to 'ready' when blockers complete
- Update bead descriptions with implementation learnings
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cyntra.core.sentinel.base import (
    BaseSentinel,
    SentinelConfig,
    SentinelSchedule,
)


@dataclass
class BeadGardenerConfig:
    """Configuration for BeadGardener sentinel."""

    # Staleness detection
    stale_days_threshold: int = 14  # Beads open > 14 days with no activity
    warn_days_threshold: int = 7  # Warn about beads approaching staleness

    # Events to scan
    events_lookback_hours: int = 24  # Only scan events from last 24 hours

    # What to check
    check_orphaned_beads: bool = True
    check_stale_beads: bool = True
    check_dependency_graph: bool = True
    check_ready_promotions: bool = True  # Promote open→ready when blockers done
    check_completed_updates: bool = True  # Update descriptions from events


class BeadGardenerSentinel(BaseSentinel):
    """
    Watches completed work and maintains bead hygiene.

    Responsibilities:
    - Detect orphaned beads (no parent, not an epic)
    - Detect stale beads (open too long with no activity)
    - Validate dependency graph (circular deps, missing refs)
    - Promote beads to 'ready' when blockers complete
    - Update bead descriptions with implementation learnings
    """

    def __init__(
        self,
        config: SentinelConfig | None = None,
        schedule: SentinelSchedule | None = None,
        repo_root: Path | None = None,
        gardener_config: BeadGardenerConfig | None = None,
    ) -> None:
        super().__init__(config, schedule, repo_root)
        self.gardener_config = gardener_config or BeadGardenerConfig()
        self._state_manager: Any = None

    @property
    def name(self) -> str:
        return "bead_gardener"

    @property
    def description(self) -> str:
        return "Maintains bead hygiene: updates descriptions, resolves deps, detects orphans"

    def _get_state_manager(self) -> Any:
        """Lazy-load StateManager to avoid circular imports."""
        if self._state_manager is None:
            from cyntra.core.state.manager import StateManager
            self._state_manager = StateManager(repo_root=self.repo_root)
        return self._state_manager

    async def execute(self) -> None:
        """Run bead gardening checks."""
        state_mgr = self._get_state_manager()
        graph = state_mgr.load_graph()

        if not graph.issues:
            self._log.info("no_beads_found")
            return

        # Run each check
        if self.gardener_config.check_orphaned_beads:
            await self._check_orphaned_beads(graph)

        if self.gardener_config.check_stale_beads:
            await self._check_stale_beads(graph)

        if self.gardener_config.check_dependency_graph:
            await self._check_dependency_graph(graph)

        if self.gardener_config.check_ready_promotions:
            await self._check_ready_promotions(graph, state_mgr)

        if self.gardener_config.check_completed_updates:
            await self._check_completed_updates(graph, state_mgr)

    async def _check_orphaned_beads(self, graph: Any) -> None:
        """Find beads without parents that aren't epics."""
        orphaned = []

        for issue in graph.issues:
            # Skip if it has a parent
            if issue.dk_parent:
                continue

            # Skip if it's an epic (epics don't need parents)
            if "epic" in issue.tags:
                continue

            # Skip if it's already done
            if issue.status == "done":
                continue

            orphaned.append(issue)

        if orphaned:
            self._log.info("orphaned_beads_found", count=len(orphaned))
            for issue in orphaned[:5]:  # Limit to first 5
                self.propose_change(
                    change_type="orphaned_bead_detected",
                    target=f"bead:{issue.id}",
                    description=f"Orphaned bead '{issue.title}' has no parent epic",
                )

    async def _check_stale_beads(self, graph: Any) -> None:
        """Find beads that have been open too long."""
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        stale_threshold = self.gardener_config.stale_days_threshold
        warn_threshold = self.gardener_config.warn_days_threshold

        stale = []
        warning = []

        for issue in graph.issues:
            # Only check open/ready beads
            if issue.status not in ("open", "ready"):
                continue

            # Calculate age in days
            age_days = (now - issue.updated).days

            if age_days >= stale_threshold:
                stale.append((issue, age_days))
            elif age_days >= warn_threshold:
                warning.append((issue, age_days))

        if stale:
            self._log.info("stale_beads_found", count=len(stale))
            for issue, age in stale[:5]:
                self.propose_change(
                    change_type="stale_bead_detected",
                    target=f"bead:{issue.id}",
                    description=f"Bead '{issue.title}' stale for {age} days - consider closing or updating",
                )

        if warning:
            self._log.debug("beads_approaching_staleness", count=len(warning))

    async def _check_dependency_graph(self, graph: Any) -> None:
        """Validate dependency graph integrity."""
        issues_by_id = {i.id: i for i in graph.issues}
        problems = []

        # Check for missing references
        for dep in graph.deps:
            if dep.from_id not in issues_by_id:
                problems.append(f"Dep references missing bead: {dep.from_id}")
            if dep.to_id not in issues_by_id:
                problems.append(f"Dep references missing bead: {dep.to_id}")

        # Check for circular dependencies (simple cycle detection)
        # Build adjacency list for blocking deps
        blocking_graph: dict[str, list[str]] = {}
        for dep in graph.deps:
            if dep.dep_type == "blocks":
                if dep.from_id not in blocking_graph:
                    blocking_graph[dep.from_id] = []
                blocking_graph[dep.from_id].append(dep.to_id)

        # DFS to find cycles
        visited: set[str] = set()
        rec_stack: set[str] = set()

        def has_cycle(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)

            for neighbor in blocking_graph.get(node, []):
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True

            rec_stack.remove(node)
            return False

        for node in blocking_graph:
            if node not in visited and has_cycle(node):
                problems.append(f"Circular dependency detected involving bead {node}")
                break  # One cycle is enough to report

        # Check for self-references
        for dep in graph.deps:
            if dep.from_id == dep.to_id:
                problems.append(f"Self-referencing dependency on bead {dep.from_id}")

        if problems:
            self._log.warning("dependency_graph_problems", count=len(problems))
            for problem in problems[:5]:
                self.propose_change(
                    change_type="dependency_graph_issue",
                    target="deps.jsonl",
                    description=problem,
                )

    async def _check_ready_promotions(self, graph: Any, state_mgr: Any) -> None:
        """Promote beads to 'ready' when all blockers are done."""
        promotable = []

        for issue in graph.issues:
            # Only check 'open' beads (not already ready or done)
            if issue.status != "open":
                continue

            # Get blocking dependencies
            blockers = graph.get_blocking_deps(issue.id)

            # If no blockers, or all blockers are done, can promote
            if not blockers or all(b.status == "done" for b in blockers):
                promotable.append(issue)

        if promotable:
            self._log.info("promotable_beads_found", count=len(promotable))
            for issue in promotable[:5]:
                blocker_info = ""
                blockers = graph.get_blocking_deps(issue.id)
                if blockers:
                    done_titles = [b.title[:30] for b in blockers if b.status == "done"]
                    blocker_info = f" (blockers completed: {', '.join(done_titles[:2])})"

                self.propose_change(
                    change_type="ready_promotion",
                    target=f"bead:{issue.id}",
                    description=f"Bead '{issue.title}' can be promoted to 'ready'{blocker_info}",
                )

                # Actually perform the update if not in dry-run mode
                if not self.config.dry_run:
                    state_mgr.update_issue(issue.id, status="ready")

    async def _check_completed_updates(self, graph: Any, state_mgr: Any) -> None:
        """Scan recent events for completed work and update beads."""
        import json
        from datetime import UTC, datetime

        events_file = self.repo_root / ".cyntra" / "logs" / "events.jsonl"
        if not events_file.exists():
            return

        now = datetime.now(UTC)
        lookback_hours = self.gardener_config.events_lookback_hours
        recent_completions: dict[str, dict] = {}

        # Parse recent events
        try:
            with open(events_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        event_type = event.get("type", "")
                        timestamp_str = event.get("timestamp", "")

                        # Parse timestamp
                        try:
                            ts = datetime.fromisoformat(timestamp_str.rstrip("Z"))
                            ts = ts.replace(tzinfo=UTC)
                        except (ValueError, TypeError):
                            continue

                        # Check if recent enough
                        age_hours = (now - ts).total_seconds() / 3600
                        if age_hours > lookback_hours:
                            continue

                        # Track completions
                        issue_id = event.get("issue_id")
                        if issue_id and event_type in ("issue.completed", "workcell.completed"):
                            recent_completions[issue_id] = event

                    except json.JSONDecodeError:
                        continue
        except OSError:
            return

        if not recent_completions:
            return

        # Check if any completed issues need description updates
        issues_by_id = {i.id: i for i in graph.issues}

        for issue_id, event in recent_completions.items():
            issue = issues_by_id.get(issue_id)
            if not issue:
                continue

            # If issue is now done but description doesn't mention completion
            if issue.status == "done":
                event_data = event.get("data", {})
                toolchain = event_data.get("toolchain", "unknown")

                # Propose adding completion note
                self.propose_change(
                    change_type="completion_annotation",
                    target=f"bead:{issue_id}",
                    description=f"Bead '{issue.title}' completed via {toolchain} - consider adding implementation notes",
                )

        self._log.info(
            "scanned_recent_completions",
            count=len(recent_completions),
        )


__all__ = [
    "BeadGardenerConfig",
    "BeadGardenerSentinel",
]
