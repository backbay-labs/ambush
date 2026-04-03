"""
Scheduler - Computes ready set, critical path, and lane packing.

Responsibilities:
- Compute which issues are ready to work on
- Find the critical path through the dependency graph
- Pack ready issues into parallel execution lanes
- Trigger speculate+vote mode for high-risk tasks
- Prevent starvation of long-waiting tasks
"""

from __future__ import annotations

import contextlib
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from cyntra.core.control.exploration_controller import ExplorationController

if TYPE_CHECKING:
    from cyntra.cognition.dynamics.transition_db import TransitionDB
    from cyntra.cognition.strategy.profiles import DomainProfileStore
    from cyntra.core.scheduler.routing import KernelConfig
    from cyntra.core.state.models import BeadsGraph, Issue

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    """Get current UTC time as timezone-aware datetime."""
    return datetime.now(UTC)


# Size to hours mapping for critical path calculation
SIZE_TO_HOURS = {"XS": 1, "S": 2, "M": 4, "L": 8, "XL": 16}

RunMode = Literal["single", "speculate"]


@dataclass
class PriorityAdjustment:
    """Adjustment to issue priority based on memory/dynamics signals."""

    issue_id: str
    base_priority: int
    adjusted_priority: int
    adjustments: list[tuple[str, float]]  # (source, delta)
    reason: str

    @property
    def total_delta(self) -> float:
        return sum(d for _, d in self.adjustments)


@dataclass(frozen=True)
class SchedulingSignals:
    """Read-only snapshot of runtime signals used for scheduling."""

    cycle_started_at: datetime
    running_task_ids: set[str] = field(default_factory=set)
    priority_ranks: dict[str, int] = field(default_factory=dict)
    speculate_parallelism: dict[str, int] = field(default_factory=dict)
    trap_state_ids: set[str] = field(default_factory=set)
    anti_patterns: list[dict[str, Any]] = field(default_factory=list)
    success_patterns: list[dict[str, Any]] = field(default_factory=list)
    priority_weights: dict[str, float] = field(default_factory=dict)

    @property
    def cycle_started_at_ms(self) -> int:
        return int(self.cycle_started_at.timestamp() * 1000)

    @classmethod
    def empty(
        cls,
        *,
        now: datetime | None = None,
        running_task_ids: set[str] | None = None,
    ) -> "SchedulingSignals":
        return cls(
            cycle_started_at=now or _utc_now(),
            running_task_ids=set(running_task_ids or set()),
        )


@dataclass(frozen=True)
class IssuePlan:
    issue_id: str
    run_mode: RunMode
    parallelism: int
    estimated_tokens: int
    priority_score: float
    base_priority: int
    adjusted_priority: int
    is_critical_path: bool
    admission_reason: str
    skip_reason: str | None = None


@dataclass(frozen=True)
class SchedulePlan:
    """Result of a scheduling cycle."""

    cycle_started_at_ms: int
    ready_issue_ids: list[str]
    critical_path_ids: list[str]
    scheduled: list[IssuePlan]
    skipped: list[IssuePlan]
    budgets: dict[str, int]
    priority_adjustments: list[PriorityAdjustment] = field(default_factory=list)

    @property
    def total_estimated_tokens(self) -> int:
        """Total estimated tokens for scheduled work."""
        return sum(i.estimated_tokens * i.parallelism for i in self.scheduled)

    def summary(self) -> str:
        """Human-readable summary."""
        adjustments = (
            f", Adjustments: {len(self.priority_adjustments)}" if self.priority_adjustments else ""
        )
        return (
            f"Ready: {len(self.ready_issue_ids)}, "
            f"Scheduled: {len(self.scheduled)}, "
            f"Speculate: {len([i for i in self.scheduled if i.run_mode == 'speculate'])}, "
            f"Tokens: {self.total_estimated_tokens:,}"
            f"{adjustments}"
        )


class Scheduler:
    """
    Computes ready set, critical path, and lane packing.

    The scheduler implements a priority-based algorithm that:
    1. Finds all issues with satisfied dependencies
    2. Computes critical path through the dependency graph
    3. Prioritizes critical path items
    4. Packs into parallel lanes respecting resource constraints
    5. Identifies candidates for speculate+vote mode
    6. Applies memory-informed priority adjustments
    7. Deprioritizes issues in known trap states
    """

    def __init__(
        self,
        config: KernelConfig,
        transition_db: TransitionDB | None = None,
        domain_profiles: "DomainProfileStore | None" = None,
    ) -> None:
        self.config = config
        self._transition_db = transition_db
        self._domain_profiles = domain_profiles

    def schedule(self, graph: BeadsGraph, signals: SchedulingSignals) -> SchedulePlan:
        """
        Run a full scheduling cycle.

        Returns a SchedulePlan built from ready issues and runtime signals.
        """
        ready_set = self.compute_ready_set(graph, signals.running_task_ids)
        critical_path = self.compute_critical_path(graph)
        ready_set = self.prevent_starvation(ready_set, signals.cycle_started_at)

        # Compute priority adjustments from memory/dynamics
        priority_adjustments = self._compute_priority_adjustments(ready_set, signals)

        # Apply adjustments to ready set ordering
        ready_set = self._apply_priority_adjustments(ready_set, priority_adjustments)
        ordered_ready_set = self._order_ready_set(
            ready_set,
            critical_path,
            signals,
            priority_adjustments,
        )

        scheduled, skipped, budgets = self.pack_lanes(
            ordered_ready_set,
            critical_path,
            signals,
            priority_adjustments,
        )

        return SchedulePlan(
            cycle_started_at_ms=signals.cycle_started_at_ms,
            ready_issue_ids=[i.id for i in ordered_ready_set],
            critical_path_ids=[i.id for i in critical_path],
            scheduled=scheduled,
            skipped=skipped,
            budgets=budgets,
            priority_adjustments=priority_adjustments,
        )

    def compute_ready_set(
        self,
        graph: BeadsGraph,
        running_task_ids: set[str],
    ) -> list[Issue]:
        """
        Compute which issues are ready to work on.

        An issue is ready if:
        1. status == 'open' or status == 'ready'
        2. All blocking deps have status == 'done'
        3. Not currently running in any workcell
        4. attempts < max_attempts
        """
        ready: list[Issue] = []

        for issue in graph.issues:
            # Check status
            if issue.status not in ("open", "ready"):
                continue

            # Escalations are for humans only; never auto-schedule them.
            if any(
                t in {"escalation", "needs-human", "@human-escalated", "human-escalated"}
                for t in (issue.tags or [])
            ):
                continue

            # Check if already running
            if issue.id in running_task_ids:
                continue

            # Check attempts
            if issue.dk_attempts >= issue.dk_max_attempts:
                continue

            # Check blocking deps
            blockers = graph.get_blocking_deps(issue.id)
            if not all(b.status == "done" for b in blockers):
                continue

            # Filter out issues trapped in known bad states
            if self._is_issue_trapped(issue.id):
                logger.info("Skipping trapped issue %s", issue.id)
                continue

            ready.append(issue)

        return ready

    def _is_issue_trapped(self, issue_id: str) -> bool:
        """Check if an issue has recent transitions ending in known trap states."""
        if not self._transition_db:
            return False
        try:
            trapped_states = self._transition_db.get_trap_state_ids()
            if not trapped_states:
                return False
            placeholders = ",".join("?" for _ in trapped_states)
            sql = (
                "SELECT 1 FROM transitions "
                f"WHERE issue_id = ? AND to_state IN ({placeholders}) LIMIT 1"
            )
            row = self._transition_db.conn.execute(
                sql, (issue_id, *trapped_states),
            ).fetchone()
            return row is not None
        except Exception:
            return False

    def compute_critical_path(self, graph: BeadsGraph) -> list[Issue]:
        """
        Compute the critical path through the dependency graph.

        Critical path = longest chain weighted by estimated effort.
        Uses topological sort + dynamic programming.
        """
        eligible = [i for i in graph.issues if i.status in ("open", "ready", "running")]
        if not eligible:
            return []

        # Build adjacency list (A blocks B means edge A→B)
        adj: dict[str, list[str]] = defaultdict(list)
        in_degree: dict[str, int] = defaultdict(int)
        issue_map = {i.id: i for i in eligible}

        for dep in graph.deps:
            if dep.dep_type != "blocks":
                continue
            if dep.from_id in issue_map and dep.to_id in issue_map:
                adj[dep.from_id].append(dep.to_id)
                in_degree[dep.to_id] += 1

        # Initialize in_degree for all issues
        for issue in eligible:
            if issue.id not in in_degree:
                in_degree[issue.id] = 0

        # Topological sort using Kahn's algorithm
        queue = deque([i for i in eligible if in_degree[i.id] == 0])
        topo_order: list[Issue] = []

        while queue:
            node = queue.popleft()
            topo_order.append(node)
            for neighbor_id in adj[node.id]:
                in_degree[neighbor_id] -= 1
                if in_degree[neighbor_id] == 0:
                    neighbor = issue_map.get(neighbor_id)
                    if neighbor:
                        queue.append(neighbor)

        if not topo_order:
            return []

        # DP: longest path ending at each node
        dist = {i.id: SIZE_TO_HOURS.get(i.dk_size, 4) for i in eligible}
        parent: dict[str, str | None] = {i.id: None for i in eligible}

        for node in topo_order:
            for neighbor_id in adj[node.id]:
                neighbor = issue_map.get(neighbor_id)
                if neighbor:
                    new_dist = dist[node.id] + SIZE_TO_HOURS.get(neighbor.dk_size, 4)
                    if new_dist > dist[neighbor_id]:
                        dist[neighbor_id] = new_dist
                        parent[neighbor_id] = node.id

        # Backtrack from max
        end_id: str = max(dist, key=lambda x: dist[x])
        path: list[Issue] = []

        current: str | None = end_id
        while current:
            issue = issue_map.get(current)
            if issue:
                path.append(issue)
            current = parent.get(current)

        return list(reversed(path))

    def pack_lanes(
        self,
        ready_set: list[Issue],
        critical_path: list[Issue],
        signals: SchedulingSignals,
        priority_adjustments: list[PriorityAdjustment],
    ) -> tuple[list[IssuePlan], list[IssuePlan], dict[str, int]]:
        """
        Pack ready issues into parallel lanes respecting:
        - max_concurrent_workcells
        - max_concurrent_tokens
        - Critical path priority

        Returns (scheduled, skipped, budgets)
        """
        lanes: list[IssuePlan] = []
        skipped: list[IssuePlan] = []

        remaining_slots = self.config.max_concurrent_workcells
        remaining_tokens = self.config.max_concurrent_tokens

        ordered_ready_set = self._order_ready_set(
            ready_set,
            critical_path,
            signals,
            priority_adjustments,
        )

        # Priority 1: Critical path items that are ready
        cp_ids = {i.id for i in critical_path}
        adjustment_map = {a.issue_id: a for a in priority_adjustments}

        def adjusted_priority(issue: Issue) -> int:
            adjustment = adjustment_map.get(issue.id)
            if adjustment:
                return adjustment.adjusted_priority
            return self._priority_to_int(issue.dk_priority)

        # Pack into lanes (critical path first, then others)
        for issue in ordered_ready_set:
            est_tokens = issue.dk_estimated_tokens or 50000
            # Refine with domain profile data when issue uses default estimate
            if est_tokens == 50000 and self._domain_profiles is not None:
                domain = self._infer_domain(issue)
                issue_type = self._infer_issue_type(issue)
                profile_est = self._domain_profiles.estimate_tokens(domain, issue_type)
                if profile_est is not None:
                    est_tokens = profile_est
            run_mode = "speculate" if self.should_speculate(issue, critical_path) else "single"
            is_critical = issue.id in cp_ids
            admission_reason = "critical_path" if is_critical else "priority"
            if getattr(issue, "dk_starved", False):
                admission_reason = "starvation"
            base_priority = self._priority_to_int(issue.dk_priority)
            adjusted = adjusted_priority(issue)
            risk_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(
                issue.dk_risk, 1
            )
            priority_score = adjusted + (signals.priority_ranks.get(issue.id, 0) * 0.1) - (
                risk_rank * 0.01
            )

            # Check slot availability
            if remaining_slots <= 0:
                skipped.append(
                    IssuePlan(
                        issue_id=issue.id,
                        run_mode=run_mode,
                        parallelism=1,
                        estimated_tokens=est_tokens,
                        priority_score=float(priority_score),
                        base_priority=base_priority,
                        adjusted_priority=adjusted,
                        is_critical_path=is_critical,
                        admission_reason=admission_reason,
                        skip_reason="no_slots",
                    )
                )
                continue

            # Check token budget
            if remaining_tokens < est_tokens:
                skipped.append(
                    IssuePlan(
                        issue_id=issue.id,
                        run_mode=run_mode,
                        parallelism=1,
                        estimated_tokens=est_tokens,
                        priority_score=float(priority_score),
                        base_priority=base_priority,
                        adjusted_priority=adjusted,
                        is_critical_path=is_critical,
                        admission_reason=admission_reason,
                        skip_reason="token_limit",
                    )
                )
                continue

            parallelism = 1

            # Schedule this issue
            if run_mode == "speculate":
                from cyntra.core.routing import speculate_parallelism as routing_parallelism

                desired_parallelism = signals.speculate_parallelism.get(issue.id)
                if desired_parallelism is None:
                    desired_parallelism = routing_parallelism(self.config, issue)
                desired_parallelism = max(1, int(desired_parallelism))
                max_by_tokens = remaining_tokens // est_tokens
                max_by_slots = remaining_slots
                parallelism = max(1, min(desired_parallelism, max_by_tokens, max_by_slots))

            lanes.append(
                IssuePlan(
                    issue_id=issue.id,
                    run_mode=run_mode,
                    parallelism=parallelism,
                    estimated_tokens=est_tokens,
                    priority_score=float(priority_score),
                    base_priority=base_priority,
                    adjusted_priority=adjusted,
                    is_critical_path=is_critical,
                    admission_reason=admission_reason,
                )
            )
            remaining_slots -= parallelism
            remaining_tokens -= est_tokens * parallelism

        budgets = {
            "max_slots": self.config.max_concurrent_workcells,
            "max_tokens": self.config.max_concurrent_tokens,
            "used_slots": self.config.max_concurrent_workcells - remaining_slots,
            "used_tokens": self.config.max_concurrent_tokens - remaining_tokens,
        }

        return lanes, skipped, budgets

    def _order_ready_set(
        self,
        ready_set: list[Issue],
        critical_path: list[Issue],
        signals: SchedulingSignals,
        priority_adjustments: list[PriorityAdjustment],
    ) -> list[Issue]:
        """Order ready issues using the same priority key as lane packing."""
        if not ready_set:
            return []

        cp_ids = {i.id for i in critical_path}
        adjustment_map = {a.issue_id: a for a in priority_adjustments}

        def adjusted_priority(issue: Issue) -> int:
            adjustment = adjustment_map.get(issue.id)
            if adjustment:
                return adjustment.adjusted_priority
            return self._priority_to_int(issue.dk_priority)

        def priority_key(issue: Issue) -> tuple[int, int, int, str]:
            risk_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(
                issue.dk_risk, 1
            )
            return (
                adjusted_priority(issue),
                signals.priority_ranks.get(issue.id, 0),
                -risk_rank,
                issue.id,
            )

        cp_ready = sorted([i for i in ready_set if i.id in cp_ids], key=priority_key)
        other_ready = sorted(
            [i for i in ready_set if i.id not in cp_ids],
            key=priority_key,
        )
        return cp_ready + other_ready

    def should_speculate(self, issue: Issue, critical_path: list[Issue]) -> bool:
        """
        Determine if an issue should use speculate+vote mode.

        Triggered when:
        1. Issue has dk_speculate: true
        2. Issue is on critical path AND has dk_risk >= 'high'
        3. Config has force_speculate enabled
        """
        if not self.config.speculation.enabled:
            return False

        # Explicit speculate flag
        if issue.dk_speculate:
            return True

        # Force speculate mode
        if self.config.force_speculate:
            return True

        # Config-driven routing can request speculation for specific issue shapes.
        from cyntra.core.routing import first_matching_rule

        if first_matching_rule(self.config, issue, require_speculate=True) is not None:
            return True

        # Auto-trigger for high-risk critical path items
        if self.config.speculation.auto_trigger_on_critical_path:
            cp_ids = {i.id for i in critical_path}
            if (
                issue.id in cp_ids
                and issue.dk_risk in self.config.speculation.auto_trigger_risk_levels
            ):
                return True

        return False

    def prevent_starvation(self, ready_set: list[Issue], now: datetime) -> list[Issue]:
        """
        Boost priority of issues that have been ready but unscheduled for too long.

        This prevents lower-priority issues from being starved indefinitely.
        """
        for issue in ready_set:
            ready_since = issue.ready_since
            if not ready_since:
                ready_since = issue.updated

            if ready_since:
                # Handle timezone-aware vs naive datetimes
                if ready_since.tzinfo is None:
                    # Assume UTC if naive
                    ready_since = ready_since.replace(tzinfo=UTC)

                wait_hours = (now - ready_since).total_seconds() / 3600

                # After threshold hours waiting, boost priority
                if (
                    wait_hours > self.config.starvation_threshold_hours
                    and issue.dk_priority
                    and issue.dk_priority.startswith("P")
                ):
                    try:
                        current = int(issue.dk_priority[1])
                        issue.dk_priority = f"P{max(0, current - 1)}"
                    except ValueError:
                        pass

                # After 24 hours, force to front
                if wait_hours > 24:
                    issue.dk_priority = "P0"
                    issue.dk_starved = True

        return sorted(
            ready_set,
            key=lambda x: (x.dk_priority or "P2", not getattr(x, "dk_starved", False)),
        )

    def _compute_priority_adjustments(
        self,
        ready_set: list[Issue],
        signals: SchedulingSignals,
    ) -> list[PriorityAdjustment]:
        """
        Compute priority adjustments for each issue based on memory/dynamics.

        Adjustment sources:
        1. Trap detection: Issues in known trap states get deprioritized
        2. Anti-pattern match: Issues matching failure patterns get deprioritized
        3. Success pattern match: Issues matching success patterns get boosted
        4. Priority weights: Pre-computed weights from sleeptime rebalancer
        """
        adjustments: list[PriorityAdjustment] = []

        for issue in ready_set:
            base_priority = self._priority_to_int(issue.dk_priority)
            issue_adjustments: list[tuple[str, float]] = []
            reasons: list[str] = []

            # 1. Trap detection (from dynamics)
            trap_adjustment = self._check_trap_state(issue, signals.trap_state_ids)
            if trap_adjustment != 0:
                issue_adjustments.append(("trap_state", trap_adjustment))
                reasons.append(f"trap_state({trap_adjustment:+.1f})")

            # 2. Anti-pattern match (from memory)
            anti_adjustment = self._check_anti_patterns(issue, signals.anti_patterns)
            if anti_adjustment != 0:
                issue_adjustments.append(("anti_pattern", anti_adjustment))
                reasons.append(f"anti_pattern({anti_adjustment:+.1f})")

            # 3. Success pattern match (from memory)
            success_adjustment = self._check_success_patterns(issue, signals.success_patterns)
            if success_adjustment != 0:
                issue_adjustments.append(("success_pattern", success_adjustment))
                reasons.append(f"success_pattern({success_adjustment:+.1f})")

            # 4. Priority weights (from sleeptime rebalancer)
            weight_adjustment = self._check_priority_weights(issue, signals.priority_weights)
            if weight_adjustment != 0:
                issue_adjustments.append(("weight", weight_adjustment))
                reasons.append(f"weight({weight_adjustment:+.1f})")

            if issue_adjustments:
                total_delta = sum(d for _, d in issue_adjustments)
                # Convert fractional adjustments into an integer priority bucket (P0–P4).
                # Use "half-up" rounding on the clamped float so smaller learned signals
                # (e.g., ±0.5) can still move the bucket by 1.
                adjusted_float = max(0.0, min(4.0, float(base_priority) + float(total_delta)))
                adjusted = int(adjusted_float + 0.5)
                adjustments.append(
                    PriorityAdjustment(
                        issue_id=issue.id,
                        base_priority=base_priority,
                        adjusted_priority=adjusted,
                        adjustments=issue_adjustments,
                        reason="; ".join(reasons),
                    )
                )

        return adjustments

    def _check_trap_state(self, issue: Issue, trap_state_ids: set[str]) -> float:
        """Check if issue is in a known trap state and return adjustment."""
        if not trap_state_ids:
            return 0.0

        # Use issue ID as a proxy for state ID (simplified)
        # In practice, you'd compute the T1 hash from issue features
        if issue.id in trap_state_ids:
            return 1.0  # Deprioritize (higher P number = lower priority)

        # Also check by title/description keywords
        issue_text = f"{issue.title} {issue.description or ''}".lower()
        for trap_id in trap_state_ids:
            if trap_id.lower() in issue_text:
                return 0.5  # Partial match
        return 0.0

    def _check_anti_patterns(self, issue: Issue, anti_patterns: list[dict[str, Any]]) -> float:
        """Check if issue matches learned anti-patterns."""
        if not anti_patterns:
            return 0.0

        issue_text = f"{issue.title} {issue.description or ''}".lower()
        max_adjustment = 0.0

        for pattern in anti_patterns:
            keywords = pattern.get("keywords", [])
            weight = pattern.get("weight", 0.5)

            # Count keyword matches
            matches = sum(1 for kw in keywords if kw.lower() in issue_text)
            if matches > 0:
                # More matches = stronger adjustment
                adjustment = weight * min(1.0, matches / max(1, len(keywords)))
                max_adjustment = max(max_adjustment, adjustment)

        return max_adjustment  # Deprioritize anti-pattern matches

    def _check_success_patterns(
        self, issue: Issue, success_patterns: list[dict[str, Any]]
    ) -> float:
        """Check if issue matches learned success patterns."""
        if not success_patterns:
            return 0.0

        issue_text = f"{issue.title} {issue.description or ''}".lower()
        max_adjustment = 0.0

        for pattern in success_patterns:
            keywords = pattern.get("keywords", [])
            weight = pattern.get("weight", 0.5)

            # Count keyword matches
            matches = sum(1 for kw in keywords if kw.lower() in issue_text)
            if matches > 0:
                # More matches = stronger adjustment
                adjustment = weight * min(1.0, matches / max(1, len(keywords)))
                max_adjustment = max(max_adjustment, adjustment)

        return -max_adjustment  # Boost success pattern matches (lower priority number)

    def _check_priority_weights(self, issue: Issue, priority_weights: dict[str, float]) -> float:
        """Check for pre-computed priority weights from sleeptime."""
        if not priority_weights:
            return 0.0

        # Check by issue ID
        if issue.id in priority_weights:
            return priority_weights[issue.id]

        # Check by tag
        for tag in issue.tags or []:
            if tag in priority_weights:
                return priority_weights[tag]

        return 0.0

    def _apply_priority_adjustments(
        self, ready_set: list[Issue], adjustments: list[PriorityAdjustment]
    ) -> list[Issue]:
        """Apply priority adjustments to ready set ordering."""
        if not adjustments:
            return ready_set

        # Build adjustment map
        adj_map = {a.issue_id: a for a in adjustments}

        def sort_key(issue: Issue) -> tuple[int, str]:
            base_priority = self._priority_to_int(issue.dk_priority)
            if issue.id in adj_map:
                adjusted = adj_map[issue.id].adjusted_priority
                return (adjusted, issue.id)
            return (base_priority, issue.id)

        return sorted(ready_set, key=sort_key)

    def _priority_to_int(self, priority: str | None) -> int:
        """Convert priority string (P0-P4) to integer."""
        if not priority:
            return 2  # Default to P2
        if priority.startswith("P") and len(priority) == 2:
            try:
                return int(priority[1])
            except ValueError:
                pass
        return 2

    @staticmethod
    def _infer_domain(issue: "Issue") -> str:
        """Infer domain from issue tags or ID prefix."""
        for tag in issue.tags or []:
            if tag in ("kernel", "frontend", "infra", "fab", "research", "aegis"):
                return tag
        for prefix in ("kernel", "frontend", "infra", "fab", "research", "aegis"):
            if issue.id.startswith(prefix) or f"-{prefix}-" in issue.id:
                return prefix
        return "general"

    @staticmethod
    def _infer_issue_type(issue: "Issue") -> str:
        """Infer issue type from tags or ID."""
        tags = set(issue.tags or [])
        if tags & {"bug", "fix", "bugfix"}:
            return "bugfix"
        if tags & {"feature", "enhancement", "feat"}:
            return "feature"
        if tags & {"refactor", "cleanup"}:
            return "refactor"
        if issue.id.startswith("fix"):
            return "bugfix"
        if issue.id.startswith("feat"):
            return "feature"
        return "general"


class SchedulingSignalsBuilder:
    """Builds SchedulingSignals by refreshing memory/dynamics and caching decisions."""

    def __init__(
        self,
        config: KernelConfig,
        controller: ExplorationController | None = None,
        *,
        transition_db: TransitionDB | None = None,
        learned_context_dir: Path | None = None,
    ) -> None:
        self.config = config
        self.controller = controller or ExplorationController(config)
        self.transition_db = transition_db
        self.learned_context_dir = learned_context_dir

        # Cache for priority weights (loaded from sleeptime)
        self._priority_weights: dict[str, float] = {}
        self._trap_state_ids: set[str] = set()
        self._anti_patterns: list[dict[str, Any]] = []
        self._success_patterns: list[dict[str, Any]] = []
        self._last_context_load = 0.0

    def build(
        self,
        *,
        graph: BeadsGraph,
        running_task_ids: set[str],
        cycle_started_at: datetime | None = None,
    ) -> SchedulingSignals:
        self._refresh_context()
        cycle_started_at = cycle_started_at or _utc_now()

        from cyntra.core.routing import speculate_parallelism as routing_parallelism

        priority_ranks: dict[str, int] = {}
        speculate_parallelism: dict[str, int] = {}

        for issue in graph.issues:
            if issue.status not in ("open", "ready", "running"):
                continue
            decision = self.controller.decide(issue)
            priority_ranks[issue.id] = int(decision.priority_rank)
            desired = routing_parallelism(self.config, issue)
            if decision.speculate_parallelism is None:
                speculate_parallelism[issue.id] = int(desired)
            else:
                speculate_parallelism[issue.id] = int(decision.speculate_parallelism)

        return SchedulingSignals(
            cycle_started_at=cycle_started_at,
            running_task_ids=set(running_task_ids),
            priority_ranks=priority_ranks,
            speculate_parallelism=speculate_parallelism,
            trap_state_ids=set(self._trap_state_ids),
            anti_patterns=list(self._anti_patterns),
            success_patterns=list(self._success_patterns),
            priority_weights=dict(self._priority_weights),
        )

    def _refresh_context(self, force: bool = False) -> None:
        """Refresh cached memory/dynamics context periodically."""
        import time

        now = time.time()
        if not force and now - self._last_context_load < 60:  # Cache for 60s
            return

        self._last_context_load = now

        # Load trap state IDs from transition_db
        if self.transition_db:
            try:
                self._trap_state_ids = self.transition_db.get_trap_state_ids()
                logger.debug("Loaded %d trap state IDs", len(self._trap_state_ids))
            except Exception as e:
                logger.warning("Failed to load trap states: %s", e)

        # Load learned patterns from context dir
        if self.learned_context_dir and self.learned_context_dir.exists():
            self._load_learned_patterns()

        # Load priority weights from sleeptime
        self._load_priority_weights()

    def _load_learned_patterns(self) -> None:
        """Load anti-patterns and success patterns from learned context."""
        if not self.learned_context_dir:
            return

        self._anti_patterns = []
        self._success_patterns = []

        # Load anti-patterns
        anti_pattern_file = self.learned_context_dir / "anti_patterns.md"
        if anti_pattern_file.exists():
            try:
                content = anti_pattern_file.read_text(encoding="utf-8")
                self._anti_patterns = self._parse_patterns(content, "anti")
            except Exception as e:
                logger.warning("Failed to load anti-patterns: %s", e)

        # Load success patterns
        success_pattern_file = self.learned_context_dir / "success_patterns.md"
        if success_pattern_file.exists():
            try:
                content = success_pattern_file.read_text(encoding="utf-8")
                self._success_patterns = self._parse_patterns(content, "success")
            except Exception as e:
                logger.warning("Failed to load success patterns: %s", e)

    def _parse_patterns(self, content: str, pattern_type: str) -> list[dict[str, Any]]:
        """Parse patterns from markdown content."""
        patterns = []
        current_pattern: dict[str, Any] = {}

        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("## "):
                if current_pattern:
                    patterns.append(current_pattern)
                current_pattern = {
                    "name": line[3:].strip(),
                    "type": pattern_type,
                    "keywords": [],
                    "weight": 0.5,
                }
            elif line.startswith("- **Keywords**:") or line.startswith("- Keywords:"):
                keywords_str = line.split(":", 1)[1].strip()
                current_pattern["keywords"] = [
                    k.strip() for k in keywords_str.split(",") if k.strip()
                ]
            elif line.startswith("- **Weight**:") or line.startswith("- Weight:"):
                with contextlib.suppress(ValueError):
                    current_pattern["weight"] = float(line.split(":", 1)[1].strip())

        if current_pattern:
            patterns.append(current_pattern)

        return patterns

    def _load_priority_weights(self) -> None:
        """Load priority weights from sleeptime rebalancer output and hint store."""
        if not self.learned_context_dir:
            return

        weights_file = self.learned_context_dir / "priority_weights.json"
        if weights_file.exists():
            import json

            try:
                self._priority_weights = json.loads(weights_file.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning("Failed to load priority weights: %s", e)

        # Merge in side-channel priority hints from sleeptime consolidation
        try:
            from cyntra.core.state.priority_hints import PriorityHintStore

            # Resolve state dir: learned_context_dir is usually .cyntra/memory,
            # hints live at .cyntra/state/priority_hints.json
            state_dir = self.learned_context_dir.parent / "state"
            hint_store = PriorityHintStore(state_dir)
            hint_weights = hint_store.get_weight_map()
            for issue_id, weight in hint_weights.items():
                # Hints are additive with existing weights
                self._priority_weights[issue_id] = (
                    self._priority_weights.get(issue_id, 0.0) + weight
                )
        except Exception as e:
            logger.debug("Failed to load priority hints: %s", e)
