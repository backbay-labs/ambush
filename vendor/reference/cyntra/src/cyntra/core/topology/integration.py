"""
Topology Integration - Connects topology system with kernel runner.

Provides integration points for:
- Detecting when tasks should use topology execution
- Converting issues to topology tasks
- Connecting orchestrator with dispatcher
- Updating scheduler signals from topology adjustments
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cyntra.core.topology.schema import (
    TaskTopology,
    TopologyResult,
)
from cyntra.core.topology.planner import (
    PlanningContext,
    TopologyPlanner,
    TopologyAdjustments,
)
from cyntra.core.topology.orchestrator import (
    OrchestratorConfig,
)
from cyntra.core.topology.cycle_orchestrator import (
    CycleOrchestrator,
    CycleOrchestratorConfig,
)
from cyntra.core.topology.hsm_schema import TransitionResult
from cyntra.infra.observability.events import Event, EventEmitter, EventType

if TYPE_CHECKING:
    from cyntra.core.dispatcher.dispatcher import Dispatcher
    from cyntra.core.scheduler.routing import KernelConfig
    from cyntra.core.scheduler.scheduler import SchedulingSignals
    from cyntra.core.state.models import Issue

logger = logging.getLogger(__name__)


@dataclass
class TopologyConfig:
    """Configuration for topology execution."""

    enabled: bool = True
    templates_dir: Path | None = None
    output_dir: Path | None = None

    # Trigger conditions
    min_complexity_for_topology: str = "M"  # Only use topology for M+ sized tasks
    tags_require_topology: list[str] = field(default_factory=lambda: ["research", "multi-phase"])
    description_triggers: list[str] = field(
        default_factory=lambda: ["research", "investigate", "multi-step", "comprehensive"]
    )

    # Execution settings
    max_parallel_agents: int = 6
    default_phase_timeout_ms: int = 600_000
    keep_workcell_logs: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TopologyConfig":
        """Create from dict (e.g., from YAML config)."""
        if not data:
            return cls(enabled=False)

        templates_dir = data.get("templates_dir")
        output_dir = data.get("output_dir")

        return cls(
            enabled=data.get("enabled", True),
            templates_dir=Path(templates_dir) if templates_dir else None,
            output_dir=Path(output_dir) if output_dir else None,
            min_complexity_for_topology=data.get("min_complexity_for_topology", "M"),
            tags_require_topology=data.get("tags_require_topology", ["research", "multi-phase"]),
            description_triggers=data.get(
                "description_triggers", ["research", "investigate", "multi-step"]
            ),
            max_parallel_agents=data.get("max_parallel_agents", 6),
            default_phase_timeout_ms=data.get("default_phase_timeout_ms", 600_000),
            keep_workcell_logs=data.get("keep_workcell_logs", True),
        )


class TopologyIntegration:
    """
    Integrates topology system with kernel runner.

    Determines when to use topology execution vs. standard dispatch,
    and coordinates execution when topology is selected.
    """

    def __init__(
        self,
        kernel_config: "KernelConfig",
        topology_config: TopologyConfig | None = None,
        dispatcher: "Dispatcher | None" = None,
        transition_db: Any = None,
    ) -> None:
        self.kernel_config = kernel_config
        self.dispatcher = dispatcher

        # Load topology config from kernel config or use provided
        if topology_config:
            self.config = topology_config
        else:
            # Try to load from kernel config
            topology_data = getattr(kernel_config, "topology", None)
            if isinstance(topology_data, dict):
                self.config = TopologyConfig.from_dict(topology_data)
            else:
                self.config = TopologyConfig(enabled=False)

        # Determine templates directory
        templates_dir = self.config.templates_dir
        if not templates_dir:
            templates_dir = kernel_config.repo_root / ".cyntra" / "topologies"

        # Initialize planner
        self.planner = TopologyPlanner(
            templates_dir=templates_dir,
            config=kernel_config,
        )

        # Initialize orchestrator
        orch_config = OrchestratorConfig(
            max_concurrent_agents=self.config.max_parallel_agents,
            phase_timeout_ms=self.config.default_phase_timeout_ms,
            output_dir=self.config.output_dir or kernel_config.repo_root / "docs",
            keep_workcell_logs=self.config.keep_workcell_logs,
        )

        # Default to a learned policy when we have persistent dynamics available.
        learned_policy = None
        try:
            from cyntra.core.topology.cycle import create_learned_policy
            from cyntra.core.topology.hsm_dynamics import SQLiteDynamicsDB

            weights_path = kernel_config.repo_root / ".cyntra" / "state" / "policy_weights.json"
            dynamics_db = SQLiteDynamicsDB(transition_db) if transition_db is not None else None
            learned_policy = create_learned_policy(
                dynamics_db=dynamics_db,
                weights_path=weights_path,
            )
        except Exception:
            learned_policy = None

        self.cycle_orchestrator = CycleOrchestrator(
            config=CycleOrchestratorConfig(
                use_hsm=True,
                orchestrator_config=orch_config,
                policy=learned_policy,
                enable_dynamics_logging=True,
                transition_db=transition_db,
                on_state_transition=self._on_hsm_transition,
                kernel_config=kernel_config,
                dispatcher=dispatcher,
            )
        )
        self._event_emitter = EventEmitter(kernel_config.logs_dir)
        self._active_issue_id: str | None = None
        self._active_task_id: str | None = None

    def should_use_topology(self, issue: "Issue") -> bool:
        """
        Determine if an issue should use topology-based execution.

        Checks (in priority order):
        1. Topology is enabled
        2. Explicit topology: tag prefix (e.g., topology:research-implement)
        3. Category tags that always trigger topology
        4. Description + complexity heuristic
        """
        if not self.config.enabled:
            return False

        tags = issue.tags or []

        # Primary: explicit topology tag (e.g., "topology:research-implement")
        if any(tag.startswith("topology:") for tag in tags):
            return True

        # Secondary: category tags that always trigger topology
        if any(tag in self.config.tags_require_topology for tag in tags):
            return True

        # Tertiary: description + complexity heuristic
        desc_lower = (issue.description or "").lower()
        title_lower = (issue.title or "").lower()
        combined = f"{title_lower} {desc_lower}"

        if any(trigger in combined for trigger in self.config.description_triggers):
            size_order = ["XS", "S", "M", "L", "XL"]
            issue_size = issue.dk_size or "S"
            min_size = self.config.min_complexity_for_topology

            if size_order.index(issue_size) >= size_order.index(min_size):
                return True

        return False

    def plan_topology(
        self,
        issue: "Issue",
        signals: "SchedulingSignals | None" = None,
    ) -> TaskTopology | None:
        """
        Plan a topology for an issue.

        Returns None if no suitable template is found.
        """
        if not self.config.enabled:
            return None

        # Build planning context from scheduling signals
        context = self._build_planning_context(signals)

        # Get task description from issue
        task_description = self._build_task_description(issue)

        # Plan topology
        return self.planner.plan(
            task_description=task_description,
            context=context,
            issue=issue,
        )

    async def execute_topology(
        self,
        topology: TaskTopology,
        issue: "Issue",
        initial_context: dict[str, Any] | None = None,
    ) -> TopologyResult:
        """
        Execute a topology for an issue.

        This is an alternative to standard dispatcher execution
        for multi-phase, multi-agent tasks.
        """
        context = initial_context or {}
        context["issue_id"] = issue.id
        context["issue_title"] = issue.title

        self._active_issue_id = issue.id
        self._active_task_id = topology.name
        try:
            result = await self.cycle_orchestrator.execute(
                topology=topology,
                initial_context=context,
                issue=issue,
            )
            return result.to_topology_result()
        finally:
            self._active_issue_id = None
            self._active_task_id = None

    def _on_hsm_transition(self, result: TransitionResult) -> None:
        """Emit HSM transition events for downstream streaming."""
        if not result.success:
            return

        context_snapshot = self.cycle_orchestrator.get_hsm_context_snapshot() or {}
        state_path = self.cycle_orchestrator.get_state_path()

        event = Event(
            type=EventType.HSM_TRANSITION,
            issue_id=self._active_issue_id or context_snapshot.get("issue_id"),
            data={
                "schema_version": 1,
                "task_id": self._active_task_id or context_snapshot.get("task_id"),
                "from_state": str(result.from_state),
                "to_state": str(result.to_state) if result.to_state else None,
                "transition": result.transition_name,
                "state_path": state_path,
                "guard_eval_ms": result.guard_eval_ms,
                "action_exec_ms": result.action_exec_ms,
                "message": (
                    f"{result.from_state} -> {result.to_state}"
                    if result.to_state is not None
                    else f"{result.from_state}"
                ),
                "context": context_snapshot,
            },
        )

        # Best-effort logging for observability dashboards.
        self._event_emitter.emit(event)

    def _build_planning_context(
        self,
        signals: "SchedulingSignals | None" = None,
    ) -> PlanningContext:
        """Build planning context from scheduling signals."""
        context = PlanningContext.from_config(self.kernel_config)

        if signals:
            context.trap_state_ids = signals.trap_state_ids
            context.anti_patterns = signals.anti_patterns
            context.success_patterns = signals.success_patterns
            context.priority_weights = signals.priority_weights

        return context

    def _build_task_description(self, issue: "Issue") -> str:
        """Build task description from issue."""
        parts = [issue.title or ""]

        if issue.description:
            parts.append(issue.description)

        return "\n\n".join(parts)

    def get_topology_adjustments(
        self,
        signals: "SchedulingSignals",
    ) -> TopologyAdjustments:
        """
        Convert scheduling signals to topology adjustments.

        This bridges the kernel's learned patterns with topology execution.
        """
        adjustments = TopologyAdjustments()

        # Convert trap states to parallelism boosts
        if signals.trap_state_ids:
            adjustments.parallelism_boost["foundational"] = 1.2
            adjustments.parallelism_boost["implementation"] = 1.2
            adjustments.sources.append("trap_state_parallelism")

        # Convert anti-patterns to model tier overrides
        if signals.anti_patterns:
            for pattern in signals.anti_patterns[:3]:
                adjustments.sources.append(f"anti:{pattern.get('name', 'unknown')}")

        # Convert success patterns to phase weights
        for pattern in signals.success_patterns:
            phase_boosts = pattern.get("phase_boosts", {})
            for phase, boost in phase_boosts.items():
                adjustments.phase_weights[phase] = boost

        return adjustments


def create_topology_integration(
    kernel_config: "KernelConfig",
    dispatcher: "Dispatcher | None" = None,
    transition_db: Any = None,
) -> TopologyIntegration | None:
    """
    Create topology integration if enabled in config.

    Returns None if topology is not configured or disabled.
    """
    topology_data = getattr(kernel_config, "topology", None)

    if not topology_data:
        # Check if templates directory exists
        templates_dir = kernel_config.repo_root / ".cyntra" / "topologies"
        if templates_dir.exists() and any(templates_dir.glob("*.yaml")):
            # Auto-enable with defaults
            return TopologyIntegration(
                kernel_config=kernel_config,
                topology_config=TopologyConfig(enabled=True, templates_dir=templates_dir),
                dispatcher=dispatcher,
                transition_db=transition_db,
            )
        return None

    config = TopologyConfig.from_dict(topology_data)
    if not config.enabled:
        return None

    return TopologyIntegration(
        kernel_config=kernel_config,
        topology_config=config,
        dispatcher=dispatcher,
        transition_db=transition_db,
    )
