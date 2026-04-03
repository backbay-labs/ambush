"""
HSM Engine - Core state machine execution engine.

This module implements the execution engine for the Hierarchical State Machine:
- StateMachine: Base class for all state machines with step() method
- HierarchicalStateMachine: Manages nested state machines with event propagation
- Concrete machines: TaskStateMachine, PhaseStateMachine, CycleStateMachine

The HSM executes via repeated step() calls until reaching a terminal state.
Each step evaluates transition guards in priority order and fires the first
valid transition.
"""

from __future__ import annotations

import logging
from abc import ABC
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable

from cyntra.core.topology.hsm_schema import (
    CycleContinuousState,
    CycleState,
    ExecutionTrace,
    HSMConfig,
    HSMStateSnapshot,
    PhaseContinuousState,
    PhaseState,
    StateContext,
    StateMachineConfig,
    StateSnapshot,
    TaskContinuousState,
    TaskState,
    Transition,
    TransitionEvent,
    TransitionResult,
)

if TYPE_CHECKING:
    from cyntra.core.topology.cycle import PolicySignals

logger = logging.getLogger(__name__)

__all__ = [
    # Base classes
    "StateMachine",
    "HierarchicalStateMachine",
    # Concrete machines
    "TaskStateMachine",
    "PhaseStateMachine",
    "CycleStateMachine",
    # Factory functions
    "create_task_config",
    "create_phase_config",
    "create_cycle_config",
    "create_default_hsm",
    # Event types
    "HSMEvent",
    "StateEntryEvent",
    "StateExitEvent",
    # Cockpit-aware guard factories
    "_autonomy_allows",
    "_has_skill",
    "_cockpit_speculation_enabled",
]


# =============================================================================
# Event Types
# =============================================================================


@dataclass
class HSMEvent:
    """Base class for HSM events."""

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    level: str = ""  # "task", "phase", or "cycle"


@dataclass(kw_only=True)
class StateEntryEvent(HSMEvent):
    """Event emitted when entering a state."""

    state: Enum
    from_state: Enum | None = None
    transition_name: str = ""


@dataclass(kw_only=True)
class StateExitEvent(HSMEvent):
    """Event emitted when exiting a state."""

    state: Enum
    to_state: Enum | None = None
    transition_name: str = ""


# =============================================================================
# Base StateMachine Class
# =============================================================================


class StateMachine(ABC):
    """
    Base class for all state machines.

    Implements the core state machine logic:
    - Maintains current state
    - Evaluates transitions in priority order
    - Executes actions on transition
    - Tracks transition history
    """

    def __init__(self, config: StateMachineConfig) -> None:
        self.config = config
        self._current_state = config.initial_state
        self._history: list[TransitionResult] = []
        self._events: list[HSMEvent] = []
        self._transition_count = 0

        # Entry/exit action callbacks
        self._entry_actions: dict[Enum, Callable[[StateContext], None]] = {}
        self._exit_actions: dict[Enum, Callable[[StateContext], None]] = {}

    @property
    def name(self) -> str:
        """Machine name from config."""
        return self.config.name

    @property
    def current_state(self) -> Enum:
        """Current state of the machine."""
        return self._current_state

    @property
    def is_terminal(self) -> bool:
        """Check if machine is in a terminal state."""
        return self._current_state in self.config.terminal_states

    @property
    def transition_count(self) -> int:
        """Number of transitions executed."""
        return self._transition_count

    def can_transition(self, to_state: Enum) -> bool:
        """Check if transition to target state is possible from current state."""
        for t in self.config.transitions:
            if t.from_state == self._current_state and t.to_state == to_state:
                return True
        return False

    def get_available_transitions(self) -> list[Transition]:
        """Get all transitions available from current state, sorted by priority."""
        transitions = [
            t for t in self.config.transitions if t.from_state == self._current_state
        ]
        return sorted(transitions, key=lambda t: -t.priority)

    def register_entry_action(
        self, state: Enum, action: Callable[[StateContext], None]
    ) -> None:
        """Register an action to execute when entering a state."""
        self._entry_actions[state] = action

    def register_exit_action(
        self, state: Enum, action: Callable[[StateContext], None]
    ) -> None:
        """Register an action to execute when exiting a state."""
        self._exit_actions[state] = action

    def step(
        self, signals: "PolicySignals", context: StateContext
    ) -> TransitionResult:
        """
        Execute one state machine step.

        Evaluates all transitions from current state in priority order.
        Fires the first transition whose guard returns True.

        Args:
            signals: Current policy signals
            context: Current execution context

        Returns:
            TransitionResult describing what happened
        """
        if self.is_terminal:
            return TransitionResult(
                success=False,
                from_state=self._current_state,
                to_state=None,
                transition_name=None,
                action_result=None,
                error="Already in terminal state",
            )

        # Safety check for infinite loops
        self._transition_count += 1
        if self._transition_count > self.config.max_transitions:
            logger.error(
                f"[{self.name}] Max transitions exceeded: {self._transition_count}"
            )
            return TransitionResult(
                success=False,
                from_state=self._current_state,
                to_state=None,
                transition_name=None,
                action_result=None,
                error=f"Max transitions exceeded ({self.config.max_transitions})",
            )

        # Get transitions from current state, sorted by priority
        transitions = self.get_available_transitions()

        # Try each transition in priority order
        for transition in transitions:
            try:
                guard_result = transition.guard(signals, context)
            except Exception as e:
                logger.warning(
                    f"[{self.name}] Guard {transition.name} raised exception: {e}"
                )
                continue

            if guard_result:
                # Execute the transition
                return self._execute_transition(transition, context)

        # No valid transition found
        if self.config.log_transitions:
            logger.debug(
                f"[{self.name}] No valid transition from {self._current_state.name}"
            )

        return TransitionResult(
            success=False,
            from_state=self._current_state,
            to_state=None,
            transition_name=None,
            action_result=None,
            error="No valid transition",
        )

    def _execute_transition(
        self, transition: Transition, context: StateContext
    ) -> TransitionResult:
        """Execute a transition with entry/exit actions."""
        old_state = self._current_state

        # Execute exit action for old state
        if exit_action := self._exit_actions.get(old_state):
            try:
                exit_action(context)
            except Exception as e:
                logger.error(f"[{self.name}] Exit action for {old_state.name} failed: {e}")

        # Emit exit event
        self._events.append(
            StateExitEvent(
                level=self.name,
                state=old_state,
                to_state=transition.to_state,
                transition_name=transition.name,
            )
        )

        # Execute transition action
        action_result = None
        if transition.action:
            try:
                action_result = transition.action(context)
            except Exception as e:
                logger.error(
                    f"[{self.name}] Transition action {transition.name} failed: {e}"
                )
                return TransitionResult(
                    success=False,
                    from_state=old_state,
                    to_state=None,
                    transition_name=transition.name,
                    action_result=None,
                    error=f"Action failed: {e}",
                )

        # Perform state change
        self._current_state = transition.to_state

        # Execute entry action for new state
        if entry_action := self._entry_actions.get(transition.to_state):
            try:
                entry_action(context)
            except Exception as e:
                logger.error(
                    f"[{self.name}] Entry action for {transition.to_state.name} failed: {e}"
                )

        # Emit entry event
        self._events.append(
            StateEntryEvent(
                level=self.name,
                state=transition.to_state,
                from_state=old_state,
                transition_name=transition.name,
            )
        )

        # Log transition
        if self.config.log_transitions:
            logger.debug(
                f"[{self.name}] {old_state.name} → {transition.to_state.name} "
                f"({transition.name})"
            )

        # Create result
        result = TransitionResult(
            success=True,
            from_state=old_state,
            to_state=transition.to_state,
            transition_name=transition.name,
            action_result=action_result,
        )
        self._history.append(result)

        return result

    def force_transition(self, to_state: Enum, context: StateContext) -> bool:
        """
        Force a transition to a specific state (for recovery/testing).

        Bypasses guards but still executes entry/exit actions.
        """
        if type(to_state) is not type(self._current_state):
            logger.error(
                f"[{self.name}] Cannot force transition to different state type"
            )
            return False

        old_state = self._current_state

        # Exit action
        if exit_action := self._exit_actions.get(old_state):
            exit_action(context)

        self._current_state = to_state

        # Entry action
        if entry_action := self._entry_actions.get(to_state):
            entry_action(context)

        logger.warning(
            f"[{self.name}] Forced transition: {old_state.name} → {to_state.name}"
        )
        return True

    def reset(self) -> None:
        """Reset machine to initial state."""
        self._current_state = self.config.initial_state
        self._history.clear()
        self._events.clear()
        self._transition_count = 0

    def get_history(self) -> list[TransitionResult]:
        """Get copy of transition history."""
        return self._history.copy()

    def dequeue_events(self) -> list[HSMEvent]:
        """Get and clear pending events."""
        events = self._events.copy()
        self._events.clear()
        return events

    def snapshot(self) -> StateSnapshot:
        """Create a snapshot of current state."""
        return StateSnapshot(
            timestamp=datetime.now(timezone.utc),
            task_state=self._current_state if isinstance(self._current_state, TaskState) else TaskState.RUNNING,
            phase_state=self._current_state if isinstance(self._current_state, PhaseState) else None,
            cycle_state=self._current_state if isinstance(self._current_state, CycleState) else None,
        )


# =============================================================================
# Concrete State Machines
# =============================================================================


# === Guard Functions ===


def _always_true(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard that always returns True."""
    return True


def _always_false(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard that always returns False."""
    return False


def _all_phases_done(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: all phases completed."""
    return context.current_phase_index >= context.total_phases


def _abort_requested(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: abort has been requested."""
    return context.get_data("abort_requested", False)


def _phase_complete(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: current phase is complete."""
    return context.phase_progress >= 1.0


def _has_successful_attempts(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: has at least one successful or high-progress attempt."""
    attempts = context.get_data("attempt_history", [])
    return any(a.get("success") or a.get("partial_progress", 0) > 0.8 for a in attempts)


def _failures_below(threshold: int) -> Callable[["PolicySignals", StateContext], bool]:
    """Factory: guard for consecutive failures below threshold."""

    def guard(signals: "PolicySignals", context: StateContext) -> bool:
        return context.consecutive_failures < threshold

    return guard


def _failures_at_or_above(
    threshold: int,
) -> Callable[["PolicySignals", StateContext], bool]:
    """Factory: guard for consecutive failures at or above threshold."""

    def guard(signals: "PolicySignals", context: StateContext) -> bool:
        return context.consecutive_failures >= threshold

    return guard


def _cycles_exceeded(threshold: int) -> Callable[["PolicySignals", StateContext], bool]:
    """Factory: guard for cycle count exceeded."""

    def guard(signals: "PolicySignals", context: StateContext) -> bool:
        return context.cycle_count >= threshold

    return guard


def _can_retry(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: can retry (under cycle, failure, trap probability, and memory limits)."""
    if context.budget_exhausted:
        return False
    if context.cycle_count >= context.max_cycles:
        return False
    # Check trap probability from signals
    trap_prob = getattr(signals, "trap_probability", 0.0)
    if trap_prob > 0.7:
        return False
    if context.consecutive_failures >= 3 and trap_prob > 0.3:
        return False
    # Check memory hints for known anti-patterns
    if not _memory_allows_retry(signals, context):
        return False
    return context.consecutive_failures < 5


def _speculation_enabled(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: speculation is enabled and failures warrant it (default threshold: 2)."""
    enabled = context.get_data("speculation_enabled", True)
    threshold = context.get_data("speculation_threshold_failures", 2)
    return enabled and context.consecutive_failures >= threshold


def _speculation_enabled_at(
    threshold: int,
) -> Callable[["PolicySignals", StateContext], bool]:
    """
    Guard factory: speculation enabled with specific threshold.

    Also triggers speculation when trap probability exceeds 0.3,
    even if the failure threshold hasn't been reached.

    Args:
        threshold: Number of consecutive failures before speculation triggers

    Returns:
        Guard function
    """

    def guard(signals: "PolicySignals", context: StateContext) -> bool:
        enabled = context.get_data("speculation_enabled", True)
        if not enabled:
            return False
        trap_prob = getattr(signals, "trap_probability", 0.0)
        if trap_prob > 0.3:
            return True
        return context.consecutive_failures >= threshold

    return guard


def _escalation_resolved(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: escalation has been resolved."""
    return context.get_data("escalation_resolved", False)


def _escalation_timeout(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: escalation has timed out."""
    return context.get_data("escalation_timeout", False)


def _cycle_complete(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: current cycle is complete."""
    return context.get_data("cycle_complete", False)


def _context_prepared(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: cycle context has been prepared."""
    return context.get_data("context_prepared", False)


def _execution_complete(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: cycle execution is complete."""
    return context.get_data("execution_complete", False)


def _synthesis_failed(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: synthesis has failed and needs retry."""
    return context.get_data("synthesis_failed", False)


def _memory_allows_retry(signals: "PolicySignals", context: StateContext) -> bool:
    """Guard: check memory hints don't flag current approach as known failure."""
    if not context.memory_hints:
        return True
    for hint in context.memory_hints:
        if hint.get("type") == "anti_pattern":
            pattern = hint.get("pattern", "")
            if any(pattern in approach for approach in context.working_approaches):
                return False  # Known failure pattern, don't retry
    return True


# === Cockpit-Aware Guard Factories ===


def _autonomy_allows(
    min_level: str,
) -> Callable[["PolicySignals", StateContext], bool]:
    """
    Guard factory: check if current autonomy level permits an action.

    Autonomy levels (from lowest to highest):
    - low: Ask before everything
    - medium: Ask for important decisions
    - high: Mostly autonomous
    - full: Fully autonomous

    Args:
        min_level: Minimum autonomy level required (low/medium/high/full)

    Returns:
        Guard function that checks autonomy threshold
    """
    level_order = {"low": 1, "medium": 2, "high": 3, "full": 4}
    min_threshold = level_order.get(min_level, 3)

    def guard(signals: "PolicySignals", context: StateContext) -> bool:
        current_level = context.autonomy_level or context.get_data("autonomy_level", "high")
        current_threshold = level_order.get(current_level, 3)
        return current_threshold >= min_threshold

    return guard


def _has_skill(
    skill_id: str,
) -> Callable[["PolicySignals", StateContext], bool]:
    """
    Guard factory: check if a skill is available in the context.

    Args:
        skill_id: Skill ID to check for

    Returns:
        Guard function that checks skill availability
    """

    def guard(signals: "PolicySignals", context: StateContext) -> bool:
        # Check both the field and data dict for skills
        available = context.available_skills or context.get_data("available_skills", [])
        return skill_id in available

    return guard


def _cockpit_speculation_enabled() -> Callable[["PolicySignals", StateContext], bool]:
    """
    Guard: check if speculation is enabled via cockpit settings.

    Returns:
        Guard function that checks cockpit speculation config
    """

    def guard(signals: "PolicySignals", context: StateContext) -> bool:
        enabled = context.get_data("speculation_enabled", True)
        if not enabled:
            return False

        threshold = context.get_data("speculation_threshold_failures", 2)
        return context.consecutive_failures >= threshold

    return guard


# === Configuration Factories ===


def create_task_config() -> StateMachineConfig:
    """Create configuration for TaskStateMachine."""
    return StateMachineConfig(
        name="task",
        initial_state=TaskState.IDLE,
        terminal_states={TaskState.COMPLETE, TaskState.ABORTED},
        transitions=[
            # Start task
            Transition(
                from_state=TaskState.IDLE,
                to_state=TaskState.RUNNING,
                name="start",
                guard=_always_true,
                priority=100,
            ),
            # Abort (highest priority)
            Transition(
                from_state=TaskState.RUNNING,
                to_state=TaskState.ABORTED,
                name="abort",
                guard=_abort_requested,
                priority=200,
            ),
            # Complete (when all phases done)
            Transition(
                from_state=TaskState.RUNNING,
                to_state=TaskState.COMPLETE,
                name="all_phases_done",
                guard=_all_phases_done,
                priority=100,
            ),
        ],
    )


def create_phase_config(
    max_cycles: int = 5,
    max_failures: int = 3,
    speculation_enabled: bool = True,
    speculation_threshold: int = 2,
) -> StateMachineConfig:
    """
    Create configuration for PhaseStateMachine.

    Args:
        max_cycles: Maximum cycles before phase fails
        max_failures: Maximum consecutive failures before phase fails
        speculation_enabled: Whether speculation is enabled
        speculation_threshold: Number of failures before speculation triggers

    Returns:
        Configured StateMachineConfig for phase execution
    """
    return StateMachineConfig(
        name="phase",
        initial_state=PhaseState.INIT,
        terminal_states={PhaseState.COMPLETE, PhaseState.FAILED},
        transitions=[
            # Start execution
            Transition(
                from_state=PhaseState.INIT,
                to_state=PhaseState.EXECUTE,
                name="start_execute",
                guard=_always_true,
                priority=100,
            ),
            # Cycle complete → evaluate
            Transition(
                from_state=PhaseState.EXECUTE,
                to_state=PhaseState.EVALUATE,
                name="cycle_done",
                guard=_cycle_complete,
                priority=100,
            ),
            # Abort from any state
            Transition(
                from_state=PhaseState.EXECUTE,
                to_state=PhaseState.FAILED,
                name="abort",
                guard=_abort_requested,
                priority=200,
            ),
            Transition(
                from_state=PhaseState.EVALUATE,
                to_state=PhaseState.FAILED,
                name="abort",
                guard=_abort_requested,
                priority=200,
            ),
            # Max cycles exceeded
            Transition(
                from_state=PhaseState.EVALUATE,
                to_state=PhaseState.FAILED,
                name="max_cycles",
                guard=_cycles_exceeded(max_cycles),
                priority=150,
            ),
            # Max failures exceeded
            Transition(
                from_state=PhaseState.EVALUATE,
                to_state=PhaseState.FAILED,
                name="max_failures",
                guard=_failures_at_or_above(max_failures),
                priority=140,
            ),
            # Success → synthesize
            Transition(
                from_state=PhaseState.EVALUATE,
                to_state=PhaseState.SYNTHESIZE,
                name="phase_success",
                guard=_phase_complete,
                priority=130,
            ),
            # Try speculation on repeated failures (configurable threshold)
            Transition(
                from_state=PhaseState.EVALUATE,
                to_state=PhaseState.SPECULATE,
                name="try_speculation",
                guard=_speculation_enabled_at(speculation_threshold) if speculation_enabled else _always_false,
                priority=120,
            ),
            # Retry (default when under limits)
            Transition(
                from_state=PhaseState.EVALUATE,
                to_state=PhaseState.EXECUTE,
                name="retry",
                guard=_can_retry,
                priority=50,
            ),
            # Speculation complete → evaluate
            Transition(
                from_state=PhaseState.SPECULATE,
                to_state=PhaseState.EVALUATE,
                name="speculation_done",
                guard=_always_true,
                priority=100,
            ),
            # Escalation resolved → retry
            Transition(
                from_state=PhaseState.ESCALATE,
                to_state=PhaseState.EXECUTE,
                name="escalation_resolved",
                guard=_escalation_resolved,
                priority=100,
            ),
            # Escalation timeout → failed
            Transition(
                from_state=PhaseState.ESCALATE,
                to_state=PhaseState.FAILED,
                name="escalation_timeout",
                guard=_escalation_timeout,
                priority=90,
            ),
            # Synthesis complete
            Transition(
                from_state=PhaseState.SYNTHESIZE,
                to_state=PhaseState.COMPLETE,
                name="synthesis_done",
                guard=_always_true,
                priority=100,
            ),
            # Synthesis failure → retry execution (recovery path)
            Transition(
                from_state=PhaseState.SYNTHESIZE,
                to_state=PhaseState.EXECUTE,
                name="synthesis_retry",
                guard=_synthesis_failed,
                priority=90,
            ),
            # Fallback: if no other transition fires from EVALUATE, fail gracefully
            # This prevents deadlock when _can_retry returns False but other guards don't fire
            Transition(
                from_state=PhaseState.EVALUATE,
                to_state=PhaseState.FAILED,
                name="evaluate_fallback",
                guard=_always_true,
                priority=10,  # Lowest priority - only fires if nothing else matches
                is_fallback=True,
            ),
        ],
    )


def create_cycle_config() -> StateMachineConfig:
    """Create configuration for CycleStateMachine."""
    return StateMachineConfig(
        name="cycle",
        initial_state=CycleState.PREPARE,
        terminal_states={CycleState.DONE},
        transitions=[
            # Context prepared → run
            Transition(
                from_state=CycleState.PREPARE,
                to_state=CycleState.RUN,
                name="context_ready",
                guard=_context_prepared,
                priority=100,
            ),
            # Execution complete → assess
            Transition(
                from_state=CycleState.RUN,
                to_state=CycleState.ASSESS,
                name="execution_done",
                guard=_execution_complete,
                priority=100,
            ),
            # Abort during run
            Transition(
                from_state=CycleState.RUN,
                to_state=CycleState.DONE,
                name="abort",
                guard=_abort_requested,
                priority=200,
            ),
            # Assessment complete → done
            Transition(
                from_state=CycleState.ASSESS,
                to_state=CycleState.DONE,
                name="assess_done",
                guard=_always_true,
                priority=100,
            ),
        ],
    )


# === Concrete State Machine Classes ===


class TaskStateMachine(StateMachine):
    """
    Top-level state machine for task execution.

    States: IDLE → RUNNING → COMPLETE/ABORTED
    """

    def __init__(self, config: StateMachineConfig | None = None) -> None:
        super().__init__(config or create_task_config())
        self.continuous = TaskContinuousState()

    def start(self, context: StateContext) -> TransitionResult:
        """Start the task (IDLE → RUNNING)."""
        if self._current_state != TaskState.IDLE:
            return TransitionResult(
                success=False,
                from_state=self._current_state,
                to_state=None,
                transition_name=None,
                error="Task already started",
            )

        # Create a minimal PolicySignals for the guard
        from cyntra.core.topology.cycle import PolicySignals

        signals = PolicySignals()
        return self.step(signals, context)


class PhaseStateMachine(StateMachine):
    """
    State machine for phase execution.

    States: INIT → EXECUTE ↔ EVALUATE → SYNTHESIZE → COMPLETE
                              ↓ ↑
                           SPECULATE
                              ↓
                           ESCALATE → FAILED
    """

    def __init__(
        self,
        config: StateMachineConfig | None = None,
        max_cycles: int = 5,
        max_failures: int = 3,
    ) -> None:
        super().__init__(config or create_phase_config(max_cycles, max_failures))
        self.continuous = PhaseContinuousState(max_cycles=max_cycles)
        self.max_cycles = max_cycles
        self.max_failures = max_failures

        # Phase-specific state
        self.attempt_history: list[dict[str, Any]] = []
        self.synthesized_output: Any = None

    def record_attempt(
        self,
        success: bool,
        partial_progress: float,
        tokens: int,
        time_ms: int,
        gates_passed: int,
        gates_total: int,
    ) -> None:
        """Record a cycle attempt outcome."""
        self.continuous.update_from_cycle(
            success=success,
            partial_progress=partial_progress,
            tokens=tokens,
            time_ms=time_ms,
            gates_passed=gates_passed,
            gates_total=gates_total,
        )

        self.attempt_history.append(
            {
                "cycle": self.continuous.cycle_count,
                "success": success,
                "partial_progress": partial_progress,
                "tokens": tokens,
                "time_ms": time_ms,
                "gates_passed": gates_passed,
                "gates_failed": gates_total - gates_passed,
            }
        )


class CycleStateMachine(StateMachine):
    """
    State machine for single cycle (Claude invocation) execution.

    States: PREPARE → RUN → ASSESS → DONE
    """

    def __init__(self, config: StateMachineConfig | None = None) -> None:
        super().__init__(config or create_cycle_config())
        self.continuous = CycleContinuousState()

        # Cycle-specific state
        self.prepared_prompt: str | None = None
        self.execution_result: Any = None
        self.attempt_summary: dict[str, Any] | None = None


# =============================================================================
# Hierarchical State Machine
# =============================================================================


class HierarchicalStateMachine:
    """
    Manages nested state machines with event propagation.

    The HSM coordinates three levels:
    1. TaskStateMachine - Overall task execution
    2. PhaseStateMachine - Per-phase execution (created for each phase)
    3. CycleStateMachine - Per-cycle execution (created for each cycle)

    Each step() call propagates to the appropriate level based on current state.
    """

    def __init__(
        self,
        task_machine: TaskStateMachine,
        phase_factory: Callable[[], PhaseStateMachine],
        cycle_factory: Callable[[], CycleStateMachine],
        config: HSMConfig | None = None,
    ) -> None:
        self.task = task_machine
        self._phase_factory = phase_factory
        self._cycle_factory = cycle_factory
        self.config = config or HSMConfig.default()

        # Current child machines
        self._current_phase: PhaseStateMachine | None = None
        self._current_cycle: CycleStateMachine | None = None

        # Phase tracking
        self._phase_index = 0
        self._phases_completed: list[PhaseStateMachine] = []

        # Event queue
        self._events: list[HSMEvent] = []

        # Execution trace
        self._trace = ExecutionTrace(
            task_id="",
            topology_name="",
        )

    @property
    def active_states(
        self,
    ) -> tuple[TaskState, PhaseState | None, CycleState | None]:
        """Get current state at all levels."""
        return (
            self.task.current_state,
            self._current_phase.current_state if self._current_phase else None,
            self._current_cycle.current_state if self._current_cycle else None,
        )

    @property
    def state_path(self) -> str:
        """Get dot-separated state path."""
        parts = [self.task.current_state.name]
        if self._current_phase:
            parts.append(self._current_phase.current_state.name)
        if self._current_cycle:
            parts.append(self._current_cycle.current_state.name)
        return ".".join(parts)

    @property
    def is_terminal(self) -> bool:
        """Check if the HSM is in a terminal state."""
        return self.task.is_terminal

    @property
    def current_phase(self) -> PhaseStateMachine | None:
        """Get current phase machine."""
        return self._current_phase

    @property
    def current_cycle(self) -> CycleStateMachine | None:
        """Get current cycle machine."""
        return self._current_cycle

    def step(
        self, signals: "PolicySignals", context: StateContext
    ) -> TransitionResult:
        """
        Execute one HSM step.

        Propagates to the appropriate level based on current state:
        - If task is IDLE, step task machine
        - If task is RUNNING and no phase, create phase machine
        - If phase is EXECUTE and no cycle, create cycle machine
        - Step the deepest active machine

        Returns the result from whichever level took a transition.
        """
        # Check if already terminal
        if self.is_terminal:
            return TransitionResult(
                success=False,
                from_state=self.task.current_state,
                to_state=None,
                transition_name=None,
                error="HSM is in terminal state",
            )

        # Task is IDLE → step task to start
        if self.task.current_state == TaskState.IDLE:
            result = self.task.step(signals, context)
            self._collect_events(self.task)
            return result

        # Task is RUNNING → manage phase/cycle
        if self.task.current_state == TaskState.RUNNING:
            return self._step_running(signals, context)

        # Shouldn't reach here
        return TransitionResult(
            success=False,
            from_state=self.task.current_state,
            to_state=None,
            transition_name=None,
            error=f"Unexpected task state: {self.task.current_state}",
        )

    def _step_running(
        self, signals: "PolicySignals", context: StateContext
    ) -> TransitionResult:
        """Handle stepping when task is RUNNING."""
        # Check if all phases complete
        if self._phase_index >= context.total_phases:
            result = self.task.step(signals, context)
            self._collect_events(self.task)
            return result

        # Create phase machine if needed
        if self._current_phase is None:
            self._current_phase = self._phase_factory()
            context.current_phase_index = self._phase_index
            logger.debug(f"Created phase machine for phase {self._phase_index}")

        # Check phase state
        if self._current_phase.is_terminal:
            # Phase completed or failed
            if self._current_phase.current_state == PhaseState.COMPLETE:
                self._phases_completed.append(self._current_phase)
                self._phase_index += 1
                context.current_phase_index = self._phase_index
                self._current_phase = None
                self._current_cycle = None

                # Check if all phases done
                if self._phase_index >= context.total_phases:
                    return self.task.step(signals, context)

                # Continue to next phase
                return TransitionResult(
                    success=True,
                    from_state=PhaseState.COMPLETE,
                    to_state=None,
                    transition_name="phase_complete",
                )
            else:
                # Phase failed → abort task
                context.set_data("abort_requested", True)
                result = self.task.step(signals, context)
                self._collect_events(self.task)
                return result

        # Phase is in EXECUTE → manage cycle
        if self._current_phase.current_state == PhaseState.EXECUTE:
            return self._step_execute(signals, context)

        # Step phase machine
        result = self._current_phase.step(signals, context)
        self._collect_events(self._current_phase)
        return result

    def _step_execute(
        self, signals: "PolicySignals", context: StateContext
    ) -> TransitionResult:
        """Handle stepping when phase is in EXECUTE state."""
        # Create cycle machine if needed
        if self._current_cycle is None:
            self._current_cycle = self._cycle_factory()
            context.set_data("context_prepared", True)  # Allow PREPARE → RUN
            logger.debug(
                f"Created cycle machine (cycle {self._current_phase.continuous.cycle_count + 1})"
            )

        # Step cycle machine
        if not self._current_cycle.is_terminal:
            result = self._current_cycle.step(signals, context)
            self._collect_events(self._current_cycle)
            return result

        # Cycle is DONE → propagate to phase
        self._current_cycle = None
        context.set_data("cycle_complete", True)

        result = self._current_phase.step(signals, context)
        self._collect_events(self._current_phase)

        # Clear cycle_complete flag after phase processes it
        context.set_data("cycle_complete", False)

        return result

    def _collect_events(self, machine: StateMachine) -> None:
        """Collect events from a machine."""
        self._events.extend(machine.dequeue_events())

    def dequeue_events(self) -> list[HSMEvent]:
        """Get and clear pending events from all levels."""
        events = self._events.copy()
        self._events.clear()
        return events

    def snapshot(self) -> HSMStateSnapshot:
        """Create a complete snapshot of HSM state."""
        continuous = {
            "progress": self._current_phase.continuous.phase_progress
            if self._current_phase
            else 0.0,
            "failures": self._current_phase.continuous.consecutive_failures
            if self._current_phase
            else 0,
            "cycles": self._current_phase.continuous.cycle_count
            if self._current_phase
            else 0,
        }

        return HSMStateSnapshot(
            state_path=self.state_path,
            task_state=self.task.current_state,
            phase_state=self._current_phase.current_state if self._current_phase else None,
            cycle_state=self._current_cycle.current_state if self._current_cycle else None,
            continuous_features=continuous,
            context={
                "phase_index": self._phase_index,
                "phases_completed": len(self._phases_completed),
            },
        )

    def get_trace(self) -> ExecutionTrace:
        """Build execution trace from all levels."""
        trace = ExecutionTrace(
            task_id=self._trace.task_id,
            topology_name=self._trace.topology_name,
        )

        # Collect all snapshots and transitions
        # (simplified - full implementation would track during execution)
        trace.total_phases = len(self._phases_completed) + (
            1 if self._current_phase else 0
        )

        for phase in self._phases_completed:
            trace.cycles_per_phase[f"phase_{len(trace.cycles_per_phase)}"] = (
                phase.continuous.cycle_count
            )
            trace.total_cycles += phase.continuous.cycle_count
            trace.total_tokens += phase.continuous.tokens_used
            trace.total_time_ms += phase.continuous.time_used_ms

        return trace

    def reset(self) -> None:
        """Reset the entire HSM to initial state."""
        self.task.reset()
        self._current_phase = None
        self._current_cycle = None
        self._phase_index = 0
        self._phases_completed.clear()
        self._events.clear()


# =============================================================================
# Factory Functions
# =============================================================================


def create_default_hsm(
    max_cycles_per_phase: int = 5,
    max_failures: int = 3,
) -> HierarchicalStateMachine:
    """
    Create a default HSM with standard configuration.

    Args:
        max_cycles_per_phase: Maximum cycles per phase
        max_failures: Maximum consecutive failures before failing phase

    Returns:
        Configured HierarchicalStateMachine
    """
    task = TaskStateMachine()

    def phase_factory() -> PhaseStateMachine:
        return PhaseStateMachine(
            max_cycles=max_cycles_per_phase,
            max_failures=max_failures,
        )

    def cycle_factory() -> CycleStateMachine:
        return CycleStateMachine()

    return HierarchicalStateMachine(
        task_machine=task,
        phase_factory=phase_factory,
        cycle_factory=cycle_factory,
    )
