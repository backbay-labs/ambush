"""
HSM Schema - Type definitions for the Hierarchical State Machine.

This module defines all data structures for the HSM orchestration system:
- State enums for each hierarchy level (Task, Phase, Cycle)
- Guard and Action protocols
- Transition definitions
- Context and configuration types
- Runtime types for tracing and debugging

The HSM has three levels:
1. TaskStateMachine - Overall task execution (IDLE → RUNNING → COMPLETE/ABORTED)
2. PhaseStateMachine - Per-phase execution (INIT → EXECUTE → EVALUATE → ...)
3. CycleStateMachine - Per-cycle execution (PREPARE → RUN → ASSESS → DONE)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Protocol, TypeVar

if TYPE_CHECKING:
    from hellcat.core.topology.cycle import PolicySignals

__all__ = [
    # State Enums
    "TaskState",
    "PhaseState",
    "CycleState",
    # Protocols
    "Guard",
    "Action",
    "AsyncAction",
    # Core Types
    "Transition",
    "StateContext",
    "TransitionEvent",
    "TransitionResult",
    # Continuous State
    "TaskContinuousState",
    "PhaseContinuousState",
    "CycleContinuousState",
    # Runtime Types
    "StateSnapshot",
    "HSMStateSnapshot",
    "ExecutionTrace",
    # Configuration
    "StateMachineConfig",
    "HSMConfig",
    # Utilities
    "StateType",
]


# =============================================================================
# State Enums
# =============================================================================


class TaskState(Enum):
    """
    Top-level states for task execution.

    State Machine:
        IDLE → RUNNING → COMPLETE
                      ↘ ABORTED
    """

    IDLE = auto()  # Task not started, waiting for start signal
    RUNNING = auto()  # Actively executing phases
    COMPLETE = auto()  # All phases completed successfully (terminal)
    ABORTED = auto()  # Execution terminated before completion (terminal)

    @property
    def is_terminal(self) -> bool:
        """Check if this is a terminal state."""
        return self in (TaskState.COMPLETE, TaskState.ABORTED)


class PhaseState(Enum):
    """
    States for phase execution.

    State Machine:
        INIT → EXECUTE → EVALUATE → SYNTHESIZE → COMPLETE
                           ↓ ↑         ↑
                        SPECULATE ─────┘
                           ↓
                        ESCALATE → FAILED
    """

    INIT = auto()  # Phase initialized, preparing context
    EXECUTE = auto()  # Running a cycle (workcell active)
    EVALUATE = auto()  # Assessing cycle outcome, policy decision
    SYNTHESIZE = auto()  # Combining outputs from successful cycles
    SPECULATE = auto()  # Running parallel speculative attempts
    ESCALATE = auto()  # Waiting for escalation resolution
    COMPLETE = auto()  # Phase completed successfully (terminal)
    FAILED = auto()  # Phase failed, cannot proceed (terminal)

    @property
    def is_terminal(self) -> bool:
        """Check if this is a terminal state."""
        return self in (PhaseState.COMPLETE, PhaseState.FAILED)

    @property
    def is_active(self) -> bool:
        """Check if this state indicates active execution."""
        return self in (PhaseState.EXECUTE, PhaseState.SPECULATE)


class CycleState(Enum):
    """
    States for a single cycle (Claude invocation) execution.

    State Machine:
        PREPARE → RUN → ASSESS → DONE
    """

    PREPARE = auto()  # Building context, preparing prompt
    RUN = auto()  # Claude is executing (workcell active)
    ASSESS = auto()  # Evaluating outcome, running gates
    DONE = auto()  # Cycle complete (terminal)

    @property
    def is_terminal(self) -> bool:
        """Check if this is a terminal state."""
        return self == CycleState.DONE


# Type alias for any state type
StateType = TypeVar("StateType", TaskState, PhaseState, CycleState)


# =============================================================================
# Guard and Action Protocols
# =============================================================================


class Guard(Protocol):
    """
    Protocol for transition guard functions.

    Guards determine whether a transition can fire based on
    current signals and context.
    """

    def __call__(
        self,
        signals: PolicySignals,
        context: StateContext,
    ) -> bool:
        """
        Evaluate whether the transition should fire.

        Args:
            signals: Current policy signals (failures, progress, etc.)
            context: Current state context

        Returns:
            True if transition should fire, False otherwise
        """
        ...


class Action(Protocol):
    """
    Protocol for synchronous transition action functions.

    Actions are executed when a transition fires.
    """

    def __call__(self, context: StateContext) -> None:
        """
        Execute the transition action.

        Args:
            context: Current state context (may be modified)
        """
        ...


class AsyncAction(Protocol):
    """
    Protocol for asynchronous transition action functions.

    Used for actions that need to await I/O operations.
    """

    async def __call__(self, context: StateContext) -> None:
        """
        Execute the async transition action.

        Args:
            context: Current state context (may be modified)
        """
        ...


# =============================================================================
# Transition Types
# =============================================================================


@dataclass
class Transition:
    """
    A state transition with guard and action.

    Transitions are evaluated in priority order (highest first).
    The first transition whose guard returns True is executed.
    """

    from_state: Enum  # TaskState | PhaseState | CycleState
    to_state: Enum  # Must be same type as from_state
    name: str  # Human-readable name for logging

    guard: Callable[[PolicySignals, StateContext], bool]
    action: Callable[[StateContext], None] | None = None

    priority: int = 0  # Higher priority = checked first

    # Optional metadata
    description: str = ""
    is_fallback: bool = False  # True if this is a default/fallback transition

    def __post_init__(self) -> None:
        """Validate transition consistency."""
        if type(self.from_state) is not type(self.to_state):
            raise ValueError(
                f"Transition states must be same type: "
                f"{type(self.from_state).__name__} vs {type(self.to_state).__name__}"
            )


@dataclass
class TransitionEvent:
    """Event emitted when a transition occurs."""

    timestamp: datetime
    from_state: Enum
    to_state: Enum
    transition_name: str

    # Context snapshot at transition time
    context_snapshot: dict[str, Any] = field(default_factory=dict)

    # Optional metadata
    signals_snapshot: dict[str, Any] | None = None
    duration_ms: int | None = None


@dataclass
class TransitionResult:
    """Result of attempting a transition."""

    success: bool
    from_state: Enum
    to_state: Enum | None  # None if no transition taken
    transition_name: str | None

    # Action execution details
    action_result: Any | None = None
    error: str | None = None

    # Timing
    guard_eval_ms: float = 0.0
    action_exec_ms: float = 0.0


# =============================================================================
# State Context
# =============================================================================


@dataclass
class StateContext:
    """
    Context passed to guards and actions.

    Contains both discrete state identifiers and continuous metrics.
    This is the primary data structure for decision-making.
    """

    # === Task Identification ===
    task_id: str
    task_description: str = ""

    # === Position in Hierarchy ===
    total_phases: int = 1
    current_phase_index: int = 0
    current_phase_name: str = ""

    # === Phase Progress ===
    phase_progress: float = 0.0  # 0.0 - 1.0
    cycle_count: int = 0
    max_cycles: int = 5

    # === Failure Tracking ===
    consecutive_failures: int = 0
    cycles_without_progress: int = 0
    last_progress_cycle: int = 0

    # === Resource Usage ===
    tokens_used: int = 0
    time_elapsed_ms: int = 0
    token_budget: int = 1_000_000
    time_budget_ms: int = 1_800_000  # 30 min

    # === Accumulated Knowledge ===
    working_approaches: list[str] = field(default_factory=list)
    failed_approaches: list[str] = field(default_factory=list)
    key_findings: list[str] = field(default_factory=list)

    # === Files and Outputs ===
    files_created: list[str] = field(default_factory=list)
    intermediate_outputs: dict[str, str] = field(default_factory=dict)

    # === Memory Layer Injection ===
    memory_hints: list[dict[str, Any]] = field(default_factory=list)

    # === External Data ===
    data: dict[str, Any] = field(default_factory=dict)

    # === Cockpit Integration (optional) ===
    cockpit_id: str | None = None
    available_skills: list[str] = field(default_factory=list)
    autonomy_level: str = "high"  # low, medium, high, full

    # === Timestamps ===
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def snapshot(self) -> dict[str, Any]:
        """Create a snapshot for logging/tracing."""
        return {
            "task_id": self.task_id,
            "current_phase_index": self.current_phase_index,
            "current_phase_name": self.current_phase_name,
            "phase_progress": self.phase_progress,
            "cycle_count": self.cycle_count,
            "consecutive_failures": self.consecutive_failures,
            "tokens_used": self.tokens_used,
            "time_elapsed_ms": self.time_elapsed_ms,
        }

    def set_data(self, key: str, value: Any) -> None:
        """Set a data value and update timestamp."""
        self.data[key] = value
        self.updated_at = datetime.now(UTC)

    def get_data(self, key: str, default: Any = None) -> Any:
        """Get a data value."""
        return self.data.get(key, default)

    @property
    def budget_remaining_tokens(self) -> int:
        """Remaining token budget."""
        return max(0, self.token_budget - self.tokens_used)

    @property
    def budget_remaining_time_ms(self) -> int:
        """Remaining time budget in milliseconds."""
        return max(0, self.time_budget_ms - self.time_elapsed_ms)

    @property
    def budget_exhausted(self) -> bool:
        """Check if any budget is exhausted."""
        return self.budget_remaining_tokens <= 0 or self.budget_remaining_time_ms <= 0

    @classmethod
    def from_cockpit(
        cls,
        cockpit_id: str,
        task_id: str,
        task_description: str = "",
        total_phases: int = 1,
        available_skills: list[str] | None = None,
        autonomy_level: str = "high",
        token_budget: int = 1_000_000,
        max_cycles: int = 5,
    ) -> StateContext:
        """
        Factory method to create StateContext from cockpit settings.

        This provides a clean API for creating cockpit-integrated contexts
        without needing to import the full cockpit module.

        Args:
            cockpit_id: ID of the cockpit session
            task_id: Task being executed
            task_description: Description of the task
            total_phases: Number of phases in topology
            available_skills: Skills available in this cockpit
            autonomy_level: Autonomy level (low/medium/high/full)
            token_budget: Token budget for the task
            max_cycles: Maximum cycles per phase

        Returns:
            Configured StateContext
        """
        return cls(
            task_id=task_id,
            task_description=task_description,
            total_phases=total_phases,
            max_cycles=max_cycles,
            token_budget=token_budget,
            cockpit_id=cockpit_id,
            available_skills=available_skills or [],
            autonomy_level=autonomy_level,
        )


# =============================================================================
# Continuous State Types
# =============================================================================


@dataclass
class TaskContinuousState:
    """Continuous state tracked at the task level."""

    # Progress (0.0 - 1.0)
    total_progress: float = 0.0

    # Resource consumption
    total_tokens: int = 0
    total_time_ms: int = 0

    # Phase tracking
    current_phase_index: int = 0
    phases_completed: int = 0

    # Quality metrics
    overall_gate_pass_rate: float = 0.0

    # Risk indicators
    consecutive_phase_failures: int = 0
    escalation_count: int = 0

    def update_from_phases(self, phase_states: list[PhaseContinuousState]) -> None:
        """Update aggregate metrics from phase states."""
        if not phase_states:
            return

        completed = sum(1 for p in phase_states if p.phase_progress >= 1.0)
        self.phases_completed = completed
        self.total_progress = completed / len(phase_states)

        self.total_tokens = sum(p.tokens_used for p in phase_states)
        self.total_time_ms = sum(p.time_used_ms for p in phase_states)


@dataclass
class PhaseContinuousState:
    """Continuous state tracked at the phase level."""

    # Progress (0.0 - 1.0)
    phase_progress: float = 0.0

    # Cycle tracking
    cycle_count: int = 0
    max_cycles: int = 5

    # Failure tracking
    consecutive_failures: int = 0
    cycles_without_progress: int = 0
    last_progress_cycle: int = 0

    # Quality metrics
    gate_pass_rate: float = 0.0

    # Resource usage
    tokens_used: int = 0
    time_used_ms: int = 0

    # Dynamics signals
    trap_probability: float = 0.0
    entropy_production: float = 0.0

    def update_from_cycle(
        self,
        success: bool,
        partial_progress: float,
        tokens: int,
        time_ms: int,
        gates_passed: int,
        gates_total: int,
    ) -> None:
        """Update state from cycle outcome."""
        self.cycle_count += 1

        if success:
            self.phase_progress = 1.0
            self.consecutive_failures = 0
            self.last_progress_cycle = self.cycle_count
            self.cycles_without_progress = 0
        else:
            self.phase_progress = max(self.phase_progress, partial_progress)
            self.consecutive_failures += 1
            if partial_progress > self.phase_progress:
                self.last_progress_cycle = self.cycle_count
                self.cycles_without_progress = 0
            else:
                self.cycles_without_progress = self.cycle_count - self.last_progress_cycle

        self.tokens_used += tokens
        self.time_used_ms += time_ms

        if gates_total > 0:
            new_rate = gates_passed / gates_total
            # Exponential moving average
            self.gate_pass_rate = 0.7 * self.gate_pass_rate + 0.3 * new_rate


@dataclass
class CycleContinuousState:
    """Continuous state tracked at the cycle level."""

    # Resource usage
    tokens_used: int = 0
    time_elapsed_ms: int = 0

    # Gate results
    gates_status: dict[str, bool] = field(default_factory=dict)

    # Execution metrics
    patch_size_lines: int = 0
    files_touched: int = 0
    tool_calls_count: int = 0
    error_count: int = 0

    @property
    def gates_passed(self) -> list[str]:
        """List of passed gate names."""
        return [name for name, passed in self.gates_status.items() if passed]

    @property
    def gates_failed(self) -> list[str]:
        """List of failed gate names."""
        return [name for name, passed in self.gates_status.items() if not passed]

    @property
    def all_gates_passed(self) -> bool:
        """Check if all gates passed."""
        return len(self.gates_failed) == 0 and len(self.gates_status) > 0


# =============================================================================
# Runtime Types
# =============================================================================


@dataclass
class StateSnapshot:
    """Snapshot of HSM state at a point in time."""

    timestamp: datetime
    task_state: TaskState
    phase_state: PhaseState | None = None
    cycle_state: CycleState | None = None
    context: StateContext | None = None

    def state_path(self) -> str:
        """Get dot-separated state path."""
        parts = [self.task_state.name]
        if self.phase_state:
            parts.append(self.phase_state.name)
        if self.cycle_state:
            parts.append(self.cycle_state.name)
        return ".".join(parts)


@dataclass
class HSMStateSnapshot:
    """Extended snapshot for dynamics layer integration."""

    # State path
    state_path: str  # e.g., "RUNNING.EXECUTE.RUN"

    # Discrete states
    task_state: TaskState
    phase_state: PhaseState | None
    cycle_state: CycleState | None

    # Continuous features for hashing
    continuous_features: dict[str, float] = field(default_factory=dict)

    # Additional context
    context: dict[str, Any] = field(default_factory=dict)

    # Timestamp
    timestamp: float = field(default_factory=lambda: datetime.now(UTC).timestamp())

    def to_state_id(self) -> str:
        """
        Convert to T1 state ID for dynamics layer.

        Format: "task:{state}|phase:{state}|cycle:{state}|{binned_features}"
        """
        parts = [f"task:{self.task_state.name}"]

        if self.phase_state:
            parts.append(f"phase:{self.phase_state.name}")
        if self.cycle_state:
            parts.append(f"cycle:{self.cycle_state.name}")

        # Add binned continuous features
        for key, value in sorted(self.continuous_features.items()):
            parts.append(f"{key}:{self._bin_feature(key, value)}")

        return "|".join(parts)

    def _bin_feature(self, key: str, value: float) -> str:
        """Bin a continuous feature to discrete buckets."""
        if key == "progress":
            if value < 0.3:
                return "early"
            if value < 0.7:
                return "mid"
            return "late"
        elif key == "failures":
            if value == 0:
                return "0"
            if value <= 2:
                return "1-2"
            return "3+"
        elif key == "cycles":
            if value <= 2:
                return "1-2"
            if value <= 5:
                return "3-5"
            return "6+"
        else:
            # Default: round to 1 decimal
            return f"{value:.1f}"


@dataclass
class ExecutionTrace:
    """Complete trace of HSM execution for debugging and learning."""

    task_id: str
    topology_name: str

    # State history
    snapshots: list[StateSnapshot] = field(default_factory=list)
    transitions: list[TransitionEvent] = field(default_factory=list)

    # Final outcome
    final_outcome: str = ""  # "complete", "aborted", "failed", "timeout"
    final_state_path: str = ""

    # Aggregate metrics
    total_tokens: int = 0
    total_time_ms: int = 0
    total_cycles: int = 0
    total_phases: int = 0

    # Phase details
    cycles_per_phase: dict[str, int] = field(default_factory=dict)
    phase_outcomes: dict[str, str] = field(default_factory=dict)

    # Timestamps
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ended_at: datetime | None = None

    def add_snapshot(self, snapshot: StateSnapshot) -> None:
        """Add a state snapshot."""
        self.snapshots.append(snapshot)

    def add_transition(self, event: TransitionEvent) -> None:
        """Add a transition event."""
        self.transitions.append(event)

    def finalize(
        self,
        outcome: str,
        total_tokens: int,
        total_time_ms: int,
    ) -> None:
        """Finalize the trace with final metrics."""
        self.final_outcome = outcome
        self.total_tokens = total_tokens
        self.total_time_ms = total_time_ms
        self.ended_at = datetime.now(UTC)

        if self.snapshots:
            self.final_state_path = self.snapshots[-1].state_path()


# =============================================================================
# Configuration Types
# =============================================================================


@dataclass
class StateMachineConfig:
    """Configuration for a single state machine level."""

    name: str  # "task", "phase", or "cycle"
    initial_state: Enum
    terminal_states: set[Enum]
    transitions: list[Transition] = field(default_factory=list)

    # Safety limits
    max_transitions: int = 1000  # Prevent infinite loops
    max_time_ms: int = 1_800_000  # 30 minutes

    # Behavior
    check_invariants: bool = True  # Enable runtime invariant checking
    log_transitions: bool = True  # Log every transition

    def get_transitions_from(self, state: Enum) -> list[Transition]:
        """Get all transitions originating from a state, sorted by priority."""
        transitions = [t for t in self.transitions if t.from_state == state]
        return sorted(transitions, key=lambda t: t.priority, reverse=True)


@dataclass
class HSMConfig:
    """Top-level configuration for the Hierarchical State Machine."""

    # Per-level configs
    task_config: StateMachineConfig
    phase_config: StateMachineConfig
    cycle_config: StateMachineConfig

    # Integration flags
    enable_logging: bool = True
    enable_dynamics: bool = True
    enable_memory_injection: bool = True

    # Dynamics settings
    dynamics_db_path: str | None = None
    transition_logging: bool = True

    # Memory settings
    max_patterns_per_phase: int = 5
    pattern_relevance_threshold: float = 0.6

    # Safety
    abort_on_invariant_violation: bool = False

    @classmethod
    def default(cls) -> HSMConfig:
        """Create default HSM configuration."""
        return cls(
            task_config=StateMachineConfig(
                name="task",
                initial_state=TaskState.IDLE,
                terminal_states={TaskState.COMPLETE, TaskState.ABORTED},
            ),
            phase_config=StateMachineConfig(
                name="phase",
                initial_state=PhaseState.INIT,
                terminal_states={PhaseState.COMPLETE, PhaseState.FAILED},
            ),
            cycle_config=StateMachineConfig(
                name="cycle",
                initial_state=CycleState.PREPARE,
                terminal_states={CycleState.DONE},
            ),
        )


# =============================================================================
# Guard Factory Functions
# =============================================================================


def always_true() -> Guard:
    """Guard that always returns True."""

    def guard(signals: PolicySignals, context: StateContext) -> bool:
        return True

    return guard


def always_false() -> Guard:
    """Guard that always returns False."""

    def guard(signals: PolicySignals, context: StateContext) -> bool:
        return False

    return guard


def failures_exceeded(threshold: int) -> Guard:
    """Guard: consecutive failures exceed threshold."""

    def guard(signals: PolicySignals, context: StateContext) -> bool:
        return context.consecutive_failures >= threshold

    return guard


def completion_reached(threshold: float = 1.0) -> Guard:
    """Guard: phase completion reached threshold."""

    def guard(signals: PolicySignals, context: StateContext) -> bool:
        return context.phase_progress >= threshold

    return guard


def cycles_exceeded(threshold: int) -> Guard:
    """Guard: cycle count exceeded threshold."""

    def guard(signals: PolicySignals, context: StateContext) -> bool:
        return context.cycle_count >= threshold

    return guard


def budget_exhausted() -> Guard:
    """Guard: token or time budget exhausted."""

    def guard(signals: PolicySignals, context: StateContext) -> bool:
        return context.budget_exhausted

    return guard


def data_flag_set(key: str, expected: bool = True) -> Guard:
    """Guard: check if a data flag is set."""

    def guard(signals: PolicySignals, context: StateContext) -> bool:
        return context.get_data(key, not expected) == expected

    return guard


# =============================================================================
# Compound Guard Factories
# =============================================================================


def all_of(*guards: Guard) -> Guard:
    """Compound guard: all guards must pass."""

    def compound(signals: PolicySignals, context: StateContext) -> bool:
        return all(g(signals, context) for g in guards)

    return compound


def any_of(*guards: Guard) -> Guard:
    """Compound guard: any guard must pass."""

    def compound(signals: PolicySignals, context: StateContext) -> bool:
        return any(g(signals, context) for g in guards)

    return compound


def not_guard(guard: Guard) -> Guard:
    """Compound guard: negation."""

    def negated(signals: PolicySignals, context: StateContext) -> bool:
        return not guard(signals, context)

    return negated
