"""
HSM Policy - Bridges CyclePolicy system with HSM transitions.

This module provides:
- PolicyGuardAdapter: Converts CyclePolicy decisions into HSM guard functions
- HSMPolicy: Wraps CyclePolicy to ensure decisions map to valid transitions
- Guard factories that use policy evaluation

The key insight is that CyclePolicy.evaluate() returns a decision
(CONTINUE, ABORT, ESCALATE, etc.) which maps to specific state transitions
in the HSM. This module handles that mapping.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hellcat.core.topology.cycle import (
    AttemptSummary,
    CycleDecision,
    CyclePolicy,
    HeuristicCyclePolicy,
    PolicyAction,
    PolicySignals,
)
from hellcat.core.topology.hsm_schema import (
    Guard,
    PhaseState,
    StateContext,
    Transition,
)

if TYPE_CHECKING:
    from hellcat.core.topology.hsm_engine import HierarchicalStateMachine
    from hellcat.core.topology.schema import TaskTopology, TopologyPhase

logger = logging.getLogger(__name__)

__all__ = [
    "PolicyGuardAdapter",
    "HSMPolicy",
    "PolicyEvaluationCache",
    "create_policy_guard",
    "create_policy_transitions",
    "DECISION_TO_STATE",
]


# =============================================================================
# Decision → State Mapping
# =============================================================================


# Maps CycleDecision to the PhaseState it typically leads to
DECISION_TO_STATE: dict[CycleDecision, PhaseState | None] = {
    CycleDecision.CONTINUE: PhaseState.EXECUTE,
    CycleDecision.COMPLETE: PhaseState.SYNTHESIZE,
    CycleDecision.SPECULATE: PhaseState.SPECULATE,
    CycleDecision.ESCALATE: PhaseState.ESCALATE,
    CycleDecision.ABORT: PhaseState.FAILED,
    CycleDecision.RETRY: PhaseState.EXECUTE,
    CycleDecision.PIVOT: None,  # Special case - triggers replanning
}


# =============================================================================
# Policy Evaluation Cache
# =============================================================================


@dataclass
class PolicyEvaluationCache:
    """
    Caches policy evaluation results for a single step.

    This prevents re-evaluating the policy multiple times when
    multiple guards need to check the same decision.
    """

    # Last evaluation inputs (for cache invalidation)
    last_phase_state: PhaseState | None = None
    last_cycle_count: int = -1
    last_consecutive_failures: int = -1

    # Cached result
    action: PolicyAction | None = None
    confidence_map: dict[PhaseState, float] = field(default_factory=dict)

    def is_valid(self, phase_state: PhaseState, context: StateContext) -> bool:
        """Check if cached result is still valid."""
        return (
            self.action is not None
            and self.last_phase_state == phase_state
            and self.last_cycle_count == context.cycle_count
            and self.last_consecutive_failures == context.consecutive_failures
        )

    def update(
        self,
        phase_state: PhaseState,
        context: StateContext,
        action: PolicyAction,
        confidence_map: dict[PhaseState, float],
    ) -> None:
        """Update cache with new evaluation."""
        self.last_phase_state = phase_state
        self.last_cycle_count = context.cycle_count
        self.last_consecutive_failures = context.consecutive_failures
        self.action = action
        self.confidence_map = confidence_map


# =============================================================================
# Policy Guard Adapter
# =============================================================================


class PolicyGuardAdapter:
    """
    Adapts CyclePolicy decisions to state machine guards.

    This is the bridge between the policy's abstract decisions (CONTINUE,
    ESCALATE, etc.) and the HSM's concrete transitions.

    Usage:
        adapter = PolicyGuardAdapter(policy, topology, phase)
        guard = adapter.create_guard(PhaseState.SPECULATE)
        # guard can now be used in a Transition
    """

    def __init__(
        self,
        policy: CyclePolicy,
        topology: TaskTopology | None = None,
        phase: TopologyPhase | None = None,
    ) -> None:
        self.policy = policy
        self.topology = topology
        self.phase = phase
        self._cache = PolicyEvaluationCache()
        self._history: list[AttemptSummary] = []

    def set_context(
        self,
        topology: TaskTopology,
        phase: TopologyPhase,
        history: list[AttemptSummary] | None = None,
    ) -> None:
        """Update the topology/phase context."""
        self.topology = topology
        self.phase = phase
        if history is not None:
            self._history = history

    def add_attempt(self, attempt: AttemptSummary) -> None:
        """Add an attempt to history."""
        self._history.append(attempt)

    def evaluate(
        self,
        current_state: PhaseState,
        signals: PolicySignals,
        context: StateContext,
    ) -> dict[PhaseState, float]:
        """
        Evaluate policy and return confidence scores for each possible next state.

        Args:
            current_state: Current phase state
            signals: Current policy signals
            context: Current execution context

        Returns:
            Dict mapping possible next states to confidence (0.0-1.0)
        """
        # Check cache
        if self._cache.is_valid(current_state, context):
            return self._cache.confidence_map

        # Need topology and phase to evaluate
        if self.topology is None or self.phase is None:
            logger.warning("PolicyGuardAdapter: No topology/phase set, returning empty")
            return {}

        # Get policy decision
        action = self.policy.evaluate(
            topology=self.topology,
            current_phase=self.phase,
            signals=signals,
            history=self._history,
        )

        # Build confidence map from decision
        confidence_map = self._build_confidence_map(current_state, action)

        # Cache the result
        self._cache.update(current_state, context, action, confidence_map)

        return confidence_map

    def _build_confidence_map(
        self,
        current_state: PhaseState,
        action: PolicyAction,
    ) -> dict[PhaseState, float]:
        """
        Build a confidence map from a policy action.

        Maps the decision to which transitions should be allowed and with
        what confidence.
        """
        confidence_map: dict[PhaseState, float] = {}

        # Get the primary target for this decision
        primary_target = DECISION_TO_STATE.get(action.decision)

        if primary_target is not None:
            confidence_map[primary_target] = action.confidence

        # Handle special cases based on current state
        if current_state == PhaseState.EVALUATE:
            # From EVALUATE, CONTINUE and RETRY both go to EXECUTE
            if action.decision in (CycleDecision.CONTINUE, CycleDecision.RETRY):
                confidence_map[PhaseState.EXECUTE] = action.confidence

            # COMPLETE goes to SYNTHESIZE
            elif action.decision == CycleDecision.COMPLETE:
                confidence_map[PhaseState.SYNTHESIZE] = action.confidence

        elif (
            current_state == PhaseState.INIT
            and action.decision in (CycleDecision.CONTINUE, CycleDecision.RETRY)
        ):
            # From INIT, always allow transition to EXECUTE
            confidence_map[PhaseState.EXECUTE] = max(
                confidence_map.get(PhaseState.EXECUTE, 0.0), 0.8
            )

        # Add fallback confidence for EXECUTE if nothing else matched
        if not confidence_map and current_state == PhaseState.EVALUATE:
            # Default to retry with low confidence
            confidence_map[PhaseState.EXECUTE] = 0.3

        return confidence_map

    def get_last_action(self) -> PolicyAction | None:
        """Get the last policy action (for logging/debugging)."""
        return self._cache.action

    def create_guard(
        self,
        target_state: PhaseState,
        confidence_threshold: float = 0.5,
    ) -> Guard:
        """
        Create a guard function that checks if policy allows transition to target.

        Args:
            target_state: The state this guard protects transition to
            confidence_threshold: Minimum confidence required (default 0.5)

        Returns:
            Guard function compatible with HSM transitions
        """

        def guard(signals: PolicySignals, context: StateContext) -> bool:
            # Get current phase state from context
            phase_state = context.get_data("phase_state", PhaseState.EVALUATE)
            if not isinstance(phase_state, PhaseState):
                phase_state = PhaseState.EVALUATE

            # Evaluate policy
            confidence_map = self.evaluate(phase_state, signals, context)

            # Check if target has sufficient confidence
            confidence = confidence_map.get(target_state, 0.0)
            return confidence >= confidence_threshold

        return guard

    def create_all_guards(
        self,
        confidence_threshold: float = 0.5,
    ) -> dict[PhaseState, Guard]:
        """
        Create guards for all possible target states.

        Returns:
            Dict mapping target states to guard functions
        """
        targets = [
            PhaseState.EXECUTE,
            PhaseState.SYNTHESIZE,
            PhaseState.SPECULATE,
            PhaseState.ESCALATE,
            PhaseState.FAILED,
        ]

        return {
            target: self.create_guard(target, confidence_threshold)
            for target in targets
        }


# =============================================================================
# HSM Policy Wrapper
# =============================================================================


class HSMPolicy(CyclePolicy):
    """
    Policy wrapper that understands HSM state structure.

    Ensures policy decisions always map to valid state transitions
    from the current state. If the base policy returns a decision
    that doesn't map to a valid transition, falls back to a safe default.

    This prevents the policy from "breaking" the HSM by requesting
    impossible transitions.
    """

    def __init__(
        self,
        base_policy: CyclePolicy,
        hsm: HierarchicalStateMachine | None = None,
    ) -> None:
        self.base_policy = base_policy
        self.hsm = hsm
        self._valid_transitions_cache: dict[PhaseState, set[PhaseState]] = {}

    def set_hsm(self, hsm: HierarchicalStateMachine) -> None:
        """Set or update the HSM reference."""
        self.hsm = hsm
        self._valid_transitions_cache.clear()

    def evaluate(
        self,
        topology: TaskTopology,
        current_phase: TopologyPhase,
        signals: PolicySignals,
        history: list[AttemptSummary],
    ) -> PolicyAction:
        """
        Evaluate policy ensuring result maps to valid transition.

        If the base policy's decision would lead to an invalid transition,
        this method adjusts it to a safe fallback.
        """
        # Get base policy decision
        action = self.base_policy.evaluate(topology, current_phase, signals, history)

        # If no HSM attached, return as-is
        if self.hsm is None:
            return action

        # Get current HSM state
        task_state, phase_state, cycle_state = self.hsm.active_states

        # If not in a phase, return as-is
        if phase_state is None:
            return action

        # Get valid targets from current state
        valid_targets = self._get_valid_targets(phase_state)

        # Map decision to expected target
        decision_target = DECISION_TO_STATE.get(action.decision)

        # Check if decision leads to valid transition
        if decision_target is None:
            # PIVOT is special - doesn't map to a state
            if action.decision == CycleDecision.PIVOT:
                logger.info("HSMPolicy: PIVOT requested, will trigger replanning")
                return action
            else:
                logger.warning(
                    f"HSMPolicy: Unknown decision {action.decision}, falling back"
                )
                return self._fallback_action(phase_state, action)

        if decision_target not in valid_targets:
            logger.info(
                f"HSMPolicy: Decision {action.decision} -> {decision_target.name} "
                f"invalid from {phase_state.name}, falling back"
            )
            return self._fallback_action(phase_state, action)

        return action

    def _get_valid_targets(self, current: PhaseState) -> set[PhaseState]:
        """Get valid transition targets from current state."""
        # Check cache
        if current in self._valid_transitions_cache:
            return self._valid_transitions_cache[current]

        # Get from HSM's phase machine
        valid = set()

        if self.hsm is not None and self.hsm.current_phase is not None:
            phase_machine = self.hsm.current_phase
            valid = {
                t.to_state
                for t in phase_machine.config.transitions
                if t.from_state == current
            }

        # If no machine, compute from standard phase transitions
        if not valid:
            valid = self._default_valid_targets(current)

        self._valid_transitions_cache[current] = valid
        return valid

    def _default_valid_targets(self, current: PhaseState) -> set[PhaseState]:
        """Get default valid targets (when HSM not available)."""
        # Based on standard phase machine structure
        defaults: dict[PhaseState, set[PhaseState]] = {
            PhaseState.INIT: {PhaseState.EXECUTE},
            PhaseState.EXECUTE: {PhaseState.EVALUATE, PhaseState.FAILED},
            PhaseState.EVALUATE: {
                PhaseState.EXECUTE,
                PhaseState.SYNTHESIZE,
                PhaseState.SPECULATE,
                PhaseState.ESCALATE,
                PhaseState.FAILED,
            },
            PhaseState.SPECULATE: {PhaseState.EVALUATE, PhaseState.FAILED},
            PhaseState.ESCALATE: {PhaseState.EXECUTE, PhaseState.FAILED},
            PhaseState.SYNTHESIZE: {PhaseState.COMPLETE, PhaseState.EXECUTE},
            PhaseState.COMPLETE: set(),
            PhaseState.FAILED: set(),
        }
        return defaults.get(current, set())

    def _fallback_action(
        self,
        current_state: PhaseState,
        original: PolicyAction,
    ) -> PolicyAction:
        """
        Generate a safe fallback action when original is invalid.

        Strategy:
        - From EVALUATE: default to CONTINUE (retry)
        - From EXECUTE: wait for cycle to complete
        - From other states: continue if possible, else abort
        """
        if current_state == PhaseState.EVALUATE:
            return PolicyAction(
                decision=CycleDecision.CONTINUE,
                reasoning=(
                    f"Fallback: original decision {original.decision.value} "
                    f"invalid from {current_state.name}"
                ),
                confidence=0.5,
            )

        elif current_state == PhaseState.INIT:
            return PolicyAction(
                decision=CycleDecision.CONTINUE,
                reasoning="Fallback: starting phase execution",
                confidence=0.8,
            )

        elif current_state in (PhaseState.SPECULATE, PhaseState.ESCALATE):
            return PolicyAction(
                decision=CycleDecision.CONTINUE,
                reasoning=f"Fallback: returning to execution from {current_state.name}",
                confidence=0.6,
            )

        else:
            # Can't continue, let the normal flow handle it
            return original

    def update(self, action: PolicyAction, outcome: AttemptSummary) -> None:
        """Forward update to base policy."""
        self.base_policy.update(action, outcome)


# =============================================================================
# Factory Functions
# =============================================================================


def create_policy_guard(
    policy: CyclePolicy,
    target_decision: CycleDecision,
    topology: TaskTopology | None = None,
    phase: TopologyPhase | None = None,
    confidence_threshold: float = 0.5,
) -> Guard:
    """
    Create a guard that fires when policy returns the target decision.

    This is a simpler alternative to PolicyGuardAdapter for cases where
    you just need a single guard.

    Args:
        policy: The policy to evaluate
        target_decision: The decision this guard should fire on
        topology: Task topology (can be set later via context)
        phase: Current phase (can be set later via context)
        confidence_threshold: Minimum confidence required

    Returns:
        Guard function
    """
    adapter = PolicyGuardAdapter(policy, topology, phase)
    target_state = DECISION_TO_STATE.get(target_decision)

    if target_state is None:
        # For decisions that don't map to states (like PIVOT)
        def special_guard(signals: PolicySignals, context: StateContext) -> bool:
            phase_state = context.get_data("phase_state", PhaseState.EVALUATE)
            if not isinstance(phase_state, PhaseState):
                phase_state = PhaseState.EVALUATE

            # Force evaluation
            adapter.evaluate(phase_state, signals, context)
            action = adapter.get_last_action()

            return (
                action is not None
                and action.decision == target_decision
                and action.confidence >= confidence_threshold
            )

        return special_guard

    return adapter.create_guard(target_state, confidence_threshold)


def create_policy_transitions(
    policy: CyclePolicy,
    from_state: PhaseState = PhaseState.EVALUATE,
    confidence_threshold: float = 0.5,
) -> list[Transition]:
    """
    Create a set of transitions from a state using policy decisions.

    This generates transitions for the common pattern where we're in
    EVALUATE and the policy decides what to do next.

    Args:
        policy: The policy to use for guard evaluation
        from_state: The state to create transitions from
        confidence_threshold: Minimum confidence for transitions

    Returns:
        List of Transition objects
    """
    adapter = PolicyGuardAdapter(policy)

    transitions = []

    # Define transition specs: (target_state, name, priority)
    specs = [
        (PhaseState.SYNTHESIZE, "policy_complete", 130),
        (PhaseState.SPECULATE, "policy_speculate", 120),
        (PhaseState.ESCALATE, "policy_escalate", 110),
        (PhaseState.FAILED, "policy_abort", 140),
        (PhaseState.EXECUTE, "policy_continue", 50),
    ]

    for target_state, name, priority in specs:
        guard = adapter.create_guard(target_state, confidence_threshold)
        transitions.append(
            Transition(
                from_state=from_state,
                to_state=target_state,
                name=name,
                guard=guard,
                priority=priority,
            )
        )

    return transitions


# =============================================================================
# Convenience Functions
# =============================================================================


def wrap_policy_for_hsm(
    policy: CyclePolicy | None = None,
    hsm: HierarchicalStateMachine | None = None,
) -> HSMPolicy:
    """
    Wrap a policy to be HSM-aware.

    Args:
        policy: Base policy (defaults to HeuristicCyclePolicy)
        hsm: HSM to attach (can be set later)

    Returns:
        HSMPolicy wrapper
    """
    base = policy or HeuristicCyclePolicy()
    return HSMPolicy(base, hsm)
