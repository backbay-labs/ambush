"""
Cycle Context and Policy - Dynamic orchestration primitives.

Bridges static topology definitions with dynamic per-cycle decisions.
Determines what context to inject into Claude based on:
- Where we are in the task topology
- What's happened in previous cycles
- Learned signals from dynamics/memory layers
- Remaining budget and constraints

The CyclePolicy learns/decides:
- What context to inject this cycle
- Whether to continue, abort, or escalate
- Whether to speculate (parallel attempts)
- What strategy patterns to apply
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from cyntra.core.topology.hsm_dynamics import DynamicsDBProtocol
    from cyntra.core.topology.policy_learner import PolicyLearner
    from cyntra.core.topology.schema import TaskTopology, TopologyPhase


class CycleDecision(Enum):
    """What to do after evaluating cycle state."""

    CONTINUE = "continue"  # Proceed with next cycle
    COMPLETE = "complete"  # Task is done
    ABORT = "abort"  # Give up on this approach
    ESCALATE = "escalate"  # Need human/stronger model intervention
    SPECULATE = "speculate"  # Run parallel attempts
    RETRY = "retry"  # Retry same cycle with adjustments
    PIVOT = "pivot"  # Switch to different topology/approach


class EscalationType(Enum):
    """Types of escalation."""

    HUMAN_REVIEW = "human_review"  # Need human decision
    STRONGER_MODEL = "stronger_model"  # Upgrade to opus
    MORE_CONTEXT = "more_context"  # Need more information
    DEPENDENCY_BLOCKED = "dependency_blocked"  # Waiting on something else


@dataclass
class AttemptSummary:
    """Summary of a previous cycle attempt."""

    cycle_number: int
    phase_name: str
    objective: str

    # Outcome
    success: bool
    partial_progress: float  # 0-1

    # What happened
    approach_taken: str
    key_actions: list[str]
    files_modified: list[str]

    # Results
    gates_passed: list[str]
    gates_failed: list[str]
    gate_summary: dict[str, Any] | None = None
    blocking_failures: list[str] = field(default_factory=list)
    informational_failures: list[str] = field(default_factory=list)
    error_summary: str | None = None

    # Metrics
    tokens_used: int = 0
    duration_ms: int = 0

    # Learnings
    what_worked: list[str] = field(default_factory=list)
    what_failed: list[str] = field(default_factory=list)


@dataclass
class CycleContext:
    """
    Context for a single workcell cycle.

    This is what Claude needs to know for THIS cycle to:
    - Understand where it is in the workflow
    - Know what's been tried and what worked/failed
    - Focus on the right objective
    - Make good decisions about approach
    """

    # === Position in Workflow ===
    task_id: str
    task_description: str

    # Phase tracking
    current_phase: str
    current_phase_index: int
    total_phases: int
    phase_progress: float  # 0-1 completion of current phase

    phases_completed: list[str] = field(default_factory=list)
    phases_remaining: list[str] = field(default_factory=list)

    # Cycle tracking
    cycle_number: int = 1
    max_cycles: int = 10

    # === History ===
    previous_attempts: list[AttemptSummary] = field(default_factory=list)

    # Accumulated knowledge
    working_approaches: list[str] = field(default_factory=list)
    failed_approaches: list[str] = field(default_factory=list)
    key_findings: list[str] = field(default_factory=list)

    # Files/artifacts from previous cycles
    files_created: list[str] = field(default_factory=list)
    intermediate_outputs: dict[str, str] = field(default_factory=dict)

    # === This Cycle's Mission ===
    cycle_objective: str = ""
    expected_outputs: list[str] = field(default_factory=list)
    success_criteria: list[str] = field(default_factory=list)

    # === Constraints ===
    remaining_budget_tokens: int = 1_000_000
    remaining_budget_time_ms: int = 1_800_000  # 30 min
    quality_gates: list[str] = field(default_factory=list)

    # === Policy Guidance ===
    suggested_strategy: str = ""
    strategy_patterns: dict[str, str] = field(default_factory=dict)
    risk_factors: list[str] = field(default_factory=list)

    # When to ask for help
    escalation_triggers: list[str] = field(default_factory=list)
    escalation_threshold_minutes: int = 5

    # === Metadata ===
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_prompt_section(self) -> str:
        """Render as markdown for prompt injection."""
        lines = [
            "## Cycle Context",
            "",
            f"**Task:** {self.task_id}",
            f"**Phase:** {self.current_phase_index + 1} of {self.total_phases} ({self.current_phase})",
            f"**Cycle:** {self.cycle_number} of {self.max_cycles}",
            f"**Progress:** {self.phase_progress:.0%} of current phase",
            "",
        ]

        # Objective
        if self.cycle_objective:
            lines.extend([
                "### This Cycle's Objective",
                "",
                self.cycle_objective,
                "",
            ])

        # Expected outputs
        if self.expected_outputs:
            lines.append("**Expected outputs:**")
            for output in self.expected_outputs:
                lines.append(f"- {output}")
            lines.append("")

        # Previous cycles summary
        if self.previous_attempts:
            lines.extend([
                "### Previous Cycles",
                "",
            ])
            for attempt in self.previous_attempts[-3:]:  # Last 3
                status = "✓" if attempt.success else "⚠" if attempt.partial_progress > 0.5 else "✗"
                lines.append(f"- Cycle {attempt.cycle_number} ({attempt.phase_name}): {status} {attempt.objective[:50]}...")
            lines.append("")

        # Working approaches
        if self.working_approaches:
            lines.extend([
                "### What's Working",
                "",
            ])
            for approach in self.working_approaches[:5]:
                lines.append(f"- {approach}")
            lines.append("")

        # Failed approaches
        if self.failed_approaches:
            lines.extend([
                "### Avoid (Failed Previously)",
                "",
            ])
            for approach in self.failed_approaches[:5]:
                lines.append(f"- {approach}")
            lines.append("")

        # Strategy guidance
        if self.suggested_strategy:
            lines.extend([
                "### Suggested Strategy",
                "",
                self.suggested_strategy,
                "",
            ])

        # Constraints
        tokens_k = self.remaining_budget_tokens // 1000
        time_min = self.remaining_budget_time_ms // 60000
        lines.extend([
            "### Constraints",
            "",
            f"- **Budget:** ~{tokens_k}k tokens, {time_min} min remaining",
        ])
        if self.escalation_triggers:
            lines.append(f"- **Escalate if:** {', '.join(self.escalation_triggers[:3])}")
        lines.append("")

        return "\n".join(lines)

    def summary(self) -> str:
        """One-line summary for logging."""
        return (
            f"Cycle {self.cycle_number}/{self.max_cycles} | "
            f"Phase {self.current_phase_index + 1}/{self.total_phases} ({self.current_phase}) | "
            f"{self.phase_progress:.0%} complete"
        )


@dataclass
class PolicySignals:
    """
    Inputs to the cycle policy from various sources.

    Aggregates signals from:
    - Dynamics layer (V, P, action, traps)
    - Memory layer (patterns, warnings)
    - Current execution state
    """

    # === From Dynamics Layer ===
    current_state_id: str | None = None
    state_potential: float | None = None  # V(s) - expected value
    action_measure: float | None = None  # Irreversibility of last transition
    trap_probability: float = 0.0  # P(getting stuck)
    entropy_production: float | None = None  # Are we exploring or exploiting?

    # === From Memory Layer ===
    similar_task_outcomes: list[dict[str, Any]] = field(default_factory=list)
    success_patterns: list[str] = field(default_factory=list)
    failure_patterns: list[str] = field(default_factory=list)
    anti_patterns: list[str] = field(default_factory=list)

    # === From Current Execution ===
    phase_completion: float = 0.0
    gates_pass_rate: float = 0.0
    gate_summary: dict[str, Any] | None = None
    blocking_failures: list[str] = field(default_factory=list)
    informational_failures: list[str] = field(default_factory=list)
    token_efficiency: float = 0.0  # quality / tokens
    time_efficiency: float = 0.0  # progress / time

    consecutive_failures: int = 0
    cycles_without_progress: int = 0

    # === External Factors ===
    priority_boost: float = 1.0  # From scheduler
    deadline_pressure: float = 0.0  # 0 = no pressure, 1 = urgent


@dataclass
class PolicyAction:
    """
    Output of the cycle policy.

    Determines what to do next and how to configure the cycle.
    """

    decision: CycleDecision

    # Context to inject
    cycle_context: CycleContext | None = None

    # Topology adjustments for this cycle
    parallelism_override: int | None = None
    model_tier_override: str | None = None
    timeout_override_ms: int | None = None

    # Speculation config (if decision == SPECULATE)
    speculation_count: int = 1
    speculation_strategies: list[str] = field(default_factory=list)

    # Escalation details (if decision == ESCALATE)
    escalation_type: EscalationType | None = None
    escalation_reason: str = ""

    # Strategy patterns to apply
    prompt_genome_id: str | None = None
    strategy_patterns: dict[str, str] = field(default_factory=dict)

    # Reasoning (for logging/debugging)
    reasoning: str = ""
    confidence: float = 0.5


class CyclePolicy(ABC):
    """
    Abstract policy for cycle decisions.

    Given the current state and signals, decides:
    - What context to inject
    - Whether to continue, abort, escalate, etc.
    - What adjustments to make

    Implementations can be:
    - Heuristic (rule-based)
    - Learned (from dynamics data)
    - Hybrid (rules + learned adjustments)
    """

    @abstractmethod
    def evaluate(
        self,
        topology: "TaskTopology",
        current_phase: "TopologyPhase",
        signals: PolicySignals,
        history: list[AttemptSummary],
    ) -> PolicyAction:
        """
        Evaluate the current state and decide what to do.

        Args:
            topology: The task topology being executed
            current_phase: Current phase in the topology
            signals: Aggregated signals from dynamics/memory
            history: Previous cycle attempts

        Returns:
            PolicyAction with decision and configuration
        """
        ...

    @abstractmethod
    def update(
        self,
        action: PolicyAction,
        outcome: AttemptSummary,
    ) -> None:
        """
        Update the policy based on observed outcome.

        For learning policies, this is where we update weights.
        For heuristic policies, this might just log.
        """
        ...


class HeuristicCyclePolicy(CyclePolicy):
    """
    Rule-based cycle policy.

    Uses heuristics to make decisions based on signals.
    Good starting point before learning from data.
    """

    def __init__(
        self,
        max_consecutive_failures: int = 3,
        trap_threshold: float = 0.7,
        escalation_threshold_cycles: int = 5,
        speculation_threshold_failures: int = 2,
    ) -> None:
        self.max_consecutive_failures = max_consecutive_failures
        self.trap_threshold = trap_threshold
        self.escalation_threshold_cycles = escalation_threshold_cycles
        self.speculation_threshold_failures = speculation_threshold_failures

    def evaluate(
        self,
        topology: "TaskTopology",
        current_phase: "TopologyPhase",
        signals: PolicySignals,
        history: list[AttemptSummary],
    ) -> PolicyAction:
        """Apply heuristic rules to decide next action."""

        # Check for completion
        if signals.phase_completion >= 1.0:
            phase_idx = next(
                (i for i, p in enumerate(topology.phases) if p.name == current_phase.name),
                0
            )
            if phase_idx >= len(topology.phases) - 1:
                return PolicyAction(
                    decision=CycleDecision.COMPLETE,
                    reasoning="All phases completed",
                    confidence=0.95,
                )

        # Check for trap state
        if signals.trap_probability > self.trap_threshold:
            return PolicyAction(
                decision=CycleDecision.PIVOT,
                reasoning=f"Trap probability {signals.trap_probability:.0%} exceeds threshold",
                confidence=0.7,
            )

        if signals.blocking_failures and signals.consecutive_failures < self.max_consecutive_failures:
            failures = ", ".join(signals.blocking_failures[:2])
            return PolicyAction(
                decision=CycleDecision.RETRY,
                reasoning=f"Blocking gate failures detected: {failures}",
                confidence=0.65,
            )

        # Check for too many failures
        if signals.consecutive_failures >= self.max_consecutive_failures:
            if signals.consecutive_failures >= self.speculation_threshold_failures:
                return PolicyAction(
                    decision=CycleDecision.SPECULATE,
                    speculation_count=3,
                    speculation_strategies=["conservative", "aggressive", "alternative"],
                    reasoning=f"{signals.consecutive_failures} consecutive failures, trying speculation",
                    confidence=0.6,
                )
            return PolicyAction(
                decision=CycleDecision.ESCALATE,
                escalation_type=EscalationType.STRONGER_MODEL,
                escalation_reason="Multiple consecutive failures",
                reasoning=f"{signals.consecutive_failures} failures, escalating to stronger model",
                confidence=0.7,
            )

        # Check for stagnation
        if signals.cycles_without_progress >= self.escalation_threshold_cycles:
            return PolicyAction(
                decision=CycleDecision.ESCALATE,
                escalation_type=EscalationType.HUMAN_REVIEW,
                escalation_reason="No progress over multiple cycles",
                reasoning=f"{signals.cycles_without_progress} cycles without progress",
                confidence=0.8,
            )

        # Default: continue with adjusted context
        cycle_context = self._build_cycle_context(
            topology, current_phase, signals, history
        )

        # Determine if we should adjust model tier based on difficulty
        model_override = None
        if signals.consecutive_failures >= 1 or signals.trap_probability > 0.3:
            model_override = "opus"

        return PolicyAction(
            decision=CycleDecision.CONTINUE,
            cycle_context=cycle_context,
            model_tier_override=model_override,
            strategy_patterns=self._select_strategy_patterns(signals),
            reasoning="Continuing with adjusted context",
            confidence=0.7,
        )

    def _build_cycle_context(
        self,
        topology: "TaskTopology",
        current_phase: "TopologyPhase",
        signals: PolicySignals,
        history: list[AttemptSummary],
    ) -> CycleContext:
        """Build cycle context from current state."""

        phase_idx = next(
            (i for i, p in enumerate(topology.phases) if p.name == current_phase.name),
            0
        )

        phases_completed = [p.name for p in topology.phases[:phase_idx]]
        phases_remaining = [p.name for p in topology.phases[phase_idx + 1:]]

        # Extract learnings from history
        working = []
        failed = []
        for attempt in history:
            working.extend(attempt.what_worked)
            failed.extend(attempt.what_failed)

        # Add patterns from memory
        working.extend(signals.success_patterns[:3])
        failed.extend(signals.anti_patterns[:3])

        # Build objective
        objective = self._derive_cycle_objective(
            current_phase, signals, history
        )

        return CycleContext(
            task_id=topology.name,
            task_description=topology.task_description,
            current_phase=current_phase.name,
            current_phase_index=phase_idx,
            total_phases=len(topology.phases),
            phase_progress=signals.phase_completion,
            phases_completed=phases_completed,
            phases_remaining=phases_remaining,
            cycle_number=len(history) + 1,
            previous_attempts=history[-5:],  # Last 5
            working_approaches=list(set(working))[:5],
            failed_approaches=list(set(failed))[:5],
            cycle_objective=objective,
            expected_outputs=current_phase.outputs or [],
            suggested_strategy=self._suggest_strategy(signals),
            risk_factors=self._identify_risks(signals),
            escalation_triggers=[
                f"Stuck > {5} min on single sub-task",
                "Same error repeated 3+ times",
                "Quality gate failing with no clear fix",
            ],
        )

    def _derive_cycle_objective(
        self,
        phase: "TopologyPhase",
        signals: PolicySignals,
        history: list[AttemptSummary],
    ) -> str:
        """Derive what this cycle should accomplish."""

        if not history:
            return f"Begin {phase.name} phase: execute all agent tasks and synthesize results"

        last = history[-1]
        if last.success:
            return f"Continue {phase.name} phase from {signals.phase_completion:.0%} completion"

        if last.gates_failed:
            gates = ", ".join(last.gates_failed[:2])
            return f"Fix failing gates ({gates}) and retry {phase.name}"

        if last.error_summary:
            return f"Address error from last cycle: {last.error_summary[:100]}"

        return f"Retry {phase.name} with adjusted approach"

    def _suggest_strategy(self, signals: PolicySignals) -> str:
        """Generate strategy suggestion based on signals."""

        if signals.trap_probability > 0.5:
            return "High trap probability detected. Try a fundamentally different approach rather than iterating on the current one."

        if signals.blocking_failures:
            failures = ", ".join(signals.blocking_failures[:2])
            return f"Blocking gate failures ({failures}). Focus on addressing these before expanding scope."

        if signals.consecutive_failures >= 2:
            return "Multiple failures suggest the current approach isn't working. Consider: (1) simplifying the task, (2) breaking into smaller steps, (3) consulting documentation."

        if signals.entropy_production and signals.entropy_production > 0.8:
            return "High exploration detected. Consider focusing on one promising direction rather than exploring broadly."

        if signals.success_patterns:
            patterns = ", ".join(signals.success_patterns[:2])
            return f"Similar tasks succeeded with: {patterns}"

        return ""

    def _identify_risks(self, signals: PolicySignals) -> list[str]:
        """Identify risk factors from signals."""
        risks = []

        if signals.trap_probability > 0.3:
            risks.append(f"Trap probability: {signals.trap_probability:.0%}")

        if signals.consecutive_failures >= 1:
            risks.append(f"Consecutive failures: {signals.consecutive_failures}")

        if signals.gate_summary and signals.gate_summary.get("blocking_failed"):
            risks.append(f"Blocking gate failures: {signals.gate_summary.get('blocking_failed')}")

        if signals.gate_summary and signals.gate_summary.get("informational_failed"):
            risks.append(f"Informational gate failures: {signals.gate_summary.get('informational_failed')}")

        if signals.anti_patterns:
            risks.append(f"Known anti-patterns in play: {len(signals.anti_patterns)}")

        return risks

    def _select_strategy_patterns(self, signals: PolicySignals) -> dict[str, str]:
        """Select strategy patterns based on signals."""
        patterns = {}

        # Adjust exploration vs exploitation
        if signals.consecutive_failures >= 2:
            patterns["exploration"] = "high"  # Try new things
        elif signals.phase_completion > 0.7:
            patterns["exploration"] = "low"  # Focus on finishing

        # Adjust verbosity based on failure
        if signals.consecutive_failures >= 1:
            patterns["verbosity"] = "detailed"  # More explanation

        return patterns

    def update(
        self,
        action: PolicyAction,
        outcome: AttemptSummary,
    ) -> None:
        """Log outcome for heuristic policy (no learning)."""
        # In a learning policy, we'd update weights here
        pass


class LearnedCyclePolicy(CyclePolicy):
    """
    Policy that learns from dynamics data and online weight updates.

    Uses a PolicyLearner (contextual bandit) to score decisions from
    feature vectors extracted from PolicySignals. Falls back to the
    heuristic base policy during cold start (< 20 observations).

    Dynamics DB adjustments (V(state), success rates) are applied on
    top of the learned scores as overrides for extreme situations.
    """

    def __init__(
        self,
        base_policy: CyclePolicy | None = None,
        dynamics_db_path: Path | None = None,
        dynamics_db: "DynamicsDBProtocol | None" = None,
        policy_learner: "PolicyLearner | None" = None,
    ) -> None:
        from cyntra.core.topology.policy_learner import PolicyLearner

        self.base_policy = base_policy or HeuristicCyclePolicy()
        self.dynamics_db_path = dynamics_db_path
        self.dynamics_db = dynamics_db
        self._transition_cache: dict[str, list[dict]] = {}
        self._learner = policy_learner or PolicyLearner()

        # Track (features, decision) pairs for the current cycle batch
        self._pending_records: list[Any] = []

    def evaluate(
        self,
        topology: "TaskTopology",
        current_phase: "TopologyPhase",
        signals: PolicySignals,
        history: list[AttemptSummary],
    ) -> PolicyAction:
        """Evaluate using learned weights or heuristic fallback."""
        from cyntra.core.topology.policy_learner import DecisionRecord

        # Cold start: delegate to heuristic base policy
        if self._learner.is_cold:
            base_action = self.base_policy.evaluate(
                topology, current_phase, signals, history
            )
            # Still record the decision for future learning
            features = self._learner.extract_features(
                signals,
                budget_fraction=self._budget_fraction(topology, history),
                cycle_count=len(history),
                max_cycles=10,
            )
            self._pending_records.append(
                DecisionRecord(decision=base_action.decision, features=features)
            )

            # Apply dynamics overrides even in cold start
            if signals.current_state_id:
                adjustments = self._get_learned_adjustments(signals.current_state_id)
                base_action = self._apply_adjustments(base_action, adjustments)

            return base_action

        # Warm: use learned policy
        budget_frac = self._budget_fraction(topology, history)
        features = self._learner.extract_features(
            signals,
            budget_fraction=budget_frac,
            cycle_count=len(history),
            max_cycles=10,
        )
        scores = self._learner.predict(features)
        scores = self._learner.apply_safety_constraints(
            scores, signals, budget_fraction=budget_frac,
        )
        decision = self._learner.select_decision(scores)

        # Record for later credit assignment
        self._pending_records.append(
            DecisionRecord(decision=decision, features=features)
        )

        # Build the action using the base policy's context-building logic
        # but with the learned decision
        base_action = self.base_policy.evaluate(
            topology, current_phase, signals, history
        )

        # Apply dynamics overrides for extreme states
        if signals.current_state_id:
            adjustments = self._get_learned_adjustments(signals.current_state_id)
            override = self._check_dynamics_override(adjustments)
            if override is not None:
                decision = override

        # Build final action with the learned decision
        action = PolicyAction(
            decision=decision,
            cycle_context=base_action.cycle_context,
            parallelism_override=base_action.parallelism_override,
            model_tier_override=base_action.model_tier_override,
            timeout_override_ms=base_action.timeout_override_ms,
            speculation_count=base_action.speculation_count if decision == CycleDecision.SPECULATE else 1,
            speculation_strategies=base_action.speculation_strategies if decision == CycleDecision.SPECULATE else [],
            escalation_type=base_action.escalation_type if decision == CycleDecision.ESCALATE else None,
            escalation_reason=base_action.escalation_reason if decision == CycleDecision.ESCALATE else "",
            strategy_patterns=base_action.strategy_patterns,
            reasoning=f"Learned policy (obs={self._learner.observation_count}, score={scores.get(decision, 0):.3f})",
            confidence=min(0.5 + self._learner.observation_count / 200.0, 0.95),
        )

        return action

    def _budget_fraction(
        self,
        topology: "TaskTopology",
        history: list[AttemptSummary],
    ) -> float:
        """Estimate remaining budget fraction from history."""
        if not history:
            return 1.0
        total_tokens = sum(a.tokens_used for a in history)
        # Rough estimate: 200k tokens per cycle * 10 max cycles
        budget = 2_000_000
        return max(0.0, 1.0 - total_tokens / budget)

    def _get_learned_adjustments(self, state_id: str) -> dict[str, Any]:
        """Look up learned adjustments for this state from dynamics DB."""
        if self.dynamics_db is None:
            return {}

        result: dict[str, Any] = {}

        # Query V(state) potential
        potential = self.dynamics_db.get_potential(state_id)
        if potential is not None:
            result["potential"] = potential

        # Compute success rate from transition history
        success_count = 0
        total_count = 0
        for suffix in ["COMPLETE", "DONE", "FAILED", "ABORTED", "RUN", "ASSESS", "PREPARE"]:
            candidate_to = f"{state_id.split('|')[0]}|{suffix}" if "|" in state_id else suffix
            count = self.dynamics_db.get_transition_count(state_id, candidate_to)
            total_count += count
            if suffix in ("COMPLETE", "DONE"):
                success_count += count

        if total_count > 0:
            result["success_rate"] = success_count / total_count
        else:
            result["success_rate"] = 0.5  # unknown -> neutral

        return result

    def _check_dynamics_override(
        self,
        adjustments: dict[str, Any],
    ) -> CycleDecision | None:
        """Check if dynamics data warrants overriding the learned decision."""
        if not adjustments:
            return None

        potential = adjustments.get("potential")
        success_rate = adjustments.get("success_rate")

        # Deep trap: force ESCALATE
        if potential is not None and potential < -5.0:
            return CycleDecision.ESCALATE

        # Very low success rate: force SPECULATE
        if success_rate is not None and success_rate < 0.2:
            return CycleDecision.SPECULATE

        return None

    def _apply_adjustments(
        self,
        action: PolicyAction,
        adjustments: dict[str, Any],
    ) -> PolicyAction:
        """Apply learned adjustments to the action."""
        if not adjustments:
            return action

        potential = adjustments.get("potential")
        success_rate = adjustments.get("success_rate")

        # Deep trap: override to ESCALATE
        if potential is not None and potential < -5.0:
            return PolicyAction(
                decision=CycleDecision.ESCALATE,
                escalation_type=EscalationType.STRONGER_MODEL,
                escalation_reason=f"V(state) = {potential:.1f} indicates deep trap",
                reasoning=f"Learned potential {potential:.1f} < -5.0, escalating",
                confidence=0.8,
            )

        # Low success rate + CONTINUE -> SPECULATE for better odds
        if (
            success_rate is not None
            and success_rate < 0.3
            and action.decision == CycleDecision.CONTINUE
        ):
            return PolicyAction(
                decision=CycleDecision.SPECULATE,
                cycle_context=action.cycle_context,
                speculation_count=2,
                speculation_strategies=["conservative", "alternative"],
                reasoning=f"Learned success rate {success_rate:.0%} < 30%, speculating",
                confidence=0.65,
            )

        return action

    def update(
        self,
        action: PolicyAction,
        outcome: AttemptSummary,
    ) -> None:
        """Update learned policy based on outcome."""
        from cyntra.core.topology.policy_learner import compute_reward

        self.base_policy.update(action, outcome)

        # Compute reward signal from outcome
        reward = compute_reward(
            success=outcome.success,
            partial_progress=outcome.partial_progress,
            gates_pass_rate=(
                len(outcome.gates_passed)
                / max(len(outcome.gates_passed) + len(outcome.gates_failed), 1)
            ),
            tokens_used=outcome.tokens_used,
            token_budget=2_000_000,
        )

        # Update learner with all pending decision records
        if self._pending_records:
            self._learner.update_batch(self._pending_records, reward)
            self._pending_records.clear()

    def save_learner(self) -> None:
        """Force-save the policy learner weights."""
        self._learner.save()


# === Factory Functions ===

def create_default_policy() -> CyclePolicy:
    """Create the default cycle policy."""
    return HeuristicCyclePolicy()


def create_learned_policy(
    dynamics_db_path: Path | None = None,
    dynamics_db: "DynamicsDBProtocol | None" = None,
    weights_path: Path | None = None,
) -> CyclePolicy:
    """Create a learned policy with dynamics and online learning integration."""
    from cyntra.core.topology.policy_learner import PolicyLearner, PolicyLearnerConfig

    learner_config = PolicyLearnerConfig(weights_path=weights_path)
    learner = PolicyLearner(config=learner_config)

    return LearnedCyclePolicy(
        base_policy=HeuristicCyclePolicy(),
        dynamics_db_path=dynamics_db_path,
        dynamics_db=dynamics_db,
        policy_learner=learner,
    )
