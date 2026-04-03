"""
Cycle Orchestrator - Executes topologies with per-cycle policy decisions.

Uses a Hierarchical State Machine (HSM) for formal control flow.

The orchestrator implements a closed-loop control system:
1. Collect signals from dynamics/memory
2. Evaluate policy to get decision
3. If CONTINUE: execute cycle with context
4. Observe outcome and update state
5. Repeat until COMPLETE, ABORT, or limits reached

HSM features:
- Formal state machine with guards and transitions
- Transition logging for dynamics analysis
- V(state) lookup for policy guidance
- Memory pattern injection on PREPARE state
- Speculation support for parallel attempts
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from cyntra.core.topology.cycle import (
    AttemptSummary,
    CycleContext,
    CycleDecision,
    CyclePolicy,
    HeuristicCyclePolicy,
    PolicyAction,
    PolicySignals,
    create_default_policy,
)
from cyntra.core.topology.hsm_dynamics import (
    HSMDynamicsLogger,
    HSMPotentialLookup,
    HSMStateHasher,
    InMemoryDynamicsDB,
    SQLiteDynamicsDB,
    create_dynamics_integration,
)
from cyntra.core.topology.hsm_engine import (
    CycleStateMachine,
    HierarchicalStateMachine,
    PhaseStateMachine,
    TaskStateMachine,
    create_default_hsm,
)
from cyntra.core.topology.hsm_policy import (
    HSMPolicy,
    PolicyGuardAdapter,
    wrap_policy_for_hsm,
)

# HSM imports
from cyntra.core.topology.hsm_schema import (
    CycleState as HSMCycleState,
)
from cyntra.core.topology.hsm_schema import (
    PhaseState,
    StateContext,
    TaskState,
    TransitionResult,
)
from cyntra.core.topology.orchestrator import (
    OrchestratorConfig,
    PhasedOrchestrator,
)
from cyntra.core.topology.schema import (
    PhaseOutput,
    TaskTopology,
    TopologyPhase,
    TopologyResult,
)

if TYPE_CHECKING:
    from cyntra.core.dispatcher.dispatcher import Dispatcher
    from cyntra.core.scheduler.routing import KernelConfig
    from cyntra.core.state.models import Issue
    from cyntra.core.topology.planner import TopologyAdjustments

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class CycleOrchestratorConfig:
    """Configuration for cycle-level orchestration."""

    # === Execution Mode ===
    use_hsm: bool = True  # Use HSM for control flow (False for legacy mode)

    # === Cycle Limits ===
    max_cycles_per_phase: int = 5
    max_cycles_total: int = 20

    # === Budget Limits ===
    max_tokens_per_cycle: int = 200_000
    max_time_per_cycle_ms: int = 600_000  # 10 min

    # === Policy Config ===
    policy: CyclePolicy | None = None

    # === HSM Config ===
    max_failures_before_escalate: int = 3
    enable_speculation: bool = True

    # === Dynamics Config ===
    collect_dynamics_signals: bool = True
    dynamics_db_path: Path | None = None
    enable_dynamics_logging: bool = True
    transition_db: Any = None  # Optional TransitionDB instance for SQLiteDynamicsDB

    # === Callbacks ===
    on_cycle_start: Callable[[CycleContext], None] | None = None
    on_cycle_complete: Callable[[AttemptSummary], None] | None = None
    on_policy_decision: Callable[[PolicyAction], None] | None = None
    on_state_transition: Callable[[TransitionResult], None] | None = None

    # === Underlying Orchestrator ===
    orchestrator_config: OrchestratorConfig | None = None

    # === Kernel Integration (optional) ===
    kernel_config: "KernelConfig | None" = None
    dispatcher: "Dispatcher | None" = None


# =============================================================================
# Result Types
# =============================================================================


@dataclass
class CycleExecutionResult:
    """Result of executing cycles for a topology."""

    topology_name: str
    success: bool

    # Cycle details
    total_cycles: int
    cycles_per_phase: dict[str, int]

    # Phase results
    phase_outputs: list[PhaseOutput]
    all_phases_completed: bool

    # Files
    files_written: list[str]

    # Metrics
    total_tokens: int
    total_time_ms: int

    # Policy trace
    policy_decisions: list[PolicyAction]
    escalations: list[dict[str, Any]]

    # Final decision
    final_decision: CycleDecision
    final_reasoning: str

    # HSM-specific (optional)
    final_state: str = ""
    transition_count: int = 0

    def to_topology_result(self) -> TopologyResult:
        """Convert to standard TopologyResult."""
        return TopologyResult(
            topology_name=self.topology_name,
            success=self.success,
            phase_outputs=self.phase_outputs,
            total_duration_ms=self.total_time_ms,
            total_tokens_used=self.total_tokens,
            all_files_written=self.files_written,
            metadata={
                "total_cycles": self.total_cycles,
                "cycles_per_phase": self.cycles_per_phase,
                "final_decision": self.final_decision.value,
                "escalations": len(self.escalations),
                "final_state": self.final_state,
                "transition_count": self.transition_count,
            },
        )


# =============================================================================
# Main Orchestrator
# =============================================================================


class CycleOrchestrator:
    """
    Orchestrates topology execution with per-cycle policy decisions.

    Uses HSM (Hierarchical State Machine) for formal state machine control.

    The main loop:
    1. Collect signals from dynamics/memory
    2. Evaluate policy to get decision
    3. If CONTINUE: execute cycle with context
    4. Observe outcome and update state
    5. Repeat until COMPLETE, ABORT, or limits reached
    """

    def __init__(self, config: CycleOrchestratorConfig | None = None) -> None:
        self.config = config or CycleOrchestratorConfig()
        self.base_policy = self.config.policy or create_default_policy()

        # Create underlying orchestrator for actual execution
        orch_config = self.config.orchestrator_config or OrchestratorConfig()
        self._orchestrator = PhasedOrchestrator(
            config=orch_config,
            kernel_config=self.config.kernel_config,
            dispatcher=self.config.dispatcher,
        )

        # === HSM Components (initialized on execute) ===
        self._hsm: HierarchicalStateMachine | None = None
        self._hsm_policy: HSMPolicy | None = None
        self._guard_adapter: PolicyGuardAdapter | None = None
        self._hsm_context: StateContext | None = None

        # === Dynamics Components ===
        self._hasher = HSMStateHasher()
        if self.config.transition_db is not None:
            self._dynamics_db = SQLiteDynamicsDB(self.config.transition_db)
        else:
            self._dynamics_db = InMemoryDynamicsDB()
        self._dynamics_logger = HSMDynamicsLogger(
            self._hasher,
            self._dynamics_db if self.config.enable_dynamics_logging else None,
        )
        self._potential_lookup = HSMPotentialLookup(self._hasher, self._dynamics_db)

        self._aborted = False

        # === Shared State ===
        self._history: list[AttemptSummary] = []
        self._issue: Issue | None = None

    def get_hsm_context_snapshot(self) -> dict[str, Any] | None:
        """Return a safe snapshot of current HSM context for external observers."""
        if not self._hsm_context:
            return None
        snapshot = dict(self._hsm_context.snapshot())
        snapshot["task_id"] = self._hsm_context.task_id
        snapshot["issue_id"] = self._hsm_context.get_data("issue_id")
        snapshot["cycles_per_phase"] = self._hsm_context.get_data("cycles_per_phase", {})
        snapshot["budget_remaining_tokens"] = self._hsm_context.budget_remaining_tokens
        snapshot["budget_remaining_time_ms"] = self._hsm_context.budget_remaining_time_ms
        return snapshot

    def get_state_path(self) -> str | None:
        """Return the current HSM state path (if initialized)."""
        if not self._hsm:
            return None
        return self._hsm.state_path

    # =========================================================================
    # Public API
    # =========================================================================

    async def execute(
        self,
        topology: TaskTopology,
        *,
        initial_context: dict[str, Any] | None = None,
        adjustments: "TopologyAdjustments | None" = None,
        issue: "Issue | None" = None,
    ) -> CycleExecutionResult:
        """
        Execute a topology with cycle-level orchestration.

        Args:
            topology: The topology to execute
            initial_context: Initial context to inject
            adjustments: Optional adjustments from planner

        Returns:
            CycleExecutionResult with full execution trace
        """
        self._issue = issue
        try:
            return await self._execute_hsm(topology, initial_context)
        finally:
            self._issue = None

    def abort(self) -> None:
        """Abort the current execution."""
        self._aborted = True
        if self._hsm_context:
            self._hsm_context.set_data("abort_requested", True)
        self._orchestrator.abort()

    # =========================================================================
    # HSM Mode Execution
    # =========================================================================

    async def _execute_hsm(
        self,
        topology: TaskTopology,
        initial_context: dict[str, Any] | None = None,
    ) -> CycleExecutionResult:
        """Execute using Hierarchical State Machine control flow."""
        logger.info(f"Starting HSM orchestration for: {topology.name}")

        # Initialize HSM components
        self._init_hsm(topology)
        assert self._hsm is not None
        assert self._hsm_context is not None

        # Apply initial context
        if initial_context:
            for key, value in initial_context.items():
                self._hsm_context.set_data(key, value)

        # Initialize phased orchestrator context for per-cycle execution
        self._orchestrator.prepare_execution(
            topology,
            initial_context=initial_context,
            issue=self._issue,
        )

        policy_decisions: list[PolicyAction] = []
        escalations: list[dict[str, Any]] = []
        transition_count = 0

        start_time = datetime.now(timezone.utc)

        try:
            # Main HSM execution loop
            while not self._hsm.is_terminal:
                if self._aborted:
                    self._hsm_context.set_data("abort_requested", True)

                # Collect signals
                signals = self._collect_hsm_signals(topology)

                # Step the state machine
                result = self._hsm.step(signals, self._hsm_context)

                if result.success:
                    transition_count += 1

                    # Log transition to dynamics
                    if self.config.enable_dynamics_logging:
                        self._log_hsm_transition(result)

                    # Handle callback
                    if self.config.on_state_transition:
                        self.config.on_state_transition(result)

                    # Handle state-specific actions
                    await self._handle_hsm_state_entry(
                        result, topology, policy_decisions, escalations
                    )

                # Check for stuck state (no valid transitions)
                if not result.success and result.error == "No valid transition":
                    logger.warning(f"HSM stuck: {result.error}")

                    # Try to get policy guidance
                    phase_idx = min(
                        self._hsm_context.current_phase_index,
                        len(topology.phases) - 1,
                    )
                    if phase_idx >= 0:
                        action = self._hsm_policy.evaluate(
                            topology,
                            topology.phases[phase_idx],
                            signals,
                            self._history,
                        )
                        policy_decisions.append(action)

                        if action.decision == CycleDecision.ABORT:
                            logger.info("Policy recommends abort")
                            break

                    # Force progress if truly stuck
                    if self._hsm_context.cycle_count > self.config.max_cycles_total:
                        logger.error("Max cycles exceeded, forcing abort")
                        break

        except Exception as e:
            logger.error(f"HSM execution failed: {e}")
            return self._create_error_result(topology, str(e), policy_decisions)

        end_time = datetime.now(timezone.utc)
        total_time_ms = int((end_time - start_time).total_seconds() * 1000)

        # Determine final status
        task_state = self._hsm.task.current_state
        success = task_state == TaskState.COMPLETE
        final_decision = CycleDecision.COMPLETE if success else CycleDecision.ABORT

        # Persist policy learner weights at terminal state
        self._save_policy_learner()

        # Gather phase outputs
        phase_outputs = []
        for phase in topology.phases:
            output = self._hsm_context.get_data(f"phase_output_{phase.name}")
            if output:
                phase_outputs.append(output)

        return CycleExecutionResult(
            topology_name=topology.name,
            success=success,
            total_cycles=self._hsm_context.cycle_count,
            cycles_per_phase=self._hsm_context.get_data("cycles_per_phase", {}),
            phase_outputs=phase_outputs,
            all_phases_completed=len(phase_outputs) == len(topology.phases),
            files_written=self._hsm_context.files_created,
            total_tokens=self._hsm_context.tokens_used,
            total_time_ms=total_time_ms,
            policy_decisions=policy_decisions,
            escalations=escalations,
            final_decision=final_decision,
            final_reasoning=f"HSM terminated in {task_state.name}",
            final_state=self._hsm.state_path,
            transition_count=transition_count,
        )

    def _init_hsm(self, topology: TaskTopology) -> None:
        """Initialize HSM components for execution."""
        # Compute per-workcell token budget from kernel config when available,
        # otherwise fall back to per-cycle * max-cycles estimate.
        kc = self.config.kernel_config
        if kc is not None and kc.max_concurrent_workcells > 0:
            token_budget = kc.max_concurrent_tokens // kc.max_concurrent_workcells
        else:
            token_budget = self.config.max_tokens_per_cycle * self.config.max_cycles_total

        # Create state context
        self._hsm_context = StateContext(
            task_id=topology.name,
            task_description=topology.task_description,
            total_phases=len(topology.phases),
            current_phase_index=0,
            phase_progress=0.0,
            cycle_count=0,
            max_cycles=self.config.max_cycles_per_phase,
            consecutive_failures=0,
            tokens_used=0,
            time_elapsed_ms=0,
            token_budget=token_budget,
            time_budget_ms=self.config.max_time_per_cycle_ms * self.config.max_cycles_total,
        )

        # Initialize cycles per phase tracking
        cycles_per_phase = {phase.name: 0 for phase in topology.phases}
        self._hsm_context.set_data("cycles_per_phase", cycles_per_phase)

        # Populate memory hints from learned context
        self._load_memory_hints()

        # Create HSM with configured limits
        self._hsm = create_default_hsm(
            max_cycles_per_phase=self.config.max_cycles_per_phase,
            max_failures=self.config.max_failures_before_escalate,
        )

        # Create guard adapter for policy integration
        self._guard_adapter = PolicyGuardAdapter(self.base_policy)

        # Wrap policy with HSM awareness
        self._hsm_policy = wrap_policy_for_hsm(self.base_policy, self._hsm)

        # Clear history
        self._history.clear()
        self._aborted = False

        logger.debug(f"HSM initialized for {topology.name} with {len(topology.phases)} phases")

    def _load_memory_hints(self) -> None:
        """Load memory hints from learned context files into StateContext."""
        if self._hsm_context is None:
            return

        kc = self.config.kernel_config
        if kc is None:
            return

        learned_dir = kc.repo_root / ".cyntra" / "learned_context"
        if not learned_dir.is_dir():
            return

        hints: list[dict[str, Any]] = []

        # Parse failure_modes.md for anti-pattern hints
        failure_modes_path = learned_dir / "failure_modes.md"
        if failure_modes_path.exists():
            try:
                text = failure_modes_path.read_text(encoding="utf-8")
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("- **") and "**" in stripped[4:]:
                        # Extract pattern name between ** markers
                        end = stripped.index("**", 4)
                        pattern = stripped[4:end]
                        hints.append({
                            "type": "anti_pattern",
                            "pattern": pattern,
                            "source": "failure_modes",
                        })
            except Exception:
                logger.debug("Failed to parse failure_modes.md for hints")

        # Parse successful_patterns.md for positive hints
        success_path = learned_dir / "successful_patterns.md"
        if success_path.exists():
            try:
                text = success_path.read_text(encoding="utf-8")
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("- **") and "**" in stripped[4:]:
                        end = stripped.index("**", 4)
                        pattern = stripped[4:end]
                        hints.append({
                            "type": "success_pattern",
                            "pattern": pattern,
                            "source": "successful_patterns",
                        })
            except Exception:
                logger.debug("Failed to parse successful_patterns.md for hints")

        if hints:
            self._hsm_context.memory_hints = hints
            logger.debug("Loaded %d memory hints into StateContext", len(hints))

    def _collect_hsm_signals(self, topology: TaskTopology) -> PolicySignals:
        """Collect signals for HSM mode."""
        assert self._hsm_context is not None
        assert self._hsm is not None

        task_state, phase_state, cycle_state = self._hsm.active_states

        # Get V(state) from dynamics
        potential = self._potential_lookup.get_potential(
            task_state,
            phase_state,
            cycle_state,
            self._hsm_context,
        )

        # Estimate trap probability
        trap_probability = self._potential_lookup.estimate_trap_probability(
            task_state,
            phase_state,
            cycle_state,
            self._hsm_context,
        )

        total_gates = 0
        passed_gates = 0
        latest_gate_summary: dict[str, Any] | None = None
        blocking_failures: list[str] = []
        informational_failures: list[str] = []
        for attempt in self._history:
            total_gates += len(attempt.gates_passed) + len(attempt.gates_failed)
            passed_gates += len(attempt.gates_passed)
            if attempt.gate_summary:
                latest_gate_summary = attempt.gate_summary
            if attempt.blocking_failures:
                blocking_failures.extend([str(name) for name in attempt.blocking_failures if name])
            if attempt.informational_failures:
                informational_failures.extend([str(name) for name in attempt.informational_failures if name])
        gates_pass_rate = passed_gates / total_gates if total_gates > 0 else 0.0
        # Use the hashed T1-style HSM state ID (not the human-readable state path)
        # so learned policy adjustments can query potentials + transition counts.
        hashed_state_id = self._hasher.hash_state(
            task_state,
            phase_state,
            cycle_state,
            self._hsm_context,
        )

        return PolicySignals(
            current_state_id=hashed_state_id,
            state_potential=potential,
            trap_probability=trap_probability,
            phase_completion=self._hsm_context.phase_progress,
            gates_pass_rate=gates_pass_rate,
            gate_summary=latest_gate_summary,
            blocking_failures=list(dict.fromkeys(blocking_failures)),
            informational_failures=list(dict.fromkeys(informational_failures)),
            consecutive_failures=self._hsm_context.consecutive_failures,
            cycles_without_progress=self._hsm_context.cycles_without_progress,
            success_patterns=self._hsm_context.working_approaches,
            failure_patterns=self._hsm_context.failed_approaches,
        )

    async def _handle_hsm_state_entry(
        self,
        result: TransitionResult,
        topology: TaskTopology,
        policy_decisions: list[PolicyAction],
        escalations: list[dict[str, Any]],
    ) -> None:
        """Handle entry into a new state in HSM mode."""
        assert self._hsm_context is not None
        assert self._hsm is not None

        to_state = result.to_state

        # Handle entering EXECUTE state (phase level)
        if to_state == PhaseState.EXECUTE:
            phase_idx = self._hsm_context.current_phase_index
            if phase_idx < len(topology.phases):
                phase = topology.phases[phase_idx]
                self._hsm_context.current_phase_name = phase.name

                # Set context_prepared to allow cycle to start
                self._hsm_context.set_data("context_prepared", True)

        # Handle entering PREPARE state (cycle level) - refresh memory hints
        elif to_state == HSMCycleState.PREPARE:
            self._load_memory_hints()

        # Handle entering RUN state (cycle level) - execute the actual cycle
        elif to_state == HSMCycleState.RUN:
            phase_idx = self._hsm_context.current_phase_index
            if phase_idx < len(topology.phases):
                phase = topology.phases[phase_idx]

                # Get policy action for context
                signals = self._collect_hsm_signals(topology)
                action = self._hsm_policy.evaluate(
                    topology, phase, signals, self._history
                )
                policy_decisions.append(action)

                if self.config.on_policy_decision:
                    self.config.on_policy_decision(action)

                # Execute the cycle
                attempt = await self._execute_cycle_hsm(topology, phase, action)
                self._history.append(attempt)

                # Update context from attempt
                self._update_context_from_attempt(attempt, phase.name)

                # Update policy
                self._hsm_policy.update(action, attempt)

                # Mark execution complete for HSM
                self._hsm_context.set_data("execution_complete", True)

        # Handle ASSESS completion
        elif to_state == HSMCycleState.DONE:
            # Clear flags for next cycle
            self._hsm_context.set_data("context_prepared", False)
            self._hsm_context.set_data("execution_complete", False)
            self._hsm_context.set_data("cycle_complete", True)

        # Handle phase completion
        elif to_state == PhaseState.COMPLETE:
            phase_idx = self._hsm_context.current_phase_index
            if phase_idx < len(topology.phases):
                phase = topology.phases[phase_idx]
                output = self._create_phase_output(phase, self._history)
                self._hsm_context.set_data(f"phase_output_{phase.name}", output)

                # Move to next phase
                self._hsm_context.current_phase_index += 1
                self._hsm_context.phase_progress = 0.0
                self._hsm_context.consecutive_failures = 0

        # Handle phase failure
        elif to_state == PhaseState.FAILED:
            phase_idx = self._hsm_context.current_phase_index
            if phase_idx < len(topology.phases):
                phase = topology.phases[phase_idx]
                escalations.append({
                    "phase": phase.name,
                    "cycle": self._hsm_context.cycle_count,
                    "type": "phase_failed",
                    "reason": f"Phase {phase.name} failed after {self._hsm_context.consecutive_failures} failures",
                })

        # Handle escalation state
        elif to_state == PhaseState.ESCALATE:
            phase_idx = self._hsm_context.current_phase_index
            if phase_idx < len(topology.phases):
                phase = topology.phases[phase_idx]
                escalations.append({
                    "phase": phase.name,
                    "cycle": self._hsm_context.cycle_count,
                    "type": "escalation",
                    "reason": "Escalation triggered by policy",
                })
                # For now, resolve escalation immediately
                self._hsm_context.set_data("escalation_resolved", True)

        # Handle speculation state
        elif to_state == PhaseState.SPECULATE:
            if self.config.enable_speculation:
                # Run parallel speculation attempts
                phase_idx = self._hsm_context.current_phase_index
                if phase_idx < len(topology.phases):
                    phase = topology.phases[phase_idx]
                    await self._run_speculation(topology, phase)

    async def _execute_cycle_hsm(
        self,
        topology: TaskTopology,
        phase: TopologyPhase,
        action: PolicyAction,
    ) -> AttemptSummary:
        """Execute a single cycle in HSM mode."""
        assert self._hsm_context is not None

        cycle_start = datetime.now(timezone.utc)
        cycle_num = self._hsm_context.cycle_count + 1

        # Build cycle context
        context = self._build_cycle_context_hsm(topology, phase, action)

        if self.config.on_cycle_start:
            self.config.on_cycle_start(context)

        logger.info(f"Executing cycle {cycle_num}: {phase.name}")

        try:
            prompt_context = self._build_cycle_prompt_context(context)
            phase_output = await self._orchestrator.execute_phase(
                topology=topology,
                phase=phase,
                context_updates=prompt_context,
                issue=self._issue,
            )

            success = phase_output.success
            agent_outputs = phase_output.agent_outputs or []
            success_count = sum(1 for o in agent_outputs if o.get("success"))
            total_agents = max(len(agent_outputs), 1)
            partial_progress = 1.0 if success else success_count / total_agents

            cycle_end = datetime.now(timezone.utc)
            duration_ms = int((cycle_end - cycle_start).total_seconds() * 1000)

            files_modified: list[str] = []
            gates_passed: list[str] = []
            gates_failed: list[str] = []
            gate_summary: dict[str, Any] | None = None
            blocking_failures: list[str] = []
            informational_failures: list[str] = []
            for output in agent_outputs:
                metadata = output.get("metadata") or {}
                files = metadata.get("files_modified")
                if isinstance(files, list):
                    files_modified.extend([str(f) for f in files if f])
                verification = metadata.get("verification")
                if isinstance(verification, dict):
                    summary = verification.get("gate_summary")
                    if isinstance(summary, dict):
                        gate_summary = summary
                        failed_blocking = summary.get("failed_blocking")
                        if isinstance(failed_blocking, list):
                            blocking_failures.extend([str(name) for name in failed_blocking if name])
                        failed_info = summary.get("failed_informational")
                        if isinstance(failed_info, list):
                            informational_failures.extend([str(name) for name in failed_info if name])
                    gates = verification.get("gates")
                    if isinstance(gates, dict):
                        for gate_name, gate_result in gates.items():
                            if isinstance(gate_result, dict):
                                if gate_result.get("passed") is True:
                                    gates_passed.append(str(gate_name))
                                else:
                                    gates_failed.append(str(gate_name))
                    blocking = verification.get("blocking_failures")
                    if isinstance(blocking, list):
                        gates_failed.extend([str(name) for name in blocking if name])
                        blocking_failures.extend([str(name) for name in blocking if name])
            files_modified = list(dict.fromkeys(files_modified))
            if not gates_passed and not gates_failed:
                gates_passed = ["dispatch"] if success else []
                gates_failed = [] if success else ["dispatch"]
            else:
                gates_passed = list(dict.fromkeys(gates_passed))
                gates_failed = list(dict.fromkeys(gates_failed))
            blocking_failures = list(dict.fromkeys(blocking_failures))
            informational_failures = list(dict.fromkeys(informational_failures))

            if self._hsm_context and phase_output.synthesized is not None:
                self._hsm_context.intermediate_outputs[phase.name] = str(
                    phase_output.synthesized
                )

            attempt = AttemptSummary(
                cycle_number=cycle_num,
                phase_name=phase.name,
                objective=context.cycle_objective if context else f"Execute {phase.name}",
                success=success,
                partial_progress=partial_progress,
                approach_taken=action.reasoning,
                key_actions=[
                    f"Executed {len(agent_outputs)} agents",
                    "Synthesized results",
                ],
                files_modified=files_modified,
                gates_passed=gates_passed,
                gates_failed=gates_failed,
                gate_summary=gate_summary,
                blocking_failures=blocking_failures,
                informational_failures=informational_failures,
                tokens_used=phase_output.token_usage,
                duration_ms=duration_ms,
                what_worked=["Parallel agent execution"] if success else [],
                what_failed=[] if success else ["Phase execution failed"],
                error_summary=None if success else (phase_output.error or "Phase execution failed"),
            )

            if self.config.on_cycle_complete:
                self.config.on_cycle_complete(attempt)

            return attempt

        except Exception as e:
            logger.error(f"Cycle execution failed: {e}")
            cycle_end = datetime.now(timezone.utc)
            duration_ms = int((cycle_end - cycle_start).total_seconds() * 1000)

            return AttemptSummary(
                cycle_number=cycle_num,
                phase_name=phase.name,
                objective=f"Execute {phase.name}",
                success=False,
                partial_progress=0.0,
                approach_taken=action.reasoning,
                key_actions=[],
                files_modified=[],
                gates_passed=[],
                gates_failed=["execution_error"],
                error_summary=str(e),
                tokens_used=1000,
                duration_ms=duration_ms,
                what_failed=[str(e)],
            )

    def _build_cycle_context_hsm(
        self,
        topology: TaskTopology,
        phase: TopologyPhase,
        action: PolicyAction,
    ) -> CycleContext:
        """Build CycleContext from HSM state."""
        assert self._hsm_context is not None

        phase_idx = self._hsm_context.current_phase_index
        phases_completed = [
            topology.phases[i].name for i in range(phase_idx)
        ]
        phases_remaining = [
            topology.phases[i].name for i in range(phase_idx + 1, len(topology.phases))
        ]

        return CycleContext(
            task_id=topology.name,
            task_description=topology.task_description,
            current_phase=phase.name,
            current_phase_index=phase_idx,
            total_phases=len(topology.phases),
            phase_progress=self._hsm_context.phase_progress,
            phases_completed=phases_completed,
            phases_remaining=phases_remaining,
            cycle_number=self._hsm_context.cycle_count + 1,
            max_cycles=self.config.max_cycles_per_phase,
            previous_attempts=self._history[-5:],
            working_approaches=self._hsm_context.working_approaches.copy(),
            failed_approaches=self._hsm_context.failed_approaches.copy(),
            key_findings=self._hsm_context.key_findings.copy(),
            files_created=self._hsm_context.files_created.copy(),
            intermediate_outputs=self._hsm_context.intermediate_outputs.copy(),
            cycle_objective=action.cycle_context.cycle_objective if action.cycle_context else f"Execute {phase.name}",
            expected_outputs=phase.outputs or [],
            remaining_budget_tokens=self._hsm_context.budget_remaining_tokens,
            remaining_budget_time_ms=self._hsm_context.budget_remaining_time_ms,
            suggested_strategy=action.reasoning,
        )

    def _build_cycle_prompt_context(self, context: CycleContext) -> dict[str, Any]:
        """Build prompt-friendly context for the phased orchestrator."""
        return {
            "cycle_context": context.to_prompt_section(),
            "cycle_objective": context.cycle_objective,
            "cycle_number": context.cycle_number,
            "max_cycles": context.max_cycles,
            "current_phase": context.current_phase,
            "current_phase_index": context.current_phase_index,
            "phase_progress": context.phase_progress,
            "suggested_strategy": context.suggested_strategy,
        }

    def _update_context_from_attempt(
        self,
        attempt: AttemptSummary,
        phase_name: str,
    ) -> None:
        """Update HSM context from cycle attempt."""
        assert self._hsm_context is not None

        # Update metrics
        self._hsm_context.tokens_used += attempt.tokens_used
        self._hsm_context.time_elapsed_ms += attempt.duration_ms
        self._hsm_context.cycle_count += 1

        # Update cycles per phase
        cycles_per_phase = self._hsm_context.get_data("cycles_per_phase", {})
        cycles_per_phase[phase_name] = cycles_per_phase.get(phase_name, 0) + 1
        self._hsm_context.set_data("cycles_per_phase", cycles_per_phase)

        # Update progress tracking
        if attempt.success or attempt.partial_progress > 0.5:
            self._hsm_context.phase_progress = max(
                self._hsm_context.phase_progress,
                attempt.partial_progress,
            )
            self._hsm_context.consecutive_failures = 0
            self._hsm_context.last_progress_cycle = self._hsm_context.cycle_count
            self._hsm_context.cycles_without_progress = 0

            if attempt.what_worked:
                self._hsm_context.working_approaches.extend(attempt.what_worked)
        else:
            self._hsm_context.consecutive_failures += 1
            self._hsm_context.cycles_without_progress = (
                self._hsm_context.cycle_count - self._hsm_context.last_progress_cycle
            )

            if attempt.what_failed:
                self._hsm_context.failed_approaches.extend(attempt.what_failed)

        # Update files
        self._hsm_context.files_created.extend(attempt.files_modified)

    def _log_hsm_transition(self, result: TransitionResult) -> None:
        """Log a transition to dynamics."""
        if not result.success or self._hsm_context is None:
            return

        self._dynamics_logger.log_transition_result(
            result,
            self._hsm_context,
            action_taken=self._guard_adapter.get_last_action().decision.value
            if self._guard_adapter and self._guard_adapter.get_last_action()
            else "unknown",
        )

    @staticmethod
    def _compute_gate_pass_rate(output: PhaseOutput) -> float:
        """Compute gate pass rate from a PhaseOutput's agent outputs.

        Scans verification metadata in agent_outputs for gate results.
        Returns 1.0 for successful outputs with no gate data, 0.0 for failures.
        """
        if not output.success:
            return 0.0

        total_gates = 0
        passed_gates = 0
        for agent_out in output.agent_outputs:
            verification = agent_out.get("verification") if isinstance(agent_out, dict) else None
            if not isinstance(verification, dict):
                continue
            gates = verification.get("gates")
            if isinstance(gates, dict):
                for _name, gate_result in gates.items():
                    if isinstance(gate_result, dict):
                        total_gates += 1
                        if gate_result.get("passed") is True:
                            passed_gates += 1

        if total_gates > 0:
            return passed_gates / total_gates
        # Successful with no gate data — treat as fully passing
        return 1.0

    async def _run_speculation(
        self,
        topology: TaskTopology,
        phase: TopologyPhase,
    ) -> None:
        """Run parallel speculative attempts for a phase.

        Launches N parallel phase executions and picks the best result
        based on gate pass rate and success status.
        """
        assert self._hsm_context is not None

        parallelism = min(
            phase.parallelism.max,
            self.config.orchestrator_config.max_concurrent_agents
            if self.config.orchestrator_config
            else 3,
            3,  # Hard cap for speculation
        )

        logger.info(
            "Running speculation: %d candidates for phase %s",
            parallelism,
            phase.name,
        )

        # Execute phase N times in parallel
        tasks = []
        for i in range(parallelism):
            tasks.append(
                self._orchestrator.execute_phase(
                    topology=topology,
                    phase=phase,
                    context_updates={
                        "speculation_candidate": i,
                        "cycle_context": (
                            f"Speculation candidate {i + 1}/{parallelism}. "
                            "Try a different approach from other candidates."
                        ),
                    },
                    issue=self._issue,
                )
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Pick winner by success + token efficiency
        valid: list[tuple[int, PhaseOutput]] = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                logger.warning("Speculation candidate %d failed: %s", i, r)
                continue
            if r.success:
                valid.append((i, r))

        if valid:
            # Prefer candidate with highest gate pass rate, then fewest tokens
            best_idx, best_result = max(
                valid,
                key=lambda x: (
                    self._compute_gate_pass_rate(x[1]),
                    -x[1].token_usage,
                ),
            )
            if best_result.synthesized is not None:
                self._hsm_context.intermediate_outputs[phase.name] = str(
                    best_result.synthesized
                )
            # Update context metrics from winner
            self._hsm_context.tokens_used += best_result.token_usage
            self._hsm_context.time_elapsed_ms += best_result.duration_ms
            self._hsm_context.phase_progress = 1.0
            self._hsm_context.consecutive_failures = 0
            self._hsm_context.files_created.extend(best_result.files_written)
            logger.info(
                "Speculation winner: candidate %d (gate_pass_rate=%.2f, tokens=%d)",
                best_idx,
                self._compute_gate_pass_rate(best_result),
                best_result.token_usage,
            )

            # Synthesize knowledge from all candidates (winner + losers)
            self._synthesize_speculation(results, best_idx, topology, phase)
        else:
            logger.warning("All %d speculation candidates failed", parallelism)
            self._hsm_context.consecutive_failures += 1

            # Still synthesize from failed candidates for learning
            self._synthesize_speculation(results, None, topology, phase)

    def _synthesize_speculation(
        self,
        results: list[Any],
        winner_index: int | None,
        topology: TaskTopology,
        phase: TopologyPhase,
    ) -> None:
        """Extract knowledge from all speculation candidates via synthesis."""
        try:
            from cyntra.core.verifier.synthesis import SpeculationSynthesizer

            # Build candidate dicts from PhaseOutput results
            candidates: list[dict[str, Any]] = []
            for i, r in enumerate(results):
                if isinstance(r, Exception):
                    candidates.append({
                        "success": False,
                        "gate_pass_rate": 0.0,
                        "tool_sequence": [],
                        "files_modified": [],
                        "gates_passed": [],
                        "gates_failed": ["exception"],
                        "token_usage": 0,
                        "duration_ms": 0,
                    })
                    continue

                gate_pass_rate = self._compute_gate_pass_rate(r)
                gates_passed = []
                gates_failed = []
                for agent_out in (r.agent_outputs or []):
                    if not isinstance(agent_out, dict):
                        continue
                    verification = agent_out.get("verification") or agent_out.get("metadata", {}).get("verification")
                    if isinstance(verification, dict):
                        gates = verification.get("gates")
                        if isinstance(gates, dict):
                            for name, gate_result in gates.items():
                                if isinstance(gate_result, dict):
                                    if gate_result.get("passed"):
                                        gates_passed.append(name)
                                    else:
                                        gates_failed.append(name)

                candidates.append({
                    "success": r.success,
                    "gate_pass_rate": gate_pass_rate,
                    "tool_sequence": [],  # Not available from PhaseOutput
                    "files_modified": list(r.files_written),
                    "gates_passed": gates_passed,
                    "gates_failed": gates_failed,
                    "token_usage": r.token_usage,
                    "duration_ms": r.duration_ms,
                })

            # Resolve DB path
            db_path = None
            if self.config.kernel_config and self.config.kernel_config.repo_root:
                db_path = self.config.kernel_config.repo_root / ".cyntra" / "dynamics" / "cyntra.db"
            elif self.config.dynamics_db_path:
                db_path = self.config.dynamics_db_path

            issue_id = None
            if self._issue:
                issue_id = getattr(self._issue, "id", None)

            synthesizer = SpeculationSynthesizer(db_path=db_path)
            synthesis = synthesizer.synthesize(
                candidates=candidates,
                winner_index=winner_index,
                issue_id=issue_id,
                run_id=f"spec-{topology.name}-{phase.name}",
            )

            if synthesis.observations:
                logger.info(
                    "Speculation synthesis: %d observations (%d persisted) for %s/%s",
                    len(synthesis.observations),
                    synthesis.persisted_count,
                    topology.name,
                    phase.name,
                )
        except Exception:
            logger.debug("Speculation synthesis failed (non-fatal)", exc_info=True)

    # =========================================================================
    # Policy Persistence
    # =========================================================================

    def _save_policy_learner(self) -> None:
        """Persist policy learner weights at HSM terminal state."""
        from cyntra.core.topology.cycle import LearnedCyclePolicy

        # Walk the policy chain to find a LearnedCyclePolicy with a learner
        policy: CyclePolicy | None = self.base_policy
        while policy is not None:
            if isinstance(policy, LearnedCyclePolicy):
                policy.save_learner()
                logger.debug("Policy learner weights saved at terminal state")
                return
            # Check if wrapped via HSMPolicy
            policy = getattr(policy, "base_policy", None)

        # Also check the HSM policy wrapper
        if self._hsm_policy is not None:
            inner = getattr(self._hsm_policy, "base_policy", None)
            if isinstance(inner, LearnedCyclePolicy):
                inner.save_learner()
                logger.debug("Policy learner weights saved (via HSM wrapper) at terminal state")

    # =========================================================================
    # Shared Helpers
    # =========================================================================

    def _create_phase_output(
        self,
        phase: TopologyPhase,
        attempts: list[AttemptSummary],
    ) -> PhaseOutput:
        """Create phase output from attempts."""
        total_tokens = sum(a.tokens_used for a in attempts)
        total_time = sum(a.duration_ms for a in attempts)

        return PhaseOutput(
            phase_name=phase.name,
            synthesized=f"Completed after {len(attempts)} cycles",
            agent_outputs=[
                {"cycle": a.cycle_number, "success": a.success, "approach": a.approach_taken}
                for a in attempts
            ],
            files_written=[f for a in attempts for f in a.files_modified],
            token_usage=total_tokens,
            duration_ms=total_time,
            success=any(a.success for a in attempts),
        )

    def _create_error_result(
        self,
        topology: TaskTopology,
        error: str,
        policy_decisions: list[PolicyAction],
    ) -> CycleExecutionResult:
        """Create result for error case."""
        hsm_context = self._hsm_context

        return CycleExecutionResult(
            topology_name=topology.name,
            success=False,
            total_cycles=hsm_context.cycle_count if hsm_context else 0,
            cycles_per_phase=hsm_context.get_data("cycles_per_phase", {}) if hsm_context else {},
            phase_outputs=[],
            all_phases_completed=False,
            files_written=hsm_context.files_created if hsm_context else [],
            total_tokens=hsm_context.tokens_used if hsm_context else 0,
            total_time_ms=0,
            policy_decisions=policy_decisions,
            escalations=[],
            final_decision=CycleDecision.ABORT,
            final_reasoning=f"Error: {error}",
        )
