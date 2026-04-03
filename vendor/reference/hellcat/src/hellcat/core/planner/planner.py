"""
AttackPlanner for Hellcat engagement scheduling.

Adapts the kernel's 7-step scheduling algorithm into a security-aware
attack planner that produces an AttackPlan respecting OPSEC constraints:

1. compute_ready_set()      - Get ANALYZED nodes not blocked by defenses
2. compute_critical_path()  - Find highest-value exploit chain
3. score_attacks()          - Score all ready nodes via AttackScorer
4. apply_opsec_constraints() - Filter by noise level, budget, circuit state
5. pack_into_slots()        - Respect concurrency limits
6. Return AttackPlan
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hellcat.core.planner.dispatch import DispatchResult

import structlog

from hellcat.offensive.opsec.circuit_breaker import OpsecCircuitBreaker, OpsecState
from hellcat.offensive.opsec.noise_monitor import NoiseMonitor, ResponseLevel
from hellcat.offensive.opsec.stealth_budget import ACTION_COSTS, StealthBudget
from hellcat.core.planner.chain_analyzer import ChainAnalyzer, ExploitChain
from hellcat.core.planner.scorer import AttackScorer, ScoredAttack
from hellcat.offensive.strikecell.manager import StrikeCellManager
from hellcat.offensive.target_graph.graph import TargetGraph

logger = structlog.get_logger()


# Maximum stealth cost for "low-noise" attacks during throttle mode
_LOW_NOISE_THRESHOLD = 4.0

# Default vuln_type -> action_type mapping for budget checks
_VULN_ACTION_MAP: dict[str, str] = {
    "sqli": "injection_probe",
    "xss": "xss_probe",
    "ssrf": "ssrf_probe",
    "rce": "exploit_attempt",
    "auth_bypass": "auth_test",
    "idor": "auth_test",
    "lfi": "injection_probe",
    "xxe": "injection_probe",
    "credential_spray": "credential_spray",
    "privesc": "privilege_escalation",
}


@dataclass
class AttackPlan:
    """The output of a planning cycle."""

    scheduled: list[ScoredAttack] = field(default_factory=list)
    skipped: list[ScoredAttack] = field(default_factory=list)
    critical_chain: ExploitChain | None = None
    opsec_state: str = ""
    budget_remaining: float = 0.0
    concurrency_limit: int = 1
    response_level: str = ResponseLevel.NORMAL


class AttackPlanner:
    """
    Produces an AttackPlan by scoring ANALYZED nodes and applying
    OPSEC constraints from the noise monitor, stealth budget, and
    circuit breaker.
    """

    def __init__(
        self,
        graph: TargetGraph,
        noise_monitor: NoiseMonitor | None = None,
        stealth_budget: StealthBudget | None = None,
        circuit_breaker: OpsecCircuitBreaker | None = None,
        epss_staleness_hours: float | None = None,
        nvd_staleness_hours: float | None = None,
    ) -> None:
        self.graph = graph
        self.noise_monitor = noise_monitor
        self.stealth_budget = stealth_budget
        self.circuit_breaker = circuit_breaker
        self.chain_analyzer = ChainAnalyzer()
        self.scorer = AttackScorer(
            graph,
            self.chain_analyzer,
            epss_staleness_hours=epss_staleness_hours,
            nvd_staleness_hours=nvd_staleness_hours,
        )

    def plan(self) -> AttackPlan:
        """
        Execute the full planning cycle and return an AttackPlan.

        Steps:
        1. compute_ready_set
        2. compute_critical_path
        3. score_attacks
        4. apply_opsec_constraints
        5. pack_into_slots
        6. build and return AttackPlan
        """
        # Step 1: Get ready attacks
        ready_nodes = self.compute_ready_set()

        logger.info(
            "planner.ready_set",
            count=len(ready_nodes),
        )

        if not ready_nodes:
            return self._empty_plan()

        # Step 2: Find critical chain
        critical_chain = self.compute_critical_path()

        # Step 3: Score all ready attacks
        scored = self.score_attacks(ready_nodes)

        # Step 4: Apply OPSEC constraints
        scheduled, skipped = self.apply_opsec_constraints(scored)

        # Step 5: Pack into concurrency slots
        scheduled = self.pack_into_slots(scheduled)

        # Step 6: Build the plan
        plan = AttackPlan(
            scheduled=scheduled,
            skipped=skipped,
            critical_chain=critical_chain,
            opsec_state=self._get_opsec_state(),
            budget_remaining=self._get_budget_remaining(),
            concurrency_limit=self._get_concurrency_limit(),
            response_level=self._get_response_level(),
        )

        logger.info(
            "planner.plan_produced",
            scheduled=len(plan.scheduled),
            skipped=len(plan.skipped),
            opsec_state=plan.opsec_state,
            budget_remaining=round(plan.budget_remaining, 1),
            response_level=plan.response_level,
        )

        return plan

    # ------------------------------------------------------------------
    # Step 1: Ready set
    # ------------------------------------------------------------------

    def compute_ready_set(self) -> list[dict[str, Any]]:
        """Get all ANALYZED nodes not blocked by active defenses."""
        return self.graph.get_ready_attacks()

    # ------------------------------------------------------------------
    # Step 2: Critical path
    # ------------------------------------------------------------------

    def compute_critical_path(self) -> ExploitChain | None:
        """Find the highest-value exploit chain."""
        return self.chain_analyzer.find_critical_chain(self.graph)

    # ------------------------------------------------------------------
    # Step 3: Score attacks
    # ------------------------------------------------------------------

    def score_attacks(self, ready_nodes: list[dict[str, Any]]) -> list[ScoredAttack]:
        """Score all ready nodes and return sorted by score descending."""
        scored = [self.scorer.score_node(node) for node in ready_nodes]
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored

    # ------------------------------------------------------------------
    # Step 4: OPSEC constraints
    # ------------------------------------------------------------------

    def apply_opsec_constraints(
        self,
        scored: list[ScoredAttack],
    ) -> tuple[list[ScoredAttack], list[ScoredAttack]]:
        """
        Filter and reorder attacks based on OPSEC constraints.

        Returns (scheduled, skipped) lists.
        """
        # Check circuit breaker first - if DARK or COMPROMISED, return empty
        if self.circuit_breaker is not None:
            state = self.circuit_breaker.state
            if state in (OpsecState.DARK, OpsecState.COMPROMISED):
                logger.warning(
                    "planner.opsec_blocked",
                    state=state.value,
                    attacks_skipped=len(scored),
                )
                return [], scored

        # Check noise monitor response level
        if self.noise_monitor is not None:
            level = self.noise_monitor.response_level
            if self.noise_monitor.should_pause():
                logger.warning(
                    "planner.noise_pause",
                    response_level=level,
                    attacks_skipped=len(scored),
                )
                return [], scored

            if self.noise_monitor.should_throttle():
                # Only allow low-noise attacks during throttle
                scheduled: list[ScoredAttack] = []
                skipped: list[ScoredAttack] = []

                for attack in scored:
                    action_key = _VULN_ACTION_MAP.get(attack.vuln_type, "exploit_attempt")
                    cost = ACTION_COSTS.get(action_key, 5.0)
                    if cost <= _LOW_NOISE_THRESHOLD:
                        scheduled.append(attack)
                    else:
                        skipped.append(attack)

                logger.info(
                    "planner.noise_throttle",
                    response_level=level,
                    scheduled=len(scheduled),
                    skipped=len(skipped),
                )
                return scheduled, skipped

        # Check stealth budget - skip attacks we can't afford
        if self.stealth_budget is not None:
            scheduled = []
            skipped = []

            for attack in scored:
                action_key = _VULN_ACTION_MAP.get(attack.vuln_type, "exploit_attempt")
                if self.stealth_budget.can_afford(action_key):
                    scheduled.append(attack)
                else:
                    skipped.append(attack)

            if skipped:
                logger.info(
                    "planner.budget_constrained",
                    scheduled=len(scheduled),
                    skipped=len(skipped),
                    remaining=round(self.stealth_budget.remaining, 1),
                )
            return scheduled, skipped

        # No OPSEC constraints active - schedule everything
        return scored, []

    # ------------------------------------------------------------------
    # Step 5: Pack into concurrency slots
    # ------------------------------------------------------------------

    def pack_into_slots(self, scheduled: list[ScoredAttack]) -> list[ScoredAttack]:
        """Trim the scheduled list to respect concurrency limits."""
        limit = self._get_concurrency_limit()

        if len(scheduled) <= limit:
            return scheduled

        logger.info(
            "planner.concurrency_capped",
            available=len(scheduled),
            limit=limit,
        )

        return scheduled[:limit]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _empty_plan(self) -> AttackPlan:
        """Return an empty plan when no attacks are ready."""
        return AttackPlan(
            opsec_state=self._get_opsec_state(),
            budget_remaining=self._get_budget_remaining(),
            concurrency_limit=self._get_concurrency_limit(),
            response_level=self._get_response_level(),
        )

    def _get_opsec_state(self) -> str:
        """Get the current OPSEC circuit breaker state."""
        if self.circuit_breaker is not None:
            return self.circuit_breaker.state.value
        return OpsecState.COVERT.value

    def _get_budget_remaining(self) -> float:
        """Get remaining stealth budget."""
        if self.stealth_budget is not None:
            return self.stealth_budget.remaining
        return 0.0

    def _get_concurrency_limit(self) -> int:
        """Get the concurrency limit from stealth budget."""
        if self.stealth_budget is not None:
            return self.stealth_budget.get_concurrency_limit()
        return 3  # Default moderate parallelism

    def _get_response_level(self) -> str:
        """Get the current noise monitor response level."""
        if self.noise_monitor is not None:
            return self.noise_monitor.response_level
        return ResponseLevel.NORMAL

    # ------------------------------------------------------------------
    # Dispatch convenience
    # ------------------------------------------------------------------

    def dispatch(
        self,
        cell_manager: StrikeCellManager,
        target_url: str,
    ) -> DispatchResult:
        """
        Plan and dispatch all scheduled attacks through StrikeCells.

        Convenience method that runs the full planning cycle, then
        dispatches the resulting plan through PlannerDispatcher.

        Args:
            cell_manager: StrikeCellManager for creating/executing cells.
            target_url: The target URL for the engagement.

        Returns:
            DispatchResult with per-phase outcomes and collected findings.
        """
        from hellcat.core.planner.dispatch import DispatchResult, PlannerDispatcher

        plan = self.plan()

        if not plan.scheduled:
            logger.info("planner.dispatch_empty", msg="No attacks to dispatch")
            return DispatchResult()

        dispatcher = PlannerDispatcher(
            graph=self.graph,
            cell_manager=cell_manager,
            target_url=target_url,
        )

        return dispatcher.dispatch_plan(plan)
