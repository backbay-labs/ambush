"""
PlannerDispatcher - Bridges AttackPlanner to StrikeCellManager.

Takes a prioritized AttackPlan and dispatches each scheduled attack
through the StrikeCell execution pipeline:

1. Group scheduled attacks by phase (recon -> vuln_analysis -> exploitation -> reporting)
2. For each phase, iterate scheduled operators sequentially
3. Create a StrikeManifest, call StrikeCellManager.create() + execute()
4. Validate proof through L1-L4 evidence gates via ProofValidator
5. Collect results, update TargetGraph status, archive cells
6. Feed prior findings forward to subsequent phases
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from hellcat.offensive.evasion.loop import EvasionLoop
from hellcat.offensive.opsec.circuit_breaker import OpsecState
from hellcat.offensive.opsec.noise_monitor import ResponseLevel
from hellcat.core.planner.planner import AttackPlan, AttackPlanner
from hellcat.core.planner.replanner import Replanner
from hellcat.core.planner.scorer import ScoredAttack
from hellcat.offensive.proof.evidence import EvidenceLevel, SecurityProof
from hellcat.offensive.proof.validator import ProofValidator, ValidationResult
from hellcat.core.routing.budget_router import BudgetRouter
from hellcat.core.routing.model_router import ModelRouter
from hellcat.offensive.strikecell.cell import StrikeCellResult
from hellcat.offensive.strikecell.manager import StrikeCellManager
from hellcat.offensive.strikecell.manifest import StrikeManifest
from hellcat.offensive.target_graph.graph import TargetGraph
from hellcat.offensive.target_graph.models import AttackStatus, CredentialType, EdgeType

logger = structlog.get_logger()


# Phase ordering: sequential execution across phases
PHASE_ORDER: list[str] = ["recon", "vuln_analysis", "exploitation", "reporting"]

# Map recommended_operator names (from AttackScorer) to registry operator names
# and their corresponding phase.
_OPERATOR_TO_PHASE: dict[str, str] = {
    "recon_operator": "recon",
    "injection_operator": "vuln_analysis",
    "xss_operator": "vuln_analysis",
    "auth_operator": "vuln_analysis",
    "authz_operator": "vuln_analysis",
    "ssrf_operator": "vuln_analysis",
    "rce_operator": "exploitation",
    "privesc_operator": "exploitation",
    "credential_operator": "exploitation",
    "generic_operator": "exploitation",
    "metasploit_operator": "exploitation",
    "sliver_operator": "exploitation",
    "report_operator": "reporting",
}

# Map recommended_operator names to operator registry keys
_OPERATOR_TO_REGISTRY: dict[str, str] = {
    "recon_operator": "recon",
    "injection_operator": "injection-vuln",
    "xss_operator": "xss-vuln",
    "auth_operator": "auth-vuln",
    "authz_operator": "authz-vuln",
    "ssrf_operator": "ssrf-vuln",
    "rce_operator": "injection-exploit",
    "privesc_operator": "auth-exploit",
    "credential_operator": "auth-exploit",
    "generic_operator": "injection-vuln",
    "metasploit_operator": "metasploit",
    "sliver_operator": "sliver-c2",
    "report_operator": "report",
}

# Map vuln_type to StrikeManifest attack_type
_VULN_TYPE_TO_ATTACK_TYPE: dict[str, str] = {
    "sqli": "exploitation",
    "xss": "exploitation",
    "ssrf": "exploitation",
    "rce": "exploitation",
    "auth_bypass": "exploitation",
    "idor": "exploitation",
    "lfi": "exploitation",
    "xxe": "exploitation",
    "credential_spray": "exploitation",
    "privesc": "exploitation",
}


@dataclass
class DispatchResult:
    """Outcome of dispatching an entire AttackPlan."""

    total_dispatched: int = 0
    total_succeeded: int = 0
    total_failed: int = 0
    phase_results: dict[str, list[CellOutcome]] = field(default_factory=dict)
    collected_findings: list[dict[str, Any]] = field(default_factory=list)

    # Evasion stats
    evasion_retries_attempted: int = 0
    evasion_retries_succeeded: int = 0
    evasion_techniques_used: list[str] = field(default_factory=list)

    # Replanning stats
    replan_cycles: int = 0
    credentials_harvested: int = 0
    replan_attacks_dispatched: int = 0


@dataclass
class CellOutcome:
    """Outcome of a single StrikeCell execution."""

    node_id: str
    operator_name: str
    cell_id: str
    success: bool
    exit_code: int
    duration_ms: int
    artifacts: list[str] = field(default_factory=list)
    proof_path: str | None = None
    error: str | None = None
    validated_level: str | None = None


class PlannerDispatcher:
    """
    Dispatches an AttackPlan through StrikeCells.

    Takes the prioritized plan from AttackPlanner, groups attacks by phase,
    and runs each through StrikeCellManager. Within a phase, attacks can
    execute concurrently up to ``max_concurrency`` (overridden by the
    plan's ``concurrency_limit`` or OPSEC state).

    OPSEC-aware throttling:
      - DETECTED state or THROTTLE response level: halve concurrency
      - DARK/COMPROMISED state or PAUSE/ABORT response level: serial (1)
    """

    # Phases that require an authorization_ref to dispatch
    RESTRICTED_PHASES: set[str] = {
        "exploitation", "c2", "post_exploitation",
    }

    def __init__(
        self,
        graph: TargetGraph,
        cell_manager: StrikeCellManager,
        target_url: str,
        proof_validator: ProofValidator | None = None,
        max_concurrency: int = 3,
        evasion_loop: EvasionLoop | None = None,
        max_evasion_retries: int = 3,
        model_router: ModelRouter | BudgetRouter | None = None,
        attack_planner: AttackPlanner | None = None,
        max_replan_cycles: int = 3,
        # Safety / control-plane
        authorization_ref: str | None = None,
        global_disable: bool = False,
        disabled_tools: list[str] | None = None,
        disabled_phases: list[str] | None = None,
        allowed_hosts: list[str] | None = None,
    ) -> None:
        self.graph = graph
        self.cell_manager = cell_manager
        self.target_url = target_url
        self.validator = proof_validator or ProofValidator(target_graph=graph)
        self.max_concurrency = max_concurrency
        self.evasion_loop = evasion_loop
        self.max_evasion_retries = max_evasion_retries
        self.model_router = model_router
        self.attack_planner = attack_planner
        self.max_replan_cycles = max_replan_cycles
        self._replanner = Replanner(graph) if attack_planner is not None else None

        # Safety / control-plane
        self.authorization_ref = authorization_ref
        self.global_disable = global_disable
        self.disabled_tools = disabled_tools or []
        self.disabled_phases = disabled_phases or []
        self.allowed_hosts = allowed_hosts or []

        # Thread safety: lock around graph write operations
        self._graph_lock = threading.Lock()

    def dispatch_plan(self, plan: AttackPlan) -> DispatchResult:
        """
        Execute all scheduled attacks in the plan through StrikeCells.

        Attacks are grouped by phase and executed in parallel within each
        phase (up to ``effective_concurrency``). Phases run sequentially
        so that findings from earlier phases feed into later ones.
        """
        result = DispatchResult()
        plan_timestamp = datetime.now(UTC).isoformat()

        if self.global_disable:
            logger.warning(
                "dispatch.global_disable",
                msg="global_disable is set — skipping all dispatch",
            )
            return result

        if not plan.scheduled:
            logger.info("dispatch.empty_plan", msg="No attacks scheduled")
            return result

        # Group scheduled attacks by phase
        by_phase = self._group_by_phase(plan.scheduled)

        # Compute effective concurrency from plan + OPSEC state
        effective = self._effective_concurrency(plan)

        logger.info(
            "dispatch.starting",
            total_attacks=len(plan.scheduled),
            phases={phase: len(attacks) for phase, attacks in by_phase.items()},
            effective_concurrency=effective,
        )

        # Execute phases in order
        collected_findings: list[dict[str, Any]] = []

        for phase in PHASE_ORDER:
            attacks = by_phase.get(phase, [])
            if not attacks:
                continue

            # Check disabled_phases
            if phase in self.disabled_phases:
                logger.warning(
                    "dispatch.phase_disabled",
                    phase=phase,
                    attack_count=len(attacks),
                )
                continue

            # Restricted phases require authorization_ref
            if (
                phase in self.RESTRICTED_PHASES
                and not self.authorization_ref
            ):
                logger.warning(
                    "dispatch.phase_requires_authorization",
                    phase=phase,
                    attack_count=len(attacks),
                )
                continue

            logger.info(
                "dispatch.phase_start",
                phase=phase,
                attack_count=len(attacks),
                concurrency=effective,
            )

            # Dispatch all attacks in this phase concurrently
            phase_outcomes = self._dispatch_phase_parallel(
                attacks=attacks,
                phase=phase,
                prior_findings=collected_findings,
                concurrency=effective,
            )

            all_outcomes: list[CellOutcome] = []

            for outcome, attack in zip(phase_outcomes, attacks, strict=False):
                result.total_dispatched += 1

                if outcome.success:
                    result.total_succeeded += 1
                    findings = self._extract_findings(outcome)
                    collected_findings.extend(findings)
                    self._update_graph_status(attack, outcome)
                    all_outcomes.append(outcome)
                elif self.evasion_loop is not None:
                    # BLOCKED: attempt evasion retry cycle
                    self._update_graph_status(attack, outcome)
                    evasion_outcome = self._attempt_evasion_retry(
                        attack=attack,
                        original_outcome=outcome,
                        phase=phase,
                        prior_findings=collected_findings,
                        result=result,
                    )
                    if evasion_outcome is not None and evasion_outcome.success:
                        result.total_succeeded += 1
                        findings = self._extract_findings(evasion_outcome)
                        collected_findings.extend(findings)
                        all_outcomes.append(evasion_outcome)
                    else:
                        result.total_failed += 1
                        all_outcomes.append(evasion_outcome or outcome)
                else:
                    result.total_failed += 1
                    self._update_graph_status(attack, outcome)
                    all_outcomes.append(outcome)

            result.phase_results[phase] = all_outcomes

            logger.info(
                "dispatch.phase_complete",
                phase=phase,
                succeeded=sum(1 for o in all_outcomes if o.success),
                failed=sum(1 for o in all_outcomes if not o.success),
            )

        result.collected_findings = collected_findings

        logger.info(
            "dispatch.complete",
            total_dispatched=result.total_dispatched,
            total_succeeded=result.total_succeeded,
            total_failed=result.total_failed,
            findings_collected=len(collected_findings),
            evasion_retries=result.evasion_retries_attempted,
            evasion_successes=result.evasion_retries_succeeded,
        )

        # Credential chaining: check if harvested credentials unlock new paths
        if self._replanner is not None and self.attack_planner is not None:
            self._run_replan_cycles(result, plan_timestamp)

        return result

    def _dispatch_phase_parallel(
        self,
        attacks: list[ScoredAttack],
        phase: str,
        prior_findings: list[dict[str, Any]],
        concurrency: int,
    ) -> list[CellOutcome]:
        """
        Dispatch all attacks in a phase concurrently using ThreadPoolExecutor.

        If concurrency == 1, dispatches sequentially (same as original behavior).
        """
        if concurrency <= 1 or len(attacks) <= 1:
            # Sequential fallback
            return [
                self._dispatch_single(attack=a, phase=phase, prior_findings=prior_findings)
                for a in attacks
            ]

        outcomes: list[CellOutcome | None] = [None] * len(attacks)

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            future_to_idx: dict[Future[CellOutcome], int] = {}
            for idx, attack in enumerate(attacks):
                future = pool.submit(
                    self._dispatch_single,
                    attack=attack,
                    phase=phase,
                    prior_findings=prior_findings,
                )
                future_to_idx[future] = idx

            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    outcomes[idx] = future.result()
                except Exception as exc:
                    # Should not happen since _dispatch_single catches all exceptions,
                    # but handle defensively.
                    attack = attacks[idx]
                    logger.error(
                        "dispatch.parallel_error",
                        node_id=attack.node_id,
                        error=str(exc),
                    )
                    outcomes[idx] = CellOutcome(
                        node_id=attack.node_id,
                        operator_name=attack.recommended_operator,
                        cell_id="",
                        success=False,
                        exit_code=-1,
                        duration_ms=0,
                        error=f"Parallel dispatch error: {exc}",
                    )

        # Type narrowing: all slots should be filled
        return [o for o in outcomes if o is not None]

    def _effective_concurrency(self, plan: AttackPlan) -> int:
        """
        Compute effective concurrency from plan limits and OPSEC state.

        Priority:
          1. OPSEC state overrides (DETECTED -> halve, DARK/COMPROMISED -> serial)
          2. Plan's concurrency_limit (from AttackPlanner/StealthBudget)
          3. self.max_concurrency default
        """
        base = plan.concurrency_limit if plan.concurrency_limit > 0 else self.max_concurrency

        # OPSEC state: response_level from NoiseMonitor
        if plan.response_level in (ResponseLevel.PAUSE, ResponseLevel.ABORT):
            return 1
        if plan.response_level == ResponseLevel.THROTTLE:
            return max(1, base // 2)

        # OPSEC state: opsec_state from CircuitBreaker
        if plan.opsec_state in (OpsecState.DARK, OpsecState.COMPROMISED):
            return 1
        if plan.opsec_state == OpsecState.DETECTED:
            return max(1, base // 2)

        return max(1, base)

    def _group_by_phase(
        self,
        attacks: list[ScoredAttack],
    ) -> dict[str, list[ScoredAttack]]:
        """Group scheduled attacks by their execution phase."""
        by_phase: dict[str, list[ScoredAttack]] = {}

        for attack in attacks:
            phase = _OPERATOR_TO_PHASE.get(
                attack.recommended_operator, "exploitation"
            )
            by_phase.setdefault(phase, []).append(attack)

        return by_phase

    def _dispatch_single(
        self,
        attack: ScoredAttack,
        phase: str,
        prior_findings: list[dict[str, Any]],
    ) -> CellOutcome:
        """Create a StrikeCell, execute the operator, and return the outcome."""
        registry_name = _OPERATOR_TO_REGISTRY.get(
            attack.recommended_operator, "injection-vuln"
        )

        # Determine attack_type for the manifest
        attack_type = _VULN_TYPE_TO_ATTACK_TYPE.get(attack.vuln_type, phase)

        # Resolve model via router (if configured)
        model_config_dict: dict[str, Any] | None = None
        if self.model_router is not None:
            mc = self.model_router.get_model(registry_name, phase)
            model_config_dict = {
                "model_id": mc.model_id,
                "provider": mc.provider.value,
                "max_tokens": mc.max_tokens,
                "temperature": mc.temperature,
            }

        manifest = StrikeManifest(
            operator_name=registry_name,
            target_url=self.target_url,
            vuln_node_id=attack.node_id,
            attack_type=attack_type,
            model_config=model_config_dict,
            prior_findings=prior_findings,
            authorization_ref=self.authorization_ref,
            global_disable=self.global_disable,
            disabled_tools=self.disabled_tools,
            disabled_phases=self.disabled_phases,
            allowed_hosts=self.allowed_hosts,
        )

        logger.info(
            "dispatch.cell_creating",
            node_id=attack.node_id,
            operator=registry_name,
            vuln_type=attack.vuln_type,
            score=attack.score,
            model=model_config_dict["model_id"] if model_config_dict else "default",
        )

        try:
            cell = self.cell_manager.create(
                operator_name=registry_name,
                target_url=self.target_url,
                manifest=manifest,
            )
        except Exception as exc:
            logger.error(
                "dispatch.cell_create_failed",
                node_id=attack.node_id,
                operator=registry_name,
                error=str(exc),
            )
            return CellOutcome(
                node_id=attack.node_id,
                operator_name=registry_name,
                cell_id="",
                success=False,
                exit_code=-1,
                duration_ms=0,
                error=f"Cell creation failed: {exc}",
            )

        try:
            cell_result: StrikeCellResult = self.cell_manager.execute(cell)
        except Exception as exc:
            logger.error(
                "dispatch.cell_execute_failed",
                cell_id=cell.id,
                error=str(exc),
            )
            # Cleanup on failure
            self.cell_manager.cleanup(cell, keep_logs=True)
            return CellOutcome(
                node_id=attack.node_id,
                operator_name=registry_name,
                cell_id=cell.id,
                success=False,
                exit_code=-1,
                duration_ms=0,
                error=f"Cell execution failed: {exc}",
            )

        outcome = CellOutcome(
            node_id=attack.node_id,
            operator_name=registry_name,
            cell_id=cell.id,
            success=cell_result.success,
            exit_code=cell_result.exit_code,
            duration_ms=cell_result.duration_ms,
            artifacts=cell_result.artifacts,
            proof_path=str(cell_result.proof_path) if cell_result.proof_path else None,
            error=cell_result.error,
        )

        # Validate proof through L1-L4 evidence gates
        if cell_result.proof_path and cell_result.proof_path.exists():
            validation = self._validate_proof(
                proof_path=cell_result.proof_path,
                node_id=attack.node_id,
                operator_name=registry_name,
                cell_id=cell.id,
            )
            if validation is not None:
                outcome.validated_level = validation.validated_level.value

        logger.info(
            "dispatch.cell_completed",
            cell_id=cell.id,
            node_id=attack.node_id,
            success=cell_result.success,
            duration_ms=cell_result.duration_ms,
            artifacts=len(cell_result.artifacts),
            validated_level=outcome.validated_level,
        )

        # Cleanup cell (archive logs)
        self.cell_manager.cleanup(cell, keep_logs=True)

        return outcome

    def _attempt_evasion_retry(
        self,
        attack: ScoredAttack,
        original_outcome: CellOutcome,
        phase: str,
        prior_findings: list[dict[str, Any]],
        result: DispatchResult,
    ) -> CellOutcome | None:
        """
        Run the evasion classify -> strategize -> retry cycle for a BLOCKED attack.

        Retries up to ``max_evasion_retries`` times. Updates the graph status
        through the evasion state machine (BLOCKED -> EVASION_QUEUED -> RETRIED ->
        EXPLOITED/BLOCKED) and respects OPSEC noise budget.

        Returns the final CellOutcome (successful retry or last failure), or
        None if evasion could not be attempted at all.
        """
        assert self.evasion_loop is not None

        registry_name = _OPERATOR_TO_REGISTRY.get(
            attack.recommended_operator, "injection-vuln"
        )
        attack_type = _VULN_TYPE_TO_ATTACK_TYPE.get(attack.vuln_type, phase)

        for retry_num in range(1, self.max_evasion_retries + 1):
            # Classify the block and generate a strategy
            evasion_attempt = self.evasion_loop.on_blocked(
                attack.node_id,
                error_message=original_outcome.error or "",
            )

            if evasion_attempt.strategy is None:
                # No viable strategy: hardened or OPSEC aborted
                logger.info(
                    "dispatch.evasion_no_strategy",
                    node_id=attack.node_id,
                    outcome=evasion_attempt.outcome,
                    retry=retry_num,
                )
                return original_outcome

            strategy = evasion_attempt.strategy

            # Track techniques used
            for tech in strategy.techniques:
                tech_name = tech.value if hasattr(tech, "value") else str(tech)
                if tech_name not in result.evasion_techniques_used:
                    result.evasion_techniques_used.append(tech_name)

            # Check for abort techniques (CAPTCHA, honeypot)
            from hellcat.offensive.evasion.strategy import EvasionTechnique

            if EvasionTechnique.ABORT_TARGET in strategy.techniques:
                logger.info(
                    "dispatch.evasion_abort_target",
                    node_id=attack.node_id,
                    reason=strategy.parameters.get("reason", ""),
                )
                return original_outcome

            # Respect cooldown
            if strategy.cooldown_seconds > 0:
                time.sleep(strategy.cooldown_seconds)

            evasion_context: dict[str, Any] = {
                "classification": {
                    "reason": evasion_attempt.classification.reason.value,
                    "confidence": evasion_attempt.classification.confidence,
                    "details": evasion_attempt.classification.evidence,
                },
                "techniques": [t.value for t in strategy.techniques],
                "description": strategy.description,
                "estimated_success_rate": strategy.estimated_success_rate,
                "attempt_number": retry_num,
            }

            # Resolve model for evasion retry (uses evasion_retry phase routing)
            retry_model_config: dict[str, Any] | None = None
            if self.model_router is not None:
                mc = self.model_router.get_model(registry_name, "evasion_retry")
                retry_model_config = {
                    "model_id": mc.model_id,
                    "provider": mc.provider.value,
                    "max_tokens": mc.max_tokens,
                    "temperature": mc.temperature,
                }

            # Create retry manifest with evasion context + control-plane fields
            retry_manifest = StrikeManifest(
                operator_name=registry_name,
                target_url=self.target_url,
                vuln_node_id=attack.node_id,
                attack_type=attack_type,
                model_config=retry_model_config,
                prior_findings=prior_findings,
                evasion_strategy=evasion_context,
                authorization_ref=self.authorization_ref,
                global_disable=self.global_disable,
                disabled_tools=self.disabled_tools,
                disabled_phases=self.disabled_phases,
                allowed_hosts=self.allowed_hosts,
            )

            logger.info(
                "dispatch.evasion_retry",
                node_id=attack.node_id,
                retry=retry_num,
                reason=evasion_attempt.classification.reason.value,
                techniques=[t.value for t in strategy.techniques],
            )

            result.evasion_retries_attempted += 1

            # Create and execute the retry cell
            try:
                cell = self.cell_manager.create(
                    operator_name=registry_name,
                    target_url=self.target_url,
                    manifest=retry_manifest,
                )
            except Exception as exc:
                logger.error(
                    "dispatch.evasion_cell_create_failed",
                    node_id=attack.node_id,
                    error=str(exc),
                )
                self.evasion_loop.on_retry_result(
                    attack.node_id, success=False,
                )
                continue

            try:
                cell_result: StrikeCellResult = self.cell_manager.execute(cell)
            except Exception as exc:
                logger.error(
                    "dispatch.evasion_cell_execute_failed",
                    node_id=attack.node_id,
                    error=str(exc),
                )
                self.cell_manager.cleanup(cell, keep_logs=True)
                self.evasion_loop.on_retry_result(
                    attack.node_id, success=False,
                )
                original_outcome = CellOutcome(
                    node_id=attack.node_id,
                    operator_name=registry_name,
                    cell_id=cell.id,
                    success=False,
                    exit_code=-1,
                    duration_ms=0,
                    error=f"Evasion retry {retry_num} execution failed: {exc}",
                )
                continue

            retry_outcome = CellOutcome(
                node_id=attack.node_id,
                operator_name=registry_name,
                cell_id=cell.id,
                success=cell_result.success,
                exit_code=cell_result.exit_code,
                duration_ms=cell_result.duration_ms,
                artifacts=cell_result.artifacts,
                proof_path=str(cell_result.proof_path) if cell_result.proof_path else None,
                error=cell_result.error,
            )

            # Validate proof
            if cell_result.proof_path and cell_result.proof_path.exists():
                validation = self._validate_proof(
                    proof_path=cell_result.proof_path,
                    node_id=attack.node_id,
                    operator_name=registry_name,
                    cell_id=cell.id,
                )
                if validation is not None:
                    retry_outcome.validated_level = validation.validated_level.value

            self.cell_manager.cleanup(cell, keep_logs=True)

            # Record result in evasion loop
            defense_node_id = None
            if evasion_attempt.classification.defense_type:
                defense_node_id = evasion_attempt.classification.defense_type.value
            self.evasion_loop.on_retry_result(
                attack.node_id,
                success=cell_result.success,
                defense_node_id=defense_node_id,
            )

            if cell_result.success:
                result.evasion_retries_succeeded += 1
                logger.info(
                    "dispatch.evasion_success",
                    node_id=attack.node_id,
                    retry=retry_num,
                    techniques=[t.value for t in strategy.techniques],
                )
                return retry_outcome

            # Failed: update original_outcome for next iteration
            original_outcome = retry_outcome

            logger.info(
                "dispatch.evasion_retry_failed",
                node_id=attack.node_id,
                retry=retry_num,
            )

        # All retries exhausted
        logger.info(
            "dispatch.evasion_exhausted",
            node_id=attack.node_id,
            retries=self.max_evasion_retries,
        )
        return original_outcome

    def _run_replan_cycles(
        self,
        result: DispatchResult,
        since: str,
    ) -> None:
        """
        After the initial dispatch, check if harvested credentials unlock
        new attack paths. If so, promote targets and run additional
        plan-dispatch cycles up to ``max_replan_cycles``.
        """
        assert self._replanner is not None
        assert self.attack_planner is not None

        for cycle in range(1, self.max_replan_cycles + 1):
            replan_result = self._replanner.check_new_paths(since=since)

            if not replan_result.should_replan:
                logger.debug(
                    "dispatch.replan_not_needed",
                    cycle=cycle,
                )
                break

            result.credentials_harvested += len(replan_result.new_credentials)

            # Promote newly reachable targets to ANALYZED
            promoted = self._replanner.promote_targets(replan_result)
            if promoted == 0:
                logger.debug(
                    "dispatch.replan_no_promotions",
                    cycle=cycle,
                )
                break

            logger.info(
                "dispatch.replan_cycle",
                cycle=cycle,
                new_credentials=len(replan_result.new_credentials),
                new_chains=len(replan_result.new_paths),
                promoted=promoted,
            )

            # Re-plan: produce a new AttackPlan with newly ANALYZED nodes
            cycle_timestamp = datetime.now(UTC).isoformat()
            new_plan = self.attack_planner.plan()

            if not new_plan.scheduled:
                logger.info(
                    "dispatch.replan_empty",
                    cycle=cycle,
                )
                break

            # Dispatch the new plan
            cycle_result = self.dispatch_plan(new_plan)

            # Merge cycle results into the main result
            result.replan_cycles += 1
            result.replan_attacks_dispatched += cycle_result.total_dispatched
            result.total_dispatched += cycle_result.total_dispatched
            result.total_succeeded += cycle_result.total_succeeded
            result.total_failed += cycle_result.total_failed
            result.collected_findings.extend(cycle_result.collected_findings)
            result.evasion_retries_attempted += cycle_result.evasion_retries_attempted
            result.evasion_retries_succeeded += cycle_result.evasion_retries_succeeded
            for tech in cycle_result.evasion_techniques_used:
                if tech not in result.evasion_techniques_used:
                    result.evasion_techniques_used.append(tech)

            # Update since for next cycle
            since = cycle_timestamp

            logger.info(
                "dispatch.replan_cycle_complete",
                cycle=cycle,
                dispatched=cycle_result.total_dispatched,
                succeeded=cycle_result.total_succeeded,
                failed=cycle_result.total_failed,
            )

    def _update_graph_status(
        self,
        attack: ScoredAttack,
        outcome: CellOutcome,
    ) -> None:
        """Update the TargetGraph node status based on cell outcome and proof validation.

        Thread-safe: acquires ``_graph_lock`` for all graph writes.

        Uses validated evidence level when available:
        - L3/L4 validated -> ATTEMPTED -> EXPLOITED (confirmed/demonstrated)
        - L1/L2 validated or success without validation -> ATTEMPTED -> EXPLOITED
        - Failure -> ATTEMPTED -> BLOCKED
        """
        with self._graph_lock:
            try:
                # Always transition ANALYZED -> ATTEMPTED first
                self.graph.update_status(attack.node_id, AttackStatus.ATTEMPTED)

                if outcome.success:
                    self.graph.update_status(attack.node_id, AttackStatus.EXPLOITED)

                    # Add EXPLOITED_BY edge if we have a validated L3+ proof
                    if outcome.validated_level in ("L3", "L4"):
                        self.graph.add_edge(
                            source_id=attack.node_id,
                            target_id=attack.node_id,
                            edge_type=EdgeType.ENABLES,
                            metadata={
                                "operator": outcome.operator_name,
                                "cell_id": outcome.cell_id,
                                "validated_level": outcome.validated_level,
                            },
                        )

                    logger.info(
                        "dispatch.graph_updated",
                        node_id=attack.node_id,
                        new_status=AttackStatus.EXPLOITED.value,
                        validated_level=outcome.validated_level,
                    )
                else:
                    self.graph.update_status(attack.node_id, AttackStatus.BLOCKED)
                    logger.info(
                        "dispatch.graph_updated",
                        node_id=attack.node_id,
                        new_status=AttackStatus.BLOCKED.value,
                    )
            except Exception as exc:
                logger.warning(
                    "dispatch.graph_update_failed",
                    node_id=attack.node_id,
                    error=str(exc),
                )

    def _extract_findings(self, outcome: CellOutcome) -> list[dict[str, Any]]:
        """Extract structured findings from a successful cell's proof artifact."""
        if not outcome.proof_path:
            return []

        proof_path = Path(outcome.proof_path)
        if not proof_path.exists():
            return []

        try:
            data = json.loads(proof_path.read_text())
            findings: list[dict[str, Any]] = []

            # Extract vulnerability findings
            for vuln in data.get("vulnerabilities_found", []):
                findings.append({
                    "source_operator": outcome.operator_name,
                    "source_cell": outcome.cell_id,
                    "type": "vulnerability",
                    "data": vuln,
                })

            # Extract exploitation results
            for exploit in data.get("exploitation_results", []):
                findings.append({
                    "source_operator": outcome.operator_name,
                    "source_cell": outcome.cell_id,
                    "type": "exploitation",
                    "data": exploit,
                })

            # Extract credential harvests
            for cred in data.get("credentials_harvested", []):
                findings.append({
                    "source_operator": outcome.operator_name,
                    "source_cell": outcome.cell_id,
                    "type": "credential",
                    "data": cred,
                })

            # Extract defense observations
            for defense in data.get("defense_observations", []):
                findings.append({
                    "source_operator": outcome.operator_name,
                    "source_cell": outcome.cell_id,
                    "type": "defense",
                    "data": defense,
                })

            # Ingest new discoveries (credentials, endpoints) into the graph
            self._ingest_discoveries(data, outcome)

            return findings
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "dispatch.proof_parse_failed",
                proof_path=str(proof_path),
                error=str(exc),
            )
            return []

    # ------------------------------------------------------------------
    # Proof validation
    # ------------------------------------------------------------------

    def _validate_proof(
        self,
        proof_path: Path,
        node_id: str,
        operator_name: str,
        cell_id: str,
    ) -> ValidationResult | None:
        """Parse proof.json and validate through L1-L4 evidence gates.

        Converts the AttackProof JSON into SecurityProof objects and runs
        each through the ProofValidator pipeline. Returns the best
        validation result (highest validated level), or None if no proofs
        could be constructed.
        """
        try:
            data = json.loads(proof_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "dispatch.proof_read_failed",
                proof_path=str(proof_path),
                error=str(exc),
            )
            return None

        security_proofs = _attack_proof_to_security_proofs(
            data, node_id, operator_name,
        )

        if not security_proofs:
            return None

        best: ValidationResult | None = None
        level_rank = {
            EvidenceLevel.L1_INFORMATIONAL: 0,
            EvidenceLevel.L2_LIKELY: 1,
            EvidenceLevel.L3_CONFIRMED: 2,
            EvidenceLevel.L4_EXPLOITED: 3,
        }

        for sp in security_proofs:
            try:
                result = self.validator.validate(sp)
            except Exception as exc:
                logger.warning(
                    "dispatch.proof_validation_error",
                    node_id=node_id,
                    error=str(exc),
                )
                continue

            if best is None or level_rank.get(
                result.validated_level, 0
            ) > level_rank.get(best.validated_level, 0):
                best = result

        if best is not None:
            logger.info(
                "dispatch.proof_validated",
                node_id=node_id,
                operator=operator_name,
                claimed=best.original_level.value,
                validated=best.validated_level.value,
                valid=best.valid,
                downgraded=best.downgraded,
            )

        return best

    def _ingest_discoveries(
        self,
        proof_data: dict[str, Any],
        outcome: CellOutcome,
    ) -> None:
        """Ingest new credentials and chain opportunities from proof into the graph.

        Thread-safe: acquires ``_graph_lock`` for graph writes.
        """
        # Ingest harvested credentials
        for cred in proof_data.get("credentials_harvested", []):
            username = cred.get("username", "")
            if not username:
                continue
            with self._graph_lock:
                try:
                    cred_type_str = cred.get("type", "password")
                    cred_type = CredentialType(cred_type_str) if cred_type_str in CredentialType.__members__.values() else CredentialType.PASSWORD
                    cred_node = self.graph.add_credential(
                        username=username,
                        credential_type=cred_type,
                        source=f"{outcome.operator_name} (cell {outcome.cell_id})",
                        access_level=cred.get("access_level", ""),
                        metadata={"source_cell": outcome.cell_id},
                    )
                    # Link credential to the vuln node that discovered it
                    self.graph.add_edge(
                        source_id=outcome.node_id,
                        target_id=cred_node.id,
                        edge_type=EdgeType.ENABLES,
                    )
                    logger.info(
                        "dispatch.credential_ingested",
                        username=username,
                        node_id=cred_node.id,
                        source_vuln=outcome.node_id,
                    )
                except Exception as exc:
                    logger.warning(
                        "dispatch.credential_ingest_failed",
                        username=username,
                        error=str(exc),
                    )


_PROOF_LEVEL_MAP: dict[str, EvidenceLevel] = {
    "L1": EvidenceLevel.L1_INFORMATIONAL,
    "L2": EvidenceLevel.L2_LIKELY,
    "L3": EvidenceLevel.L3_CONFIRMED,
    "L4": EvidenceLevel.L4_EXPLOITED,
}

_SEVERITY_TO_LEVEL: dict[str, EvidenceLevel] = {
    "critical": EvidenceLevel.L2_LIKELY,
    "high": EvidenceLevel.L2_LIKELY,
    "medium": EvidenceLevel.L1_INFORMATIONAL,
    "low": EvidenceLevel.L1_INFORMATIONAL,
    "info": EvidenceLevel.L1_INFORMATIONAL,
}


def _attack_proof_to_security_proofs(
    data: dict[str, Any],
    node_id: str,
    operator_name: str,
) -> list[SecurityProof]:
    """Convert AttackProof JSON into SecurityProof objects for validation.

    Constructs SecurityProof objects from exploitation results first (L3/L4),
    then from vulnerability findings (L1/L2). If neither exist but the proof
    status indicates success, constructs a minimal L1 proof from the evidence.
    """
    proofs: list[SecurityProof] = []
    confidence = data.get("confidence", 0.5)

    # Exploitation results produce the highest-level proofs
    for exploit in data.get("exploitation_results", []):
        level = _PROOF_LEVEL_MAP.get(
            exploit.get("proof_level", "L1"),
            EvidenceLevel.L1_INFORMATIONAL,
        )
        proofs.append(SecurityProof(
            vuln_node_id=node_id,
            operator_name=operator_name,
            claimed_level=level,
            description=exploit.get("impact_description", "Exploitation result"),
            source_location=data.get("evidence", {}).get("target_url", ""),
            observed_behavior=exploit.get("response_summary", "")[:500],
            witness_payload=exploit.get("payload", ""),
            response_evidence=exploit.get("response_summary", "")[:200],
            impact_description=exploit.get("impact_description", ""),
            data_accessed=json.dumps(exploit.get("data_extracted", {}))[:200] if exploit.get("data_extracted") else "",
            confidence=confidence,
        ))

    # Vulnerability findings produce L1-L2 proofs
    for vuln in data.get("vulnerabilities_found", []):
        level = _SEVERITY_TO_LEVEL.get(
            vuln.get("severity", "medium"),
            EvidenceLevel.L1_INFORMATIONAL,
        )
        proofs.append(SecurityProof(
            vuln_node_id=node_id,
            operator_name=operator_name,
            claimed_level=level,
            description=vuln.get("description", vuln.get("title", "Vulnerability finding")),
            source_location=vuln.get("endpoint", ""),
            observed_behavior=vuln.get("evidence_summary", ""),
            confidence=confidence,
        ))

    # Fallback: if proof status is success/partial but no structured findings,
    # construct a minimal L1 proof from the evidence blob
    if not proofs and data.get("status") in ("success", "partial"):
        evidence = data.get("evidence", {})
        final_text = evidence.get("final_text", "")
        if final_text:
            proofs.append(SecurityProof(
                vuln_node_id=node_id,
                operator_name=operator_name,
                claimed_level=EvidenceLevel.L1_INFORMATIONAL,
                description=final_text[:200],
                source_location=operator_name,
                confidence=max(0.3, confidence),
            ))

    return proofs
