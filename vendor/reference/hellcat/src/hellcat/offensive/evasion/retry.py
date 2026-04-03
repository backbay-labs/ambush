"""
Evasion retry manager for the Hellcat kernel.

Bridges the evasion subsystem (classifier + strategy) with the StrikeCell
execution pipeline, enabling automatic retry of blocked exploitation attempts
with modified evasion strategies.

Flow:
  1. AttackProof comes back with status="blocked" or "evasion_needed"
  2. EvasionRetryManager classifies the block from defense_observations
  3. StrategyGenerator picks a bypass technique
  4. OPSEC checks (circuit breaker + stealth budget) gate the retry
  5. A new StrikeManifest is built with evasion_strategy populated
  6. StrikeCellManager creates + executes a retry cell
  7. Repeat up to max_retries or until success / hardened / OPSEC halt
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from hellcat.offensive.evasion.classifier import BlockReason, FailureClassifier
from hellcat.offensive.evasion.strategy import EvasionStrategy, StrategyGenerator
from hellcat.core.manifests.attack_proof import AttackProof
from hellcat.offensive.strikecell.cell import StrikeCellResult
from hellcat.offensive.strikecell.manifest import StrikeManifest

if TYPE_CHECKING:
    from hellcat.offensive.opsec.circuit_breaker import OpsecCircuitBreaker
    from hellcat.offensive.opsec.noise_monitor import NoiseMonitor
    from hellcat.offensive.opsec.stealth_budget import StealthBudget
    from hellcat.offensive.strikecell.manager import StrikeCellManager

logger = structlog.get_logger()


# Maps DefenseObservation.defense_type strings to BlockReason for classification.
_DEFENSE_TYPE_TO_REASON: dict[str, BlockReason] = {
    "WAF": BlockReason.WAF_BLOCKED,
    "waf": BlockReason.WAF_BLOCKED,
    "rate-limit": BlockReason.RATE_LIMITED,
    "rate_limiter": BlockReason.RATE_LIMITED,
    "input-validation": BlockReason.INPUT_VALIDATED,
    "input_validation": BlockReason.INPUT_VALIDATED,
    "CSP": BlockReason.WAF_BLOCKED,
    "csp": BlockReason.WAF_BLOCKED,
    "captcha": BlockReason.CAPTCHA_CHALLENGED,
    "ip_allowlist": BlockReason.IP_BLOCKED,
    "auth_mechanism": BlockReason.SESSION_KILLED,
}


@dataclass
class RetryOutcome:
    """Result of an evasion retry cycle."""

    succeeded: bool
    attempts: int
    final_result: StrikeCellResult | None = None
    final_strategy: EvasionStrategy | None = None
    halted_reason: str | None = None  # "opsec_pause" | "budget_exhausted" | "compromised" | "hardened" | "max_retries"
    history: list[dict[str, Any]] = field(default_factory=list)


class EvasionRetryManager:
    """
    Wires the evasion classifier/strategy pipeline to StrikeCell retry execution.

    Given a failed AttackProof, classifies the block, selects evasion strategies,
    checks OPSEC constraints, and dispatches retry cells through the
    StrikeCellManager.
    """

    def __init__(
        self,
        *,
        noise_monitor: NoiseMonitor | None = None,
        circuit_breaker: OpsecCircuitBreaker | None = None,
        stealth_budget: StealthBudget | None = None,
        max_retries: int = 2,
    ) -> None:
        self.noise_monitor = noise_monitor
        self.circuit_breaker = circuit_breaker
        self.stealth_budget = stealth_budget
        self.max_retries = max_retries

        self.classifier = FailureClassifier()
        self.strategy_gen = StrategyGenerator(max_retries=max_retries)

    def should_retry(self, proof: AttackProof) -> bool:
        """Check if a proof indicates the attempt should be retried with evasion."""
        if proof.status not in ("blocked", "evasion_needed"):
            return False

        # Must have defense observations to classify
        if not proof.defense_observations:
            logger.info(
                "evasion.retry.no_observations",
                status=proof.status,
                strike_cell_id=proof.strike_cell_id,
            )
            return False

        # OPSEC gates
        if self.circuit_breaker and self.circuit_breaker.is_compromised():
            logger.warning("evasion.retry.opsec_compromised")
            return False

        if self.circuit_breaker and not self.circuit_breaker.allows_exploitation():
            logger.warning(
                "evasion.retry.exploitation_not_allowed",
                state=self.circuit_breaker.state.value,
            )
            return False

        if self.noise_monitor and self.noise_monitor.should_pause():
            logger.warning("evasion.retry.noise_pause")
            return False

        if self.stealth_budget and not self.stealth_budget.can_afford("evasion_retry"):
            logger.warning("evasion.retry.budget_exhausted")
            return False

        return True

    def classify_block(self, proof: AttackProof) -> BlockReason:
        """
        Determine the primary block reason from an AttackProof's defense_observations.

        Uses the defense_type mapping first, then falls back to the FailureClassifier
        with observation descriptions as signal text.
        """
        # Try direct mapping from defense_observations
        for obs in proof.defense_observations:
            if not obs.bypassed:
                reason = _DEFENSE_TYPE_TO_REASON.get(obs.defense_type)
                if reason is not None:
                    return reason

        # Fall back to classifier with combined observation text
        combined_text = " ".join(
            obs.description for obs in proof.defense_observations
        )
        result = self.classifier.classify(
            response_body=combined_text,
            error_message=combined_text,
        )
        return result.reason

    def build_retry_manifest(
        self,
        original_manifest: StrikeManifest,
        proof: AttackProof,
    ) -> StrikeManifest | None:
        """
        Build a new StrikeManifest with evasion_strategy populated for retry.

        Returns None if no viable evasion strategies remain (target is hardened).
        """
        reason = self.classify_block(proof)

        strategy = self.strategy_gen.generate(
            reason,
            vuln_node_id=original_manifest.vuln_node_id,
        )

        if strategy is None:
            logger.info(
                "evasion.retry.strategies_exhausted",
                vuln_node_id=original_manifest.vuln_node_id,
                reason=reason.value,
            )
            return None

        evasion_dict: dict[str, Any] = {
            "block_reason": reason.value,
            "techniques": [t.value for t in strategy.techniques],
            "parameters": strategy.parameters,
            "description": strategy.description,
            "cooldown_seconds": strategy.cooldown_seconds,
            "defense_observations": [
                {
                    "defense_type": obs.defense_type,
                    "description": obs.description,
                    "bypassed": obs.bypassed,
                }
                for obs in proof.defense_observations
            ],
        }

        # Create a new manifest with evasion context
        retry_manifest = StrikeManifest(
            operator_name=original_manifest.operator_name,
            target_url=original_manifest.target_url,
            vuln_node_id=original_manifest.vuln_node_id,
            attack_type=original_manifest.attack_type,
            prompt_template=original_manifest.prompt_template,
            max_turns=original_manifest.max_turns,
            timeout_seconds=original_manifest.timeout_seconds,
            evasion_strategy=evasion_dict,
            cpu_limit=original_manifest.cpu_limit,
            memory_limit=original_manifest.memory_limit,
            allowed_hosts=list(original_manifest.allowed_hosts),
            prior_findings=list(original_manifest.prior_findings),
        )

        logger.info(
            "evasion.retry.manifest_built",
            vuln_node_id=original_manifest.vuln_node_id,
            reason=reason.value,
            techniques=[t.value for t in strategy.techniques],
        )

        return retry_manifest

    def retry_with_evasion(
        self,
        cell_manager: StrikeCellManager,
        manifest: StrikeManifest,
        proof: AttackProof,
        *,
        max_retries: int | None = None,
    ) -> RetryOutcome:
        """
        Execute the full evasion retry loop.

        Classifies the block, picks strategies, checks OPSEC, and dispatches
        retry cells through the StrikeCellManager up to max_retries times.

        Returns a RetryOutcome summarizing what happened.
        """
        retries = max_retries if max_retries is not None else self.max_retries
        history: list[dict[str, Any]] = []
        current_proof = proof
        current_manifest = manifest

        for attempt in range(1, retries + 1):
            # --- OPSEC gate: circuit breaker ---
            if self.circuit_breaker and self.circuit_breaker.is_compromised():
                return RetryOutcome(
                    succeeded=False,
                    attempts=attempt - 1,
                    halted_reason="compromised",
                    history=history,
                )

            if self.circuit_breaker and not self.circuit_breaker.allows_exploitation():
                return RetryOutcome(
                    succeeded=False,
                    attempts=attempt - 1,
                    halted_reason="opsec_pause",
                    history=history,
                )

            # --- OPSEC gate: noise monitor ---
            if self.noise_monitor and self.noise_monitor.should_pause():
                return RetryOutcome(
                    succeeded=False,
                    attempts=attempt - 1,
                    halted_reason="opsec_pause",
                    history=history,
                )

            # --- OPSEC gate: stealth budget ---
            if self.stealth_budget and not self.stealth_budget.can_afford("evasion_retry"):
                return RetryOutcome(
                    succeeded=False,
                    attempts=attempt - 1,
                    halted_reason="budget_exhausted",
                    history=history,
                )

            # Build retry manifest with evasion strategy
            retry_manifest = self.build_retry_manifest(current_manifest, current_proof)

            if retry_manifest is None:
                return RetryOutcome(
                    succeeded=False,
                    attempts=attempt - 1,
                    halted_reason="hardened",
                    history=history,
                )

            # Spend the OPSEC budget
            if self.stealth_budget:
                self.stealth_budget.spend("evasion_retry")

            # Record noise signal for the retry attempt
            if self.noise_monitor:
                reason = self.classify_block(current_proof)
                self.noise_monitor.record_signal(
                    signal_type=f"evasion_retry:{reason.value}",
                    severity=0.5,
                    source=current_manifest.operator_name,
                )

            # Respect cooldown from the strategy
            if (
                retry_manifest.evasion_strategy
                and retry_manifest.evasion_strategy.get("cooldown_seconds", 0) > 0
            ):
                cooldown = retry_manifest.evasion_strategy["cooldown_seconds"]
                logger.debug(
                    "evasion.retry.cooldown",
                    seconds=cooldown,
                    attempt=attempt,
                )
                time.sleep(cooldown)

            # Create and execute the retry cell
            logger.info(
                "evasion.retry.dispatching",
                attempt=attempt,
                vuln_node_id=retry_manifest.vuln_node_id,
                operator=retry_manifest.operator_name,
            )

            cell = cell_manager.create(
                operator_name=retry_manifest.operator_name,
                target_url=retry_manifest.target_url,
                manifest=retry_manifest,
            )
            result = cell_manager.execute(cell)

            # Record attempt in history
            record: dict[str, Any] = {
                "attempt": attempt,
                "cell_id": cell.id,
                "success": result.success,
                "exit_code": result.exit_code,
                "duration_ms": result.duration_ms,
                "evasion_strategy": retry_manifest.evasion_strategy,
            }
            history.append(record)

            # Clean up the cell
            cell_manager.cleanup(cell)

            if result.success:
                logger.info(
                    "evasion.retry.success",
                    attempt=attempt,
                    cell_id=cell.id,
                    vuln_node_id=retry_manifest.vuln_node_id,
                )
                return RetryOutcome(
                    succeeded=True,
                    attempts=attempt,
                    final_result=result,
                    final_strategy=self.strategy_gen.generate(
                        self.classify_block(current_proof),
                        vuln_node_id=retry_manifest.vuln_node_id,
                    ),
                    history=history,
                )

            # Failed: update current_manifest for next iteration
            logger.info(
                "evasion.retry.failed",
                attempt=attempt,
                cell_id=cell.id,
            )
            current_manifest = retry_manifest

            # If the result produced a new proof (from proof.json), use it
            # for the next classification. Otherwise keep using the current proof.
            # The actual proof parsing happens upstream; here we keep
            # current_proof unchanged as the caller can provide updated proofs
            # via a subsequent call.

        # All retries exhausted
        return RetryOutcome(
            succeeded=False,
            attempts=retries,
            final_result=result if history else None,
            halted_reason="max_retries",
            history=history,
        )
