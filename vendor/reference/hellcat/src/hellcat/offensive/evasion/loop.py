"""
Evasion loop orchestrator for the Hellcat kernel.

Coordinates the classify -> strategize -> retry cycle when an operator
reports a blocked exploitation attempt. Integrates with the TargetGraph
to track status transitions and the OPSEC noise monitor to respect
stealth budgets.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from hellcat.offensive.evasion.classifier import (
    ClassificationResult,
    FailureClassifier,
)
from hellcat.offensive.evasion.strategy import EvasionStrategy, StrategyGenerator
from hellcat.offensive.target_graph.models import AttackStatus, EdgeType

if TYPE_CHECKING:
    from hellcat.offensive.opsec.noise_monitor import NoiseMonitor
    from hellcat.offensive.target_graph.graph import TargetGraph

logger = structlog.get_logger()


@dataclass
class EvasionAttempt:
    """Record of a single evasion attempt."""

    vuln_node_id: str
    attempt_number: int
    classification: ClassificationResult
    strategy: EvasionStrategy | None
    outcome: str = "pending"  # pending | success | failed | hardened | aborted
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class EvasionLoop:
    """
    Orchestrates the evasion cycle for blocked exploitation attempts.

    Flow:
        1. Operator reports BLOCKED status with response context
        2. FailureClassifier determines the block reason
        3. StrategyGenerator picks a bypass technique
        4. TargetGraph status: BLOCKED -> EVASION_QUEUED -> RETRIED
        5. Operator retries with evasion context
        6. On success: EXPLOITED (with BYPASSED_BY edge to defense)
        7. On failure: back to BLOCKED or HARDENED if strategies exhausted
    """

    def __init__(
        self,
        graph: TargetGraph | None = None,
        noise_monitor: NoiseMonitor | None = None,
        *,
        max_evasion_attempts: int = 3,
    ) -> None:
        self.graph = graph
        self.noise_monitor = noise_monitor
        self.classifier = FailureClassifier()
        self.strategy_gen = StrategyGenerator(max_retries=max_evasion_attempts)
        self.max_evasion_attempts = max_evasion_attempts

        # Track active evasion attempts
        self._active: dict[str, list[EvasionAttempt]] = {}

    def on_blocked(
        self,
        vuln_node_id: str,
        *,
        status_code: int | None = None,
        response_body: str = "",
        response_headers: dict[str, str] | None = None,
        error_message: str = "",
        response_time_ms: float | None = None,
    ) -> EvasionAttempt:
        """
        Handle a blocked exploitation attempt.

        Classifies the failure and generates an evasion strategy.
        Returns an EvasionAttempt with the strategy (or None if hardened).
        """
        attempts = self._active.get(vuln_node_id, [])
        attempt_number = len(attempts) + 1

        # Classify
        classification = self.classifier.classify(
            status_code=status_code,
            response_body=response_body,
            response_headers=response_headers,
            error_message=error_message,
            response_time_ms=response_time_ms,
        )

        # Check OPSEC budget before generating strategy
        if self.noise_monitor and self.noise_monitor.should_pause():
            logger.warning(
                "evasion.paused_by_opsec",
                vuln_node_id=vuln_node_id,
                noise_level=self.noise_monitor.current_noise_score(),
            )
            attempt = EvasionAttempt(
                vuln_node_id=vuln_node_id,
                attempt_number=attempt_number,
                classification=classification,
                strategy=None,
                outcome="aborted",
                metadata={"reason": "opsec_budget_exceeded"},
            )
            attempts.append(attempt)
            self._active[vuln_node_id] = attempts
            return attempt

        if attempt_number > self.max_evasion_attempts:
            logger.info(
                "evasion.max_attempts_reached",
                vuln_node_id=vuln_node_id,
                attempts=attempt_number - 1,
            )
            attempt = EvasionAttempt(
                vuln_node_id=vuln_node_id,
                attempt_number=attempt_number,
                classification=classification,
                strategy=None,
                outcome="hardened",
            )
            self._mark_hardened(vuln_node_id)
            attempts.append(attempt)
            self._active[vuln_node_id] = attempts
            return attempt

        # Generate strategy
        strategy = self.strategy_gen.generate(
            classification.reason,
            vuln_node_id=vuln_node_id,
            attempt_number=attempt_number,
        )

        if strategy is None:
            # No viable strategies remain
            attempt = EvasionAttempt(
                vuln_node_id=vuln_node_id,
                attempt_number=attempt_number,
                classification=classification,
                strategy=None,
                outcome="hardened",
            )
            self._mark_hardened(vuln_node_id)
            attempts.append(attempt)
            self._active[vuln_node_id] = attempts
            return attempt

        # Transition: BLOCKED -> EVASION_QUEUED
        self._update_status(vuln_node_id, AttackStatus.EVASION_QUEUED)

        # Record noise signal
        if self.noise_monitor:
            self.noise_monitor.record_signal(
                signal_type=classification.reason.value,
                severity=classification.confidence,
            )

        attempt = EvasionAttempt(
            vuln_node_id=vuln_node_id,
            attempt_number=attempt_number,
            classification=classification,
            strategy=strategy,
        )
        attempts.append(attempt)
        self._active[vuln_node_id] = attempts

        logger.info(
            "evasion.queued",
            vuln_node_id=vuln_node_id,
            reason=classification.reason.value,
            techniques=[t.value for t in strategy.techniques],
            attempt=attempt_number,
        )

        return attempt

    def on_retry_result(
        self,
        vuln_node_id: str,
        *,
        success: bool,
        defense_node_id: str | None = None,
    ) -> None:
        """
        Record the result of an evasion retry.

        Args:
            vuln_node_id: The vulnerability node that was retried.
            success: Whether the evasion bypass succeeded.
            defense_node_id: If successful, the defense node that was bypassed.
        """
        attempts = self._active.get(vuln_node_id, [])
        if not attempts:
            return

        latest = attempts[-1]

        # Transition: EVASION_QUEUED -> RETRIED
        self._update_status(vuln_node_id, AttackStatus.RETRIED)

        if success:
            latest.outcome = "success"
            latest.completed_at = time.time()

            # RETRIED -> EXPLOITED
            self._update_status(vuln_node_id, AttackStatus.EXPLOITED)

            # Add BYPASSED_BY edge if we know the defense
            if defense_node_id and self.graph:
                self.graph.add_edge(
                    source_id=vuln_node_id,
                    target_id=defense_node_id,
                    edge_type=EdgeType.BYPASSED_BY,
                )

            logger.info(
                "evasion.success",
                vuln_node_id=vuln_node_id,
                defense_bypassed=defense_node_id,
                attempt=latest.attempt_number,
            )
        else:
            latest.outcome = "failed"
            latest.completed_at = time.time()

            # RETRIED -> BLOCKED (can try again)
            self._update_status(vuln_node_id, AttackStatus.BLOCKED)

            logger.info(
                "evasion.retry_failed",
                vuln_node_id=vuln_node_id,
                attempt=latest.attempt_number,
            )

    def get_attempts(self, vuln_node_id: str) -> list[EvasionAttempt]:
        """Get all evasion attempts for a vulnerability node."""
        return list(self._active.get(vuln_node_id, []))

    def get_stats(self) -> dict[str, Any]:
        """Get evasion loop statistics."""
        total = sum(len(a) for a in self._active.values())
        outcomes: dict[str, int] = {}
        for attempts in self._active.values():
            for attempt in attempts:
                outcomes[attempt.outcome] = outcomes.get(attempt.outcome, 0) + 1

        return {
            "active_vuln_nodes": len(self._active),
            "total_attempts": total,
            "outcomes": outcomes,
        }

    def _update_status(self, node_id: str, status: AttackStatus) -> None:
        """Update a node's status in the TargetGraph if available."""
        if self.graph:
            try:
                self.graph.update_status(node_id, status)
            except Exception:
                logger.debug(
                    "evasion.status_update_failed",
                    node_id=node_id,
                    status=status.value,
                )

    def _mark_hardened(self, vuln_node_id: str) -> None:
        """Mark a vulnerability as hardened (no bypass possible)."""
        self._update_status(vuln_node_id, AttackStatus.HARDENED)
        self.strategy_gen.reset(vuln_node_id)
        logger.info("evasion.hardened", vuln_node_id=vuln_node_id)
