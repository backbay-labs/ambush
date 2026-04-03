"""
Ralph-style Circuit Breaker for Cyntra Kernel.

Implements intelligent stagnation detection and automatic recovery:
- Tracks consecutive failures and no-progress cycles
- Opens circuit after threshold breaches
- Half-open state for gradual recovery
- Two-stage error filtering (avoids JSON field false positives)
- Memory-informed decisions (patterns, anti-patterns, discoveries)
- Dynamics-informed trap detection (known trap states)

Inspired by: https://github.com/frankbria/ralph-claude-code
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from cyntra.cognition.dynamics.transition_db import TransitionDB
    from cyntra.core.memory_integration import KernelMemoryBridge

logger = structlog.get_logger()


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Blocking requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior."""

    # Thresholds for opening circuit
    no_progress_threshold: int = 3  # Open after N cycles with no file changes
    same_error_threshold: int = 5  # Open after N cycles with same error
    consecutive_failure_threshold: int = 3  # Open after N consecutive failures

    # Recovery settings
    recovery_timeout_seconds: int = 300  # Time before trying half-open (5 min)
    half_open_success_threshold: int = 2  # Successes needed to close

    # Output monitoring
    output_decline_threshold: float = 0.7  # Open if output declines by >70%

    # Memory/Dynamics integration (Phase 1 - Full-scale Ralph)
    use_memory_context: bool = True  # Query memory for recent discoveries
    use_dynamics_traps: bool = True  # Query dynamics for known trap states
    trap_immediate_trip: bool = True  # Trip immediately on known trap revisit
    discovery_resets_no_progress: bool = True  # Discoveries count as progress


@dataclass
class CircuitMetrics:
    """Tracking metrics for circuit breaker decisions."""

    consecutive_failures: int = 0
    consecutive_no_progress: int = 0
    same_error_count: int = 0
    last_error_signature: str | None = None
    half_open_successes: int = 0
    last_output_tokens: int = 0
    files_changed_history: list[int] = field(default_factory=list)

    def reset(self) -> None:
        """Reset all metrics (on successful close)."""
        self.consecutive_failures = 0
        self.consecutive_no_progress = 0
        self.same_error_count = 0
        self.last_error_signature = None
        self.half_open_successes = 0
        self.last_output_tokens = 0
        self.files_changed_history.clear()


@dataclass
class CircuitEvent:
    """Record of a circuit state transition."""

    timestamp: float
    from_state: CircuitState
    to_state: CircuitState
    reason: str
    issue_id: str | None = None


class CircuitBreaker:
    """
    Ralph-style circuit breaker for kernel execution.

    Prevents runaway loops by detecting:
    1. Stagnation (no file changes across cycles)
    2. Repeated errors (same error signature)
    3. Consecutive failures (multiple failed attempts)
    4. Output decline (sudden drop in response quality)
    5. Known trap states (from dynamics analysis)
    6. Memory-informed stagnation (discoveries count as progress)

    State machine:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Circuit tripped, blocking new requests
    - HALF_OPEN: Testing if system recovered
    """

    def __init__(
        self,
        config: CircuitBreakerConfig | None = None,
        persist_path: Path | None = None,
        # Optional integrations for enhanced intelligence
        transition_db: TransitionDB | None = None,
        memory_bridge: KernelMemoryBridge | None = None,
    ) -> None:
        self.config = config or CircuitBreakerConfig()
        self.persist_path = persist_path

        # External integrations (graceful degradation if unavailable)
        self.transition_db = transition_db
        self.memory_bridge = memory_bridge

        self.state = CircuitState.CLOSED
        self.metrics = CircuitMetrics()
        self.opened_at: float | None = None
        self.history: list[CircuitEvent] = []

        # Known traps cache (loaded from dynamics)
        self._known_traps: dict[str, dict[str, Any]] = {}
        self._traps_loaded_at: float = 0.0

        # Load persisted state if available
        if persist_path:
            self._load_state()

        # Load known traps from dynamics
        self._refresh_known_traps()

    def allow_request(self, issue_id: str | None = None) -> bool:
        """
        Check if a request should be allowed through.

        Returns True if the circuit allows the request.
        """
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if recovery timeout has elapsed
            if self.opened_at and (time.time() - self.opened_at) >= self.config.recovery_timeout_seconds:
                self._transition(CircuitState.HALF_OPEN, "recovery_timeout_elapsed", issue_id)
                return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            # Allow limited requests to test recovery
            return True

        return False

    def record_success(
        self,
        issue_id: str | None = None,
        files_changed: int = 0,
        output_tokens: int = 0,
        state_id: str | None = None,  # For dynamics trap checking
        session_id: str | None = None,  # For memory context
    ) -> None:
        """
        Record a successful execution.

        Enhanced with:
        - Dynamics trap detection (state_id)
        - Memory-informed progress tracking (session_id)
        """
        logger.debug(
            "circuit_breaker.success",
            issue_id=issue_id,
            files_changed=files_changed,
            state=self.state.value,
            state_id=state_id,
        )

        # Track file change history
        self.metrics.files_changed_history.append(files_changed)
        if len(self.metrics.files_changed_history) > 10:
            self.metrics.files_changed_history.pop(0)

        # Reset failure counters
        self.metrics.consecutive_failures = 0
        self.metrics.same_error_count = 0
        self.metrics.last_error_signature = None

        # Check for no-progress (success but no changes)
        if files_changed == 0:
            # ENHANCED: Check if we're in a known trap state
            if self._is_known_trap(state_id):
                if self.config.trap_immediate_trip:
                    self._trip("known_trap_revisited", issue_id)
                    logger.warning(
                        "circuit_breaker.known_trap",
                        state_id=state_id,
                        issue_id=issue_id,
                    )
                    return

            # ENHANCED: Check memory for recent discoveries (conceptual progress)
            if self._has_recent_discoveries(session_id):
                logger.debug(
                    "circuit_breaker.discovery_progress",
                    issue_id=issue_id,
                    session_id=session_id,
                )
                # Discoveries count as progress - don't increment no_progress
                if self.config.discovery_resets_no_progress:
                    self.metrics.consecutive_no_progress = 0
                    # Continue to check other conditions
                else:
                    # Still track no_progress but don't trip immediately
                    self.metrics.consecutive_no_progress += 1
            else:
                # No file changes and no discoveries - true stagnation
                self.metrics.consecutive_no_progress += 1

            if self.metrics.consecutive_no_progress >= self.config.no_progress_threshold:
                self._trip("no_progress_stagnation", issue_id)
                return
        else:
            self.metrics.consecutive_no_progress = 0

        # Check for output decline
        if self.metrics.last_output_tokens > 0 and output_tokens > 0:
            decline = 1 - (output_tokens / self.metrics.last_output_tokens)
            if decline >= self.config.output_decline_threshold:
                self._trip(f"output_declined_{decline:.0%}", issue_id)
                return
        self.metrics.last_output_tokens = output_tokens

        # Handle state transitions on success
        if self.state == CircuitState.HALF_OPEN:
            self.metrics.half_open_successes += 1
            if self.metrics.half_open_successes >= self.config.half_open_success_threshold:
                self._transition(CircuitState.CLOSED, "recovery_confirmed", issue_id)
                self.metrics.reset()

    def record_failure(
        self,
        issue_id: str | None = None,
        error: str | None = None,
    ) -> None:
        """Record a failed execution."""
        error_signature = self._compute_error_signature(error)

        logger.debug(
            "circuit_breaker.failure",
            issue_id=issue_id,
            error_signature=error_signature,
            state=self.state.value,
        )

        self.metrics.consecutive_failures += 1

        # Track repeated errors
        if error_signature:
            if error_signature == self.metrics.last_error_signature:
                self.metrics.same_error_count += 1
            else:
                self.metrics.same_error_count = 1
                self.metrics.last_error_signature = error_signature

        # Check thresholds
        if self.metrics.consecutive_failures >= self.config.consecutive_failure_threshold:
            self._trip("consecutive_failures", issue_id)
        elif self.metrics.same_error_count >= self.config.same_error_threshold:
            self._trip(f"repeated_error:{error_signature}", issue_id)
        elif self.state == CircuitState.HALF_OPEN:
            # Any failure in half-open reopens the circuit
            self._transition(CircuitState.OPEN, "half_open_failure", issue_id)
            self.opened_at = time.time()

    def record_pty_hang(self, issue_id: str) -> None:
        """
        Record a PTY hang as a failure for circuit breaker tracking.

        PTY hangs (unresponsive interactive sessions) are treated as failures
        that count toward the consecutive failure threshold.
        """
        logger.warning(
            "circuit_breaker.pty_hang",
            issue_id=issue_id,
            state=self.state.value,
        )

        self.metrics.consecutive_failures += 1

        # Track as a specific error signature so repeated hangs are detected
        hang_signature = "pty_hang"
        if hang_signature == self.metrics.last_error_signature:
            self.metrics.same_error_count += 1
        else:
            self.metrics.same_error_count = 1
            self.metrics.last_error_signature = hang_signature

        # Check thresholds
        if self.metrics.consecutive_failures >= self.config.consecutive_failure_threshold:
            self._trip("pty_hang_consecutive_failures", issue_id)
        elif self.metrics.same_error_count >= self.config.same_error_threshold:
            self._trip("pty_hang_repeated", issue_id)
        elif self.state == CircuitState.HALF_OPEN:
            self._transition(CircuitState.OPEN, "pty_hang_half_open", issue_id)
            self.opened_at = time.time()

    def _trip(self, reason: str, issue_id: str | None = None) -> None:
        """Trip the circuit breaker (open it)."""
        if self.state != CircuitState.OPEN:
            self._transition(CircuitState.OPEN, reason, issue_id)
            self.opened_at = time.time()

    def _transition(
        self,
        new_state: CircuitState,
        reason: str,
        issue_id: str | None = None,
    ) -> None:
        """Transition to a new state."""
        event = CircuitEvent(
            timestamp=time.time(),
            from_state=self.state,
            to_state=new_state,
            reason=reason,
            issue_id=issue_id,
        )
        self.history.append(event)

        # Keep history bounded
        if len(self.history) > 50:
            self.history = self.history[-50:]

        logger.info(
            "circuit_breaker.transition",
            from_state=self.state.value,
            to_state=new_state.value,
            reason=reason,
            issue_id=issue_id,
        )

        self.state = new_state
        self._persist_state()

    def _compute_error_signature(self, error: str | None) -> str | None:
        """
        Compute a normalized signature for error matching.

        Uses two-stage filtering to avoid false positives from JSON fields.
        """
        if not error:
            return None

        # Stage 1: Filter out JSON-like patterns that aren't real errors
        # e.g., '"is_error": false' should not match as an error
        lines = error.split("\n")
        filtered_lines = []
        for line in lines:
            line_lower = line.lower().strip()
            # Skip JSON field patterns
            if '"error"' in line_lower and ("false" in line_lower or "null" in line_lower):
                continue
            if '"is_error"' in line_lower and "false" in line_lower:
                continue
            filtered_lines.append(line)

        # Stage 2: Extract actual error indicators
        error_keywords = [
            "error",
            "exception",
            "failed",
            "timeout",
            "rate limit",
            "429",
            "500",
            "502",
            "503",
            "connection refused",
            "api limit",
        ]

        for line in filtered_lines:
            line_lower = line.lower()
            for keyword in error_keywords:
                if keyword in line_lower:
                    # Normalize: take first 100 chars, remove variable parts
                    sig = line[:100].strip()
                    # Remove timestamps, IDs, etc.
                    import re

                    sig = re.sub(r"\d{4}-\d{2}-\d{2}", "DATE", sig)
                    sig = re.sub(r"\d{2}:\d{2}:\d{2}", "TIME", sig)
                    sig = re.sub(r"[a-f0-9]{8,}", "ID", sig)
                    return sig

        return None

    def reset(self, reason: str = "manual_reset") -> None:
        """Manually reset the circuit breaker."""
        if self.state != CircuitState.CLOSED:
            self._transition(CircuitState.CLOSED, reason, None)
        self.metrics.reset()
        self.opened_at = None

    def get_status(self) -> dict:
        """Get current circuit breaker status."""
        time_in_state = None
        if self.opened_at:
            time_in_state = time.time() - self.opened_at

        return {
            "state": self.state.value,
            "metrics": {
                "consecutive_failures": self.metrics.consecutive_failures,
                "consecutive_no_progress": self.metrics.consecutive_no_progress,
                "same_error_count": self.metrics.same_error_count,
                "half_open_successes": self.metrics.half_open_successes,
            },
            "opened_at": self.opened_at,
            "time_in_open_state": time_in_state,
            "recovery_timeout": self.config.recovery_timeout_seconds,
            "recent_history": [
                {
                    "timestamp": e.timestamp,
                    "from": e.from_state.value,
                    "to": e.to_state.value,
                    "reason": e.reason,
                }
                for e in self.history[-5:]
            ],
        }

    def _persist_state(self) -> None:
        """Persist state to disk."""
        if not self.persist_path:
            return

        import json

        try:
            self.persist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.persist_path, "w") as f:
                json.dump(
                    {
                        "state": self.state.value,
                        "opened_at": self.opened_at,
                        "metrics": {
                            "consecutive_failures": self.metrics.consecutive_failures,
                            "consecutive_no_progress": self.metrics.consecutive_no_progress,
                            "same_error_count": self.metrics.same_error_count,
                            "last_error_signature": self.metrics.last_error_signature,
                            "half_open_successes": self.metrics.half_open_successes,
                        },
                    },
                    f,
                )
        except Exception:
            logger.exception("Failed to persist circuit breaker state")

    def _load_state(self) -> None:
        """Load persisted state from disk."""
        if not self.persist_path or not self.persist_path.exists():
            return

        import json

        try:
            with open(self.persist_path) as f:
                data = json.load(f)

            self.state = CircuitState(data.get("state", "closed"))
            self.opened_at = data.get("opened_at")

            metrics = data.get("metrics", {})
            self.metrics.consecutive_failures = metrics.get("consecutive_failures", 0)
            self.metrics.consecutive_no_progress = metrics.get("consecutive_no_progress", 0)
            self.metrics.same_error_count = metrics.get("same_error_count", 0)
            self.metrics.last_error_signature = metrics.get("last_error_signature")
            self.metrics.half_open_successes = metrics.get("half_open_successes", 0)

            logger.info("circuit_breaker.loaded", state=self.state.value)
        except Exception:
            logger.exception("Failed to load circuit breaker state")

    # =========================================================================
    # Memory/Dynamics Integration (Full-Scale Ralph)
    # =========================================================================

    def _refresh_known_traps(self) -> None:
        """
        Load known trap states from dynamics report and TransitionDB.

        Traps are states with low action_rate and low delta_V, indicating
        the system is stuck and unlikely to make progress.
        """
        if not self.config.use_dynamics_traps:
            return

        # Refresh every 5 minutes
        if time.time() - self._traps_loaded_at < 300:
            return

        self._known_traps.clear()

        # Try loading from dynamics report (faster, always available)
        try:
            report_path = self._find_dynamics_report()
            if report_path and report_path.exists():
                with open(report_path) as f:
                    report = json.load(f)

                # Extract trap warnings from report
                trap_warnings = report.get("trap_warnings", [])
                for trap in trap_warnings:
                    state_id = trap.get("state_id")
                    if state_id:
                        self._known_traps[state_id] = {
                            "reason": trap.get("reason", "unknown"),
                            "action_rate": trap.get("action_rate", 0.0),
                            "delta_v": trap.get("delta_v", 0.0),
                        }

                # Also check by_domain action rates
                action_summary = report.get("action_summary", {})
                by_domain = action_summary.get("by_domain", {})
                for domain, rate in by_domain.items():
                    if isinstance(rate, (int, float)) and rate < 0.1:
                        # Low action rate domain - all states are potential traps
                        self._known_traps[f"domain:{domain}"] = {
                            "reason": "low_domain_action_rate",
                            "action_rate": rate,
                        }

        except Exception:
            logger.debug("Failed to load traps from dynamics report")

        # Try loading from TransitionDB (richer data, may not exist)
        if self.transition_db:
            try:
                # Query trap_warnings table if it exists
                cursor = self.transition_db.conn.cursor()
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='trap_warnings'"
                )
                if cursor.fetchone():
                    rows = cursor.execute(
                        """
                        SELECT state_id, domain, reason, action_rate, delta_v
                        FROM trap_warnings
                        WHERE discovered_at > datetime('now', '-7 days')
                        """
                    ).fetchall()
                    for row in rows:
                        self._known_traps[row["state_id"]] = {
                            "domain": row["domain"],
                            "reason": row["reason"],
                            "action_rate": row["action_rate"],
                            "delta_v": row["delta_v"],
                        }
            except Exception:
                logger.debug("Failed to load traps from TransitionDB")

        self._traps_loaded_at = time.time()

        if self._known_traps:
            logger.info(
                "circuit_breaker.traps_loaded",
                trap_count=len(self._known_traps),
            )

    def _find_dynamics_report(self) -> Path | None:
        """Find the dynamics report file."""
        # Try common locations
        candidates = [
            Path(".cyntra/dynamics/dynamics_report.json"),
            Path("kernel/.cyntra/dynamics/dynamics_report.json"),
        ]

        # If persist_path is set, use its parent to find repo root
        if self.persist_path:
            repo_root = self.persist_path.parent.parent.parent
            candidates.insert(0, repo_root / ".cyntra" / "dynamics" / "dynamics_report.json")

        for path in candidates:
            if path.exists():
                return path

        return None

    def _is_known_trap(self, state_id: str | None) -> bool:
        """
        Check if a state is a known trap.

        A state is considered a trap if:
        1. It's in the known_traps cache
        2. Its domain has low action rate
        """
        if not state_id or not self.config.use_dynamics_traps:
            return False

        # Refresh cache periodically
        self._refresh_known_traps()

        # Direct state match
        if state_id in self._known_traps:
            return True

        # Check domain-level traps (state_id often contains domain prefix)
        for trap_key, trap_info in self._known_traps.items():
            if trap_key.startswith("domain:"):
                domain = trap_key.split(":", 1)[1]
                if domain in state_id.lower():
                    return True

        return False

    def _has_recent_discoveries(self, session_id: str | None) -> bool:
        """
        Check if the session has recent discoveries that count as progress.

        Discoveries include:
        - New patterns identified
        - Key decisions made
        - Problem-solution pairs found
        - Architecture insights

        This prevents false-positive stagnation detection when the agent
        is making conceptual progress without file changes.
        """
        if not session_id or not self.config.use_memory_context:
            return False

        if not self.memory_bridge:
            return False

        try:
            # Query recent observations from memory
            observations = self.memory_bridge.hooks.db.get_observations(
                session_id=session_id,
                limit=10,
            )

            # Check for discovery-type observations
            discovery_types = {"discovery", "decision", "pattern", "PATTERN", "DECISION"}
            discovery_concepts = {"PATTERN", "PROBLEM_SOLUTION", "WORKFLOW"}

            for obs in observations:
                obs_type = obs.get("type", "")
                obs_concept = obs.get("concept", "")

                if obs_type in discovery_types or obs_concept in discovery_concepts:
                    logger.debug(
                        "circuit_breaker.discovery_found",
                        type=obs_type,
                        concept=obs_concept,
                        session_id=session_id,
                    )
                    return True

            return False

        except Exception:
            # Graceful degradation - don't block on memory errors
            logger.debug("Failed to query memory for discoveries")
            return False

    def get_trap_info(self, state_id: str | None) -> dict[str, Any] | None:
        """Get trap information for a state, if it's a known trap."""
        if not state_id:
            return None

        self._refresh_known_traps()
        return self._known_traps.get(state_id)
