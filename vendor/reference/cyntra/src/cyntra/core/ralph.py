"""
Ralph Integration for Cyntra Kernel.

Unified interface for Ralph-style autonomous loop features:
- Circuit breaker for stagnation detection
- Response analyzer for completion signals
- Rate limiter for API quota management
- Session manager for context continuity

This module provides a single integration point for the kernel runner
to incorporate all Ralph features.

Inspired by: https://github.com/frankbria/ralph-claude-code
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from cyntra.core.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
)
from cyntra.core.rate_limiter import (
    RateLimiter,
    RateLimiterConfig,
    format_wait_time,
)
from cyntra.core.response_analyzer import (
    AnalysisResult,
    CompletionSignal,
    ResponseAnalyzer,
)
from cyntra.core.session_manager import (
    SessionConfig,
    SessionInfo,
    SessionManager,
)

if TYPE_CHECKING:
    from cyntra.cognition.dynamics.transition_db import TransitionDB
    from cyntra.core.memory_integration import KernelMemoryBridge
    from cyntra.core.state.models import Issue

logger = structlog.get_logger()


@dataclass
class RalphConfig:
    """
    Configuration for Ralph-style autonomous loop features.

    Loaded from .cyntra/config.yaml under the 'ralph' key:

    ```yaml
    ralph:
      enabled: true
      circuit_breaker:
        no_progress_threshold: 3
        same_error_threshold: 5
        recovery_timeout_seconds: 300
      rate_limiter:
        max_calls_per_hour: 100
        max_tokens_per_hour: 500000
      session:
        expiration_seconds: 86400
        idle_timeout_seconds: 3600
      completion:
        confidence_threshold: 0.7
        auto_exit_on_done: true
    ```
    """

    enabled: bool = True

    # Circuit breaker
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)

    # Rate limiter
    rate_limiter: RateLimiterConfig = field(default_factory=RateLimiterConfig)

    # Session manager
    session: SessionConfig = field(default_factory=SessionConfig)

    # Completion detection
    completion_confidence_threshold: float = 0.7
    auto_exit_on_done: bool = False  # Exit kernel when all tasks done
    max_consecutive_done_signals: int = 2

    # Exit detection
    max_consecutive_test_loops: int = 3
    test_percentage_threshold: float = 0.3

    # Full-Scale Ralph: Memory/Dynamics integration
    use_memory_context: bool = True
    use_dynamics_traps: bool = True
    learned_context_dir: str | None = None  # Path to .cyntra/learned_context/

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RalphConfig:
        """Create config from dictionary."""
        if not data:
            return cls()

        cb_data = data.get("circuit_breaker", {})
        rl_data = data.get("rate_limiter", {})
        session_data = data.get("session", {})

        return cls(
            enabled=bool(data.get("enabled", True)),
            circuit_breaker=CircuitBreakerConfig(
                no_progress_threshold=int(cb_data.get("no_progress_threshold", 3)),
                same_error_threshold=int(cb_data.get("same_error_threshold", 5)),
                consecutive_failure_threshold=int(cb_data.get("consecutive_failure_threshold", 3)),
                recovery_timeout_seconds=int(cb_data.get("recovery_timeout_seconds", 300)),
                half_open_success_threshold=int(cb_data.get("half_open_success_threshold", 2)),
                output_decline_threshold=float(cb_data.get("output_decline_threshold", 0.7)),
            ),
            rate_limiter=RateLimiterConfig(
                max_calls_per_hour=int(rl_data.get("max_calls_per_hour", 100)),
                max_tokens_per_hour=int(rl_data.get("max_tokens_per_hour", 500_000)),
                toolchain_limits=dict(rl_data.get("toolchain_limits", {})),
                max_burst=int(rl_data.get("max_burst", 10)),
                burst_window_seconds=int(rl_data.get("burst_window_seconds", 60)),
                five_hour_limit_detection=bool(rl_data.get("five_hour_limit_detection", True)),
                five_hour_wait_minutes=int(rl_data.get("five_hour_wait_minutes", 60)),
            ),
            session=SessionConfig(
                expiration_seconds=int(session_data.get("expiration_seconds", 86400)),
                idle_timeout_seconds=int(session_data.get("idle_timeout_seconds", 3600)),
                max_history_entries=int(session_data.get("max_history_entries", 50)),
                reset_on_circuit_breaker=bool(session_data.get("reset_on_circuit_breaker", True)),
                reset_on_interrupt=bool(session_data.get("reset_on_interrupt", True)),
                reset_on_completion=bool(session_data.get("reset_on_completion", True)),
            ),
            completion_confidence_threshold=float(data.get("completion_confidence_threshold", 0.7)),
            auto_exit_on_done=bool(data.get("auto_exit_on_done", False)),
            max_consecutive_done_signals=int(data.get("max_consecutive_done_signals", 2)),
            max_consecutive_test_loops=int(data.get("max_consecutive_test_loops", 3)),
            test_percentage_threshold=float(data.get("test_percentage_threshold", 0.3)),
            use_memory_context=bool(data.get("use_memory_context", True)),
            use_dynamics_traps=bool(data.get("use_dynamics_traps", True)),
            learned_context_dir=data.get("learned_context_dir"),
        )


@dataclass
class RalphDecision:
    """Decision from Ralph integration about whether to proceed."""

    allow: bool = True
    reason: str = ""
    wait_seconds: float = 0.0
    should_exit: bool = False
    exit_reason: str = ""


class RalphIntegration:
    """
    Unified Ralph integration for the kernel runner.

    Combines all Ralph features into a single interface that the runner
    can use to make decisions about execution flow.

    Usage:
        ralph = RalphIntegration(config, repo_root)

        # Before dispatch
        decision = ralph.before_dispatch(issue, toolchain)
        if not decision.allow:
            if decision.should_exit:
                break  # Exit kernel loop
            await asyncio.sleep(decision.wait_seconds)
            continue

        # Get session for --continue flag
        session = ralph.get_session(issue.id, toolchain)

        # After dispatch
        ralph.after_dispatch(issue, result, response_text, files_changed)

        # On success/failure
        ralph.on_success(issue)
        ralph.on_failure(issue, error)
    """

    def __init__(
        self,
        config: RalphConfig,
        repo_root: Path,
        *,
        memory_bridge: KernelMemoryBridge | None = None,
        transition_db: TransitionDB | None = None,
    ) -> None:
        self.config = config
        self.repo_root = repo_root
        self.memory_bridge = memory_bridge
        self.transition_db = transition_db

        # State directory
        state_dir = repo_root / ".cyntra" / "ralph"
        state_dir.mkdir(parents=True, exist_ok=True)

        # Resolve learned context directory
        learned_context_dir = None
        if config.learned_context_dir:
            learned_context_dir = Path(config.learned_context_dir)
        elif (repo_root / ".cyntra" / "learned_context").exists():
            learned_context_dir = repo_root / ".cyntra" / "learned_context"

        # Update circuit breaker config with memory/dynamics settings
        cb_config = config.circuit_breaker
        cb_config.use_memory_context = config.use_memory_context
        cb_config.use_dynamics_traps = config.use_dynamics_traps

        # Initialize components with Full-Scale Ralph integrations
        self.circuit_breaker = CircuitBreaker(
            config=cb_config,
            persist_path=state_dir / "circuit_breaker.json",
            transition_db=transition_db if config.use_dynamics_traps else None,
            memory_bridge=memory_bridge if config.use_memory_context else None,
        )

        self.rate_limiter = RateLimiter(
            config=config.rate_limiter,
            persist_path=state_dir / "rate_limiter.json",
        )

        self.session_manager = SessionManager(
            config=config.session,
            persist_path=state_dir / "sessions.json",
        )

        self.response_analyzer = ResponseAnalyzer(
            learned_context_dir=learned_context_dir,
            memory_bridge=memory_bridge if config.use_memory_context else None,
        )

        # Tracking for exit detection
        self._consecutive_done_signals = 0
        self._consecutive_test_loops = 0
        self._total_loops = 0
        self._test_only_loops = 0

        # Ensemble exit detector (Phase 3 - Full-Scale Ralph)
        self.ensemble_detector = EnsembleExitDetector(
            exit_threshold=config.completion_confidence_threshold,
        )
        self._last_ensemble_decision: EnsembleExitDecision | None = None

        logger.info(
            "ralph.initialized",
            enabled=config.enabled,
            use_memory_context=config.use_memory_context,
            use_dynamics_traps=config.use_dynamics_traps,
            learned_context_dir=str(learned_context_dir) if learned_context_dir else None,
            has_memory_bridge=memory_bridge is not None,
            has_transition_db=transition_db is not None,
        )

    def before_dispatch(
        self,
        issue: Issue,
        toolchain: str,
    ) -> RalphDecision:
        """
        Check if dispatch should proceed.

        Called before each dispatch to verify:
        - Circuit breaker allows requests
        - Rate limits not exceeded
        - Exit conditions not met
        """
        if not self.config.enabled:
            return RalphDecision(allow=True)

        # Check circuit breaker
        if not self.circuit_breaker.allow_request(issue.id):
            cb_status = self.circuit_breaker.get_status()
            wait_seconds = cb_status.get("time_in_open_state", 0) or 0
            recovery_timeout = self.config.circuit_breaker.recovery_timeout_seconds

            if self.circuit_breaker.state == CircuitState.OPEN:
                # Trigger session reset on circuit breaker open
                self.session_manager.on_circuit_breaker_open()

                return RalphDecision(
                    allow=False,
                    reason="circuit_breaker_open",
                    wait_seconds=max(0, recovery_timeout - wait_seconds),
                )

        # Check rate limiter
        wait_info = self.rate_limiter.get_wait_info(toolchain)
        if wait_info.should_wait:
            return RalphDecision(
                allow=False,
                reason=wait_info.reason,
                wait_seconds=wait_info.wait_seconds,
            )

        # Check exit conditions
        if self._should_exit():
            return RalphDecision(
                allow=False,
                should_exit=True,
                exit_reason=self._get_exit_reason(),
            )

        return RalphDecision(allow=True)

    def get_session(
        self,
        issue_id: str,
        toolchain: str,
    ) -> SessionInfo | None:
        """Get session for --continue flag support."""
        if not self.config.enabled:
            return None

        return self.session_manager.get_or_create_session(issue_id, toolchain)

    def should_resume_session(self, issue_id: str) -> bool:
        """Check if an issue has a session to resume."""
        if not self.config.enabled:
            return False

        return self.session_manager.should_resume(issue_id)

    def after_dispatch(
        self,
        issue: Issue,
        toolchain: str,
        success: bool,
        response_text: str = "",
        files_changed: list[str] | None = None,
        tokens_used: int = 0,
        error: str | None = None,
        *,
        state_id: str | None = None,
        session_id: str | None = None,
    ) -> AnalysisResult | None:
        """
        Process dispatch result.

        Called after each dispatch to:
        - Record rate limiter usage
        - Update circuit breaker
        - Analyze response for completion
        - Track exit detection metrics
        """
        if not self.config.enabled:
            return None

        # Record rate limiter usage
        self.rate_limiter.record_call(toolchain, tokens_used, success)

        # Detect 5-hour limit
        if error and self.rate_limiter.detect_five_hour_limit(error):
            self.rate_limiter.record_five_hour_limit()

        # Analyze response
        analysis = self.response_analyzer.analyze(
            response_text,
            issue=issue,
            files_changed=files_changed,
        )

        # Update circuit breaker with Full-Scale Ralph state/session tracking
        if success:
            self.circuit_breaker.record_success(
                issue_id=issue.id,
                files_changed=len(files_changed or []),
                output_tokens=tokens_used,
                state_id=state_id,
                session_id=session_id,
            )
        else:
            self.circuit_breaker.record_failure(
                issue_id=issue.id,
                error=error,
            )

        # Update exit detection metrics
        self._total_loops += 1
        self._update_exit_metrics(analysis, files_changed)

        # Phase 3: Ensemble exit evaluation
        if analysis:
            self._last_ensemble_decision = self.ensemble_detector.evaluate(
                analysis=analysis,
                circuit_breaker=self.circuit_breaker,
                memory_bridge=self.memory_bridge,
                transition_db=self.transition_db,
                state_id=state_id,
                session_id=session_id,
            )
            if self._last_ensemble_decision.should_exit:
                logger.info(
                    "ralph.ensemble_exit_signal",
                    confidence=self._last_ensemble_decision.confidence,
                    reason=self._last_ensemble_decision.reason,
                    completion=self._last_ensemble_decision.completion_score,
                    stagnation=self._last_ensemble_decision.stagnation_score,
                    trap=self._last_ensemble_decision.trap_score,
                )

        return analysis

    def on_success(self, issue: Issue) -> None:
        """Handle successful completion of an issue."""
        if not self.config.enabled:
            return

        # Complete the session
        self.session_manager.complete_session(issue.id)

        # Reset response analyzer history for this issue
        self.response_analyzer.reset_history()

    def on_failure(self, issue: Issue, error: str | None = None) -> None:
        """Handle failed dispatch."""
        if not self.config.enabled:
            return

        # Pause the session (can be resumed on retry)
        self.session_manager.pause_session(issue.id, "dispatch_failed")

    def on_interrupt(self) -> None:
        """Handle keyboard interrupt."""
        if not self.config.enabled:
            return

        self.session_manager.on_interrupt()

    def reset_circuit_breaker(self, reason: str = "manual_reset") -> None:
        """Manually reset the circuit breaker."""
        self.circuit_breaker.reset(reason)

    def reset_rate_limiter(self) -> None:
        """Manually reset rate limiter state."""
        self.rate_limiter.reset()

    def get_status(self) -> dict:
        """Get comprehensive Ralph status."""
        return {
            "enabled": self.config.enabled,
            "circuit_breaker": self.circuit_breaker.get_status(),
            "rate_limiter": self.rate_limiter.get_status(),
            "sessions": self.session_manager.get_status(),
            "exit_detection": {
                "consecutive_done_signals": self._consecutive_done_signals,
                "consecutive_test_loops": self._consecutive_test_loops,
                "total_loops": self._total_loops,
                "test_only_loops": self._test_only_loops,
                "test_percentage": (
                    self._test_only_loops / self._total_loops if self._total_loops > 0 else 0
                ),
            },
            # Full-Scale Ralph additions
            "learned_patterns": self.response_analyzer.get_learned_pattern_stats(),
            "integrations": {
                "use_memory_context": self.config.use_memory_context,
                "use_dynamics_traps": self.config.use_dynamics_traps,
                "has_memory_bridge": self.memory_bridge is not None,
                "has_transition_db": self.transition_db is not None,
            },
            "ensemble": self._get_ensemble_status(),
        }

    def _get_ensemble_status(self) -> dict[str, Any]:
        """Get status of ensemble exit detector."""
        if not self._last_ensemble_decision:
            return {"evaluated": False}

        decision = self._last_ensemble_decision
        return {
            "evaluated": True,
            "should_exit": decision.should_exit,
            "confidence": decision.confidence,
            "reason": decision.reason,
            "completion_score": decision.completion_score,
            "stagnation_score": decision.stagnation_score,
            "trap_score": decision.trap_score,
            "signal_count": len(decision.signals),
        }

    def get_ensemble_decision(self) -> EnsembleExitDecision | None:
        """Get the last ensemble exit decision."""
        return self._last_ensemble_decision

    def _update_exit_metrics(
        self,
        analysis: AnalysisResult,
        files_changed: list[str] | None,
    ) -> None:
        """Update metrics for exit detection."""
        # Track done signals
        if analysis.completion_signal in (CompletionSignal.STRONG, CompletionSignal.MODERATE):
            if analysis.completion_confidence >= self.config.completion_confidence_threshold:
                self._consecutive_done_signals += 1
            else:
                self._consecutive_done_signals = 0
        else:
            self._consecutive_done_signals = 0

        # Track test-only loops
        if files_changed:
            test_files = sum(1 for f in files_changed if "test" in f.lower())
            if test_files == len(files_changed) and len(files_changed) > 0:
                self._consecutive_test_loops += 1
                self._test_only_loops += 1
            else:
                self._consecutive_test_loops = 0
        else:
            self._consecutive_test_loops = 0

    def _should_exit(self) -> bool:
        """Check if kernel should exit based on Ralph metrics."""
        if not self.config.auto_exit_on_done:
            return False

        # Check consecutive done signals
        if self._consecutive_done_signals >= self.config.max_consecutive_done_signals:
            return True

        # Check consecutive test-only loops
        if self._consecutive_test_loops >= self.config.max_consecutive_test_loops:
            return True

        # Check test percentage threshold
        if self._total_loops >= 5:  # Need enough data
            test_pct = self._test_only_loops / self._total_loops
            if test_pct >= self.config.test_percentage_threshold:
                return True

        return False

    def _get_exit_reason(self) -> str:
        """Get reason for exit decision."""
        if self._consecutive_done_signals >= self.config.max_consecutive_done_signals:
            return f"consecutive_done_signals ({self._consecutive_done_signals})"

        if self._consecutive_test_loops >= self.config.max_consecutive_test_loops:
            return f"consecutive_test_loops ({self._consecutive_test_loops})"

        if self._total_loops >= 5:
            test_pct = self._test_only_loops / self._total_loops
            if test_pct >= self.config.test_percentage_threshold:
                return f"test_percentage ({test_pct:.0%})"

        return "unknown"


# =============================================================================
# Phase 3: Ensemble Exit Detection (Full-Scale Ralph)
# =============================================================================


@dataclass
class EnsembleSignal:
    """Individual signal contributing to ensemble exit decision."""

    source: str  # analyzer, circuit_breaker, memory, dynamics
    signal_type: str  # completion, stagnation, trap, discovery
    value: float  # 0.0 - 1.0 (contribution to exit)
    weight: float  # How much this signal contributes
    reason: str  # Human-readable explanation


@dataclass
class EnsembleExitDecision:
    """Result of ensemble exit detection."""

    should_exit: bool
    confidence: float  # 0.0 - 1.0
    reason: str
    signals: list[EnsembleSignal] = field(default_factory=list)

    # Breakdown by category
    completion_score: float = 0.0
    stagnation_score: float = 0.0
    trap_score: float = 0.0


class EnsembleExitDetector:
    """
    Combines multiple signals for robust exit detection.

    Weighted ensemble of:
    - Response analyzer (completion signals, semantic overlap)
    - Circuit breaker (stuck loops, known traps)
    - Memory context (recent discoveries)
    - Dynamics (trap warnings, exploration mode)

    Exit is triggered when combined confidence exceeds threshold.
    """

    # Default weights for each signal source
    DEFAULT_WEIGHTS = {
        "analyzer_completion": 0.35,
        "analyzer_anti_pattern": 0.15,
        "circuit_breaker_state": 0.20,
        "circuit_breaker_trap": 0.15,
        "memory_discovery": 0.10,
        "dynamics_trap": 0.05,
    }

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        exit_threshold: float = 0.7,
        stagnation_threshold: float = 0.6,
    ) -> None:
        """
        Initialize ensemble exit detector.

        Args:
            weights: Custom weights for signal sources
            exit_threshold: Combined confidence threshold for exit
            stagnation_threshold: Threshold for stagnation detection
        """
        self.weights = {**self.DEFAULT_WEIGHTS, **(weights or {})}
        self.exit_threshold = exit_threshold
        self.stagnation_threshold = stagnation_threshold

    def evaluate(
        self,
        analysis: AnalysisResult | None,
        circuit_breaker: CircuitBreaker,
        memory_bridge: KernelMemoryBridge | None = None,
        transition_db: TransitionDB | None = None,
        state_id: str | None = None,
        session_id: str | None = None,
    ) -> EnsembleExitDecision:
        """
        Evaluate all signals and produce exit decision.

        Args:
            analysis: Latest response analysis
            circuit_breaker: Circuit breaker instance
            memory_bridge: Optional memory bridge for discovery signals
            transition_db: Optional transition DB for trap queries
            state_id: Current state ID for trap checking
            session_id: Current session ID for memory queries

        Returns:
            EnsembleExitDecision with combined assessment
        """
        signals: list[EnsembleSignal] = []
        completion_score = 0.0
        stagnation_score = 0.0
        trap_score = 0.0

        # --- Response Analyzer Signals ---
        if analysis:
            # Completion confidence
            if analysis.completion_confidence > 0:
                weight = self.weights.get("analyzer_completion", 0.35)
                signals.append(
                    EnsembleSignal(
                        source="analyzer",
                        signal_type="completion",
                        value=analysis.completion_confidence,
                        weight=weight,
                        reason=f"Completion signal: {analysis.completion_signal.value} "
                        f"({analysis.completion_confidence:.2f})",
                    )
                )
                completion_score += analysis.completion_confidence * weight

            # Anti-pattern warnings (negative signal)
            if analysis.anti_pattern_warnings:
                weight = self.weights.get("analyzer_anti_pattern", 0.15)
                penalty = min(1.0, 0.3 * len(analysis.anti_pattern_warnings))
                signals.append(
                    EnsembleSignal(
                        source="analyzer",
                        signal_type="anti_pattern",
                        value=-penalty,
                        weight=weight,
                        reason=f"Anti-patterns detected: {len(analysis.anti_pattern_warnings)}",
                    )
                )
                completion_score -= penalty * weight

            # Semantic overlap (boosts completion if high)
            if analysis.semantic_overlap_score > 0.3:
                completion_score += 0.1 * analysis.semantic_overlap_score

        # --- Circuit Breaker Signals ---
        cb_status = circuit_breaker.get_status()
        cb_state = cb_status.get("state", "closed")

        if cb_state in ("open", "half_open"):
            weight = self.weights.get("circuit_breaker_state", 0.20)
            signals.append(
                EnsembleSignal(
                    source="circuit_breaker",
                    signal_type="stagnation",
                    value=0.8 if cb_state == "open" else 0.4,
                    weight=weight,
                    reason=f"Circuit breaker: {cb_state}",
                )
            )
            stagnation_score += (0.8 if cb_state == "open" else 0.4) * weight

        # Known trap detection
        if state_id and circuit_breaker._is_known_trap(state_id):
            weight = self.weights.get("circuit_breaker_trap", 0.15)
            trap_info = circuit_breaker.get_trap_info(state_id)
            signals.append(
                EnsembleSignal(
                    source="circuit_breaker",
                    signal_type="trap",
                    value=1.0,
                    weight=weight,
                    reason=f"Known trap state: {trap_info.get('source', 'unknown')}",
                )
            )
            trap_score += 1.0 * weight

        # --- Memory Discovery Signal ---
        if memory_bridge and session_id:
            has_discoveries = circuit_breaker._has_recent_discoveries(session_id)
            if has_discoveries:
                weight = self.weights.get("memory_discovery", 0.10)
                signals.append(
                    EnsembleSignal(
                        source="memory",
                        signal_type="discovery",
                        value=-0.5,  # Negative = continue exploring
                        weight=weight,
                        reason="Recent discoveries detected - continue exploring",
                    )
                )
                completion_score -= 0.5 * weight

        # --- Dynamics Trap Signal ---
        if transition_db and state_id and transition_db.is_known_trap(state_id):
            weight = self.weights.get("dynamics_trap", 0.05)
            trap_warning = transition_db.get_trap_warning(state_id)
            severity = trap_warning.get("severity", "warning") if trap_warning else "unknown"
            signals.append(
                EnsembleSignal(
                    source="dynamics",
                    signal_type="trap",
                    value=1.0 if severity == "critical" else 0.7,
                    weight=weight,
                    reason=f"Dynamics trap warning: {severity}",
                )
            )
            trap_score += (1.0 if severity == "critical" else 0.7) * weight

        # --- Compute Final Decision ---
        # Normalize scores to [0, 1]
        completion_score = max(0.0, min(1.0, completion_score))
        stagnation_score = max(0.0, min(1.0, stagnation_score))
        trap_score = max(0.0, min(1.0, trap_score))

        # Exit if completion is high OR if stagnation/trap is very high
        combined_confidence = max(
            completion_score,
            stagnation_score * 0.8,  # Stagnation needs slightly higher threshold
            trap_score * 0.9,  # Traps need higher threshold
        )

        should_exit = combined_confidence >= self.exit_threshold
        reason = self._build_reason(completion_score, stagnation_score, trap_score, signals)

        return EnsembleExitDecision(
            should_exit=should_exit,
            confidence=combined_confidence,
            reason=reason,
            signals=signals,
            completion_score=completion_score,
            stagnation_score=stagnation_score,
            trap_score=trap_score,
        )

    def _build_reason(
        self,
        completion: float,
        stagnation: float,
        trap: float,
        signals: list[EnsembleSignal],
    ) -> str:
        """Build human-readable reason for decision."""
        parts = []
        if completion >= 0.5:
            parts.append(f"completion:{completion:.2f}")
        if stagnation >= 0.3:
            parts.append(f"stagnation:{stagnation:.2f}")
        if trap >= 0.2:
            parts.append(f"trap:{trap:.2f}")

        if not parts:
            return "no significant signals"

        return f"ensemble[{', '.join(parts)}]"


# Convenience for quick status formatting
def format_ralph_status(status: dict) -> str:
    """Format Ralph status for display."""
    lines = []

    cb = status.get("circuit_breaker", {})
    lines.append(f"Circuit Breaker: {cb.get('state', 'unknown')}")
    if cb.get("state") == "open":
        wait = cb.get("time_in_open_state", 0)
        lines.append(f"  Recovery in: {format_wait_time(wait)}")

    rl = status.get("rate_limiter", {}).get("hourly", {})
    lines.append(f"Rate Limit: {rl.get('calls', 0)}/{rl.get('calls_limit', 100)} calls/hour")
    if rl.get("reset_in_seconds", 0) > 0:
        lines.append(f"  Reset in: {format_wait_time(rl['reset_in_seconds'])}")

    sessions = status.get("sessions", {})
    lines.append(f"Sessions: {sessions.get('active_sessions', 0)} active")

    return "\n".join(lines)
