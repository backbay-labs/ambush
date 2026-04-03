"""
Ralph Metrics Collection

Collects and exposes metrics for Full-Scale Ralph autonomous features:
- Circuit breaker state and trip frequency
- Response analyzer confidence distributions
- Exit detection ensemble signals
- Memory/Dynamics integration health
- Rate limiter utilization
- Session management statistics

These metrics enable dashboards and alerting for autonomous execution monitoring.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from cyntra.core.ralph import RalphIntegration

logger = structlog.get_logger()


@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker behavior."""

    state: str = "closed"
    total_trips: int = 0
    trips_by_reason: dict[str, int] = field(default_factory=dict)
    time_in_open_total_seconds: float = 0.0
    recovery_count: int = 0
    last_trip_timestamp: str | None = None
    last_trip_reason: str | None = None

    # Memory integration
    discoveries_detected: int = 0
    trap_state_trips: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "total_trips": self.total_trips,
            "trips_by_reason": dict(self.trips_by_reason),
            "time_in_open_total_seconds": self.time_in_open_total_seconds,
            "recovery_count": self.recovery_count,
            "last_trip_timestamp": self.last_trip_timestamp,
            "last_trip_reason": self.last_trip_reason,
            "discoveries_detected": self.discoveries_detected,
            "trap_state_trips": self.trap_state_trips,
        }


@dataclass
class ResponseAnalyzerMetrics:
    """Metrics for response analysis."""

    total_analyses: int = 0
    completion_signals: dict[str, int] = field(default_factory=dict)
    avg_confidence: float = 0.0
    confidence_histogram: dict[str, int] = field(default_factory=dict)

    # Pattern detection
    anti_patterns_detected: int = 0
    patterns_confirmed: int = 0
    learned_patterns_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_analyses": self.total_analyses,
            "completion_signals": dict(self.completion_signals),
            "avg_confidence": round(self.avg_confidence, 3),
            "confidence_histogram": dict(self.confidence_histogram),
            "anti_patterns_detected": self.anti_patterns_detected,
            "patterns_confirmed": self.patterns_confirmed,
            "learned_patterns_count": self.learned_patterns_count,
        }


@dataclass
class EnsembleExitMetrics:
    """Metrics for ensemble exit detection."""

    total_evaluations: int = 0
    exit_recommendations: int = 0
    exit_confidence_histogram: dict[str, int] = field(default_factory=dict)
    signal_contributions: dict[str, float] = field(default_factory=dict)

    # Exit accuracy (if tracked)
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    def to_dict(self) -> dict[str, Any]:
        total = (
            self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        )
        accuracy = (self.true_positives + self.true_negatives) / total if total > 0 else 0.0
        precision = (
            self.true_positives / (self.true_positives + self.false_positives)
            if (self.true_positives + self.false_positives) > 0
            else 0.0
        )

        return {
            "total_evaluations": self.total_evaluations,
            "exit_recommendations": self.exit_recommendations,
            "exit_rate": (
                self.exit_recommendations / self.total_evaluations
                if self.total_evaluations > 0
                else 0.0
            ),
            "exit_confidence_histogram": dict(self.exit_confidence_histogram),
            "signal_contributions": dict(self.signal_contributions),
            "accuracy": round(accuracy, 3),
            "precision": round(precision, 3),
        }


@dataclass
class RateLimiterMetrics:
    """Metrics for rate limiting."""

    total_calls: int = 0
    total_tokens: int = 0
    waits_triggered: int = 0
    total_wait_seconds: float = 0.0
    calls_by_toolchain: dict[str, int] = field(default_factory=dict)
    five_hour_limit_hits: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_calls": self.total_calls,
            "total_tokens": self.total_tokens,
            "waits_triggered": self.waits_triggered,
            "total_wait_seconds": round(self.total_wait_seconds, 1),
            "avg_wait_seconds": (
                round(self.total_wait_seconds / self.waits_triggered, 1)
                if self.waits_triggered > 0
                else 0.0
            ),
            "calls_by_toolchain": dict(self.calls_by_toolchain),
            "five_hour_limit_hits": self.five_hour_limit_hits,
        }


@dataclass
class SessionMetrics:
    """Metrics for session management."""

    active_sessions: int = 0
    total_sessions_created: int = 0
    sessions_completed: int = 0
    sessions_paused: int = 0
    sessions_expired: int = 0
    avg_session_duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_sessions": self.active_sessions,
            "total_sessions_created": self.total_sessions_created,
            "sessions_completed": self.sessions_completed,
            "sessions_paused": self.sessions_paused,
            "sessions_expired": self.sessions_expired,
            "avg_session_duration_seconds": round(self.avg_session_duration_seconds, 1),
        }


@dataclass
class IntegrationHealthMetrics:
    """Metrics for memory/dynamics integration health."""

    memory_bridge_available: bool = False
    transition_db_available: bool = False
    learned_context_available: bool = False

    memory_queries: int = 0
    memory_query_errors: int = 0
    dynamics_queries: int = 0
    dynamics_query_errors: int = 0

    traps_loaded: int = 0
    patterns_loaded: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "memory_bridge_available": self.memory_bridge_available,
            "transition_db_available": self.transition_db_available,
            "learned_context_available": self.learned_context_available,
            "memory_queries": self.memory_queries,
            "memory_query_errors": self.memory_query_errors,
            "memory_query_error_rate": (
                self.memory_query_errors / self.memory_queries if self.memory_queries > 0 else 0.0
            ),
            "dynamics_queries": self.dynamics_queries,
            "dynamics_query_errors": self.dynamics_query_errors,
            "dynamics_query_error_rate": (
                self.dynamics_query_errors / self.dynamics_queries
                if self.dynamics_queries > 0
                else 0.0
            ),
            "traps_loaded": self.traps_loaded,
            "patterns_loaded": self.patterns_loaded,
        }


@dataclass
class RalphMetrics:
    """Aggregate metrics for Full-Scale Ralph."""

    circuit_breaker: CircuitBreakerMetrics = field(default_factory=CircuitBreakerMetrics)
    response_analyzer: ResponseAnalyzerMetrics = field(default_factory=ResponseAnalyzerMetrics)
    ensemble_exit: EnsembleExitMetrics = field(default_factory=EnsembleExitMetrics)
    rate_limiter: RateLimiterMetrics = field(default_factory=RateLimiterMetrics)
    session: SessionMetrics = field(default_factory=SessionMetrics)
    integration_health: IntegrationHealthMetrics = field(default_factory=IntegrationHealthMetrics)

    # Timing
    collected_at: str = ""
    collection_duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "circuit_breaker": self.circuit_breaker.to_dict(),
            "response_analyzer": self.response_analyzer.to_dict(),
            "ensemble_exit": self.ensemble_exit.to_dict(),
            "rate_limiter": self.rate_limiter.to_dict(),
            "session": self.session.to_dict(),
            "integration_health": self.integration_health.to_dict(),
            "collected_at": self.collected_at,
            "collection_duration_ms": self.collection_duration_ms,
        }


class RalphMetricsCollector:
    """
    Collects metrics from RalphIntegration components.

    Usage:
        collector = RalphMetricsCollector(ralph)

        # Get current metrics
        metrics = collector.collect()

        # Export to file
        collector.export_to_file(Path(".cyntra/metrics/ralph.json"))

        # Get prometheus-format metrics
        prom_metrics = collector.to_prometheus()
    """

    def __init__(self, ralph: RalphIntegration | None = None):
        self.ralph = ralph
        self._cumulative_metrics = RalphMetrics()
        self._history: list[RalphMetrics] = []
        self._max_history = 1000

    def set_ralph(self, ralph: RalphIntegration) -> None:
        """Set or update the Ralph integration instance."""
        self.ralph = ralph

    def collect(self) -> RalphMetrics:
        """Collect current metrics from Ralph components."""
        start = time.time()
        metrics = RalphMetrics()

        if not self.ralph:
            metrics.collected_at = datetime.now(UTC).isoformat()
            return metrics

        # Collect circuit breaker metrics
        cb = self.ralph.circuit_breaker
        metrics.circuit_breaker.state = cb.state.value

        # Count trips from history
        for event in cb.history:
            if event.to_state.value == "open":
                metrics.circuit_breaker.total_trips += 1
                reason = event.reason
                metrics.circuit_breaker.trips_by_reason[reason] = (
                    metrics.circuit_breaker.trips_by_reason.get(reason, 0) + 1
                )
                metrics.circuit_breaker.last_trip_timestamp = str(event.timestamp)
                metrics.circuit_breaker.last_trip_reason = reason

                if "trap" in reason.lower():
                    metrics.circuit_breaker.trap_state_trips += 1

            elif event.to_state.value == "closed" and event.from_state.value != "closed":
                metrics.circuit_breaker.recovery_count += 1

        # Collect response analyzer metrics
        ra = self.ralph.response_analyzer
        ra_stats = ra.get_learned_pattern_stats()
        metrics.response_analyzer.learned_patterns_count = ra_stats.get("anti_patterns_count", 0)

        # Collect rate limiter metrics
        rl_status = self.ralph.rate_limiter.get_status()
        metrics.rate_limiter.total_calls = rl_status.get("hourly", {}).get("calls", 0)
        metrics.rate_limiter.total_tokens = rl_status.get("hourly", {}).get("tokens", 0)

        # Collect session metrics
        session_status = self.ralph.session_manager.get_status()
        metrics.session.active_sessions = session_status.get("active_count", 0)
        metrics.session.total_sessions_created = session_status.get("total_created", 0)

        # Collect integration health
        metrics.integration_health.memory_bridge_available = self.ralph.memory_bridge is not None
        metrics.integration_health.transition_db_available = self.ralph.transition_db is not None
        metrics.integration_health.learned_context_available = (
            self.ralph.response_analyzer.learned_context_dir is not None
        )

        if self.ralph.circuit_breaker._known_traps:
            metrics.integration_health.traps_loaded = len(self.ralph.circuit_breaker._known_traps)

        # Collect ensemble metrics
        if self.ralph._last_ensemble_decision:
            decision = self.ralph._last_ensemble_decision
            metrics.ensemble_exit.total_evaluations += 1
            if decision.should_exit:
                metrics.ensemble_exit.exit_recommendations += 1

            # Bucket confidence
            conf_bucket = f"{int(decision.confidence * 10) * 10}%"
            metrics.ensemble_exit.exit_confidence_histogram[conf_bucket] = (
                metrics.ensemble_exit.exit_confidence_histogram.get(conf_bucket, 0) + 1
            )

        # Record collection time
        metrics.collected_at = datetime.now(UTC).isoformat()
        metrics.collection_duration_ms = int((time.time() - start) * 1000)

        # Store in history
        self._history.append(metrics)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]

        return metrics

    def export_to_file(self, path: Path) -> None:
        """Export current metrics to JSON file."""
        metrics = self.collect()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(metrics.to_dict(), indent=2))
        logger.debug("ralph_metrics.exported", path=str(path))

    def to_prometheus(self) -> str:
        """
        Export metrics in Prometheus exposition format.

        Returns metrics that can be scraped by Prometheus or compatible systems.
        """
        metrics = self.collect()
        lines = []

        # Circuit breaker metrics
        lines.append(
            "# HELP ralph_circuit_breaker_state Circuit breaker state (0=closed, 1=open, 2=half_open)"
        )
        lines.append("# TYPE ralph_circuit_breaker_state gauge")
        state_value = {"closed": 0, "open": 1, "half_open": 2}.get(
            metrics.circuit_breaker.state, -1
        )
        lines.append(f"ralph_circuit_breaker_state {state_value}")

        lines.append("# HELP ralph_circuit_breaker_trips_total Total circuit breaker trips")
        lines.append("# TYPE ralph_circuit_breaker_trips_total counter")
        lines.append(f"ralph_circuit_breaker_trips_total {metrics.circuit_breaker.total_trips}")

        for reason, count in metrics.circuit_breaker.trips_by_reason.items():
            lines.append(f'ralph_circuit_breaker_trips_total{{reason="{reason}"}} {count}')

        # Rate limiter metrics
        lines.append("# HELP ralph_rate_limiter_calls_total Total API calls")
        lines.append("# TYPE ralph_rate_limiter_calls_total counter")
        lines.append(f"ralph_rate_limiter_calls_total {metrics.rate_limiter.total_calls}")

        lines.append("# HELP ralph_rate_limiter_tokens_total Total tokens used")
        lines.append("# TYPE ralph_rate_limiter_tokens_total counter")
        lines.append(f"ralph_rate_limiter_tokens_total {metrics.rate_limiter.total_tokens}")

        # Session metrics
        lines.append("# HELP ralph_sessions_active Current active sessions")
        lines.append("# TYPE ralph_sessions_active gauge")
        lines.append(f"ralph_sessions_active {metrics.session.active_sessions}")

        # Integration health
        lines.append(
            "# HELP ralph_integration_available Integration availability (1=available, 0=unavailable)"
        )
        lines.append("# TYPE ralph_integration_available gauge")
        lines.append(
            f'ralph_integration_available{{component="memory_bridge"}} {int(metrics.integration_health.memory_bridge_available)}'
        )
        lines.append(
            f'ralph_integration_available{{component="transition_db"}} {int(metrics.integration_health.transition_db_available)}'
        )
        lines.append(
            f'ralph_integration_available{{component="learned_context"}} {int(metrics.integration_health.learned_context_available)}'
        )

        # Traps loaded
        lines.append("# HELP ralph_traps_loaded Number of trap states loaded")
        lines.append("# TYPE ralph_traps_loaded gauge")
        lines.append(f"ralph_traps_loaded {metrics.integration_health.traps_loaded}")

        return "\n".join(lines)

    def get_summary(self) -> dict[str, Any]:
        """Get a high-level summary suitable for dashboards."""
        metrics = self.collect()

        return {
            "status": "healthy" if metrics.circuit_breaker.state == "closed" else "degraded",
            "circuit_breaker_state": metrics.circuit_breaker.state,
            "total_trips": metrics.circuit_breaker.total_trips,
            "api_calls": metrics.rate_limiter.total_calls,
            "tokens_used": metrics.rate_limiter.total_tokens,
            "active_sessions": metrics.session.active_sessions,
            "integrations": {
                "memory": metrics.integration_health.memory_bridge_available,
                "dynamics": metrics.integration_health.transition_db_available,
                "patterns": metrics.integration_health.learned_context_available,
            },
            "traps_loaded": metrics.integration_health.traps_loaded,
            "patterns_loaded": metrics.response_analyzer.learned_patterns_count,
            "collected_at": metrics.collected_at,
        }
