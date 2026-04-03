"""
Noise monitor for Hellcat OPSEC.

Tracks detection signals throughout an engagement and produces a composite
noise score that determines whether to throttle, pause, or abort operations.

The ensemble noise detector combines multiple signal sources with configurable
weights (see architecture overview):

  analyzer(35%) + circuit(20%) + trap(15%) + rate_monitor(15%) + session_health(15%)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class NoiseSignal:
    """A single detection signal observed during the engagement."""

    signal_type: str  # e.g. "waf_blocked", "rate_limited", "captcha_challenged"
    severity: float  # 0.0 - 1.0
    timestamp: float = field(default_factory=time.time)
    source: str = ""  # which operator/target produced this signal
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NoiseMonitorConfig:
    """Configuration for noise monitoring thresholds."""

    # Noise score thresholds (0.0 - 1.0)
    warn_threshold: float = 0.3
    throttle_threshold: float = 0.5
    pause_threshold: float = 0.7
    abort_threshold: float = 0.9

    # Signal decay: signals lose relevance over time
    decay_half_life_seconds: float = 300.0  # 5 minutes

    # Window: only consider signals within this period
    window_seconds: float = 1800.0  # 30 minutes

    # Ensemble weights
    weight_analyzer: float = 0.35
    weight_circuit: float = 0.20
    weight_trap: float = 0.15
    weight_rate: float = 0.15
    weight_session: float = 0.15

    # Throttle parameters
    throttle_delay_ms: int = 3000
    throttle_jitter_ms: int = 2000


class ResponseLevel:
    """Current OPSEC response level."""

    NORMAL = "normal"
    WARN = "warn"
    THROTTLE = "throttle"
    PAUSE = "pause"
    ABORT = "abort"


class NoiseMonitor:
    """
    Tracks cumulative detection signals and manages OPSEC response level.

    The noise score is a weighted, time-decayed aggregate of all detection
    signals observed during the engagement. As it rises through thresholds,
    the response level escalates from NORMAL -> WARN -> THROTTLE -> PAUSE -> ABORT.
    """

    def __init__(self, config: NoiseMonitorConfig | None = None) -> None:
        self.config = config or NoiseMonitorConfig()
        self._signals: list[NoiseSignal] = []
        self._response_level: str = ResponseLevel.NORMAL
        self._paused_operators: set[str] = set()

        # Sub-scores from different monitors (set externally or computed)
        self._circuit_score: float = 0.0
        self._trap_score: float = 0.0
        self._rate_score: float = 0.0
        self._session_score: float = 0.0

    def record_signal(
        self,
        signal_type: str,
        severity: float,
        source: str = "",
        **metadata: Any,
    ) -> None:
        """Record a detection signal."""
        signal = NoiseSignal(
            signal_type=signal_type,
            severity=min(1.0, max(0.0, severity)),
            source=source,
            metadata=metadata,
        )
        self._signals.append(signal)
        self._prune_old_signals()
        self._update_response_level()

        logger.debug(
            "opsec.signal_recorded",
            signal_type=signal_type,
            severity=severity,
            source=source,
            noise_score=self.current_noise_score(),
            response_level=self._response_level,
        )

    def current_noise_score(self) -> float:
        """Compute the current composite noise score (0.0 - 1.0)."""
        analyzer_score = self._compute_analyzer_score()

        # Ensemble: weighted combination
        score = (
            self.config.weight_analyzer * analyzer_score
            + self.config.weight_circuit * self._circuit_score
            + self.config.weight_trap * self._trap_score
            + self.config.weight_rate * self._rate_score
            + self.config.weight_session * self._session_score
        )

        return min(1.0, max(0.0, score))

    def _compute_analyzer_score(self) -> float:
        """Compute the signal analyzer sub-score from recent signals."""
        now = time.time()
        total_weight = 0.0
        weighted_severity = 0.0

        for signal in self._signals:
            age = now - signal.timestamp
            # Exponential decay
            decay = 0.5 ** (age / self.config.decay_half_life_seconds)
            weight = decay
            total_weight += weight
            weighted_severity += signal.severity * weight

        if total_weight == 0.0:
            return 0.0

        # Normalize: average weighted severity, scaled by signal density
        avg_severity = weighted_severity / total_weight
        # Density factor: more signals in the window = higher score
        density = min(1.0, len(self._signals) / 20.0)

        return min(1.0, avg_severity * (0.5 + 0.5 * density))

    def update_sub_scores(
        self,
        *,
        circuit: float | None = None,
        trap: float | None = None,
        rate: float | None = None,
        session: float | None = None,
    ) -> None:
        """Update sub-scores from external monitors."""
        if circuit is not None:
            self._circuit_score = min(1.0, max(0.0, circuit))
        if trap is not None:
            self._trap_score = min(1.0, max(0.0, trap))
        if rate is not None:
            self._rate_score = min(1.0, max(0.0, rate))
        if session is not None:
            self._session_score = min(1.0, max(0.0, session))

        self._update_response_level()

    @property
    def response_level(self) -> str:
        """Current OPSEC response level."""
        return self._response_level

    def should_pause(self) -> bool:
        """Whether operations should be paused."""
        return self._response_level in (ResponseLevel.PAUSE, ResponseLevel.ABORT)

    def should_throttle(self) -> bool:
        """Whether operations should be throttled."""
        return self._response_level in (
            ResponseLevel.THROTTLE,
            ResponseLevel.PAUSE,
            ResponseLevel.ABORT,
        )

    def should_abort(self) -> bool:
        """Whether the engagement should be aborted."""
        return self._response_level == ResponseLevel.ABORT

    def pause_operator(self, operator_name: str) -> None:
        """Pause a specific operator until noise decays."""
        self._paused_operators.add(operator_name)
        logger.warning("opsec.operator_paused", operator=operator_name)

    def resume_operator(self, operator_name: str) -> None:
        """Resume a paused operator."""
        self._paused_operators.discard(operator_name)
        logger.info("opsec.operator_resumed", operator=operator_name)

    def is_operator_paused(self, operator_name: str) -> bool:
        """Check if an operator is paused."""
        return operator_name in self._paused_operators

    def get_throttle_delay_ms(self) -> int:
        """Get the current throttle delay in milliseconds."""
        if not self.should_throttle():
            return 0

        import random

        base = self.config.throttle_delay_ms
        jitter = random.randint(0, self.config.throttle_jitter_ms)
        return base + jitter

    def get_status(self) -> dict[str, Any]:
        """Get current noise monitor status."""
        return {
            "noise_score": round(self.current_noise_score(), 3),
            "response_level": self._response_level,
            "signal_count": len(self._signals),
            "paused_operators": sorted(self._paused_operators),
            "sub_scores": {
                "analyzer": round(self._compute_analyzer_score(), 3),
                "circuit": round(self._circuit_score, 3),
                "trap": round(self._trap_score, 3),
                "rate": round(self._rate_score, 3),
                "session": round(self._session_score, 3),
            },
            "thresholds": {
                "warn": self.config.warn_threshold,
                "throttle": self.config.throttle_threshold,
                "pause": self.config.pause_threshold,
                "abort": self.config.abort_threshold,
            },
        }

    def reset(self) -> None:
        """Reset all noise state."""
        self._signals.clear()
        self._response_level = ResponseLevel.NORMAL
        self._paused_operators.clear()
        self._circuit_score = 0.0
        self._trap_score = 0.0
        self._rate_score = 0.0
        self._session_score = 0.0

    def _update_response_level(self) -> None:
        """Update the response level based on current noise score."""
        score = self.current_noise_score()
        previous = self._response_level

        if score >= self.config.abort_threshold:
            self._response_level = ResponseLevel.ABORT
        elif score >= self.config.pause_threshold:
            self._response_level = ResponseLevel.PAUSE
        elif score >= self.config.throttle_threshold:
            self._response_level = ResponseLevel.THROTTLE
        elif score >= self.config.warn_threshold:
            self._response_level = ResponseLevel.WARN
        else:
            self._response_level = ResponseLevel.NORMAL

        if self._response_level != previous:
            logger.warning(
                "opsec.level_changed",
                previous=previous,
                current=self._response_level,
                noise_score=round(score, 3),
            )

    def _prune_old_signals(self) -> None:
        """Remove signals outside the monitoring window."""
        cutoff = time.time() - self.config.window_seconds
        self._signals = [s for s in self._signals if s.timestamp > cutoff]
