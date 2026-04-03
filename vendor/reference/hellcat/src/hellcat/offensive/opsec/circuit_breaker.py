"""
OPSEC circuit breaker for Hellcat engagements.

Evolves the kernel's Ralph-style circuit breaker into a security-aware
OPSEC state machine::

  COVERT -> DETECTED -> DARK -> PROBE -> COVERT
                     -> COMPROMISED (terminal)

This controls the engagement's operational posture based on detection
signals from the noise monitor.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()


class OpsecState(str, enum.Enum):
    """OPSEC operational states."""

    COVERT = "covert"          # Normal operation, no detection signals
    DETECTED = "detected"      # Detection signals received, reducing footprint
    DARK = "dark"              # Gone silent, waiting for detection to decay
    PROBE = "probe"            # Cautiously resuming after dark period
    COMPROMISED = "compromised"  # Terminal: OPSEC fully blown, engagement halted


# Valid state transitions
OPSEC_TRANSITIONS: dict[OpsecState, set[OpsecState]] = {
    OpsecState.COVERT: {OpsecState.DETECTED},
    OpsecState.DETECTED: {OpsecState.DARK, OpsecState.COMPROMISED},
    OpsecState.DARK: {OpsecState.PROBE},
    OpsecState.PROBE: {OpsecState.COVERT, OpsecState.DETECTED},
    OpsecState.COMPROMISED: set(),  # terminal
}


@dataclass
class OpsecCircuitConfig:
    """Configuration for the OPSEC circuit breaker."""

    # Thresholds for state transitions (noise score 0.0 - 1.0)
    detected_threshold: float = 0.4
    dark_threshold: float = 0.65
    compromised_threshold: float = 0.9

    # Dark period: how long to stay silent before probing
    dark_period_seconds: float = 300.0  # 5 minutes

    # Probe: how many successful low-noise probes to return to COVERT
    probe_success_threshold: int = 3

    # Decay: noise must drop below this to leave DETECTED for DARK->PROBE->COVERT
    covert_recovery_threshold: float = 0.2

    # Auto-recovery: transition from DARK->PROBE after dark_period elapses
    auto_probe: bool = True


@dataclass
class OpsecEvent:
    """Record of an OPSEC state transition."""

    timestamp: float
    from_state: OpsecState
    to_state: OpsecState
    reason: str
    noise_score: float


class OpsecCircuitBreaker:
    """
    Security-aware circuit breaker for engagement OPSEC.

    Unlike the kernel's generic circuit breaker (which detects stagnation),
    this one specifically tracks whether the target's defenses have detected
    our activity and manages the operational response.

    State machine:
      COVERT: Normal scanning/exploitation. No detection signals.
      DETECTED: Defense signals received. Reduce scan rate, add jitter.
      DARK: Gone silent. No active scanning. Wait for signals to decay.
      PROBE: Cautiously resume with minimal activity to test detection state.
      COMPROMISED: OPSEC is fully blown. Halt the engagement.
    """

    def __init__(self, config: OpsecCircuitConfig | None = None) -> None:
        self.config = config or OpsecCircuitConfig()
        self.state = OpsecState.COVERT
        self._entered_state_at: float = time.time()
        self._probe_successes: int = 0
        self._history: list[OpsecEvent] = []

    def evaluate(self, noise_score: float) -> OpsecState:
        """
        Evaluate the OPSEC state based on the current noise score.

        Returns the (possibly new) state. Transitions happen automatically
        based on thresholds.
        """

        if self.state == OpsecState.COVERT:
            if noise_score >= self.config.detected_threshold:
                self._transition(OpsecState.DETECTED, "noise_detected", noise_score)

        elif self.state == OpsecState.DETECTED:
            if noise_score >= self.config.compromised_threshold:
                self._transition(OpsecState.COMPROMISED, "opsec_compromised", noise_score)
            elif noise_score >= self.config.dark_threshold:
                self._transition(OpsecState.DARK, "going_dark", noise_score)
            elif noise_score < self.config.covert_recovery_threshold:
                # Signals decayed quickly, can return to covert
                self._transition(OpsecState.COVERT, "signals_decayed", noise_score)

        elif self.state == OpsecState.DARK:
            if self.config.auto_probe and self._dark_period_elapsed():
                self._transition(OpsecState.PROBE, "dark_period_elapsed", noise_score)

        elif self.state == OpsecState.PROBE:
            if noise_score >= self.config.detected_threshold:
                # Still detected during probe, go back to DETECTED
                self._transition(OpsecState.DETECTED, "probe_detected", noise_score)
                self._probe_successes = 0
            elif noise_score < self.config.covert_recovery_threshold:
                self._probe_successes += 1
                if self._probe_successes >= self.config.probe_success_threshold:
                    self._transition(OpsecState.COVERT, "probe_recovery_confirmed", noise_score)
                    self._probe_successes = 0

        # COMPROMISED is terminal, no transitions out

        return self.state

    def record_probe_success(self) -> None:
        """Record a successful probe action (low noise response)."""
        if self.state == OpsecState.PROBE:
            self._probe_successes += 1
            logger.debug(
                "opsec.probe_success",
                count=self._probe_successes,
                threshold=self.config.probe_success_threshold,
            )

    def allows_active_scanning(self) -> bool:
        """Whether active scanning is permitted in the current state."""
        return self.state in (OpsecState.COVERT, OpsecState.DETECTED, OpsecState.PROBE)

    def allows_exploitation(self) -> bool:
        """Whether exploitation attempts are permitted."""
        return self.state in (OpsecState.COVERT, OpsecState.PROBE)

    def is_compromised(self) -> bool:
        """Whether OPSEC is fully compromised (terminal)."""
        return self.state == OpsecState.COMPROMISED

    def force_dark(self, reason: str = "manual") -> None:
        """Manually force the circuit into DARK state."""
        if self.state != OpsecState.COMPROMISED:
            self._transition(OpsecState.DARK, f"forced_dark:{reason}", 0.0)

    def reset(self) -> None:
        """Reset to COVERT state (e.g., for a new engagement)."""
        self.state = OpsecState.COVERT
        self._entered_state_at = time.time()
        self._probe_successes = 0
        self._history.clear()

    def get_status(self) -> dict[str, Any]:
        """Get current OPSEC circuit breaker status."""
        time_in_state = time.time() - self._entered_state_at

        status: dict[str, Any] = {
            "state": self.state.value,
            "time_in_state_seconds": round(time_in_state, 1),
            "allows_active_scanning": self.allows_active_scanning(),
            "allows_exploitation": self.allows_exploitation(),
        }

        if self.state == OpsecState.DARK:
            remaining = self.config.dark_period_seconds - time_in_state
            status["dark_remaining_seconds"] = round(max(0, remaining), 1)

        if self.state == OpsecState.PROBE:
            status["probe_successes"] = self._probe_successes
            status["probe_threshold"] = self.config.probe_success_threshold

        status["recent_history"] = [
            {
                "from": e.from_state.value,
                "to": e.to_state.value,
                "reason": e.reason,
                "noise_score": round(e.noise_score, 3),
            }
            for e in self._history[-5:]
        ]

        return status

    def _transition(
        self,
        new_state: OpsecState,
        reason: str,
        noise_score: float,
    ) -> None:
        """Transition to a new OPSEC state."""
        # Validate transition
        allowed = OPSEC_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            logger.warning(
                "opsec.invalid_transition",
                from_state=self.state.value,
                to_state=new_state.value,
                reason=reason,
            )
            return

        event = OpsecEvent(
            timestamp=time.time(),
            from_state=self.state,
            to_state=new_state,
            reason=reason,
            noise_score=noise_score,
        )
        self._history.append(event)

        if len(self._history) > 100:
            self._history = self._history[-100:]

        logger.warning(
            "opsec.state_transition",
            from_state=self.state.value,
            to_state=new_state.value,
            reason=reason,
            noise_score=round(noise_score, 3),
        )

        self.state = new_state
        self._entered_state_at = time.time()

    def _dark_period_elapsed(self) -> bool:
        """Check if the dark period has elapsed."""
        return (time.time() - self._entered_state_at) >= self.config.dark_period_seconds
