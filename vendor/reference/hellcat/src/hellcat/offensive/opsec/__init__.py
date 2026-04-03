"""
OPSEC monitoring for Hellcat Kernel.

Tracks cumulative detection signals and manages the engagement's
noise budget through escalating response levels:
  WARN -> THROTTLE -> PAUSE -> ABORT

The noise monitor implements a security-aware OPSEC state machine.
"""

from hellcat.offensive.opsec.circuit_breaker import OpsecCircuitBreaker, OpsecState
from hellcat.offensive.opsec.noise_monitor import NoiseMonitor, NoiseSignal
from hellcat.offensive.opsec.stealth_budget import AggressionLevel, StealthBudget

__all__ = [
    "AggressionLevel",
    "NoiseMonitor",
    "NoiseSignal",
    "OpsecCircuitBreaker",
    "OpsecState",
    "StealthBudget",
]
