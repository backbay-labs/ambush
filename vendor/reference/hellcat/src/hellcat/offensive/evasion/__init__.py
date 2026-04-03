"""
Evasion loop for Hellcat Kernel.

When a defense blocks exploitation, the evasion subsystem:
1. Classifies the failure type (WAF, rate limit, input validation, etc.)
2. Generates a bypass strategy from the AttackPatternDB
3. Dispatches a retry with evasion context

Status flow: BLOCKED -> EVASION_QUEUED -> RETRIED -> (EXPLOITED | BLOCKED | HARDENED)
"""

from hellcat.offensive.evasion.classifier import BlockReason, FailureClassifier
from hellcat.offensive.evasion.loop import EvasionLoop
from hellcat.offensive.evasion.retry import EvasionRetryManager, RetryOutcome
from hellcat.offensive.evasion.strategy import EvasionStrategy, StrategyGenerator

__all__ = [
    "BlockReason",
    "EvasionLoop",
    "EvasionRetryManager",
    "EvasionStrategy",
    "FailureClassifier",
    "RetryOutcome",
    "StrategyGenerator",
]
