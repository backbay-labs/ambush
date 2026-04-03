"""
Sentinel Protocol - Background agents for system health.

Periodic background agents that maintain system health:
- SecuritySentinel: Scan for vulnerabilities, secrets, insecure patterns
- ShieldIngest: Poll external shields for alerts
"""

from hellcat.core.sentinel.base import (
    BaseSentinel,
    SentinelChange,
    SentinelConfig,
    SentinelMaxChangesError,
    SentinelMetrics,
    SentinelRunResult,
    SentinelSchedule,
    SentinelState,
)
from hellcat.core.sentinel.manager import (
    SentinelScheduler,
    create_sentinel_scheduler_from_config,
)
from hellcat.core.sentinel.security import (
    SecurityConfig,
    SecuritySentinel,
)
from hellcat.core.sentinel.shield_ingest import (
    ShieldIngestConfig,
    ShieldIngestContext,
    ShieldIngestSentinel,
)

__all__ = [
    # Base classes
    "BaseSentinel",
    "SentinelConfig",
    "SentinelSchedule",
    "SentinelState",
    "SentinelChange",
    "SentinelRunResult",
    "SentinelMetrics",
    "SentinelMaxChangesError",
    # Scheduler
    "SentinelScheduler",
    "create_sentinel_scheduler_from_config",
    # Security
    "SecurityConfig",
    "SecuritySentinel",
    # Shield Ingest
    "ShieldIngestConfig",
    "ShieldIngestContext",
    "ShieldIngestSentinel",
]
