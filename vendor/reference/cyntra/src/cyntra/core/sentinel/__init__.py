"""
Sentinel Protocol - Background agents for system health.

Periodic background agents that maintain system health:
- BeadGardener: Update bead descriptions, resolve deps, detect orphans
- DocSync: Keep CLAUDE.md and API docs in sync with code
- SecuritySentinel: Scan for vulnerabilities, secrets, insecure patterns
- MemoryGardener: Prune stale memories, consolidate observations
- ShieldIngest: Poll external shields for alerts
"""

from cyntra.core.sentinel.base import (
    BaseSentinel,
    SentinelChange,
    SentinelConfig,
    SentinelMaxChangesError,
    SentinelMetrics,
    SentinelRunResult,
    SentinelSchedule,
    SentinelState,
)
from cyntra.core.sentinel.manager import (
    SentinelScheduler,
    create_sentinel_scheduler_from_config,
)
from cyntra.core.sentinel.bead_gardener import (
    BeadGardenerConfig,
    BeadGardenerSentinel,
)
from cyntra.core.sentinel.doc_sync import (
    DocSyncConfig,
    DocSyncSentinel,
)
from cyntra.core.sentinel.security import (
    SecurityConfig,
    SecuritySentinel,
)
from cyntra.core.sentinel.shield_ingest import (
    ShieldIngestConfig,
    ShieldIngestContext,
    ShieldIngestSentinel,
)
from cyntra.core.sentinel.memory_gardener import (
    MemoryGardenerSentinel,
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
    # Bead Gardener
    "BeadGardenerConfig",
    "BeadGardenerSentinel",
    # Doc Sync
    "DocSyncConfig",
    "DocSyncSentinel",
    # Security
    "SecurityConfig",
    "SecuritySentinel",
    # Shield Ingest
    "ShieldIngestConfig",
    "ShieldIngestContext",
    "ShieldIngestSentinel",
    # Memory Gardener
    "MemoryGardenerSentinel",
]
