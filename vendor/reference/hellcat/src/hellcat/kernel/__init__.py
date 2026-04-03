"""
Kernel - Core orchestration components.

Modules:
    scheduler   - Computes ready set, critical path, lane packing
    dispatcher  - Spawns workcells, routes to toolchains, monitors
    verifier    - Runs quality gates, compares candidates, vote selection
    runner      - Main kernel loop
    init        - Kernel initialization
    escalation  - Escalation logic
    status      - Status display
    sentinel    - Periodic background agents for system health
"""

from hellcat.core.dispatcher import Dispatcher
from hellcat.core.scheduler import Scheduler
from hellcat.core.sentinel import (
    BaseSentinel,
    BeadGardenerConfig,
    BeadGardenerSentinel,
    DocSyncConfig,
    DocSyncSentinel,
    MemoryGardenerSentinel,
    SecurityConfig,
    SecuritySentinel,
    SentinelConfig,
    SentinelSchedule,
    SentinelScheduler,
    ShieldIngestConfig,
    ShieldIngestSentinel,
    create_sentinel_scheduler_from_config,
)
from hellcat.core.verifier import Verifier

__all__ = [
    "Scheduler",
    "Dispatcher",
    "Verifier",
    # Sentinel system
    "BaseSentinel",
    "SentinelConfig",
    "SentinelSchedule",
    "SentinelScheduler",
    "BeadGardenerConfig",
    "BeadGardenerSentinel",
    "DocSyncConfig",
    "DocSyncSentinel",
    "SecurityConfig",
    "SecuritySentinel",
    "ShieldIngestConfig",
    "ShieldIngestSentinel",
    "MemoryGardenerSentinel",
    "create_sentinel_scheduler_from_config",
]
