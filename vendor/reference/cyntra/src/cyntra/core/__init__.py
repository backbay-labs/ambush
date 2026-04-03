"""Core orchestration engine.

The heart of Cyntra: schedules tasks from Beads, dispatches to Workcells, verifies results.

Sub-packages:
    scheduler/      Task scheduling and prioritization
    dispatcher/     Workcell spawning and management
    verifier/       Quality gate validation
    runner/         Main execution loop
    state/          Beads integration
    workcell/       Git worktree management
    adapters/       LLM toolchain adapters
    gates/          Quality check definitions
    sentinel/       Background agents
    control/        Control flow utilities
    manifests/      Manifest schemas
    providers/      LLM provider abstractions
    topology/       Multi-agent topology planning and execution

Note: To avoid circular imports, import directly from submodules:
    from cyntra.core.scheduler.scheduler import Scheduler
    from cyntra.core.scheduler.routing import KernelConfig
    from cyntra.core.dispatcher.dispatcher import Dispatcher
"""

# Lazy imports to avoid circular dependencies
_LAZY_IMPORTS = {
    # Scheduler
    "Scheduler": "cyntra.core.scheduler.scheduler",
    "SchedulePlan": "cyntra.core.scheduler.scheduler",
    "KernelConfig": "cyntra.core.scheduler.routing",
    # Dispatcher
    "Dispatcher": "cyntra.core.dispatcher.dispatcher",
    "DispatchResult": "cyntra.core.dispatcher.dispatcher",
    # Verifier
    "Verifier": "cyntra.core.verifier.verifier",
    "VerificationResult": "cyntra.core.verifier.verifier",
    # Runner
    "KernelRunner": "cyntra.core.runner.runner",
    # Sentinel
    "BaseSentinel": "cyntra.core.sentinel.sentinel",
    "SentinelConfig": "cyntra.core.sentinel.sentinel",
    "SentinelSchedule": "cyntra.core.sentinel.sentinel",
    "SentinelScheduler": "cyntra.core.sentinel.sentinel",
    "BeadGardenerConfig": "cyntra.core.sentinel.sentinel",
    "BeadGardenerSentinel": "cyntra.core.sentinel.sentinel",
    "DocSyncConfig": "cyntra.core.sentinel.sentinel",
    "DocSyncSentinel": "cyntra.core.sentinel.sentinel",
    "SecurityConfig": "cyntra.core.sentinel.sentinel",
    "SecuritySentinel": "cyntra.core.sentinel.sentinel",
    "ShieldIngestConfig": "cyntra.core.sentinel.sentinel",
    "ShieldIngestSentinel": "cyntra.core.sentinel.sentinel",
    "MemoryGardenerSentinel": "cyntra.core.sentinel.sentinel",
    "create_sentinel_scheduler_from_config": "cyntra.core.sentinel.sentinel",
    # Topology
    "TaskTopology": "cyntra.core.topology.schema",
    "TopologyPhase": "cyntra.core.topology.schema",
    "AgentSpec": "cyntra.core.topology.schema",
    "TopologyPlanner": "cyntra.core.topology.planner",
    "PlanningContext": "cyntra.core.topology.planner",
    "PhasedOrchestrator": "cyntra.core.topology.orchestrator",
    "TopologyIntegration": "cyntra.core.topology.integration",
}


def __getattr__(name: str):
    """Lazy import to avoid circular dependencies."""
    if name in _LAZY_IMPORTS:
        import importlib
        module = importlib.import_module(_LAZY_IMPORTS[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_LAZY_IMPORTS.keys())
