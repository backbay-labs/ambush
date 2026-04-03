"""Core orchestration engine.

The heart of Hellcat: plans attacks via TargetGraph, dispatches operators
to StrikeCells, verifies proof artifacts.

Sub-packages:
    scheduler/      Task scheduling and prioritization
    dispatcher/     Operator spawning and management
    verifier/       Quality gate validation
    runner/         Main execution loop
    state/          State integration
    workcell/       Git worktree management
    adapters/       LLM toolchain and operator adapters
    gates/          Quality check definitions
    sentinel/       Background agents
    control/        Control flow utilities
    manifests/      Manifest schemas
    providers/      LLM provider abstractions
    topology/       Multi-agent topology planning and execution

Note: To avoid circular imports, import directly from submodules:
    from hellcat.core.scheduler.scheduler import Scheduler
    from hellcat.core.scheduler.routing import KernelConfig
    from hellcat.core.dispatcher.dispatcher import Dispatcher
"""

# Lazy imports to avoid circular dependencies
_LAZY_IMPORTS = {
    # Scheduler
    "Scheduler": "hellcat.core.scheduler.scheduler",
    "SchedulePlan": "hellcat.core.scheduler.scheduler",
    "KernelConfig": "hellcat.core.scheduler.routing",
    # Dispatcher
    "Dispatcher": "hellcat.core.dispatcher.dispatcher",
    "DispatchResult": "hellcat.core.dispatcher.dispatcher",
    # Verifier
    "Verifier": "hellcat.core.verifier.verifier",
    "VerificationResult": "hellcat.core.verifier.verifier",
    # Runner
    "KernelRunner": "hellcat.core.runner.runner",
    # Sentinel
    "BaseSentinel": "hellcat.core.sentinel.base",
    "SentinelConfig": "hellcat.core.sentinel.base",
    "SentinelSchedule": "hellcat.core.sentinel.base",
    "SentinelScheduler": "hellcat.core.sentinel.manager",
    "SecurityConfig": "hellcat.core.sentinel.security",
    "SecuritySentinel": "hellcat.core.sentinel.security",
    "ShieldIngestConfig": "hellcat.core.sentinel.shield_ingest",
    "ShieldIngestSentinel": "hellcat.core.sentinel.shield_ingest",
    "create_sentinel_scheduler_from_config": "hellcat.core.sentinel.manager",
    # Topology
    "TaskTopology": "hellcat.core.topology.schema",
    "TopologyPhase": "hellcat.core.topology.schema",
    "AgentSpec": "hellcat.core.topology.schema",
    "TopologyPlanner": "hellcat.core.topology.planner",
    "PlanningContext": "hellcat.core.topology.planner",
    "PhasedOrchestrator": "hellcat.core.topology.orchestrator",
    "TopologyIntegration": "hellcat.core.topology.integration",
}


def __getattr__(name: str):
    """Lazy import to avoid circular dependencies."""
    if name in _LAZY_IMPORTS:
        import importlib
        module = importlib.import_module(_LAZY_IMPORTS[name])
        return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = list(_LAZY_IMPORTS.keys())
