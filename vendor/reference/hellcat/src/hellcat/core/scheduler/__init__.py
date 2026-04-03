"""Task scheduling and prioritization.

Computes ready set, critical path, lane packing.

Note: To avoid circular imports, import directly from submodules:
    from hellcat.core.scheduler.scheduler import Scheduler
    from hellcat.core.scheduler.routing import KernelConfig
"""

# Lazy imports to avoid circular dependencies
def __getattr__(name: str):
    """Lazy import to avoid circular dependencies."""
    if name in _SCHEDULER_EXPORTS:
        from hellcat.core.scheduler import scheduler
        return getattr(scheduler, name)
    if name in _ROUTING_EXPORTS:
        from hellcat.core.scheduler import routing
        return getattr(routing, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


_SCHEDULER_EXPORTS = {
    "Scheduler",
    "SchedulePlan",
    "IssuePlan",
    "SchedulingSignals",
    "SchedulingSignalsBuilder",
    "PriorityAdjustment",
}

_ROUTING_EXPORTS = {
    "KernelConfig",
    "ToolchainConfig",
    "GatesConfig",
    "SpeculationConfig",
    "ControlConfig",
    "PlannerConfig",
    "SentinelScheduleConfig",
    "SentinelsConfig",
    "RoutingConfig",
    "RoutingRule",
    "StrategyConfig",
    "StrategyRoutingConfig",
    "GpuPoolConfig",
    "GpuPoolPoolConfig",
    "GpuPoolBackendConfig",
    "OracleConfig",
    "SettlementConfig",
    "OrcaConfig",
    "TreasuryConfig",
    "CCIPConfig",
    "FederationConfig",
    "CodeReviewerHookConfig",
    "DebugSpecialistHookConfig",
    "PostExecutionHooksConfig",
}

__all__ = list(_SCHEDULER_EXPORTS | _ROUTING_EXPORTS)
