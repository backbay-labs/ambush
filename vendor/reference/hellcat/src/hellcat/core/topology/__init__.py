"""
Topology module - Task to agent swarm mapping.

This module provides primitives for defining and executing multi-agent
topologies from task descriptions.
"""

from hellcat.core.topology.schema import (
    AgentSpec,
    ModelTier,
    ParallelismConfig,
    PhaseOutput,
    SynthesisMode,
    TaskTopology,
    TopologyConstraints,
    TopologyMetadata,
    TopologyPhase,
    TopologyResult,
)
from hellcat.core.topology.templates import (
    TopologyTemplate,
    TopologyTrigger,
    load_all_templates,
    load_template,
)

__all__ = [
    # Schema
    "AgentSpec",
    "ModelTier",
    "ParallelismConfig",
    "PhaseOutput",
    "SynthesisMode",
    "TaskTopology",
    "TopologyConstraints",
    "TopologyMetadata",
    "TopologyPhase",
    "TopologyResult",
    # Templates
    "TopologyTemplate",
    "TopologyTrigger",
    "load_all_templates",
    "load_template",
    # Planner
    "PlanningContext",
    "TopologyPlanner",
    "TopologyAdjustments",
    # Orchestrator
    "PhasedOrchestrator",
    "OrchestratorConfig",
    # Cycle Orchestration
    "CycleContext",
    "CyclePolicy",
    "CycleDecision",
    "PolicySignals",
    "PolicyAction",
    "AttemptSummary",
    "HeuristicCyclePolicy",
    "CycleOrchestrator",
    "CycleOrchestratorConfig",
    "CycleExecutionResult",
    # Integration
    "TopologyConfig",
    "TopologyIntegration",
    "create_topology_integration",
    # Claude Compiler
    "ClaudeCompiler",
    "ClaudeSkillSpec",
    "ClaudeTaskSpec",
    "ClaudePhaseSpec",
    "ClaudeOrchestrationPlan",
    "compile_topologies_to_skills",
]

# Lazy imports for planner, orchestrator, cycle, integration, and compiler
def __getattr__(name: str):
    if name in ("PlanningContext", "TopologyPlanner", "TopologyAdjustments"):
        from hellcat.core.topology.planner import (
            PlanningContext,
            TopologyAdjustments,
            TopologyPlanner,
        )
        return {"PlanningContext": PlanningContext, "TopologyPlanner": TopologyPlanner, "TopologyAdjustments": TopologyAdjustments}[name]
    elif name in ("PhasedOrchestrator", "OrchestratorConfig"):
        from hellcat.core.topology.orchestrator import OrchestratorConfig, PhasedOrchestrator
        return PhasedOrchestrator if name == "PhasedOrchestrator" else OrchestratorConfig
    elif name in ("CycleContext", "CyclePolicy", "CycleDecision", "PolicySignals", "PolicyAction", "AttemptSummary", "HeuristicCyclePolicy"):
        from hellcat.core.topology.cycle import (
            AttemptSummary,
            CycleContext,
            CycleDecision,
            CyclePolicy,
            HeuristicCyclePolicy,
            PolicyAction,
            PolicySignals,
        )
        return {
            "CycleContext": CycleContext,
            "CyclePolicy": CyclePolicy,
            "CycleDecision": CycleDecision,
            "PolicySignals": PolicySignals,
            "PolicyAction": PolicyAction,
            "AttemptSummary": AttemptSummary,
            "HeuristicCyclePolicy": HeuristicCyclePolicy,
        }[name]
    elif name in ("CycleOrchestrator", "CycleOrchestratorConfig", "CycleExecutionResult"):
        from hellcat.core.topology.cycle_orchestrator import (
            CycleExecutionResult,
            CycleOrchestrator,
            CycleOrchestratorConfig,
        )
        return {
            "CycleOrchestrator": CycleOrchestrator,
            "CycleOrchestratorConfig": CycleOrchestratorConfig,
            "CycleExecutionResult": CycleExecutionResult,
        }[name]
    elif name in ("TopologyConfig", "TopologyIntegration", "create_topology_integration"):
        from hellcat.core.topology.integration import (
            TopologyConfig,
            TopologyIntegration,
            create_topology_integration,
        )
        return {"TopologyConfig": TopologyConfig, "TopologyIntegration": TopologyIntegration, "create_topology_integration": create_topology_integration}[name]
    elif name in ("ClaudeCompiler", "ClaudeSkillSpec", "ClaudeTaskSpec", "ClaudePhaseSpec", "ClaudeOrchestrationPlan", "compile_topologies_to_skills"):
        from hellcat.core.topology.claude_compiler import (
            ClaudeCompiler,
            ClaudeOrchestrationPlan,
            ClaudePhaseSpec,
            ClaudeSkillSpec,
            ClaudeTaskSpec,
            compile_topologies_to_skills,
        )
        return {
            "ClaudeCompiler": ClaudeCompiler,
            "ClaudeSkillSpec": ClaudeSkillSpec,
            "ClaudeTaskSpec": ClaudeTaskSpec,
            "ClaudePhaseSpec": ClaudePhaseSpec,
            "ClaudeOrchestrationPlan": ClaudeOrchestrationPlan,
            "compile_topologies_to_skills": compile_topologies_to_skills,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
