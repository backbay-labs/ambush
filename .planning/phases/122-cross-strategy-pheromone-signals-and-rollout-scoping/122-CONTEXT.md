# Phase 122: Cross-Strategy Pheromone Signals And Rollout Scoping - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Make deposits from different strategies count as distinct pheromone sources for escalation, weight cross-strategy correlation higher in WeaverAgent, and scope canary/promotion to individual strategies within the composite.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion — infrastructure phase. Requirements define:
- COMPOSE-03: Deposits from different strategies use distinct agent_id incorporating strategy_id so distinct_sources counts independent strategies
- COMPOSE-04: CorrelationEngine weights cross-strategy pairs higher than same-strategy
- COMPOSE-05: CanaryConfig and PromotionConfig gain optional strategy_id for per-strategy scoping

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `PheromoneDeposit.agent_id` in swarm-core/src/pheromone.rs — currently set to the agent's AgentId
- `PheromoneConcentration.distinct_sources` counts unique agent_ids in substrate queries
- `CorrelationEngine::assemble_incident_at()` in swarm-runtime/src/correlation.rs groups by shared keys
- `CanaryConfig` and `PromotionConfig` in swarm-core/src/config.rs
- `detect_and_deposit()` in pipeline.rs creates deposits with agent_id

### Integration Points
- pipeline.rs: where deposits are created (needs strategy_id in agent_id)
- correlation.rs: where incidents are assembled (needs cross-strategy weighting)
- config.rs: CanaryConfig and PromotionConfig need optional strategy_id field
- canary.rs and promotion.rs: need to scope observation to strategy_id

</code_context>

<specifics>
## Specific Ideas

The agent_id for deposits should be formatted as `{agent_id}:{strategy_id}` to maintain agent identity while adding strategy differentiation.

</specifics>

<deferred>
## Deferred Ideas

None — all three requirements are in scope.

</deferred>
