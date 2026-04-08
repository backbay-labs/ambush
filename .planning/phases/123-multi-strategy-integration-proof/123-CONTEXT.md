# Phase 123: Multi-Strategy Integration Proof - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

End-to-end integration tests proving: NetworkConnect detection produces CommandAndControl deposits, and a multi-stage attack across 3+ strategies triggers escalation via cross-strategy distinct sources. Close the milestone.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion — pure integration test phase. Requirements define:
- NETWORK-04: NetworkConnectDetector sets findings to ThreatClass::CommandAndControl; integration test proves NetworkConnect telemetry through detection to signed pheromone deposit
- NETWORK-05: Cross-strategy test with CompositeDetector (3+ strategies), multi-stage attack, asserts distinct_sources >= 3 and escalation triggers

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- Existing integration tests in crates/swarm-runtime/tests/ (persistence_supply_chain_integration.rs, multi_agent_pipeline_integration.rs, escalation_integration.rs)
- InMemoryPheromoneSubstrate for test substrates
- detect_and_deposit() for running detection pipeline
- ConcentrationMonitor::evaluate_all() for escalation checking
- findings_to_deposits() for converting findings to deposits

### Integration Points
- New integration test file(s) in crates/swarm-runtime/tests/
- Depends on CompositeDetector (Phase 120), NetworkConnectDetector (Phase 121), cross-strategy deposits (Phase 122)

</code_context>

<specifics>
## Specific Ideas

The multi-stage attack sequence should use: suspicious scripting (ProcessStart), network C2 (NetworkConnect), and credential access (AuthenticationEvent) — three different payload types hitting three different strategies on the same host.

</specifics>

<deferred>
## Deferred Ideas

None — both requirements are in scope. Milestone verification closes v1.38.

</deferred>
