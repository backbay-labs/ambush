# Phase 170: Identity And Peer-Group Behavioral Baselines - Context

**Gathered:** 2026-04-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 170 extends the shipped behavioral-anomaly system from per-host scope into identity and peer-group scope. The phase deepens evidence and persistence semantics without changing the hot-path requirement that detection stays bounded and explainable.

</domain>

<decisions>
## Implementation Decisions

- Extend the existing `BehavioralAnomalyDetector` instead of creating a separate anomaly family.
- Keep baseline state durable and scope-aware so restart behavior remains predictable across host, identity, and peer-group learning.
- Findings must explain which scope triggered the anomaly so later correlation and operator review can distinguish local versus cross-entity drift.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-whisker/src/behavioral_anomaly.rs` already owns per-host baseline logic and is the primary implementation surface.
- `crates/swarm-runtime/src/detection/pipeline.rs` and runtime config wiring already hydrate and persist behavioral baseline snapshots.
- `crates/swarm-core/src/pheromone.rs` and `crates/swarm-pheromone` already carry durable behavioral snapshot semantics that can be extended for multiple scopes.

</code_context>

<deferred>
## Deferred Ideas

- Queue prioritization and ambiguous-vote workflow belong to Phase 169.
- New async operator surfaces and milestone-level end-to-end proof belong to Phase 171.
- Any broader adaptive policy response based on new baseline scopes remains out of scope for this milestone.

</deferred>
