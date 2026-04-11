# Phase 168: Weaver Multi-Graph Correlation Foundations - Context

**Gathered:** 2026-04-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 168 deepens the shipped async correlation lane. It extends Weaver from the current graph-backed incident assembly into explicit temporal, causal, entity, and semantic traversal without widening the hot path or inventing a second correlation system.

</domain>

<decisions>
## Implementation Decisions

- Treat the existing `Whisker -> Stalker -> Weaver` path as the source of truth and evolve it in place.
- Prefer repo-owned scoring and explainability over opaque similarity scores.
- Keep correlation asynchronous and evidence-first so later scheduling and operator-surface work can build on stable artifacts.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/weaver_agent.rs` already consumes completed investigation artifacts and persists `CorrelatedIncident` records.
- `crates/swarm-runtime/src/correlation.rs` is the current correlation engine and the natural home for richer graph traversal and evidence-chain assembly.
- `crates/swarm-runtime/src/sphinx_agent.rs`, `crates/swarm-spine/src/investigation.rs`, and `crates/swarm-spine/src/incident.rs` already provide durable graph-like context, investigation bundles, and incident persistence that Phase 168 can reuse.

</code_context>

<deferred>
## Deferred Ideas

- Queue prioritization and ambiguous-lead voting belong to Phase 169.
- Host, identity, and peer-group behavioral depth belongs to Phase 170.
- New operator surfaces and milestone-level end-to-end proof belong to Phase 171.

</deferred>
