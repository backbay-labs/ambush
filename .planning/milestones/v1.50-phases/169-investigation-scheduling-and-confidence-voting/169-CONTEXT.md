# Phase 169: Investigation Scheduling And Confidence Voting - Context

**Gathered:** 2026-04-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 169 upgrades the async investigation lane from simple queueing into bounded priority scheduling with explicit handling for ambiguous interpretations. It remains an async-lane change and does not widen live-response autonomy.

</domain>

<decisions>
## Implementation Decisions

- Reuse the shipped investigation coordinator rather than introducing a second scheduler.
- Make scheduling and vote lineage durable so later operator surfaces and assurance work can read the same state.
- Keep queue budgets explicit and fail visible rather than hiding starvation or dropped work behind implicit behavior.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/investigation.rs` and `crates/swarm-runtime/src/service.rs` already own the investigation coordinator, queue snapshot, and runtime review status.
- `crates/swarm-runtime/src/stalker_agent.rs` already submits async investigation work from live leads and is the natural insertion point for richer priority metadata.
- `crates/swarm-spine/src/investigation.rs` already persists bundle state and can carry vote lineage or queued-priority metadata if the current runtime needs durable storage.

</code_context>

<deferred>
## Deferred Ideas

- Multi-graph incident stitching belongs to Phase 168.
- Host, identity, and peer-group baseline depth belongs to Phase 170.
- Public operator status surfaces and milestone-level integration proof belong to Phase 171.

</deferred>
