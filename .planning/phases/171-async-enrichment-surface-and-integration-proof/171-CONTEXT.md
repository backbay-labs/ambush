# Phase 171: Async Enrichment Surface And Integration Proof - Context

**Gathered:** 2026-04-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 171 makes the async lane operator-visible and proves the bounded detect → investigate → correlate → operator-review flow after the deeper correlation, scheduling, and behavioral work from phases 168 through 170 lands.

</domain>

<decisions>
## Implementation Decisions

- Reuse the shipped control, service, ingest, and runtime-event surfaces instead of inventing a parallel review path.
- Surface backlog, pressure, vote state, and correlation outcomes through the same runtime status philosophy already used elsewhere in the system.
- End the milestone with one integration proof that exercises the bounded async lane without expanding live action authority.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/service.rs`, `crates/swarm-runtime/src/control.rs`, and `crates/swarm-runtime/src/ingest.rs` already expose runtime review and operator-visible surfaces that can be extended with async status.
- `crates/swarm-runtime/src/runtime_events.rs` already carries typed SSE status families and can host async-lane status events.
- `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs` and `crates/swarm-runtime/tests/critical_path_integration.rs` already prove bounded end-to-end paths and are the right place for the milestone closeout proof.

</code_context>

<deferred>
## Deferred Ideas

- Assurance-gated rollout decisions belong to `v1.51`.
- Providence reconciliation and rehearsal handoff belong to `v1.52`.
- Production packaging and multi-operator access remain out of scope until `v1.53`.

</deferred>
