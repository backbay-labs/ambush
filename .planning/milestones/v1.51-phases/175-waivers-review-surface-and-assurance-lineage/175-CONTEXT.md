# Phase 175: Waivers, Review Surface, And Assurance Lineage - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 175 closes the assurance milestone with bounded signed waivers and operator-visible assurance lineage across the normal proof, status, and review artifacts.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing signed-operator identity model and durable review artifacts instead of adding an external waiver system.
- Keep waivers narrow: signed, reasoned, time-bounded, and attached to one concrete assurance decision.
- Surface waived gaps through the existing proof, proposal, handoff, canary, promotion, and status artifacts so operators do not need a separate assurance console.

</decisions>

<code_context>
## Existing Code Insights

- Runtime agents and operator actions already have persisted Ed25519 identity primitives and signed approval lineage that can anchor waiver records.
- `crates/swarm-evolution/src/evolution.rs` already renders proposal and handoff artifacts with blocking reasons and decision history, which is the right place to add assurance-waiver context.
- `crates/swarm-runtime/src/evolution_status.rs` already aggregates formal proof and admission state, so assurance lineage should surface there instead of a new status endpoint.

</code_context>

<deferred>
## Deferred Ideas

- Providence-facing review or rehearsal reuse belongs to `v1.52`.
- Production packaging and multi-operator deployment guidance remain out of scope until `v1.53`.

</deferred>
