# Phase 150: Incident Lifecycle Adapter - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 150 turns the Phase 149 contract-and-auth seam into a stateful Providence incident lifecycle: create, update, resolve, retry, dead-letter, idempotency, and surfaced health.

</domain>

<decisions>
## Implementation Decisions

- Build a dedicated `ProvidenceIncidentAdapter` instead of trying to stretch the generic notification router into incident-state ownership.
- Reuse Phase 149's `SwarmProvidenceWebhookContract`, bearer-token config, and HMAC signing semantics instead of inventing a second Providence transport shape.
- Persist Providence incident IDs alongside existing incident / escalation records rather than introducing a new top-level store.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/ingest.rs` already has the live Providence payload mapping and operator/runtime context needed for outbound incident create bodies.
- `crates/swarm-response/src/notification.rs` already provides dead-letter and canonical JSON delivery patterns, but does not own incident state transitions.
- `crates/swarm-spine` already persists incident-oriented records and is the right durability seam for Providence external references.

</code_context>

<deferred>
## Deferred Ideas

- Providence feedback ingestion remains Phase 151.
- Embeddable widget and context-token work remain Phase 152.
- Full bidirectional state reconciliation with Providence callbacks remains out of scope for v1.45.

</deferred>
