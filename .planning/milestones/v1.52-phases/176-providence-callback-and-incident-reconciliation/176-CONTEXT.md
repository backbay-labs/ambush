# Phase 176: Providence Callback And Incident Reconciliation - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 176 adds the inbound Providence reconciliation seam: authenticated callback intake, durable remote-vs-local incident status comparison, and explicit mismatch state that operators can inspect without widening into full Providence workflow orchestration.

</domain>

<decisions>
## Implementation Decisions

### Callback Contract
- Reuse the existing `providence_webhook` HMAC signing configuration and add a dedicated inbound `/v1/providence/callback` endpoint instead of introducing a second Providence auth path.
- Match callbacks primarily by durable Providence external reference and secondarily by the existing `incident_key` contract so reconciliation can recover across restart and partial rollout.
- Keep the callback payload narrow to incident lifecycle reconciliation only: remote incident identity, status, severity, timestamps, and optional operator notes.

### Reconciliation Persistence
- Persist reconciliation state directly on the durable incident artifact in `swarm-spine` rather than creating a separate Providence-only store.
- Store both a latest reconciliation snapshot and an append-only callback audit trail so operators can see current drift plus the callback that produced it.
- Treat remote-vs-local lifecycle disagreement as explicit review-required state, not a transient log line.

### Drift Handling And Surfacing
- When Providence and Swarm disagree, record which side is ahead and preserve the mismatch for review instead of silently forcing the remote state back on the next sync tick.
- Surface the persisted reconciliation summary through the existing incident API/read path so the operator review lane can consume it without a new console.
- Keep automatic side effects bounded to external-reference refresh and adapter-state refresh; broader review UX remains Phase 179.

### Claude's Discretion
Use the smallest type additions and API changes needed to make reconciliation durable and queryable without reworking the wider incident lifecycle model.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-runtime/src/providence.rs` already owns the outbound Providence adapter, the stable `incident_key`, and scoped Providence link helpers.
- `crates/swarm-runtime/src/ingest/providence_handlers.rs` already provides signed inbound-request verification and incident-store lookup patterns through the feedback endpoint.
- `crates/swarm-spine/src/incident.rs` already persists external references and feedback audit entries on `CorrelatedIncident`, which is the right durability seam for reconciliation state.

### Established Patterns
- Providence inbound auth already uses canonical JSON plus `X-Swarm-Signature` HMAC verification sourced from `notification_channels.providence_webhook.request_signature`.
- Incident-related audit state is stored on the incident artifact itself and mirrored onto `IncidentRecord` for light-weight listing surfaces.
- `/v2/api/incidents` is the existing machine-readable operator surface for incident summaries and is the least disruptive place to expose reconciliation state.

### Integration Points
- `crates/swarm-runtime/src/ingest/mod.rs` owns route registration and runtime state wiring for Providence handlers.
- `crates/swarm-runtime/src/providence.rs` owns adapter sync behavior and is the correct place to gate outbound updates when reconciliation drift needs review.
- `crates/swarm-runtime/src/ingest/tests.rs` and `crates/swarm-runtime/src/providence.rs` already contain Providence-focused tests that can be extended for callback reconciliation.

</code_context>

<specifics>
## Specific Ideas

Prefer an outcome model that answers: in sync, Swarm ahead, Providence ahead, or mismatched, with a short human-readable reason and a `needs_review` flag.

</specifics>

<deferred>
## Deferred Ideas

- Full Providence-owned workflow orchestration and richer bidirectional sync remain out of scope.
- Analyst disposition memory feedback remains Phase 177.
- Local review UI and Providence-facing handoff presentation remain Phase 179.

</deferred>
