# Phase 149: Providence Contract And Service Auth - Context

**Gathered:** 2026-04-09
**Status:** Completed

<domain>
## Phase Boundary

Phase 149 establishes the Providence-native contract and service-auth seam without taking on lifecycle synchronization, analyst feedback ingestion, or widget rendering yet.

</domain>

<decisions>
## Implementation Decisions

- Keep the existing `providence_webhook` notification lane for this phase instead of introducing the full incident adapter early.
- Add generic notification-channel request signing rather than Providence-only transport code so later integrations can reuse the same HMAC path.
- Put the shared Providence contract in `swarm-core::types` so outbound delivery and later inbound feedback handling can share one schema boundary.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/ingest.rs` already built a Providence-shaped payload, but only as ad hoc JSON with no shared typed contract.
- `crates/swarm-response/src/notification.rs` already owned bearer-authenticated outbound delivery, dedupe, rate limiting, and dead-letter handling.
- `crates/swarm-runtime/src/config.rs` already resolved `@secret:` references for notification channels, which is the correct seam for Providence bearer and HMAC secrets.

</code_context>

<deferred>
## Deferred Ideas

- Full create / update / resolve incident lifecycle remains explicit Phase 150 work.
- Providence feedback ingestion and signed audit persistence remain Phase 151 work.
- Embeddable dashboard and context-token work remain Phase 152 work.

</deferred>
