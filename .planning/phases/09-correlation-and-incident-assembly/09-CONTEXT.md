# Phase 9: Correlation And Incident Assembly - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Turn persisted investigation bundles into durable, reviewable incidents that explicitly record which inputs were included, which were rejected, and why.

</domain>

<decisions>
## Implementation Decisions

### Correlation Scope
- Correlate from persisted investigation bundles, not directly from the hot path.
- Keep the first correlation engine deterministic and rule-based.
- Treat incidents as operator context only; do not let correlation change live-response policy in this phase.

### Inclusion Logic
- Use stable identifiers, bounded time windows, and shared correlation keys as the inclusion rules.
- Record rejected candidates alongside included members so false merges stay visible.
- Start with a seeded incident model: build an incident around one hunt and explain every candidate against that seed.

### Persistence
- Persist incidents as a separate durable artifact family in `swarm-spine`.
- Reuse the same memory vs local-files backend pattern used for replay and investigation bundles.
- Carry summary metadata, hunt IDs, investigation IDs, receipt IDs, and shared keys in the incident record.

### Claude's Discretion
The exact summary wording and shared-key ranking are flexible as long as inclusion and rejection reasons are stable and testable.

</decisions>

<specifics>
## Specific Ideas

Phase 8 already emits correlation-friendly keys like host, user, and strategy. Phase 9 should use those directly instead of inventing a heavier graph model.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `.planning/phases/08-async-investigation-pipeline/08-01-SUMMARY.md`
- `crates/swarm-runtime/src/investigation.rs`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-spine/src/investigation.rs`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Investigation bundles already persist stable identifiers, summary text, failure state, and correlation keys.
- `RuntimeService` already exposes persisted replay-bundle loading helpers and is the accepted runtime composition seam.

### Established Patterns
- New durable artifact families belong in `swarm-spine` with configurable memory and file-backed stores.
- Async coordination logic can live beside `RuntimeService` without becoming part of the hot path.

### Integration Points
- Correlation should load candidate investigation bundles from the investigation store, not from transient queue memory.
- Incident persistence belongs beside investigation persistence in `swarm-spine`.
- Service-level helpers should assemble and persist incidents so Phase 10 can surface them from one operator report.

</code_context>

<deferred>
## Deferred Ideas

- Graph or clustering engines
- Cross-node incident assembly
- Correlation-driven automated response escalation

</deferred>

---
*Phase: 09-correlation-and-incident-assembly*
*Context gathered: 2026-04-03*
