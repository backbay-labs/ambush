# Phase 4: Audit And Hardening - Context

**Gathered:** 2026-04-02
**Status:** Ready for planning

<domain>
## Phase Boundary

Make the critical lane observable, replayable, and end-to-end testable with an auditable receipt trail.

</domain>

<decisions>
## Implementation Decisions

### Audit Trail
- Record detection, policy, and response steps in one replayable bundle.
- Keep replay file-backed for v1 rather than introducing JetStream.
- Prefer typed audit records over free-form logging for replay.

### Hardening
- Add structured tracing across the critical path.
- Use end-to-end integration tests as the final gate for the v1 slice.
- Verification artifacts should map directly back to the phase requirements.

### Claude's Discretion
Exact file format for replay bundles is flexible as long as it is typed, serialized, and test-covered.

</decisions>

<specifics>
## Specific Ideas

This phase should leave the project with a believable operator story: inspect, replay, and trust the same critical path that the runtime executes.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Product Direction
- `.planning/ROADMAP.md` - Phase 4 goal and success criteria.
- `.planning/REQUIREMENTS.md` - Audit and operations requirement IDs.
- `docs/ARCHITECTURE.md` - Receipt and replay expectations for the critical lane.

### Existing Code
- `crates/swarm-runtime/src/lib.rs` - Runtime entrypoint to extend with audit hooks.
- `crates/swarm-runtime/src/service.rs` - Good place for replay helpers or orchestration glue.
- `crates/swarm-response/src/lib.rs` - Response receipt contract that should feed the audit trail.
- `crates/swarm-spine/src/lib.rs` - Reserved home for receipt-chain concepts if a shared type crate is needed.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `swarm-runtime` already centralizes authorization and execution.
- `swarm-response` already exposes a receipt struct suitable for embedding in a larger trail.

### Established Patterns
- The codebase uses typed serde models that are easy to serialize for replay.
- Unit tests are already colocated with implementation and rely on small synthetic fixtures.

### Integration Points
- The runtime should become the single point that emits detection, policy, and response records.
- Replay support should consume the same serialized types the runtime produces.

</code_context>

<deferred>
## Deferred Ideas

Persistent NATS or Merkle checkpoint durability is deferred until after file-backed replay works.

</deferred>

---
*Phase: 04-audit-and-hardening*
*Context gathered: 2026-04-02*
