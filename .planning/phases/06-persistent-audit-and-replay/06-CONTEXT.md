# Phase 6: Persistent Audit And Replay - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Persist replay bundles and receipt correlations so operators can load and inspect prior decisions after restart without re-executing actions.

</domain>

<decisions>
## Implementation Decisions

### Store Shape
- Use a store abstraction that supports memory and local-file backends.
- Persist replay bundles as structured JSON plus an index keyed by bundle, hunt, trail, and receipt identifiers.
- Keep replay inspection side-effect free.

### Correlation
- Carry upstream receipt-chain IDs into the audit trail.
- Expose stable bundle, hunt, trail, and receipt identifiers through the persisted record.
- Keep replay previews descriptive rather than imperative.

### Claude's Discretion
Exact index-file shape is flexible as long as load-by-hunt and load-by-receipt are restart-safe and test-covered.

</decisions>

<specifics>
## Specific Ideas

Persisting one JSON file per bundle plus a compact index is sufficient for this milestone and easy to inspect manually.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `crates/swarm-spine/src/lib.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/src/service.rs`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ReplayBundle` already captures the event, findings, deposits, action request, and audit trail.
- `RuntimeService` already knows how to serialize and load bundles from ad hoc paths.

### Established Patterns
- Persistence stays JSON-first and repository-owned.
- Runtime logs already carry hunt and action identifiers.

### Integration Points
- `swarm-spine` should own bundle persistence and lookup.
- `swarm-runtime` should delegate to the store rather than invent another persistence path.

</code_context>

<deferred>
## Deferred Ideas

- Signature envelopes and Merkle proofs
- Remote multi-node receipt replication

</deferred>

---
*Phase: 06-persistent-audit-and-replay*
*Context gathered: 2026-04-03*
