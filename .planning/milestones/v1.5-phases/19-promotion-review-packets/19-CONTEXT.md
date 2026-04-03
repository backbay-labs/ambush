# Phase 19: Promotion Review Packets - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Assemble a durable promotion review packet that references one candidate experiment, one verification report, and one shadow report. The packet is for manual operator review only; it does not approve or deploy anything.

</domain>

<decisions>
## Implementation Decisions

### Packet Shape
- Keep the packet thin and reference-oriented: reuse the persisted verification and shadow artifacts instead of duplicating full nested reports.
- Summarize only the operator-relevant fields: lineage, verdicts, deltas, failed references, and a recommendation flag.
- Give the packet its own stable ID and dedicated local store.

### CLI Flow
- Add explicit create and result commands rather than overloading the existing shadow or verification commands.
- Require stable verification and shadow IDs at packet-creation time so the operator chooses the evidence set intentionally.
- Keep output human-readable by default and JSON-capable like the rest of `swarmctl`.

### Review Semantics
- Manual approval remains outside scope; the packet only says whether the evidence is ready for review or blocked.
- Blocking reasons should be derived directly from failed invariants or failed shadow gates.
- Docs should explain the end-to-end workflow from experiment -> verification -> shadow -> review packet.

</decisions>

<specifics>
## Specific Ideas

The packet should feel like a durable handoff artifact, not another execution report. Operators need to know what candidate this is, what evidence exists, whether anything failed, and exactly which verification or shadow IDs to inspect next.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/phases/18-verification-gate-and-shadow-runner/18-01-SUMMARY.md`
- `docs/EVOLUTION.md`

### Existing Code
- `crates/swarm-runtime/src/replay.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`
- `docs/CONFIGURATION.md`
- `experiments/`
- `verifications/`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Experiment, verification, and shadow artifacts already persist by stable ID with local indexes.
- Experiment lineage is already tracked in repo-owned manifests.
- Render helpers already produce operator-facing text plus JSON output through `swarmctl`.

### Established Patterns
- New artifact types get a dedicated local store under `data/`.
- CLI lookup by stable ID is the operator contract for offline artifacts.
- Failure semantics stay explicit: a packet can be blocked without preventing inspection.

### Integration Points
- Extend `crates/swarm-runtime/src/replay.rs` with the promotion review packet type, store, and loader.
- Extend `crates/swarm-runtime/src/bin/swarmctl.rs` with create and result commands.
- Update `.gitignore` and `docs/CONFIGURATION.md` for `data/promotion-reviews/`.

</code_context>

<deferred>
## Deferred Ideas

- Human approval state transitions
- Consensus or signed promotion votes
- Automatic canary or production promotion

</deferred>

---
*Phase: 19-promotion-review-packets*
*Context gathered: 2026-04-03*
