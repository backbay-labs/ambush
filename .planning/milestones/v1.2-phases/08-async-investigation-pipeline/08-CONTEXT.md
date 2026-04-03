# Phase 8: Async Investigation Pipeline - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Add a background investigation lane that can enqueue off persisted replay bundles, run deterministic enrichment asynchronously, and persist investigation bundles without blocking the original detect or response decision.

</domain>

<decisions>
## Implementation Decisions

### Investigation Runtime Shape
- Keep investigation as a separate asynchronous coordinator layered on top of `RuntimeService`, not a new critical-lane dependency.
- Submit investigation work from persisted replay bundles so the async lane starts from durable hot-path artifacts.
- Use immediate queue submission plus background workers; never wait for investigation completion in the event-processing path.

### Investigation Artifacts
- Persist investigation work as a first-class durable bundle type in `swarm-spine`.
- Reuse the existing memory vs local-files storage pattern for investigation bundles.
- Carry hunt, trail, receipt, and summary metadata directly in the persisted records so later correlation and operator review do not need raw bundle scans.

### Configuration And Failure Behavior
- Add a dedicated `investigation` config section for enablement, worker count, queue depth, time budget, and bundle storage backend.
- Treat timeouts and queue pressure as visible async outcomes, not hot-path failures.
- Keep the first investigation strategy deterministic and summary-oriented so the milestone stays Rust-first and testable.

### Claude's Discretion
Exact summary formatting, queue counters, and evidence field extraction can stay lightweight as long as persisted investigation bundles are stable and operator-visible.

</decisions>

<specifics>
## Specific Ideas

The smallest viable phase is a queue-backed coordinator with one default investigator that summarizes existing replay-bundle evidence into a durable investigation bundle.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`

### Existing Code
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/src/config.rs`
- `crates/swarm-spine/src/lib.rs`
- `crates/swarm-spine/src/store.rs`
- `crates/swarm-core/src/config.rs`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `RuntimeService::process_event_with_store` already emits persisted replay bundles after the critical lane completes.
- `swarm-spine` already has durable memory and local-files storage patterns that can be mirrored for investigation bundles.
- Stable hunt, trail, and receipt identifiers already flow through replay bundles and operator status.

### Established Patterns
- Repository-owned config lives in `swarm-core::config` and is validated centrally.
- Durable artifact stores use thin configurable enums plus small in-memory and file-backed implementations.
- Service-level orchestration is the accepted place to combine hot-path execution with adjacent operational workflows.

### Integration Points
- Investigation submission should hang off persisted replay bundles in `RuntimeService`.
- Investigation bundle storage belongs in `swarm-spine`, beside replay storage.
- Operator-facing queue and failure state should be shaped now so Phase 10 can surface it without redesign.

</code_context>

<deferred>
## Deferred Ideas

- LLM-backed or external investigation strategies
- Investigation-triggered policy escalation
- Multi-node worker coordination

</deferred>

---
*Phase: 08-async-investigation-pipeline*
*Context gathered: 2026-04-03*
