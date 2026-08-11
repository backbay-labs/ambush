# Phase 231: RuntimeService Arc Reduction - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase is limited to narrowing the shared runtime ownership model after the
Phase 230 service decomposition so request-facing paths stop cloning the full
configured runtime stack when they only need audited execution.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
- All implementation choices are at Claude's discretion as long as the request-path behavior remains unchanged and runtime reloads keep the narrowed handle in sync.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-runtime/src/service/runtime_service.rs` now isolates the `RuntimeService` ownership boundary, so the runtime execution handle can be narrowed without reopening the whole service decomposition.
- `crates/swarm-runtime/src/ingest/mod.rs` already uses `ArcSwap` for live reload of the full configured stack, which gives this phase a natural place to maintain a narrower request-runtime swap alongside the broader stack swap.

### Established Patterns
- The request router and demo approval/replay resume paths only need `SwarmRuntime` execution plus the runtime mode, but they currently load the full `Arc<ConfiguredRuntimeStack>` to reach `service.runtime`.
- Reload already rebuilds the runtime stack atomically, so any narrowed request-runtime handle must be swapped at the same time as the stack.

### Integration Points
- `crates/swarm-runtime/src/service/runtime_service.rs`
- `crates/swarm-runtime/src/ingest/mod.rs`
- `crates/swarm-runtime/src/ingest/demo.rs`
- `crates/swarm-runtime/src/http/core.inc`

</code_context>

<specifics>
## Specific Ideas

- Wrap `RuntimeService`'s owned `SwarmRuntime` in an explicit shared handle so narrow request paths can clone only the execution runtime instead of the entire configured stack.
- Add a separate `ArcSwap` for the request runtime inside ingest state and route request-response plus human-approved demo execution through that narrower handle.

</specifics>

<deferred>
## Deferred Ideas

- Wider ingest-state slimming beyond the audited execution lane is deferred; this phase only narrows paths that provably need `SwarmRuntime` instead of the full configured stack.

</deferred>
