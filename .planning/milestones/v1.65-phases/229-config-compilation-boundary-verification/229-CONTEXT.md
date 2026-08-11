# Phase 229: Config Compilation Boundary Verification - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase is limited to proving the rebuild scope after the Phase 228 config
split and documenting the remaining crate-boundary fanout for future extraction
work.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
- All implementation choices are at Claude's discretion — infrastructure-only verification phase.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `tools/measure-config-rebuild-scope.sh` can provide a repeatable workspace warm-build, touch, and rebuild-scope measurement.

### Established Patterns
- `cargo tree --workspace --invert swarm-core` exposes the reverse dependency fanout of `swarm-core`.
- `cargo check --workspace --message-format short -j1` emits a stable per-crate rebuild list that can be diffed against the reverse dependency set.

### Integration Points
- `crates/swarm-core/src/config/*.rs`
- `tools/measure-config-rebuild-scope.sh`
- `.planning/ROADMAP.md`
- `.planning/STATE.md`

</code_context>

<specifics>
## Specific Ideas

- Use a focused config leaf such as `crates/swarm-core/src/config/policy.rs` as the representative config-only edit.
- Record both the rebuilt crate set and the unaffected workspace crate set so the remaining compile breadth is explicit.

</specifics>

<deferred>
## Deferred Ideas

- Extract config into a dedicated crate if the measured reverse dependency fanout remains too broad after the module split.

</deferred>
