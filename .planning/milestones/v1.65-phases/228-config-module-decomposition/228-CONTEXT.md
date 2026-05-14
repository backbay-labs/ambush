# Phase 228: Config Module Decomposition - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase is limited to decomposing `swarm-core/src/config.rs` into focused
sub-modules while preserving the shipped `swarm_core::config` API surface.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
- All implementation choices are at Claude's discretion — pure infrastructure phase.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-core/src/lib.rs` already exposes `pub mod config;`, so the split
  can preserve the public path by converting `config.rs` into `config/mod.rs`
  plus internal submodules.

### Established Patterns
- The workspace already tolerates focused internal module trees with small root
  composition files and stable re-exports.
- `swarm-runtime` and downstream crates depend on `swarm_core::config::{...}`
  directly, so the public item names and module path must remain stable.

### Integration Points
- `swarm-core/src/lib.rs`
- `crates/swarm-runtime/src/config.rs`
- All crates importing `swarm_core::config::{...}`

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase.

</specifics>

<deferred>
## Deferred Ideas

None.

</deferred>
