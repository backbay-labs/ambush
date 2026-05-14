# Phase 230: Service Module Decomposition - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase is limited to decomposing `crates/swarm-runtime/src/service.rs`
into focused internal modules while preserving the shipped
`swarm_runtime::service::{...}` surface and runtime behavior.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
- All implementation choices are at Claude's discretion — infrastructure-only refactor phase.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-runtime/src/lib.rs` already exposes `pub mod service;`, so the public path can stay stable by converting `service.rs` into `service/mod.rs` plus internal submodules.

### Established Patterns
- `crates/swarm-core/src/config` now demonstrates the same refactor pattern: a stable root module with focused internal files, shared helper/default imports, and test modules split by responsibility.
- `service.rs` has visible internal seams already:
  - types, error enums, degradation state, and metrics up front
  - preview and enrichment helpers before `RuntimeService`
  - `RuntimeService` main impl from line `1465`
  - `ConfiguredRuntimeStack` impls from line `2597`
  - operator-status helpers near line `2822`
  - tests from line `2945`

### Integration Points
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/ingest/mod.rs`
- `crates/swarm-runtime/src/http/core.inc`
- `crates/swarm-runtime/src/replay/core.inc`

</code_context>

<specifics>
## Specific Ideas

- Split `service.rs` into `types`, `metrics`, `preview`, `runtime_service`, `stack`, `status`, and multiple test modules so no extracted file exceeds the 2000-line roadmap ceiling.
- Preserve all current re-exports from `swarm_runtime::service` through `service/mod.rs` so downstream modules do not need call-site churn.

</specifics>

<deferred>
## Deferred Ideas

- Arc-ownership narrowing inside `RuntimeService` is deferred to Phase 231 once the service responsibilities are structurally separated.

</deferred>
