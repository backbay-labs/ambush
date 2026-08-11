# Phase 225: Extract Runtime-Evolution Bridge Types - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 225 has to break the effective `swarm-runtime` <-> `swarm-evolution`
cycle in a way that actually lets Phase 226 delete the runtime `#[path]`
directives. The audit from Phase 224 showed that a neutral support-crate
extraction would immediately expand into `config`, `replay`, `detector_factory`,
`control`, `operator_maintenance`, and `service` decomposition, which is too
large for this milestone.

</domain>

<decisions>
## Implementation Decisions

### Bounded Cycle Break
- Make `swarm-runtime` the real source owner of the ten path-hacked evolution
  modules by moving their source tree under `crates/swarm-runtime/src/`.
- Turn `crates/swarm-evolution` into a thin compatibility facade that re-exports
  the public runtime modules instead of compiling its own duplicate source.
- Keep the existing crate names so downstream code can still refer to
  `swarm_runtime::...` or `swarm_evolution::...` through normal Rust crate
  dependencies.

### Why This Shape
- The moved modules already compile successfully under the runtime crate root
  today because the current `#[path]` directives include them there.
- Converting `swarm-evolution` into a compatibility facade breaks the cycle
  without inventing a new support crate or widening the milestone into a large
  shared-types extraction.
- This keeps the immediate change bounded to file ownership and crate exports,
  which Phase 226 can finish by deleting the old path directives and repairing
  the remaining imports.

</decisions>

<code_context>
## Existing Code Insights

### Source Layout
- The ten path-hacked modules live in `crates/swarm-evolution/src/`:
  `canary`, `drafting`, `evidence`, `evolution`, `governance_prep`,
  `mutation`, `portfolio`, `promotion`, `selection`, and `strategy`.
- The `mutation/` and `evolution/` subdirectories contain supporting modules and
  tests that must move with the top-level files.
- `crates/swarm-runtime/src/lib.rs` already exposes those modules as
  `pub mod ...` through `#[path]`, so moving the files into the runtime crate is
  a structural cleanup rather than a semantic rewrite.

### Compatibility Surface
- `crates/swarm-evolution/src/lib.rs` can preserve the outward crate surface by
  re-exporting the runtime-owned modules and the runtime utility modules it
  already forwards (`config`, `control`, `detector_factory`, `evasion_coverage`,
  `operator_maintenance`, `replay`, and `service`).
- No workspace crate currently imports `swarm_evolution::...` directly, which
  keeps the compatibility risk low for this phase.

</code_context>

<specifics>
## Specific Ideas

- Move the top-level files and their `evolution/` and `mutation/` support trees
  into `crates/swarm-runtime/src/`.
- Replace each `#[path = "../../swarm-evolution/src/..."]` entry in
  `crates/swarm-runtime/src/lib.rs` with a normal `pub mod ...;`.
- Simplify `crates/swarm-evolution/src/lib.rs` down to `pub use swarm_runtime`
  module re-exports so the crate remains buildable without owning duplicate
  source files.

</specifics>

<deferred>
## Deferred Ideas

- Any future decision to re-expand `swarm-evolution` into an independently owned
  crate can happen after the path-hack debt is gone; it is not required for
  this milestone.

</deferred>
