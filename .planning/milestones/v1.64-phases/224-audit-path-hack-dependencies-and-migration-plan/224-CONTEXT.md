# Phase 224: Audit Path Hack Dependencies And Migration Plan - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 224 audits the existing `#[path]` bridge between `swarm-runtime` and
`swarm-evolution`, documents the dependency cycle it is hiding, and defines the
migration strategy for Phases 225-227. This phase does not remove the hacks or
move production code yet.

</domain>

<decisions>
## Implementation Decisions

### Audit Scope
- Inventory all ten `#[path = "../../swarm-evolution/..."]` directives in
  `crates/swarm-runtime/src/lib.rs` and map the runtime modules that consume
  them.
- Record every place where `swarm-evolution` currently depends back on
  `swarm-runtime` through re-exported runtime modules or helpers.
- Treat the current `cargo check -p swarm-runtime` result as the pre-change
  baseline for later path-hack removal proof.

### Migration Shape
- Replace the path hacks with normal crate re-exports from `swarm-evolution`
  only after the cycle is broken.
- Break the cycle by extracting the runtime-owned support seams currently
  consumed by `swarm-evolution` into a neutral bridge crate or equivalent
  shared module boundary that both crates can depend on.
- Keep the outward runtime call sites stable where practical by preferring
  `pub use swarm_evolution::{...};` style re-exports over broad downstream code
  churn once the dependency graph allows it.

### Claude's Discretion
- Exact support-crate naming and final file layout are at Claude's discretion
  in Phase 225, as long as the cycle is removed cleanly and the runtime/evolution
  API boundary remains explicit.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-evolution/src/lib.rs` already groups the evolution modules under
  one crate surface, so the path-hacked modules can later be re-exported from
  that crate instead of being source-included into `swarm-runtime`.
- The existing GSD helper commands can update roadmap and requirements progress
  once the phase directory contains plan and summary artifacts.

### Established Patterns
- `swarm-runtime` currently avoids a direct dependency on `swarm-evolution`;
  instead it source-includes ten evolution modules with `#[path]` so runtime
  code can refer to them as `crate::canary`, `crate::drafting`, and similar.
- `swarm-evolution` already depends on `swarm-runtime` and re-exports runtime
  seams such as `config`, `control`, `detector_factory`, `evasion_coverage`,
  `operator_maintenance`, `replay`, and `service`.
- The current workspace baseline is green under `cargo check -p swarm-runtime`.

### Integration Points
- Runtime consumers of the path-hacked modules are concentrated in
  `kitten_agent.rs`, `ingest/mod.rs`, `evolution_status.rs`,
  `operator_maintenance.rs`, `sphinx_agent.rs`, and `lib.rs`.
- Evolution modules reach back into runtime-owned APIs primarily through
  `config`, `detector_factory`, `replay`, `control`, `operator_maintenance`,
  `service`, and `evasion_coverage`, plus one test helper call in
  `evidence.rs`.
- `RuntimeMode` is already core-owned via `swarm_core::config::RuntimeMode`,
  which makes it an easy early candidate to stop routing through
  `swarm-runtime`.

</code_context>

<specifics>
## Specific Ideas

- Recommended migration sequence:
  1. Extract runtime-owned evolution support seams into a neutral shared crate.
  2. Make `swarm-evolution` depend on that shared crate instead of
     `swarm-runtime`.
  3. Add a normal `swarm-evolution` dependency to `swarm-runtime`.
  4. Replace the ten `#[path]` directives with direct re-exports from
     `swarm-evolution`.
- Keep `config.rs` decomposition out of scope for this milestone; extract only
  the subset required to eliminate the cycle so Phase 225 stays bounded.

</specifics>

<deferred>
## Deferred Ideas

- Full `config.rs` extraction and broader service decomposition remain the
  separate v1.65 milestone.
- Any post-removal cleanup of now-redundant compatibility re-exports can wait
  until after Phase 227 proves the new boundary works.

</deferred>
