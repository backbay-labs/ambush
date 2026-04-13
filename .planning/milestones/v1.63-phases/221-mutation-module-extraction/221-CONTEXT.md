# Phase 221: Mutation Module Extraction - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 221 decomposes the oversized `crates/swarm-evolution/src/mutation.rs`
implementation into focused internal submodules without changing the existing
crate contract or mixing in the later wire-format and API schema migration work
reserved for Phases 222 and 223.

</domain>

<decisions>
## Implementation Decisions

- Keep the outward `swarm_evolution::mutation` surface stable for current
  runtime and library callers while moving implementation into a `mutation/`
  module tree.
- Reuse the extraction pattern proven in Phase 220: focused sibling modules,
  explicit `pub(crate)` boundaries for internal helpers, and explicit `#[path]`
  wiring where that prevents path-import regressions.
- Treat this as a behavior-preserving structural refactor. Mutation algorithm
  changes, new candidate-generation features, and schema migration remain out of
  scope.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-evolution/src/mutation.rs` is currently roughly 7,000 lines and
  is now the largest remaining structural hotspot in `swarm-evolution`.
- Phase 220 already decomposed `evolution.rs` into an `evolution/` module tree,
  so the crate now has a recent proven extraction pattern to mirror for
  `mutation.rs`.
- Runtime-facing autonomous evolution flows still import `swarm-evolution`
  through the crate surface declared in `lib.rs`, which makes internal
  extraction lower risk than an API redesign.

</code_context>

<deferred>
## Deferred Ideas

- Pheromone wire-format versioning remains the separate Phase 222 work.
- Operator/API schema versioning remains the separate Phase 223 work.
- Any mutation-logic tuning, heuristic changes, or new autonomous search modes
  remain future work after the structural extraction is stable.

</deferred>
