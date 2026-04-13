# Phase 220: Evolution Module Extraction - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 220 decomposes the oversized `crates/swarm-evolution/src/evolution.rs`
implementation into focused internal submodules without changing the existing
crate contract or mixing in the separate `mutation.rs` breakup that belongs to
Phase 221.

</domain>

<decisions>
## Implementation Decisions

- Keep the outward `swarm_evolution::evolution` surface stable for current
  runtime callers while moving implementation into an `evolution/` module tree.
- Use explicit `pub(crate)` boundaries where possible so the structural split
  reduces accidental cross-module coupling instead of just renaming files.
- Treat this as a behavior-preserving structural refactor. New evolution
  features, wire-format changes, and mutation-specific extraction remain out of
  scope for this phase.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-evolution/src/evolution.rs` is currently 6,670 lines, well
  above the milestone target of keeping extracted files under 2,000 lines.
- `crates/swarm-evolution/src/lib.rs` already exposes separate neighboring
  modules such as `drafting`, `selection`, `promotion`, `evidence`, `strategy`,
  `canary`, `governance_prep`, and `portfolio`, so `evolution.rs` is the most
  obvious remaining structural hotspot inside the crate.
- The active runtime still imports `swarm-evolution` through the crate surface
  declared in `lib.rs`, which makes internal extraction lower risk than a
  package-level API redesign.

</code_context>

<deferred>
## Deferred Ideas

- `mutation.rs` extraction is intentionally deferred to Phase 221 so the two
  large-file refactors do not tangle together.
- Wire-format and API schema versioning remain the separate Phase 222 and 223
  work.

</deferred>
