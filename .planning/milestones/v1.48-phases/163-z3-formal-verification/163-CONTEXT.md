# Phase 163: Z3 Formal Verification - Context

**Gathered:** 2026-04-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 163 adds an optional solver-backed proof lane for invariants that are too broad for replay enumeration, while keeping the shipped replay, mutation, and signed-proof artifacts as the canonical execution path when the `z3` feature is disabled.

</domain>

<decisions>
## Implementation Decisions

- Keep the solver tier behind an explicit `z3` feature flag so normal builds do not take a hard dependency on SMT tooling.
- Compile strategy invariants into a typed intermediate form before emitting solver constraints; direct YAML-to-Z3 string stitching is too brittle for signed proof artifacts.
- Reuse the existing proof and evolution artifact lanes so counterexamples, timeout outcomes, and signed proof metadata land in the same durable history surface operators already use.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-evolution/src/evolution.rs` and the current proof-artifact pipeline already persist signed proof state and review metadata.
- `crates/swarm-runtime/src/evolution_status.rs` is the right shared seam for surfacing optional solver proof status once the artifacts exist.
- Phase 162 now preserves measured evasion pressure and canary-ready proposal history, so Phase 163 can focus strictly on solver-backed invariant proof without reopening mutation plumbing.

</code_context>

<deferred>
## Deferred Ideas

- Broad operator UX for browsing solver counterexamples can wait until the proof lane itself is stable.
- Any runtime-online solver execution beyond the existing evolution/proof path remains out of scope for this phase.

</deferred>
