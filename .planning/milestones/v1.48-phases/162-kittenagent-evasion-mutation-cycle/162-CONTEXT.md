# Phase 162: KittenAgent Evasion Mutation Cycle - Context

**Gathered:** 2026-04-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 162 closes the loop between the new evasion benchmark and the existing evolution stack: measured detector gaps need to influence candidate mutation, ranking, and canary validation instead of remaining operator-only reporting.

</domain>

<decisions>
## Implementation Decisions

- Reuse the Phase 161 `EvasionCoverageSnapshot` as the bounded mutation-pressure input instead of teaching Kitten a second raw-suite parser.
- Push evasion pressure through the existing durable mutation and population artifacts so gap-driven decisions survive restart and show up in the same evolution history lane as replay and adversarial pressure.
- Prove the full evasion → mutation → canary flow with runtime and evolution integration tests rather than a detector-local unit harness.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/kitten_agent.rs` already owns the bounded multi-tick state machine and proposal routing into the canary lane.
- `crates/swarm-evolution/src/mutation.rs` already persists ranking, population, and durable episode reports, which is the right seam for storing evasion-gap pressure and outcomes.
- `crates/swarm-runtime/src/evasion_coverage.rs` now exposes a typed coverage snapshot and intentional-gap catalog that Phase 162 can consume directly.
- `crates/swarm-runtime/src/replay/core.inc` plus the existing canary flow already provide the deterministic corpus and proof surfaces needed for end-to-end validation.

</code_context>

<deferred>
## Deferred Ideas

- Solver-backed `z3` invariants remain Phase 163.
- Broader operator visualization of evasion gap history can wait until the mutation loop is proven end to end.

</deferred>
