# Phase 173: Counterexample Harvest And Replay Regeneration - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 173 turns assurance failures into durable replayable evidence so evasion misses and solver counterexamples stop as dead-end blockers and instead feed the existing mutation and review lane.

</domain>

<decisions>
## Implementation Decisions

- Reuse repo-owned replay and scenario manifest shapes instead of inventing a one-off assurance artifact.
- Preserve lineage back to the triggering proof, strategy, and assurance decision for every harvested case.
- Feed harvested cases into existing mutation ranking and review summaries before widening rollout enforcement.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-evolution/src/evolution.rs` already persists solver artifacts and queue proposals with blocking reasons.
- `crates/swarm-runtime/src/evasion_coverage.rs` and `crates/swarm-evolution/src/mutation.rs` already carry durable evasion-gap context from the measured corpus.
- The replay lane already understands repo-owned scenario manifests and verification lineage, which is the correct target format for harvested assurance cases.

</code_context>

<deferred>
## Deferred Ideas

- Queue, canary, and promotion fail-closed enforcement belongs to Phase 174.
- Signed waivers and exported assurance lineage belong to Phase 175.

</deferred>
