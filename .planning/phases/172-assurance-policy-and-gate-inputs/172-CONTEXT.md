# Phase 172: Assurance Policy And Gate Inputs - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 172 turns the artifacts shipped in `v1.48` and `v1.50` into one repo-owned assurance policy that can explain when a candidate is safe enough to remain eligible for queue, canary, and promotion work.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing evolution queue blocking-reason path instead of inventing a second assurance verdict channel.
- Treat evasion coverage and solver proof outcomes as one shared policy input set rooted in repo-owned config.
- Keep the first phase policy-focused: define and persist assurance status now, then apply it to downstream rollout transitions in later phases.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-evolution/src/evolution.rs` already creates proof-backed queue proposals and persists blocking reasons, proof summaries, and advisory lineage.
- `crates/swarm-runtime/src/evolution_status.rs` already surfaces solver-proof state and population or admission summaries from durable artifacts.
- `crates/swarm-runtime/src/evasion_coverage.rs` and the Phase 162 mutation lane already persist evasion-gap and coverage context that can feed a shared assurance policy.

</code_context>

<deferred>
## Deferred Ideas

- Durable replay-case harvest from assurance failures belongs to Phase 173.
- Fail-closed rollout enforcement across queue, canary, and promotion belongs to Phase 174.
- Signed waivers and surfaced assurance lineage belong to Phase 175.

</deferred>
