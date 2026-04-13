# Phase 197: Autonomous Fitness Evaluation Loop - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 197 starts once bounded autonomous variants already exist. The boundary is
measured candidate evaluation: generated variants now need catch-rate,
false-positive, and latency fitness recorded against the tracked evasion corpus.
Multi-generation benchmarking and published results stay in Phases 198 and 199.

</domain>

<decisions>
## Implementation Decisions

- Reuse the autonomous lineage persisted in Phase 196 as the identity key for
  measured fitness instead of inventing a parallel scoring artifact.
- Extend the existing replay, population, and adversarial episode artifacts so
  measured fitness remains attributable to the exact generated genome that
  entered the current proposal lane.
- Keep evaluation bounded to one candidate batch and one generation at a time;
  statistical benchmark loops remain deferred.

</decisions>

<code_context>
## Existing Code Insights

- `swarm-evolution::mutation` now persists `autonomous_generation` on mutation
  specs and per-variant autonomous parent lineage, so Phase 197 can join
  measured fitness directly to generated parents and recipes.
- `refresh_population` already computes replay-derived objectives and bounded
  evasion-pressure-adjusted fitness, while `evaluate_adversarial_pressure`
  persists per-generation red-blue episode artifacts with genome hashes.
- `kitten_agent` already routes autonomous candidates through the existing
  validation, ranking, durable population, and proposal seams, so Phase 197
  should enrich the fitness loop rather than widen the runtime contract.

</code_context>

<deferred>
## Deferred Ideas

- Running configurable N-generation autonomous loops remains Phase 198.
- Publishing measured improvement claims and operator-facing reports remains
  Phase 199.

</deferred>
