# Phase 198: Measured Evolution Benchmark - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 198 starts once one-generation autonomous candidates already carry durable
measured catch-rate, false-positive, latency, and lineage artifacts. The next
boundary is benchmark orchestration: run a bounded multi-generation evolution
loop, persist generation-over-generation fitness deltas, and produce a
reproducible benchmark artifact without turning those results into published
improvement claims yet.

</domain>

<decisions>
## Implementation Decisions

- Reuse the durable autonomous fitness artifacts from Phase 197 as the source of
  truth for benchmark scoring instead of inventing a parallel benchmark-only
  fitness model.
- Keep the benchmark repo-owned and bounded: one explicit N-generation run with
  deterministic inputs and persisted generation summaries, not an always-on
  background evolution controller.
- Separate benchmark execution from outward-facing claims. Statistical framing
  and reproducible raw results land in Phase 198; operator-facing results
  publication remains Phase 199.

</decisions>

<code_context>
## Existing Code Insights

- `swarm-evolution::mutation` now persists `EvolutionAutonomousFitnessMeasurement`
  on both durable population members and adversarial episode reports, including
  corpus identity and parent lineage.
- `kitten_agent` already reuses the bounded mutation, materialization,
  validation, ranking, population, and proposal seams for autonomous candidates,
  so a multi-generation benchmark should orchestrate those seams rather than
  create a separate proposal path.
- `evolution_status` now surfaces the latest autonomous measured fitness and
  lineage, which provides a natural operator-facing summary seam for a later
  benchmark report.

</code_context>

<deferred>
## Deferred Ideas

- Publishing detector-specific improvement claims and polished operator-facing
  benchmark results remains Phase 199.
- Any unbounded autonomous evolution daemon beyond a repo-owned benchmark run
  remains deferred.

</deferred>
