# Phase 199: Evolution Results And Reporting - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 199 starts once the bounded benchmark harness exists and the repo has at
least one checked-in multi-generation benchmark artifact. Phase 198 now meets
that bar, but the current suspicious-process-tree benchmark is flat: measured
fitness stayed at `0.656` and catch-rate stayed at `0.143` across both the
3-generation reference run and an expanded 10-generation search run.

The next boundary is not more raw benchmarking. It is publishing a truthful
improvement result, which means finding or enabling a detector and bounded
search configuration that produces a real measured gain before any improvement
claim is written down.

</domain>

<decisions>
## Implementation Decisions

- Treat the flat Phase 198 result as blocking evidence, not a publication-ready
  story.
- Reuse the repo-owned `evolution_benchmark` entrypoint and durable benchmark
  store for repeated sweeps instead of inventing one-off measurement scripts.
- Keep any published improvement claim tied to one exact benchmark command,
  host profile, detector, corpus, and persisted benchmark artifact.

</decisions>

<code_context>
## Existing Code Insights

- `run_bounded_evolution_benchmark` now persists durable benchmark reports and
  accepts an explicit autonomous base-experiment override so staged benchmark
  runs stay isolated from the repo tree.
- `evolution_status` now surfaces the latest benchmark summary, which gives
  Phase 199 a natural operator-facing publication seam once a real gain exists.
- `docs/benchmarks/autonomous-evolution.md` records the current no-gain baseline
  for `suspicious_process_tree` against `office-baseline-control`.

</code_context>

<deferred>
## Deferred Ideas

- An always-on autonomous tuning controller remains out of scope.
- Publishing a benchmark dashboard or multi-detector comparison matrix remains
  deferred until at least one detector shows a reproducible measured gain.

</deferred>
