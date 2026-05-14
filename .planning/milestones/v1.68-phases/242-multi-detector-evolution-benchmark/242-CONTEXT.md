# Phase 242: Multi-Detector Evolution Benchmark - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 242 adds one measured benchmark loop that can exercise every supported
detector genome family through the same bounded evolution path and persist
generation-over-generation fitness output.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing `run_bounded_evolution_benchmark` harness instead of
  building a second benchmark runner for non-process-tree detectors.
- Make benchmark measurement independent from proposal readiness so blocked
  validation outputs can still contribute measured autonomous fitness.
- Keep the benchmark bounded to one staged detector baseline at a time and
  persist comparable baseline versus generation metrics in the same report.

</decisions>

<code_context>
## Existing Code Insights

- [kitten_agent.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/kitten_agent.rs) already owns the bounded measured benchmark loop and benchmark report persistence.
- [mutation/harness.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/mutation/harness.rs) previously refreshed population state only from queue-ready candidates, which is correct for proposal selection but too narrow for benchmark measurement.
- The benchmark staging tests needed a repo-root-like temporary workspace with a signed config sidecar because benchmark path resolution is rooted at the staged config file.

</code_context>

<deferred>
## Deferred Ideas

- No multi-generation optimization campaign beyond the bounded milestone proof.
- No benchmark regression gate in CI yet; that belongs to later hardening work.

</deferred>
