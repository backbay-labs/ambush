# Phase 219: Anomaly Quality Benchmark - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 219 turns the widened behavioral anomaly path from Phases 216-218 into a
repeatable quality benchmark that measures false-positive and catch-rate
behavior against labeled telemetry.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing repo-owned benchmark or replay entrypoint patterns where
  possible instead of inventing a one-off evaluation harness for behavioral
  anomaly quality.
- Measure the widened behavioral detector as it actually ships after the Phase
  218 breadth expansion. Do not benchmark an older process-start-only subset.
- Check in the resulting benchmark artifact so later milestone work can compare
  against the same reference run instead of relying on ephemeral terminal
  output.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-whisker/src/behavioral_anomaly.rs` now supports process-start
  plus the shipped non-process telemetry families through one explicit
  `deviation_scoring` model and one restart-safe baseline seam.
- The repo already ships benchmark and replay precedents under
  `crates/swarm-runtime/examples/` and `docs/benchmarks/`, which is the likely
  shape for a reproducible anomaly-quality artifact here as well.
- The roadmap requirement for this phase is outcome-oriented: it needs measured
  false-positive and catch-rate behavior against labeled telemetry, not just
  unit tests for individual anomaly cases.

</code_context>

<deferred>
## Deferred Ideas

- Any deeper tuning or parameter search driven by benchmark results belongs in a
  later milestone, not in the benchmark phase itself.
- Broad architectural changes to the widened behavioral detector are out of
  scope unless they are strictly required to make the benchmark runnable and
  honest.

</deferred>
