# Phase 191 Plan 01 Summary

## Delivered

- Extended
  [end_to_end_ingest_bench.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/examples/end_to_end_ingest_bench.rs)
  so the shipped benchmark now supports both `fixed` steady-state measurement
  and `ramp_until_shed` staged concurrency measurement on the same detect HTTP
  surface. The example now emits host-profile metadata, configurable
  `runtime.max_heap_pressure`, optional heap ballast, live `/readyz` polling,
  and per-stage throughput plus latency summaries.
- Updated
  [end-to-end-ingest.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/benchmarks/end-to-end-ingest.md)
  with the refreshed fixed-profile numbers and the first checked-in
  readiness-shed contract for the reference host:
  highest stable sustained throughput `4,394.19` events/sec at concurrency `2`,
  with the first `/readyz` shed at concurrency `4` under
  `runtime.max_heap_pressure=0.00335`.
- Updated
  [CONFIGURATION.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/CONFIGURATION.md)
  so the capacity envelope now distinguishes the steady-state HTTP ingest
  baseline from the readiness-shed ceiling, refreshes the hot-path Criterion
  numbers from Phase 190, and explains how operators should rerun the same
  command on JetStream or deployment-specific memory budgets.

## Notes

- The checked-in ramp reference deliberately uses a low
  `runtime.max_heap_pressure` so heap-pressure shedding is observable in a
  single-process loopback harness on a 32 GiB developer machine. It is a
  reproducible sizing fixture, not a universal production default.
- The monotonic ramp stops at the first shed stage. It does not binary-search
  back downward on the same process because a process that has already crossed
  the heap-pressure threshold is no longer a clean lower-concurrency probe.
