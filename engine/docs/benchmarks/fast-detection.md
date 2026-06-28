# Fast Detection Hot-Path Benchmark

**Generated:** 2026-04-12
**Command:** `cargo bench -p swarm-runtime --bench hot_path -- --noplot`
**Workload:** 20,000 measured iterations after 1,000 warmup iterations

## Benchmark Scope

This benchmark measures the bounded runtime hot path for one synthetic suspicious process-tree event:

1. JSON-to-`TelemetryEvent` ingest parsing
2. `SuspiciousProcessTreeDetector` evaluation
3. finding-to-pheromone conversion plus signed deposit
4. pheromone persistence on the selected benchmark backend
5. concentration evaluation through `ConcentrationMonitor::evaluate_all()`

The default benchmark backend is `in_memory`, which keeps this benchmark focused
on the runtime-owned hot path rather than networked durability. Set
`STS_HOT_PATH_BACKEND=local_journal` to rerun the same benchmark against the
local durable substrate. JetStream-backed operator envelope measurement remains
the `end_to_end_ingest_bench` and the sustained-load work in Phase 191.

## Results

| Metric | Value |
|--------|-------|
| Backend | `in_memory` |
| p50 latency | 103.04 us |
| p95 latency | 109.29 us |
| p99 latency | 139.21 us |
| Throughput | 8,401.69 events/sec |

## Notes

- These numbers are regression data for the bounded ingest-to-escalate hot
  path, not the full supported production capacity envelope.
- The Criterion timing band for the same benchmark run was
  `104.54 us .. 106.41 us`, which lines up with the recorded percentile sample.
- The `local_journal` backend switch is also wired and runnable through the
  same bench target via `STS_HOT_PATH_BACKEND=local_journal`, but the default
  checked-in baseline remains the `in_memory` regression slice for
  like-for-like hot-path comparison.
- Use `end_to_end_ingest_bench` plus `/readyz` and `/metrics` for operator
  capacity, SLO, and alert guidance.
