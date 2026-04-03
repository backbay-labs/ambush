# Fast Detection Benchmark

**Generated:** 2026-04-02
**Command:** `cargo run -p swarm-runtime --release --example fast_detection_bench`
**Workload:** 20,000 measured iterations after 1,000 warmup iterations

## Benchmark Scope

This benchmark measures the current critical detection path for one synthetic suspicious process-tree event:

1. normalized telemetry event creation
2. `SuspiciousProcessTreeDetector` evaluation
3. finding-to-pheromone conversion
4. in-memory substrate deposit

The benchmark uses the same typed Rust pipeline exercised by the unit tests. It does not include external I/O or JetStream.

## Results

| Metric | Value |
|--------|-------|
| p50 latency | 2.04 us |
| p95 latency | 3.75 us |
| p99 latency | 6.29 us |
| Throughput | 303,344.56 events/sec |

## Notes

- These numbers come from a local single-process release build on the current development machine.
- They are intended to track regressions on the v1 hot path, not to serve as a cross-machine performance claim.
- The current detector path is intentionally simple; future detector complexity should preserve the same measurement discipline.
