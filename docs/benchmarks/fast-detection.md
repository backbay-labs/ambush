# Fast Detection Hot-Path Benchmark

**Generated:** 2026-04-11
**Command:** `cargo run -p swarm-runtime --release --example fast_detection_bench`
**Workload:** 20,000 measured iterations after 1,000 warmup iterations

## Benchmark Scope

This benchmark measures the current critical detection path for one synthetic suspicious process-tree event:

1. normalized telemetry event creation
2. `SuspiciousProcessTreeDetector` evaluation
3. finding-to-pheromone conversion
4. in-memory substrate deposit

The benchmark uses the same typed Rust pipeline exercised by the unit tests. It
does not include HTTP, JSON parsing, replay persistence, or JetStream.

## Results

| Metric | Value |
|--------|-------|
| p50 latency | 59.00 us |
| p95 latency | 63.79 us |
| p99 latency | 85.08 us |
| Throughput | 16,186.91 events/sec |

## Notes

- These numbers come from a local single-process release build on the reference
  host described in `docs/benchmarks/end-to-end-ingest.md`.
- They are regression data for the detector-plus-deposit hot path, not the
  supported production capacity envelope.
- Use `end_to_end_ingest_bench` plus `/readyz` and `/metrics` for operator
  capacity, SLO, and alert guidance.
