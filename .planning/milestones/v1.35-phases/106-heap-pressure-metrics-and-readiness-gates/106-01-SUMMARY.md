---
phase: 106-heap-pressure-metrics-and-readiness-gates
plan: 01
subsystem: observability
tags: [metrics, memory, readiness, prometheus]
requirements-completed: [K8S-05]
one-liner: "Prometheus now exposes live heap bytes and heap-pressure ratio gauges derived from the running process and its container memory budget."
completed: 2026-04-07
---

# Phase 106 Plan 01 Summary

**Prometheus now exposes live heap bytes and heap-pressure ratio gauges derived from the running process and its container memory budget.**

## Accomplishments

- Added `swarm_heap_bytes` and `swarm_heap_pressure_ratio` gauges to `CriticalPathMetrics`.
- Added live heap sampling that reads process memory usage and computes pressure against cgroup or host memory limits.
- Reused the same heap snapshot path for both readiness gating and metrics export so memory reporting stays consistent.
- Updated `/metrics` to refresh heap gauges before encoding the Prometheus response.
- Added focused metrics tests proving the new gauges are exported.

## Files Created Or Modified

- `Cargo.toml`
- `crates/swarm-runtime/Cargo.toml`
- `crates/swarm-runtime/src/detection/metrics.rs`
- `crates/swarm-runtime/src/ingest.rs`

## Verification

- `cargo test -p swarm-runtime ingest --lib`
- `cargo check -p swarm-runtime -p swarm-response -p swarm-core`
- `cargo build --workspace`

## Notes

- Heap pressure is container-aware first and falls back to host memory only when cgroup limits are unavailable, which keeps the signal useful in Kubernetes.
- The metrics surface reports live sampled state instead of config placeholders, so Prometheus and readiness consume the same truth source.
