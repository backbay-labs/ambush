---
phase: 106-heap-pressure-metrics-and-readiness-gates
type: context
created_at: 2026-04-07
depends_on: [105]
---

# Phase 106 Context

## Goal

Expose live heap-pressure metrics and fail readiness when the process is approaching its memory limit so Kubernetes can shed load before the runtime reaches an OOM boundary.

## Why This Phase Exists

The runtime already exports hot-path latency, verdict, bridge, and agent metrics, but it has no notion of memory pressure. Kubernetes can only react to what the process surfaces. Without a memory-pressure gate, the runtime stays ready until the kernel or cgroup limit kills it.

## What Is Already True

- `CriticalPathMetrics` already owns the Prometheus registry and bridge/agent gauges.
- `/metrics` and `/readyz` are both served from `ingest.rs`, which makes it straightforward to keep the exported measurement and readiness decision consistent.
- The runtime config already owns serve-mode operational thresholds, so heap gating can stay repo-configured.

## Constraints

- The metric source must work without changing detector or response execution semantics.
- Readiness should degrade on memory pressure without changing `/livez`.
- Metric collection must fail soft when an exact platform-specific memory limit is unavailable.

## Decisions

- `swarm_heap_bytes` will report current process memory usage in bytes, and `swarm_heap_pressure_ratio` will report usage divided by the best available memory limit.
- The implementation will prefer cgroup memory limits when present and fall back to total system memory otherwise.
- `RuntimeSettings.max_heap_pressure` will define the readiness threshold instead of a hard-coded constant.

## Phase Direction

- Add the new gauges and live sampling support first.
- Then wire the readiness gate and health payloads to the same measurement path.
- Keep the implementation inside runtime metrics and ingest surfaces rather than spreading memory logic across the service layer.
