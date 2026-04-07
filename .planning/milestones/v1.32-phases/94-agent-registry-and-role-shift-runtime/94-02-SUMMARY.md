---
phase: 94-agent-registry-and-role-shift-runtime
plan: 02
subsystem: runtime
tags: [agents, environment, metrics, observability]
requirements-completed: [MULTI-03, MULTI-06]
one-liner: "dispatcher ticks now build peer-aware `SwarmEnvironment` snapshots and emit shared Prometheus lifecycle counters plus structured logs for agent ticks, role shifts, and health transitions."
completed: 2026-04-06
---

# Phase 94 Plan 02 Summary

**dispatcher ticks now build peer-aware `SwarmEnvironment` snapshots and emit shared Prometheus lifecycle counters plus structured logs for agent ticks, role shifts, and health transitions.**

## Accomplishments

- Expanded `SwarmEnvironment` with `peer_findings`, and taught the dispatcher to track the latest finding-like action per agent so each tick sees a read-only peer snapshot refreshed from the previous cycle.
- Added shared Prometheus lifecycle counters to `CriticalPathMetrics`: `agent_ticks_total`, `agent_role_shifts_total`, and `agent_health_transitions_total`, all partitioned by role on the existing `/metrics` surface.
- Wired the dispatcher to the runtime’s shared Prometheus registry through `IngestState::current_prometheus_metrics()` so lifecycle metrics land on the same registry already exported by `detect_http_router`.
- Added structured logging for agent registration, deregistration, tick completion, role-shift broadcasts, failed event observation, and health transitions with explicit `agent_id` fields.
- Added dispatcher tests proving peer findings appear on subsequent ticks and that lifecycle metrics are encoded in the shared OpenMetrics output.

## Files Created Or Modified

- `crates/swarm-core/src/agent.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-runtime/src/detection/metrics.rs`
- `crates/swarm-runtime/src/dispatcher.rs`
- `crates/swarm-runtime/src/ingest.rs`

## Verification

- `cargo test -p swarm-runtime dispatcher --lib`
- `cargo test -p swarm-runtime ingest --lib`
- `cargo test -p swarm-runtime --bin swarm_detect`
- `cargo build --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace`

## Notes

- Peer findings intentionally summarize agent actions rather than exposing mutable peer state; this keeps the environment snapshot cheap and read-only.
- The shared metric path means no extra `/metrics` integration was needed beyond plumbing the existing runtime registry into the dispatcher.
