---
phase: 106-heap-pressure-metrics-and-readiness-gates
plan: 02
subsystem: readiness
tags: [memory, readiness, health, kubernetes]
requirements-completed: [K8S-05]
one-liner: "Readiness now fails closed under configured heap pressure and surfaces memory state clearly in the health payload without changing startup or liveness semantics."
completed: 2026-04-07
---

# Phase 106 Plan 02 Summary

**Readiness now fails closed under configured heap pressure and surfaces memory state clearly in the health payload without changing startup or liveness semantics.**

## Accomplishments

- Added `RuntimeSettings.max_heap_pressure` with validation and repo-owned defaults.
- Extended `/readyz` and `/healthz` to include an explicit heap component so operators can distinguish memory pressure from substrate or detector degradation.
- Returned HTTP `503` from `/readyz` when measured heap pressure exceeds the configured threshold.
- Kept `/livez` and `/startupz` independent from heap-pressure shedding so startup and liveness semantics remain stable.
- Added regression tests proving readiness degrades on heap pressure and that metrics and health payloads expose the new state.

## Files Created Or Modified

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/src/ingest.rs`

## Verification

- `cargo test -p swarm-runtime ingest --lib`
- `cargo clippy -p swarm-core -p swarm-response -p swarm-runtime --tests -- -D warnings`
- `cargo build --workspace`

## Notes

- Readiness shedding happens before the process reaches an OOM boundary, which gives Kubernetes a useful signal to stop routing traffic.
- Startup and liveness remain separate concerns so transient memory pressure does not look like failed boot or dead process state.
