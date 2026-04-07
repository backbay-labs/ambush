---
phase: 104-drain-control-and-startup-probe-surface
plan: 01
subsystem: lifecycle
tags: [kubernetes, lifecycle, drain, ingest]
requirements-completed: [K8S-01]
one-liner: "Serve mode now enters a bounded drain state, rejects new ingest requests, waits for accepted work, and then hands shutdown back to the existing graceful-stop path."
completed: 2026-04-07
---

# Phase 104 Plan 01 Summary

**Serve mode now enters a bounded drain state, rejects new ingest requests, waits for accepted work, and then hands shutdown back to the existing graceful-stop path.**

## Accomplishments

- Added drain-aware lifecycle state and in-flight request accounting to the ingest service so accepted work is tracked explicitly during shutdown.
- Added a `/prestop` control path that flips the runtime into drain mode, rejects new `/v1/ingest/events` requests with HTTP `503`, and waits for accepted work to complete.
- Bound drain completion with `RuntimeSettings.drain_timeout_ms` so Kubernetes rollouts fail closed instead of hanging indefinitely.
- Preserved the existing Axum and Tokio graceful shutdown flow by signaling the same runtime shutdown channel after drain completion or timeout.
- Added lifecycle tests proving drain mode rejects new ingest traffic and that PreStop waits for in-flight work before shutdown.

## Files Created Or Modified

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`

## Verification

- `cargo test -p swarm-runtime ingest --lib`
- `cargo test -p swarm-runtime --tests --no-run`
- `cargo clippy -p swarm-core -p swarm-response -p swarm-runtime --tests -- -D warnings`

## Notes

- Drain accounting stays tied to accepted ingest requests, which keeps rollout behavior deterministic without changing the existing hot-path request contract.
- The PreStop path intentionally reuses the runtime shutdown channel instead of inventing a parallel termination mechanism.
