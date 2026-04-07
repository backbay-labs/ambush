---
phase: 85-container-and-deployment-infrastructure
plan: 01
subsystem: runtime
tags: [ingest, healthz, reload, shutdown, serve-mode]
requirements-completed: [DEPLOY-03, DEPLOY-04]
one-liner: "swarm-detect now exposes /healthz, reloads config on file change or SIGHUP, and shuts down cleanly on SIGTERM or Ctrl-C."
completed: 2026-04-05
---

# Phase 85 Plan 01 Summary

**swarm-detect now exposes /healthz, reloads config on file change or SIGHUP, and shuts down cleanly on SIGTERM or Ctrl-C.**

## Accomplishments

- Reworked `IngestState` around `ArcSwap` so the runtime stack and detector strategy can be atomically replaced on reload.
- Added `/healthz` to the shared ingest router with readiness details for detector strategy, substrate, replay store, runtime mode, config path, and configured response adapter.
- Added `reload_from_disk` plus file-watch and `SIGHUP` reload tasks to `swarm_detect --serve`.
- Switched serve-mode stack construction to `ConfiguredRuntimeStack::from_config`, so the live service uses the same response adapter selection path as the rest of the runtime.
- Added graceful shutdown handling for SIGTERM, SIGINT, and non-Unix Ctrl-C, with an explicit completion log line on exit.
- Added ingest integration coverage for `/healthz` ready/degraded behavior and config reload changing the active detector strategy.

## Files Created Or Modified

- `Cargo.toml`
- `crates/swarm-runtime/Cargo.toml`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-runtime/tests/ingest_integration.rs`

## Verification

- `cargo test -p swarm-runtime --test ingest_integration`
- `curl -sf http://localhost:9090/healthz`

## Notes

- `/healthz` intentionally reports degraded status when live response is configured to require durable backends but the current substrate or replay store is only in memory.
