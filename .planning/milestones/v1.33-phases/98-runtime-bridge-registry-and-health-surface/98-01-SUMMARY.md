---
phase: 98-runtime-bridge-registry-and-health-surface
plan: 01
subsystem: runtime
tags: [bridges, runtime, serve-mode, telemetry]
requirements-completed: []
one-liner: "Serve mode now constructs named telemetry bridge instances from repo config and feeds their normalized output into the shared live detection channel."
completed: 2026-04-07
---

# Phase 98 Plan 01 Summary

**Serve mode now constructs named telemetry bridge instances from repo config and feeds their normalized output into the shared live detection channel.**

## Accomplishments

- Added first-class `tetragon` bridge config support in `swarm-core`, including `TetragonBridgeConfig` defaults and fail-closed validation for endpoint and reconnect settings.
- Introduced `BridgeRuntimeRegistry` in `swarm-runtime` to construct configured `tetragon`, `cloudtrail`, and `generic_json` bridge instances from `runtime.telemetry_sources[*].bridge`.
- Moved bridge-health ownership into a shared runtime snapshot so serve-mode HTTP surfaces can read bridge state without holding bridge instances directly.
- Wired `swarm-detect --serve` to spawn one worker task per configured bridge, forward normalized `TelemetryEvent` output into the existing `telemetry_tx`, and wait for bridge tasks during shutdown.
- Preserved the existing HTTP ingest path and agent runtime seam by having bridge workers reuse the same shared telemetry lane already consumed by `WhiskerAgent`.

## Files Created Or Modified

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/Cargo.toml`
- `crates/swarm-runtime/src/bridge_runtime.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/src/config.rs`

## Verification

- `cargo fmt --all`
- `cargo test -p swarm-runtime bridge_runtime --lib`
- `cargo test -p swarm-runtime config --lib`
- `cargo test -p swarm-core --lib`
- `cargo clippy -p swarm-core -p swarm-runtime --tests -- -D warnings`

## Notes

- `BridgeRuntimeRegistry` is intentionally runtime-owned rather than detector-owned so bridge lifecycle concerns stay outside the hot detection path.
- File-backed bridge sources stop cleanly after input exhaustion; channel-close and bridge poll failures degrade bridge-specific health instead of crashing serve mode.
