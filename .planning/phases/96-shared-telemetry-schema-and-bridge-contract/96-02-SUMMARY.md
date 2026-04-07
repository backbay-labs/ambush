---
phase: 96-shared-telemetry-schema-and-bridge-contract
plan: 02
subsystem: ingest
tags: [tetragon, bridges, polling, health]
requirements-completed: [BRIDGE-02]
one-liner: "`TetragonBridge` now implements `TelemetryBridge`, keeps reconnect and mapping coverage, and consumes the shared schema directly from `swarm-core`."
completed: 2026-04-06
---

# Phase 96 Plan 02 Summary

**`TetragonBridge` now implements `TelemetryBridge`, keeps reconnect and mapping coverage, and consumes the shared schema directly from `swarm-core`.**

## Accomplishments

- Refactored `TetragonBridge` onto the shared `TelemetryBridge` contract with `source_id()`, async `poll()`, schema validation, and synchronous bridge-health snapshots.
- Preserved the existing channel-oriented `run()` and `run_once()` helpers as compatibility wrappers layered on top of trait-based polling instead of leaving channel coupling as the primary bridge contract.
- Added shared bridge-health tracking to the Tetragon bridge so readiness, processed-event counts, errors, lag, and the last error context stay available for later runtime registry and metrics work.
- Mapped `TelemetryBridgeError` into the existing ingest error surface so callers retain one crate-local error type even after the bridge contract moved into `swarm-core`.
- Updated `swarm-ingest-tetragon::mapper` to use the shared telemetry types from `swarm-core` directly and removed the crate's remaining `swarm-whisker` dependency so the phase actually resolves the schema ownership boundary.
- Extended unit coverage for successful `ProcessExec` mapping, malformed payload rejection, schema validation, processed-event health accounting, and reconnect-backoff behavior under the new trait shape.

## Files Created Or Modified

- `crates/swarm-ingest-tetragon/Cargo.toml`
- `crates/swarm-ingest-tetragon/src/bridge.rs`
- `crates/swarm-ingest-tetragon/src/error.rs`
- `crates/swarm-ingest-tetragon/src/mapper.rs`

## Verification

- `cargo test -p swarm-ingest-tetragon --lib`
- `cargo test -p swarm-runtime --lib`
- `cargo clippy -p swarm-core -p swarm-whisker -p swarm-ingest-tetragon -- -D warnings`

## Notes

- `poll()` currently returns one normalized event at a time inside a `Vec`, which keeps the shared bridge contract batch-friendly without forcing Tetragon to buffer multiple gRPC frames before yielding.
- The bridge now uses `BridgeHealth` as the canonical health surface, so later runtime phases can surface bridge metrics without inventing a second status model.
