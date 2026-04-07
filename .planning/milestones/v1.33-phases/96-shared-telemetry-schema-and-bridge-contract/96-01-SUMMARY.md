---
phase: 96-shared-telemetry-schema-and-bridge-contract
plan: 01
subsystem: core
tags: [telemetry, bridges, schema, compatibility]
requirements-completed: [BRIDGE-01]
one-liner: "Shared telemetry types and the `TelemetryBridge` contract now live in `swarm-core`, with compatibility re-exports keeping detector and runtime callers compiling."
completed: 2026-04-06
---

# Phase 96 Plan 01 Summary

**Shared telemetry types and the `TelemetryBridge` contract now live in `swarm-core`, with compatibility re-exports keeping detector and runtime callers compiling.**

## Accomplishments

- Added `crates/swarm-core/src/telemetry.rs` as the canonical home for `TelemetryEvent`, `TelemetryPayload`, the shared payload structs, `BridgeHealth`, `TelemetryBridgeError`, `TelemetryBridgeResult`, and the new `TelemetryBridge` trait.
- Re-exported the shared telemetry and bridge contract from `swarm-core` so downstream crates can depend on one canonical schema surface instead of importing normalized events through `swarm-whisker`.
- Updated `swarm-whisker` to re-export the moved telemetry types from `swarm-core`, preserving compatibility for existing detector and runtime imports while removing the crate-boundary cycle that blocked a core-owned bridge contract.
- Kept the bridge contract async where it matters (`poll`) and made `health()` a synchronous snapshot API, which avoids forcing streaming bridge implementations to satisfy unnecessary `Sync` and send-future constraints.
- Added unit coverage for the shared bridge-health bookkeeping and verified that detector/runtime crates still compile cleanly against the moved schema.

## Files Created Or Modified

- `crates/swarm-core/src/telemetry.rs`
- `crates/swarm-core/src/lib.rs`
- `crates/swarm-whisker/src/detector.rs`

## Verification

- `cargo test -p swarm-core --lib`
- `cargo test -p swarm-whisker --lib`
- `cargo test -p swarm-runtime --lib`
- `cargo clippy -p swarm-core -p swarm-whisker -p swarm-ingest-tetragon -- -D warnings`

## Notes

- `swarm-whisker` remains a compatibility surface for telemetry imports, but the canonical normalized schema now lives in `swarm-core`.
- The shared bridge trait intentionally requires `Send` but not `Sync` because `poll(&mut self)` already models exclusive ownership of streaming bridge state.
