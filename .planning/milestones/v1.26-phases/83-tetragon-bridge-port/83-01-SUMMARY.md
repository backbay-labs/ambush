---
phase: 83-tetragon-bridge-port
plan: 01
subsystem: ingest
tags: [tetragon, grpc, tonic, telemetry, bridge]
requirements-completed: [INGEST-03]
one-liner: "A new `swarm-ingest-tetragon` workspace crate now compiles Tetragon gRPC protos, maps `ProcessExec` events into normalized `TelemetryEvent`s, and forwards them through a retrying bridge loop."
completed: 2026-04-05
---

# Phase 83 Summary

**A new `swarm-ingest-tetragon` workspace crate now compiles Tetragon gRPC protos, maps `ProcessExec` events into normalized `TelemetryEvent`s, and forwards them through a retrying bridge loop.**

## Accomplishments

- Added `swarm-ingest-tetragon` to the workspace plus the required gRPC/protobuf dependencies and vendored-protoc build support.
- Ported the reference `tetragon.proto` and built a focused `TetragonClient` wrapper around `FineGuidanceSensorsClient`.
- Implemented `map_process_exec` so Tetragon `ProcessExec` events normalize directly into `TelemetryPayload::ProcessStart`.
- Added a minimal `TetragonBridge` that opens the gRPC stream, forwards mapped telemetry to a `tokio::sync::mpsc::Sender`, retries on gRPC failures, and fails cleanly on malformed messages or closed channels.
- Added unit tests for event mapping, empty-parent handling, fallback timestamps, malformed response handling, and channel-closure behavior.

## Files Created Or Modified

- `Cargo.toml`
- `crates/swarm-ingest-tetragon/Cargo.toml`
- `crates/swarm-ingest-tetragon/build.rs`
- `crates/swarm-ingest-tetragon/proto/tetragon.proto`
- `crates/swarm-ingest-tetragon/src/lib.rs`
- `crates/swarm-ingest-tetragon/src/error.rs`
- `crates/swarm-ingest-tetragon/src/client.rs`
- `crates/swarm-ingest-tetragon/src/mapper.rs`
- `crates/swarm-ingest-tetragon/src/bridge.rs`

## Verification

- `cargo test -p swarm-ingest-tetragon`
- `cargo build -p swarm-ingest-tetragon`

## Notes

- The crate is intentionally scoped to `ProcessExec` normalization for this milestone; richer event mapping can extend the same client and bridge surfaces later without changing the ingest contract.
