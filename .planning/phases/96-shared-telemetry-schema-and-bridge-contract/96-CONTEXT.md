# Phase 96: Shared Telemetry Schema And Bridge Contract

## Vision

Telemetry ingestion graduates from ad hoc source-specific plumbing into a reusable bridge layer. The normalized telemetry schema moves into `swarm-core`, bridge crates share one canonical `TelemetryEvent` contract without crate cycles, and `TetragonBridge` becomes the first concrete implementation of a polling-based `TelemetryBridge` interface.

## Decisions

- Shared telemetry types move into `swarm-core` and are re-exported from `swarm-whisker` for compatibility rather than introducing a new schema crate
- `TelemetryBridge` lives in `swarm-core` beside the shared telemetry schema because multiple bridge crates and the runtime need the same contract
- `BridgeHealth` will report at least readiness, processed event count, error count, lag seconds, and last error context so later runtime health surfaces can reuse it directly
- `TetragonBridge` keeps its reconnect backoff logic but the primary interface becomes `poll()` plus `health()` instead of a mandatory `Sender<TelemetryEvent>` loop
- Compatibility matters in this phase: existing detector/runtime code should keep compiling through re-exports before any runtime bridge registry work begins

## Deferred Ideas

- A dedicated bridge registry/factory in the runtime
- Runtime config for bridge-specific options beyond existing telemetry source names
- Persistent bridge checkpoints or offsets for pull-based sources
- Per-bridge Prometheus metric families and operator HTTP surfaces

## Claude's Discretion

- Exact `TelemetryBridgeError` shape and naming
- Whether `TetragonBridge::poll()` yields single-event or batch results internally so long as the trait contract returns `Vec<TelemetryEvent>`
- Whether to keep a compatibility `run()` helper on `TetragonBridge` after trait adoption
- Exact `BridgeHealth` lag calculation strategy
