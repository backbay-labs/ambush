# Phase 83: Tetragon Bridge Port -- Context

## User Decisions

### Locked Decisions

1. **New crate `swarm-ingest-tetragon`** -- The bridge is a separate crate, not a module inside swarm-runtime. This keeps gRPC/proto build deps isolated and the runtime crate focused.
2. **Use tonic + prost for gRPC** -- Same stack as the vendor reference bridge. Proto compiled via tonic-build in build.rs.
3. **Copy proto from vendor reference** -- The Tetragon proto file at `vendor/reference/clawdstrike/bridges/tetragon-bridge/proto/tetragon.proto` is copied into the new crate. No external proto fetch.
4. **Publish directly into detection pipeline** -- Unlike the reference bridge which publishes to NATS, the ported bridge maps Tetragon events to `TelemetryPayload` and feeds them through the existing `detect_and_deposit` pipeline function. No NATS, no Spine envelopes, no signing.
5. **Map ProcessExec to TelemetryPayload::ProcessStart** -- The primary mapping. ProcessExit and ProcessKprobe are logged and counted but not mapped to TelemetryPayload variants in this phase (future work).

### Deferred Ideas

- ProcessExit and ProcessKprobe to TelemetryPayload mapping (no variants exist yet)
- NATS publish path (not needed -- direct pipeline integration)
- Namespace allowlist filtering (simplify for first port)
- SPIFFE identity binding
- Durable outbox retry queue
- Admin healthz/readyz endpoints for the bridge (the bridge runs inside swarm-detect, not as a standalone binary)

### Claude's Discretion

- Error type design for the bridge crate
- Reconnection backoff parameters (reference uses 100ms base, 30s max -- reasonable defaults)
- Whether to expose bridge config through SwarmConfig or a separate struct
- Test strategy for gRPC streaming without a real Tetragon instance

## Technical Context

### What Exists

- `TelemetryEvent` and `TelemetryPayload` in `swarm-whisker::detector` -- the normalization target
- `TelemetryPayload::ProcessStart(ProcessStartEvent)` with fields: parent_process, process_name, command_line, user
- `detect_and_deposit()` in `swarm-runtime::pipeline` -- the detection pipeline entry point
- Reference bridge at `vendor/reference/clawdstrike/bridges/tetragon-bridge/` -- complete working bridge with tonic gRPC client, proto, mapper, error types
- Tetragon proto at `vendor/reference/.../proto/tetragon.proto` -- minimal subset of Tetragon v1.3.x API (ProcessExec, ProcessExit, ProcessKprobe, FineGuidanceSensors service)

### What Phase 82 Provides (dependency)

- HTTP ingest endpoint with TelemetryPayload normalization and validation
- The normalization contract that this phase also targets (TelemetryPayload schema)
- The pattern for how external event sources feed into `detect_and_deposit`

### Key Mapping: Tetragon ProcessExec -> TelemetryPayload::ProcessStart

| Tetragon ProcessExec field | TelemetryPayload::ProcessStartEvent field |
|---|---|
| `process.binary` | `process_name` |
| `process.arguments` | `command_line` (binary + arguments) |
| `parent.binary` (or parent_exec_id) | `parent_process` |
| `process.uid` | `user` (UID as string, or "unknown") |
| `node_name` + `process.exec_id` | `event_id` |
| `process.start_time` or wallclock | `timestamp` |
| `"tetragon"` literal | `source` |
| `node_name` | `host_id` |
