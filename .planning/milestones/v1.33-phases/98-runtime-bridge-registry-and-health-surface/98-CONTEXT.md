# Phase 98: Runtime Bridge Registry And Health Surface

## Vision

Bridge implementations stop being isolated crates and become a live runtime capability. Serve mode should construct only the configured bridge instances, poll them into the shared telemetry lane without breaking the existing HTTP ingest path, and surface bridge readiness and throughput on operator-visible health and metrics surfaces.

## Decisions

- The runtime will reuse the existing `telemetry_tx` channel that already feeds `WhiskerAgent`, so bridge workers and HTTP ingest share one normalized event entrypoint into the detection pipeline
- Bridge worker orchestration belongs near `swarm_detect`/`IngestState`, not inside detector or service code, because it is a serve-mode runtime concern rather than a critical-lane event-processing concern
- Bridge health must be stored outside the bridge worker tasks in a shared snapshot structure so `/healthz`, operator status, and Prometheus can read it without owning bridge instances directly
- `TelemetrySourceConfig.bridge` will need a `tetragon` variant so the runtime registry can construct all current bridge types from one config surface instead of hard-coding Tetragon as a special case forever
- Bridge failures should degrade bridge-specific health and metrics while leaving the existing HTTP ingest and agent runtime path intact

## Deferred Ideas

- Per-bridge backpressure controls or retry policy tuning beyond existing bridge-local behavior
- Dynamic add/remove of bridge workers on config reload without restarting the serve process
- Separate bridge worker pools or dedicated runtime executors
- Operator controls for pausing or replaying bridge sources

## Claude's Discretion

- Exact runtime module shape for bridge worker registration and health snapshot ownership
- Whether bridge polling runs in one supervisor task or one task per bridge instance so long as only configured bridges are built and polled
- Exact operator-status representation for bridge health so long as readiness, counts, lag, and last error are exposed
- Exact Prometheus metric names and labels for bridge health so long as event counts, error counts, and lag are queryable
