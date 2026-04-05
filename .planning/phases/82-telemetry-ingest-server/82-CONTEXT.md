# Phase 82: Telemetry Ingest Server -- Context

## Decisions

- **Ingest route on swarm-detect binary**: The ingest endpoint is added to the same axum server that already serves `/metrics` in swarm-detect, not to the operator surface (swarmctl). No separate process.
- **POST /v1/ingest/events**: Endpoint accepts a JSON array of `TelemetryEvent` objects, processes them sequentially, returns per-event status.
- **No auth on ingest endpoint**: Same as `/metrics` -- unauthenticated, separate from the operator auth layer.
- **Use existing types**: `TelemetryEvent` and `TelemetryPayload` from swarm-whisker are the schema contract. Serde `deny_unknown_fields` already enforces strict validation on payload variants.
- **New ingest module**: Create `crates/swarm-runtime/src/ingest.rs` for the handler, request/response types, and validation logic. Keep it self-contained.
- **swarm-detect binary becomes a long-running server**: Currently swarm-detect processes scenario files and exits. Add a `--serve` flag that starts the axum server with both `/metrics` and `/v1/ingest/events`, listening until interrupted.

## Deferred Ideas

- Authentication on the ingest endpoint (planned for future deployment milestone)
- Rate limiting or backpressure
- Streaming/websocket ingest
- Batch-parallel processing (process sequentially for now)
- Content-type negotiation (JSON only)

## Claude's Discretion

- Error response shape (use a consistent JSON envelope with `accepted`/`rejected` arrays)
- Per-event error detail level
- How to wire RuntimeService into the handler state (Arc shared state pattern matching operator_http)
- Whether to add tracing spans for ingest events
