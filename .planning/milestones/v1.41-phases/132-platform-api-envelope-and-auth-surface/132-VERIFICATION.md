# Phase 132 Verification

status: passed

## Result

Phase 132 verification passed.

## Commands

- `cargo test -p swarm-core config::tests::platform_api_rejects_invalid_key_hash -- --exact`
- `cargo test -p swarm-runtime ingest::tests::platform_ -- --nocapture`
- `cargo test -p swarm-runtime ingest::tests::events_stream_filters_typed_runtime_events -- --exact`
- `cargo test -p swarm-runtime ingest::tests::healthz_returns_ok_with_component_status -- --exact`

## Verified Behaviors

- `/v2/api/findings`, `/v2/api/incidents`, and `/v2/api/runtime/status` now exist on the detect server and return the shared `{ data, cursor }` envelope.
- Findings and incidents support cursor pagination plus filter parameters while enforcing default `page_size=50` and a hard cap of `200`.
- `/v2/api/*` requires a configured hashed `x-api-key` with `read` scope, while health probes and `/v1/ingest/events` remain unauthenticated.
- The detect-router composition change did not regress the pre-existing runtime SSE stream or health endpoint behavior.
