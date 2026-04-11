# Phase 132 Summary

## Outcome

Phase 132 is implemented and verified.

- Added a repo-owned `platform_api` config section with scoped hashed keys so the detect server can authenticate `/v2/api/*` independently from the operator bearer-token surface.
- Introduced a dedicated platform API middleware path on the detect server that validates `x-api-key`, resolves `read` scope, and attaches the authenticated principal to request extensions for downstream logging.
- Added versioned `GET /v2/api/findings`, `GET /v2/api/incidents`, and `GET /v2/api/runtime/status` endpoints behind one `{ data, cursor }` envelope with `page_size` default `50`, max `200`, and cursor pagination on the list routes.
- Backed findings from persisted replay bundles and incidents from the durable incident store so the new platform API reads the same artifacts the runtime already owns.
- Added focused config and detect-server tests for auth boundaries, findings pagination and filtering, incidents pagination and filtering, and runtime-status output, then rechecked the existing SSE and health routes to catch detect-router regressions.
- Updated the runtime test/sample `SwarmConfig` builders to carry the new `platform_api` field so the workspace compiles cleanly on the Phase 132 contract.

## Files

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/canary.rs`
- `crates/swarm-runtime/src/evidence.rs`
- `crates/swarm-runtime/src/http/core.inc`
- `crates/swarm-runtime/src/promotion.rs`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/strategy.rs`
- `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs`
- `crates/swarm-runtime/tests/operational_hardening_integration.rs`

## Verification

- `cargo test -p swarm-core config::tests::platform_api_rejects_invalid_key_hash -- --exact`
- `cargo test -p swarm-runtime ingest::tests::platform_ -- --nocapture`
- `cargo test -p swarm-runtime ingest::tests::events_stream_filters_typed_runtime_events -- --exact`
- `cargo test -p swarm-runtime ingest::tests::healthz_returns_ok_with_component_status -- --exact`
