# Phase 152 Verification

status: passed

## Result

Phase 152 verification passed.

## Commands

- `cargo test -p swarm-core config::tests::operator_surface_requires_positive_widget_token_ttl_when_enabled -- --exact`
- `cargo test -p swarm-core config::tests::operator_surface_rejects_invalid_embed_origin -- --exact`
- `cargo test -p swarm-runtime --lib ingest::tests::demo_widget_endpoint_sets_embed_headers_and_renders_scoped_context -- --exact`
- `cargo test -p swarm-runtime --lib ingest::tests::events_stream_filters_scoped_runtime_events_for_widget_context -- --exact`
- `cargo test -p swarm-runtime --lib ingest::tests::platform_api_read_routes_accept_context_token_for_scoped_queries -- --exact`
- `cargo test -p swarm-runtime --lib ingest::tests::providence_webhook_payload_includes_runtime_context_and_links -- --exact`
- `cargo fmt --all`
- `cargo check -p swarm-core -p swarm-spine -p swarm-pheromone -p swarm-runtime --tests -j 1 --message-format short`

## Verified Behaviors

- Widget embed policy fails closed on invalid origins or zero TTL and is exposed through the repo-owned default config and docs.
- `/v1/demo/widget` serves a self-contained Providence embed surface with scoped runtime links and the configured `frame-ancestors` plus `X-Frame-Options` headers.
- Runtime SSE filtering respects hunt-scoped widget context instead of leaking adjacent activity from unrelated hunts.
- Providence drilldown links now carry short-lived signed context tokens whose scope is verified before the runtime serves read-only platform findings or incidents data.
