# Phase 185 Verification

status: passed

## Result

Phase 185 verification passed.

## Commands

- `cargo fmt --all`
- `cargo test -p swarm-runtime malformed_event_is_rejected`
- `cargo test -p swarm-runtime resolve_demo_scope_rejects_requested_fields_outside_token_scope`
- `cargo test -p swarm-runtime live_response_requires_durable_substrate_when_enabled`
- `cargo test -p swarm-runtime control_service_readiness_error_maps_to_internal_api_error`
- `cargo test -p swarm-runtime --lib portfolio_invalid_request_maps_to_bad_request`
- `cargo test -p swarm-runtime --lib review_evidence_artifact_not_found_maps_to_not_found`
- `cargo test -p swarm-runtime --lib handler_rejects_malformed_batch`
- `cargo test -p swarm-runtime --lib rehearse_bundle_fails_closed_before_executor_when_scope_metadata_is_missing`
- `cargo test -p swarm-runtime --lib review_surface_renders_html_shell_and_evidence_pages`
- `cargo test -p swarm-runtime --lib demo_widget_endpoint_sets_embed_headers_and_renders_scoped_context`

## Verified Behaviors

- Malformed ingest payloads now fail through `IngestRequestError` instead of a plain `String`, and the HTTP ingest surface still returns the expected rejected-event envelope.
- Providence-scoped demo requests now reject out-of-scope query fields through an explicit `ContextScopeMismatch` variant before the edge serializes the error for the client.
- Durable-live-response substrate failures now surface as typed `ReadinessError` variants inside `ServiceError`, and representative operator-surface control failures map through named HTTP adapters rather than inline blanket string flattening.
- Review, evidence, portfolio, governance, and maintenance handlers continue to return stable operator responses while consuming typed runtime and store errors behind the HTTP boundary.

## Notes

- The `cargo test -p swarm-runtime <filter>` commands still walk the crate’s other binaries and integration targets with zero matched tests, which is normal Cargo behavior for filtered runs and not a verification gap.
