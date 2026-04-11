# Phase 131 Summary

## Outcome

Phase 131 is implemented and verified.

- Added repo-owned `operator.public_base_url` config and validation so outbound Providence payloads can carry absolute drilldown links back to the operator surface.
- Extended `NotificationRouter` with a runtime-installed channel payload builder so `providence_webhook` can emit Providence-shaped payloads without changing the generic notification channel contract.
- Wired the live runtime to enrich Providence payloads with `SwarmFindingEnvelope`, Providence incident fields, aggregate timestamps and counts, absolute replay and investigation links, the demo dashboard link, current `SwarmMode`, active agent counts, and bridge-health summary.
- Added an ingest-path end-to-end test that captures the real outbound Providence webhook and asserts runtime context plus stable drilldown URLs.
- While verifying the package-level runtime suite, fixed an unrelated brittle portfolio test fixture ordering assumption so `cargo test -p swarm-runtime` returns to green on the current tree.

## Files

- `crates/swarm-core/src/config.rs`
- `crates/swarm-response/src/notification.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/http/core.inc`
- `crates/swarm-runtime/src/portfolio.rs`

## Verification

- `cargo test -p swarm-core config::tests::operator_surface_requires_http_public_base_url_when_enabled -- --exact`
- `cargo test -p swarm-response notification::tests::router_uses_channel_specific_payload_builder_when_present -- --exact`
- `cargo test -p swarm-runtime ingest::tests::providence_webhook_payload_includes_runtime_context_and_links -- --exact`
- `cargo test -p swarm-runtime ingest::tests::demo_dashboard_snapshot_endpoint_reports_live_runtime_state -- --exact`
- `cargo test -p swarm-runtime portfolio::tests::portfolio_supports_curation_and_listing -- --exact`
- `cargo test -p swarm-runtime`
