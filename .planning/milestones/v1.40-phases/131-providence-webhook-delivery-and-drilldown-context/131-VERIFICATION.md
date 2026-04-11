# Phase 131 Verification

status: passed

## Result

Phase 131 verification passed.

## Commands

- `cargo test -p swarm-core config::tests::operator_surface_requires_http_public_base_url_when_enabled -- --exact`
- `cargo test -p swarm-response notification::tests::router_uses_channel_specific_payload_builder_when_present -- --exact`
- `cargo test -p swarm-runtime ingest::tests::providence_webhook_payload_includes_runtime_context_and_links -- --exact`
- `cargo test -p swarm-runtime ingest::tests::demo_dashboard_snapshot_endpoint_reports_live_runtime_state -- --exact`
- `cargo test -p swarm-runtime portfolio::tests::portfolio_supports_curation_and_listing -- --exact`
- `cargo test -p swarm-runtime`

## Verified Behaviors

- A repo-owned `providence_webhook` channel now delivers Providence-shaped notifications through the existing notification router rather than a sidecar path.
- Providence payloads include `SwarmFindingEnvelope`, Providence incident fields for threat class and severity, aggregate counts and timestamps, and absolute links to replay, investigation, incident, review, and dashboard surfaces.
- The runtime enriches Providence payloads with current `SwarmMode`, registered and active agent counts, and bridge-health summary from the live serve path.
- The broader `swarm-runtime` package stays green after the Providence delivery work landed; package verification also surfaced and then cleared an unrelated brittle portfolio fixture ordering assumption in `portfolio.rs`.
