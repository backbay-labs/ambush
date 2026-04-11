# Phase 150 Verification

status: passed

## Result

Phase 150 verification passed.

## Commands

- `cargo check -p swarm-spine -p swarm-runtime --tests -j 1 --message-format short`
- `cargo test -p swarm-runtime providence::tests:: -- --nocapture`
- `cargo test -p swarm-runtime ingest::tests::providence_webhook_payload_includes_runtime_context_and_links -- --exact`
- `cargo test -p swarm-runtime ingest::tests::healthz_includes_providence_component_when_configured -- --exact`
- `cargo test -p swarm-runtime ingest::tests::readyz_reports_providence_auth_failure -- --exact`
- `cargo test -p swarm-runtime service::tests:: -- --nocapture`
- `cargo test -p swarm-spine incident::tests::file_store_upserts_external_reference_and_persists_it -- --exact`

## Verified Behaviors

- Correlated incidents now persist Providence external references and the trigger metadata needed to compute a stable create-by-key incident identifier.
- The Providence adapter can create, update, and resolve one remote incident per durable incident key and survives restart through the persisted external reference on `IncidentRecord`.
- Failed Providence writes retry with exponential backoff and are dead-lettered after the third failure instead of failing silently.
- `/healthz` and `/readyz` now expose Providence integration health and fail readiness when Providence authentication or write acceptance is degraded.
- Filtering `providence_webhook` out of the generic `NotificationRouter` did not regress the existing runtime service test suite.
