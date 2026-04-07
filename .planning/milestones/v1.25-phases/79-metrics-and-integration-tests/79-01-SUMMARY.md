---
phase: 79-metrics-and-integration-tests
plan: 01
subsystem: runtime
tags: [metrics, prometheus, operator-http, observability]
requirements-completed: [OPS-28]
one-liner: "Critical-path detection, policy, and response stages now emit Prometheus histograms and the operator surface exposes them at `/metrics`."
completed: 2026-04-05
---

# Phase 79: Metrics And Integration Tests Summary

**Critical-path detection, policy, and response stages now emit Prometheus histograms and the operator surface exposes them at `/metrics`.**

## Accomplishments

- Added a dedicated `metrics` runtime module backed by `prometheus-client`, with histogram metric families for detection, policy, and response latency in microseconds.
- Extended `RuntimeService` so every critical-path execution records the Prometheus histograms alongside the existing in-memory runtime metrics snapshots.
- Wired the operator HTTP surface to share the same registry and expose an unauthenticated `/metrics` endpoint that returns OpenMetrics text for scraper consumption.
- Added focused metrics unit coverage and an operator HTTP route test proving the endpoint content type and exported histogram families.

## Files Created Or Modified

- `Cargo.toml` - added the workspace-level `prometheus-client` dependency.
- `crates/swarm-runtime/Cargo.toml` - wired the runtime crate to the shared dependency and workspace lints.
- `crates/swarm-runtime/src/metrics.rs` - added the Prometheus registry, histograms, encoder, and unit test.
- `crates/swarm-runtime/src/service.rs` - attached Prometheus observers to critical-path execution.
- `crates/swarm-runtime/src/operator_http.rs` - exposed `/metrics` and shared the registry through HTTP state.
- `crates/swarm-runtime/src/lib.rs` - exported the new metrics module.

## Key Decisions

- Prometheus support was added alongside, not instead of, the existing internal runtime metrics so operator status snapshots and scraper-facing metrics can evolve independently.
- The `/metrics` route is intentionally left outside the bearer-token middleware so standard local Prometheus scraping works without special auth handling.
- Histogram buckets mirror the runtime’s existing microsecond-oriented latency ranges to keep internal and exported metrics comparable.

## Verification

- `cargo test -p swarm-runtime metrics:: --no-fail-fast`
- `cargo test -p swarm-runtime operator_http::tests::metrics_route_returns_openmetrics_without_auth -- --exact`
- `cargo clippy --workspace --all-targets -- -D warnings`

## Notes

- The current metrics surface is in-process and local to the operator service; no separate metrics exporter or dashboarding assets were added in this milestone.
