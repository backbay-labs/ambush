---
phase: 98-runtime-bridge-registry-and-health-surface
plan: 02
subsystem: observability
tags: [bridges, healthz, metrics, operator-status]
requirements-completed: [BRIDGE-05]
one-liner: "Bridge health now appears on operator status, `/healthz`, and `/metrics` without letting degraded bridge workers break core detector readiness."
completed: 2026-04-07
---

# Phase 98 Plan 02 Summary

**Bridge health now appears on operator status, `/healthz`, and `/metrics` without letting degraded bridge workers break core detector readiness.**

## Accomplishments

- Added bridge-aware Prometheus gauges to `CriticalPathMetrics` for readiness, processed-event counts, error counts, and lag seconds keyed by bridge name plus source id.
- Extended `OperatorStatusReport` with an optional bridge-health report and warning generation so operators can see degraded bridge workers from the same runtime status surface they already use.
- Extended `/healthz` to include a `bridges` component with configured, ok, degraded, idle, and per-bridge entry details while preserving the existing detector/substrate readiness gate.
- Added integration coverage proving degraded bridge state is visible on `/healthz` and bridge metrics render on `/metrics` without corrupting the serve-mode detection path.
- Kept bridge health reporting read-only and snapshot-based so the HTTP surface never owns or mutates live bridge worker state.

## Files Created Or Modified

- `crates/swarm-runtime/src/detection/metrics.rs`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/tests/ingest_integration.rs`

## Verification

- `cargo fmt --all`
- `cargo test -p swarm-runtime ingest --lib`
- `cargo test -p swarm-runtime --test ingest_integration`
- `cargo test -p swarm-runtime service --lib`
- `cargo clippy -p swarm-core -p swarm-runtime --tests -- -D warnings`

## Notes

- Bridge visibility is intentionally attached to `/healthz` rather than redefining `/readyz`; the core detector readiness contract remains stable for existing operators.
- The operator status and `/healthz` surfaces both consume `BridgeStatusReport`, which keeps per-bridge aggregation logic in one place.
