---
phase: 90-structured-logging-and-expanded-metrics
plan: 01
subsystem: runtime
tags: [observability, logging, metrics, ingest]
requirements-completed: [OBS-01, OBS-02]
one-liner: "ingest now assigns correlation IDs, `swarm_detect` emits flattened JSON logs, and Prometheus tracks verdict, guard, adapter, and finding counters across the hot path."
completed: 2026-04-05
---

# Phase 90 Plan 01 Summary

**ingest now assigns correlation IDs, `swarm_detect` emits flattened JSON logs, and Prometheus tracks verdict, guard, adapter, and finding counters across the hot path.**

## Accomplishments

- Added `correlation_id` to `ApprovalContext`, generated a UUID per ingest request, and threaded that identifier through ingest, runtime, policy, and response logging paths.
- Extended `CriticalPathMetrics` with counter families for verdicts, guard rejections, adapter outcomes, and findings while preserving the existing latency histograms.
- Recorded those counters from the runtime service at the actual decision points instead of leaving observability at histogram-only timing level.
- Switched `swarm_detect` to a JSON `tracing-subscriber` setup with flattened event fields and env-filter support.
- Expanded runtime tests to prove correlation IDs are returned per request and that Prometheus output includes the new counter families for success, timeout, guard rejection, and human-gated flows.

## Files Created Or Modified

- `Cargo.toml`
- `crates/swarm-runtime/Cargo.toml`
- `crates/swarm-policy/src/lib.rs`
- `crates/swarm-runtime/src/detection/metrics.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-runtime/src/control.rs`

## Verification

- `cargo test -p swarm-runtime --lib detection::metrics -- --nocapture`
- `cargo test -p swarm-runtime --lib ingest::tests::handler_ -- --nocapture`
- `cargo test -p swarm-runtime --lib service::tests::process_event_records -- --nocapture`
- `cargo test -p swarm-runtime --lib`
- `cargo test -p swarm-runtime`
- `cargo test --workspace`
- `cargo clippy -p swarm-core -p swarm-whisker -p swarm-response -p swarm-runtime -- -D warnings`

## Notes

- Correlation IDs are surfaced both in structured logs and in ingest HTTP responses so operators can tie a bad request or accepted batch back to runtime logs immediately.
- The metrics expansion stays inside the existing `CriticalPathMetrics` registry boundary, so existing `/metrics` export behavior remained stable.
