# Phase 182 Verification

status: passed

## Result

Phase 182 verification passed.

## Commands

- `cargo fmt --all`
- `cargo run -p swarm-runtime --release --example fast_detection_bench`
- `cargo run -p swarm-runtime --release --example end_to_end_ingest_bench`
- `cargo test -p swarm-runtime --lib encode_metrics_renders_all_histograms`
- `cargo test -p swarm-runtime ingest_router_coexists_with_metrics_endpoint -- --exact`
- `rg -n "Measured SLO And Capacity Envelope|Scaling Guidance|Operational Envelope|End-To-End Ingest Benchmark|swarm_ingest_request_latency_microseconds|swarm_ingest_events_total" docs/CONFIGURATION.md docs/ARCHITECTURE.md docs/benchmarks/end-to-end-ingest.md docs/benchmarks/fast-detection.md crates/swarm-runtime/src/detection/metrics.rs crates/swarm-runtime/tests/ingest_integration.rs -S`

## Verified Behaviors

- The hot-path benchmark is runnable again and now reports current measured
  detector-plus-deposit numbers instead of failing on signer identity mismatch.
- The new end-to-end ingest benchmark measures the real detect HTTP surface and
  confirms `/readyz`, `/healthz`, and `/metrics` stay healthy after the measured
  run on the reference host.
- `/metrics` now exposes `swarm_ingest_request_latency_microseconds` and
  `swarm_ingest_events_total` alongside the existing stage-latency and
  heap-pressure series, which makes the documented SLO and alert guidance
  queryable from shipped telemetry instead of prose alone.
- The docs now distinguish detector-only regression numbers from the
  operator-facing ingest envelope, publish the reference host assumptions, and
  replace heuristic scaling tables with measured latency and event-rate guardrails.

## Notes

- The durable JetStream rerun command is documented, but Phase 182 verification
  itself stays on the shipped local-journal reference run. Later `v1.55`
  JetStream harness work is still responsible for automated durable-substrate
  benchmarking.

