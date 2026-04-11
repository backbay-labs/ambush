# Phase 182 Plan 01 Summary

## Delivered

- Added first-class ingest-envelope observability to the runtime by introducing
  `swarm_ingest_request_latency_microseconds` and
  `swarm_ingest_events_total` in
  [metrics.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/detection/metrics.rs),
  wiring those metrics through
  [mod.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/mod.rs),
  and extending
  [ingest_integration.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/tests/ingest_integration.rs)
  so the new request-latency and event-rate contract is verified on `/metrics`.
- Added a repeatable end-to-end benchmark command in
  [end_to_end_ingest_bench.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/examples/end_to_end_ingest_bench.rs)
  that boots the detect HTTP surface, measures loopback `POST /v1/ingest/events`
  against the real runtime, and confirms `/readyz`, `/healthz`, and `/metrics`
  after the run.
- Re-qualified the hot-path benchmark in
  [fast_detection_bench.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/examples/fast_detection_bench.rs)
  so it no longer panics on signer or agent-identity mismatch, and updated
  [fast-detection.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/benchmarks/fast-detection.md)
  with the new measured detector-only reference numbers.
- Published the measured operator contract in
  [end-to-end-ingest.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/benchmarks/end-to-end-ingest.md),
  [CONFIGURATION.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/CONFIGURATION.md),
  and [ARCHITECTURE.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/ARCHITECTURE.md),
  including reference-host assumptions, throughput and latency envelope, and
  alert thresholds tied to `/readyz` plus shipped Prometheus series instead of
  the old static population-scaling table.

## Notes

- The reference Phase 182 envelope is intentionally anchored to the shipped
  `local_journal` topology on the current host class. The docs now include the
  exact `STS_E2E_BENCH_BACKEND=jet_stream` rerun command operators must use
  before treating the reference ceiling as a durable production JetStream limit.
- Phase 182 stops short of containerized JetStream automation. That remains
  later `v1.55` work; this phase establishes the measured benchmark and
  observability contract that future harnesses will reuse.
- Removing the heuristic agent-count table was part of the deliverable. Scaling
  guidance is now expressed as measured latency and accepted-event-rate guardrails.

