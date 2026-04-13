# Phase 190: Hot Path Criterion Benchmarks - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 190 follows the shipped JetStream substrate parity work by adding
repo-owned Criterion benchmarks for the bounded ingest -> detect -> deposit ->
escalate hot path. Phase 189 proved durable backend semantics; this phase
measures latency distributions for that slice without widening into sustained
throughput or readiness-shedding analysis, which remains Phase 191.

</domain>

<decisions>
## Implementation Decisions

- Add benchmark coverage inside the production runtime crate instead of relying
  only on manually timed example binaries.
- Reuse the existing synthetic suspicious-process benchmark fixtures and the
  repo-owned JetStream harness where the durable backend needs to be exercised.
- Record p50, p95, and p99 results with the exact workload contract in repo docs
  so later phases can compare against a stable baseline.

</decisions>

<code_context>
## Existing Code Insights

- [fast_detection_bench.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/examples/fast_detection_bench.rs)
  already measures detector-to-deposit latency with manual timing against the
  in-memory substrate, but it is an example binary rather than a Criterion
  benchmark and it does not include the broader hot-path contract.
- [end_to_end_ingest_bench.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/examples/end_to_end_ingest_bench.rs)
  already measures the shipped HTTP ingest surface for `local_journal` and
  `jet_stream`, but it is an operator-facing example workload rather than a
  repo-owned microbenchmark harness.
- [Cargo.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/Cargo.toml)
  currently has no `criterion` dependency and no `[[bench]]` targets, so the
  runtime crate has no first-class benchmark entrypoint yet.
- [fast-detection.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/benchmarks/fast-detection.md)
  and [end-to-end-ingest.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/benchmarks/end-to-end-ingest.md)
  already publish measured benchmark data; Phase 190 should keep that benchmark
  documentation aligned with the new Criterion-owned hot-path slice instead of
  replacing the operator-facing ingest benchmark.
- `swarm-runtime/src/detection/metrics.rs` already defines ingest, detect,
  policy, and response latency histograms, giving the benchmark work a clear
  runtime vocabulary to mirror.

</code_context>

<deferred>
## Deferred Ideas

- Sustained throughput, readiness shedding, and host-profile envelope capture
  remain Phase 191 work.
- CI regression gating on benchmark thresholds can follow once the first
  Criterion baseline is stable and documented.

</deferred>
