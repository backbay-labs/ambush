# Phase 191: Sustained Throughput Load Test - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 191 follows the new Phase 190 Criterion baseline by measuring the shipped
HTTP ingest surface under sustained load until readiness shedding activates.
This phase owns the operator-facing throughput ceiling and readiness-threshold
artifact. It does not widen into CI perf gates or a universal JetStream ceiling.

</domain>

<decisions>
## Implementation Decisions

- Extend the existing
  [end_to_end_ingest_bench.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/examples/end_to_end_ingest_bench.rs)
  example instead of introducing a second load-test binary.
- Keep the existing fixed steady-state workload and add a monotonic
  `ramp_until_shed` mode with live `/readyz` polling so the same tool can report
  both the steady-state envelope and the first readiness-shedding stage.
- Document the measured host profile, the explicit heap-pressure threshold used
  to make shedding observable on a large developer machine, and the rerun
  contract operators must use on deployment-class hardware.

</decisions>

<code_context>
## Existing Code Insights

- [end_to_end_ingest_bench.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/examples/end_to_end_ingest_bench.rs)
  already boots the shipped detect HTTP router, measures accepted ingest
  throughput, and confirms `/readyz`, `/healthz`, and `/metrics` after the run.
- [health.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/health.rs)
  marks `/readyz` unhealthy when sampled heap pressure exceeds
  `runtime.max_heap_pressure`, so a load-test ceiling can be expressed against
  the same readiness surface operators already monitor.
- [metrics.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/detection/metrics.rs)
  already exports ingest latency, accepted-event rate, detect latency, policy
  latency, and heap-pressure series that the docs can anchor to.
- [end-to-end-ingest.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/benchmarks/end-to-end-ingest.md)
  and [CONFIGURATION.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/CONFIGURATION.md)
  already treat this example as the operator-facing envelope artifact, so Phase
  191 should extend that contract instead of creating a separate benchmark doc.

</code_context>

<deferred>
## Deferred Ideas

- JetStream-specific ceiling numbers on durable deployment hardware remain an
  operator rerun, not a checked-in universal claim.
- CI threshold gating on throughput regressions remains future work once the
  load profile is stable enough to automate.

</deferred>
