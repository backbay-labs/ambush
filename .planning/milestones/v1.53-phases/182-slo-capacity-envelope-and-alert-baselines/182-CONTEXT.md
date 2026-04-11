# Phase 182: SLO, Capacity Envelope, And Alert Baselines - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 182 turns the supported packaging and recovery baseline into measured operational guidance. The target is not another microbenchmark note. It is one end-to-end SLO and alert contract tied to the supported runtime profile, hardware assumptions, and measured readiness or degradation behavior.

</domain>

<decisions>
## Implementation Decisions

- Reuse the Phase 180 production profile and the Phase 181 recovery baseline as the topology under test instead of inventing a second benchmark environment.
- Prefer end-to-end runtime metrics, readiness behavior, and measured load evidence over detector-only microbenchmarks.
- Replace or qualify heuristic capacity guidance in the docs when it is not backed by measured runtime behavior.

</decisions>

<code_context>
## Existing Code Insights

- [fast-detection.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/benchmarks/fast-detection.md) already provides a detector-only local microbenchmark, but it explicitly excludes external I/O and JetStream, so it cannot serve as the production SLO source of truth.
- The runtime already publishes Prometheus stage metrics, heap-pressure gauges, and readiness surfaces through `CriticalPathMetrics` and the ingest health handlers, which gives Phase 182 shipped observability seams to anchor load and alert guidance.
- [CONFIGURATION.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/CONFIGURATION.md) still carries heuristic population-scaling guidance by telemetry volume; Phase 182 needs to either replace or explicitly bound that guidance with measured end-to-end evidence.
- Phase 181 now defines the supported durability and recovery topology, so hardware and state-root assumptions for the SLO envelope no longer need to be inferred from ad hoc local layouts.

</code_context>

<deferred>
## Deferred Ideas

- Multi-operator authentication and attributable approval work remain Phase 183.
- Containerized JetStream CI load harness work in later milestones should build on Phase 182's published envelope rather than replacing the supported-profile contract.

</deferred>
