# Phase 218: Multi-Telemetry Behavioral Extension - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 218 extends the learned behavioral-baseline path beyond process starts
so the shipped behavioral anomaly strategy can learn bounded per-entity norms
for the other telemetry families already present on the shared telemetry
schema.

</domain>

<decisions>
## Implementation Decisions

- Keep the work inside the existing `BehavioralAnomalyDetector` and shared
  behavioral baseline snapshot seam rather than introducing separate detectors
  or a second persistence store for non-process telemetry.
- Extend only the shipped telemetry families called out by the roadmap:
  network, DNS, authentication, file-oriented, and memory-oriented events.
  Do not widen into unrelated behavioral ideas during this phase.
- Preserve structured strategy attribution and evidence naming so operators can
  distinguish which telemetry family produced a behavioral anomaly after the
  detector broadens beyond process starts.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-whisker/src/behavioral_anomaly.rs` now owns restart-safe
  online novelty distributions plus explicit `deviation_scoring` evidence, but
  `evaluate()` still returns `Vec::new()` for every non-process payload.
- `crates/swarm-core/src/pheromone.rs` and the existing snapshot hydration path
  currently persist process-start-oriented behavioral features only, so Phase
  218 will likely need a bounded schema extension to carry non-process learned
  state through the same restart-safe seam.
- `crates/swarm-runtime/src/config.rs` already routes repo-owned
  `behavioral_anomaly` profile overrides through the shared detector-profile
  validation path, which is the natural place for any additional telemetry
  breadth knobs or defaults this phase requires.

</code_context>

<deferred>
## Deferred Ideas

- The labeled benchmark for false-positive reduction stays Phase 219 work.
- Evolution-driven tuning of the broadened behavioral detector remains outside
  this milestone phase boundary.

</deferred>
