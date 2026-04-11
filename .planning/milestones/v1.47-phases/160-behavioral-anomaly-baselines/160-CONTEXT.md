# Phase 160: Behavioral Anomaly Baselines - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 160 adds a stateful `BehavioralAnomalyDetector` that learns per-host process ancestry baselines, decays that state over time, and persists restart-safe snapshots through the durable pheromone substrate.

</domain>

<decisions>
## Implementation Decisions

- Persist behavioral baseline state as typed `BehavioralBaselineSnapshot` records in the substrate instead of detector-owned sidecar files so all durable backends can support restart-safe learning.
- Keep the detector stateful inside `swarm-whisker`, but hydrate and persist it through the existing runtime detection-pipeline seam so composite detectors and runtime-selected strategies reuse one persistence path.
- Limit the phase to process-start ancestry, binary novelty, and role-tool anomaly scoring. Broader role semantics and additional telemetry families stay deferred.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-whisker/src/detector.rs` already provides the trait boundary needed for a new stateful detector, but runtime-owned hydration needs object-safe detector introspection.
- `crates/swarm-pheromone/src/substrate.rs` and `crates/swarm-pheromone/src/jetstream.rs` already own durable journal or key-value persistence, so baseline snapshots belong there rather than in `swarm-runtime`.
- `crates/swarm-runtime/src/detection/pipeline.rs` is the only place that sees the detector, substrate, and event together on the hot path, which makes it the correct seam for one-time hydration and dirty-state persistence.
- `crates/swarm-runtime/src/config.rs` and `rulesets/default.yaml` already define the repo-owned profile merge path used by every other detector strategy.

</code_context>

<deferred>
## Deferred Ideas

- Evasion corpus pressure and detector robustness scoring remain v1.48 work.
- Cross-host behavioral clustering and richer identity-role baselines remain future follow-on work after the single-host restart-safe baseline proves out.

</deferred>
