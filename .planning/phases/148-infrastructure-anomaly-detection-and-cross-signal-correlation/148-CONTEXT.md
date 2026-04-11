# Phase 148: Infrastructure Anomaly Detection And Cross-Signal Correlation - Context

**Gathered:** 2026-04-09
**Status:** Ready for execution

<domain>
## Phase Boundary

Phase 148 turns the normalized Sentinel infrastructure lane into live detection. The work is detector-side: interpret infrastructure payloads, route them through the existing pheromone and escalation pipeline, and prove that infrastructure findings combine with behavioral findings through the shared distinct-source model.

</domain>

<decisions>
## Implementation Decisions

### Detector Shape
- Add a dedicated `InfrastructureAnomalyDetector` to `swarm-whisker` instead of embedding infrastructure rules into bridge code or escalation code.
- Keep the detector stateful but bounded with per-node in-memory correlation state; no new durable detector storage is needed for this milestone.

### Correlation Model
- Reuse the existing strategy-scoped pheromone deposit flow and `distinct_sources` escalation logic instead of inventing a second correlation pipeline.
- Map infrastructure signals into existing threat classes that already participate in the alert path: `Execution` for cryptominer-style resource hijack, `Impact` for destructive exhaustion, and `DefenseEvasion` for low-noise memory pressure patterns.

### Scope Discipline
- Keep Kubernetes workload-context suppression, full Sentinel-style long-horizon statistical baselines, and broader infrastructure forensics out of scope for this phase.
- The phase only needs detector config, runtime factory wiring, unit coverage, and one end-to-end cross-signal escalation proof.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-whisker/src/*.rs` already contains the profile, detector, and test shape expected for a new strategy.
- `crates/swarm-runtime/src/detector_factory.rs` and `crates/swarm-runtime/src/config.rs` are the runtime seams for exposing a new detector strategy from repo-owned config.
- `crates/swarm-runtime/src/detection/pipeline.rs` already scopes deposits by `strategy_id`, which means infrastructure and behavioral findings naturally contribute independent `distinct_sources`.
- `crates/swarm-runtime/tests/multi_strategy_integration.rs` already proves multi-strategy escalation and is the right place to verify cross-signal correlation without inventing a separate harness.

### Integration Points
- `DetectorProfilesConfig` in `crates/swarm-core/src/config.rs` must accept an `infrastructure_anomaly` profile payload.
- `build_composite_detector()` only needs new factory support; the existing composite detector and pheromone pipeline can stay unchanged.
- Sentinel bridge events already arrive as `InfrastructureHealth`, `ThermalAnomaly`, and `ResourceExhaustion`; the detector just needs to consume those payloads.

</code_context>

<deferred>
## Deferred Ideas

- Full Sentinel statistical baselines, Kubernetes workload-context suppression, and richer false-positive suppression remain future refinement work.
- Evolution mutation/candidate tooling for `infrastructure_anomaly` remains separate from this milestone’s live-detection scope.

</deferred>
