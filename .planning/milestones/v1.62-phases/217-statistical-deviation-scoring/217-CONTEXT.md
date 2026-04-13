# Phase 217: Statistical Deviation Scoring - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 217 turns the learned per-scope novelty distributions added in Phase 216
into one explicit statistical deviation model for behavioral anomaly scoring,
instead of the current bounded confidence-from-distribution span mapping.

</domain>

<decisions>
## Implementation Decisions

- Build directly on the persisted online novelty distributions already stored in
  the behavioral baseline snapshot. Do not introduce a second detector-state
  store.
- Keep the work bounded to the existing `BehavioralAnomalyDetector`
  process-start path so the phase closes anomaly scoring before Phase 218
  widens telemetry breadth.
- Surface the chosen deviation model in evidence so operators can see how one
  score was derived, not just the final confidence number.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-whisker/src/behavioral_anomaly.rs` now persists one online
  novelty distribution per host, identity, and peer-group scope and emits
  `confidence_learning` evidence for the learned-confidence path.
- `crates/swarm-core/src/pheromone.rs` already carries the restart-safe
  `BehavioralOnlineDistributionSnapshot` schema, so Phase 217 can reuse that
  baseline contract without widening substrate responsibilities.
- `crates/swarm-runtime/src/config.rs` already merges and validates the new
  behavioral-anomaly learning knobs, which is the natural place for any
  additional deviation-scoring tuning bounds this phase may require.

</code_context>

<deferred>
## Deferred Ideas

- Extending learned behavioral scoring to network, DNS, authentication, file,
  and memory telemetry remains Phase 218 work.
- Measuring false-positive reduction against labeled telemetry remains the
  dedicated benchmark phase in 219.

</deferred>
