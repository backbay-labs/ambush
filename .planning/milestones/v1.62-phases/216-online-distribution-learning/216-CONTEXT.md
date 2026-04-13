# Phase 216: Online Distribution Learning - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 216 replaces `BehavioralAnomalyDetector`'s fixed confidence arithmetic
with learned per-entity online distributions while preserving the current
restart-safe behavioral baseline contract and bounded process-start anomaly
semantics.

</domain>

<decisions>
## Implementation Decisions

- Start with `BehavioralAnomalyDetector` only. DNS, auth, file, memory, and
  other telemetry families remain later milestone work.
- Extend the existing behavioral baseline snapshot instead of creating a second
  persistence lane for learned distribution state.
- Keep threat-class and severity semantics bounded in this phase; the main
  scope is replacing fixed confidence arithmetic with online learned
  distribution state, not choosing the final deviation scoring model for later
  phases.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-whisker/src/behavioral_anomaly.rs` already tracks host,
  identity, and peer-group baseline state, hydrates that state from durable
  snapshots, and currently computes confidence with a fixed
  `medium + 0.05 * signal_count + 0.03 * scope_hits` formula.
- `crates/swarm-core/src/pheromone.rs` owns the shared
  `BehavioralBaselineSnapshot` schema, so any learned online-distribution state
  that must survive restart needs to fit this repo-owned persistence contract.
- `crates/swarm-runtime/src/config.rs` and
  `crates/swarm-runtime/src/detector_factory.rs` already provide the runtime
  seam that validates and constructs `BehavioralAnomalyProfile`, which is the
  natural place to surface any new online-learning profile knobs.

</code_context>

<deferred>
## Deferred Ideas

- Choosing the final statistical deviation score shape (z-score, percentile,
  surprise, or equivalent) remains Phase 217 work.
- Extending learned baselines beyond process-start behavior to network, DNS,
  auth, file, and memory telemetry remains Phase 218 work.

</deferred>
