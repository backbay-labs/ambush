# Phase 217 Plan 01 Summary

## Delivered

- Replaced the Phase 216 learned-span confidence path in
  `crates/swarm-whisker/src/behavioral_anomaly.rs` with one explicit
  support-weighted z-score model built directly on the persisted per-scope
  novelty distributions already carried in the shared behavioral baseline
  snapshot.
- Added one repo-owned deviation tuning bound,
  `high_confidence_z_score`, to `BehavioralAnomalyProfile`. The detector now
  maps aggregate deviation score into the existing medium-to-high confidence
  range by clamping against that explicit z-score cap instead of relying on
  the earlier implicit span arithmetic.
- Surfaced the scoring path directly in finding evidence. Behavioral anomaly
  findings now emit `deviation_scoring` with the `z_score` model name,
  aggregate deviation score, sample-support weighting, and per-scope learned
  moments so operators can see how one anomaly score was produced.
- Updated the runtime config merge path in `crates/swarm-runtime/src/config.rs`
  so repo-owned `behavioral_anomaly` profile overrides can tune
  `high_confidence_z_score` alongside the Phase 216 learning bounds, and the
  validator fails closed when that new deviation bound is invalid.
- Kept the phase bounded to the existing process-start detector and restart-safe
  baseline snapshot seam. Phase 217 does not widen evaluation into the other
  telemetry families; that breadth expansion remains the dedicated follow-up in
  Phase 218.

## Notes

- The detector still learns and persists one novelty distribution per host,
  identity, and peer-group scope through the shared behavioral snapshot
  contract; Phase 217 changed the scoring model, not the persistence seam.
- The explicit model is a support-weighted z-score: each scope computes
  deviation from the learned novelty mean over the floored standard deviation,
  then dampens that score according to available sample support before the
  aggregate deviation score is mapped into the configured confidence band.
