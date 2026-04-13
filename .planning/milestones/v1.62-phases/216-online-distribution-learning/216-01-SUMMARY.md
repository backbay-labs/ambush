# Phase 216 Plan 01 Summary

## Delivered

- Extended the shared behavioral baseline schema in
  `crates/swarm-core/src/pheromone.rs` so each host, identity, and peer-group
  baseline now persists restart-safe online novelty-distribution state through
  `BehavioralOnlineDistributionSnapshot` instead of keeping learned confidence
  inputs in memory only.
- Updated `crates/swarm-whisker/src/behavioral_anomaly.rs` so
  `BehavioralAnomalyDetector` now learns one online novelty distribution per
  scope, snapshots and hydrates that state through the existing baseline seam,
  and derives finding confidence from learned scope pressure rather than the
  old fixed `signal_count` and `scope_hits` arithmetic.
- Surfaced the learned path explicitly in finding evidence. Behavioral anomaly
  findings now include `confidence_learning` with the online-distribution model
  name, learned sample counts, distribution moments, and per-scope confidence
  ratios, so the detector explains why learned confidence rose above the
  previous fixed-threshold floor.
- Updated runtime profile wiring in `crates/swarm-runtime/src/config.rs` so
  repo-owned `behavioral_anomaly` profile overrides can now tune
  `distribution_min_observations` and `distribution_stddev_floor`, and the
  profile validator fails closed on invalid learning bounds.
- Kept the phase bounded to the existing process-start behavioral detector.
  This work does not yet widen learning to other telemetry families or define
  the final explicit deviation model reserved for Phase 217.

## Notes

- The existing behavioral baseline snapshot path in `swarm-pheromone` remains
  the only persistence seam. Phase 216 did not add a second journal or state
  file for learned detector statistics.
- Learned confidence now reacts to per-scope novelty pressure and preserved
  online history, but the explicit z-score or percentile-style anomaly scoring
  contract remains the dedicated follow-up in Phase 217.
