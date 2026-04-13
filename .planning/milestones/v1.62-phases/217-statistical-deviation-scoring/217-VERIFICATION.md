# Phase 217 Verification

status: passed

## Result

Phase 217 verification passed.

## Commands

- `cargo test -p swarm-whisker behavioral_anomaly -- --nocapture`
- `cargo test -p swarm-runtime --lib 'config::tests::behavioral_anomaly_profile_merges_overrides' -- --exact --nocapture`
- `cargo test -p swarm-pheromone --lib local_journal_recovers_behavioral_baseline_snapshots_after_reopen -- --nocapture`
- `cargo fmt --all`

## Verified Behaviors

- `BehavioralAnomalyDetector` now derives confidence from explicit
  `deviation_scoring` evidence built on per-scope z-scores and sample-support
  weighting instead of the earlier implicit learned-span mapping.
- Runtime config merging preserves repo-owned `behavioral_anomaly` overrides
  for `high_confidence_z_score`, and invalid deviation bounds fail closed at
  profile validation time.
- Restart-safe behavioral baseline snapshots still survive local-journal
  persistence and reopen through the existing substrate contract after the
  detector-side scoring model change.
