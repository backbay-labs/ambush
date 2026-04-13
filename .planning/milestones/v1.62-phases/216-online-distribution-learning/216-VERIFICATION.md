# Phase 216 Verification

status: passed

## Result

Phase 216 verification passed.

## Commands

- `cargo test -p swarm-whisker behavioral_anomaly -- --nocapture`
- `cargo test -p swarm-runtime --lib 'config::tests::behavioral_anomaly_profile_merges_overrides' -- --exact --nocapture`
- `cargo test -p swarm-pheromone --lib local_journal_recovers_behavioral_baseline_snapshots_after_reopen -- --nocapture`
- `cargo fmt --all`

## Verified Behaviors

- `BehavioralAnomalyDetector` no longer depends on the old fixed
  `signal_count`/`scope_hits` confidence arithmetic; a single-scope first-seen
  binary anomaly now receives confidence from learned online-distribution state
  and emits `confidence_learning` evidence.
- Behavioral profile validation fails closed for invalid online-learning
  bounds, and runtime config merging preserves repo-owned overrides for the new
  behavioral-anomaly tuning knobs.
- Restart-safe behavioral baseline snapshots, including the new learned
  novelty-distribution state, survive local-journal persistence and reopen
  through the existing substrate contract.
