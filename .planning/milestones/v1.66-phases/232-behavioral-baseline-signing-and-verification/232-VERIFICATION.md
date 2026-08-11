# Phase 232 Verification

Date: 2026-04-13

- `CARGO_TARGET_DIR=target-v166 cargo test -p swarm-runtime behavioral_anomaly_detector_hydrates_persisted_baseline_after_restart --lib`
- `CARGO_TARGET_DIR=target-v166 cargo test -p swarm-pheromone local_journal_recovers_behavioral_baseline_snapshots_after_reopen --lib`
- `CARGO_TARGET_DIR=target-v166 cargo test -p swarm-pheromone local_journal_rejects_tampered_behavioral_baseline_snapshot_after_reopen --lib`
- `CARGO_TARGET_DIR=target-v166 cargo test -p swarm-pheromone local_journal_rejects_replayed_behavioral_baseline_snapshot_after_reopen --lib`

Result: Passed.
