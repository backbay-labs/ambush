# Phase 160 Verification

status: passed

## Result

Phase 160 verification passed.

## Commands

- `cargo test -p swarm-runtime config::tests::behavioral_anomaly_profile_merges_overrides -- --exact`
- `cargo test -p swarm-whisker behavioral_anomaly -- --nocapture`
- `cargo test -p swarm-pheromone substrate::tests::deposit_accepts_strategy_scoped_agent_id_when_base_identity_matches_signing_key -- --exact`
- `cargo test -p swarm-pheromone substrate::tests::local_journal_recovers_behavioral_baseline_snapshots_after_reopen -- --exact`
- `cargo test -p swarm-runtime detection::pipeline::tests::behavioral_anomaly_detector_hydrates_persisted_baseline_after_restart -- --exact`
- `cargo fmt --all`
- `cargo check -p swarm-core -p swarm-pheromone -p swarm-whisker -p swarm-runtime --tests -j 1 --message-format short`

## Verified Behaviors

- The runtime config layer now merges repo-owned `behavioral_anomaly` profile overrides correctly, including host warm-up count, feature-weight floor, and baseline half-life.
- `BehavioralAnomalyDetector` now learns host-local ancestry and binary baselines, flags deviations after warm-up, and preserves snapshot dirty-state semantics.
- Local-journal substrate persistence now round-trips behavioral baseline snapshots across reopen, and health reporting includes the baseline journal file as part of the durable substrate contract.
- A fresh runtime detector can now hydrate persisted behavioral baselines from a durable substrate and emit the expected anomaly finding immediately after restart instead of relearning from zero.
- Durable deposit validation now accepts strategy-scoped `agent_id` values when their base signer identity matches the Ed25519 key used to sign the canonical deposit payload.
