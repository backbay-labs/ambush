# Phase 262 Plan 01 Summary

## Delivered

- Added `recruitment_kill_chain_replay_reaches_alert_at_least_twenty_percent_faster` to `crates/swarm-runtime/tests/recruitment_integration.rs`, proving the recruited replay alerts in 120 seconds versus 180 seconds without recruitment.
- Added `behavioral_anomaly_quantifies_distinct_poisoning_observations_required_for_sigma_shifts` to `crates/swarm-whisker/src/behavioral_anomaly.rs`, measuring `3σ=2`, `2σ=4`, and `1σ=13` distinct poisoning observations for the held-out aggregate deviation benchmark.
- Checked the results into `docs/benchmarks/stigmergic-feedback.md` and `docs/benchmarks/stigmergic-feedback-baseline.json`, and added `tools/check-stigmergic-feedback-benchmark.sh` to rerun the proof surface.

## Notes

- The replay benchmark uses the shipped runtime escalation path rather than a benchmark-only fast path.
- The sigma benchmark deliberately uses distinct novel destinations, because replaying one exact flow would be absorbed into the baseline after the first observation and would not represent poisoning pressure.
