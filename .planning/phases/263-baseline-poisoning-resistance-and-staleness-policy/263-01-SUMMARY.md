# Phase 263 Plan 01 Summary

## Delivered

- Extended `crates/swarm-whisker/src/behavioral_anomaly.rs` with a configurable baseline-staleness policy, staleness evidence, and confidence reduction that stays lock-free during finding construction.
- Updated `crates/swarm-runtime/src/detection/pipeline.rs` so persisted behavioral snapshots carry their signed capture timestamp back into the live detector after restart.
- Added restart-proof tests showing stale signed baselines reduce confidence and emit the expected `baseline_staleness` evidence while fresh baselines do not.

## Notes

- The staleness policy is intentionally confidence-only; it reduces trust in old learned state without discarding the baseline snapshot outright.
- The final detector path still hydrates from the signed baseline envelope, so stale handling composes with the existing tamper and replay protections from the learned-state integrity work.
