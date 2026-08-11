# Phase 261 Plan 01 Summary

## Delivered

- Updated `crates/swarm-runtime/src/escalation.rs` so de-escalation to `SwarmMode::Normal` writes a durable inhibitory record for the resolved threat class.
- Extended `crates/swarm-runtime/src/detection/pipeline.rs` to read that persisted resolution state and disable recruitment after the swarm has already cooled down.
- Added restart-proof coverage in `crates/swarm-runtime/tests/recruitment_integration.rs` showing the inhibited detector returns to the baseline beacon threshold after reopening the local journal.

## Notes

- The inhibition path is deliberately threat-class specific, so resolving command-and-control recruitment does not alter unrelated detector families.
- The durable `Normal` record lets the reset survive restart without adding a second mutable runtime-owned cache.
