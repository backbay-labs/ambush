# Phase 260 Plan 01 Summary

## Delivered

- Extended `crates/swarm-whisker/src/network_connect.rs` with a bounded recruitment profile and observable recruitment evidence for command-and-control beaconing.
- Wired `crates/swarm-runtime/src/detection/pipeline.rs` and `crates/swarm-runtime/src/detector_factory.rs` so the runtime refreshes recruitment state from trusted signed pheromone concentration before evaluating each event.
- Added `crates/swarm-runtime/tests/recruitment_integration.rs` proof that matching command-and-control pressure lowers the beacon threshold, while unrelated threat classes and rejected unsigned deposits do not.

## Notes

- Recruitment is intentionally scoped to one detector family and one threat class instead of becoming a global sensitivity multiplier.
- The recruitment evidence block keeps the faster firing path explainable by surfacing baseline versus effective beacon thresholds and the trusted concentration that activated the reduction.
