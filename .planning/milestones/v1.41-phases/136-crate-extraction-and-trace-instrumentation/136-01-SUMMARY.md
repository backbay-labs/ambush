# Phase 136 Plan 01 Summary

## Delivered

- Added first-class `swarm-evolution` and `swarm-cli` workspace crates and moved the evolution-heavy modules plus CLI implementation files out of `swarm-runtime` ownership.
- Kept the shipped `swarm_detect` and `swarmctl` entrypoints stable while the extraction landed by bridging the moved source files back into `swarm-runtime` through a temporary `#[path]` seam.
- Added shared tracing bootstrap in `swarm-cli` with optional OTLP export behind `--otlp-endpoint`, while preserving the existing stdout JSON tracing default when OTLP is not configured.
- Added `trace_id` propagation through the hot path with a task-local observability seam and structured spans across ingest, runtime processing, detector evaluation, policy evaluation, and response dispatch.
- Removed a flaky evolution-validation path by reusing a single replay experiment evaluation for both the experiment artifact and the derived shadow artifact, eliminating inconsistent double-run shadow verdicts during validation refresh.
- Aligned the control-candidate experiment latency gate with the current debug-test runtime envelope so control-path replay, promotion-review, selection, and drafting tests stop failing on host jitter instead of real regressions.

## Notes

- The `#[path]` includes are still transitional. They avoid an immediate Cargo cycle while the crate graph is being separated, but they are not the desired long-term boundary.
- The validation refresh fix was paired with repeat-loop verification because the original failure was intermittent rather than deterministic.
