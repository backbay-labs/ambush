# Phase 219 Plan 01 Summary

## Delivered

- Added a repo-owned labeled-telemetry benchmark entrypoint in
  `crates/swarm-runtime/examples/behavioral_anomaly_quality_benchmark.rs`.
  The example reconstructs the merged behavioral anomaly profile from the
  signed repo config, evaluates the widened detector on a deterministic corpus,
  and prints both case-level results and aggregate metrics.
- Kept the comparison bounded to the current shipped detector path. The example
  measures current `deviation_scoring` behavior against a reconstructed legacy
  fixed-arithmetic control derived from the same emitted finding evidence
  instead of inventing a benchmark-only detector branch.
- Checked in the measured artifact in
  `docs/benchmarks/behavioral-anomaly-quality.md`, including the exact command,
  benchmark corpus shape, aggregate metrics, and case-level output table for
  the 2026-04-12 reference run.
- The measured result satisfies the milestone requirement honestly: the current
  detector preserved catch rate at `1.000` while reducing actionable
  false-positive rate from `1.000` to `0.000` on the repo-owned corpus,
  exceeding the required 30% reduction target without catch-rate loss.

## Notes

- The benchmark corpus is intentionally synthetic and restart-free so later
  work can rerun it as a stable regression baseline without depending on
  external capture infrastructure.
- The next milestone turns away from anomaly-quality work and back toward
  structural debt reduction in `swarm-evolution`; no further detector tuning is
  bundled into this benchmark phase.
