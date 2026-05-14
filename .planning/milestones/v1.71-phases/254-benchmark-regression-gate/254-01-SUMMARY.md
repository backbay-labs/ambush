# Phase 254 Plan 01 Summary

## Delivered

- Added the `benchmark` CI job in `.github/workflows/ci.yml` to run the hot-path Criterion gate and upload the benchmark log artifact.
- Added `tools/check-hot-path-regression.sh` to execute the benchmark, parse the emitted percentile metrics, compare measured p99 against the tracked threshold, and print a machine-readable summary.
- Refreshed `docs/benchmarks/fast-detection-baseline.json` and the benchmark documentation so the gate anchors on the current runtime hot path instead of a stale percentile sample.

## Notes

- The baseline refresh used the gate’s first clean local measurement so the repo tracks a conservative p99 sample instead of a warmed rerun that would make CI unnecessarily flaky.
- The helper stays backend-aware through the existing benchmark surface and still supports `STS_HOT_PATH_BACKEND=local_journal` for local durable-path measurement.
