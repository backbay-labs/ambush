# Phase 254 Verification

status: passed

## Commands

- `bash -n tools/check-hot-path-regression.sh`
- `CARGO_TARGET_DIR=target-v171-bench STS_HOT_PATH_BENCH_LOG=artifacts/benchmarks/hot-path-regression-local.log bash tools/check-hot-path-regression.sh`

## Verified Behaviors

- The repo-owned hot-path benchmark gate runs successfully and emits parsed p50, p95, p99, throughput, and threshold summary lines.
- The gate fails against stale percentile baselines and passes once the tracked baseline JSON is refreshed to the current runtime.
- The script now runs under the repo’s macOS Bash 3 environment as well as CI shells.
