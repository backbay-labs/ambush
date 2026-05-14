#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASELINE_FILE="${STS_HOT_PATH_BASELINE_FILE:-docs/benchmarks/fast-detection-baseline.json}"
LOG_PATH="${STS_HOT_PATH_BENCH_LOG:-artifacts/benchmarks/hot-path-regression.log}"

mkdir -p "$(dirname "$LOG_PATH")"

if [[ ! -f "$BASELINE_FILE" ]]; then
  echo "missing hot-path baseline file: $BASELINE_FILE" >&2
  exit 1
fi

read_baseline() {
  python3 - "$BASELINE_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

print(data["metrics"]["p99_latency_us"])
print(data["thresholds"]["max_p99_regression_percent"])
PY
}

baseline_values=()
while IFS= read -r line; do
  baseline_values+=("$line")
done < <(read_baseline)

BASELINE_P99_US="${baseline_values[0]}"
THRESHOLD_PERCENT="${STS_HOT_PATH_MAX_P99_REGRESSION_PERCENT:-${baseline_values[1]}}"

{
  echo "running cargo bench -p swarm-runtime --bench hot_path -- --noplot"
  cargo bench -p swarm-runtime --bench hot_path -- --noplot
} 2>&1 | tee "$LOG_PATH"

extract_metric() {
  local name="$1"
  local value

  value="$(grep -E "^${name}=" "$LOG_PATH" | tail -n 1 | cut -d= -f2 || true)"
  if [[ -z "$value" ]]; then
    echo "failed to extract ${name} from benchmark log $LOG_PATH" >&2
    exit 1
  fi
  printf '%s\n' "$value"
}

MEASURED_P50_US="$(extract_metric hot_path_baseline_p50_us)"
MEASURED_P95_US="$(extract_metric hot_path_baseline_p95_us)"
MEASURED_P99_US="$(extract_metric hot_path_baseline_p99_us)"
MEASURED_THROUGHPUT_EPS="$(extract_metric hot_path_baseline_throughput_eps)"

python3 - "$BASELINE_P99_US" "$MEASURED_P99_US" "$THRESHOLD_PERCENT" "$MEASURED_P50_US" "$MEASURED_P95_US" "$MEASURED_THROUGHPUT_EPS" <<'PY'
import sys

baseline = float(sys.argv[1])
measured = float(sys.argv[2])
threshold_percent = float(sys.argv[3])
p50 = float(sys.argv[4])
p95 = float(sys.argv[5])
throughput = float(sys.argv[6])
allowed = baseline * (1.0 + (threshold_percent / 100.0))
delta = measured - baseline
delta_percent = (delta / baseline) * 100.0

print(f"hot_path_regression_baseline_p99_us={baseline:.2f}")
print(f"hot_path_regression_measured_p50_us={p50:.2f}")
print(f"hot_path_regression_measured_p95_us={p95:.2f}")
print(f"hot_path_regression_measured_p99_us={measured:.2f}")
print(f"hot_path_regression_measured_throughput_eps={throughput:.2f}")
print(f"hot_path_regression_allowed_p99_us={allowed:.2f}")
print(f"hot_path_regression_delta_percent={delta_percent:.2f}")

if measured > allowed:
    print(
        f"p99 latency regression exceeded threshold: baseline={baseline:.2f} us, "
        f"measured={measured:.2f} us, allowed={allowed:.2f} us ({threshold_percent:.1f}%)",
        file=sys.stderr,
    )
    sys.exit(1)
PY
