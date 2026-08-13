#!/usr/bin/env bash
#
# Stigmergic feedback benchmark gate.
#
# WHAT THIS USED TO BE, AND WHY IT WAS WORTH NOTHING
#   Two bare `cargo test <name>` invocations and nothing else. Both were vacuous,
#   for two independent reasons:
#
#   1. A libtest NAME FILTER that matches nothing EXITS 0. Measured, at HEAD:
#
#        $ cargo test -p swarm-whisker definitely_not_a_real_test_name --lib
#        test result: ok. 0 passed; 0 failed; 0 ignored; 110 filtered out
#        $ echo $?
#        0
#
#      So renaming or deleting either test left this script green.
#
#   2. Both tests ALREADY run in the `test` job -- the whisker one via
#      ci.yml:225, the recruitment one via ci.yml:253. Wiring the old script
#      would have spent a CI job re-running tests the same workflow already ran.
#
#   And docs/benchmarks/stigmergic-feedback.md:4 called
#   docs/benchmarks/stigmergic-feedback-baseline.json a "Tracked baseline" while
#   this script never opened the file. Compare tools/check-hot-path-regression.sh
#   :7, which genuinely reads its baseline and compares against it.
#
# WHAT IT IS NOW
#   The same two tests, plus the three things that make them a gate:
#     a. `--exact` with the FULLY QUALIFIED test path, so the filter is not a
#        fuzzy substring;
#     b. an explicit assertion that each test RAN -- the `test <path> ... ok`
#        line and `1 passed` -- because an exit code alone cannot distinguish
#        "passed" from "matched nothing";
#     c. a comparison of every number the tests print against the tracked
#        baseline, which is the part that was missing entirely.
#
#   WHAT (c) ACTUALLY BUYS, stated honestly. The recruitment half is already
#   pinned in Rust: recruitment_integration.rs:527-530 asserts 4/3/180/120
#   exactly, so 33.3% is derived and pinned, and checking it here is
#   belt-and-braces. The SIGMA half is pinned nowhere -- behavioral_anomaly.rs
#   only asserts `sigma_3 > 0`, `sigma_2 >= sigma_3`, `sigma_1 >= sigma_2`. The
#   published 3-sigma=2 / 2-sigma=4 / 1-sigma=13 could all have been false and
#   every gate in the repo would have stayed green. That is the uncovered ground
#   this gate now covers.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BASELINE_FILE="${STS_STIGMERGIC_BASELINE_FILE:-docs/benchmarks/stigmergic-feedback-baseline.json}"

# Fully qualified paths, required by `--exact`: it matches the whole test path,
# not a substring of it. The whisker test lives in `mod tests` inside
# `pub mod behavioral_anomaly`; the recruitment test is a top-level fn in an
# integration target and so has no module prefix.
SIGMA_TEST="behavioral_anomaly::tests::behavioral_anomaly_quantifies_distinct_poisoning_observations_required_for_sigma_shifts"
RECRUITMENT_TEST="recruitment_kill_chain_replay_reaches_alert_at_least_twenty_percent_faster"

if [ ! -f "$BASELINE_FILE" ]; then
  echo "::error::missing stigmergic baseline file: $BASELINE_FILE" >&2
  exit 1
fi

LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-stigmergic.XXXXXX")"
trap 'rm -rf "$LOG_DIR"' EXIT

SIGMA_LOG="$LOG_DIR/sigma.log"
RECRUITMENT_LOG="$LOG_DIR/recruitment.log"

# Asserts the named test actually EXECUTED. `cargo test <filter>` exits 0 when
# the filter matches zero tests, so the exit code is not evidence -- the
# `test <path> ... ok` line and the `1 passed` summary are.
assert_test_ran() {
  local log="$1"
  local name="$2"
  local escaped="${name//./\\.}"

  if ! grep -qE "^test ${escaped} \.\.\. ok$" "$log"; then
    echo "::error::${name} did not run; a libtest name filter that matches nothing still exits 0" >&2
    echo "::error::  (renamed, deleted, #[ignore]d, or moved to another target?)" >&2
    return 1
  fi
  if ! grep -qE '^test result: ok\. 1 passed; 0 failed;' "$log"; then
    echo "::error::${name}: expected exactly one passing test in this target run" >&2
    grep -E '^test result:' "$log" >&2 || true
    return 1
  fi
}

status=0

echo "== $SIGMA_TEST =="
if cargo test -p swarm-whisker --lib -- --exact "$SIGMA_TEST" --nocapture 2>&1 \
    | tee "$SIGMA_LOG"; then
  assert_test_ran "$SIGMA_LOG" "$SIGMA_TEST" || status=1
else
  echo "::error::cargo test failed for $SIGMA_TEST" >&2
  status=1
fi

echo "== $RECRUITMENT_TEST =="
if cargo test -p swarm-runtime --test recruitment_integration -- \
    --exact "$RECRUITMENT_TEST" --nocapture 2>&1 | tee "$RECRUITMENT_LOG"; then
  assert_test_ran "$RECRUITMENT_LOG" "$RECRUITMENT_TEST" || status=1
else
  echo "::error::cargo test failed for $RECRUITMENT_TEST" >&2
  status=1
fi

if [ "$status" -ne 0 ]; then
  exit "$status"
fi

echo "== measured values vs $BASELINE_FILE =="
python3 - "$BASELINE_FILE" "$SIGMA_LOG" "$RECRUITMENT_LOG" <<'PY'
import json
import re
import sys

baseline_path, sigma_log, recruitment_log = sys.argv[1:4]

with open(baseline_path, "r", encoding="utf-8") as handle:
    baseline = json.load(handle)


def extract(path, pattern, label):
    regex = re.compile(pattern)
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            match = regex.search(line.strip())
            if match:
                return match.groupdict()
    print(
        f"::error::{label}: the test ran but printed no parseable metrics line "
        f"in {path}; expected a line matching /{pattern}/",
        file=sys.stderr,
    )
    sys.exit(1)


sigma = extract(
    sigma_log,
    r"^warm_observations=(?P<warm>\d+) sigma_3=(?P<s3>\d+) "
    r"sigma_2=(?P<s2>\d+) sigma_1=(?P<s1>\d+)$",
    "sigma shift bounds",
)
recruitment = extract(
    recruitment_log,
    r"^baseline_samples=(?P<bs>\d+) baseline_elapsed_secs=(?P<be>\d+) "
    r"recruited_samples=(?P<rs>\d+) recruited_elapsed_secs=(?P<re>\d+) "
    r"improvement=(?P<imp>[0-9.]+)$",
    "kill chain replay",
)

bounds = baseline["sigma_shift_bounds"]
thresholds = bounds["threshold_observations"]
replay = baseline["kill_chain_replay"]

comparisons = [
    ("sigma_shift_bounds.warm_observation_count", int(sigma["warm"]), bounds["warm_observation_count"]),
    ("sigma_shift_bounds.threshold_observations.3_sigma", int(sigma["s3"]), thresholds["3_sigma"]),
    ("sigma_shift_bounds.threshold_observations.2_sigma", int(sigma["s2"]), thresholds["2_sigma"]),
    ("sigma_shift_bounds.threshold_observations.1_sigma", int(sigma["s1"]), thresholds["1_sigma"]),
    ("kill_chain_replay.baseline.alert_sample_count", int(recruitment["bs"]), replay["baseline"]["alert_sample_count"]),
    ("kill_chain_replay.baseline.alert_elapsed_secs", int(recruitment["be"]), replay["baseline"]["alert_elapsed_secs"]),
    ("kill_chain_replay.recruited.alert_sample_count", int(recruitment["rs"]), replay["recruited"]["alert_sample_count"]),
    ("kill_chain_replay.recruited.alert_elapsed_secs", int(recruitment["re"]), replay["recruited"]["alert_elapsed_secs"]),
    (
        "kill_chain_replay.improvement_percent",
        round(float(recruitment["imp"]) * 100.0, 1),
        round(float(replay["improvement_percent"]), 1),
    ),
]

failed = False
for key, measured, expected in comparisons:
    if measured == expected:
        print(f"  ok   {key}: {measured}")
    else:
        failed = True
        print(f"  FAIL {key}: measured {measured}, baseline says {expected}")

if failed:
    print(
        "::error::stigmergic feedback benchmark disagrees with its tracked "
        "baseline; update docs/benchmarks/stigmergic-feedback-baseline.json AND "
        "docs/benchmarks/stigmergic-feedback.md, or explain the regression",
        file=sys.stderr,
    )
    sys.exit(1)
PY

echo "stigmergic feedback benchmark matches its tracked baseline"
