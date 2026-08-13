#!/usr/bin/env bash
#
# Adversary emulation coverage gate.
#
# WHAT THIS USED TO BE
#   Two `cargo test` lines, a `cargo run` of the report generator, and a python
#   block asserting three FLOORS: `scenario_count >= 7`, `technique_count >= 20`,
#   `coverage_percent >= 0.60`.
#
#   The floors were dead code. crates/swarm-runtime/src/evasion_coverage.rs
#   asserts `scenario_count == 7` (strictly stronger), `>= 20` and `>= 0.60` over
#   the SAME summarize_repo_adversary_emulation_coverage call with the same
#   config -- so if the second cargo test line passed, the python block could not
#   fail. And that second line was a bare name filter, which exits 0 when it
#   matches nothing:
#
#     $ cargo test -p swarm-runtime definitely_not_a_real_test_name --lib
#     test result: ok. 0 passed; 0 failed; 0 ignored; 354 filtered out
#     $ echo $?
#     0
#
#   Meanwhile docs/benchmarks/adversary-emulation-coverage.md publishes 7
#   scenarios / 23 techniques / 4 detected / 19 partial / 0 not_covered / 100%.
#   Only the 7, the ">= 20" and the ">= 0.60" were asserted anywhere in the
#   repository. The 23, the 4, the 19, the 0 and the 100% were not.
#
# WHAT IT IS NOW
#   Same three commands, plus:
#     a. `--exact` with the fully qualified test path on the name-filtered line;
#     b. an assertion that each named test RAN, since an exit code cannot tell
#        "passed" from "matched nothing";
#     c. an exact comparison of the generated report against
#        docs/benchmarks/adversary-emulation-baseline.json, whose values were
#        read out of a real run rather than copied from the markdown table --
#        the two were then cross-checked and agree;
#     d. internal-consistency assertions on the report itself
#        (detected + partial + not_covered == technique_count, and
#        len(techniques) == technique_count).
#   The floors are kept as a lower bound on top of the exact match, because a
#   floor and an exact value fail differently: a floor survives a deliberate
#   baseline update, an exact value catches an accidental one.
#
#   MARGINAL COVERAGE OVER ci.yml's `test` JOB, stated honestly. Both cargo test
#   lines already run there. What does not run anywhere else is
#   generate_adversary_emulation_report -- nothing exercises that bin, its
#   serialization, or its behaviour when invoked from the repo root -- and the
#   five published numbers above.
#
# `cd "$repo_root"` ON LINE ~60 IS LOAD-BEARING. resolve_repo_root walks
# `rulesets/` upward and then cwd upward looking for the suite and the catalog,
# so the generator finds its inputs relative to the working directory.
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# STS_ADVERSARY_BASELINE_FILE repoints the baseline this gate compares against. It is a
# REGENERATION hook, not a bypass: nothing in CI sets it, so a workflow run
# always compares against the checked-in docs/benchmarks/adversary-emulation-baseline.json.
# Point it at a scratch file to produce a new baseline, inspect the diff, and
# commit the result deliberately -- do not let a gate rewrite its own baseline.
BASELINE_FILE="${STS_ADVERSARY_BASELINE_FILE:-docs/benchmarks/adversary-emulation-baseline.json}"

# Fully qualified path, required by `--exact`.
FLOOR_TEST="evasion_coverage::tests::repo_adversary_emulation_coverage_report_meets_floor"

if [ ! -f "$BASELINE_FILE" ]; then
  echo "::error::missing adversary emulation baseline file: $BASELINE_FILE" >&2
  exit 1
fi

# `mktemp -d` with the X's at the END of the template. The previous template was
# `swarm-adversary-emulation-XXXXXX.json`; BSD/macOS mktemp does not substitute
# X's that are followed by a suffix, so it returned the LITERAL path -- a fixed
# name in a shared temp dir that two concurrent runs collide on. Observed:
#   Running `generate_adversary_emulation_report --output /var/.../T//swarm-adversary-emulation-XXXXXX.json`
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-adversary-emulation.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

report_path="$WORK_DIR/adversary-emulation-report.json"
integration_log="$WORK_DIR/integration.log"
floor_log="$WORK_DIR/floor.log"

status=0

echo "== adversary_emulation_integration (whole target, no name filter) =="
if cargo test -p swarm-runtime --test adversary_emulation_integration -- --nocapture 2>&1 \
    | tee "$integration_log"; then
  # This invocation has no name filter, so it cannot be vacuous the way a filter
  # can -- a missing target is `error: no test target named ...`. The assertion
  # here is against the OTHER silent-pass shape: a target that still exists but
  # whose tests were all deleted or #[ignore]d reports `0 passed` and exits 0.
  if ! grep -qE '^test result: ok\. [1-9][0-9]* passed; 0 failed;' "$integration_log"; then
    echo "::error::adversary_emulation_integration ran zero tests" >&2
    grep -E '^test result:' "$integration_log" >&2 || true
    status=1
  fi
else
  echo "::error::cargo test failed for --test adversary_emulation_integration" >&2
  status=1
fi

echo "== $FLOOR_TEST =="
if cargo test -p swarm-runtime --lib -- --exact "$FLOOR_TEST" --nocapture 2>&1 \
    | tee "$floor_log"; then
  escaped="${FLOOR_TEST//./\\.}"
  if ! grep -qE "^test ${escaped} \.\.\. ok$" "$floor_log"; then
    echo "::error::${FLOOR_TEST} did not run; a libtest name filter that matches nothing still exits 0" >&2
    echo "::error::  (renamed, deleted, #[ignore]d, or moved to another target?)" >&2
    status=1
  elif ! grep -qE '^test result: ok\. 1 passed; 0 failed;' "$floor_log"; then
    echo "::error::${FLOOR_TEST}: expected exactly one passing test in this target run" >&2
    grep -E '^test result:' "$floor_log" >&2 || true
    status=1
  fi
else
  echo "::error::cargo test failed for $FLOOR_TEST" >&2
  status=1
fi

if [ "$status" -ne 0 ]; then
  exit "$status"
fi

echo "== generate_adversary_emulation_report =="
cargo run -q -p swarm-runtime --bin generate_adversary_emulation_report -- --output "$report_path"

if [ ! -s "$report_path" ]; then
  echo "::error::generate_adversary_emulation_report exited 0 but wrote no report to $report_path" >&2
  exit 1
fi

echo "== generated report vs $BASELINE_FILE =="
python3 - "$report_path" "$BASELINE_FILE" <<'PY'
import json
import sys

report_path, baseline_path = sys.argv[1:3]

with open(report_path, "r", encoding="utf-8") as handle:
    report = json.load(handle)
with open(baseline_path, "r", encoding="utf-8") as handle:
    baseline = json.load(handle)

failed = False


def check(label, measured, expected):
    global failed
    if measured == expected:
        print(f"  ok   {label}: {measured}")
    else:
        failed = True
        print(f"  FAIL {label}: measured {measured!r}, baseline says {expected!r}")


for key in (
    "suite_name",
    "suite_path",
    "corpus_version",
    "scenario_count",
    "technique_count",
    "detected_technique_count",
    "partial_technique_count",
    "not_covered_technique_count",
):
    check(key, report[key], baseline[key])

check("coverage_percent", round(float(report["coverage_percent"]), 6),
      round(float(baseline["coverage_percent"]), 6))

techniques = sorted(entry["technique"] for entry in report["techniques"])
detected = sorted(
    entry["technique"] for entry in report["techniques"] if entry["status"] == "detected"
)
check("techniques", techniques, sorted(baseline["techniques"]))
check("detected_techniques", detected, sorted(baseline["detected_techniques"]))

# Internal consistency of the report, independent of the baseline. A report that
# disagrees with itself is a generator bug, and would otherwise be invisible for
# as long as the baseline was regenerated from the same broken generator.
print("  -- report internal consistency --")
bucket_sum = (
    report["detected_technique_count"]
    + report["partial_technique_count"]
    + report["not_covered_technique_count"]
)
check("detected+partial+not_covered == technique_count", bucket_sum, report["technique_count"])
check("len(techniques) == technique_count", len(report["techniques"]), report["technique_count"])

# Floors, kept alongside the exact match on purpose: an exact value catches an
# accidental baseline edit, a floor survives a deliberate one and still refuses
# to let the corpus shrink below the v1.75 Phase 270 contract.
print("  -- floors --")
floors = baseline["floors"]
for label, measured, minimum in (
    ("scenario_count", report["scenario_count"], floors["min_scenario_count"]),
    ("technique_count", report["technique_count"], floors["min_technique_count"]),
    ("coverage_percent", float(report["coverage_percent"]), floors["min_coverage_percent"]),
):
    if measured >= minimum:
        print(f"  ok   {label} >= {minimum}: {measured}")
    else:
        failed = True
        print(f"  FAIL {label} >= {minimum}: got {measured}")

if failed:
    print(
        "::error::adversary emulation coverage disagrees with its tracked "
        "baseline; update docs/benchmarks/adversary-emulation-baseline.json AND "
        "docs/benchmarks/adversary-emulation-coverage.md from a real report run, "
        "or explain the regression",
        file=sys.stderr,
    )
    sys.exit(1)

print(
    "Adversary emulation coverage OK: "
    f"{report['scenario_count']} scenarios, {report['technique_count']} techniques, "
    f"{float(report['coverage_percent']):.2%} mapped coverage"
)
PY
