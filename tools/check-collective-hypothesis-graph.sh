#!/usr/bin/env bash
# Phase 286 collective-epistemology gate.
#
# The checker asserts exact test execution, frozen oracle identity, report
# schema/denominators, deterministic repeats, and mutation-proven failure modes.
# Wall-clock measurements are observations and may never enter the verdict.
set -euo pipefail

COG_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$COG_ROOT"

COG_PYTHON=""
for candidate in /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if [[ -x "$candidate" ]] \
    && "$candidate" -I -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' \
      >/dev/null 2>&1; then
    COG_PYTHON="$candidate"
    break
  fi
done
if [[ -z "$COG_PYTHON" ]]; then
  echo "collective hypothesis gate requires Python >= 3.11 at a pinned system path" >&2
  exit 1
fi

assert_exact_test_output() {
  local output_file="$1"
  local test_name="$2"
  local running_count
  local named_count
  local result_count

  running_count="$(grep -Ec '^running 1 test$' "$output_file" || true)"
  named_count="$(grep -Ec "^test ${test_name} \.\.\. ok$" "$output_file" || true)"
  result_count="$(grep -Ec '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in ' "$output_file" || true)"
  if [[ "$running_count" -ne 1 || "$named_count" -ne 1 || "$result_count" -ne 1 ]]; then
    echo "expected exactly one successful execution of ${test_name}; got running=${running_count} named=${named_count} result=${result_count}" >&2
    return 1
  fi
}

run_exact() {
  local test_name="$1"
  shift
  local output_file
  output_file="$(mktemp "${TMPDIR:-/tmp}/ambush-cog-test.XXXXXX")"
  if ! "$@" >"$output_file" 2>&1; then
    cat "$output_file" >&2
    rm -f -- "$output_file"
    return 1
  fi
  if ! assert_exact_test_output "$output_file" "$test_name"; then
    cat "$output_file" >&2
    rm -f -- "$output_file"
    return 1
  fi
  cat "$output_file"
  rm -f -- "$output_file"
}

verify_frozen_oracle() {
  "$COG_PYTHON" -I - "$COG_ROOT" <<'PY'
from __future__ import annotations
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
baseline_path = root / "docs/benchmarks/collective-hypothesis-graph-baseline.json"
baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
expected_top = {
    "schema_version", "corpus_id", "corpus_version", "oracle_digests",
    "denominators", "thresholds", "single_agent_baseline",
}
if set(baseline) != expected_top:
    raise SystemExit(f"baseline fields drifted: {sorted(set(baseline) ^ expected_top)}")
expected_digests = {
    "manifest_sha256": "scenarios/collective-hypothesis-graph/manifest.yaml",
    "ambiguous_fixture_sha256": "scenarios/collective-hypothesis-graph/ambiguous-cross-telemetry.yaml",
    "withheld_fixture_sha256": "scenarios/collective-hypothesis-graph/withheld-kill-chain.yaml",
}
if set(baseline["oracle_digests"]) != set(expected_digests):
    raise SystemExit("oracle digest fields drifted")
for field, relative in expected_digests.items():
    actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if baseline["oracle_digests"][field] != actual:
        raise SystemExit(f"frozen oracle digest mismatch: {relative}")
PY
}

verify_reports() {
  local first="$1"
  local second="$2"
  "$COG_PYTHON" -I - "$COG_ROOT" "$first" "$second" <<'PY'
from __future__ import annotations
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
report_paths = [pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])]
baseline = json.loads(
    (root / "docs/benchmarks/collective-hypothesis-graph-baseline.json").read_text(
        encoding="utf-8"
    )
)

TOP = {
    "schema_version", "corpus_id", "seed", "corpus_digest", "config_digest",
    "lane_input_digest", "oracle_digests", "source_families", "denominators",
    "single_agent", "collective", "deltas", "verdict", "observations",
}
METRICS = {
    "median_hypothesis_time_ms", "attack_chain_recall_bps",
    "false_causal_edge_rate_bps", "duplicate_work_rate_bps",
    "evidence_coverage_bps", "logical_work_units",
}
DELTAS = {"hypothesis_time_reduction_bps", "attack_chain_recall_gain_bps"}
VERDICT = {"passed", "failed_gates"}
OBSERVATIONS = {
    "single_agent_wall_clock_ms", "collective_wall_clock_ms", "gate_inputs"
}
GATE_INPUTS = {
    "median_hypothesis_time_ms", "attack_chain_recall_bps",
    "false_causal_edge_rate_bps", "duplicate_work_rate_bps",
    "evidence_coverage_bps", "logical_work_units",
}
FAMILIES = [
    "process", "identity", "kubernetes", "cloudtrail", "network",
    "threat_intelligence",
]


def exact_fields(value, expected, label):
    if not isinstance(value, dict) or set(value) != expected:
        got = set(value) if isinstance(value, dict) else set()
        raise ValueError(f"{label} fields drifted: {sorted(got ^ expected)}")


def ratio_reduction(baseline_value, candidate_value):
    if baseline_value <= 0 or candidate_value > baseline_value:
        return 0
    return ((baseline_value - candidate_value) * 10_000) // baseline_value


def verify(report):
    exact_fields(report, TOP, "report")
    exact_fields(report["single_agent"], METRICS, "single_agent")
    exact_fields(report["collective"], METRICS, "collective")
    exact_fields(report["deltas"], DELTAS, "deltas")
    exact_fields(report["verdict"], VERDICT, "verdict")
    exact_fields(report["observations"], OBSERVATIONS, "observations")
    if report["schema_version"] != 1 or report["corpus_id"] != baseline["corpus_id"]:
        raise ValueError("report identity mismatch")
    if report["seed"] <= 0:
        raise ValueError("seed must be nonzero")
    for field in ("corpus_digest", "config_digest", "lane_input_digest"):
        if not isinstance(report[field], str) or len(report[field]) != 64:
            raise ValueError(f"{field} is not a SHA-256 digest")
    if report["oracle_digests"] != baseline["oracle_digests"]:
        raise ValueError("report oracle identity drifted")
    if report["source_families"] != FAMILIES:
        raise ValueError("six ordered source families are required")
    if report["denominators"] != baseline["denominators"]:
        raise ValueError("metric denominators drifted")
    if any(not isinstance(value, int) or value <= 0
           for value in report["denominators"].values()):
        raise ValueError("denominators must be positive integers")
    for lane in ("single_agent", "collective"):
        metrics = report[lane]
        if metrics["median_hypothesis_time_ms"] <= 0 or metrics["logical_work_units"] <= 0:
            raise ValueError(f"{lane} has a zero time/work denominator")
        for field in METRICS - {"median_hypothesis_time_ms", "logical_work_units"}:
            if not 0 <= metrics[field] <= 10_000:
                raise ValueError(f"{lane}.{field} is outside basis-point range")
    expected_time = ratio_reduction(
        report["single_agent"]["median_hypothesis_time_ms"],
        report["collective"]["median_hypothesis_time_ms"],
    )
    expected_recall = (
        report["collective"]["attack_chain_recall_bps"]
        - report["single_agent"]["attack_chain_recall_bps"]
    )
    if report["deltas"] != {
        "hypothesis_time_reduction_bps": expected_time,
        "attack_chain_recall_gain_bps": expected_recall,
    }:
        raise ValueError("reported deltas do not match lane metrics")
    thresholds = baseline["thresholds"]
    failures = []
    if expected_time < thresholds["min_hypothesis_time_reduction_bps"]:
        failures.append("hypothesis_time")
    if expected_recall < thresholds["min_attack_chain_recall_gain_bps"]:
        failures.append("attack_chain_recall")
    if report["collective"]["false_causal_edge_rate_bps"] > thresholds["max_false_causal_edge_rate_bps"]:
        failures.append("false_causal_edges")
    if report["collective"]["duplicate_work_rate_bps"] > thresholds["max_duplicate_work_rate_bps"]:
        failures.append("duplicate_work")
    if report["collective"]["evidence_coverage_bps"] < thresholds["min_evidence_coverage_bps"]:
        failures.append("evidence_coverage")
    expected_verdict = {"passed": not failures, "failed_gates": failures}
    if report["verdict"] != expected_verdict:
        raise ValueError("verdict does not follow immutable thresholds")
    gate_inputs = report["observations"]["gate_inputs"]
    if set(gate_inputs) != GATE_INPUTS:
        raise ValueError("gate inputs missing or include observations such as wall clock")
    if any("wall" in field or "latency" in field for field in gate_inputs):
        raise ValueError("wall-clock data entered the verdict")
    return report


reports = [verify(json.loads(path.read_text(encoding="utf-8"))) for path in report_paths]
for report in reports:
    if not report["verdict"]["passed"]:
        raise SystemExit(f"collective intelligence thresholds failed: {report['verdict']}")
normalized = []
for report in reports:
    copy = dict(report)
    copy.pop("observations")
    normalized.append(json.dumps(copy, sort_keys=True, separators=(",", ":")))
if normalized[0] != normalized[1]:
    raise SystemExit("fixed inputs produced different deterministic report bytes")
PY
}

self_test_report_verifier() {
  "$COG_PYTHON" -I - "$COG_ROOT" <<'PY'
from __future__ import annotations
import copy
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
baseline = json.loads(
    (root / "docs/benchmarks/collective-hypothesis-graph-baseline.json").read_text(
        encoding="utf-8"
    )
)
families = [
    "process", "identity", "kubernetes", "cloudtrail", "network",
    "threat_intelligence",
]
metric_fields = {
    "median_hypothesis_time_ms", "attack_chain_recall_bps",
    "false_causal_edge_rate_bps", "duplicate_work_rate_bps",
    "evidence_coverage_bps", "logical_work_units",
}
report = {
    "schema_version": 1,
    "corpus_id": baseline["corpus_id"],
    "seed": 286001,
    "corpus_digest": "a" * 64,
    "config_digest": "b" * 64,
    "lane_input_digest": "c" * 64,
    "oracle_digests": baseline["oracle_digests"],
    "source_families": families,
    "denominators": baseline["denominators"],
    "single_agent": {
        "median_hypothesis_time_ms": 5000,
        "attack_chain_recall_bps": 7000,
        "false_causal_edge_rate_bps": 1500,
        "duplicate_work_rate_bps": 0,
        "evidence_coverage_bps": 7500,
        "logical_work_units": 100,
    },
    "collective": {
        "median_hypothesis_time_ms": 3500,
        "attack_chain_recall_bps": 8500,
        "false_causal_edge_rate_bps": 800,
        "duplicate_work_rate_bps": 400,
        "evidence_coverage_bps": 9500,
        "logical_work_units": 120,
    },
    "deltas": {
        "hypothesis_time_reduction_bps": 3000,
        "attack_chain_recall_gain_bps": 1500,
    },
    "verdict": {"passed": True, "failed_gates": []},
    "observations": {
        "single_agent_wall_clock_ms": 20,
        "collective_wall_clock_ms": 40,
        "gate_inputs": sorted(metric_fields),
    },
}
top = set(report)


def verify(value, baseline_value=baseline):
    if set(value) != top:
        raise ValueError("top-level schema")
    if set(value["single_agent"]) != metric_fields or set(value["collective"]) != metric_fields:
        raise ValueError("metric schema")
    if set(value["observations"]) != {
        "single_agent_wall_clock_ms", "collective_wall_clock_ms", "gate_inputs"
    }:
        raise ValueError("observation schema")
    if value["source_families"] != families:
        raise ValueError("source family oracle")
    if value["oracle_digests"] != baseline_value["oracle_digests"]:
        raise ValueError("oracle digest")
    required_thresholds = {
        "min_hypothesis_time_reduction_bps", "min_attack_chain_recall_gain_bps",
        "max_false_causal_edge_rate_bps", "max_duplicate_work_rate_bps",
        "min_evidence_coverage_bps",
    }
    if set(baseline_value["thresholds"]) != required_thresholds:
        raise ValueError("threshold schema")
    if set(value["observations"]["gate_inputs"]) != metric_fields:
        raise ValueError("wall clock entered gate")
    thresholds = baseline_value["thresholds"]
    candidate = value["collective"]
    failures = []
    if value["deltas"]["hypothesis_time_reduction_bps"] < thresholds["min_hypothesis_time_reduction_bps"]:
        failures.append("hypothesis_time")
    if value["deltas"]["attack_chain_recall_gain_bps"] < thresholds["min_attack_chain_recall_gain_bps"]:
        failures.append("attack_chain_recall")
    if candidate["false_causal_edge_rate_bps"] > thresholds["max_false_causal_edge_rate_bps"]:
        failures.append("false_causal_edges")
    if candidate["duplicate_work_rate_bps"] > thresholds["max_duplicate_work_rate_bps"]:
        failures.append("duplicate_work")
    if candidate["evidence_coverage_bps"] < thresholds["min_evidence_coverage_bps"]:
        failures.append("evidence_coverage")
    if value["verdict"] != {"passed": not failures, "failed_gates": failures}:
        raise ValueError("verdict inversion")


def must_fail(label, mutate):
    candidate = copy.deepcopy(report)
    candidate_baseline = copy.deepcopy(baseline)
    mutate(candidate, candidate_baseline)
    try:
        verify(candidate, candidate_baseline)
    except (KeyError, TypeError, ValueError):
        return
    raise SystemExit(f"self-test mutation unexpectedly passed: {label}")


verify(report)
must_fail("missing report field", lambda value, _: value.pop("deltas"))
must_fail("extra report field", lambda value, _: value.update({"override": True}))
must_fail("source omission", lambda value, _: value["source_families"].pop())
must_fail("oracle mutation", lambda value, _: value["oracle_digests"].update({"manifest_sha256": hashlib.sha256(b"mutated").hexdigest()}))
must_fail("threshold removal", lambda _, base: base["thresholds"].pop("max_false_causal_edge_rate_bps"))
must_fail("threshold failure", lambda value, _: value["collective"].update({"false_causal_edge_rate_bps": 1001}))
must_fail("verdict inversion", lambda value, _: value["verdict"].update({"passed": False, "failed_gates": ["inverted"]}))
must_fail("wall-clock gating", lambda value, _: value["observations"]["gate_inputs"].append("collective_wall_clock_ms"))
print("collective hypothesis report verifier self-test passed")
PY
}

self_test_exact_output() {
  local valid
  local zero
  local two
  local renamed
  valid="$(mktemp "${TMPDIR:-/tmp}/ambush-cog-valid.XXXXXX")"
  zero="$(mktemp "${TMPDIR:-/tmp}/ambush-cog-zero.XXXXXX")"
  two="$(mktemp "${TMPDIR:-/tmp}/ambush-cog-two.XXXXXX")"
  renamed="$(mktemp "${TMPDIR:-/tmp}/ambush-cog-renamed.XXXXXX")"
  printf '%s\n' \
    'running 1 test' \
    'test expected_test ... ok' \
    'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s' >"$valid"
  printf '%s\n' \
    'running 0 tests' \
    'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out; finished in 0.00s' >"$zero"
  printf '%s\n' \
    'running 2 tests' \
    'test expected_test ... ok' \
    'test another_test ... ok' \
    'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.00s' >"$two"
  printf '%s\n' \
    'running 1 test' \
    'test renamed_test ... ok' \
    'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s' >"$renamed"

  assert_exact_test_output "$valid" expected_test
  if assert_exact_test_output "$zero" expected_test >/dev/null 2>&1; then
    echo "zero-test mutation unexpectedly passed" >&2
    return 1
  fi
  if assert_exact_test_output "$two" expected_test >/dev/null 2>&1; then
    echo "wrong execution-count mutation unexpectedly passed" >&2
    return 1
  fi
  if assert_exact_test_output "$renamed" expected_test >/dev/null 2>&1; then
    echo "renamed-test mutation unexpectedly passed" >&2
    return 1
  fi
  rm -f -- "$valid" "$zero" "$two" "$renamed"
}

self_test() {
  self_test_exact_output
  verify_frozen_oracle
  self_test_report_verifier
  run_exact benchmark_manifest_is_strict \
    cargo test -p swarm-runtime --test collective_hypothesis_oracle \
      benchmark_manifest_is_strict -- --exact
  run_exact boundary_checker_rejects_broken_fixture \
    cargo test -p swarm-runtime --test negative_graph_response_boundary \
      boundary_checker_rejects_broken_fixture -- --exact
  echo "collective hypothesis gate self-test passed"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi
if [[ "$#" -ne 0 ]]; then
  echo "usage: tools/check-collective-hypothesis-graph.sh [--self-test]" >&2
  exit 2
fi

self_test
verify_frozen_oracle

if [[ ! -f crates/swarm-runtime/tests/collective_hypothesis_graph.rs ]]; then
  echo "collective hypothesis behavior target is not implemented; Plan 02 must create it without modifying the sealed oracle target" >&2
  exit 1
fi

run_exact cross_telemetry_fixture_preserves_conflicts \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    cross_telemetry_fixture_preserves_conflicts -- --exact --nocapture
run_exact ambiguous_seed_retains_competing_hypotheses \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    ambiguous_seed_retains_competing_hypotheses -- --exact --nocapture
run_exact withheld_kill_chain_reports_missing_evidence \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    withheld_kill_chain_reports_missing_evidence -- --exact --nocapture
run_exact containment_plan_is_simulation_only \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    containment_plan_is_simulation_only -- --exact --nocapture
run_exact duplicate_claim_fixture_100 \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    duplicate_claim_fixture_100 -- --exact --nocapture
run_exact memory_replay_changes_priority_deterministically \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    memory_replay_changes_priority_deterministically -- --exact --nocapture
run_exact seed_signal_converges_through_real_runtime \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    seed_signal_converges_through_real_runtime -- --exact --nocapture
run_exact disabled_hypothesis_graph_preserves_legacy_runtime \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    disabled_hypothesis_graph_preserves_legacy_runtime -- --exact --nocapture

COG_RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/ambush-cog-gate.XXXXXX")"
trap 'rm -r -- "$COG_RUN_ROOT"' EXIT
COG_REPORT_ONE="$COG_RUN_ROOT/report-one.json"
COG_REPORT_TWO="$COG_RUN_ROOT/report-two.json"
run_exact collective_reasoning_beats_single_agent_baseline \
  env COLLECTIVE_HYPOTHESIS_REPORT_PATH="$COG_REPORT_ONE" \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    collective_reasoning_beats_single_agent_baseline -- --exact --nocapture
run_exact collective_reasoning_beats_single_agent_baseline \
  env COLLECTIVE_HYPOTHESIS_REPORT_PATH="$COG_REPORT_TWO" \
  cargo test -p swarm-runtime --test collective_hypothesis_graph \
    collective_reasoning_beats_single_agent_baseline -- --exact --nocapture
verify_reports "$COG_REPORT_ONE" "$COG_REPORT_TWO"

echo "collective hypothesis graph gate passed"
