#!/usr/bin/env bash
# Wave 0 fail-closed entry point. Plan 07B owns path, ledger, attestation, and
# final-evidence validation.
set -euo pipefail

self_test() {
  python3 <<'PY'
import copy

required = {"paths", "local-ledger", "hosted", "review", "final-closure"}
base = {"target": True, "executed": 5, "passed": 5, "failed": 0,
        "ignored": 0, "commit": "c", "tree": "t", "lanes": set(required)}
def valid(x):
    return (x["target"] and x["executed"] > 0 and x["passed"] == x["executed"]
            and x["failed"] == 0 and x["ignored"] == 0
            and x["commit"] == "c" and x["tree"] == "t" and x["lanes"] == required)
mutations = {
    "missing_target": lambda x: x.update(target=False),
    "zero_execution": lambda x: x.update(executed=0, passed=0),
    "ignored_test": lambda x: x.update(passed=4, ignored=1),
    "failed_test": lambda x: x.update(passed=4, failed=1),
    "stale_commit_or_tree": lambda x: x.update(tree="stale"),
    "omitted_lane": lambda x: x.update(lanes=required - {"review"}),
}
if not valid(base):
    raise SystemExit("evidence self-test control unexpectedly failed")
for name, mutate in mutations.items():
    value = copy.deepcopy(base)
    mutate(value)
    if valid(value):
        raise SystemExit(f"evidence mutation unexpectedly passed: {name}")
    print(f"self_test_red checker=evidence mutation={name}")
print("evidence_self_test executed=1 passed=1 failed=0 ignored=0 mutation_failure_count=6")
PY
}

case "${1:-}" in
  --self-test)
    [ "$#" -eq 1 ] || { echo "usage: $0 --self-test" >&2; exit 2; }
    self_test
    ;;
  *)
    echo "missing evidence target: Plan 07B has not materialized path/ledger/final-closure modes" >&2
    exit 1
    ;;
esac
