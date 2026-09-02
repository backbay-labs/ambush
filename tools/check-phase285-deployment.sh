#!/usr/bin/env bash
# Wave 0 fail-closed entry point. Plan 07A replaces the missing render/live
# targets; until then no deployment assurance can be produced.
set -euo pipefail

self_test() {
  python3 <<'PY'
import copy

base = {"target": True, "executed": 1, "passed": 1, "failed": 0,
        "ignored": 0, "commit": "c", "tree": "t", "lanes": {"render", "live"}}
def valid(x):
    return (x["target"] and x["executed"] > 0 and x["passed"] == x["executed"]
            and x["failed"] == 0 and x["ignored"] == 0
            and x["commit"] == "c" and x["tree"] == "t"
            and x["lanes"] == {"render", "live"})
mutations = {
    "missing_target": lambda x: x.update(target=False),
    "zero_execution": lambda x: x.update(executed=0, passed=0),
    "ignored_test": lambda x: x.update(passed=0, ignored=1),
    "failed_test": lambda x: x.update(passed=0, failed=1),
    "stale_commit_or_tree": lambda x: x.update(tree="stale"),
    "omitted_lane": lambda x: x.update(lanes={"render"}),
}
if not valid(base):
    raise SystemExit("deployment self-test control unexpectedly failed")
count = 0
for name, mutate in mutations.items():
    value = copy.deepcopy(base)
    mutate(value)
    if valid(value):
        raise SystemExit(f"deployment mutation unexpectedly passed: {name}")
    print(f"self_test_red checker=deployment mutation={name}")
    count += 1
if count != 6:
    raise SystemExit(f"deployment mutation registry mismatch: {count}")
print("deployment_self_test executed=1 passed=1 failed=0 ignored=0 mutation_failure_count=6")
PY
}

case "${1:-}" in
  --self-test)
    [ "$#" -eq 1 ] || { echo "usage: $0 --self-test|render|live" >&2; exit 2; }
    self_test
    ;;
  render|live|"")
    mode="${1:-render+live}"
    echo "missing deployment target: Plan 07A has not materialized Phase 285 mode '$mode'" >&2
    exit 1
    ;;
  *)
    echo "unknown deployment mode: $1" >&2
    exit 2
    ;;
esac
