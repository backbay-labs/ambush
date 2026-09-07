#!/usr/bin/env bash
#
# Red-swarm CI arms-race gate (ARMSCI-01) + wall-clock guard (ARMSCI-05).
#
# WHAT THIS CLOSES
#   Phase 290 gave `swarmctl red-swarm campaign` a real bidirectional red/blue
#   loop: red plans and budgets an attack, blue closes detection gaps, the two
#   co-evolve generation over generation, and the whole run is persisted as a
#   report under data/red-swarm/campaigns/<campaign>-<seed>.json. Nothing
#   before this gate ever EXECUTED that loop in CI and compared what it
#   measured against a tracked expectation. A change that quietly made blue
#   worse at converging -- a bad default, an inverted comparison, a dropped
#   gap-closing move -- would show green everywhere: `cargo test` exercises
#   the mechanism with small synthetic fixtures (see red_swarm_cmd.rs's own
#   `campaign_args` tests), not the real catalog/suites end to end, and
#   nothing asserts a FLOOR on the number that actually matters operationally:
#   how much of red's play blue ends up catching.
#
# SHAPE
#   Mirrors tools/check-hot-path-regression.sh (a measured value compared
#   against a checked-in number, exit 1 naming observed vs. required) and
#   tools/check-stigmergic-feedback-benchmark.sh (a `STS_*_FILE` env override
#   as a regeneration hook, never consulted by CI itself). The one thing this
#   gate does NOT do like those two: it never re-parses stdout for the
#   measurement. It reads `final_blue_catch_rate` from the JSON report file
#   `run_campaign` actually persists to disk -- the same file an operator
#   would open -- because a gate that only checks what a command PRINTS can
#   pass while the artifact it's supposed to vouch for is missing or wrong.
#
# ARMSCI-05 -- THE WALL-CLOCK GUARD
#   The campaign run (and only the campaign run -- not the `cargo build`
#   above it, which already has its own CI-level timeout-minutes) is wrapped
#   in `timeout`. A convergence bug that spins instead of terminating must
#   fail this gate loudly within a bounded number of seconds, never hang a CI
#   job or silently inflate its runtime. `--kill-after` backstops a child that
#   ignores the initial TERM; both a plain timeout (124) and an escalated kill
#   (137) are treated as the same loud failure.
#
# WHY THE CAMPAIGN STAYS BOUNDED
#   Fixed --seed, --campaign, --max-generations and --virtual-clock-start-ms,
#   run once, against the repo's real (tiny: 4 suites, 18 techniques) default
#   catalog and scenario-suites. Measured at ~0.3s wall-clock locally, and
#   deterministic: re-running with identical arguments reproduces the exact
#   same final_blue_catch_rate every time (no wall-clock or other hidden
#   entropy feeds the campaign itself -- see red_swarm_cmd.rs's own
#   byte-identical-report test). That determinism is WHY the threshold file
#   can sit a little below the measured value rather than needing a wide
#   statistical margin: a real regression moves the ratio by at least
#   1/(techniques attempted), far more than the cushion below.
#
# BASH 3.2 -- no `mapfile`, macOS ships bash 3.2 (precedent:
# check-no-unrouted-authorize.sh, check-gates-wired.sh).
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# --- fixed, bounded campaign parameters (ARMSCI-01) -------------------------
# Overridable only for local iteration on this gate itself; CI sets none of
# these, so a real run always exercises the checked-in values below.
SEED="${STS_RED_SWARM_ARMS_RACE_SEED:-42}"
CAMPAIGN="${STS_RED_SWARM_ARMS_RACE_CAMPAIGN:-ci-arms-race}"
MAX_GENERATIONS="${STS_RED_SWARM_ARMS_RACE_MAX_GENERATIONS:-5}"
VIRTUAL_CLOCK_START_MS="${STS_RED_SWARM_ARMS_RACE_VIRTUAL_CLOCK_START_MS:-1700000000000}"

# STS_RED_SWARM_ARMS_RACE_THRESHOLD_FILE repoints the threshold this gate
# compares against. It is a REGENERATION/TEST hook, not a bypass: nothing in
# CI sets it, so a workflow run always compares against the checked-in
# rulesets/red-swarm/arms-race-threshold.txt.
THRESHOLD_FILE="${STS_RED_SWARM_ARMS_RACE_THRESHOLD_FILE:-rulesets/red-swarm/arms-race-threshold.txt}"

# ARMSCI-05: the campaign run's wall-clock budget. ~0.3s measured locally;
# 120s leaves generous headroom for a slower CI runner without letting a
# genuine hang burn CI time silently. --kill-after backstops a child that
# ignores the initial TERM.
TIMEOUT_BUDGET="${STS_RED_SWARM_ARMS_RACE_TIMEOUT:-120s}"
KILL_AFTER="${STS_RED_SWARM_ARMS_RACE_KILL_AFTER:-10s}"

REPORTS_DIR="data/red-swarm/campaigns"
REPORT_FILE="$REPORTS_DIR/${CAMPAIGN}-${SEED}.json"

# --- resolve `timeout` -------------------------------------------------------
# GNU coreutils. ubuntu-latest ships it as `timeout`; macOS ships bash 3.2 and
# BSD userland, so Homebrew coreutils lands it as `gtimeout` unless installed
# unprefixed -- accept either rather than assuming the CI name everywhere.
TIMEOUT_BIN=""
for candidate in timeout gtimeout; do
  if command -v "$candidate" >/dev/null 2>&1; then
    TIMEOUT_BIN="$candidate"
    break
  fi
done
if [ -z "$TIMEOUT_BIN" ]; then
  echo "check-red-swarm-arms-race: FATAL -- no 'timeout' or 'gtimeout' on PATH (GNU coreutils required)" >&2
  exit 1
fi

# --- read the checked-in threshold ------------------------------------------
if [ ! -f "$THRESHOLD_FILE" ]; then
  echo "check-red-swarm-arms-race: missing checked-in threshold file: $THRESHOLD_FILE" >&2
  exit 1
fi

REQUIRED_CATCH_RATE="$(
  grep -v '^[[:space:]]*#' "$THRESHOLD_FILE" | grep -v '^[[:space:]]*$' | head -n1 | tr -d '[:space:]'
)"
if [ -z "$REQUIRED_CATCH_RATE" ]; then
  echo "check-red-swarm-arms-race: $THRESHOLD_FILE has no threshold value (only comments/blank lines)" >&2
  exit 1
fi

# --- resolve (building if needed) the swarmctl binary -----------------------
# Mirrors ci.yml's `build` job: a plain `cargo build`, no --release. In CI,
# the `build` job already populated the shared `target/ci` cache under this
# exact commit sha, so this is a fast no-op that reuses the CI-built binary
# rather than a second real compile; run standalone (or on a first checkout)
# it performs the real build.
if [ -n "${STS_RED_SWARM_SWARMCTL_BIN:-}" ]; then
  # Test-only escape hatch for exercising ARMSCI-05: point this at a stub
  # binary (e.g. one that just `sleep`s) to prove the timeout guard fires
  # without waiting on a real slow campaign. Nothing in CI sets this -- a
  # real workflow run always builds and runs the real swarmctl below.
  SWARMCTL_BIN="$STS_RED_SWARM_SWARMCTL_BIN"
  if [ ! -x "$SWARMCTL_BIN" ]; then
    echo "check-red-swarm-arms-race: STS_RED_SWARM_SWARMCTL_BIN=$SWARMCTL_BIN is not executable" >&2
    exit 1
  fi
else
  TARGET_DIR="${CARGO_TARGET_DIR:-target}"
  SWARMCTL_BIN="$TARGET_DIR/debug/swarmctl"
  if [ ! -x "$SWARMCTL_BIN" ]; then
    echo "check-red-swarm-arms-race: building swarmctl (cargo build -p swarm-runtime-http --bin swarmctl)"
    cargo build -p swarm-runtime-http --bin swarmctl
  fi
  if [ ! -x "$SWARMCTL_BIN" ]; then
    echo "check-red-swarm-arms-race: cargo build did not produce an executable at $SWARMCTL_BIN" >&2
    exit 1
  fi
fi

# --- run ONE bounded campaign, wall-clock guarded (ARMSCI-05) ---------------
mkdir -p "$REPORTS_DIR"
# A stale report from an earlier run at this exact campaign/seed must never
# be mistaken for this run's own output -- if the campaign dies before
# persisting, the missing-file check below must fire, not a leftover pass.
rm -f "$REPORT_FILE"

# X's at the very END of the template, on purpose (precedent:
# check-platform-openapi.sh:30-41, check-adversary-emulation-coverage.sh:72-77).
# GNU coreutils substitutes X's followed by a suffix; BSD/macOS mktemp does
# not -- it silently returns the LITERAL path instead, so a `.log`-suffixed
# template collides across concurrent/repeated runs on macOS instead of
# producing a unique file.
LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/red-swarm-arms-race.XXXXXX")"
trap 'rm -f "$LOG_FILE"' EXIT

echo "check-red-swarm-arms-race: running: $SWARMCTL_BIN red-swarm campaign --seed $SEED --campaign $CAMPAIGN --max-generations $MAX_GENERATIONS --virtual-clock-start-ms $VIRTUAL_CLOCK_START_MS"
echo "check-red-swarm-arms-race: wall-clock budget ${TIMEOUT_BUDGET} (kill-after ${KILL_AFTER})"

# `set +e` around the call itself, NOT `if ! CMD; then run_status=$?; fi`:
# under that idiom `$?` inside the `then` branch reflects the exit status of
# the NEGATION (`! CMD`), which collapses to 0/1 and throws away CMD's real
# code -- 124 vs. 137 vs. an ordinary failure would be indistinguishable.
# Measured while writing this gate: it silently read as run_status=0 (a
# "pass") on every timeout. `set +e`/`set -e` bracketing captures the actual
# code `timeout` exited with.
set +e
"$TIMEOUT_BIN" --kill-after="$KILL_AFTER" "$TIMEOUT_BUDGET" \
    "$SWARMCTL_BIN" red-swarm campaign \
      --seed "$SEED" \
      --campaign "$CAMPAIGN" \
      --max-generations "$MAX_GENERATIONS" \
      --virtual-clock-start-ms "$VIRTUAL_CLOCK_START_MS" \
    >"$LOG_FILE" 2>&1
run_status=$?
set -e

# GNU timeout: 124 = killed by the initial TERM, 137 = escalated to KILL via
# --kill-after. Either way this is ARMSCI-05's guard firing, not the campaign
# itself failing -- report it as a budget failure, loudly, never a silent hang.
if [ "$run_status" -eq 124 ] || [ "$run_status" -eq 137 ]; then
  echo "check-red-swarm-arms-race: FAIL -- the campaign exceeded its wall-clock budget (${TIMEOUT_BUDGET}, kill-after ${KILL_AFTER}); ARMSCI-05" >&2
  echo "check-red-swarm-arms-race: this is a bug in the campaign/convergence loop, not a flake -- do not retry, fix the hang" >&2
  echo "check-red-swarm-arms-race: captured output before the guard fired:" >&2
  sed -n '1,200p' "$LOG_FILE" >&2 || true
  exit 1
fi
if [ "$run_status" -ne 0 ]; then
  echo "check-red-swarm-arms-race: FAIL -- campaign run exited $run_status" >&2
  sed -n '1,200p' "$LOG_FILE" >&2 || true
  exit 1
fi

if [ ! -f "$REPORT_FILE" ]; then
  echo "check-red-swarm-arms-race: FAIL -- campaign exited 0 but wrote no report at $REPORT_FILE" >&2
  exit 1
fi

# --- compare the report FILE's final_blue_catch_rate against the threshold -
# Reads the field from the persisted report file the executor actually wrote
# (data/red-swarm/campaigns/...), never by re-parsing stdout: the file is the
# artifact an operator would open, and a gate that only checked stdout could
# pass while that artifact were missing, stale, or wrong.
python3 - "$REPORT_FILE" "$REQUIRED_CATCH_RATE" "$THRESHOLD_FILE" <<'PY'
import json
import sys

report_path, required_str, threshold_path = sys.argv[1:4]

with open(report_path, "r", encoding="utf-8") as handle:
    report = json.load(handle)

if "final_blue_catch_rate" not in report:
    print(
        f"check-red-swarm-arms-race: FAIL -- {report_path} has no "
        "final_blue_catch_rate field",
        file=sys.stderr,
    )
    sys.exit(1)

measured = float(report["final_blue_catch_rate"])
required = float(required_str)

print(f"check-red-swarm-arms-race: observed final_blue_catch_rate={measured} (from {report_path})")
print(f"check-red-swarm-arms-race: required final_blue_catch_rate>={required} (from {threshold_path})")

if measured < required:
    print(
        f"check-red-swarm-arms-race: FAIL -- blue's catch rate regressed: "
        f"observed {measured} is below the required {required} ({threshold_path})",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"check-red-swarm-arms-race: OK -- {measured} >= {required}")
PY
