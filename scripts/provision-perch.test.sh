#!/usr/bin/env bash
#
# Hermetic tests for scripts/provision-perch.sh.
#
# The script talks to a relay and signs with a real key, so each case runs it
# against a synthetic root: a stub `ambush` CLI that keeps channel state in a
# JSON file, a `file://` "relay" whose /health is just a file, and a `node`
# wrapper that records every argv it is handed. Nothing here needs Docker, a
# relay, or a built CLI.
#
# Covers the three defects fixed in the Ground review:
#   1. the operator secret must never appear in a child process's argv;
#   2. an unverifiable lane taxonomy is a hard failure, not a note on stderr;
#   3. an archived lane is found and reused, not duplicated.
#
# Usage: bash scripts/provision-perch.test.sh
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/provision-perch.sh"
# The well-known dev identity: sha256("ambush-perch-dev-operator-v1").
DEV_SECRET="$(printf '%s' 'ambush-perch-dev-operator-v1' \
  | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"

failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

pass() {
  echo "ok: $*"
}

# Build a throwaway root: fake escalation.rs, stub CLI, node wrapper, relay.
# $1 = "with-taxonomy" | "without-taxonomy".
make_root() {
  local mode="$1"
  local work
  work="$(mktemp -d)"
  mkdir -p "$work/root/scripts" "$work/root/workspace/bin" "$work/relay" \
    "$work/root/crates/swarm-runtime/src"
  cp "$SCRIPT" "$work/root/scripts/provision-perch.sh"
  : >"$work/relay/health"
  echo '{"channels": []}' >"$work/state.json"
  : >"$work/node-argv.log"
  : >"$work/cli.log"

  if [ "$mode" = "with-taxonomy" ]; then
    cat >"$work/root/crates/swarm-runtime/src/escalation.rs" <<'RUST'
pub fn standard_threat_classes() -> Vec<ThreatClass> {
    vec![
        ThreatClass::LateralMovement,
        ThreatClass::DataExfiltration,
        ThreatClass::PrivilegeEscalation,
        ThreatClass::CommandAndControl,
        ThreatClass::InitialAccess,
        ThreatClass::Persistence,
        ThreatClass::SupplyChain,
        ThreatClass::DefenseEvasion,
        ThreatClass::CredentialAccess,
        ThreatClass::Discovery,
        ThreatClass::Execution,
        ThreatClass::Impact,
    ]
}
RUST
  fi

  # `node` wrapper: records the argv it was called with, then runs the real one.
  cat >"$work/root/workspace/bin/node" <<NODEWRAP
#!/usr/bin/env bash
printf '%s\n' "\$*" >>"$work/node-argv.log"
exec "$(command -v node)" "\$@"
NODEWRAP
  chmod +x "$work/root/workspace/bin/node"

  cat >"$work/ambush" <<'STUB'
#!/usr/bin/env python3
"""Stub `ambush` CLI: channel state in $STUB_STATE, calls appended to $STUB_LOG."""
import json
import os
import sys

argv = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as handle:
    handle.write(" ".join(argv) + "\n")

state_path = os.environ["STUB_STATE"]
with open(state_path, encoding="utf-8") as handle:
    state = json.load(handle)


def opt(name):
    return argv[argv.index(name) + 1] if name in argv else None


def save():
    with open(state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


if "search" in argv:
    include_archived = "--include-archived" in argv
    query = opt("--query")
    print(json.dumps([
        channel for channel in state["channels"]
        if channel["name"] == query and (include_archived or not channel["archived"])
    ]))
elif "create" in argv:
    channel_id = "00000000-0000-4000-8000-%012d" % (len(state["channels"]) + 1)
    state["channels"].append(
        {"channel_id": channel_id, "name": opt("--name"), "archived": False}
    )
    save()
    print(json.dumps(
        {"event_id": "e" * 64, "accepted": True, "message": "", "channel_id": channel_id}
    ))
elif "unarchive" in argv:
    for channel in state["channels"]:
        if channel["channel_id"] == opt("--channel"):
            channel["archived"] = False
    save()
    print(json.dumps({"event_id": "e" * 64, "accepted": True, "message": ""}))
else:
    sys.exit("stub ambush: unhandled args: " + " ".join(argv))
STUB
  chmod +x "$work/ambush"
  echo "$work"
}

# Run the script inside a prepared root. Stdout+stderr to $work/out.log.
run_provision() {
  local work="$1"
  set +e
  env -u AMBUSH_PRIVATE_KEY \
    AMBUSH_RELAY_URL="file://$work/relay" \
    AMBUSH_CLI="$work/ambush" \
    PERCH_DEV_DIR="$work/out" \
    STUB_STATE="$work/state.json" \
    STUB_LOG="$work/cli.log" \
    bash "$work/root/scripts/provision-perch.sh" >"$work/out.log" 2>&1
  local status=$?
  set -e
  echo "$status"
}

# --- 1. a fresh root provisions all twelve lanes ------------------------------
work="$(make_root with-taxonomy)"
status="$(run_provision "$work")"
if [ "$status" -ne 0 ]; then
  fail "fresh provision exited $status"
  cat "$work/out.log" >&2
else
  lanes="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' \
    "$work/out/lane-channels.json")"
  [ "$lanes" = "12" ] || fail "fresh provision wrote $lanes lanes, expected 12"
  pass "a fresh root provisions twelve lanes"
fi

# --- 2. the operator secret never reaches a child process's argv --------------
if grep -qF "$DEV_SECRET" "$work/node-argv.log"; then
  fail "the operator secret appears in node's argv (visible in ps -ef)"
else
  pass "the operator secret stays out of child argv"
fi
if ! grep -qF "$DEV_SECRET" "$work/out/operator.env"; then
  fail "operator.env is missing the secret it is supposed to carry"
fi
pubkey="$(sed -n 's/^AMBUSH_OPERATOR_PUBKEY=//p' "$work/out/operator.env")"
case "$pubkey" in
  [0-9a-f]*) [ "${#pubkey}" -eq 64 ] || fail "derived pubkey is ${#pubkey} chars, expected 64" ;;
  *) fail "derived pubkey is not lowercase hex: $pubkey" ;;
esac

# --- 3. archived lanes are reused, not duplicated -----------------------------
python3 - "$work/state.json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    state = json.load(handle)
for channel in state["channels"]:
    channel["archived"] = True
with open(path, "w", encoding="utf-8") as handle:
    json.dump(state, handle)
PY
before="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])))' \
  "$work/out/lane-channels.json")"
: >"$work/cli.log"
status="$(run_provision "$work")"
if [ "$status" -ne 0 ]; then
  fail "re-run over archived lanes exited $status"
  cat "$work/out.log" >&2
else
  creates="$(grep -c ' create ' "$work/cli.log" || true)"
  unarchives="$(grep -c ' unarchive ' "$work/cli.log" || true)"
  total="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["channels"]))' \
    "$work/state.json")"
  after="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])))' \
    "$work/out/lane-channels.json")"
  [ "$creates" = "0" ] || fail "re-run created $creates duplicate lane channels, expected 0"
  [ "$unarchives" = "12" ] || fail "re-run unarchived $unarchives lanes, expected 12"
  [ "$total" = "12" ] || fail "relay now holds $total channels, expected 12"
  [ "$before" = "$after" ] || fail "lane ids changed across a re-run"
  [ "$creates" = "0" ] && [ "$unarchives" = "12" ] \
    && pass "an archived lane is found and unarchived, never duplicated"
fi
rm -rf "$work"

# --- 4. an unverifiable lane taxonomy is fatal --------------------------------
work="$(make_root without-taxonomy)"
status="$(run_provision "$work")"
if [ "$status" -eq 0 ]; then
  fail "missing escalation.rs provisioned anyway (exit 0) instead of failing"
elif ! grep -q "lane list cannot be checked" "$work/out.log"; then
  fail "missing escalation.rs failed without explaining why:"
  cat "$work/out.log" >&2
elif [ -f "$work/out/lane-channels.json" ]; then
  fail "missing escalation.rs still wrote lane-channels.json"
else
  pass "a missing lane taxonomy is a hard failure"
fi
rm -rf "$work"

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all provision-perch checks passed"
