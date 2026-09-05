#!/usr/bin/env bash
#
# The OS notification bodies interpolate only typed fields, and there are
# exactly four of them.
#
# WHY THIS EXISTS
#   An OS notification is rendered by the operating system: outside this app's
#   markup, outside its escaping, and on a lock screen a passer-by can read. A
#   detector's `command_line` in a notification body is a remote-controlled
#   string on the operator's screen, and no amount of care in the renderer
#   prevents it, because the renderer is not involved.
#
#   The second rule is about attention rather than safety. The set of events
#   allowed to interrupt a person is a decision. Left as a default, every
#   surface that could add one eventually does, and the four that matter stop
#   being distinguishable from the twenty that do not. Findings never page.
#
# WHAT IS COVERED
#   workspace/desktop/src/features/perch/notifications/copy.ts
#     N1  every `{name}` inside NOTIFICATION_BODIES is a member of
#         NOTIFICATION_FIELDS
#     N2  NOTIFICATION_BODIES has exactly four keys
#
# WHAT THIS CANNOT SEE
#   A caller that formats its own body instead of reading NOTIFICATION_BODIES.
#   That is the desktop unit test's job (notificationBodies.test.mjs) plus the
#   perch branch of use-feed-desktop-notifications.ts, which reads this module
#   by key and holds no format string of its own.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET="${1:-workspace/desktop/src/features/perch/notifications/copy.ts}"

# The scan, as one function, so the fixture and the real file cannot drift.
# Prints one line per violation; silent means clean.
scan() {
  python3 - "$1" <<'PY'
import re, sys

path = sys.argv[1]
src = open(path, encoding="utf-8").read()

def block(name):
    start = src.find(f"export const {name}")
    if start == -1:
        print(f"{path}: {name} is not exported")
        return None
    # From the first bracket to its match, tracking [] and {} together so a
    # nested object cannot end the block early.
    i = src.find("=", start)
    depth = 0
    for j in range(i, len(src)):
        c = src[j]
        if c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    print(f"{path}: {name} is not closed")
    return None

fields_block = block("NOTIFICATION_FIELDS")
bodies_block = block("NOTIFICATION_BODIES")
if fields_block is None or bodies_block is None:
    sys.exit(0)

fields = set(re.findall(r'"([A-Za-z]+)"', fields_block))

# Strip comments before counting keys or placeholders: a commented-out key is
# not a key, and a `{name}` in a comment is documentation.
no_block = re.sub(r"/\*.*?\*/", "", bodies_block, flags=re.S)
no_line = re.sub(r"//[^\n]*", "", no_block)

keys = re.findall(r"(?m)^\s{2}([A-Za-z][A-Za-z0-9_]*):", no_line)
if len(keys) != 4:
    print(f"{path}: N2 NOTIFICATION_BODIES has {len(keys)} keys, expected 4: {sorted(keys)}")

for name in sorted(set(re.findall(r"\{([A-Za-z]+)\}", no_line))):
    if name not in fields:
        print(f"{path}: N1 {{{name}}} is not in NOTIFICATION_FIELDS")
PY
}

# ---------------------------------------------------------------- fixture --
# A gate that has never been observed to fail is not a gate.
FIXTURE_DIR="$(mktemp -d)"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

cat >"$FIXTURE_DIR/untyped.ts" <<'BAD'
export const NOTIFICATION_FIELDS = ["actionKind", "severity"] as const;
export const NOTIFICATION_BODIES = {
  incident: "Mode INCIDENT · {actionKind}",
  holdNamedYou: "A held {actionKind} at {severity}",
  containmentFailedToRelease: "Lease expired · {commandLine}",
  snoozeDue: "Snooze returned",
} as const;
BAD

cat >"$FIXTURE_DIR/fifth.ts" <<'BAD'
export const NOTIFICATION_FIELDS = ["actionKind"] as const;
export const NOTIFICATION_BODIES = {
  incident: "a",
  holdNamedYou: "b",
  containmentFailedToRelease: "c",
  snoozeDue: "d",
  findingArrived: "e",
} as const;
BAD

cat >"$FIXTURE_DIR/clean.ts" <<'CLEAN'
export const NOTIFICATION_FIELDS = ["actionKind", "severity"] as const;
export const NOTIFICATION_BODIES = {
  // {commandLine} would be a violation; in a comment it is documentation.
  incident: "Mode INCIDENT",
  holdNamedYou: "A held {actionKind} at {severity}",
  containmentFailedToRelease: "Lease expired",
  snoozeDue: "Snooze returned",
} as const;
CLEAN

if ! scan "$FIXTURE_DIR/untyped.ts" | grep -q "N1 {commandLine}"; then
  echo "check-perch-notification-fields: SELF-TEST FAILED -- N1 caught nothing." >&2
  exit 2
fi
if ! scan "$FIXTURE_DIR/fifth.ts" | grep -q "N2 "; then
  echo "check-perch-notification-fields: SELF-TEST FAILED -- N2 caught nothing." >&2
  exit 2
fi
CLEAN_HITS="$(scan "$FIXTURE_DIR/clean.ts")"
if [ -n "$CLEAN_HITS" ]; then
  echo "check-perch-notification-fields: SELF-TEST FAILED -- clean control flagged:" >&2
  printf '%s\n' "$CLEAN_HITS" >&2
  exit 2
fi

# ------------------------------------------------------------------- scan --
if [ ! -f "$TARGET" ]; then
  echo "check-perch-notification-fields: $TARGET does not exist" >&2
  exit 2
fi

HITS="$(scan "$TARGET")"
if [ -n "$HITS" ]; then
  echo "check-perch-notification-fields: violations" >&2
  printf '%s\n' "$HITS" >&2
  echo >&2
  echo "N1 -> an OS notification is rendered outside this app's escaping; every" >&2
  echo "      interpolation must be a typed field from NOTIFICATION_FIELDS" >&2
  echo "N2 -> exactly four wake classes. Findings never page." >&2
  exit 1
fi

echo "check-perch-notification-fields: OK (4 wake classes, every field typed; self-test 2 rules fired, 1 control clean)"
