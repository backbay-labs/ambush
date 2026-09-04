#!/usr/bin/env bash
#
# B1 commitment C4. `SwarmRuntime::authorize_and_execute`
# (crates/swarm-runtime/src/lib.rs, the non-audit variant) returns
# `ApprovalError::Denied` on RequireHuman instead of an AuditTrail, so a
# RequireHuman reaching it is NOT captured as a hold. It has no production
# caller today. This gate keeps it that way: the first caller must move the
# interception in-runtime (12-BACKEND-BILL-API.md §3.5 option (a)).
#
# THE HOLE THIS CLOSES
#   `IngestRuntimeRequestResponseRouter::route_request` calls
#   `audit_authorize_and_execute` and captures the returned `Skipped`
#   RequireHuman trail as a durable hold. The other door -- the bare
#   `authorize_and_execute` -- has no capture and cannot grow one without
#   moving the interception inside the runtime. A caller appearing there would
#   silently drop a destructive action that a human was supposed to see, with
#   no store row, no `46010`, no alarm and no log line saying so. That is the
#   failure this milestone exists to make impossible, so it gets a gate rather
#   than a comment.
#
# SHAPE
#   check-visibility-baseline.sh's: an allowlist of KNOWN call sites, where a
#   STALE entry also fails, so the list cannot rot into a no-op.
#
# WHY NOT PLAIN GREP
#   Because an empty scan and a broken needle look identical. Every invocation
#   first plants a synthetic call in a temp tree and asserts the needle matches
#   it; if that fails the script exits 2 without scanning. A gate that cannot
#   see its own subject is not a passing gate.
#
# BASH 3.2
#   No `mapfile`: macOS ships bash 3.2 and a gate a developer cannot run
#   locally is a gate that is only ever seen red in CI.
set -euo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Known non-test call sites, as `<path>:<count>`. Today: none.
ALLOWLIST=()

# --- self-test on a fixture, so an empty scan cannot pass vacuously ---------
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/crates/x/src"
printf 'fn a() { runtime.authorize_and_execute(&r, &c).await }\n' > "$fixture/crates/x/src/lib.rs"
if ! grep -rn --include='*.rs' -E '\.authorize_and_execute\(' "$fixture/crates" >/dev/null; then
  echo "check-no-unrouted-authorize: FIXTURE FAILED -- the needle does not match a planted call" >&2
  exit 2
fi
# The audit variant must NOT match: it is the routed door, and a needle that
# caught it would report the routed path as a violation on every run.
printf 'fn b() { runtime.audit_authorize_and_execute(&d, &r, &c).await }\n' > "$fixture/crates/x/src/audit.rs"
if grep -rn --include='*.rs' -E '\.authorize_and_execute\(' "$fixture/crates/x/src/audit.rs" \
  | grep -v -E 'audit_authorize_and_execute' | grep -q .; then
  echo "check-no-unrouted-authorize: FIXTURE FAILED -- the needle matches the routed audit variant" >&2
  exit 2
fi

# --- the real scan ----------------------------------------------------------
# `crates/*/tests/`, `*_tests.rs` and `tests.rs` are dev targets, not the
# live-response lane. `audit_authorize_and_execute` is the ROUTED door and is
# excluded by name. The declaration line itself is not a call.
raw_hits="$(grep -rn --include='*.rs' -E '\.authorize_and_execute\(' crates \
  | grep -v -E '(/tests?/|_tests\.rs|/tests\.rs)' \
  | grep -v -E 'audit_authorize_and_execute' \
  | grep -v -E 'crates/swarm-runtime/src/lib\.rs:[0-9]+:[[:space:]]*pub async fn authorize_and_execute' \
  || true)"

# A `#[cfg(test)] mod tests { ... }` inside a `src/` file compiles into the lib
# test target, not into the daemon, so a call inside one is not a live caller.
#
# The suppression is a SPAN check, not "after the first #[cfg(test)] line".
# The line-offset form is a silent unscan: a production caller appended below a
# file's test module reads as test code and the gate goes green over it. That
# was measured -- appending an unrouted caller to the end of dispatcher.rs
# passed under the offset rule and fails under this one.
#
# `cfg_test_spans` emits `start end` pairs for both shapes the tree uses: a
# braced `mod tests { .. }` closing at column 0, and the `#[cfg(test)]
# #[path = ".."] mod tests;` declaration form, which spans only its own lines.
cfg_test_spans() {
  awk '
    /^#\[cfg\(test\)\]/ && state == 0 { state = 1; start = NR; next }
    state == 1 && /^#\[/                 { next }
    state == 1 && /;[[:space:]]*$/        { print start, NR; state = 0; next }
    state == 1 && /\{[[:space:]]*$/       { state = 2; next }
    state == 1                           { state = 0; next }
    state == 2 && /^\}/                  { print start, NR; state = 0; next }
    END { if (state != 0) print start, NR }
  ' "$1"
}

filtered=""
suppressed=0
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  file="${hit%%:*}"; rest="${hit#*:}"; line="${rest%%:*}"
  in_test=0
  while read -r span_start span_end; do
    [ -n "$span_start" ] || continue
    if [ "$line" -ge "$span_start" ] && [ "$line" -le "$span_end" ]; then
      in_test=1
      break
    fi
  done <<SPANS
$(cfg_test_spans "$file")
SPANS
  if [ "$in_test" -eq 1 ]; then
    suppressed=$((suppressed + 1))
    continue
  fi
  filtered="${filtered}${hit}
"
done <<EOF
$raw_hits
EOF

status=0
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  echo "check-no-unrouted-authorize: UNROUTED CALLER: $hit" >&2
  echo "  A RequireHuman reaching authorize_and_execute is refused, not held. Route through" >&2
  echo "  IngestRuntimeRequestResponseRouter::route_request, or move the intercept in-runtime." >&2
  status=1
done <<EOF
$filtered
EOF

for entry in ${ALLOWLIST[@]+"${ALLOWLIST[@]}"}; do
  [ -n "$entry" ] || continue
  path="${entry%%:*}"
  if ! printf '%s' "$filtered" | grep -q "^${path}:"; then
    echo "check-no-unrouted-authorize: STALE ALLOWLIST ENTRY: $entry (no such caller any more)" >&2
    status=1
  fi
done

if [ "$status" -eq 0 ]; then
  echo "check-no-unrouted-authorize: clean (0 non-test callers of authorize_and_execute; ${suppressed} cfg(test) call(s) excluded)"
fi
exit "$status"
