#!/usr/bin/env bash
#
# INV-01: the console's Ambush-bound write surface is exactly five routes.
#
# WHY THIS EXISTS
#   "Perch NEVER authorizes" is the product's whole claim, and it is a claim
#   about a SET: the set of non-GET requests the console process can issue to an
#   Ambush host. A claim about a set is only true if the set is enumerable, and
#   it is only enumerable if there is no generic passthrough. So the client is
#   built with one Tauri command per route and the route string compiled into
#   Rust (17-COMPONENT-SPECS.md and the tauriPerch.ts skeleton both DECIDE this),
#   and this script asserts the shape holds.
#
#   The five, from APPENDIX-NORMATIVE.md section 5 and 08 INV-01:
#     POST /v1/response/holds/{hold_id}/decide                   (B2)
#     POST /v1/operator/findings/{finding_id}/feedback           (B3)
#     POST /v1/operator/incidents                                (B3i)
#     POST /v1/operator/containment/leases/{lease_id}/release
#     POST /v1/operator/review/sessions
#   B3i was missing from 08's first draft and would have failed the build on the
#   first promote-to-case. It is in the table below, by name, for that reason.
#
# WHAT IS COVERED
#   $PERCH_DESKTOP_ROOT/src-tauri/src/perch/ and src-tauri/src/commands/perch_*.rs.
#     W1  a PERCH_DAEMON_WRITES table exists and its (method, path) pairs are
#         EXACTLY the five above -- set equality, both directions
#     W2  no non-GET HTTP verb appears anywhere on the Perch Rust surface except
#         inside the one dispatch function that consults the table
#     W3  no generic passthrough: no command name matching
#         perch_(request|call|fetch|proxy|daemon_request)
#     W4  the renderer never names a daemon URL: no `http://` or `https://`
#         literal under the Perch feature roots
#
# WHAT THIS SCRIPT CANNOT SEE, AND THEREFORE DOES NOT CLAIM
#   1. A path built at runtime from a config value. W1 reads literals. The
#      runtime half is the Rust assertion in
#      tests/rust/buzz/perch_daemon_client_tests.rs, which drives
#      `perch_daemon_request` with an unlisted (method, path) and asserts it
#      returns Err BEFORE any socket is opened. That test is the real INV-01;
#      this script is the tripwire that keeps the shape reviewable.
#   2. A write issued by something other than the Tauri process -- the relay
#      publish path, for instance. That is deliberate: leg 1 is a signed intent
#      card on the relay and carries no authority, which is the whole two-legged
#      design. INV-12 and INV-29 cover that leg.
#   3. Anything the bridge does. The bridge is a different process with a
#      different key and its own budget (11-BRIDGE-CRATE.md).
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ROOTS_LIB="$ROOT_DIR/tools/lib/perch-roots.sh"
if [ ! -f "$ROOTS_LIB" ]; then
  echo "missing $ROOTS_LIB; refusing to pass silently" >&2
  exit 1
fi
# shellcheck source=tools/lib/perch-roots.sh
. "$ROOTS_LIB"

if [ -z "${PERCH_DESKTOP_ROOT:-}" ] || [ ! -d "${PERCH_DESKTOP_ROOT}" ]; then
  echo "PERCH_DESKTOP_ROOT is unset or not a directory; refusing to pass silently" >&2
  exit 1
fi

EXPECTED="$(cat <<'EOF'
POST /v1/operator/containment/leases/{lease_id}/release
POST /v1/operator/findings/{finding_id}/feedback
POST /v1/operator/incidents
POST /v1/operator/review/sessions
POST /v1/response/holds/{hold_id}/decide
EOF
)"

extract_table() {
  # Every ("VERB", "/path") pair inside the PERCH_DAEMON_WRITES literal.
  sed -n '/PERCH_DAEMON_WRITES/,/^\];\|^];/p' "$1" \
    | awk '
        {
          rest = $0
          while (match(rest, "\\(\"[A-Z]+\",[[:space:]]*\"/[^\"]*\"\\)")) {
            st = RSTART; ln = RLENGTH
            chunk = substr(rest, st, ln)
            gsub(/[()"]/, "", chunk)
            gsub(/,[[:space:]]*/, " ", chunk)
            print chunk
            rest = substr(rest, st + ln)
          }
        }
      ' | LC_ALL=C sort -u
}

# ---------------------------------------------------------------------------
# FIXTURE
# ---------------------------------------------------------------------------
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/perch-write-gate.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
fixture_failures=0

perch_roots_selftest || fixture_failures=$((fixture_failures + 1))

cat > "$FIXTURE_DIR/routes.good.rs" <<'FIX'
pub const PERCH_DAEMON_WRITES: [(&str, &str); 5] = [
    ("POST", "/v1/response/holds/{hold_id}/decide"),
    ("POST", "/v1/operator/findings/{finding_id}/feedback"),
    ("POST", "/v1/operator/incidents"),
    ("POST", "/v1/operator/containment/leases/{lease_id}/release"),
    ("POST", "/v1/operator/review/sessions"),
];
FIX
cat > "$FIXTURE_DIR/routes.sixth.rs" <<'FIX'
pub const PERCH_DAEMON_WRITES: [(&str, &str); 6] = [
    ("POST", "/v1/response/holds/{hold_id}/decide"),
    ("POST", "/v1/operator/findings/{finding_id}/feedback"),
    ("POST", "/v1/operator/incidents"),
    ("POST", "/v1/operator/containment/leases/{lease_id}/release"),
    ("POST", "/v1/operator/review/sessions"),
    ("DELETE", "/v1/operator/containment/leases/{lease_id}"),
];
FIX

if [ "$(extract_table "$FIXTURE_DIR/routes.good.rs")" != "$EXPECTED" ]; then
  echo "FIXTURE FAILURE: the table extractor did not reproduce the five expected routes" >&2
  echo "got:"; extract_table "$FIXTURE_DIR/routes.good.rs" >&2
  fixture_failures=$((fixture_failures + 1))
fi
if [ "$(extract_table "$FIXTURE_DIR/routes.sixth.rs")" = "$EXPECTED" ]; then
  echo "FIXTURE FAILURE: a sixth write route was not detected" >&2
  fixture_failures=$((fixture_failures + 1))
fi

if [ "$fixture_failures" -ne 0 ]; then
  echo "The fixture proves this scanner can fail. Fix the scanner, not the fixture." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# REAL SCAN
# ---------------------------------------------------------------------------
perch_roots_gate writes "$PERCH_DESKTOP_ROOT"

rust_files=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  case "$path" in *_tests.rs) continue ;; esac
  rust_files+=("$path")
done < <(
  find "$PERCH_DESKTOP_ROOT/src-tauri/src/perch" -name '*.rs' -type f 2>/dev/null
  find "$PERCH_DESKTOP_ROOT/src-tauri/src/commands" -name 'perch_*.rs' -type f 2>/dev/null
)

# THE PHASE-0 ARM, keyed on ONE manifest row rather than on the aggregate.
# `src-tauri/src/commands` carries status `probe`: it already exists in
# block/buzz at eed74bde2 and perch_roots_gate has therefore already failed if
# PERCH_DESKTOP_ROOT does not resolve to a real Buzz desktop/ tree. So reaching
# this line with zero Rust files means one of exactly two things, and the
# `src-tauri/src/perch` row says which: `absent` is Phase 0, `required` is a
# module that was supposed to be there and is not.
if [ "${#rust_files[@]}" -eq 0 ]; then
  if [ "$(perch_root_status 'src-tauri/src/perch')" != "required" ]; then
    echo "write-allowlist gate: no Perch Rust file exists yet, so nothing was asserted."
    echo "" >&2
    echo "WARNING: INV-01's write surface is unenforced. tools/perch-source-roots.tsv" >&2
    echo "marks src-tauri/src/perch 'absent' and no commands/perch_*.rs exists. The" >&2
    echo "commit that creates either fails this gate until it flips that row to" >&2
    echo "'required'. The fixture above still ran, so the scanner itself is known" >&2
    echo "good, and the manifest's one `required` row proved PERCH_DESKTOP_ROOT" >&2
    echo "resolves -- a wrong checkout path does NOT reach this arm." >&2
    exit 0
  fi
  echo "tools/perch-source-roots.tsv marks src-tauri/src/perch required and it exists," >&2
  echo "but no .rs file was found in it or in commands/perch_*.rs; refusing to pass" >&2
  echo "silently" >&2
  exit 1
fi

violations=""
table_file=""
for f in "${rust_files[@]}"; do
  if grep -q 'PERCH_DAEMON_WRITES' "$f"; then table_file="$f"; break; fi
done
if [ -z "$table_file" ]; then
  violations="${violations}W1	-	no PERCH_DAEMON_WRITES table found; INV-01's set is not enumerable"$'\n'
else
  got="$(extract_table "$table_file")"
  if [ "$got" != "$EXPECTED" ]; then
    # Symmetric difference, one violation line per differing route, so the
    # failure names the route rather than dumping two lists a reader must diff.
    while IFS= read -r extra; do
      [ -n "$extra" ] || continue
      violations="${violations}W1	$table_file	not on the INV-01 allowlist: ${extra// /~}"$'\n'
    done < <(comm -13 <(printf '%s\n' "$EXPECTED") <(printf '%s\n' "$got"))
    while IFS= read -r missing; do
      [ -n "$missing" ] || continue
      violations="${violations}W1	$table_file	an INV-01 route is missing from the table: ${missing// /~}"$'\n'
    done < <(comm -23 <(printf '%s\n' "$EXPECTED") <(printf '%s\n' "$got"))
  fi
fi

w2="$(awk '
  $0 ~ /^[[:space:]]*(\/\/|\/\/!|\*)/ { next }
  /PERCH_DAEMON_WRITES/ { next }
  /Method::(POST|PUT|PATCH|DELETE)|\.post\(|\.put\(|\.patch\(|\.delete\(/ {
    printf "W2\t%s:%d\ta non-GET verb outside the table-driven dispatch\n", FILENAME, FNR
  }' "${rust_files[@]}" | grep -v 'perch_daemon_request' || true)"
[ -n "$w2" ] && violations="${violations}${w2}"$'\n'

w3="$(grep -Rn -E 'fn perch_(request|call|fetch|proxy|daemon_request_generic)\b' "${rust_files[@]}" 2>/dev/null \
      | awk -F: '{ printf "W3\t%s:%s\ta generic daemon passthrough command; INV-01 requires one command per route\n", $1, $2 }' || true)"
[ -n "$w3" ] && violations="${violations}${w3}"$'\n'

ts_files=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  case "$path" in *.test.*|*.spec.*|*/tests/*) continue ;; esac
  ts_files+=("$path")
done < <(
  find "$PERCH_DESKTOP_ROOT/src/features" -maxdepth 1 -type d -name 'perch*' \
    -exec find {} \( -name '*.ts' -o -name '*.tsx' \) -type f \; 2>/dev/null | LC_ALL=C sort
)
if [ "${#ts_files[@]}" -gt 0 ]; then
  w4="$(awk '
    $0 ~ /^[[:space:]]*(\/\/|\*|\/\*)/ { next }
    /https?:\/\// { printf "W4\t%s:%d\tthe renderer names a URL; every daemon route lives in Rust\n", FILENAME, FNR }
  ' "${ts_files[@]}")"
  [ -n "$w4" ] && violations="${violations}${w4}"$'\n'
fi

if [ -n "$(printf '%s' "$violations" | tr -d '\n')" ]; then
  echo "INV-01 violations (the console's Ambush-bound write surface):" >&2
  printf '%s' "$violations" | grep -v '^$' | sed "s#$PERCH_DESKTOP_ROOT/##g" \
    | awk -F'\t' 'NF >= 3 { gsub(/~/, " ", $3); printf "  [%s] %s\n      %s\n", $1, $2, $3 }' >&2
  exit 1
fi

echo "write-allowlist gate clean: 5 routes, ${#rust_files[@]} Rust file(s), ${#ts_files[@]} renderer file(s)"
