#!/usr/bin/env bash
#
# INV-14: the trusted-string allowlist, enforced where it can actually hold.
#
# WHY THIS EXISTS, AND WHY IT IS NOT THE GATE 08 SECTION 9 IMAGINED
#   INV-14 as written is "every interpolated string in the Perch feature tree
#   that is not on the trusted-value allowlist is wrapped in <AdversaryString>".
#   A lexical gate cannot decide that. `{row.summary}` is adversary-controlled
#   and `{row.severity}` is not, and nothing about the two expressions says so.
#   A gate that guesses produces a wall of false positives and is switched off,
#   which is worse than no gate.
#
#   So the enforcement moves into the TYPE SYSTEM and this script guards the
#   type system's two escape hatches.
#
#     THE TYPE.  `AdversaryText` is a branded string
#     (`type AdversaryText = string & { readonly __adversary: unique symbol }`).
#     Every `string`-typed field on every Perch wire type is `AdversaryText`.
#     `<AdversaryString value={…}>` is the only component whose `value` prop
#     accepts `AdversaryText`, and JSX text position, `title`, `aria-label`,
#     `alt` and `placeholder` reject it because they take `string`. Then `tsc`
#     -- which already runs on every pre-push (BUZZ CLAUDE.md) -- is the gate,
#     and it is exhaustive over exactly the thing INV-14 wants.
#
#     THE ESCAPE HATCHES, which is what this script closes:
#       E1  `as string` / `as unknown as` / `as any` launders the brand.
#       E2  a wire type declaring a bare `string` field never acquires it.
#       E3  a template literal (`${x}`) coerces AdversaryText to string with no
#           cast at all -- TypeScript widens a branded string in a template.
#           This is the hole that would otherwise make the whole scheme decorative.
#       E4  `String(x)`, `x.toString()`, `x + ""` do the same.
#
# WHAT IS COVERED
#   $PERCH_DESKTOP_ROOT/src/features/perch*/ and src/shared/ui/perch/,
#   .ts/.tsx, excluding *.test.*, *.spec.*, tests/.
#     A1  `AdversaryText` is declared, exactly once, as a branded type
#     A2  zero `as string`, `as unknown`, `as any` in the tree            (E1)
#     A3  every `: string` field inside a `type Perch*Wire` / `*WireV1` block
#         is `AdversaryText`                                             (E2)
#     A4  no `${` interpolation, `String(`, `.toString()` or `+ ""` applied to
#         an identifier whose name is on the wire-field name list         (E3, E4)
#
# WHAT THIS SCRIPT CANNOT SEE, AND THEREFORE DOES NOT CLAIM
#   1. A4 is name-based. It knows `summary`, `reason`, `file_path`,
#      `command_line`, `rule_name`, `note`, `detail`, `message`, `topic` and
#      `display_name` because those are the adversary-reachable field names in
#      13-WIRE-SCHEMAS.md. A wire field added under a new name is invisible
#      until it is added to WIRE_TEXT_FIELDS below. That list is the human
#      review this gate substitutes for, written down.
#   2. A value renamed into a local (`const s = row.summary; …${s}`) defeats A4.
#      `tsc` still catches it if `s` keeps its type, which it does unless E1 was
#      used -- and A2 closes E1. The two rules only hold TOGETHER.
#   3. It says nothing about whether <AdversaryString> renders safely. That is
#      tests/e2e/perch-marker-admission.spec.ts.
#
# PROVING IT CAN FAIL
#   A fixture per rule plus a clean control, run on every invocation.
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

# The adversary-reachable string field names, from 13-WIRE-SCHEMAS.md. Adding a
# wire field means adding it here in the same commit; that is the point.
WIRE_TEXT_FIELDS="summary reason rule_name file_path command_line process_name note detail message topic display_name user_id credential_id session_id task_name domain target host_id"

scan_casts() {
  awk '
    $0 ~ /^[[:space:]]*(\/\/|\*|\/\*)/ { next }
    # awk EREs have no \b. `([^A-Za-z]|$)` is the boundary idiom, the same one
    # tools/copy-ban-list.tsv documents; the first draft used \b and the fixture
    # caught it on the first run.
    /as[[:space:]]+string([^A-Za-z]|$)/ || /as[[:space:]]+unknown([^A-Za-z]|$)/ || /as[[:space:]]+any([^A-Za-z]|$)/ {
      printf "A2\t%s:%d\t%s\n", FILENAME, FNR, "a cast that launders the AdversaryText brand"
    }
  ' "$@"
}

scan_coercions() {
  awk -v fields="$WIRE_TEXT_FIELDS" '
    BEGIN { split(fields, f, " "); for (i in f) want[f[i]] = 1 }
    $0 ~ /^[[:space:]]*(\/\/|\*|\/\*)/ { next }
    {
      for (name in want) {
        # `${…name…}` -- template interpolation of a wire text field.
        if ($0 ~ ("[$][{][^}]*[.]" name "[^A-Za-z_}]*[}]") || $0 ~ ("[$][{][[:space:]]*" name "[[:space:]]*[}]")) {
          printf "A4\t%s:%d\t%s is interpolated into a template literal; that coerces AdversaryText to string and defeats the type gate\n", FILENAME, FNR, name
        }
        if ($0 ~ ("String[(][^)]*" name) || $0 ~ (name "[.]toString[(]")) {
          printf "A4\t%s:%d\t%s is coerced with String()/toString()\n", FILENAME, FNR, name
        }
      }
    }
  ' "$@"
}

scan_wire_fields() {
  awk '
    /^(export )?(type|interface) [A-Za-z]*Wire(V1)?([^A-Za-z]|$)/ { inwire = 1 }
    inwire && /^[};]/ { inwire = 0 }
    inwire && /:[[:space:]]*string[;,]?[[:space:]]*$/ {
      printf "A3\t%s:%d\ta wire type declares a bare `string` field; every wire string is AdversaryText\n", FILENAME, FNR
    }
  ' "$@"
}

# ---------------------------------------------------------------------------
# FIXTURE
# ---------------------------------------------------------------------------
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/perch-adversary-gate.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
fixture_failures=0

perch_roots_selftest || fixture_failures=$((fixture_failures + 1))

expect_nonempty() { [ -n "$1" ] || { echo "FIXTURE FAILURE: $2" >&2; fixture_failures=$((fixture_failures + 1)); }; }
expect_empty()    { [ -z "$1" ] || { echo "FIXTURE FAILURE: $2 -- got: $1" >&2; fixture_failures=$((fixture_failures + 1)); }; }

cat > "$FIXTURE_DIR/bad.tsx" <<'FIX'
export function Row({ hold }: { hold: PerchHoldWire }) {
  const label = `${hold.summary} on ${hold.host_id}`;
  const raw = hold.reason as string;
  return <span title={String(hold.file_path)}>{raw}</span>;
}
FIX
cat > "$FIXTURE_DIR/good.tsx" <<'FIX'
export function Row({ hold }: { hold: PerchHoldWire }) {
  return (
    <>
      <AdversaryString field="summary" value={hold.summary} />
      <AdversaryString field="host_id" value={hold.host_id} />
      <span>{hold.severity}</span>
    </>
  );
}
FIX
cat > "$FIXTURE_DIR/wire.bad.ts" <<'FIX'
export type PerchHoldWire = {
  hold_id: string;
  summary: string;
};
FIX
cat > "$FIXTURE_DIR/wire.good.ts" <<'FIX'
export type PerchHoldWire = {
  hold_id: HexId;
  summary: AdversaryText;
};
FIX

expect_nonempty "$(scan_casts "$FIXTURE_DIR/bad.tsx")" "A2 did not catch \`as string\`"
expect_empty    "$(scan_casts "$FIXTURE_DIR/good.tsx")" "A2 flagged a clean file"
expect_nonempty "$(scan_coercions "$FIXTURE_DIR/bad.tsx")" "A4 did not catch a template interpolation of a wire text field"
expect_empty    "$(scan_coercions "$FIXTURE_DIR/good.tsx")" "A4 flagged a properly wrapped file"
expect_nonempty "$(scan_wire_fields "$FIXTURE_DIR/wire.bad.ts")" "A3 did not catch a bare \`string\` wire field"
expect_empty    "$(scan_wire_fields "$FIXTURE_DIR/wire.good.ts")" "A3 flagged a branded wire type"

if [ "$fixture_failures" -ne 0 ]; then
  echo "" >&2
  echo "The fixture proves this scanner can fail. $fixture_failures cases misbehaved." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# REAL SCAN
# ---------------------------------------------------------------------------
perch_roots_gate adversary "$PERCH_DESKTOP_ROOT"

if [ "$PERCH_TREE_STATE" != "present" ]; then
  echo "adversary-string gate: the Perch tree does not exist yet, so nothing was asserted."
  echo "" >&2
  echo "WARNING: no Perch source was scanned. INV-14's four escape hatches are" >&2
  echo "unenforced and the AdversaryText brand is not asserted to exist at all." >&2
  echo "tools/perch-source-roots.tsv marks every scanned root 'absent'; the commit" >&2
  echo "that creates the first one fails this gate until it flips that row to" >&2
  echo "'required'. The fixture above still ran, so the scanner itself is known good." >&2
  exit 0
fi

files=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  case "$path" in *.test.*|*.spec.*|*/tests/*) continue ;; esac
  files+=("$path")
done < <(
  for dir in "${PERCH_ROOT_DIRS[@]}"; do
    find "$dir" \( -name '*.ts' -o -name '*.tsx' \) -type f 2>/dev/null
  done | LC_ALL=C sort
)
if [ "${#files[@]}" -eq 0 ]; then
  echo "tools/perch-source-roots.tsv marks Perch roots required and they exist, but no" >&2
  echo ".ts/.tsx file was found in any of them; refusing to pass silently" >&2
  exit 1
fi

brand_decls="$(grep -rn 'type AdversaryText' "${files[@]}" 2>/dev/null | grep -c . || true)"
violations=""
if [ "$brand_decls" -ne 1 ]; then
  violations="${violations}A1	-	AdversaryText must be declared exactly once as a branded type; found $brand_decls declaration(s)"$'\n'
fi
violations="${violations}$(scan_casts "${files[@]}")"$'\n'
violations="${violations}$(scan_coercions "${files[@]}")"$'\n'
violations="${violations}$(scan_wire_fields "${files[@]}")"$'\n'

if [ -n "$(printf '%s' "$violations" | tr -d '\n')" ]; then
  echo "INV-14 violations (the AdversaryText brand's escape hatches):" >&2
  printf '%s' "$violations" | grep -v '^$' | sed "s#$PERCH_DESKTOP_ROOT/##g" \
    | awk -F'\t' 'NF >= 3 { printf "  [%s] %s\n      %s\n", $1, $2, $3 }' >&2
  exit 1
fi

echo "adversary-string gate clean over ${#files[@]} file(s)"
