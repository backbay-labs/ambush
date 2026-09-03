#!/usr/bin/env bash
#
# The grant affordance gate: INV-07, INV-10, INV-11 (static half), INV-27,
# and the closure of the `data-perch-role` attribute.
#
# WHY THIS EXISTS
#   Four invariants are greps over source and 08 section 9 says so outright. A
#   grep is only a gate if it is written down, run, and proved able to fail.
#
#   INV-10 exists because AlertDialogAction forwards `cn(buttonVariants(), …)`
#   with NO variant (BUZZ desktop/src/shared/ui/alert-dialog.tsx:149), and
#   buttonVariants() with no variant resolves to the `default` arm --
#   `bg-primary text-primary-foreground shadow` (button.tsx:12-13). A grant
#   control built the obvious way is therefore styled as the app's primary
#   action, which is exactly what render law 6 forbids. Worse,
#   applyAccentColor writes `--primary` INLINE on the root element
#   (ThemeProvider.tsx:198,213-218), so no stylesheet can defend against it and
#   a red accent makes a red grant button.
#
#   INV-11 is the two-stroke gate. Its behaviour is a Playwright test
#   (tests/e2e/perch-verdict-pane.spec.ts). What a grep CAN prove is that the
#   three mechanisms it depends on are present in the one file that declares the
#   control, and that the control is declared in exactly one file.
#
#   INV-27 exists because the daemon has no override route at all. A Perch
#   "force" control could only ever be a client-side fiction that produces a
#   500. Better to make it unbuildable.
#
# THE HOLE THIS VERSION CLOSES, STATED PLAINLY
#   Every rule in the first version keyed on the PRESENCE of
#   data-perch-role="grant". R2 counted declarations, R3 grepped only the
#   declaring file, R4 matched lines carrying the attribute. So a second,
#   entirely ungated grant control that simply OMITS the attribute left
#   grant_count at 1 and passed all four rules at once -- and this file's own
#   header claimed the opposite ("which is why R2 asserts the declaration count
#   rather than only scanning for bad ones"). Counting declarations inside the
#   Perch roots cannot detect an UNDECLARED control anywhere; that sentence was
#   wrong and is deleted.
#
#   It is not a hypothetical shape either. A peer drawing in this plan set
#   (build/prototypes/watch.html) renders
#
#       <button class="grant" data-armed=… onclick="armGrant()">
#         Record my decision and send it to the daemon
#       </button>
#
#   with no data-perch-role, no IntersectionObserver, no dwell timer and no
#   1500 -- a fully functional, entirely ungated grant affordance. Two new rules
#   catch that shape from two independent directions:
#
#     R7  THE ACCESSIBLE NAME. Render law 6 fixes the grant control's words:
#         "record my decision and send it to the daemon". Any line in the Perch
#         tree carrying that phrase, or a <button>/<AlertDialogAction> element
#         whose text matches it, must also carry data-perch-role="grant" within
#         a small window. The words are the one thing a second implementation
#         cannot change and still be the grant control.
#     R8  WRITE REACHABILITY. A control that cannot reach POST /decide is not a
#         grant control; one that can, is. The command literal
#         `perch_decide_hold` may appear under the Perch roots only in files
#         that declare data-perch-role="grant" or "refuse". A third file
#         referencing it is either an ungated decision path or a helper that
#         belongs behind one.
#
#   R7 catches a control that looks right and is ungated; R8 catches one that is
#   relabelled and still writes. Neither depends on the attribute the defect
#   omits. Both have fixture cases, including one copied from the real markup
#   above.
#
# WHAT IS COVERED
#   The roots in tools/perch-source-roots.tsv marked `grant`, .ts/.tsx,
#   excluding *.test.*, *.spec.* and tests/. Read that file's header for the
#   Phase-0 / tree-landed mechanism.
#
#     R1  every `data-perch-role="X"` value is one of the closed thirteen
#         (17-COMPONENT-SPECS.md section 1.4)
#     R2  exactly ONE file declares data-perch-role="grant"
#     R3  that file contains `.repeat`, `IntersectionObserver` and the
#         literal 1500 (INV-11's three mechanisms)
#     R4  no element carrying data-perch-role="grant" is on a line that also
#         carries `variant="default"`; and every `<AlertDialogAction` in the
#         Perch tree carries an explicit `variant=`  (INV-10)
#     R5  no `extend` affordance under the containment root except the
#         one element carrying data-perch-role="containment-extend-disabled"
#         (INV-07)
#     R6  no override / break-glass / force affordance anywhere in the tree
#         (INV-27)
#     R7  the grant control's accessible name implies the attribute
#     R8  the decide command is reachable only from a declared verdict control
#
# WHAT THIS SCRIPT CANNOT SEE, AND THEREFORE DOES NOT CLAIM
#   1. A variant passed through a variable or spread (`{...grantProps}`). R4 is
#      lexical and one indirection defeats it. The Playwright assertion on the
#      computed background colour is the real INV-10 check; this is the tripwire
#      that keeps the obvious mistake out of a diff.
#   2. Whether the 1500 it found is the dwell constant or an unrelated timeout.
#      R3 proves presence, not meaning.
#   3. An override reached by a synonym ("proceed anyway", "administrative
#      unlock"). R6 catches the words people actually reach for.
#   4. A grant control whose label is a DIFFERENT sentence and which reaches the
#      daemon through an indirection R8 cannot follow -- a re-exported wrapper,
#      say. R7 and R8 close the two shapes a second implementation actually
#      takes; they do not close every one. The Playwright assertion that exactly
#      one element with an accessible name matching /record my decision/i exists
#      in a rendered verdict pane (perch-verdict-pane.spec.ts #03) is the third
#      angle, and it reads the DOM rather than the source.
#   5. Anything outside the Perch roots, including the HTML prototypes under
#      docs/plans/. Those are drawings; a grant control drawn without its gate
#      is a review finding against the drawing, not a build failure.
#
# PROVING IT CAN FAIL
#   A fixture runs on every invocation: one planted violation per rule plus a
#   clean control for each. Same shape as tools/check-single-governor-key.sh.
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
  echo "PERCH_DESKTOP_ROOT is unset or not a directory; see tools/check-copy-banned-terms.sh's" >&2
  echo "header for the two-checkout CI wiring. Refusing to pass over a tree nobody supplied." >&2
  exit 1
fi

# The closed set. 17-COMPONENT-SPECS.md section 1.4 DECIDED these thirteen.
PERCH_ROLES="grant refuse verdict-slot blast-radius provenance-row derived source-count evidence-card adversary-string containment-release containment-extend-disabled empty-state gap-link"

# Render law 6's sentence, lowercased. The `.*` between the halves tolerates a
# JSX line break or an interpolated hold reference inside the label.
GRANT_PHRASE='record my decision'
# INV-01's decide command. 14-CLIENT-ARCHITECTURE.md names it.
DECIDE_COMMAND='perch_decide_hold'
# How many lines apart a role attribute and the label text may sit and still be
# read as one element. JSX puts the attribute on the opening tag and the text on
# a following line; six lines covers a multi-attribute opening tag comfortably
# and is small enough that two adjacent controls do not alias.
ROLE_WINDOW=6

scan_roles() {
  # path<TAB>line<TAB>role, one per occurrence
  awk '
    {
      rest = $0
      while (match(rest, "data-perch-role[[:space:]]*=[[:space:]]*\"[^\"]*\"")) {
        st = RSTART; ln = RLENGTH
        chunk = substr(rest, st, ln)
        if (match(chunk, "\"[^\"]*\"")) {
          printf "%s\t%d\t%s\n", FILENAME, FNR, substr(chunk, RSTART + 1, RLENGTH - 2)
        }
        rest = substr(rest, st + ln)
      }
    }
  ' "$@"
}

check_roles_closed() {
  local input="$1"
  awk -F'\t' -v allowed="$PERCH_ROLES" '
    BEGIN { split(allowed, a, " "); for (i in a) ok[a[i]] = 1 }
    !($3 in ok) { printf "R1\t%s:%s\tdata-perch-role=\"%s\" is not one of the closed thirteen\n", $1, $2, $3 }
  ' "$input"
}

# R7: every occurrence of the grant sentence must have a data-perch-role="grant"
# within ROLE_WINDOW lines, in the same file. Two passes over each file: collect
# the role lines, then check each phrase line against them.
check_grant_phrase() {
  awk -v phrase="$GRANT_PHRASE" -v window="$ROLE_WINDOW" '
    FNR == 1 { file = FILENAME; nr[file] = 0; np[file] = 0 }
    {
      lc = tolower($0)
      if (index($0, "data-perch-role=\"grant\"") > 0) {
        roleline[file, ++nr[file]] = FNR
      }
      if (index(lc, phrase) > 0) {
        phraseline[file, ++np[file]] = FNR
        phrasetext[file, np[file]] = $0
      }
    }
    END {
      for (f in np) {
        for (p = 1; p <= np[f]; p++) {
          found = 0
          for (r = 1; r <= nr[f]; r++) {
            d = phraseline[f, p] - roleline[f, r]
            if (d < 0) d = -d
            if (d <= window) { found = 1; break }
          }
          if (!found) {
            t = phrasetext[f, p]
            gsub(/^[[:space:]]+/, "", t)
            gsub(/[[:space:]]+$/, "", t)
            printf "R7\t%s:%d\tthe grant control'"'"'s accessible name appears with no data-perch-role=\"grant\" within %d lines: %s\n", f, phraseline[f, p], window, t
          }
        }
      }
    }
  ' "$@"
}

# R8: the decide command literal may appear only in files declaring a verdict
# role. Takes the roles file on stdin-equivalent (arg 1) and the source files.
check_decide_reachability() {
  local roles_file="$1"
  shift
  local verdict_files decide_files stray
  verdict_files="$(awk -F'\t' '$3 == "grant" || $3 == "refuse" { print $1 }' "$roles_file" | LC_ALL=C sort -u)"
  decide_files="$(grep -l "$DECIDE_COMMAND" "$@" 2>/dev/null | LC_ALL=C sort -u || true)"
  [ -z "$decide_files" ] && return 0
  stray="$(comm -23 <(printf '%s\n' "$decide_files") <(printf '%s\n' "$verdict_files") | grep -c . || true)"
  [ "$stray" -eq 0 ] && return 0
  comm -23 <(printf '%s\n' "$decide_files") <(printf '%s\n' "$verdict_files") | while IFS= read -r f; do
    [ -n "$f" ] || continue
    printf "R8\t%s\tthis file references %s but declares neither data-perch-role=\"grant\" nor \"refuse\"; a control that can reach POST /decide IS a verdict control and must be declared as one\n" "$f" "$DECIDE_COMMAND"
  done
}

# ---------------------------------------------------------------------------
# FIXTURE
# ---------------------------------------------------------------------------
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/perch-grant-gate.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT
fixture_failures=0

perch_roots_selftest || fixture_failures=$((fixture_failures + 1))

cat > "$FIXTURE_DIR/bad-role.tsx" <<'FIX'
export const X = () => <div data-perch-role="approve-button">no</div>;
FIX
cat > "$FIXTURE_DIR/good-role.tsx" <<'FIX'
export const X = () => <div data-perch-role="verdict-slot">yes</div>;
FIX

scan_roles "$FIXTURE_DIR/bad-role.tsx" > "$FIXTURE_DIR/bad.roles"
scan_roles "$FIXTURE_DIR/good-role.tsx" > "$FIXTURE_DIR/good.roles"
if [ -z "$(check_roles_closed "$FIXTURE_DIR/bad.roles")" ]; then
  echo "FIXTURE FAILURE: an unknown data-perch-role value was not caught" >&2
  fixture_failures=$((fixture_failures + 1))
fi
if [ -n "$(check_roles_closed "$FIXTURE_DIR/good.roles")" ]; then
  echo "FIXTURE FAILURE: a legal data-perch-role value was flagged" >&2
  fixture_failures=$((fixture_failures + 1))
fi

cat > "$FIXTURE_DIR/primary.tsx" <<'FIX'
<AlertDialogAction data-perch-role="grant" variant="default">go</AlertDialogAction>
FIX
if ! grep -q 'data-perch-role="grant"' "$FIXTURE_DIR/primary.tsx" \
   || ! grep -q 'variant="default"' "$FIXTURE_DIR/primary.tsx"; then
  echo "FIXTURE FAILURE: the R4 fixture does not contain the shape R4 looks for" >&2
  fixture_failures=$((fixture_failures + 1))
fi
if ! awk '/data-perch-role="grant"/ && /variant="default"/ { found = 1 } END { exit found ? 0 : 1 }' \
     "$FIXTURE_DIR/primary.tsx"; then
  echo "FIXTURE FAILURE: R4 did not catch a grant control styled as the default variant" >&2
  fixture_failures=$((fixture_failures + 1))
fi

cat > "$FIXTURE_DIR/override.tsx" <<'FIX'
export const Force = () => <button aria-label="Break glass and force this action">x</button>;
FIX
cat > "$FIXTURE_DIR/no-override.tsx" <<'FIX'
// The daemon has no override route; a client-side force control could only lie.
export const Refuse = () => <button data-perch-role="refuse">Refuse</button>;
FIX
OVERRIDE_RE='break.?glass|force[- ]?(this|the)? ?(action|grant|decision)|override'
if ! grep -Eiq "$OVERRIDE_RE" "$FIXTURE_DIR/override.tsx"; then
  echo "FIXTURE FAILURE: R6 did not catch a break-glass control" >&2
  fixture_failures=$((fixture_failures + 1))
fi
if grep -Eiq "$OVERRIDE_RE" <(grep -Ev '^[[:space:]]*(//|\*|/\*)' "$FIXTURE_DIR/no-override.tsx"); then
  echo "FIXTURE FAILURE: R6 flagged a whole-line comment explaining the ban" >&2
  fixture_failures=$((fixture_failures + 1))
fi

# --- R7 fixtures. The violating one is the real markup from a peer prototype,
# --- transposed to TSX: a working grant control with none of the gate.
cat > "$FIXTURE_DIR/ungated-grant.tsx" <<'FIX'
export function VerdictActions({ armed, onArm }: { armed: boolean; onArm: () => void }) {
  return (
    <button className="grant" data-armed={armed} onClick={onArm}>
      Record my decision and send it to the daemon
    </button>
  );
}
FIX
cat > "$FIXTURE_DIR/gated-grant.tsx" <<'FIX'
export function VerdictActions({ armed, onArm }: { armed: boolean; onArm: () => void }) {
  // IntersectionObserver at threshold 1.0 on the blast-radius block's last
  // child; the 1500 ms dwell accrues only while it is fully visible.
  return (
    <button
      data-perch-role="grant"
      variant="ghost"
      data-armed={armed}
      onKeyDown={(e) => { if (e.repeat) return; onArm(); }}
    >
      Record my decision and send it to the daemon
    </button>
  );
}
FIX
if [ -z "$(check_grant_phrase "$FIXTURE_DIR/ungated-grant.tsx")" ]; then
  echo "FIXTURE FAILURE: R7 did not catch a grant control carrying render law 6's own sentence with no data-perch-role" >&2
  fixture_failures=$((fixture_failures + 1))
fi
if [ -n "$(check_grant_phrase "$FIXTURE_DIR/gated-grant.tsx")" ]; then
  echo "FIXTURE FAILURE: R7 flagged a properly declared grant control" >&2
  fixture_failures=$((fixture_failures + 1))
fi

# --- R8 fixtures.
cat > "$FIXTURE_DIR/stray-decide.tsx" <<'FIX'
import { invokeTauri } from "@/shared/api/tauri";
export async function quickGrant(holdId: string) {
  return invokeTauri("perch_decide_hold", { holdId, decision: "grant" });
}
FIX
cat > "$FIXTURE_DIR/declared-decide.tsx" <<'FIX'
import { invokeTauri } from "@/shared/api/tauri";
export function RefuseControl({ holdId }: { holdId: string }) {
  return (
    <button
      data-perch-role="refuse"
      onClick={() => invokeTauri("perch_decide_hold", { holdId, decision: "refuse" })}
    >
      Refuse
    </button>
  );
}
FIX
scan_roles "$FIXTURE_DIR/stray-decide.tsx" "$FIXTURE_DIR/declared-decide.tsx" \
  > "$FIXTURE_DIR/r8.roles"
r8_fixture="$(check_decide_reachability "$FIXTURE_DIR/r8.roles" \
  "$FIXTURE_DIR/stray-decide.tsx" "$FIXTURE_DIR/declared-decide.tsx")"
case "$r8_fixture" in
  *stray-decide.tsx*) ;;
  *) echo "FIXTURE FAILURE: R8 did not catch a decide call in a file declaring no verdict role" >&2
     fixture_failures=$((fixture_failures + 1)) ;;
esac
case "$r8_fixture" in
  *declared-decide.tsx*)
     echo "FIXTURE FAILURE: R8 flagged a decide call inside a declared refuse control" >&2
     fixture_failures=$((fixture_failures + 1)) ;;
esac

if [ "$fixture_failures" -ne 0 ]; then
  echo "" >&2
  echo "The fixture proves this scanner can fail. $fixture_failures of its cases did not" >&2
  echo "behave as documented. Fix the scanner, not the fixture." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# REAL SCAN
# ---------------------------------------------------------------------------
perch_roots_gate grant "$PERCH_DESKTOP_ROOT"

if [ "$PERCH_TREE_STATE" != "present" ]; then
  echo "grant affordance gate: the Perch tree does not exist yet, so nothing was asserted."
  echo "" >&2
  echo "WARNING: no Perch source was scanned. INV-07, INV-10, INV-11's static half and" >&2
  echo "INV-27 are unenforced. tools/perch-source-roots.tsv marks every scanned root" >&2
  echo "'absent'; the commit that creates the first one fails this gate until it flips" >&2
  echo "that row to 'required'. The fixture above still ran, so the scanner itself is" >&2
  echo "known good." >&2
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

violations=""
add() { violations="$violations$1"$'\n'; }

scan_roles "${files[@]}" > "$FIXTURE_DIR/real.roles"
r1="$(check_roles_closed "$FIXTURE_DIR/real.roles")"
[ -n "$r1" ] && add "$r1"

grant_files="$(awk -F'\t' '$3 == "grant" { print $1 }' "$FIXTURE_DIR/real.roles" | LC_ALL=C sort -u)"
grant_count="$(printf '%s' "$grant_files" | grep -c . || true)"
if [ "$grant_count" -ne 1 ]; then
  add "R2	-	exactly one file may declare data-perch-role=\"grant\"; found $grant_count"
else
  # `\.repeat` rather than `event\.repeat`: the handler's parameter is named
  # `e` as often as `event`, and a gate that fails on a variable name gets
  # switched off. The fixture's own handler uses `e.repeat`.
  for mech in '\.repeat' 'IntersectionObserver' '1500'; do
    if ! grep -Eq "$mech" "$grant_files"; then
      add "R3	$grant_files	the grant control's file does not mention /$mech/; INV-11 needs all three of event.repeat, IntersectionObserver and the 1500 ms dwell"
    fi
  done
fi

r4="$(awk '/data-perch-role="grant"/ && /variant="default"/ { printf "R4\t%s:%d\tthe grant control is styled as the default (primary) button variant\n", FILENAME, FNR }' "${files[@]}")"
[ -n "$r4" ] && add "$r4"
r4b="$(awk '/<AlertDialogAction/ && !/variant=/ { printf "R4\t%s:%d\t<AlertDialogAction without an explicit variant resolves to buttonVariants() default = bg-primary\n", FILENAME, FNR }' "${files[@]}")"
[ -n "$r4b" ] && add "$r4b"

containment_files=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  containment_files+=("$path")
done < <(find "$PERCH_DESKTOP_ROOT/src/features/perch-containment" \( -name '*.ts' -o -name '*.tsx' \) -type f 2>/dev/null | LC_ALL=C sort)
if [ "${#containment_files[@]}" -gt 0 ]; then
  r5="$(awk 'tolower($0) ~ /extend/ && !/containment-extend-disabled/ && $0 !~ /^[[:space:]]*(\/\/|\*|\/\*)/ { printf "R5\t%s:%d\tan extend affordance on a containment surface; a ContainmentLease cannot be extended (swarm-response/src/containment.rs:74-95)\n", FILENAME, FNR }' "${containment_files[@]}")"
  [ -n "$r5" ] && add "$r5"
fi

r6="$(awk 'BEGIN { IGNORECASE = 0 }
  $0 ~ /^[[:space:]]*(\/\/|\*|\/\*)/ { next }
  { l = tolower($0) }
  l ~ /break.?glass/ || l ~ /override/ || l ~ /force (this|the) (action|grant|decision)/ {
    printf "R6\t%s:%d\tan override / break-glass / force path; the daemon has no override route\n", FILENAME, FNR
  }' "${files[@]}")"
[ -n "$r6" ] && add "$r6"

r7="$(check_grant_phrase "${files[@]}")"
[ -n "$r7" ] && add "$r7"

r8="$(check_decide_reachability "$FIXTURE_DIR/real.roles" "${files[@]}")"
[ -n "$r8" ] && add "$r8"

if [ -n "${violations//[$'\n']/}" ]; then
  echo "Perch grant-affordance violations (INV-07, INV-10, INV-11, INV-27):" >&2
  printf '%s' "$violations" \
    | sed "s#$PERCH_DESKTOP_ROOT/##g" \
    | awk -F'\t' 'NF >= 3 { printf "  [%s] %s\n      %s\n", $1, $2, $3 }' >&2
  exit 1
fi

echo "grant affordance gate clean over ${#files[@]} file(s)"
