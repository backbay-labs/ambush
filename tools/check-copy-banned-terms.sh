#!/usr/bin/env bash
#
# Perch copy gate: the banned-term list, the A-key ban, and one-key-one-verb.
#
# WHY THIS EXISTS
#   APPENDIX-NORMATIVE.md section 2 and section 7 both name
#   `tools/check-copy-banned-terms.sh` as the gate that enforces the vocabulary
#   rulings, the outright ban list, and INV-31's "A is banned as a verdict key".
#   The file did not exist in either repository. Ten documents cited an
#   enforcement mechanism that was a filename. That is the same shape as the
#   three gate scripts check-gates-wired.sh was written to catch, one step
#   earlier: a gate nobody wrote, cited as though it ran.
#
#   The bans are not style. `Approve` on a control is the product claiming an
#   authority it does not have (render law 6). `A` bound to a verdict is the key
#   surviving the relabelled button. A bare source count is
#   `min_sources_for_escalation` misread. Each row of tools/copy-ban-list.tsv
#   carries the sentence that says which.
#
# WHAT IS COVERED
#   TWO TREES, because Perch's product copy does not live in this repository.
#
#   A. This repo: docs/assets/*.svg. Those twenty files are the only Ambush
#      artifacts that become Perch product chrome (05 section 2.1). Scanned for
#      aria-label values and <text> node contents.
#
#      WHETHER THAT HALF IS ENFORCING IS DATA, in tools/copy-scope.tsv, and the
#      skeleton this file was copied from was wrong to hard-code "always". 00-
#      DECISIONS.md W3-24 defers the twelve README-art rewrites to Operator-
#      complete Task 20, so the reviewed row reads `deferred` today, the gate
#      skips the extraction and prints PARTIAL COVERAGE on every run, and its
#      closing line never claims a clean sweep without naming the scope it did
#      not cover. `required` demands at least one SVG and scans all of them.
#      Read tools/copy-scope.tsv's header for why the deferral is a row rather
#      than an allowlist of 41 strings or a deleted scan.
#
#   B. The Perch desktop tree, over the roots named in
#      tools/perch-source-roots.tsv. It resolves to $ROOT/workspace/desktop --
#      the two repositories are one checkout now -- and PERCH_DESKTOP_ROOT
#      overrides that, which is what the gate's own negative controls use. Two
#      scan modes:
#        copy   -- every string literal in a copy module
#                  (**/copy.ts, **/copy/*.ts, **/*Copy.ts). A copy module's
#                  literals ARE the rendered strings; that is what makes the
#                  mode exact.
#        markup -- everywhere else: only `aria-label` / `title` / `placeholder`
#                  / `alt` attribute values, only `label|title|body|hint|detail
#                  |tip` object fields, and only JSX text nodes.
#
#   C. $PERCH_DESKTOP_ROOT/src/features/perch/lib/perchKeymapRegistry.ts, parsed
#      as data, for INV-31 and INV-32.
#
#   The B and C scopes are DATA, in tools/perch-source-roots.tsv, shared with the
#   other three Perch gates. Read that file's header for the whole mechanism; the
#   short version is that a root marked `absent` whose directory EXISTS is a hard
#   failure, so the day the Perch tree lands is the day this gate starts
#   enforcing, without anyone having to remember.
#
# THE SYMMETRIC GUARD, ADDED AFTER REVIEW
#   The first version of this script had a refuse-to-pass guard on the ASSET half
#   and none on the desktop half: `perch_source_present` was computed and then
#   used only to decide whether to warn about a missing keymap file. Run from an
#   Ambush-shaped tree with PERCH_DESKTOP_ROOT pointed at the real block/buzz
#   desktop/, it printed
#
#       scanned 20 asset(s), 0 copy module(s), 0 component file(s)
#
#   and then a green line, with every vocabulary ban unenforced on the product
#   surface. That is the exact failure this file's own header was written
#   against, one half of the scan at a time. Both halves now refuse, and the
#   Phase-0 case -- the tree genuinely not existing yet -- is a loud WARNING with
#   a named next step rather than a silent number inside a success message.
#
# WHAT THIS SCRIPT CANNOT SEE, AND THEREFORE DOES NOT CLAIM
#   1. A rendered string assembled at runtime from parts
#      (`title={\`${verb} this hold\`}` where `verb` is a variable). Only the
#      literal halves are scanned. The template-literal half IS scanned; the
#      interpolation is not, and cannot be.
#   2. ANY STRING THAT ARRIVES AS DATA. The markup mode extracts four attribute
#      names, six field names and literal JSX text nodes -- it never sees a value
#      interpolated from a variable, so a banned word arriving from the daemon at
#      runtime is invisible to it in EVERY case. This is not a corner: the daemon
#      returns exactly one reason for every hold today ("authorized but held for
#      human approval", AMB crates/swarm-policy/src/static_gate.rs:297) and
#      render law 1's fourth slot requires it be rendered. The ban list carries
#      an exemption so the required render does not fail the build, and INV-14's
#      <AdversaryString> brand -- a different gate -- is what covers daemon text.
#      A clean run here says nothing about strings this product did not author.
#   3. WHICH CARD a string lands on. That is why the card-scoped
#      `signed`/`verified` ban is a DOM assertion in
#      tests/playwright/perch-provenance.spec.ts and not a row in the ban list.
#   4. A ban defeated by a synonym. `Authorise this action` passes. Nothing
#      lexical closes that; code review does.
#   5. `href`, `to=` and `data-testid` values are skipped ON PURPOSE. A gate
#      that fails on `href="/ledger?q=ambush:lease"` gets switched off in a
#      week (06 section 7.2's own guard-scope note).
#   6. The HTML prototypes under docs/plans/ambush-ui/build/prototypes/. They are
#      drawings, not product source, and they are not under any root in the
#      manifest. A banned string in a prototype is a review finding, not a build
#      failure.
#
# PROVING IT CAN FAIL
#   A fixture runs on EVERY invocation, before the real scan, following
#   tools/check-single-governor-key.sh's pattern. It plants one violating
#   string per ban row plus two keymap violations, and it plants CLEAN controls
#   -- the honest replacement sentence for each ban, a whole-line comment
#   naming a banned word, an `href` carrying one, a wire value in snake_case,
#   the ratified `Lanes` nav label, and the daemon's verbatim hold reason. Every
#   planted violation must be caught and every control must pass, or the
#   scanner's verdict over the real trees means nothing.
#
# ALLOWLIST
#   tools/copy-ban-allowlist.tsv. Keyed `id <TAB> path <TAB> needle <TAB> reason`.
#   Ships EMPTY by design; product copy is never allowlisted.
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BAN_LIST="$ROOT_DIR/tools/copy-ban-list.tsv"
ALLOWLIST="$ROOT_DIR/tools/copy-ban-allowlist.tsv"
ROOTS_LIB="$ROOT_DIR/tools/lib/perch-roots.sh"
# Overridden ONLY by this gate's own fixture, which drives the parser over
# synthetic manifests. The real run always reads the reviewed file.
COPY_SCOPE_FILE="${PERCH_COPY_SCOPE_MANIFEST:-$ROOT_DIR/tools/copy-scope.tsv}"

if [ ! -f "$BAN_LIST" ]; then
  echo "missing $BAN_LIST; refusing to pass silently" >&2
  exit 1
fi
if [ ! -f "$ROOTS_LIB" ]; then
  echo "missing $ROOTS_LIB; refusing to pass silently" >&2
  exit 1
fi
# shellcheck source=tools/lib/perch-roots.sh
. "$ROOTS_LIB"

# ---------------------------------------------------------------------------
# THE ASSET SCOPE (W3-24). tools/copy-scope.tsv decides whether the asset half
# of this gate enforces. Read STRICTLY: every way the row can go missing, go
# double, lose a column, gain an unknown status, lose its reason, or name a
# directory that is not there exits 1 with a named cause.
#
# The point of the strictness is that this file can only ever REDUCE what the
# gate covers. A scope narrowed by deleting a line, or by a typo in a path, must
# be louder than the coverage it removes -- otherwise the next person shrinks
# the gate by accident and the build stays green, which is the exact silent-pass
# this whole script was written against.
#
# Sets COPY_SCOPE_DIR, COPY_SCOPE_STATUS and COPY_SCOPE_REASON, or exits.
# Emits diagnostics to stderr and returns non-zero rather than exiting when
# COPY_SCOPE_SOFT_FAIL is set, so the fixture can assert each arm.
# ---------------------------------------------------------------------------
copy_scope_fail() {
  echo "$1" >&2
  if [ -n "${COPY_SCOPE_SOFT_FAIL:-}" ]; then
    return 1
  fi
  exit 1
}

read_copy_scope() {
  local manifest="$1"
  COPY_SCOPE_DIR=""
  COPY_SCOPE_STATUS=""
  COPY_SCOPE_REASON=""

  if [ ! -f "$manifest" ]; then
    copy_scope_fail "missing $manifest; the asset scope is reviewed data and its absence is not a pass. Restore the file; see 00-DECISIONS.md W3-24." || return 1
  fi

  local rows=0 line scope status reason extra
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    IFS=$'\t' read -r scope status reason extra <<<"$line"
    [ "$scope" = "scope" ] && continue
    if [ -n "$extra" ]; then
      copy_scope_fail "copy-scope.tsv row '$scope' has more than three columns; the format is scope<TAB>status<TAB>reason" || return 1
    fi
    rows=$((rows + 1))
    if [ "$rows" -gt 1 ]; then
      copy_scope_fail "copy-scope.tsv carries more than one row. Exactly one asset scope is reviewed; a second row is a scope nobody decided about." || return 1
    fi
    COPY_SCOPE_DIR="$scope"
    COPY_SCOPE_STATUS="$status"
    COPY_SCOPE_REASON="$reason"
  done < "$manifest"

  if [ "$rows" -eq 0 ]; then
    copy_scope_fail "copy-scope.tsv carries no row. The asset half of this gate would silently scan nothing; refusing to pass." || return 1
  fi
  case "$COPY_SCOPE_STATUS" in
    deferred|required) ;;
    *)
      copy_scope_fail "copy-scope.tsv row '$COPY_SCOPE_DIR' has status '$COPY_SCOPE_STATUS'; expected deferred or required" || return 1 ;;
  esac
  if [ -z "$COPY_SCOPE_REASON" ]; then
    copy_scope_fail "copy-scope.tsv row '$COPY_SCOPE_DIR' has no reason column. A deferral nobody justified is a deletion with extra steps." || return 1
  fi
  if [ ! -d "$ROOT_DIR/$COPY_SCOPE_DIR" ]; then
    copy_scope_fail "copy-scope.tsv names scope '$COPY_SCOPE_DIR', which is not a directory under $ROOT_DIR. A typo here would defer a scope that does not exist and read as coverage." || return 1
  fi
  return 0
}

# The Perch tree lives in block/buzz. This gate is inherently cross-repo and
# no plan document budgeted the second checkout; naming that here is cheaper
# than a green build over a directory nobody supplied.
# The Perch product tree used to live in a second repository and this gate used
# to demand PERCH_DESKTOP_ROOT name a checkout of it. The two are one checkout
# now, so the default is in-tree and the variable is an override -- kept because
# the gate's own negative controls point it at synthetic trees.
PERCH_DESKTOP_ROOT="${PERCH_DESKTOP_ROOT:-$ROOT_DIR/workspace/desktop}"
if [ ! -d "$PERCH_DESKTOP_ROOT" ]; then
  cat >&2 <<MSG
PERCH_DESKTOP_ROOT does not name a directory:

  $PERCH_DESKTOP_ROOT

It defaults to \$ROOT/workspace/desktop and is overridden only to point this
gate at a synthetic tree. Refusing to report a pass over a tree that is not
there.
MSG
  exit 1
fi

KEYMAP_FILE="$PERCH_DESKTOP_ROOT/src/features/perch/lib/perchKeymapRegistry.ts"

# ---------------------------------------------------------------------------
# EXTRACTION. `mode` is `copy` or `markup`; output is `path<TAB>line<TAB>string`.
# ---------------------------------------------------------------------------
extract_strings() {
  local mode="$1"
  shift
  awk -v mode="$mode" '
    function esc(s) { gsub(/\t/, " ", s); gsub(/\r/, "", s); return s }
    function push(s) { if (s != "") printf "%s\t%d\t%s\n", FILENAME, FNR, esc(s) }

    # A snake_case wire token, a route, a url or an anchor is not product copy.
    function skip_value(s) {
      if (s ~ /^\//) return 1
      if (s ~ /^#/) return 1
      if (s ~ /^https?:/) return 1
      if (s ~ /^[a-z0-9_]+$/ && s ~ /_/) return 1
      return 0
    }

    # Pull the quoted value out of every occurrence of `re` on this line.
    function grab(re,   rest, st, ln, chunk, qs, qn, s) {
      rest = $0
      while (match(rest, re)) {
        st = RSTART; ln = RLENGTH
        chunk = substr(rest, st, ln)
        if (match(chunk, /"[^"]*"/)) {
          qs = RSTART; qn = RLENGTH
          s = substr(chunk, qs + 1, qn - 2)
          if (!skip_value(s)) push(s)
        }
        rest = substr(rest, st + ln)
      }
    }

    function quoted_run(open,   rest, st, ln, s) {
      rest = $0
      while (match(rest, open)) {
        st = RSTART; ln = RLENGTH
        s = substr(rest, st + 1, ln - 2)
        if (!skip_value(s)) push(s)
        rest = substr(rest, st + ln)
      }
    }

    # Whole-line comments declare nothing. This file names every word it bans.
    /^[[:space:]]*(\/\/|\*|\/\*|<!--)/ { next }
    /^[[:space:]]*(import|export type|export interface)[[:space:]]/ { next }
    /from[[:space:]]*"/ { next }

    mode == "copy" {
      # Regexes are passed as STRINGS. In awk a /re/ literal in argument
      # position evaluates to `$0 ~ /re/`, i.e. 0 or 1 -- the first draft of
      # this script did exactly that and extracted nothing, which the fixture
      # caught on the first run.
      quoted_run("\"[^\"]*\"")
      quoted_run("`[^`]*`")
      next
    }

    # markup: attributes, the six copy field names, and JSX/SVG text nodes.
    /href[[:space:]]*=/ { next }
    /data-testid[[:space:]]*=/ { next }
    /[^-a-zA-Z]to[[:space:]]*=[[:space:]]*"/ { next }
    {
      grab("(aria-label|placeholder|alt|title)[[:space:]]*=[[:space:]]*\"[^\"]*\"")
      grab("(label|title|body|hint|detail|tip)[[:space:]]*:[[:space:]]*\"[^\"]*\"")
      rest2 = $0
      while (match(rest2, ">[^<>{}]+<")) {
        st2 = RSTART; ln2 = RLENGTH
        t = substr(rest2, st2 + 1, ln2 - 2)
        gsub(/^[[:space:]]+/, "", t)
        gsub(/[[:space:]]+$/, "", t)
        if (t ~ /[A-Za-z]/) push(t)
        rest2 = substr(rest2, st2 + ln2)
      }
      # A JSX text node on a line of its own carries no angle brackets, so the
      # rule above cannot see it. A line that is prose -- starts with a letter,
      # holds a space, and holds none of the punctuation that makes a line code
      # -- is a text node. Requiring the space is what keeps a bare identifier
      # out; requiring no `=`, `;`, quote, brace or paren is what keeps
      # declarations, calls and object literals out.
      if ($0 ~ /^[[:space:]]*[A-Za-z][^<>{}=;()"`]*$/ && $0 ~ /[A-Za-z] [A-Za-z]/) {
        t2 = $0
        gsub(/^[[:space:]]+/, "", t2)
        gsub(/[[:space:]]+$/, "", t2)
        push(t2)
      }
    }
  ' "$@"
}

# ---------------------------------------------------------------------------
# SCANNING. stdin is the extractor output; stdout is
# `id<TAB>severity<TAB>path<TAB>line<TAB>string<TAB>message`.
# ---------------------------------------------------------------------------
scan_extracted() {
  awk -F'\t' -v banfile="$BAN_LIST" '
    BEGIN {
      n = 0
      while ((getline line < banfile) > 0) {
        if (line ~ /^#/ || line == "") continue
        split(line, f, "\t")
        if (f[1] == "id") continue
        if (f[7] == "") continue
        n++
        bid[n] = f[1]; bsev[n] = f[2]; bfl[n] = f[3]; bmin[n] = f[4] + 0
        bpat[n] = f[5]; bex[n] = f[6]; bmsg[n] = f[7]
      }
      close(banfile)
      if (n == 0) {
        print "ban list parsed to zero rows; refusing to pass silently" > "/dev/stderr"
        exit 2
      }
    }
    {
      path = $1; lineno = $2; s = $3
      for (i = 1; i <= n; i++) {
        if (length(s) < bmin[i]) continue
        t = (bfl[i] == "i") ? tolower(s) : s
        if (t ~ bpat[i]) {
          # The exemption is matched against the SAME normalized string, which
          # is why a case-insensitive row must write its exemption lowercase.
          if (bex[i] != "-" && t ~ bex[i]) continue
          printf "%s\t%s\t%s\t%s\t%s\t%s\n", bid[i], bsev[i], path, lineno, s, bmsg[i]
        }
      }
    }
  '
}

apply_allowlist() {
  if [ ! -f "$ALLOWLIST" ]; then
    cat
    return
  fi
  awk -F'\t' -v allow="$ALLOWLIST" '
    BEGIN {
      m = 0
      while ((getline line < allow) > 0) {
        if (line ~ /^#/ || line == "") continue
        split(line, a, "\t")
        if (a[1] == "id") continue
        if (a[4] == "") continue
        m++
        aid[m] = a[1]; apath[m] = a[2]; aneedle[m] = a[3]
      }
      close(allow)
    }
    {
      for (i = 1; i <= m; i++) {
        if ($1 == aid[i] && index($3, apath[i]) > 0 && index($5, aneedle[i]) > 0) next
      }
      print
    }
  '
}

# ---------------------------------------------------------------------------
# THE KEYMAP PASS -- INV-31 and INV-32, over PERCH_BINDINGS as data.
# ---------------------------------------------------------------------------
keymap_entries() {
  # One `{ ... }` object per output line. `tr '{' '\n'` is enough because the
  # registry is a flat array of flat objects (17-COMPONENT-SPECS.md section 6.1);
  # a nested object would show up as an entry with no `key:` and be ignored,
  # which the fixture's `nested` case proves.
  sed -n '/PERCH_BINDINGS/,/^\];/p' "$1" | tr '\n' ' ' | tr '{' '\n'
}

scan_keymap() {
  awk '
    function pick(re,   st, ln, chunk, qs, qn) {
      if (!match($0, re)) return ""
      st = RSTART; ln = RLENGTH
      chunk = substr($0, st, ln)
      if (!match(chunk, /"[^"]*"/)) return ""
      qs = RSTART; qn = RLENGTH
      return substr(chunk, qs + 1, qn - 2)
    }
    {
      key = pick("key[[:space:]]*:[[:space:]]*\"[^\"]*\"")
      if (key == "") next
      verb = pick("verb[[:space:]]*:[[:space:]]*\"[^\"]*\"")
      entries++
      if (verb == "") next
      verdicts++
      seen_verb[verb] = 1
      lk = tolower(key)
      if (lk == "a") {
        printf "INV-31\tverdict verb \"%s\" is bound to key \"%s\"\n", verb, key
      }
      if (!((lk, verb) in pair)) {
        pair[lk, verb] = 1
        verbs_for[lk] = verbs_for[lk] " " verb
        count_for[lk]++
      }
    }
    END {
      for (k in count_for) {
        if (count_for[k] > 1) {
          printf "INV-32\tkey \"%s\" is bound to %d different verdict verbs:%s\n", k, count_for[k], verbs_for[k]
        }
      }
      if (entries == 0) {
        printf "REGISTRY\tPERCH_BINDINGS parsed to zero entries; refusing to pass silently\n"
      }
      if (verdicts == 0) {
        printf "REGISTRY\tPERCH_BINDINGS carries no verdict binding at all; refusing to pass silently\n"
      }
      split("confirm dismiss investigate grant refuse", want, " ")
      for (i = 1; i <= 5; i++) {
        if (!(want[i] in seen_verb)) {
          printf "REGISTRY\tthe verdict verb \"%s\" is not bound to any key; the appendix section 2 keymap names five\n", want[i]
        }
      }
    }
  '
}

# ---------------------------------------------------------------------------
# THE FIXTURE. Runs on every invocation, INCLUDING in Phase 0, so a broken
# scanner is caught before the Perch tree exists rather than after.
# ---------------------------------------------------------------------------
FIXTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/perch-copy-gate.XXXXXX")"
trap 'rm -rf "$FIXTURE_DIR"' EXIT

fixture_failures=0

perch_roots_selftest || fixture_failures=$((fixture_failures + 1))

fixture_hits() {
  local mode="$1" file="$2"
  extract_strings "$mode" "$file" | scan_extracted | cut -f1 | LC_ALL=C sort -u
}

expect_ids() {
  local mode="$1" file="$2"
  shift 2
  local got want
  got="$(fixture_hits "$mode" "$file" | tr '\n' ' ')"
  for want in "$@"; do
    case " $got " in
      *" $want "*) ;;
      *)
        echo "FIXTURE FAILURE: $(basename "$file") did not trip ban row '$want' (tripped: ${got:-none})" >&2
        fixture_failures=$((fixture_failures + 1))
        ;;
    esac
  done
}

expect_no_hits() {
  local mode="$1" file="$2" description="$3"
  local got
  got="$(fixture_hits "$mode" "$file" | tr '\n' ' ')"
  if [ -n "${got// /}" ]; then
    echo "FIXTURE FAILURE: the scanner flagged $description ($(basename "$file")): $got" >&2
    extract_strings "$mode" "$file" | scan_extracted >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

cat > "$FIXTURE_DIR/violations.copy.ts" <<'FIX'
export const WATCH_COPY = {
  grantLabel: "Approve this action",
  refuseLabel: "Deny",
  attestationHint: "verified by the governor",
  quorumLine: "quorum 2 / 3 governors",
  sourceLine: "2 sources",
  emptyQueue: "All clear",
  navHunt: "Open the hunt",
  colonyWord: "the clowder is healthy",
  codename: "Swarm Team Six console",
  bareLease: "the lease expires in 12 minutes",
  bareLane: "open the async lane",
  shouty: "Recorded!",
};
FIX

cat > "$FIXTURE_DIR/clean.copy.ts" <<'FIX'
import { CASE_COPY } from "./caseCopy";
export const WATCH_COPY = {
  grantLabel: "Record my decision and send it to the daemon",
  refuseLabel: "Refuse",
  attestationHint: "attestation matches this body",
  quorumLine: "committee of 1 (solo transport)",
  sourceLine: "2 sources / 1 agent",
  emptyQueue: "18 techniques are deliberately uncovered by 11 detectors",
  navField: "hunt_id",
  colonyWord: "the colony is healthy",
  product: "Ambush",
  namedLease: "the containment lease expires in 12 minutes",
  laneWord: "twelve lanes, one per threat class",
  quiet: "Recorded",
  wireValue: "quarantine_file",
  policyWord: "PolicyVerdict::Deny",
  releaseWord: "the containment release did not complete",
  planeWord: "control-plane audit",
  resourceWord: "the host has limited resources",
  huntingWord: "autonomous threat hunting",
  navLanes: "Lanes",
  laneHeading: "Lane",
  daemonHoldReason: "authorized but held for human approval",
  daemonRuleName: "static.human_gate",
  capabilityIdToken: "lease:hunt-evt-1:isolate_host:1773738882600",
  huntIdentifier: "hunt-evt-1",
};
FIX

cat > "$FIXTURE_DIR/violations.markup.tsx" <<'FIX'
export function GrantControl() {
  return (
    <div>
      <button aria-label="Approve this hold">Grant</button>
      <span title="verified by Tom">tier 2</span>
      <p>2 sources</p>
      <p>
        You are all caught up
      </p>
      <a>open the async lane</a>
    </div>
  );
}
FIX

cat > "$FIXTURE_DIR/clean.markup.tsx" <<'FIX'
// TODO: the old label said Approve; do not bring it back.
/* All clear was the phrase we removed. */
import { Trusted } from "./nope";
export function GrantControl() {
  return (
    <div>
      <a href="/ledger?q=ambush:lease">open in Ledger</a>
      <button data-testid="perch-approve-legacy" aria-label="Record my decision and send it to the daemon">
        Record my decision
      </button>
      <span title="attestation matches this body">tier 1</span>
      <p>2 sources / 1 agent</p>
      <nav aria-label="Lanes">
        <span>Lanes</span>
      </nav>
      <p>authorized but held for human approval</p>
    </div>
  );
}
FIX

cat > "$FIXTURE_DIR/keymap.bad.ts" <<'FIX'
export const PERCH_BINDINGS: readonly PerchBinding[] = [
  { key: "A", rowTypes: ["hold"], verb: "grant", meaning: "Grant" },
  { key: "D", rowTypes: ["finding"], verb: "dismiss", meaning: "Dismiss" },
  { key: "D", rowTypes: ["hold"], verb: "refuse", meaning: "Refuse" },
  { key: "C", rowTypes: ["finding"], verb: "confirm", meaning: "Confirm" },
  { key: "I", rowTypes: ["finding"], verb: "investigate", meaning: "Investigate" },
];
FIX

cat > "$FIXTURE_DIR/keymap.good.ts" <<'FIX'
export const PERCH_BINDINGS: readonly PerchBinding[] = [
  { key: "C", rowTypes: ["finding"], verb: "confirm", meaning: "Confirm" },
  { key: "D", rowTypes: ["finding"], verb: "dismiss", meaning: "Dismiss" },
  { key: "I", rowTypes: ["finding"], verb: "investigate", meaning: "Investigate" },
  { key: "G", rowTypes: ["hold"], verb: "grant", meaning: "Arms the grant" },
  { key: "R", rowTypes: ["hold"], verb: "refuse", meaning: "Refuse" },
  { key: "S", rowTypes: ["finding", "case"], disabledOn: ["hold"], meaning: "Snooze" },
  { key: "E", rowTypes: ["finding", "hold", "lane"], meaning: "Promote to a case" },
];
FIX

cat > "$FIXTURE_DIR/keymap.gutted.ts" <<'FIX'
export const PERCH_BINDINGS: readonly PerchBinding[] = [
];
FIX

expect_ids copy "$FIXTURE_DIR/violations.copy.ts" \
  approve deny-label trust-claim quorum-fraction bare-source-count \
  reassurance hunt-noun clowder legacy-codename bare-lease bare-lane exclamation
expect_ids markup "$FIXTURE_DIR/violations.markup.tsx" \
  approve trust-claim bare-source-count reassurance bare-lane
expect_no_hits copy "$FIXTURE_DIR/clean.copy.ts" \
  "the honest replacement for every ban, the four word-boundary near-misses \
release / control-plane / resources / hunting, the ratified Lanes nav label, the \
daemon's verbatim hold reason, and the two identifier-token exemptions"
expect_no_hits markup "$FIXTURE_DIR/clean.markup.tsx" \
  "banned words in comments, an href, a testid, an import, the Lanes nav label \
and the daemon's verbatim hold reason"

# The allowlist is a gate-weakening mechanism, so it is fixture-tested too: an
# entry must drop exactly its own hit and nothing else. An untested allowlist is
# how a gate quietly stops asserting anything.
cat > "$FIXTURE_DIR/allow.tsv" <<'FIX'
id	path	needle	reason
clowder	violations.copy.ts	the clowder is healthy	fixture-only entry; proves the allowlist matches on all three columns
FIX
allow_before="$(extract_strings copy "$FIXTURE_DIR/violations.copy.ts" | scan_extracted | cut -f1 | LC_ALL=C sort -u | tr '\n' ' ')"
allow_after="$(ALLOWLIST="$FIXTURE_DIR/allow.tsv" ; export ALLOWLIST; extract_strings copy "$FIXTURE_DIR/violations.copy.ts" | scan_extracted | apply_allowlist | cut -f1 | LC_ALL=C sort -u | tr '\n' ' ')"
case " $allow_before " in
  *" clowder "*) ;;
  *) echo "FIXTURE FAILURE: the allowlist control string did not violate before allowlisting" >&2
     fixture_failures=$((fixture_failures + 1)) ;;
esac
case " $allow_after " in
  *" clowder "*)
     echo "FIXTURE FAILURE: an allowlist entry did not drop its own hit" >&2
     fixture_failures=$((fixture_failures + 1)) ;;
esac
case " $allow_after " in
  *" approve "*) ;;
  *) echo "FIXTURE FAILURE: an allowlist entry dropped a hit it does not name" >&2
     fixture_failures=$((fixture_failures + 1)) ;;
esac

# --- THE PARITY CORPUS. The other half of decision D2: this same set is scanned
# --- by BUZZ desktop/scripts/check-copy-banned-terms.mjs, which asserts the same
# --- expected.tsv. Two implementations of one rule set drift; running both over
# --- one recorded contract is the only thing that stops it. Mode rides the
# --- filename suffix here (tools/fixtures/copy-corpus/README.md); a corpus file
# --- matching neither suffix is refused rather than scanned in the wrong mode.
CORPUS_DIR="$ROOT_DIR/tools/fixtures/copy-corpus"
if [ ! -f "$CORPUS_DIR/expected.tsv" ]; then
  echo "FIXTURE FAILURE: missing $CORPUS_DIR/expected.tsv; the parity contract is the file" >&2
  fixture_failures=$((fixture_failures + 1))
else
  corpus_got="$FIXTURE_DIR/corpus.got"
  : > "$corpus_got"
  corpus_files=0
  for f in "$CORPUS_DIR"/*.ts "$CORPUS_DIR"/*.tsx; do
    [ -e "$f" ] || continue
    b="$(basename "$f")"
    case "$b" in
      *.copy.ts|*.copy.tsx)     m=copy ;;
      *.markup.ts|*.markup.tsx) m=markup ;;
      *)
        echo "FIXTURE FAILURE: corpus file $b matches neither *.copy.ts* nor *.markup.ts*;" >&2
        echo "  its mode is undecidable and it would be scanned wrong" >&2
        fixture_failures=$((fixture_failures + 1))
        continue ;;
    esac
    corpus_files=$((corpus_files + 1))
    extract_strings "$m" "$f" | scan_extracted | awk -F'\t' -v b="$b" '{ print b "\t" $1 }' >> "$corpus_got"
  done
  if [ "$corpus_files" -eq 0 ]; then
    echo "FIXTURE FAILURE: the parity corpus is empty; refusing to pass silently" >&2
    fixture_failures=$((fixture_failures + 1))
  else
    corpus_want="$FIXTURE_DIR/corpus.want"
    # ONE awk, not a chain of `grep -v`. A grep that filters everything out
    # returns 1, and under `set -o pipefail` that killed this script with exit 1
    # and NOT ONE LINE of output -- so an expected.tsv holding only its header
    # (the state a corpus with no expected hits would be in, and the state a
    # bisect leaves behind) looked exactly like a crash. Found by running this
    # gate's own negative control. awk returns 0 whether or not it prints, which
    # is what lets the diff below produce the diagnostic instead.
    awk '!/^#/ && $0 != "" && $0 !~ /^file\t/' "$CORPUS_DIR/expected.tsv" \
      | LC_ALL=C sort -u > "$corpus_want"
    LC_ALL=C sort -u "$corpus_got" -o "$corpus_got"
    if ! diff -u "$corpus_want" "$corpus_got" > "$FIXTURE_DIR/corpus.diff" 2>&1; then
      echo "FIXTURE FAILURE: this scanner disagrees with tools/fixtures/copy-corpus/expected.tsv." >&2
      echo "  '-' lines are expected and not produced; '+' lines are produced and not expected." >&2
      sed -n '3,$p' "$FIXTURE_DIR/corpus.diff" >&2
      echo "  expected.tsv is the contract the Buzz-side .mjs meets too. Change the ban" >&2
      echo "  list and expected.tsv together, and run BOTH scanners before landing." >&2
      fixture_failures=$((fixture_failures + 1))
    fi
  fi
fi

bad_keymap="$(keymap_entries "$FIXTURE_DIR/keymap.bad.ts" | scan_keymap)"
case "$bad_keymap" in
  *INV-31*) ;;
  *) echo "FIXTURE FAILURE: the keymap scanner did not catch an A-bound verdict verb" >&2
     fixture_failures=$((fixture_failures + 1)) ;;
esac
case "$bad_keymap" in
  *INV-32*) ;;
  *) echo "FIXTURE FAILURE: the keymap scanner did not catch one key with two verdict verbs" >&2
     fixture_failures=$((fixture_failures + 1)) ;;
esac
good_keymap="$(keymap_entries "$FIXTURE_DIR/keymap.good.ts" | scan_keymap)"
if [ -n "$good_keymap" ]; then
  echo "FIXTURE FAILURE: the keymap scanner flagged the appendix section 2 keymap:" >&2
  printf '%s\n' "$good_keymap" >&2
  fixture_failures=$((fixture_failures + 1))
fi
gutted_keymap="$(keymap_entries "$FIXTURE_DIR/keymap.gutted.ts" | scan_keymap)"
case "$gutted_keymap" in
  *REGISTRY*) ;;
  *) echo "FIXTURE FAILURE: an empty PERCH_BINDINGS did not refuse to pass silently" >&2
     fixture_failures=$((fixture_failures + 1)) ;;
esac

# --- THE ASSET-SCOPE PARSER (W3-24). tools/copy-scope.tsv can only ever REDUCE
# --- what this gate covers, so every way it can be wrong runs on every
# --- invocation: the row deleted, doubled, mis-columned, given an unknown
# --- status, stripped of its reason, or pointed at a directory that is not
# --- there. A scope narrowed by a deleted line has to be louder than the
# --- coverage it removes, and this is what makes that true rather than claimed.
scope_case() {
  local label="$1" expect="$2" body="$3"
  local f="$FIXTURE_DIR/scope-$label.tsv" got
  printf '%b' "$body" > "$f"
  got="$(
    COPY_SCOPE_SOFT_FAIL=1
    if read_copy_scope "$f" 2>/dev/null; then
      printf 'ok:%s' "$COPY_SCOPE_STATUS"
    else
      printf 'fail'
    fi
  )"
  if [ "$got" != "$expect" ]; then
    echo "FIXTURE FAILURE: copy-scope case '$label' produced '$got', expected '$expect'" >&2
    fixture_failures=$((fixture_failures + 1))
  fi
}

scope_case empty-file fail ''
got_missing="$(
  COPY_SCOPE_SOFT_FAIL=1
  if read_copy_scope "$FIXTURE_DIR/nope.tsv" 2>/dev/null; then printf 'ok'; else printf 'fail'; fi
)"
if [ "$got_missing" != "fail" ]; then
  echo "FIXTURE FAILURE: a missing copy-scope.tsv did not fail" >&2
  fixture_failures=$((fixture_failures + 1))
fi

scope_case header-only fail 'scope	status	reason
'
scope_case two-rows fail 'scope	status	reason
docs/assets	deferred	W3-24
docs	required	second row
'
scope_case unknown-status fail 'scope	status	reason
docs/assets	skipped	W3-24
'
scope_case no-reason fail 'scope	status	reason
docs/assets	deferred	
'
scope_case four-columns fail 'scope	status	reason
docs/assets	deferred	W3-24	extra
'
scope_case absent-scope fail 'scope	status	reason
docs/assetz	deferred	typo in the path
'
scope_case valid-deferred ok:deferred 'scope	status	reason
docs/assets	deferred	W3-24: rewrite and require in Operator-complete Task 20
'
scope_case valid-required ok:required 'scope	status	reason
docs/assets	required	flipped by Operator-complete Task 20
'

if [ "$fixture_failures" -ne 0 ]; then
  echo "" >&2
  echo "The fixture proves this scanner can fail. $fixture_failures of its cases did" >&2
  echo "not behave as documented, so its verdict over the real trees means nothing." >&2
  echo "Fix the scanner, not the fixture." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# THE REAL SCAN -- HALF A: this repository's assets, scoped by W3-24.
# ---------------------------------------------------------------------------
violations=""

read_copy_scope "$COPY_SCOPE_FILE"

asset_files=()
if [ "$COPY_SCOPE_STATUS" = "required" ]; then
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    asset_files+=("$path")
  done < <(find "$COPY_SCOPE_DIR" -name '*.svg' -type f 2>/dev/null | LC_ALL=C sort)

  if [ "${#asset_files[@]}" -eq 0 ]; then
    echo "copy-scope.tsv marks '$COPY_SCOPE_DIR' required but no *.svg was found under it;" >&2
    echo "refusing to pass silently." >&2
    exit 1
  fi
  violations="$violations$(extract_strings markup "${asset_files[@]}" | scan_extracted | apply_allowlist)"
else
  # Conspicuous, on stdout AND stderr, on every single run. A deferral nobody
  # sees is the allowlist this row exists instead of.
  echo "PARTIAL COVERAGE: $COPY_SCOPE_DIR deferred by $COPY_SCOPE_REASON"
  echo "" >&2
  echo "PARTIAL COVERAGE: $COPY_SCOPE_DIR deferred by $COPY_SCOPE_REASON" >&2
  echo "  No asset string was scanned on this run. tools/copy-scope.tsv carries the" >&2
  echo "  reviewed row and its header carries the count of what is unscanned." >&2
fi

# ---------------------------------------------------------------------------
# THE REAL SCAN -- HALF B: the Perch product tree, scoped by the manifest.
# ---------------------------------------------------------------------------
perch_roots_gate copy "$PERCH_DESKTOP_ROOT"

# THE THIRD ROOTS RULE. perch_roots_gate catches a `required` row whose
# directory is missing and an `absent` row whose directory has landed. It does
# NOT catch the other direction: a Perch directory that exists and that no row
# mentions at all. 12-PLAN-FIRST-CARD.md Task 24 names all three, and this was
# the one no gate carried -- so a new feature root, or a manifest row someone
# deleted, would silently drop out of every scan while the gate stayed green.
# That is the same silent-narrowing shape tools/copy-scope.tsv is written
# against, so it is refused the same way.
undeclared=""
while IFS= read -r discovered; do
  [ -n "$discovered" ] || continue
  rel="${discovered#"$PERCH_DESKTOP_ROOT"/}"
  if [ -z "$(perch_root_status "$rel")" ]; then
    undeclared="${undeclared}  $rel"$'\n'
  fi
done < <(
  {
    find "$PERCH_DESKTOP_ROOT/src/features" -maxdepth 1 -type d -name 'perch*' 2>/dev/null
    find "$PERCH_DESKTOP_ROOT/src/shared/ui" -maxdepth 1 -type d -name 'perch*' 2>/dev/null
  } | LC_ALL=C sort
)
if [ -n "$undeclared" ]; then
  echo "" >&2
  echo "Perch source directories that tools/perch-source-roots.tsv does not mention:" >&2
  printf '%s' "$undeclared" >&2
  echo "" >&2
  echo "Every Perch root is reviewed data. An unlisted one is scanned by no gate," >&2
  echo "so its copy, its keymap and its write surface all go unchecked while every" >&2
  echo "gate reports clean. Add a row -- status 'required' if it is Perch source --" >&2
  echo "in the same commit that creates the directory." >&2
  exit 1
fi

copy_files=()
markup_files=()
if [ "$PERCH_TREE_STATE" = "present" ]; then
  for dir in "${PERCH_ROOT_DIRS[@]}"; do
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      case "$path" in
        *.test.*|*.spec.*|*/tests/*|*/__fixtures__/*) continue ;;
        */copy.ts|*/copy/*.ts|*Copy.ts) copy_files+=("$path") ;;
        *) markup_files+=("$path") ;;
      esac
    done < <(find "$dir" \( -name '*.ts' -o -name '*.tsx' \) -type f | LC_ALL=C sort)
  done

  # THE SYMMETRIC GUARD. A root the manifest calls `required` exists (or
  # perch_roots_gate would already have exited), so finding zero scannable files
  # inside every one of them means a rename, an extension change, or an
  # exclusion pattern that swallowed the tree. Reporting a pass here is the
  # silent-green this script's header is written against.
  if [ "${#copy_files[@]}" -eq 0 ] && [ "${#markup_files[@]}" -eq 0 ]; then
    echo "" >&2
    echo "tools/perch-source-roots.tsv marks Perch roots as required and they exist," >&2
    echo "but no .ts/.tsx file was found in any of them:" >&2
    printf '  %s\n' "${PERCH_ROOT_DIRS[@]}" >&2
    echo "Every vocabulary ban would be unenforced on the product surface." >&2
    echo "Refusing to pass silently." >&2
    exit 1
  fi

  [ "${#copy_files[@]}" -gt 0 ] && \
    violations="$violations$(extract_strings copy "${copy_files[@]}" | scan_extracted | apply_allowlist)"
  [ "${#markup_files[@]}" -gt 0 ] && \
    violations="$violations$(extract_strings markup "${markup_files[@]}" | scan_extracted | apply_allowlist)"

  # ------------------------------------------------------------------------
  # THE BARE-LITERAL BLIND SPOT, DECLARED.
  #
  # markup mode reads four attribute values, six object field names and JSX
  # text nodes. A bare `const X = "..."` is none of those, so its string is
  # invisible to every ban row -- including TIER_0_BADGE, the one literal the
  # plan mandates verbatim. That is not a small corner: this gate's whole
  # design principle is "refuse to pass silently", and a blind spot nobody
  # counts is the silent part.
  #
  # The measure is exact rather than estimated: run BOTH modes over the same
  # markup files and take the quoted literals copy mode would have seen and
  # markup mode did not. copy mode's own skip rules still apply, so routes,
  # URLs and snake_case wire tokens are excluded -- what remains is prose-
  # shaped text that no ban row can currently judge.
  #
  # Moving a literal into a copy module (`copy.ts`, `copy/*.ts`, `*Copy.ts`)
  # is what takes it out of this count and puts it under the ban list.
  # ------------------------------------------------------------------------
  UNSEEN_TOTAL=0
  unseen_by_root=""
  if [ "${#markup_files[@]}" -gt 0 ]; then
    extract_strings markup "${markup_files[@]}" | LC_ALL=C sort -u > "$FIXTURE_DIR/seen"
    extract_strings copy "${markup_files[@]}" | LC_ALL=C sort -u > "$FIXTURE_DIR/quoted"
    comm -13 "$FIXTURE_DIR/seen" "$FIXTURE_DIR/quoted" > "$FIXTURE_DIR/unseen"
    UNSEEN_TOTAL="$(wc -l < "$FIXTURE_DIR/unseen" | tr -d ' ')"
    for dir in "${PERCH_ROOT_DIRS[@]}"; do
      n="$(awk -F'\t' -v d="$dir/" 'index($1, d) == 1 { c++ } END { print c + 0 }' "$FIXTURE_DIR/unseen")"
      unseen_by_root="${unseen_by_root}  ${n}	${dir#"$PERCH_DESKTOP_ROOT"/}"$'\n'
    done
  fi
  if [ "$UNSEEN_TOTAL" -gt 0 ]; then
    echo "BLIND SPOT: $UNSEEN_TOTAL string literal(s) in the required roots were NOT scanned"
    echo "" >&2
    echo "BLIND SPOT: $UNSEEN_TOTAL string literal(s) in the required roots were NOT scanned." >&2
    printf '%s' "$unseen_by_root" | awk -F'\t' '{ printf "  %6s  %s\n", $1, $2 }' >&2
    echo "  markup mode reads four attribute values, six object field names and JSX text" >&2
    echo "  nodes. A bare \`const X = \"...\"\` is none of those, so no ban row can judge it." >&2
    echo "  Move a rendered literal into a copy module (copy.ts, copy/*.ts, *Copy.ts) to" >&2
    echo "  bring it under the ban list. Run with PERCH_LIST_UNSEEN=1 to print them." >&2
    if [ -n "${PERCH_LIST_UNSEEN:-}" ]; then
      sed "s#$PERCH_DESKTOP_ROOT/##" "$FIXTURE_DIR/unseen" \
        | awk -F'\t' '{ printf "    %s:%s\n        %s\n", $1, $2, $3 }' >&2
    fi
    # The number with teeth. A raw count is mostly wire tokens, Tailwind class
    # strings and schema names -- true, and easy to learn to ignore. This is the
    # part that is not ignorable: how many of those unscanned literals a ban row
    # WOULD have flagged. It runs the same rows over the same strings, so a
    # nonzero here is a real violation hiding behind an extraction mode.
    would_violate="$(scan_extracted < "$FIXTURE_DIR/unseen" | apply_allowlist || true)"
    if [ -n "${would_violate//[$'\n']/}" ]; then
      echo "" >&2
      echo "  OF THOSE, these would violate a ban row if the literal were scanned:" >&2
      printf '%s\n' "$would_violate" \
        | awk -F'\t' -v r="$PERCH_DESKTOP_ROOT/" 'NF >= 6 { gsub(r, "", $3); printf "    [%s %s] %s:%s\n        %s\n", $2, $1, $3, $4, $5 }' >&2
      echo "  Move each into a copy module so the ban row can judge it, or change the" >&2
      echo "  string. This is not a pass over them." >&2
    else
      echo "  None of them trips a ban row today, checked by running the same rows over" >&2
      echo "  the same strings on every run." >&2
    fi
  fi

  if [ "$COPY_SCOPE_STATUS" = "required" ]; then
    echo "scanned ${#asset_files[@]} asset(s), ${#copy_files[@]} copy module(s), ${#markup_files[@]} component file(s)"
  else
    echo "scanned ${#copy_files[@]} copy module(s), ${#markup_files[@]} component file(s); no asset was scanned"
  fi
else
  if [ "$COPY_SCOPE_STATUS" = "required" ]; then
    echo "scanned ${#asset_files[@]} asset(s)"
  fi
  echo "" >&2
  echo "WARNING: the Perch product tree does not exist yet, so NO PRODUCT COPY WAS" >&2
  echo "SCANNED and no vocabulary ban is enforced on a rendered string. Every root" >&2
  echo "in tools/perch-source-roots.tsv is marked 'absent' and none of them is" >&2
  echo "present under $PERCH_DESKTOP_ROOT." >&2
  echo "" >&2
  echo "This is not a pass over the product surface. It becomes one automatically:" >&2
  echo "the commit that creates the first Perch feature directory fails this gate" >&2
  echo "until it also flips that root's row to 'required' in the same commit." >&2
fi

# ---------------------------------------------------------------------------
# THE KEYMAP PASS
# ---------------------------------------------------------------------------
# The skeleton assumed the keymap registry lands with the first Perch feature
# directory and failed the moment the tree existed without it. It does not:
# 12-PLAN-FIRST-CARD creates the wire mirror and the evidence cards, and
# 13-PLAN-THE-HOLD Task 26 creates perchKeymapRegistry.ts beside The Watch.
# Between the two the file is legitimately absent, and a gate that is red for a
# whole milestone gets switched off.
#
# So the requirement rides a row that already exists rather than a new one. The
# keymap and The Watch land together, `src/features/perch-watch` is tracked in
# tools/perch-source-roots.tsv, and that manifest already fails the commit that
# creates the directory without flipping its row. The moment that row reads
# `required`, a missing keymap is a hard failure here. Until then it is a loud
# warning that names what will make it mandatory -- the same "it expires on its
# own, nobody has to remember" shape as the rest of this gate.
keymap_report=""
keymap_deferred=""
if [ -f "$KEYMAP_FILE" ]; then
  keymap_report="$(keymap_entries "$KEYMAP_FILE" | scan_keymap)"
elif [ "$PERCH_TREE_STATE" = "present" ]; then
  watch_status="$(perch_root_status src/features/perch-watch)"
  if [ "$watch_status" = "required" ]; then
    keymap_report="REGISTRY	$KEYMAP_FILE is missing while src/features/perch-watch is required; INV-31 and INV-32 assert nothing"
  else
    keymap_deferred="yes"
    echo "" >&2
    echo "PARTIAL COVERAGE: the keymap registry does not exist yet, so INV-31 (no verdict" >&2
    echo "verb on the A key) and INV-32 (one key, one verb) assert NOTHING on real source." >&2
    echo "  expected at: $KEYMAP_FILE" >&2
    echo "  It lands with The Watch (13-PLAN-THE-HOLD Task 26). The commit that creates" >&2
    echo "  src/features/perch-watch must flip that row in tools/perch-source-roots.tsv" >&2
    echo "  to 'required', and this arm becomes a hard failure the moment it does." >&2
    echo "  The scanner itself is proved on every run by keymap.bad.ts / keymap.good.ts" >&2
    echo "  / keymap.gutted.ts in the fixture above." >&2
  fi
fi

status=0
if [ -n "${violations//[$'\n']/}" ]; then
  echo "" >&2
  echo "Banned terms in rendered strings. Each line is id / severity / where / the string." >&2
  echo "The rule and its replacement come from tools/copy-ban-list.tsv." >&2
  echo "" >&2
  printf '%s\n' "$violations" \
    | awk -F'\t' 'NF >= 6 { printf "  [%s %s] %s:%s\n      %s\n      -> %s\n", $2, $1, $3, $4, $5, $6 }' >&2
  status=1
fi

if [ -n "$keymap_report" ]; then
  echo "" >&2
  echo "Keymap registry violations (APPENDIX-NORMATIVE.md section 2, INV-31, INV-32):" >&2
  printf '%s\n' "$keymap_report" | awk -F'\t' '{ printf "  [%s] %s\n", $1, $2 }' >&2
  status=1
fi

if [ "$status" -ne 0 ]; then
  echo "" >&2
  echo "If a ban is wrong, change tools/copy-ban-list.tsv and say so in the PR as a" >&2
  echo "brief amendment under 00-BRIEF.md section 12. Do not add an allowlist entry" >&2
  echo "for product copy; the allowlist exists for documentation assets carrying" >&2
  echo "recorded, dated debt." >&2
  exit 1
fi

# The closing line names every scope this run did NOT cover. Unqualified
# "copy gate clean" is reserved for the run that covered everything; anything
# else would let a deferral or a blind spot read as a clean sweep, which is the
# whole reason W3-24 made the assets deferral a reviewed row instead of a
# deleted scan. Three independent caveats can apply, so they are a list rather
# than a nest of ifs -- adding a fourth must not be able to drop a third.
caveats=()
if [ "$COPY_SCOPE_STATUS" != "required" ]; then
  caveats+=("$COPY_SCOPE_DIR is deferred and was NOT scanned")
fi
if [ -n "$keymap_deferred" ]; then
  caveats+=("the keymap registry does not exist yet")
fi
if [ "${UNSEEN_TOTAL:-0}" -gt 0 ]; then
  caveats+=("$UNSEEN_TOTAL literal(s) sit in the bare-literal blind spot")
fi

if [ "$PERCH_TREE_STATE" != "present" ]; then
  closing="copy gate asserted nothing over the product half: it is not yet scannable"
elif [ "${#caveats[@]}" -eq 0 ]; then
  closing="copy gate clean"
else
  closing="copy gate clean over what it scanned"
fi

if [ "${#caveats[@]}" -eq 0 ]; then
  echo "$closing"
else
  printf '%s; ' "$closing"
  printf '%s' "${caveats[0]}"
  for ((i = 1; i < ${#caveats[@]}; i++)); do
    printf ', %s' "${caveats[i]}"
  done
  printf '\n'
fi
