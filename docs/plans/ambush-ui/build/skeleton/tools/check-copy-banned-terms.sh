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
#      aria-label values and <text> node contents. ALWAYS scanned; an empty
#      match refuses to pass.
#
#   B. $PERCH_DESKTOP_ROOT (a checkout of block/buzz's `desktop/`), over the
#      roots named in tools/perch-source-roots.tsv. Two scan modes:
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

# The Perch tree lives in block/buzz. This gate is inherently cross-repo and
# no plan document budgeted the second checkout; naming that here is cheaper
# than a green build over a directory nobody supplied.
if [ -z "${PERCH_DESKTOP_ROOT:-}" ] || [ ! -d "${PERCH_DESKTOP_ROOT}" ]; then
  cat >&2 <<'MSG'
PERCH_DESKTOP_ROOT is unset or not a directory.

This gate scans product copy that lives in block/buzz, not in this repository.
Wire it in .github/workflows/ci.yml as:

  - name: Check out the Perch desktop tree
    uses: actions/checkout@v4
    with:
      repository: block/buzz
      path: .perch-desktop
  - name: Check Perch copy against the banned-term list
    env:
      PERCH_DESKTOP_ROOT: ${{ github.workspace }}/.perch-desktop/desktop
    run: bash tools/check-copy-banned-terms.sh

Refusing to report a pass over a tree that was not supplied.
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
    grep -v '^#' "$CORPUS_DIR/expected.tsv" | grep -v '^file\t' | grep -v '^$' \
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

if [ "$fixture_failures" -ne 0 ]; then
  echo "" >&2
  echo "The fixture proves this scanner can fail. $fixture_failures of its cases did" >&2
  echo "not behave as documented, so its verdict over the real trees means nothing." >&2
  echo "Fix the scanner, not the fixture." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# THE REAL SCAN -- HALF A: this repository's assets. Always required.
# ---------------------------------------------------------------------------
violations=""

asset_files=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  asset_files+=("$path")
done < <(find docs/assets -name '*.svg' -type f 2>/dev/null | LC_ALL=C sort)

if [ "${#asset_files[@]}" -eq 0 ]; then
  echo "no docs/assets/*.svg found; refusing to pass silently" >&2
  exit 1
fi
violations="$violations$(extract_strings markup "${asset_files[@]}" | scan_extracted | apply_allowlist)"

# ---------------------------------------------------------------------------
# THE REAL SCAN -- HALF B: the Perch product tree, scoped by the manifest.
# ---------------------------------------------------------------------------
perch_roots_gate copy "$PERCH_DESKTOP_ROOT"

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

  echo "scanned ${#asset_files[@]} asset(s), ${#copy_files[@]} copy module(s), ${#markup_files[@]} component file(s)"
else
  echo "scanned ${#asset_files[@]} asset(s)"
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
keymap_report=""
if [ -f "$KEYMAP_FILE" ]; then
  keymap_report="$(keymap_entries "$KEYMAP_FILE" | scan_keymap)"
elif [ "$PERCH_TREE_STATE" = "present" ]; then
  keymap_report="REGISTRY	$KEYMAP_FILE is missing while the Perch tree exists; INV-31 and INV-32 assert nothing"
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

if [ "$PERCH_TREE_STATE" = "present" ]; then
  echo "copy gate clean"
else
  echo "copy gate clean over the asset half only; the product half is not yet scannable"
fi
