#!/usr/bin/env bash
#
# Phase-282 visibility baseline gate (SPLIT-05).
#
# WHY THIS EXISTS
#   Phase 282 was briefed with a no-widening invariant: no item that was
#   `pub(crate)`, `pub(super)` or `pub(in ...)` at the phase baseline may be
#   `pub` afterwards, because `pub` on a crate is public API forever. SPLIT-05
#   broke it three times -- `config::kill_chain_sequence_profile`,
#   `config::validate_all_detector_profiles` and
#   `escalation::standard_threat_classes` had to cross the new crate line -- and
#   ADR 0006 records why each one could not follow its caller and why a
#   re-export facade cannot substitute (a re-export of a `pub(crate)` item is
#   `error[E0364]`, so the item has to be widened before any facade can name it).
#
#   SPLIT-05's recorded decision (ADR 0006, "Decision on the broken invariant")
#   is to ACCEPT those three and re-baseline the rule at them. This script is
#   that re-baselined rule, made executable: three named widenings are allowed,
#   a fourth is a gate failure. Without it the rule is prose in an ADR and the
#   next widening lands unremarked.
#
# WHY NOT THE COMMAND IN THE BRIEF
#   The brief stated the invariant as
#
#       git diff <base>..HEAD | grep -E '^-.*(pub\(crate\)|pub\(super\)|pub\(in )'
#
#   which reads diff hunks, so it answers a different question than the one that
#   matters. It counts a `pub(super)` line whose TYPE changed as a hit (it did:
#   `bridge_health`), it counts a NARROWING as a hit (it did:
#   `approval_context_now`, `pub(crate)` -> private), and it reports nothing at
#   all when git pairs a moved file as a rename -- which is most of what a crate
#   extraction does. Its five hits at HEAD are three widenings and two
#   non-widenings, and separating them was hand work.
#
#   This script compares DECLARATION SETS at two revisions instead: which item
#   names were declared with a restricted visibility at the baseline, and which
#   of those are declared `pub` anywhere under `crates/*/src` now. A pure file
#   move carries its declaration text with it and is invisible to that
#   comparison, which is the property the diff-line form lacks.
#
# WHAT IS COVERED
#   Item declarations under `crates/*/src` (any depth), for the keywords
#   `fn struct enum trait const static type mod union`, with `async`/`unsafe`
#   between the visibility and the keyword tolerated.
#
# WHAT IS NOT COVERED (deliberately)
#   - Struct FIELDS (`pub(super) bridge_health: ...`). Fields carry no item
#     keyword, so matching them means telling a field from a local binding
#     textually, and every `pub` field in the workspace becomes noise. The
#     diff-line command above stays the coarse net for those.
#   - `pub use` re-exports. A re-export cannot widen what it names (E0364), so
#     the item it points at is already covered here.
#   - Macro-generated items, and anything outside `crates/*/src` (tests,
#     benches, examples, `vendor/reference/`): none of those are library API.
#   - Same-name collisions WITHIN ONE FILE. Matching is by
#     `<path-under-src> <keyword> <name>`, so two `fn validate` in the same file
#     -- one `pub`, one `pub(super)` -- are one key. Five such keys exist and are
#     on the allowlist with their measured baseline visibility mix.
#
#     This used to be matched by `<keyword> <name>` alone, with no path at all,
#     and the header recorded only the false-POSITIVE direction of that ("an item
#     restricted in crate A and legitimately `pub` in crate B reads as widened").
#     The false-NEGATIVE direction went undisclosed and made the gate vacuous:
#     the baseline-`pub` exclusion below dropped any key appearing in BOTH
#     baseline sets, which under name-only matching meant "some item ANYWHERE in
#     20 crates shared this name" -- 20 tokens (`fn new`, `fn parse`,
#     `fn validate`, `fn snapshot`, `fn record`, `fn open`, ...) covering 152 of
#     the 829 restricted declarations. Widening any of them exited 0 while still
#     printing "no others". Keying on the path under `src/` -- which a
#     crate-to-crate move preserves, so pure moves stay invisible as intended --
#     drops that from 20 keys to 5, and the exclusion is gone entirely: every
#     surviving exemption is now a named allowlist line rather than a silent
#     set-subtraction.
#
# HOW TO CHANGE THE ALLOWLIST
#   Adding a line is a reviewable act, and the review is the point: say which
#   caller across which crate line needs it, and what deletes it later. Removing
#   a line is required as soon as the item narrows again -- a stale entry fails
#   this gate too, so the allowlist cannot quietly outlive its reason.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# The phase-282 baseline. Every crate extraction in the phase is measured from
# here, and so is the invariant.
BASE_REV="${STS_VISIBILITY_BASELINE_REV:-742206d}"
# The near side is the WORKING TREE, not `HEAD`. A gate that reads the committed
# tree passes on an uncommitted widening, which is the one moment it is asked to
# speak. Set STS_VISIBILITY_HEAD_REV to audit a specific commit instead.
HEAD_REV="${STS_VISIBILITY_HEAD_REV:-}"

# Accepted entries: `<path-under-src> <keyword> <name>`.
#
# Group 1, ACCEPTED WIDENINGS -- each with the ADR that justifies it.
#
#   fn kill_chain_sequence_profile     SPLIT-05, ADR 0006 -- control.rs:1559,
#                                      still called 4x inside swarm-runtime
#   fn validate_all_detector_profiles  SPLIT-05, ADR 0006 -- control.rs:716;
#                                      moving it widens the 13 pub(crate)
#                                      validators it dispatches to instead of 1
#   fn standard_threat_classes         SPLIT-05, ADR 0006 -- ingest/demo.rs and
#                                      ingest/platform_api.rs, still called 3x
#                                      inside swarm-runtime
#
# All three are deleted by one keyword each when `config` and `escalation`
# leave the composition root, which the remaining SPLITs intend.
#
# Group 2, NOT WIDENINGS -- one file declares the same `<keyword> <name>` at two
# different visibilities, so the key cannot separate them. Each was checked
# against the baseline and the visibility MIX is unchanged at HEAD, which is what
# rules out a widening hiding behind the collision:
#
#   config/bridges.rs fn validate            1 pub + 11 pub(super), both revs
#   config/response.rs fn validate           2 pub +  6 pub(super), both revs
#   evolution/stores.rs fn open              3 pub +  1 pub(crate), both revs
#   evolution/stores.rs fn persist           3 pub +  1 pub(crate), both revs
#   substrate.rs fn set_admitted_identities  3 pub +  1 pub(crate), both revs
#
# Reproduce any row with:
#   git show 742206d:crates/<crate>/src/<path> \
#     | grep -oE '^[[:space:]]*pub(\([^)]*\))?[[:space:]]+fn <name>\b' \
#     | sed -E 's/^[[:space:]]*//; s/ fn .*//' | sort | uniq -c
#
# These five are the gate's remaining blind spot and it is file-scoped: widening
# a DIFFERENT restricted `fn validate` inside config/bridges.rs would not be
# caught. Splitting the key further (by enclosing `impl` block) is the fix if
# that ever matters; it did not seem worth the parser.
ALLOWED_FILE="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-allowed-XXXXXX")"
WIDENINGS_FILE=""
COLLISIONS_FILE=""
BASE_RESTRICTED="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-base-restricted-XXXXXX")"
BASE_PUB="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-base-pub-XXXXXX")"
HEAD_PUB="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-head-pub-XXXXXX")"
RESTRICTED_ONLY="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-restricted-only-XXXXXX")"
WIDENED="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-widened-XXXXXX")"
trap 'rm -f "$ALLOWED_FILE" "$WIDENINGS_FILE" "$COLLISIONS_FILE" "$BASE_RESTRICTED" "$BASE_PUB" "$HEAD_PUB" "$RESTRICTED_ONLY" "$WIDENED"' EXIT

# The two groups are kept in SEPARATE heredocs so the success line can COUNT
# them instead of stating them. The first version of that line read
# "3 accepted widenings and 5 same-file name collisions" with both numbers as
# string literals, which meant two proposed success criteria elsewhere in the
# repo ("still reports three accepted widenings, not four") could not fail on
# the condition they named: add a fourth widening AND its allowlist line and the
# script exits 0 while still printing "3". The gate's invariant was always
# enforced -- a non-allowlisted widening exits 1, a stale allowlist line exits 1
# -- but a count nobody derives is a claim, not a measurement, and this repo has
# shipped ten defects of that exact shape.
WIDENINGS_FILE="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-widenings-XXXXXX")"
COLLISIONS_FILE="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-collisions-XXXXXX")"

cat >"$WIDENINGS_FILE" <<'EOF'
config.rs fn kill_chain_sequence_profile
config.rs fn validate_all_detector_profiles
escalation.rs fn standard_threat_classes
EOF

cat >"$COLLISIONS_FILE" <<'EOF'
config/bridges.rs fn validate
config/response.rs fn validate
evolution/stores.rs fn open
evolution/stores.rs fn persist
substrate.rs fn set_admitted_identities
EOF

cat "$WIDENINGS_FILE" "$COLLISIONS_FILE" >"$ALLOWED_FILE"
sort -o "$ALLOWED_FILE" "$ALLOWED_FILE"

if ! git rev-parse --verify --quiet "${BASE_REV}^{commit}" >/dev/null; then
  echo "visibility baseline commit ${BASE_REV} is not in this clone." >&2
  echo "This gate reads history, so a shallow checkout cannot run it:" >&2
  echo "  actions/checkout needs 'fetch-depth: 0' on the job that runs it." >&2
  exit 1
fi

ITEM_KEYWORDS='fn|struct|enum|trait|const|static|type|mod|union'
# `const` is BOTH a modifier (`pub const fn f()`) and an item keyword
# (`pub const X: u8`), so it has to appear in the modifier alternation as well as
# in ITEM_KEYWORDS. While it appeared only as an item keyword, `pub const fn f()`
# matched with keyword=`const` and name=`fn` and normalized to the single token
# `const fn` -- identical for every const fn in the workspace. The baseline holds
# 90 restricted `const fn` declarations and 3 public ones, so `const fn` landed
# in both baseline sets and the exclusion then removed it: all 90 were invisible,
# and the gate could not have named which one changed even without the exclusion.
# Leftmost-longest matching separates the two forms with no further help --
# `pub const fn f()` -> `fn f` (the modifier group takes `const`), and
# `pub const X: u8` -> `const X` (no item keyword follows, so it matches empty).
# The self-test at the bottom pins both, because this regex regresses silently.
MODIFIERS='((async|unsafe|const)[[:space:]]+)*'
RESTRICTED_RE="^[[:space:]]*pub\((crate|super|in [^)]*)\)[[:space:]]+${MODIFIERS}(${ITEM_KEYWORDS})[[:space:]]+[A-Za-z_][A-Za-z0-9_]*"
PUB_RE="^[[:space:]]*pub[[:space:]]+${MODIFIERS}(${ITEM_KEYWORDS})[[:space:]]+[A-Za-z_][A-Za-z0-9_]*"
# Key: `<path-under-src> <keyword> <name>`. The path is what makes the key mean
# "this item" rather than "this name"; taking it from under `src/` rather than
# from the repo root is what keeps a pure crate-to-crate move invisible, since
# phase 282's moves preserve the in-crate path
# (`swarm-runtime/src/ingest/mod.rs` -> `swarm-ingest-runtime/src/ingest/mod.rs`,
# `swarm-runtime/src/tom_agent.rs` -> `swarm-agents/src/tom_agent.rs`).
#
# `([^:]*:)?` absorbs the `<rev>:` prefix that `git grep` prints and `grep -r`
# does not. `%` is the delimiter because the expression is full of `|`.
NORMALIZE="s%^([^:]*:)?crates/[^/]+/src/([^:]*):[[:space:]]*pub(\([^)]*\))?[[:space:]]+${MODIFIERS}(${ITEM_KEYWORDS})[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*%\2 \6 \7%"

# Both collectors keep the filename (no `-h`), because the path is half the key.
# The trailing `grep` drops any line NORMALIZE failed to rewrite instead of
# letting it through verbatim, so a path-layout change surfaces as a shrinking
# declaration set rather than as phantom entries that match nothing.
KEY_RE="^[^:[:space:]]+ (${ITEM_KEYWORDS}) [A-Za-z_][A-Za-z0-9_]*$"

declarations_rev() { # <rev> <regex>
  git grep -E "$2" "$1" -- 'crates/*/src/*' | sed -E "$NORMALIZE" \
    | grep -E "$KEY_RE" | sort -u
}

declarations_tree() { # <regex>
  # `-I` skips binaries; no `--include` filter, because `.inc` files are real
  # Rust that rustc compiles (see check-no-include-files.sh) and are scanned by
  # the `git grep` side too.
  grep -rIE "$1" crates/*/src | sed -E "$NORMALIZE" \
    | grep -E "$KEY_RE" | sort -u
}

# SELF-TEST. NORMALIZE is the whole gate: if it stops distinguishing
# `pub const fn f()` from `pub const X`, or stops emitting the path, the
# comparison keeps running and keeps exiting 0 while checking nothing. That is
# exactly how this gate shipped broken the first time, so the parsing is pinned
# here rather than trusted. Runs on every invocation; it is seven sed calls.
self_test() {
  local input expected actual failed=0
  while IFS='|' read -r input expected; do
    [[ -z "$input" ]] && continue
    actual="$(printf '%s\n' "$input" | sed -E "$NORMALIZE")"
    if [[ "$actual" != "$expected" ]]; then
      echo "check-visibility-baseline self-test FAILED" >&2
      echo "  input:    $input" >&2
      echo "  expected: $expected" >&2
      echo "  actual:   $actual" >&2
      failed=1
    fi
  done <<'CASES'
crates/swarm-core/src/config/defaults.rs:pub const fn default_x() -> u64 {|config/defaults.rs fn default_x
crates/swarm-core/src/config/defaults.rs:pub(super) const fn default_y() -> u64 {|config/defaults.rs fn default_y
crates/swarm-core/src/lib.rs:pub const MAX_DEPTH: u8 = 4;|lib.rs const MAX_DEPTH
742206d:crates/swarm-runtime/src/replay/detect_stall.rs:    pub(crate) fn new(i: R) -> Self {|replay/detect_stall.rs fn new
crates/swarm-runtime/src/service/mod.rs:    pub async fn run(&self) {|service/mod.rs fn run
crates/swarm-core/src/types.rs:pub struct ActionRequest {|types.rs struct ActionRequest
crates/swarm-policy/src/governance.rs:    pub(in crate::governance) fn seal(&self) {|governance.rs fn seal
CASES
  if [[ "$failed" -ne 0 ]]; then
    echo "The declaration parser is broken; every comparison below would be" >&2
    echo "vacuous. Fix NORMALIZE/MODIFIERS before trusting this gate." >&2
    exit 1
  fi
}
self_test

declarations_rev "$BASE_REV" "$RESTRICTED_RE" >"$BASE_RESTRICTED"
declarations_rev "$BASE_REV" "$PUB_RE" >"$BASE_PUB"
if [[ -n "$HEAD_REV" ]]; then
  declarations_rev "$HEAD_REV" "$PUB_RE" >"$HEAD_PUB"
  near="$HEAD_REV"
else
  declarations_tree "$PUB_RE" >"$HEAD_PUB"
  near="the working tree"
fi

# There is deliberately NO baseline-`pub` exclusion here any more. It used to
# read `comm -23 "$BASE_RESTRICTED" "$BASE_PUB"`, justified as "an item that was
# BOTH restricted somewhere and `pub` somewhere at the baseline was already
# public API then". Under name-only keying that sentence was false -- "somewhere"
# meant anywhere in 20 crates -- and it silently exempted 152 declarations. Now
# that the key carries the path, the five keys that genuinely collide inside one
# file are named on the allowlist instead, where a reviewer sees them.
cp "$BASE_RESTRICTED" "$RESTRICTED_ONLY"
comm -12 "$RESTRICTED_ONLY" "$HEAD_PUB" >"$WIDENED"

status=0

unexpected="$(comm -23 "$WIDENED" "$ALLOWED_FILE")"
if [[ -n "$unexpected" ]]; then
  status=1
  echo "restricted at ${BASE_REV}, now 'pub' in ${near}, and NOT on the accepted list:" >&2
  echo "$unexpected" | sed 's/^/  /' >&2
  echo >&2
  echo "'pub' on a crate is public API forever. Prefer moving the item to its" >&2
  echo "caller's crate, or inverting the dependency behind a trait. If neither" >&2
  echo "works, add a line to the allowlist in $(basename "${BASH_SOURCE[0]}")" >&2
  echo "with the caller that needs it and what deletes it later, and record the" >&2
  echo "reasoning in an ADR." >&2
fi

stale="$(comm -13 "$WIDENED" "$ALLOWED_FILE")"
if [[ -n "$stale" ]]; then
  status=1
  echo "allowlisted but no longer widened -- delete these lines:" >&2
  echo "$stale" | sed 's/^/  /' >&2
fi

if [[ "$status" -ne 0 ]]; then
  exit "$status"
fi

# Both counts are DERIVED from the two allowlist groups, never written as
# literals: a success line whose numbers are typed in is a claim the gate cannot
# check, and this file exists because a gate that could not fail printed
# "no others" over 152 exempt declarations.
echo "visibility baseline holds in ${near}: $(wc -l <"$WIDENINGS_FILE" | tr -d ' ') accepted widenings and $(wc -l <"$COLLISIONS_FILE" | tr -d ' ') same-file name collisions since ${BASE_REV}, no others"
