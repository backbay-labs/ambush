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
#   - Same-name collisions. Matching is by `<keyword> <name>`, not by path, so an
#     item that was restricted in crate A and is legitimately `pub` in crate B
#     reads as widened. That is a deliberate false-positive bias: the response is
#     to look, and then either fix it or add a dated allowlist line.
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

# Accepted widenings: `<keyword> <name>`, each with the ADR that justifies it.
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
ALLOWED_FILE="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-allowed-XXXXXX")"
BASE_RESTRICTED="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-base-restricted-XXXXXX")"
BASE_PUB="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-base-pub-XXXXXX")"
HEAD_PUB="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-head-pub-XXXXXX")"
RESTRICTED_ONLY="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-restricted-only-XXXXXX")"
WIDENED="$(mktemp "${TMPDIR:-/tmp}/swarm-visibility-widened-XXXXXX")"
trap 'rm -f "$ALLOWED_FILE" "$BASE_RESTRICTED" "$BASE_PUB" "$HEAD_PUB" "$RESTRICTED_ONLY" "$WIDENED"' EXIT

cat >"$ALLOWED_FILE" <<'EOF'
fn kill_chain_sequence_profile
fn standard_threat_classes
fn validate_all_detector_profiles
EOF

if ! git rev-parse --verify --quiet "${BASE_REV}^{commit}" >/dev/null; then
  echo "visibility baseline commit ${BASE_REV} is not in this clone." >&2
  echo "This gate reads history, so a shallow checkout cannot run it:" >&2
  echo "  actions/checkout needs 'fetch-depth: 0' on the job that runs it." >&2
  exit 1
fi

ITEM_KEYWORDS='fn|struct|enum|trait|const|static|type|mod|union'
RESTRICTED_RE="^[[:space:]]*pub\((crate|super|in [^)]*)\)[[:space:]]+((async|unsafe)[[:space:]]+)*(${ITEM_KEYWORDS})[[:space:]]+[A-Za-z_][A-Za-z0-9_]*"
PUB_RE="^[[:space:]]*pub[[:space:]]+((async|unsafe)[[:space:]]+)*(${ITEM_KEYWORDS})[[:space:]]+[A-Za-z_][A-Za-z0-9_]*"
NORMALIZE="s/^[[:space:]]*pub(\([^)]*\))?[[:space:]]+((async|unsafe)[[:space:]]+)*(${ITEM_KEYWORDS})[[:space:]]+([A-Za-z_][A-Za-z0-9_]*).*/\4 \5/"

declarations_rev() { # <rev> <regex>
  git grep -hE "$2" "$1" -- 'crates/*/src/*' | sed -E "$NORMALIZE" | sort -u
}

declarations_tree() { # <regex>
  # `-I` skips binaries; no `--include` filter, because `.inc` files are real
  # Rust that rustc compiles (see check-no-include-files.sh) and are scanned by
  # the `git grep` side too.
  grep -rhIE "$1" crates/*/src | sed -E "$NORMALIZE" | sort -u
}

declarations_rev "$BASE_REV" "$RESTRICTED_RE" >"$BASE_RESTRICTED"
declarations_rev "$BASE_REV" "$PUB_RE" >"$BASE_PUB"
if [[ -n "$HEAD_REV" ]]; then
  declarations_rev "$HEAD_REV" "$PUB_RE" >"$HEAD_PUB"
  near="$HEAD_REV"
else
  declarations_tree "$PUB_RE" >"$HEAD_PUB"
  near="the working tree"
fi

# An item that was BOTH restricted somewhere and `pub` somewhere at the baseline
# was already public API then, so widening cannot be what made it so.
comm -23 "$BASE_RESTRICTED" "$BASE_PUB" >"$RESTRICTED_ONLY"
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

echo "visibility baseline holds in ${near}: $(wc -l <"$ALLOWED_FILE" | tr -d ' ') accepted widenings since ${BASE_REV}, no others"
