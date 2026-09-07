#!/usr/bin/env bash
#
# ARMSCI-02. Structural isolation for the red lane: `crates/swarm-runtime/src/
# red_swarm/**` and `crates/swarm-cli/src/red_swarm_cmd.rs` generate adversarial
# telemetry and score detectors (phases 288-290) and must never grow a path to
# response authority. This scans both for four forbidden names --
# `execute_response`, `ResponseAdapter`, `PolicyDecision::Authorize`,
# `live_response` -- and fails the build if any appears.
#
# THE HOLE THIS CLOSES
#   Nothing today stops a future red-swarm change from calling into
#   `swarm-response` or `swarm-policy`'s authorize path directly -- the red
#   lane is a normal Rust module with normal visibility, and `swarm-runtime`
#   already depends on both crates for its OWN legitimate response dispatch.
#   A red genome that could authorize or execute a real response is not a
#   detection-and-scoring exercise any more; it is live response with no
#   policy gate in front of it. This is a bright-line lexical ban, not a
#   judgment call left to review.
#
# WHY NOT PLAIN GREP
#   Because an empty scan and a broken needle look identical. Every
#   invocation first plants each forbidden name as real code in a temp tree
#   and asserts `scan_forbidden_symbols` (the SAME function the real scan
#   below calls) catches it; if any does not, the script exits 2 without
#   scanning the real tree at all. A gate that cannot see its own subject is
#   not a passing gate. The real scan targets are also asserted to exist and
#   to contain at least one `*.rs` file before they are trusted, for the same
#   reason: a target renamed out from under this script must fail loudly, not
#   report a silent, vacuous "clean".
#
# COMMENTS ARE EXCLUDED, ON PURPOSE
#   `pattern_db.rs`'s module doc says, in prose, "nothing here resolves to
#   `execute_response`, `ResponseAdapter`, `live_response`" -- a true claim
#   about that file's imports and call graph, and a claim it can only make by
#   naming the very symbols it says are absent. A comment does not compile
#   and cannot reach response authority, so a line that is ONLY a `//`/`//!`/
#   `///` comment (leading whitespace, then `//`) is excluded before the
#   forbidden-name check runs. This is a per-LINE rule, not a tokenizer: a
#   forbidden name arriving as a trailing comment after real code on the same
#   line is still (deliberately, conservatively) scanned. The fixture below
#   proves both directions: a planted comment-only mention is NOT caught, and
#   a planted code occurrence IS.
#
#   NOT RECOGNIZED: a `/* ... */` block comment -- only a line starting with
#   `//` (after leading whitespace) is treated as a comment. A forbidden name
#   inside a block comment would be scanned and FLAGGED rather than excluded,
#   which is the safe direction to be wrong in (a spurious failure over dead
#   comment text, never a missed real violation). There are no `/* */` blocks
#   under either scan target today -- confirmed by grepping both for `/*`;
#   every hit is a `///` doc-comment line or a glob pattern such as `*.yaml`
#   written inside one -- so this is disclosed rather than fixed. The Rust
#   companion's `isolation_gate.rs` module doc carries the identical note.
#
# ARMSCI-03, AND WHY ITS FILE IS EXCLUDED BY NAME BELOW
#   `crates/swarm-runtime/src/red_swarm/isolation_gate.rs` is the Rust-side
#   companion: it runs the same rule, in Rust, over the same two source
#   locations, from inside `cargo test`, so a miswired or skipped CI step
#   still gets caught. Its own non-vacuity proof needs a counterexample that
#   WOULD trip this scan, and it has to spell out the four forbidden names as
#   literal text to look for them at all -- but that file lives inside
#   `crates/swarm-runtime/src/red_swarm/`, which this script scans
#   byte-for-byte, so both requirements collide with this script seeing
#   every byte of that file too. `EXCLUDED_FILES` below names that one file
#   by its exact repo-relative path and skips it; every OTHER file under
#   `red_swarm/`, including every other test module, is still scanned
#   exactly as before. See that file's module doc for the full argument,
#   including why an earlier version tried to dodge this with split-literal
#   obfuscation instead and why that was worse.
#
# BASH 3.2
#   No `mapfile`, no associative arrays: macOS ships bash 3.2 and a gate a
#   developer cannot run locally is a gate that is only ever seen red in CI.
set -euo pipefail
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# The four names ARMSCI-02 forbids, verbatim from `.planning/REQUIREMENTS.md`
# and mirrored in `FORBIDDEN_SYMBOLS` in the Rust companion
# (`crates/swarm-runtime/src/red_swarm/isolation_gate.rs`). A fifth name
# belongs in both arrays in the same commit.
FORBIDDEN=(
  'execute_response'
  'ResponseAdapter'
  'PolicyDecision::Authorize'
  'live_response'
)

# "Red-swarm sources", per 291-01-PLAN.md's design of record: the red lane
# only, not every consumer of it.
SCAN_TARGETS=(
  'crates/swarm-runtime/src/red_swarm'
  'crates/swarm-cli/src/red_swarm_cmd.rs'
)

# ARMSCI-03's own Rust companion. It legitimately spells out the same four
# forbidden names -- as its own copy of the ban list, and as a planted
# counterexample proving its check is not vacuous -- so it is excluded here
# by its exact repo-relative path, not by directory or by a `#[cfg(test)]`
# span. See that file's module doc ("WHY THIS FILE IS EXCLUDED FROM ITS OWN
# SCAN") for why a narrower, per-literal dodge was tried first and abandoned.
EXCLUDED_FILES=(
  'crates/swarm-runtime/src/red_swarm/isolation_gate.rs'
)

is_excluded_file() {
  local candidate="$1"
  local excluded
  for excluded in "${EXCLUDED_FILES[@]}"; do
    if [ "$candidate" = "$excluded" ]; then
      return 0
    fi
  done
  return 1
}

# scan_forbidden_symbols PATH...
#
# Prints one "<file>:<line>:<content>" line per hit: a non-comment line in
# any `*.rs` file under the given files/directories that contains one of the
# forbidden names in $FORBIDDEN as a plain substring. Called on a planted
# fixture below AND on the real tree at the bottom -- one function, so the
# matching rule cannot silently diverge between the self-test and the real
# scan the way two hand-copied greps could.
#
# Always returns 0: a `set -euo pipefail` script must never let "grep found
# nothing" (exit 1) read as a script failure at the call site, because
# "nothing" is exactly what a clean tree should produce. Callers judge the
# PRINTED output, not this function's exit status.
scan_forbidden_symbols() {
  local grep_patterns=()
  local symbol
  for symbol in "${FORBIDDEN[@]}"; do
    grep_patterns+=(-e "$symbol")
  done

  local raw
  raw="$(grep -rn --include='*.rs' -F "${grep_patterns[@]}" -- "$@" || true)"
  if [ -z "$raw" ]; then
    return 0
  fi

  local hit file rest line_no content
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    file="${hit%%:*}"
    rest="${hit#*:}"
    line_no="${rest%%:*}"
    content="${rest#*:}"
    # ARMSCI-03's own fixture file -- see EXCLUDED_FILES above.
    if is_excluded_file "$file"; then
      continue
    fi
    # A line that is ONLY a comment (leading whitespace, then `//`) does not
    # compile and cannot reach response authority -- see COMMENTS ARE
    # EXCLUDED above.
    if printf '%s\n' "$content" | grep -Eq '^[[:space:]]*//'; then
      continue
    fi
    printf '%s:%s:%s\n' "$file" "$line_no" "$content"
  done <<EOF
$raw
EOF
  return 0
}

# --- self-test on a fixture, so an empty scan cannot pass vacuously --------
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT

for symbol in "${FORBIDDEN[@]}"; do
  rm -rf "$fixture/needle"
  mkdir -p "$fixture/needle"
  printf 'fn planted_violation() {\n    let _ = %s;\n}\n' "$symbol" \
    > "$fixture/needle/planted.rs"
  needle_hits="$(scan_forbidden_symbols "$fixture/needle")"
  if [ -z "$needle_hits" ]; then
    echo "check-red-swarm-no-execution-authority: FIXTURE FAILED -- planting '$symbol' as code was not caught" >&2
    exit 2
  fi
done
rm -rf "$fixture/needle"

# The mirror image: a name mentioned ONLY in a comment must NOT be caught, or
# pattern_db.rs's own module doc -- which says in prose that it resolves to
# none of these names -- would fail this exact gate for saying so.
mkdir -p "$fixture/comment"
printf '//! nothing here resolves to `%s`.\n' "${FORBIDDEN[0]}" > "$fixture/comment/doc.rs"
comment_hits="$(scan_forbidden_symbols "$fixture/comment")"
if [ -n "$comment_hits" ]; then
  echo "check-red-swarm-no-execution-authority: FIXTURE FAILED -- a comment-only mention of '${FORBIDDEN[0]}' was caught" >&2
  exit 2
fi
rm -rf "$fixture/comment"

# is_excluded_file must recognize exactly the configured path (ARMSCI-03's
# own fixture, which legitimately contains the ban list) and nothing else --
# a predicate that excluded more would blind the scan to a real violation
# anywhere it matched.
if ! is_excluded_file "${EXCLUDED_FILES[0]}"; then
  echo "check-red-swarm-no-execution-authority: FIXTURE FAILED -- is_excluded_file does not recognize its own configured path" >&2
  exit 2
fi
if is_excluded_file "crates/swarm-runtime/src/red_swarm/mod.rs"; then
  echo "check-red-swarm-no-execution-authority: FIXTURE FAILED -- is_excluded_file excludes more than the configured path" >&2
  exit 2
fi

# --- the real scan cannot be trusted to see nothing -------------------------
for target in "${SCAN_TARGETS[@]}"; do
  if [ ! -e "$target" ]; then
    echo "check-red-swarm-no-execution-authority: configured scan target '$target' does not exist -- refusing to pass silently" >&2
    exit 2
  fi
done

file_count="$(find "${SCAN_TARGETS[@]}" -type f -name '*.rs' | LC_ALL=C sort -u | wc -l | tr -d '[:space:]')"

excluded_count=0
for excluded in "${EXCLUDED_FILES[@]}"; do
  if [ -e "$excluded" ]; then
    excluded_count=$((excluded_count + 1))
  fi
done
scanned_count=$((file_count - excluded_count))

if [ "$scanned_count" -le 0 ]; then
  echo "check-red-swarm-no-execution-authority: zero non-excluded *.rs files found under the scan targets -- refusing to pass silently" >&2
  exit 2
fi

# --- the real scan -----------------------------------------------------------
hits="$(scan_forbidden_symbols "${SCAN_TARGETS[@]}")"

status=0
if [ -n "$hits" ]; then
  status=1
  while IFS= read -r hit; do
    [ -n "$hit" ] || continue
    echo "check-red-swarm-no-execution-authority: FORBIDDEN SYMBOL: $hit" >&2
    echo "  the red lane generates telemetry and scores detectors; it must never name" >&2
    echo "  execute_response, ResponseAdapter, PolicyDecision::Authorize, or live_response" >&2
  done <<EOF
$hits
EOF
fi

if [ "$status" -eq 0 ]; then
  echo "check-red-swarm-no-execution-authority: clean (0 forbidden symbol(s) across ${scanned_count} red-swarm source file(s), ${excluded_count} excluded as ARMSCI-03's own fixture)"
fi
exit "$status"
