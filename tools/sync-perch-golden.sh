#!/usr/bin/env bash
# Re-pins the golden corpus hash in BOTH language suites from one computation:
# sha256 over the concatenation of every golden vector except manifest.json,
# sorted by file name in C locale (the order tests/golden.rs and golden.test.mjs use).
# Also mirrors the engine's golden/ into the desktop's, so the two directories
# cannot drift. Never edit GOLDEN.sha256 by hand.
#
# Not a gate: tools/check-gates-wired.sh enumerates only check-* and verify-*,
# so this script is not required to appear in a workflow `run:` step.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/crates/swarm-perch-wire/golden"
DST="$ROOT/workspace/desktop/src/features/perch/wire/golden"

# `ls | grep | sort` rather than a glob, so the order is the byte order both
# test suites sort in and not the shell's locale-dependent glob order.
hash="$(cd "$SRC" && cat $(ls *.json | grep -v '^manifest.json$' | LC_ALL=C sort) | shasum -a 256 | cut -d' ' -f1)"
printf '%s  (concatenated, sorted by filename)\n' "$hash" > "$SRC/GOLDEN.sha256"

# perl rather than `sed -i`: BSD and GNU sed disagree on the in-place flag, and
# rustfmt/biome are free to keep the constant on one line or wrap it onto two.
perl -0pi -e 's/(const GOLDEN_SHA256: &str =\s*")[0-9a-f]{64}(")/${1}'"$hash"'${2}/' \
  "$ROOT/crates/swarm-perch-wire/tests/golden.rs"
grep -q "$hash" "$ROOT/crates/swarm-perch-wire/tests/golden.rs" || {
  echo "sync-perch-golden: could not find the GOLDEN_SHA256 constant in tests/golden.rs" >&2
  exit 1
}

# Mirror whenever the desktop's wire module exists, creating golden/ on its
# first run so Task 2's "copy and mirror" step needs no manual mkdir.
if [ -d "$(dirname "$DST")" ]; then
  mkdir -p "$DST"
  rm -f "$DST"/*.json "$DST/GOLDEN.sha256"
  cp "$SRC"/*.json "$SRC/GOLDEN.sha256" "$DST/"
  perl -0pi -e 's/(const GOLDEN_SHA256 =\s*")[0-9a-f]{64}(")/${1}'"$hash"'${2}/' \
    "$DST/../golden.test.mjs"
  grep -q "$hash" "$DST/../golden.test.mjs" || {
    echo "sync-perch-golden: could not find the GOLDEN_SHA256 constant in golden.test.mjs" >&2
    exit 1
  }
fi
echo "pinned $hash"
