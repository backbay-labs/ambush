#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# Regenerate the repo-owned detector experiment fixtures consumed by the
# swarm-runtime tests, through the compiled `DetectorExperimentManifest` schema.
#
# With no argument the fixtures are rewritten IN PLACE under `experiments/`.
# Pass an output directory to regenerate somewhere else -- that is how
# `tools/check-fixture-freshness.sh` compares a regeneration against the
# committed bytes without writing into the working tree.
#
# The generator is `crates/swarm-runtime/examples/regen_experiment_fixtures.rs`;
# see its module docs for what "pinned schema version" means here.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/experiments}"

# shellcheck source=tools/fixture-inventory.sh
source "$ROOT_DIR/tools/fixture-inventory.sh"

# Enumerate the COMMITTED set, not a hardcoded array.
#
# `git ls-files -c -o --exclude-standard` is exactly "what a `git add -A`
# would leave tracked": cached files plus untracked files that .gitignore does
# not exclude. That is the set a "sync generated artifacts" commit can carry, so
# it is the set the schema gate has to cover. Deriving it from git rather than
# from a glob is what keeps the transient, gitignored `experiments/mutation-*`
# and `experiments/materialized-*` outputs out without this script having to
# restate the ignore rules.
if ! git -C "$ROOT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  echo "not a git checkout: cannot enumerate the committed fixture set" >&2
  exit 1
fi

STATE_DIR="$(mktemp -d)"
trap 'rm -rf "$STATE_DIR"' EXIT
INVENTORY="$STATE_DIR/fixtures.nul"
fixture_inventory_write "$ROOT_DIR" "$INVENTORY"

# `mapfile` is bash 4+; macOS ships 3.2 and this gate has to run locally too.
FIXTURES=()
while IFS= read -r -d '' fixture; do
  fixture_require_direct_path "$fixture"
  FIXTURES+=("$fixture")
done <"$INVENTORY"

if [ "${#FIXTURES[@]}" -eq 0 ]; then
  echo "no experiments/*.yaml fixtures found; refusing to pass silently" >&2
  exit 1
fi

GENERATOR_LOG="$STATE_DIR/generator.log"
set +e
(
  cd "$ROOT_DIR"
  cargo run --quiet -p swarm-runtime --example regen_experiment_fixtures -- \
    "$OUT_DIR" "${FIXTURES[@]}"
) >"$GENERATOR_LOG" 2>&1
generator_status=$?
set -e

if [ "$generator_status" -ne 0 ]; then
  echo "fixture generator failed (exit $generator_status): $(fixture_display_stream <"$GENERATOR_LOG")" >&2
  exit "$generator_status"
fi
