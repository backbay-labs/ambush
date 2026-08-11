#!/usr/bin/env bash
set -euo pipefail

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

# Enumerate the COMMITTED set, not a hardcoded array.
#
# `git ls-files -c -o --exclude-standard` is exactly "what a `git add -A`
# would leave tracked": cached files plus untracked files that .gitignore does
# not exclude. That is the set a "sync generated artifacts" commit can carry, so
# it is the set the schema gate has to cover. Deriving it from git rather than
# from a glob is what keeps the transient, gitignored `experiments/mutation-*`
# and `experiments/materialized-*` outputs out without this script having to
# restate the ignore rules.
fixture_list() {
  git -C "$ROOT_DIR" ls-files -c -o --exclude-standard -- experiments \
    | grep -E '\.(yaml|yml)$' \
    | LC_ALL=C sort
}

if ! git -C "$ROOT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  echo "not a git checkout: cannot enumerate the committed fixture set" >&2
  exit 1
fi

# `mapfile` is bash 4+; macOS ships 3.2 and this gate has to run locally too.
FIXTURES=()
while IFS= read -r fixture; do
  [ -n "$fixture" ] || continue
  FIXTURES+=("$fixture")
done < <(fixture_list)

if [ "${#FIXTURES[@]}" -eq 0 ]; then
  echo "no experiments/*.yaml fixtures found; refusing to pass silently" >&2
  exit 1
fi

pushd "$ROOT_DIR" >/dev/null
cargo run --quiet -p swarm-runtime --example regen_experiment_fixtures -- \
  "$OUT_DIR" "${FIXTURES[@]}"
popd >/dev/null
