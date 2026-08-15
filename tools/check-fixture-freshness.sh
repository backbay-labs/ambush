#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# Fail when a committed detector experiment fixture differs from a regeneration.
#
# Regenerates into a scratch directory and diffs; NEVER writes into the working
# tree, because a repository-hygiene gate that dirties the repository cannot be
# trusted to report on it.
#
# Three ways this fails, all useful:
#   1. The fixture carries a field the current `DetectorExperimentManifest`
#      schema does not accept -- the generator's `deny_unknown_fields`
#      deserialization errors out and `set -e` propagates it.
#   2. The fixture's bytes differ from the canonical rendering of its parsed
#      value -- the `diff` below reports it.
#   3. The regenerated set and the committed set are not the same set.
#
# Fix 1 and 2 by running `bash tools/regen-kitten-fixtures.sh` and committing.
#
# This loop iterates the COMMITTED set. It used to iterate `"$SCRATCH"/*.yaml`
# -- the REGENERATED set -- which came from a hardcoded 3-element array in the
# generator, so detection covered three named files rather than the directory.
# A fourth fixture the parser rejects, dropped into `experiments/` and picked up
# by a `git add -A`, was invisible to the gate: exactly the failure FIXTURE-03
# exists to prevent, and exactly the shape of `a840fd8`, which checked in 137
# NEW files.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck source=tools/fixture-inventory.sh
source "$ROOT_DIR/tools/fixture-inventory.sh"

bash "$ROOT_DIR/tools/test-fixture-inventory.sh"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

# The same enumeration `tools/regen-kitten-fixtures.sh` performs. Recomputed
# here rather than inferred from the scratch directory so that a generator that
# silently skips a fixture is caught by the set comparison below instead of
# defining the set it is checked against.
if ! git -C "$ROOT_DIR" rev-parse --git-dir >/dev/null 2>&1; then
  echo "not a git checkout: cannot enumerate the committed fixture set" >&2
  exit 1
fi

INVENTORY="$SCRATCH/fixtures.nul"
fixture_inventory_write "$ROOT_DIR" "$INVENTORY"

# `mapfile` is bash 4+; macOS ships 3.2 and this gate has to run locally too.
committed=()
while IFS= read -r -d '' fixture; do
  fixture_require_direct_path "$fixture"
  committed+=("$fixture")
done <"$INVENTORY"

if [ "${#committed[@]}" -eq 0 ]; then
  echo "no experiments/*.yaml fixtures found; refusing to pass silently" >&2
  exit 1
fi

echo "checking ${#committed[@]} committed fixture(s):"
for relative in "${committed[@]}"; do
  echo "  $(fixture_display "$relative")"
done

# Runs the generator over the same set. A schema-rejecting fixture fails here.
bash "$ROOT_DIR/tools/regen-kitten-fixtures.sh" "$SCRATCH"

status=0
for relative in "${committed[@]}"; do
  name="${relative#experiments/}"
  regenerated="$SCRATCH/$name"
  if [ ! -f "$regenerated" ]; then
    echo "fixture not regenerated: $(fixture_display "$relative")" >&2
    status=1
    continue
  fi
  diff_output="$SCRATCH/diff-output"
  diff_error="$SCRATCH/diff-error"
  set +e
  diff -u \
    -L "expected $(fixture_display "$relative")" \
    -L "regenerated $(fixture_display "$relative")" \
    "$ROOT_DIR/$relative" "$regenerated" >"$diff_output" 2>"$diff_error"
  diff_status=$?
  set -e
  if [ "$diff_status" -eq 1 ]; then
    cat "$diff_output"
    echo "fixture out of date: $(fixture_display "$relative")" >&2
    status=1
  elif [ "$diff_status" -ne 0 ]; then
    echo "fixture comparison failed for $(fixture_display "$relative"): $(fixture_display_stream <"$diff_error")" >&2
    status=1
  fi
done

# The other direction: a regeneration with no committed counterpart means the
# two enumerations disagree, and the gate is no longer checking what ships.
for regenerated in "$SCRATCH"/*.yaml "$SCRATCH"/*.yml; do
  [ -e "$regenerated" ] || continue
  name="${regenerated##*/}"
  candidate="experiments/$name"
  found=0
  for relative in "${committed[@]}"; do
    if [ "$relative" = "$candidate" ]; then
      found=1
      break
    fi
  done
  if [ "$found" -eq 0 ]; then
    echo "regenerated fixture is not committed: $(fixture_display "$candidate")" >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo "run 'bash tools/regen-kitten-fixtures.sh' and commit the result" >&2
fi

exit "$status"
