#!/usr/bin/env bash
set -euo pipefail

# Fail when a committed detector experiment fixture differs from a regeneration.
#
# Regenerates into a scratch directory and diffs; NEVER writes into the working
# tree, because a repository-hygiene gate that dirties the repository cannot be
# trusted to report on it.
#
# Two ways this fails, both useful:
#   1. The fixture carries a field the current `DetectorExperimentManifest`
#      schema does not accept -- the generator's `deny_unknown_fields`
#      deserialization errors out and `set -e` propagates it.
#   2. The fixture's bytes differ from the canonical rendering of its parsed
#      value -- the `diff` below reports it.
#
# Fix either by running `bash tools/regen-kitten-fixtures.sh` and committing.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

bash "$ROOT_DIR/tools/regen-kitten-fixtures.sh" "$SCRATCH"

status=0
for regenerated in "$SCRATCH"/*.yaml; do
  name="$(basename "$regenerated")"
  committed="$ROOT_DIR/experiments/$name"
  if ! diff -u "$committed" "$regenerated"; then
    echo "fixture out of date: experiments/$name" >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo "run 'bash tools/regen-kitten-fixtures.sh' and commit the result" >&2
fi

exit "$status"
