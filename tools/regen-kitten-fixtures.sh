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

pushd "$ROOT_DIR" >/dev/null
cargo run --quiet -p swarm-runtime --example regen_experiment_fixtures -- "$OUT_DIR"
popd >/dev/null
