#!/usr/bin/env bash
#
# DROP-IN FOR `AMBUSH tools/generate-perch-openapi.sh`. Adapted from
# tools/generate-platform-openapi.sh, which it must stay in step with.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="${1:-$ROOT_DIR/docs/openapi/perch-operator-v1.json}"
# Same separate-but-under-target/ default as tools/check-perch-openapi.sh, for the
# same reason and with the same consequence if it is wrong. This is the script an
# operator runs BY HAND to regenerate the spec, so an un-gitignored default leaks
# here first and most often. See the comment block in
# tools/check-platform-openapi.sh; keep all four scripts in step.
CARGO_TARGET="${CARGO_TARGET_DIR:-$ROOT_DIR/target/openapi-check}"

CARGO_TARGET_DIR="$CARGO_TARGET" cargo run -p swarm-runtime-http \
  --bin generate_perch_openapi -- --output "$SPEC_PATH"
