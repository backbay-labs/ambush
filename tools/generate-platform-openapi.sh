#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="${1:-$ROOT_DIR/docs/openapi/v2-platform-openapi.json}"
# Same separate-but-under-target/ default as tools/check-platform-openapi.sh,
# for the same reason and with the same consequence if it is wrong. This is the
# script an operator runs BY HAND to regenerate the spec, so the un-gitignored
# `$ROOT_DIR/target-v172-openapi` default leaked here first and most often. See
# the comment block in check-platform-openapi.sh; keep the two in step.
CARGO_TARGET="${CARGO_TARGET_DIR:-$ROOT_DIR/target/openapi-check}"

CARGO_TARGET_DIR="$CARGO_TARGET" cargo run -p swarm-ingest-runtime --bin generate_platform_openapi -- --output "$SPEC_PATH"
