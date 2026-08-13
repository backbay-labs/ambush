#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="${1:-$ROOT_DIR/docs/openapi/v2-platform-openapi.json}"
CARGO_TARGET="${CARGO_TARGET_DIR:-$ROOT_DIR/target-v172-openapi}"

CARGO_TARGET_DIR="$CARGO_TARGET" cargo run -p swarm-ingest-runtime --bin generate_platform_openapi -- --output "$SPEC_PATH"
