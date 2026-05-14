#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="$ROOT_DIR/docs/openapi/v2-platform-openapi.json"
TMP_PATH="$(mktemp "${TMPDIR:-/tmp}/swarm-platform-openapi.XXXXXX.json")"
CARGO_TARGET="${CARGO_TARGET_DIR:-$ROOT_DIR/target-v172-openapi}"
trap 'rm -f "$TMP_PATH"' EXIT

CARGO_TARGET_DIR="$CARGO_TARGET" cargo run -p swarm-runtime --bin generate_platform_openapi -- --output "$TMP_PATH" >/dev/null
cmp -s "$SPEC_PATH" "$TMP_PATH"

uvx --from openapi-spec-validator openapi-spec-validator "$SPEC_PATH" >/dev/null

echo "platform OpenAPI is current and valid"
