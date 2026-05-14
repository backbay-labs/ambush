#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="$ROOT_DIR/docs/openapi/v2-platform-openapi.json"
CONFIG_PATH="$ROOT_DIR/clients/python/openapi-python-client-config.yml"
OUTPUT_PATH="$ROOT_DIR/clients/python/swarm-platform-client"

"$ROOT_DIR/tools/generate-platform-openapi.sh" "$SPEC_PATH" >/dev/null

uvx --from openapi-python-client openapi-python-client generate \
  --path "$SPEC_PATH" \
  --config "$CONFIG_PATH" \
  --output-path "$OUTPUT_PATH" \
  --overwrite

rm -rf "$OUTPUT_PATH/.ruff_cache"
