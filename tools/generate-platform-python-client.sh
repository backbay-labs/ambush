#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="$ROOT_DIR/docs/openapi/v2-platform-openapi.json"
CONFIG_PATH="$ROOT_DIR/clients/python/openapi-python-client-config.yml"
OUTPUT_PATH="$ROOT_DIR/clients/python/swarm-platform-client"
PACKAGE_DIR="$OUTPUT_PATH/swarm_platform_client"

"$ROOT_DIR/tools/generate-platform-openapi.sh" "$SPEC_PATH" >/dev/null

# Preserve hand-maintained `helpers.py` (combined-auth wrapper + SSE streamer)
# across regeneration — the generator's --overwrite wipes the package dir.
HELPERS_BACKUP="$(mktemp)"
if [[ -f "$PACKAGE_DIR/helpers.py" ]]; then
  cp "$PACKAGE_DIR/helpers.py" "$HELPERS_BACKUP"
fi

uvx --from openapi-python-client openapi-python-client generate \
  --path "$SPEC_PATH" \
  --config "$CONFIG_PATH" \
  --output-path "$OUTPUT_PATH" \
  --overwrite

if [[ -s "$HELPERS_BACKUP" ]]; then
  mkdir -p "$PACKAGE_DIR"
  mv "$HELPERS_BACKUP" "$PACKAGE_DIR/helpers.py"
  # Re-export the helpers from the generated `__init__.py`.
  python3 - <<'PY'
import pathlib
init_path = pathlib.Path("clients/python/swarm-platform-client/swarm_platform_client/__init__.py")
text = init_path.read_text()
if "from .helpers import" not in text:
    text = text.replace(
        "from .client import AuthenticatedClient, Client",
        "from .client import AuthenticatedClient, Client\nfrom .helpers import iter_findings_sse, make_platform_client",
    )
    text = text.replace(
        "__all__ = (\n    \"AuthenticatedClient\",\n    \"Client\",\n)",
        "__all__ = (\n    \"AuthenticatedClient\",\n    \"Client\",\n    \"iter_findings_sse\",\n    \"make_platform_client\",\n)",
    )
    init_path.write_text(text)
PY
else
  rm -f "$HELPERS_BACKUP"
fi

rm -rf "$OUTPUT_PATH/.ruff_cache"
