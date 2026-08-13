#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="$ROOT_DIR/docs/openapi/v2-platform-openapi.json"
TMP_PATH="$(mktemp "${TMPDIR:-/tmp}/swarm-platform-openapi.XXXXXX.json")"
# A SEPARATE target dir on purpose (phase 256): the generator must not contend
# for the main target-dir lock with a cargo the operator already has running.
# It lives UNDER target/ rather than beside it because the previous default,
# `$ROOT_DIR/target-v172-openapi`, is matched by no .gitignore rule -- one local
# run left 2.3 GB across 7,171 untracked paths, and the clean-tree contract in
# .github/workflows/ci.yml:278-348 (`grep -v '^!! target/'` at :316,
# `-not -path './target/*'` at :337) whitelists `target/` and only `target/`.
# Redirecting needs no new ignore rule; gitignoring the old name would have
# needed three coordinated edits, and .gitignore:27-42 is a written warning
# about what adding an ignore rule does to a gate. CI is unaffected either way:
# .github/workflows/ci.yml:13 sets CARGO_TARGET_DIR at workflow scope, so this
# default only ever fires for a local operator -- which is exactly who the
# clean-tree contract then failed for.
CARGO_TARGET="${CARGO_TARGET_DIR:-$ROOT_DIR/target/openapi-check}"
trap 'rm -f "$TMP_PATH"' EXIT

CARGO_TARGET_DIR="$CARGO_TARGET" cargo run -p swarm-ingest-runtime --bin generate_platform_openapi -- --output "$TMP_PATH" >/dev/null
cmp -s "$SPEC_PATH" "$TMP_PATH"

uvx --from openapi-spec-validator openapi-spec-validator "$SPEC_PATH" >/dev/null

echo "platform OpenAPI is current and valid"
