#!/usr/bin/env bash
#
# Platform OpenAPI contract gate.
#
# Two independent assertions about docs/openapi/v2-platform-openapi.json:
#   1. it is a valid OpenAPI 3.1 document
#   2. it is byte-identical to what generate_platform_openapi emits today
#
# Nothing else in the repository checks either one, and clients/python/ is
# GENERATED FROM THIS FILE -- a stale spec ships a wrong client with a green
# suite. That is why this gate is worth a CI job of its own.
#
# The two assertions are aggregated rather than chained: an invalid spec must not
# hide drift, and drift must not hide invalidity. Validating the COMMITTED file
# rather than the freshly generated one is deliberate for the same reason -- the
# committed file is the artifact that ships, and validating it is reachable even
# on a run where the drift half fails. When both halves pass they are the same
# bytes, so the generator's output is covered transitively.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="$ROOT_DIR/docs/openapi/v2-platform-openapi.json"

# The validator is PINNED. `uvx --from openapi-spec-validator` resolves the
# newest PyPI release on every run, so an upstream release could turn this gate
# red on a day nobody touched the repo. Bumping this is a reviewed change, and
# the new version has to be shown rejecting a corrupted spec before it lands.
VALIDATOR_VERSION="0.9.0"

# `mktemp -d` with the X's at the END of the template, on purpose. The previous
# template was `swarm-platform-openapi.XXXXXX.json`: GNU coreutils handles X's
# followed by a suffix, but BSD/macOS mktemp does not substitute them -- it
# creates the LITERAL path `.../swarm-platform-openapi.XXXXXX.json` and exits 0.
# That is a fixed shared path, so two concurrent runs collide, and the second
# run of the day died on it:
#
#   $ bash tools/check-platform-openapi.sh
#   mktemp: mkstemp failed on /var/folders/.../T//swarm-platform-openapi.XXXXXX.json: File exists
#
# A directory keeps the `.json` name on the file the generator writes.
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-platform-openapi.XXXXXX")"
TMP_PATH="$TMP_DIR/v2-platform-openapi.json"
trap 'rm -rf "$TMP_DIR"' EXIT

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

if [ ! -f "$SPEC_PATH" ]; then
  echo "::error::missing committed spec $SPEC_PATH; refusing to pass silently" >&2
  exit 1
fi

if ! command -v uvx >/dev/null 2>&1; then
  # Reported separately from a validation failure so an absent toolchain is never
  # mistaken for an invalid spec. The `test` job installs uv for the generated
  # python client smoke test for the same reason (ci.yml:214-222).
  echo "::error::uvx not found on PATH; this gate needs uv to run openapi-spec-validator" >&2
  exit 1
fi

CARGO_TARGET_DIR="$CARGO_TARGET" cargo run -p swarm-ingest-runtime \
  --bin generate_platform_openapi -- --output "$TMP_PATH" >/dev/null

# State the invariant rather than relying on diff to notice. A generator that
# exits 0 having written nothing would otherwise surface as a 40 KB unified diff
# against an empty file, which reads like spec drift and is not.
if [ ! -s "$TMP_PATH" ]; then
  echo "::error::generate_platform_openapi exited 0 but wrote no output to $TMP_PATH" >&2
  exit 1
fi

status=0

echo "== committed spec is a valid OpenAPI 3.1 document =="
if uvx --from "openapi-spec-validator==$VALIDATOR_VERSION" \
    openapi-spec-validator "$SPEC_PATH"; then
  echo "valid (openapi-spec-validator $VALIDATOR_VERSION)"
else
  echo "::error::$SPEC_PATH failed OpenAPI 3.1 validation" >&2
  status=1
fi

echo "== committed spec matches the generator =="
# `diff -u`, not `cmp -s`. cmp -s prints NOTHING on failure, so the previous
# version of this gate could only ever exit 1 with no diagnostic at all -- a red
# gate that does not say what broke is a gate people learn to re-run rather than
# read.
if diff -u --label "docs/openapi/v2-platform-openapi.json (committed)" \
    --label "generate_platform_openapi (current)" "$SPEC_PATH" "$TMP_PATH"; then
  echo "current"
else
  echo "::error::committed platform OpenAPI is stale; run 'bash tools/generate-platform-openapi.sh' and commit the result" >&2
  status=1
fi

if [ "$status" -ne 0 ]; then
  exit "$status"
fi

echo "platform OpenAPI is current and valid"
