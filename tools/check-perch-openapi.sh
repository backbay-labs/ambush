#!/usr/bin/env bash
#
# DROP-IN FOR `AMBUSH tools/check-perch-openapi.sh`.
#
# Perch operator OpenAPI contract gate.
#
# Two independent assertions about docs/openapi/perch-operator-v1.json:
#   1. it is a valid OpenAPI 3.1 document
#   2. it is byte-identical to what generate_perch_openapi emits today
#
# This is tools/check-platform-openapi.sh with four strings changed. Everything
# below that is not a path or a binary name is deliberately verbatim, including
# the comments, because the two gates fail the same way and a reader who has read
# one has read both. Keep all four scripts in step.
#
# The two assertions are aggregated rather than chained: an invalid spec must not
# hide drift, and drift must not hide invalidity. Validating the COMMITTED file
# rather than the freshly generated one is deliberate for the same reason -- the
# committed file is the artifact that ships, and validating it is reachable even
# on a run where the drift half fails. When both halves pass they are the same
# bytes, so the generator's output is covered transitively.
#
# WHY JSON AND NOT THE AUTHORING YAML
#   The reviewable form of this contract is
#   docs/plans/ambush-ui/build/openapi/perch-operator-v1.yaml, which carries 28
#   comment lines and 126 block scalars. NO SERIALIZER EMITS COMMENTS AND
#   serde_yaml 0.9 EMITS NO BLOCK SCALARS, so a readable YAML file can
#   never satisfy assertion 2, and assertion 2 is the only half that catches
#   drift. serde_yaml 0.9 (Cargo.toml:76) additionally has no block-scalar control
#   and is a DEV-dependency of swarm-runtime-http
#   (crates/swarm-runtime-http/Cargo.toml:55), while serde_json is already a
#   normal one (:23). So the gated artifact is JSON emitted by
#   serde_json::to_string_pretty, exactly as generate_platform_openapi does
#   (crates/swarm-ingest-runtime/src/bin/generate_platform_openapi.rs:33,:48), and
#   the YAML is kept in step by hand with
#   docs/plans/ambush-ui/build/openapi/render-perch-openapi.py --check.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC_PATH="$ROOT_DIR/docs/openapi/perch-operator-v1.json"

# The validator is PINNED. `uvx --from openapi-spec-validator` resolves the
# newest PyPI release on every run, so an upstream release could turn this gate
# red on a day nobody touched the repo. Bumping this is a reviewed change, and
# the new version has to be shown rejecting a corrupted spec before it lands.
# Kept equal to tools/check-platform-openapi.sh:28 on purpose: two pinned
# validators that can drift apart is two problems.
VALIDATOR_VERSION="0.9.0"

# `mktemp -d` with the X's at the END of the template, on purpose. A template
# like `swarm-perch-openapi.XXXXXX.json` works on GNU coreutils and silently does
# not on BSD/macOS, which creates the LITERAL path and exits 0 -- a fixed shared
# path two concurrent runs collide on. A directory keeps the `.json` name on the
# file the generator writes. See tools/check-platform-openapi.sh:30-41.
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-perch-openapi.XXXXXX")"
TMP_PATH="$TMP_DIR/perch-operator-v1.json"
trap 'rm -rf "$TMP_DIR"' EXIT

# A SEPARATE target dir on purpose: the generator must not contend for the main
# target-dir lock with a cargo the operator already has running. It lives UNDER
# target/ because the clean-tree contract in .github/workflows/ci.yml whitelists
# target/ and only target/. See tools/check-platform-openapi.sh:43-58.
CARGO_TARGET="${CARGO_TARGET_DIR:-$ROOT_DIR/target/openapi-check}"

if [ ! -f "$SPEC_PATH" ]; then
  echo "::error::missing committed spec $SPEC_PATH; refusing to pass silently" >&2
  exit 1
fi

if ! command -v uvx >/dev/null 2>&1; then
  # Reported separately from a validation failure so an absent toolchain is never
  # mistaken for an invalid spec.
  echo "::error::uvx not found on PATH; this gate needs uv to run openapi-spec-validator" >&2
  exit 1
fi

CARGO_TARGET_DIR="$CARGO_TARGET" cargo run -p swarm-runtime-http \
  --bin generate_perch_openapi -- --output "$TMP_PATH" >/dev/null

# State the invariant rather than relying on diff to notice. A generator that
# exits 0 having written nothing would otherwise surface as a 100 KB unified diff
# against an empty file, which reads like spec drift and is not.
if [ ! -s "$TMP_PATH" ]; then
  echo "::error::generate_perch_openapi exited 0 but wrote no output to $TMP_PATH" >&2
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
# `diff -u`, not `cmp -s`. cmp -s prints NOTHING on failure, so a gate built on it
# can only ever exit 1 with no diagnostic at all -- a red gate that does not say
# what broke is a gate people learn to re-run rather than read.
if diff -u --label "docs/openapi/perch-operator-v1.json (committed)" \
    --label "generate_perch_openapi (current)" "$SPEC_PATH" "$TMP_PATH"; then
  echo "current"
else
  echo "::error::committed Perch OpenAPI is stale; run 'bash tools/generate-perch-openapi.sh' and commit the result" >&2
  status=1
fi

if [ "$status" -ne 0 ]; then
  exit "$status"
fi

echo "Perch operator OpenAPI is current and valid"
