#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET_FILE="${1:-crates/swarm-core/src/config/policy.rs}"
LOG_PATH="${2:-target/config-rebuild-scope.log}"

if [[ ! -f "$TARGET_FILE" ]]; then
  echo "target file not found: $TARGET_FILE" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to measure rebuild scope" >&2
  exit 1
fi

mkdir -p "$(dirname "$LOG_PATH")"

timestamp_file="$(mktemp)"
workspace_file="$(mktemp)"
dependents_file="$(mktemp)"
rebuilt_file="$(mktemp)"
unaffected_file="$(mktemp)"
trap 'rm -f "$timestamp_file" "$workspace_file" "$dependents_file" "$rebuilt_file" "$unaffected_file"' EXIT

touch -r "$TARGET_FILE" "$timestamp_file"

echo "==> warming workspace"
CARGO_TERM_COLOR=never cargo check --workspace --message-format short -j1 >/dev/null

echo "==> touching $TARGET_FILE"
touch "$TARGET_FILE"

echo "==> measuring rebuilt crates"
CARGO_TERM_COLOR=never cargo check --workspace --message-format short -j1 2>&1 | tee "$LOG_PATH" >/dev/null

touch -r "$timestamp_file" "$TARGET_FILE"

cargo metadata --format-version 1 --no-deps \
  | jq -r '[.packages[] | select(.source == null) | .name] | unique | sort | .[]' \
  > "$workspace_file"

cargo tree --workspace --invert swarm-core --prefix none \
  | sed -E 's/ v[0-9].*$//' \
  | rg '^swarm-' \
  | sort -u \
  > "$dependents_file"

rg -o '^\\s*(Checking|Compiling) ([^ ]+)' "$LOG_PATH" -r '$2' \
  | rg '^swarm-' \
  | sort -u \
  > "$rebuilt_file"

grep -Fvx -f "$rebuilt_file" "$workspace_file" > "$unaffected_file" || true

echo
echo "Workspace crates: $(wc -l < "$workspace_file" | tr -d ' ')"
echo "Rebuilt crates after touching $TARGET_FILE: $(wc -l < "$rebuilt_file" | tr -d ' ')"
echo "Expected swarm-core dependent crates: $(wc -l < "$dependents_file" | tr -d ' ')"
echo
echo "Rebuilt crates:"
sed 's/^/- /' "$rebuilt_file"
echo
echo "Unaffected workspace crates:"
sed 's/^/- /' "$unaffected_file"

if ! diff -u "$dependents_file" "$rebuilt_file" >/dev/null; then
  echo
  echo "rebuild set diverged from the swarm-core dependent set" >&2
  diff -u "$dependents_file" "$rebuilt_file" >&2 || true
  exit 1
fi

echo
echo "rebuild scope matches the swarm-core dependent set"
