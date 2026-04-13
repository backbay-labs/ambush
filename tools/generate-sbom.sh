#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/artifacts/sbom}"

mkdir -p "$OUTPUT_DIR"
find "$OUTPUT_DIR" -maxdepth 1 -name '*.cdx.json' -delete

pushd "$ROOT_DIR" >/dev/null
find "$ROOT_DIR/crates" -mindepth 2 -maxdepth 2 \
  \( -name '*.cdx.json' -o -name 'swarm-team-six.json' \) -delete
cargo cyclonedx --manifest-path Cargo.toml --format json --spec-version 1.5 --quiet

count=0
while IFS= read -r -d '' sbom; do
  cp "$sbom" "$OUTPUT_DIR/$(basename "$sbom")"
  rm -f "$sbom"
  count=$((count + 1))
done < <(find "$ROOT_DIR/crates" -mindepth 2 -maxdepth 2 -name '*.cdx.json' -print0 | sort -z)
find "$ROOT_DIR/crates" -mindepth 2 -maxdepth 2 -name 'swarm-team-six.json' -delete
popd >/dev/null

if [[ "$count" -eq 0 ]]; then
  echo "no SBOM files were generated" >&2
  exit 1
fi

echo "generated $count SBOM files in $OUTPUT_DIR"
