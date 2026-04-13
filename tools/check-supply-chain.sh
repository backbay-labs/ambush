#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pushd "$ROOT_DIR" >/dev/null
cargo deny check advisories licenses sources
cargo deny check bans -A duplicate
cargo audit \
  --deny warnings \
  --ignore RUSTSEC-2024-0384 \
  --ignore RUSTSEC-2025-0134 \
  --ignore RUSTSEC-2026-0097
popd >/dev/null
