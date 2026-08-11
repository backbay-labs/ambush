#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

pushd "$ROOT_DIR" >/dev/null
cargo deny check advisories licenses sources
cargo deny check bans -A duplicate
# Keep this list identical to `[advisories] ignore` in deny.toml, with the same
# reasons. `cargo deny` honours features and targets; `cargo audit` reads the whole
# lockfile, so the two see different graphs and BOTH must run -- but they must not
# disagree about which advisories are accepted.
cargo audit \
  --deny warnings \
  --ignore RUSTSEC-2024-0384 \
  --ignore RUSTSEC-2025-0134
popd >/dev/null
