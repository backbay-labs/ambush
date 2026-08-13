#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-release-hardening.XXXXXX")"
trap 'rm -rf "$TARGET_DIR"' EXIT

BUILD_LOG="$TARGET_DIR/release-build.log"
CARGO_TARGET_DIR="$TARGET_DIR" cargo build -v -p swarm-runtime-http --release --bin swarm_detect --bin swarmctl >"$BUILD_LOG" 2>&1

verify_bin() {
    local bin="$1"
    local line

    line="$(grep -F -- "--crate-name $bin " "$BUILD_LOG" | tail -n 1 || true)"
    if [[ -z "$line" ]]; then
        echo "missing rustc invocation for $bin in release build log" >&2
        return 1
    fi

    if [[ "$line" != *"-C panic=abort"* ]]; then
        echo "expected -C panic=abort for $bin release build" >&2
        return 1
    fi

    if [[ "$line" != *"-C overflow-checks=on"* ]]; then
        echo "expected -C overflow-checks=on for $bin release build" >&2
        return 1
    fi

    echo "verified $bin"
}

verify_bin "swarm_detect"
verify_bin "swarmctl"
