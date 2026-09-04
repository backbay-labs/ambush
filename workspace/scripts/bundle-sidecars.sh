#!/usr/bin/env bash
set -euo pipefail

SIDECARS=(ambush-acp ambush-agent ambush-dev-mcp git-credential-nostr ambush)
HOST=$(rustc -vV | sed -n 's|host: ||p')
TARGET=${1:-$HOST}
if [[ "$TARGET" != *windows* ]]; then
    SIDECARS+=(ambush-backend-kubernetes)
    BUILD_HINT="cargo build --release -p ambush-acp -p ambush-agent -p ambush-backend-kubernetes -p ambush-dev-mcp -p git-credential-nostr -p ambush-cli"
else
    BUILD_HINT="cargo build --release -p ambush-acp -p ambush-agent -p ambush-dev-mcp -p git-credential-nostr -p ambush-cli"
fi
# The laptop demo's detector, opt-in.
#
# It is NOT in the default set for two reasons. It comes from the ENGINE
# workspace at the repository root, which builds on a different Rust toolchain
# and edition than everything above -- so it cannot be added to BUILD_HINT and
# must already exist when this runs. And most builds do not want a detector
# bundled at all; a security daemon shipped inside a chat app that nobody asked
# for is a surprise, not a feature.
#
#   cargo build --release -p swarm-runtime-http --bin swarm_detect   # repo root
#   PERCH_SIDECAR=1 bash scripts/bundle-sidecars.sh
if [[ "${PERCH_SIDECAR:-0}" == "1" ]]; then
    SIDECARS+=(swarm_detect)
    PERCH_SRC_DIR="../target/release"
fi

BINARIES_DIR="desktop/src-tauri/binaries"

# When --target is passed explicitly to cargo (even if it matches the host),
# binaries land in target/<triple>/release/. Without --target, they land in
# target/release/. The script receives the target as $1 only when cargo was
# invoked with --target, so use the qualified path whenever $1 is set.
if [[ -n "${1:-}" ]]; then
    SRC_DIR="target/${TARGET}/release"
else
    SRC_DIR="target/release"
fi

# MSVC emits <name>.exe; Tauri's externalBin then expects binaries/<name>-<triple>.exe.
if [[ "$TARGET" == *windows* ]]; then
    EXE=".exe"
else
    EXE=""
fi

# swarm_detect is built by the engine workspace at the repository root, so it
# lands in a different target directory than every other sidecar here.
src_dir_for() {
    if [[ "$1" == "swarm_detect" ]]; then
        echo "${PERCH_SRC_DIR:-$SRC_DIR}"
    else
        echo "$SRC_DIR"
    fi
}

missing=()
for bin in "${SIDECARS[@]}"; do
    [[ -f "$(src_dir_for "$bin")/${bin}${EXE}" ]] || missing+=("${bin}${EXE}")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Error: missing release binaries in $SRC_DIR: ${missing[*]}" >&2
    echo "Run '$BUILD_HINT' first." >&2
    if [[ " ${missing[*]} " == *" swarm_detect"* ]]; then
        echo "swarm_detect comes from the engine workspace at the repository root:" >&2
        echo "  cargo build --release -p swarm-runtime-http --bin swarm_detect" >&2
    fi
    exit 1
fi

mkdir -p "$BINARIES_DIR"
for bin in "${SIDECARS[@]}"; do
    destination="$BINARIES_DIR/${bin}-${TARGET}${EXE}"
    cp "$(src_dir_for "$bin")/${bin}${EXE}" "$destination"

    # cp preserves the mode of an existing destination on macOS. Generated
    # sidecar placeholders may not be executable, so make the bundled Unix
    # binaries executable explicitly.
    if [[ -z "$EXE" ]]; then
        chmod 755 "$destination"
    fi
done
echo "Sidecars bundled for $TARGET"
