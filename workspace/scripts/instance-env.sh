#!/usr/bin/env bash
# Computes the full multi-instance desktop dev environment.
# Source this file from desktop dev commands; it exports:
#   AMBUSH_VITE_PORT, AMBUSH_HMR_PORT, VITE_PORT, VITE_HMR_PORT
#   AMBUSH_RELAY_PORT, AMBUSH_RELAY_URL
#   AMBUSH_INSTANCE_SLUG, AMBUSH_WORKTREE_LABEL, VITE_DEV_BRANCH (worktrees only)
#   AMBUSH_TAURI_CONFIG
#   AMBUSH_PRIVATE_KEY (worktrees only, when AMBUSH_SHARE_IDENTITY=1)

WORKSPACE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORKTREE_ROOT=$(git -C "$WORKSPACE_ROOT" rev-parse --show-toplevel 2>/dev/null || printf '%s' "$WORKSPACE_ROOT")

# Derive a stable base port from the worktree root so the same worktree always
# gets the same ports. This keeps the Tauri dev config stable between runs and
# preserves Cargo's build cache.
BASE_PORT=$(python3 -c "import hashlib,sys; h=int(hashlib.sha256(sys.argv[1].encode()).hexdigest(), 16); print(10000 + h % 55000)" "$WORKTREE_ROOT")
export AMBUSH_VITE_PORT=$BASE_PORT
export AMBUSH_HMR_PORT=$((BASE_PORT + 1))
export AMBUSH_RELAY_PORT=3000
export VITE_PORT="$AMBUSH_VITE_PORT"
export VITE_HMR_PORT="$AMBUSH_HMR_PORT"
export AMBUSH_RELAY_URL="${AMBUSH_RELAY_URL:-ws://localhost:3000}"

DEV_URL="http://localhost:${AMBUSH_VITE_PORT}"
if [[ "${AMBUSH_RESET_WEBVIEW_STATE:-0}" == "1" ]]; then
    DEV_URL="${DEV_URL}?resetDevState=1"
fi

AMBUSH_TAURI_CONFIG="{\"build\":{\"devUrl\":\"${DEV_URL}\",\"beforeDevCommand\":\"exec ./node_modules/.bin/vite --port ${AMBUSH_VITE_PORT} --strictPort\"},\"identifier\":\"com.backbay.ambush.app.dev\",\"productName\":\"Ambush Dev\"}"
unset VITE_DEV_BRANCH

# In worktrees, derive the app identity from the worktree directory and use the
# branch only as a display label. The identity therefore survives branch
# switches and remains distinct for detached worktrees.
#
# Worktree detection: compare --git-dir to --git-common-dir. In the main
# working tree these are identical; in any worktree (whether under .worktrees/,
# .claude/worktrees/, or elsewhere on disk) they differ.
if git -C "$WORKSPACE_ROOT" rev-parse --is-inside-work-tree &>/dev/null; then
    GIT_DIR=$(git -C "$WORKSPACE_ROOT" rev-parse --git-dir)
    GIT_COMMON_DIR=$(git -C "$WORKSPACE_ROOT" rev-parse --git-common-dir 2>/dev/null)
    if [[ -n "$GIT_COMMON_DIR" && "$GIT_DIR" != "$GIT_COMMON_DIR" ]]; then
        WORKTREE_NAME=$(basename "$WORKTREE_ROOT")
        BRANCH_NAME=$(git -C "$WORKSPACE_ROOT" rev-parse --abbrev-ref HEAD)
        if [[ "$BRANCH_NAME" == "HEAD" ]]; then
            LABEL_RAW=$(git -C "$WORKSPACE_ROOT" rev-parse --short HEAD)
        else
            LABEL_RAW="${BRANCH_NAME##*/}"
        fi
        export AMBUSH_WORKTREE_LABEL=$(printf '%s' "$LABEL_RAW" | sed -e 's/[^A-Za-z0-9._-]/-/g' -e 's/--*/-/g' -e 's/^-//' -e 's/-$//')
        [[ -n "$AMBUSH_WORKTREE_LABEL" ]] || export AMBUSH_WORKTREE_LABEL="worktree"
        export AMBUSH_INSTANCE_SLUG=$(printf '%s' "$WORKTREE_NAME" | tr '[:upper:]' '[:lower:]' | sed -e 's/[^a-z0-9]/-/g' -e 's/--*/-/g' -e 's/^-//' -e 's/-$//')
        [[ -n "$AMBUSH_INSTANCE_SLUG" ]] || export AMBUSH_INSTANCE_SLUG="worktree"

        # AMBUSH_SHARE_IDENTITY=1: reuse the main dev checkout's Nostr key so
        # worktrees skip onboarding and share the same identity. The per-worktree
        # identifier is kept so concurrent instances don't collide on
        # tauri-plugin-single-instance or the app data directory.
        if [[ "${AMBUSH_SHARE_IDENTITY:-0}" == "1" ]]; then
            KEYRING_SERVICE="ambush-desktop-dev"
            KEYRING_BLOB=""
            case "$(uname -s)" in
                Darwin)
                    if command -v security &>/dev/null; then
                        KEYRING_BLOB="$(security find-generic-password -s "$KEYRING_SERVICE" -a secrets -w 2>/dev/null || true)"
                    fi
                    ;;
                Linux)
                    if command -v secret-tool &>/dev/null; then
                        KEYRING_BLOB="$(secret-tool lookup service "$KEYRING_SERVICE" username secrets target default 2>/dev/null || true)"
                    fi
                    ;;
            esac

            KEYRING_IDENTITY="$(printf '%s' "$KEYRING_BLOB" | python3 -c 'import json, sys; value = json.load(sys.stdin).get("identity", ""); print(value if isinstance(value, str) else "")' 2>/dev/null || true)"
            CANONICAL_KEY="$HOME/Library/Application Support/com.backbay.ambush.app.dev/identity.key"
            LEGACY_CANONICAL_KEY="$HOME/Library/Application Support/xyz.block.sprout.app.dev/identity.key"

            SHARED_IDENTITY="$KEYRING_IDENTITY"
            if [[ -z "$SHARED_IDENTITY" && -f "$CANONICAL_KEY" ]]; then
                SHARED_IDENTITY="$(cat "$CANONICAL_KEY")"
            elif [[ -z "$SHARED_IDENTITY" && -f "$LEGACY_CANONICAL_KEY" ]]; then
                SHARED_IDENTITY="$(cat "$LEGACY_CANONICAL_KEY")"
            fi

            if [[ -n "$SHARED_IDENTITY" ]]; then
                export AMBUSH_PRIVATE_KEY="$SHARED_IDENTITY"
            else
                echo "⚠ AMBUSH_SHARE_IDENTITY=1 but no identity found in keyring service $KEYRING_SERVICE, at $CANONICAL_KEY, or at $LEGACY_CANONICAL_KEY — run Ambush from repo root first" >&2
            fi
        fi

        ICON_DIR="$WORKSPACE_ROOT/desktop/src-tauri/target/dev-icons"
        mkdir -p "$ICON_DIR"
        DEV_ICON="$ICON_DIR/icon.icns"
        GENERATE_DEV_ICON="$WORKSPACE_ROOT/scripts/generate-dev-icon.swift"
        BASE_ICON="$WORKSPACE_ROOT/desktop/src-tauri/icons/icon.icns"

        echo "🌳 Worktree: ${AMBUSH_WORKTREE_LABEL}"
        export VITE_DEV_BRANCH="$AMBUSH_WORKTREE_LABEL"
        AMBUSH_TAURI_CONFIG="{\"build\":{\"devUrl\":\"${DEV_URL}\",\"beforeDevCommand\":\"exec ./node_modules/.bin/vite --port ${AMBUSH_VITE_PORT} --strictPort\"},\"identifier\":\"com.backbay.ambush.app.dev.${AMBUSH_INSTANCE_SLUG}\",\"productName\":\"Ambush Dev (${AMBUSH_WORKTREE_LABEL})\"}"
        if swift "$GENERATE_DEV_ICON" "$BASE_ICON" "$DEV_ICON" "$AMBUSH_WORKTREE_LABEL"; then
            AMBUSH_TAURI_CONFIG="{\"build\":{\"devUrl\":\"${DEV_URL}\",\"beforeDevCommand\":\"exec ./node_modules/.bin/vite --port ${AMBUSH_VITE_PORT} --strictPort\"},\"identifier\":\"com.backbay.ambush.app.dev.${AMBUSH_INSTANCE_SLUG}\",\"productName\":\"Ambush Dev (${AMBUSH_WORKTREE_LABEL})\",\"bundle\":{\"icon\":[\"$DEV_ICON\"]}}"
        fi
    fi
fi

export AMBUSH_TAURI_CONFIG
