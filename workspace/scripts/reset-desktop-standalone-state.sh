#!/usr/bin/env bash
# Reset only one standalone desktop development instance.
set -euo pipefail

instance_id="${1:-}"
keyring_service="${2:-}"

valid_scope() {
    [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,126}[a-z0-9])?$ ]]
}

if [[ "$instance_id" == "com.backbay.ambush.app.dev" ]]; then
    instance_scope=""
elif [[ "$instance_id" == com.backbay.ambush.app.dev.* ]] && valid_scope "${instance_id#com.backbay.ambush.app.dev.}"; then
    instance_scope="${instance_id#com.backbay.ambush.app.dev.}"
else
    echo "reset-desktop-standalone-state: refusing non-dev bundle identifier: $instance_id" >&2
    exit 1
fi
if [[ "$keyring_service" == "ambush-desktop-dev" ]]; then
    keyring_scope=""
elif [[ "$keyring_service" == ambush-desktop-dev.* ]] && valid_scope "${keyring_service#ambush-desktop-dev.}"; then
    keyring_scope="${keyring_service#ambush-desktop-dev.}"
else
    echo "reset-desktop-standalone-state: refusing non-dev keyring service: $keyring_service" >&2
    exit 1
fi
[[ "$instance_scope" == "$keyring_scope" ]] || {
    echo "reset-desktop-standalone-state: bundle and keyring scopes differ" >&2
    exit 1
}

add_unique() {
    local array_name="$1" value="$2" existing
    eval "existing=(\"\${${array_name}[@]}\")"
    for existing in "${existing[@]}"; do
        [[ "$existing" == "$value" ]] && return 0
    done
    eval "$array_name+=(\"\$value\")"
}

bundle_ids=("$instance_id")
services=("$keyring_service")
if [[ -z "$instance_scope" ]]; then
    bundle_ids+=(xyz.block.buzz.app.dev xyz.block.sprout.app.dev)
    services+=(buzz-desktop-dev sprout-desktop-dev)
else
    for env_name in AMBUSH_WORKTREE_PATH_SLUG AMBUSH_LEGACY_BRANCH_SLUG; do
        scope="${!env_name:-}"
        if [[ -n "$scope" ]] && ! valid_scope "$scope"; then
            echo "reset-desktop-standalone-state: invalid $env_name scope" >&2
            exit 1
        fi
    done
    if [[ -n "${AMBUSH_WORKTREE_PATH_SLUG:-}" ]]; then
        add_unique bundle_ids "com.backbay.ambush.app.dev.$AMBUSH_WORKTREE_PATH_SLUG"
        add_unique services "ambush-desktop-dev.$AMBUSH_WORKTREE_PATH_SLUG"
    fi
    for scope in "${AMBUSH_LEGACY_BRANCH_SLUG:-}" "$instance_scope" head; do
        [[ -n "$scope" ]] || continue
        for prefix in xyz.block.buzz.app.dev xyz.block.sprout.app.dev; do
            add_unique bundle_ids "$prefix.$scope"
        done
        for prefix in buzz-desktop-dev sprout-desktop-dev; do
            add_unique services "$prefix.$scope"
        done
    done
    add_unique bundle_ids com.backbay.ambush.app.dev.head
    add_unique services ambush-desktop-dev.head
fi

remove_path() {
    local path="$1"
    if [[ -e "$path" || -L "$path" ]]; then
        echo "Removing $path"
        rm -rf -- "$path"
    fi
}

case "${AMBUSH_TEST_PLATFORM:-$(uname -s)}" in
    Darwin)
        for bundle_id in "${bundle_ids[@]}"; do
            remove_path "$HOME/Library/Application Support/$bundle_id"
            remove_path "$HOME/Library/Caches/$bundle_id"
            remove_path "$HOME/Library/WebKit/$bundle_id"
            remove_path "$HOME/Library/HTTPStorages/$bundle_id"
            remove_path "$HOME/Library/Saved Application State/$bundle_id.savedState"
            remove_path "$HOME/Library/Preferences/$bundle_id.plist"
        done
        if command -v security >/dev/null 2>&1; then
            for service in "${services[@]}"; do
                while security delete-generic-password -s "$service" >/dev/null 2>&1; do :; done
            done
        fi
        ;;
    Linux)
        for bundle_id in "${bundle_ids[@]}"; do
            remove_path "${XDG_DATA_HOME:-$HOME/.local/share}/$bundle_id"
            remove_path "${XDG_CONFIG_HOME:-$HOME/.config}/$bundle_id"
            remove_path "${XDG_CACHE_HOME:-$HOME/.cache}/$bundle_id"
        done
        if command -v secret-tool >/dev/null 2>&1; then
            for service in "${services[@]}"; do
                secret-tool clear service "$service" username secrets target default >/dev/null 2>&1 || true
            done
        fi
        ;;
    *)
        echo "reset-desktop-standalone-state: unsupported platform" >&2
        exit 1
        ;;
esac

echo "Standalone state removed for $instance_id; relay and database data were not touched"
