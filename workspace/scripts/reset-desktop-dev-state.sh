#!/usr/bin/env bash
# Remove desktop state owned by development bundle identifiers only.
# Production state (`com.backbay.ambush.app`, `~/.ambush`, and `ambush-desktop`) is
# deliberately outside every deletion pattern in this script.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log() { printf '[desktop-dev-reset] %s\n' "$*"; }

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | \
    sed -e 's/[^a-z0-9]/-/g' -e 's/--*/-/g' -e 's/^-//' -e 's/-$//'
}

# SecretStore uses the base development service for normal debug launches and
# a directory-scoped service for standalone worktrees. Older worktree builds
# used a branch-derived suffix, so a full reset clears both inventories.
DEV_KEYRING_SERVICES=(ambush-desktop-dev sprout-desktop-dev ambush-desktop-dev.main)
add_dev_keyring_service() {
  local service="$1" existing
  [[ -n "$service" ]] || return 0
  for existing in "${DEV_KEYRING_SERVICES[@]}"; do
    [[ "$existing" == "$service" ]] && return 0
  done
  DEV_KEYRING_SERVICES+=("$service")
}

if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  while IFS= read -r -d '' field; do
    case "$field" in
      "worktree "*)
        worktree_slug=$(slugify "$(basename "${field#worktree }")")
        add_dev_keyring_service "ambush-desktop-dev.${worktree_slug}"
        ;;
      "branch refs/heads/"*)
        legacy_branch_slug=$(slugify "${field#branch refs/heads/}")
        add_dev_keyring_service "ambush-desktop-dev.${legacy_branch_slug}"
        ;;
    esac
  done < <(git -C "$REPO_ROOT" worktree list --porcelain -z)
fi

remove_path() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    log "Removing $path"
    rm -rf -- "$path"
  fi
}

remove_bundle_state() {
  local base="$1"
  local suffix="${2:-}"
  local prefix path

  [[ -d "$base" ]] || return 0
  shopt -s nullglob
  for prefix in com.backbay.ambush.app.dev xyz.block.sprout.app.dev; do
    # Match the canonical dev identifier and dot-delimited worktree variants.
    # Do not use `${prefix}*`: that could match a non-dev prefix collision.
    remove_path "$base/${prefix}${suffix}"
    for path in "$base/${prefix}."*"${suffix}"; do
      remove_path "$path"
    done
  done
  shopt -u nullglob
}

case "${AMBUSH_TEST_PLATFORM:-$(uname -s)}" in
  Darwin)
    remove_bundle_state "$HOME/Library/Application Support"
    remove_bundle_state "$HOME/Library/Caches"
    remove_bundle_state "$HOME/Library/WebKit"
    remove_bundle_state "$HOME/Library/HTTPStorages"
    remove_bundle_state "$HOME/Library/Saved Application State" ".savedState"
    remove_bundle_state "$HOME/Library/Preferences" ".plist"

    # Delete every matching item in case an older build used multiple accounts.
    if command -v security >/dev/null 2>&1; then
      for service in "${DEV_KEYRING_SERVICES[@]}"; do
        while security delete-generic-password -s "$service" >/dev/null 2>&1; do :; done
      done
    fi
    ;;
  Linux)
    remove_bundle_state "${XDG_DATA_HOME:-$HOME/.local/share}"
    remove_bundle_state "${XDG_CONFIG_HOME:-$HOME/.config}"
    remove_bundle_state "${XDG_CACHE_HOME:-$HOME/.cache}"
    if command -v secret-tool >/dev/null 2>&1; then
      for service in "${DEV_KEYRING_SERVICES[@]}"; do
        secret-tool clear service "$service" username secrets target default >/dev/null 2>&1 || true
      done
    fi
    ;;
  *)
    log "Desktop bundle cleanup is not implemented for $(uname -s); continuing"
    ;;
esac

remove_path "$HOME/.ambush-dev"
remove_path "$HOME/.sprout-dev"

# A fresh dev nest must not re-import the installed app's ~/.ambush contents on
# its next boot. The sentinel is the same one used by migrate_dev_nest().
mkdir -p "$HOME/.ambush-dev"
: > "$HOME/.ambush-dev/.dev-nest-migrated"

log "Development desktop state removed; production Ambush state was not touched"
