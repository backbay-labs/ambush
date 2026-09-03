#!/usr/bin/env bash
set -euo pipefail

source_script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/reset-desktop-dev-state.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

main="$tmp/Main_Checkout"
mkdir -p "$main"
git -C "$main" init -q -b main
git -C "$main" -c user.name=fixture -c user.email=fixture@invalid commit -q --allow-empty -m init

worktree="$tmp/Scoped_Worktree"
git -C "$main" worktree add -q -b feature/reset "$worktree"
git -C "$main" branch legacy/inactive
empty_slug_worktree="$tmp/___"
git -C "$main" worktree add -q -b empty/slug "$empty_slug_worktree"
worktree_hash=$(python3 -c 'import hashlib, os, sys; print(hashlib.sha256(os.path.realpath(sys.argv[1]).encode()).hexdigest()[:8])' "$worktree")
empty_slug_hash=$(python3 -c 'import hashlib, os, sys; print(hashlib.sha256(os.path.realpath(sys.argv[1]).encode()).hexdigest()[:8])' "$empty_slug_worktree")
workspace="$worktree/workspace"
mkdir -p "$workspace/scripts"
cp "$source_script" "$workspace/scripts/reset-desktop-dev-state.sh"

export HOME="$tmp/home"
export XDG_DATA_HOME="$tmp/xdg-data"
export XDG_CONFIG_HOME="$tmp/xdg-config"
export XDG_CACHE_HOME="$tmp/xdg-cache"
mkdir -p \
    "$XDG_DATA_HOME/com.backbay.ambush.app.dev.scoped-worktree" \
    "$XDG_DATA_HOME/xyz.block.buzz.app.dev.feature-reset" \
    "$XDG_DATA_HOME/com.backbay.ambush.app" \
    "$XDG_CONFIG_HOME/com.backbay.ambush.app.dev.scoped-worktree" \
    "$XDG_CACHE_HOME/com.backbay.ambush.app.dev.scoped-worktree" \
    "$HOME/.ambush-dev/keyring-services-v1"
touch "$HOME/.ambush-dev/old-state"
printf '1\n' > "$HOME/.ambush-dev/keyring-services-v1/ambush-desktop-dev.deleted-worktree-deadbeef"

mkdir -p "$tmp/bin"
cat > "$tmp/bin/secret-tool" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$HOME/secret-tool-calls"
MOCK
chmod +x "$tmp/bin/secret-tool"
export PATH="$tmp/bin:$PATH"

AMBUSH_TEST_PLATFORM=Linux "$workspace/scripts/reset-desktop-dev-state.sh"

[[ ! -e "$XDG_DATA_HOME/com.backbay.ambush.app.dev.scoped-worktree" ]]
[[ ! -e "$XDG_DATA_HOME/xyz.block.buzz.app.dev.feature-reset" ]]
[[ ! -e "$XDG_CONFIG_HOME/com.backbay.ambush.app.dev.scoped-worktree" ]]
[[ ! -e "$XDG_CACHE_HOME/com.backbay.ambush.app.dev.scoped-worktree" ]]
[[ -d "$XDG_DATA_HOME/com.backbay.ambush.app" ]]
[[ ! -e "$HOME/.ambush-dev/old-state" ]]
[[ -f "$HOME/.ambush-dev/.dev-nest-migrated" ]]

for service in \
    ambush-desktop-dev \
    buzz-desktop-dev \
    sprout-desktop-dev \
    ambush-desktop-dev.main \
    buzz-desktop-dev.main \
    sprout-desktop-dev.main \
    ambush-desktop-dev.head \
    buzz-desktop-dev.head \
    sprout-desktop-dev.head \
    ambush-desktop-dev.deleted-worktree-deadbeef \
    ambush-desktop-dev.scoped-worktree \
    ambush-desktop-dev.scoped-worktree-${worktree_hash} \
    ambush-desktop-dev.worktree-${empty_slug_hash} \
    ambush-desktop-dev.worktree \
    ambush-desktop-dev.feature-reset \
    ambush-desktop-dev.legacy-inactive \
    buzz-desktop-dev.feature-reset \
    buzz-desktop-dev.legacy-inactive; do
    grep -Fx -- "clear service $service username secrets target default" \
        "$HOME/secret-tool-calls" >/dev/null
done

if grep -Fx -- "clear service ambush-desktop username secrets target default" \
    "$HOME/secret-tool-calls" >/dev/null; then
    echo "full dev reset must preserve the production keyring service" >&2
    exit 1
fi

# A similarly prefixed registry entry is not Ambush-owned and must make the
# reset fail before it deletes either the registry or any keyring service.
mkdir -p "$HOME/.ambush-dev/keyring-services-v1"
printf '1\n' > "$HOME/.ambush-dev/keyring-services-v1/ambush-desktop-devil.collision"
if AMBUSH_TEST_PLATFORM=Linux "$workspace/scripts/reset-desktop-dev-state.sh" >/dev/null 2>&1; then
    echo "full dev reset must reject a keyring prefix collision" >&2
    exit 1
fi
[[ -f "$HOME/.ambush-dev/keyring-services-v1/ambush-desktop-devil.collision" ]]

rm -rf -- "$HOME/.ambush-dev/keyring-services-v1"
mkdir -p "$HOME/.ambush-dev/keyring-services-v1"
printf '\n1' > "$HOME/.ambush-dev/keyring-services-v1/ambush-desktop-dev.corrupt"
if AMBUSH_TEST_PLATFORM=Linux "$workspace/scripts/reset-desktop-dev-state.sh" >/dev/null 2>&1; then
    echo "full dev reset must reject non-exact registry marker contents" >&2
    exit 1
fi
[[ -f "$HOME/.ambush-dev/keyring-services-v1/ambush-desktop-dev.corrupt" ]]

echo "full desktop dev reset scope test passed"
