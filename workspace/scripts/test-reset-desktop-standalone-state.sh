#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export HOME="$tmp/home"
export AMBUSH_TEST_PLATFORM=Darwin
mkdir -p "$HOME/Library/Application Support/com.backbay.ambush.app.dev.example"
mkdir -p "$HOME/Library/Application Support/com.backbay.ambush.app.dev.other"
mkdir -p "$HOME/Library/Application Support/com.backbay.ambush.app"
mkdir -p "$HOME/.ambush-dev"
touch "$HOME/.ambush-dev/keep"
mkdir -p "$tmp/bin"
cat > "$tmp/bin/security" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$HOME/security-calls"
exit 1
MOCK
cat > "$tmp/bin/secret-tool" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$HOME/secret-tool-calls"
MOCK
chmod +x "$tmp/bin/security"
chmod +x "$tmp/bin/secret-tool"
export PATH="$tmp/bin:$PATH"

"$repo_root/scripts/reset-desktop-standalone-state.sh" \
    com.backbay.ambush.app.dev.example ambush-desktop-dev.example

[[ ! -e "$HOME/Library/Application Support/com.backbay.ambush.app.dev.example" ]]
[[ -d "$HOME/Library/Application Support/com.backbay.ambush.app.dev.other" ]]
[[ -d "$HOME/Library/Application Support/com.backbay.ambush.app" ]]
[[ -f "$HOME/.ambush-dev/keep" ]]
grep -Fx -- "delete-generic-password -s ambush-desktop-dev.example" "$HOME/security-calls" >/dev/null

export AMBUSH_TEST_PLATFORM=Linux
export XDG_DATA_HOME="$tmp/xdg-data"
export XDG_CONFIG_HOME="$tmp/xdg-config"
export XDG_CACHE_HOME="$tmp/xdg-cache"
mkdir -p \
    "$XDG_DATA_HOME/com.backbay.ambush.app.dev.linux" \
    "$XDG_CONFIG_HOME/com.backbay.ambush.app.dev.linux" \
    "$XDG_CACHE_HOME/com.backbay.ambush.app.dev.linux"

"$repo_root/scripts/reset-desktop-standalone-state.sh" \
    com.backbay.ambush.app.dev.linux ambush-desktop-dev.linux

[[ ! -e "$XDG_DATA_HOME/com.backbay.ambush.app.dev.linux" ]]
[[ ! -e "$XDG_CONFIG_HOME/com.backbay.ambush.app.dev.linux" ]]
[[ ! -e "$XDG_CACHE_HOME/com.backbay.ambush.app.dev.linux" ]]
grep -Fx -- "clear service ambush-desktop-dev.linux username secrets target default" \
    "$HOME/secret-tool-calls" >/dev/null

if "$repo_root/scripts/reset-desktop-standalone-state.sh" \
    com.backbay.ambush.app ambush-desktop >/dev/null 2>&1; then
    echo "expected production scope guard to reject reset" >&2
    exit 1
fi

echo "standalone desktop reset scope test passed"
