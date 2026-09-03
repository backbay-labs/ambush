#!/usr/bin/env bash
# Regression test for the combined-repository layout: worktree identity is
# derived from the outer checkout, while desktop assets resolve below the
# nested workspace product root.
set -Eeuo pipefail

trap 'printf "desktop identity contract failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

product_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_script="$product_root/scripts/instance-env.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

main="$tmp/main"
mkdir -p "$main"
git -C "$main" init -q -b main
git -C "$main" -c user.name=fixture -c user.email=fixture@invalid commit -q --allow-empty -m init

worktree="$tmp/Nested_Worktree"
git -C "$main" worktree add -q -b feature/test "$worktree"
worktree_hash=$(python3 -c 'import hashlib, os, sys; print(hashlib.sha256(os.path.realpath(sys.argv[1]).encode()).hexdigest()[:8])' "$worktree")
expected_slug="nested-worktree-${worktree_hash}"
workspace="$worktree/workspace"
mkdir -p "$workspace/scripts" "$workspace/desktop/src-tauri/icons" "$workspace/desktop"
cp "$source_script" "$workspace/scripts/instance-env.sh"
: > "$workspace/desktop/src-tauri/icons/icon.icns"
: > "$workspace/scripts/generate-dev-icon.swift"

stub_bin="$tmp/bin"
mkdir -p "$stub_bin"
cat > "$stub_bin/swift" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$INSTANCE_ENV_CAPTURE"
if [[ "${INSTANCE_ENV_SWIFT_FAIL:-0}" == "1" ]]; then
  exit 1
fi
: > "$3"
STUB
chmod +x "$stub_bin/swift"

capture="$tmp/swift-args"
result="$(
  cd "$workspace/desktop"
  PATH="$stub_bin:$PATH" INSTANCE_ENV_CAPTURE="$capture" bash -c '
    source "$1"
    printf "%s\n%s\n%s\n%s\n" "$AMBUSH_WORKTREE_LABEL" "$AMBUSH_INSTANCE_SLUG" "$VITE_DEV_BRANCH" "$AMBUSH_TAURI_CONFIG"
  ' _ "$workspace/scripts/instance-env.sh"
)"

[[ "$(sed -n '1p' "$capture")" == "$workspace/scripts/generate-dev-icon.swift" ]]
[[ "$(sed -n '2p' "$capture")" == "$workspace/desktop/src-tauri/icons/icon.icns" ]]
[[ "$(sed -n '3p' "$capture")" == "$workspace/desktop/src-tauri/target/dev-icons/icon.icns" ]]
[[ "$(sed -n '4p' "$capture")" == "test" ]]
printf '%s\n' "$result" | grep -q '^test$'
printf '%s\n' "$result" | grep -q "^${expected_slug}$"
printf '%s\n' "$result" | grep -Fq "$workspace/desktop/src-tauri/target/dev-icons/icon.icns"

failed_icon_result="$(
  cd "$workspace/desktop"
  PATH="$stub_bin:$PATH" INSTANCE_ENV_CAPTURE="$capture" INSTANCE_ENV_SWIFT_FAIL=1 bash -c '
    source "$1"
    printf "%s\n%s\n%s\n%s\n" "$AMBUSH_WORKTREE_LABEL" "$AMBUSH_INSTANCE_SLUG" "$VITE_DEV_BRANCH" "$AMBUSH_TAURI_CONFIG"
  ' _ "$workspace/scripts/instance-env.sh"
)"
printf '%s\n' "$failed_icon_result" | grep -q '^test$'
printf '%s\n' "$failed_icon_result" | grep -q "^${expected_slug}$"
printf '%s\n' "$failed_icon_result" | grep -Fq "\"identifier\":\"com.backbay.ambush.app.dev.${expected_slug}\""
printf '%s\n' "$failed_icon_result" | grep -Fq '"productName":"Ambush Dev (test)"'
if printf '%s\n' "$failed_icon_result" | grep -Fq '"bundle"'; then
  echo "failed icon generation must omit only the custom icon" >&2
  exit 1
fi

git -C "$worktree" switch -q -c alternate/Changed_Branch
switched_result="$(
  cd "$workspace/desktop"
  PATH="$stub_bin:$PATH" INSTANCE_ENV_CAPTURE="$capture" INSTANCE_ENV_SWIFT_FAIL=1 bash -c '
    source "$1"
    printf "%s\n%s\n%s\n" "$AMBUSH_WORKTREE_LABEL" "$AMBUSH_INSTANCE_SLUG" "$VITE_DEV_BRANCH"
  ' _ "$workspace/scripts/instance-env.sh"
)"
printf '%s\n' "$switched_result" | grep -q '^Changed_Branch$'
printf '%s\n' "$switched_result" | grep -q "^${expected_slug}$"

detached_sha=$(git -C "$worktree" rev-parse --short HEAD)
git -C "$worktree" switch -q --detach
detached_result="$(
  cd "$workspace/desktop"
  PATH="$stub_bin:$PATH" INSTANCE_ENV_CAPTURE="$capture" INSTANCE_ENV_SWIFT_FAIL=1 bash -c '
    source "$1"
    printf "%s\n%s\n%s\n" "$AMBUSH_WORKTREE_LABEL" "$AMBUSH_INSTANCE_SLUG" "$VITE_DEV_BRANCH"
  ' _ "$workspace/scripts/instance-env.sh"
)"
printf '%s\n' "$detached_result" | grep -q "^${detached_sha}$"
printf '%s\n' "$detached_result" | grep -q "^${expected_slug}$"

# The basename is only a readable prefix. Two worktrees with the same final
# path component must still receive different install/keyring identities.
other_worktree="$tmp/elsewhere/Nested_Worktree"
mkdir -p "$(dirname "$other_worktree")"
git -C "$main" worktree add -q -b feature/other "$other_worktree"
other_workspace="$other_worktree/workspace"
mkdir -p "$other_workspace/scripts" "$other_workspace/desktop/src-tauri/icons" "$other_workspace/desktop"
cp "$source_script" "$other_workspace/scripts/instance-env.sh"
: > "$other_workspace/desktop/src-tauri/icons/icon.icns"
: > "$other_workspace/scripts/generate-dev-icon.swift"
other_slug="$(
  cd "$other_workspace/desktop"
  PATH="$stub_bin:$PATH" INSTANCE_ENV_CAPTURE="$capture" INSTANCE_ENV_SWIFT_FAIL=1 bash -c '
    source "$1"
    printf "%s" "$AMBUSH_INSTANCE_SLUG"
  ' _ "$other_workspace/scripts/instance-env.sh"
)"
[[ "$other_slug" == nested-worktree-* ]]
[[ "$other_slug" != "$expected_slug" ]]

# Distinct directory names can normalize to the same readable prefix. Their
# canonical paths must still keep the desktop identities disjoint.
normalized_worktree="$tmp/nested-worktree"
git -C "$main" worktree add -q -b feature/normalized "$normalized_worktree"
normalized_workspace="$normalized_worktree/workspace"
mkdir -p "$normalized_workspace/scripts" "$normalized_workspace/desktop/src-tauri/icons" "$normalized_workspace/desktop"
cp "$source_script" "$normalized_workspace/scripts/instance-env.sh"
: > "$normalized_workspace/desktop/src-tauri/icons/icon.icns"
: > "$normalized_workspace/scripts/generate-dev-icon.swift"
normalized_slug="$(
  cd "$normalized_workspace/desktop"
  PATH="$stub_bin:$PATH" INSTANCE_ENV_CAPTURE="$capture" INSTANCE_ENV_SWIFT_FAIL=1 bash -c '
    source "$1"
    printf "%s" "$AMBUSH_INSTANCE_SLUG"
  ' _ "$normalized_workspace/scripts/instance-env.sh"
)"
[[ "$normalized_slug" == nested-worktree-* ]]
[[ "$normalized_slug" != "$expected_slug" ]]

echo "desktop nested-worktree identity contract passed"
