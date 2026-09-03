#!/usr/bin/env bash
# Regression test for the combined-repository layout: worktree identity is
# derived from the outer checkout, while desktop assets resolve below the
# nested workspace product root.
set -euo pipefail

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
    printf "%s\n%s\n%s\n" "$AMBUSH_WORKTREE_LABEL" "$AMBUSH_INSTANCE_SLUG" "$AMBUSH_TAURI_CONFIG"
  ' _ "$workspace/scripts/instance-env.sh"
)"

[[ "$(sed -n '1p' "$capture")" == "$workspace/scripts/generate-dev-icon.swift" ]]
[[ "$(sed -n '2p' "$capture")" == "$workspace/desktop/src-tauri/icons/icon.icns" ]]
[[ "$(sed -n '3p' "$capture")" == "$workspace/desktop/src-tauri/target/dev-icons/icon.icns" ]]
[[ "$(sed -n '4p' "$capture")" == "test" ]]
printf '%s\n' "$result" | grep -q '^test$'
printf '%s\n' "$result" | grep -q '^feature-test$'
printf '%s\n' "$result" | grep -Fq "$workspace/desktop/src-tauri/target/dev-icons/icon.icns"

failed_icon_result="$(
  cd "$workspace/desktop"
  PATH="$stub_bin:$PATH" INSTANCE_ENV_CAPTURE="$capture" INSTANCE_ENV_SWIFT_FAIL=1 bash -c '
    source "$1"
    printf "%s\n%s\n%s\n" "$AMBUSH_WORKTREE_LABEL" "$AMBUSH_INSTANCE_SLUG" "$AMBUSH_TAURI_CONFIG"
  ' _ "$workspace/scripts/instance-env.sh"
)"
printf '%s\n' "$failed_icon_result" | grep -q '^test$'
printf '%s\n' "$failed_icon_result" | grep -q '^feature-test$'
printf '%s\n' "$failed_icon_result" | grep -Fq '"identifier":"com.backbay.ambush.app.dev.feature-test"'
printf '%s\n' "$failed_icon_result" | grep -Fq '"productName":"Ambush Dev (test)"'
if printf '%s\n' "$failed_icon_result" | grep -Fq '"bundle"'; then
  echo "failed icon generation must omit only the custom icon" >&2
  exit 1
fi

echo "desktop nested-worktree identity contract passed"
