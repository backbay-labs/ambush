#!/usr/bin/env bash
set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$workspace_root/../.github/workflows/workspace-ci.yml"
lefthook="$workspace_root/lefthook.yml"

require_literal() {
    local needle="$1"
    grep -Fq -- "$needle" "$workflow" || {
        echo "workspace CI is missing required contract: $needle" >&2
        exit 1
    }
}

require_literal 'admin: ${{ steps.filter.outputs.admin }}'
require_literal "              - 'workspace/admin-web/**'"
require_literal "              - 'workspace/Justfile'"
require_literal "              - 'workspace/.cargo/config.toml'"
require_literal "              - 'workspace/scripts/reconcile-schema-after-pgschema.sql'"
require_literal "  admin-dashboard:"
require_literal "    name: Admin Dashboard"
require_literal "needs.changes.outputs.admin == 'true'"
require_literal "        run: just admin-check"
require_literal "        run: scripts/test-workspace-ci-contract.sh"
require_literal '          CHECK_FILE_SIZES_BASE: ${{ github.event.pull_request.head.sha || github.sha }}'
require_literal "needs.changes.outputs.desktop-rust == 'true'"
require_literal "              - 'workspace/scripts/check-desktop-vulnerabilities.sh'"
require_literal "      - name: Install cargo-audit"
require_literal "          tool: cargo-audit@0.22.0"
require_literal "        run: scripts/check-desktop-vulnerabilities.sh"
require_literal "          scripts/test-reset-desktop-dev-state.sh"
require_literal "          scripts/test-reset-desktop-standalone-state.sh"

web_filter_block=$(awk '
    $0 == "            web:" { found = 1 }
    found && $0 == "            admin:" { exit }
    found { print }
' "$workflow")
grep -Fq "              - '.github/workflows/workspace-ci.yml'" <<<"$web_filter_block" || {
    echo "workspace workflow changes must activate the web lane" >&2
    exit 1
}

git_root="$workspace_root/.."
if git -C "$git_root" check-ignore -q --no-index \
    workspace/docs/plans/ambush-ui/build/README.md; then
    echo "root ignore rules must expose the workspace Ambush build plan" >&2
    exit 1
fi

grep -Fq 'pnpm build:e2e' \
    "$workspace_root/desktop/src-tauri/src/managed_agents/screenshot_skill.md" || {
    echo "managed-agent screenshot guidance must preserve the E2E mock bridge" >&2
    exit 1
}

if [[ $(grep -oF '"workspace/.cargo/config.toml"' "$lefthook" | wc -l | tr -d ' ') -ne 2 ]]; then
    echo "Rust and desktop-Tauri pre-push lanes must both include workspace/.cargo/config.toml" >&2
    exit 1
fi

reconciliation_cache_entries=$(grep -c "hashFiles(.*workspace/scripts/reconcile-schema-after-pgschema.sql" "$workflow" || true)
if [[ "$reconciliation_cache_entries" -ne 2 ]]; then
    echo "relay restore and save keys must both hash schema reconciliation SQL" >&2
    exit 1
fi

for job in desktop desktop-e2e-integration; do
    block=$(awk -v job="$job" '
        $0 == "  " job ":" { found = 1 }
        found && $0 ~ /^  [a-z0-9-]+:$/ && $0 != "  " job ":" { exit }
        found { print }
    ' "$workflow")
    grep -Fq "working-directory: ." <<<"$block" || {
        echo "$job aggregate must run from the checkout-independent job root" >&2
        exit 1
    }
done

echo "workspace CI source contract passed"
