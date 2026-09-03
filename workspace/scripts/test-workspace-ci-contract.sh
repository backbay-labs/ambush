#!/usr/bin/env bash
set -euo pipefail

workspace_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="$workspace_root/../.github/workflows/workspace-ci.yml"

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
