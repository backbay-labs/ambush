#!/usr/bin/env bash
#
# SAFEP-04 / SC3: model-check the partition-contingency-lease TLA+ spec clean.
#
# Checks each NAMED safety invariant of formal/tla/PartitionContingency.tla with
# Apalache (the typed TLA+ checker), one at a time, bounded to --length. Fails if
# any invariant does not report "NoError". Constants come from the spec's `CInit`
# operator (Apalache does not consume a TLC-style .cfg the same way).
#
# Usage: scripts/run-apalache-partition.sh   (run from the repository root)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$REPO_ROOT/formal/tla/PartitionContingency.tla"
LENGTH="${APALACHE_LENGTH:-8}"

INVARIANTS=(
    BlastRadiusNeverExceeded
    OverrideRequiresReceipt
    NoRedemptionAfterExpiry
    NoLeaseWhenHealthy
)

if [[ ! -f "$SPEC" ]]; then
    echo "run-apalache-partition: spec not found at $SPEC" >&2
    exit 2
fi
if ! command -v apalache-mc >/dev/null 2>&1; then
    echo "run-apalache-partition: apalache-mc not installed" >&2
    exit 2
fi

OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT

echo "run-apalache-partition: checking ${#INVARIANTS[@]} invariant(s), length=$LENGTH"
for inv in "${INVARIANTS[@]}"; do
    echo "=== $inv ==="
    if apalache-mc check --out-dir="$OUT" --cinit=CInit --inv="$inv" \
        --length="$LENGTH" "$SPEC" 2>&1 | grep -q "The outcome is: NoError"; then
        echo "--- $inv: NoError"
    else
        echo "!!! $inv: NOT clean (unexpected violation or checker error)" >&2
        exit 1
    fi
done

echo "run-apalache-partition: all ${#INVARIANTS[@]} named invariant(s) hold (clean)"
