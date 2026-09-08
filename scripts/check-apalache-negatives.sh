#!/usr/bin/env bash
#
# SAFEP-05: prove the partition-lease negative-falsifiability registry is real.
#
# For each broken variant in formal/tla/negative/, Apalache MUST report a
# VIOLATION of the named invariant (outcome: Error). A "negative" that reports
# NoError — or fails to parse — is a broken negative (the model drifted so the
# defect no longer bites, or the variant rotted); this script fails on it, so the
# registry can never silently become vacuous. It also re-confirms the CLEAN model
# holds all its invariants, so a bug that flipped the base model is caught too.
#
# Usage: scripts/check-apalache-negatives.sh   (run from the repository root)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NEG_DIR="$REPO_ROOT/formal/tla/negative"
LENGTH="${APALACHE_LENGTH:-8}"

# variant : invariant it must VIOLATE : runtime regression test it mirrors
NEGATIVES=(
    "NoCapGuard:BlastRadiusNeverExceeded:lease_redeem_fails_closed_on_mismatch_expiry_and_cap"
    "NoExpiryGuard:NoRedemptionAfterExpiry:lease_can_redeem_denies_an_expired_lease"
    "NoReceiptRequired:OverrideRequiresReceipt:keyless_policy_reloaded_into_a_partition_refuses_persisted_leases"
)

if ! command -v apalache-mc >/dev/null 2>&1; then
    echo "check-apalache-negatives: apalache-mc not installed" >&2
    exit 2
fi

# 1. The clean model must hold every invariant (a flipped base model is a bug).
echo "check-apalache-negatives: confirming the clean model holds ..."
bash "$REPO_ROOT/scripts/run-apalache-partition.sh"

# 2. Each broken variant must VIOLATE its named invariant.
echo "check-apalache-negatives: confirming ${#NEGATIVES[@]} negative(s) violate ..."
for entry in "${NEGATIVES[@]}"; do
    variant="${entry%%:*}"
    rest="${entry#*:}"
    inv="${rest%%:*}"
    spec="$NEG_DIR/$variant.tla"
    echo "=== $variant must violate $inv ==="
    out="$(apalache-mc check --out-dir="$(mktemp -d)" --cinit=CInit \
            --inv="$inv" --length="$LENGTH" "$spec" 2>&1 || true)"
    if grep -q "The outcome is: Error" <<<"$out" \
        && grep -qiE "state invariant.*violated" <<<"$out"; then
        echo "--- $variant: VIOLATES $inv (as required)"
    else
        echo "!!! $variant did NOT violate $inv — negative is vacuous or the spec rotted" >&2
        grep -iE "The outcome is|Could not parse|type input error" <<<"$out" >&2 || true
        exit 1
    fi
done

echo "check-apalache-negatives: clean model holds; all ${#NEGATIVES[@]} negatives violate as required"
