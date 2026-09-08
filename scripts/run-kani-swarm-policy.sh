#!/usr/bin/env bash
#
# KANI-05: run every PR-lane swarm-policy Kani harness.
#
# The proofs are the machine-checked half of the decision core (phase 293). This
# script is the CI entry point: it reads the harness manifest
# (formal/kani/swarm-policy-harnesses.toml), selects the `lane = "pr"` harnesses,
# and proves each ONE AT A TIME with `cargo kani -p swarm-policy --harness <NAME>`.
# It fails on the first proof that does not report `VERIFICATION:- SUCCESSFUL`.
#
# WHY per-harness, scoped, and serial:
#   * `-p swarm-policy` keeps Kani from code-generating the whole workspace
#     (swarm-response, tonic, ...) under CBMC — it builds only swarm-policy and
#     swarm-core, the decision-core surface these proofs are about.
#   * one harness per `cargo kani` invocation, in sequence, because CBMC is
#     memory-heavy; a parallel run risks an out-of-memory kill on a CI box.
#   * the harness bounds live on the harnesses themselves (`#[kani::unwind]`,
#     bounded symbolic inputs); this script does not override them.
#
# The manifest is the single source of truth for WHICH harnesses run (the
# kani_harness_manifest.rs unit test proves the manifest matches the
# `#[kani::proof]` set), so a new PR-lane harness is picked up here automatically
# once it is added to the manifest.
#
# Usage: scripts/run-kani-swarm-policy.sh   (run from the repository root)

set -euo pipefail

MANIFEST="formal/kani/swarm-policy-harnesses.toml"

if [[ ! -f "$MANIFEST" ]]; then
    echo "run-kani-swarm-policy: manifest not found at $MANIFEST (run from the repo root)" >&2
    exit 2
fi

if ! command -v cargo-kani >/dev/null 2>&1 && ! cargo kani --version >/dev/null 2>&1; then
    echo "run-kani-swarm-policy: Kani is not installed (cargo kani unavailable)" >&2
    echo "  install with: cargo install --locked kani-verifier && cargo kani setup" >&2
    exit 2
fi

# PR-lane harness names, in manifest order. `name` precedes `lane` in every
# block, so emit the pending name when its block's lane is read as "pr". A
# `while read` loop rather than `mapfile` so it runs on bash 3.2 (macOS) as well
# as the CI bash.
HARNESSES=()
while IFS= read -r harness_name; do
    [[ -n "$harness_name" ]] && HARNESSES+=("$harness_name")
done < <(awk '
    /^\[\[harness\]\]/            { name=""; lane="" }
    /^name = "/                  { name=$0; sub(/^name = "/, "", name); sub(/"$/, "", name) }
    /^lane = "/                  { lane=$0; sub(/^lane = "/, "", lane); sub(/"$/, "", lane);
                                   if (lane == "pr" && name != "") print name }
' "$MANIFEST")

if [[ ${#HARNESSES[@]} -eq 0 ]]; then
    echo "run-kani-swarm-policy: no pr-lane harnesses in $MANIFEST" >&2
    exit 2
fi

echo "run-kani-swarm-policy: proving ${#HARNESSES[@]} pr-lane harness(es)"

failed=0
for harness in "${HARNESSES[@]}"; do
    echo "=== cargo kani --harness $harness ==="
    if cargo kani -p swarm-policy --harness "$harness"; then
        echo "--- $harness: SUCCESSFUL"
    else
        echo "!!! $harness: FAILED" >&2
        failed=1
        break
    fi
done

if [[ $failed -ne 0 ]]; then
    echo "run-kani-swarm-policy: a harness failed to verify" >&2
    exit 1
fi

echo "run-kani-swarm-policy: all ${#HARNESSES[@]} pr-lane harness(es) verified"
