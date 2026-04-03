---
phase: 17-verification-corpus-and-invariants
verified: 2026-04-03T17:13:00Z
status: passed
score: 3/3 must-haves verified
---

# Phase 17: Verification Corpus And Invariants Verification Report

**Phase Goal:** Define repo-owned verification inputs for candidate detectors, including known-bad indicators, benign controls, and explicit resource-budget or invariant manifests.
**Verified:** 2026-04-03T17:13:00Z
**Status:** passed

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Canonical known-bad coverage, benign controls, threat-class templates, and resource budgets are tracked in repo-owned manifests instead of tests. | ✓ VERIFIED | `verifications/office-detector-safety-v1.yaml` defines known-bad suite coverage, benign controls, one canonical `execution` template, and resource budgets. |
| 2 | Existing candidate experiment manifests can point at one canonical verification corpus without touching production runtime config. | ✓ VERIFIED | `experiments/office-baseline-control.yaml` and `experiments/office-python-parent-broadening.yaml` now declare `verification.corpus: ../verifications/office-detector-safety-v1.yaml`. |
| 3 | Verification corpus manifests are validated and documented for later gate execution. | ✓ VERIFIED | `load_verification_manifest` and `validate_verification_manifest` were added to `crates/swarm-runtime/src/replay.rs`, replay tests passed, and `docs/CONFIGURATION.md` documents the new corpus contract. |

**Score:** 3/3 truths verified

## Requirements Coverage

| Requirement | Status | Blocking Issue |
|-------------|--------|----------------|
| VER-03 | ✓ SATISFIED | - |

## Human Verification Required

None — this phase established manifest contracts, docs, and automated validation only.

## Verification Metadata

**Automated checks:**
- `cargo test -p swarm-runtime replay --quiet`
- `cargo fmt --all --check`
- `cargo clippy --workspace -- -D warnings`

---
*Verified: 2026-04-03T17:13:00Z*
*Verifier: Codex*
