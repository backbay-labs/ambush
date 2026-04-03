---
phase: 16-experiment-reports-and-offline-safety-gates
verified: 2026-04-03T16:30:26Z
status: passed
score: 4/4 must-haves verified
---

# Phase 16: Experiment Reports And Offline Safety Gates Verification Report

**Phase Goal:** Persist experiment lineage and turn candidate evaluation into a practical offline safety gate.
**Verified:** 2026-04-03T16:30:26Z
**Status:** passed

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Experiment reports persist lineage, corpus version, and score summaries. | ✓ VERIFIED | Stored experiment reports now include lineage, suite name, corpus version, baseline and candidate metrics, and are reloadable through `swarmctl experiment-result`. |
| 2 | Offline gates fail when a candidate exceeds configured thresholds. | ✓ VERIFIED | `swarmctl experiment-evaluate --experiment experiments/office-python-parent-broadening.yaml` exited with code `1` because the candidate exceeded `false_positive_delta`. |
| 3 | Reports identify which scenario caused the regression. | ✓ VERIFIED | The failing broadened-parent experiment reported `python_maintenance_benign` as the false-positive regression. |
| 4 | Operator docs explain named suite and experiment workflows end to end. | ✓ VERIFIED | `docs/CONFIGURATION.md` now documents scenario metadata, suite manifests, experiment manifests, result persistence, and failure semantics. |

**Score:** 4/4 truths verified

## Requirements Coverage

| Requirement | Status | Blocking Issue |
|-------------|--------|----------------|
| RED-03 | ✓ SATISFIED | - |
| EVO-03 | ✓ SATISFIED | - |
| EVO-04 | ✓ SATISFIED | - |

## Human Verification Required

None — both passing and failing experiment behaviors were exercised through the CLI and automated tests.

## Verification Metadata

**Automated checks:**
- `cargo fmt --all --check`
- `cargo test --workspace --quiet`
- `cargo clippy --workspace -- -D warnings`
- `cargo run -p swarm-runtime --bin swarmctl -- replay-evaluate --suite scenario-suites/hellcat-office-v1.yaml`
- `cargo run -p swarm-runtime --bin swarmctl -- experiment-evaluate --experiment experiments/office-baseline-control.yaml`
- `cargo run -p swarm-runtime --bin swarmctl -- experiment-evaluate --experiment experiments/office-python-parent-broadening.yaml`

---
*Verified: 2026-04-03T16:30:26Z*
*Verifier: Codex*
