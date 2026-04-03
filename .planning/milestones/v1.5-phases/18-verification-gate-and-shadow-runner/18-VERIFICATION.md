---
phase: 18-verification-gate-and-shadow-runner
verified: 2026-04-03T17:26:16Z
status: passed
score: 3/3 must-haves verified
---

# Phase 18: Verification Gate And Shadow Runner Verification Report

**Phase Goal:** Run candidate detectors through repo-owned invariant checks and shadow-style baseline comparison without live side effects.
**Verified:** 2026-04-03T17:26:16Z
**Status:** passed

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Candidate detectors can be verified against repo-owned invariants with explicit pass/fail output and preserved failures. | ✓ VERIFIED | `swarmctl verification-evaluate --experiment experiments/office-baseline-control.yaml` passed, and the broadened candidate failed on `false_positive_bound` with a preserved `python_maintenance_benign` reference. |
| 2 | Candidate detectors can run in shadow mode over the same recorded replay corpus as baseline without live side effects. | ✓ VERIFIED | `swarmctl shadow-evaluate --experiment experiments/office-baseline-control.yaml` produced a persisted shadow report over `hellcat_office_v1`; the replay harness still forces `detect_only` execution. |
| 3 | Verification and shadow reports persist separately and reload by stable ID through `swarmctl`. | ✓ VERIFIED | `verification-result --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1` and `shadow-result --shadow-id shadow:office_baseline_control:office_baseline_control:2026-04-03` both reloaded the stored artifacts successfully. |

**Score:** 3/3 truths verified

## Requirements Coverage

| Requirement | Status | Blocking Issue |
|-------------|--------|----------------|
| VER-01 | ✓ SATISFIED | - |
| SHD-01 | ✓ SATISFIED | - |
| SHD-02 | ✓ SATISFIED | - |

## Human Verification Required

None — the verification and shadow workflows were exercised through the CLI and automated tests.

## Verification Metadata

**Automated checks:**
- `cargo test -p swarm-runtime replay --quiet`
- `cargo fmt --all --check`
- `cargo clippy --workspace -- -D warnings`
- `cargo run -p swarm-runtime --bin swarmctl -- verification-evaluate --experiment experiments/office-baseline-control.yaml`
- `cargo run -p swarm-runtime --bin swarmctl -- shadow-evaluate --experiment experiments/office-baseline-control.yaml`
- `cargo run -p swarm-runtime --bin swarmctl -- verification-evaluate --experiment experiments/office-python-parent-broadening.yaml`
- `cargo run -p swarm-runtime --bin swarmctl -- verification-result --verification-id verification:office_baseline_control:office_baseline_control:office_detector_safety_v1`
- `cargo run -p swarm-runtime --bin swarmctl -- shadow-result --shadow-id shadow:office_baseline_control:office_baseline_control:2026-04-03`

---
*Verified: 2026-04-03T17:26:16Z*
*Verifier: Codex*
