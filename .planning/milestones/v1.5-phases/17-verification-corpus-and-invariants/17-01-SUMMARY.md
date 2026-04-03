---
phase: 17-verification-corpus-and-invariants
plan: 01
subsystem: verification-corpus
tags:
  - replay
  - verification
  - manifests
  - docs
one-liner: The repo now ships a canonical verification corpus manifest that captures known-bad coverage, benign controls, threat-class templates, and resource budgets for candidate detectors.
requires:
  - 16-experiment-reports-and-offline-safety-gates
provides:
  - repo-owned verification corpus manifests under `verifications/`
  - experiment-to-verification corpus bindings
  - documented and validated invariant inputs for later gate execution
affects: []
tech-stack:
  added: []
  patterns:
    - detector safety inputs tracked as YAML instead of hidden in tests
    - experiment manifests declare the verification corpus they target
    - replay manifest validation remains fail-closed
key-files:
  created:
    - verifications/office-detector-safety-v1.yaml
  modified:
    - crates/swarm-runtime/src/replay.rs
    - docs/CONFIGURATION.md
    - experiments/office-baseline-control.yaml
    - experiments/office-python-parent-broadening.yaml
key-decisions:
  - "Use one tracked verification corpus manifest as the source of truth for the first detector."
  - "Reuse the existing office replay suite as known-bad coverage instead of inventing a parallel proof corpus."
  - "Keep the first threat-class template narrow: one `execution` example matching the current detector."
patterns-established:
  - "Offline promotion-readiness work starts from repo-owned verification inputs before adding new gates."
requirements-completed:
  - VER-03
duration: 35min
completed: 2026-04-03
---

# Phase 17: Verification Corpus And Invariants Summary

**The repo now has a canonical verification corpus contract: known-bad suite coverage, benign controls, threat-class templates, and resource budgets all live in tracked YAML and are no longer implied by tests alone.**

## Performance

- **Duration:** 35 min
- **Completed:** 2026-04-03T17:13:00Z
- **Tasks:** 3
- **Files modified:** 6

## Accomplishments

- Added verification-corpus manifest types, loading, and fail-closed validation in `crates/swarm-runtime/src/replay.rs`.
- Added `verifications/office-detector-safety-v1.yaml` as the first repo-owned verification corpus for the suspicious process-tree detector.
- Bound existing experiment manifests to the canonical verification corpus through `verification.corpus`.
- Added replay tests covering verification-corpus manifest loading and validation.
- Documented the verification-corpus contract in `docs/CONFIGURATION.md`.

## Decisions Made

- The existing `hellcat_office_v1` suite remains the known-bad coverage source for the first detector.
- Benign controls stay explicit as tracked scenario paths so false-positive inputs remain inspectable.
- Resource budgets are tracked in the corpus manifest today as detect latency and total detections, which is enough for the current runtime slice.

## Deviations from Plan

`swarmctl` did not need a new command yet. This phase only established the manifest contract that later verification and shadow commands will consume.

## Issues Encountered

`cargo fmt --check` initially flagged a few style diffs in `replay.rs`; running `cargo fmt --all` resolved them without code changes.

## User Setup Required

Inspect the canonical verification corpus:

```bash
sed -n '1,220p' verifications/office-detector-safety-v1.yaml
```

## Next Phase Readiness

Phase 18 can now turn the tracked verification corpus into a real per-invariant gate and a persisted shadow report without inventing new input contracts.

---
*Phase: 17-verification-corpus-and-invariants*
*Completed: 2026-04-03*
