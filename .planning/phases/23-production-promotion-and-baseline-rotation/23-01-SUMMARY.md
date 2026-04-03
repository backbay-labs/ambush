---
phase: 23-production-promotion-and-baseline-rotation
plan: 01
subsystem: production-promotion
tags:
  - promotion
  - config
  - runtime
  - cli
one-liner: A canary-approved detector can now be promoted into the production role through repo-owned config, baseline rotation, and stable promotion IDs.
requires:
  - 22-rollback-and-canary-review
provides:
  - validated promotion config in the shared Rust config model
  - fail-closed promotion start from a ready canary artifact
  - persisted promotion artifacts keyed by stable production-promotion IDs
affects: []
tech-stack:
  added: []
  patterns:
    - one active production observation window per config
    - promotion starts from canary evidence instead of config edits
    - previous production detector stays attached as explicit rollback target
key-files:
  created:
    - crates/swarm-runtime/src/promotion.rs
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - rulesets/default.yaml
key-decisions:
  - "Represent production promotion in the shared config model with a dedicated `PromotionConfig` block."
  - "Start promotion from a completed canary report instead of introducing a separate hand-authored promotion manifest."
  - "Capture the previous production detector as a portable detector manifest so rollback stays self-contained."
patterns-established:
  - "The rollout ladder now continues cleanly from canary artifact to production promotion artifact."
requirements-completed:
  - PROD-01
  - PROD-02
duration: 40min
completed: 2026-04-03
---

# Phase 23: Production Promotion And Baseline Rotation Summary

**The runtime now has a first-class production-promotion start path: operators can promote a ready canary artifact into production, keep the prior baseline as rollback target, and persist one stable promotion record without touching detector config by hand.**

## Performance

- **Duration:** 40 min
- **Completed:** 2026-04-03T21:12:35Z
- **Tasks:** 4
- **Files modified:** 7

## Accomplishments

- Added `PromotionConfig` to the shared Rust config model and validated it during repo config loading.
- Added a production-promotion store and `DefaultProductionPromotionHarness::start_run` to materialize a production promotion from a completed canary run.
- Enforced fail-closed start behavior for missing, blocked, incomplete, or baseline-mismatched canary artifacts.
- Added `swarmctl promotion-start` and `promotion-result` as the repo-owned production-promotion control surface.

## Decisions Made

- The first promotion lane uses a single named observation window, not generalized rollout scheduling.
- Promotion starts from canary evidence only; the operator does not hand-author production detector swaps.
- The prior production detector is stored as a portable detector manifest inside the promotion artifact so later rollback does not depend on mutable config state.

## Deviations from Plan

The milestone uses the canary artifact itself as the promotion handoff rather than composing the older promotion-review packet into a second approval object. The canary report already carries the required verification, shadow, lineage, and bounded-run evidence.

## Issues Encountered

Adding a new top-level config block caused the usual test-builder drift in runtime unit tests; those builders were updated with default promotion settings.

## User Setup Required

Inspect the shipped promotion defaults:

```bash
sed -n '61,80p' rulesets/default.yaml
```

## Next Phase Readiness

Phase 24 can now observe the promoted detector over a bounded production window and make rollback decisions from post-promotion metrics instead of only pre-promotion evidence.

---
*Phase: 23-production-promotion-and-baseline-rotation*
*Completed: 2026-04-03*
