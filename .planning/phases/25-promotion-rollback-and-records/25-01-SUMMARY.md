---
phase: 25-promotion-rollback-and-records
plan: 01
subsystem: promotion-records
tags:
  - promotion
  - records
  - operator
  - docs
one-liner: Production promotions are now operator-readable and reversible through durable records, manual controls, stable-ID lookup, and documented workflow.
requires:
  - 24-production-observation-window-and-metrics
provides:
  - manual halt and rollback for active promotions
  - stable-ID reload for promotion records
  - documented canary-to-production operator workflow
affects: []
tech-stack:
  added: []
  patterns:
    - one production-promotion report acts as the durable operator handoff artifact
    - manual actions and automatic rollback share the same persisted history model
    - CLI remains the single operator surface for rollout control
key-files:
  created:
    - crates/swarm-runtime/src/promotion.rs
  modified:
    - .gitignore
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Treat the production-promotion report itself as the durable operator record rather than inventing a second promotion packet."
  - "Manual halt and manual rollback preserve distinct triggers in the same rollback-history stream."
  - "Make `promotion-event` exit nonzero on auto rollback so automation can stop promotion flows immediately."
patterns-established:
  - "The runtime now ships a full candidate rollout ladder with stable-ID operator artifacts at every stage."
requirements-completed:
  - PROD-05
  - PROD-06
  - PROD-07
duration: 45min
completed: 2026-04-03
---

# Phase 25: Promotion Rollback And Records Summary

**Production promotion is now an operator workflow instead of a hidden runtime state change: manual halt and rollback are durable, the full evidence chain reloads by stable ID, and the docs explain the canary-to-production path end to end.**

## Performance

- **Duration:** 45 min
- **Completed:** 2026-04-03T21:12:35Z
- **Tasks:** 4
- **Files modified:** 5

## Accomplishments

- Added `promotion-halt`, `promotion-rollback`, and `promotion-result` to `swarmctl`.
- Persisted manual and automatic rollback history with restored baseline strategy and observed event count.
- Documented the production-promotion defaults and operator commands in `docs/CONFIGURATION.md`.
- Added CLI-backed verification for both clean completion and manual rollback drill.

## Decisions Made

- The production-promotion report itself is the durable review record. It already contains canary evidence, promoted lineage, rollback target, metrics, threshold results, and recommendation state.
- Stable-ID lookup stays on the production-promotion store instead of being folded into the generic control plane.
- Promotion rollback history explicitly records restored baseline strategy and observed event count so operators can reason about the affected window.

## Deviations from Plan

The milestone did not introduce a multi-surface control plane for promotions. CLI-first remains the smallest practical operator seam, and the persisted artifact already preserves the information needed for later UI work.

## Issues Encountered

The first compile pass failed on a private `CanaryConfig` import inside promotion tests. Importing it from the shared config module resolved the issue immediately.

## User Setup Required

Reload a production promotion by stable ID:

```bash
cargo run -p swarm-runtime --bin swarmctl -- promotion-result --promotion-id promotion:production-primary:office_baseline_control:<timestamp>
```

## Next Phase Readiness

The repo now supports `experiment -> verification -> shadow -> canary -> production promotion`. The next milestone can choose governance, richer operator surfaces, or MemRL-based production learning on top of a real promotion path.

---
*Phase: 25-promotion-rollback-and-records*
*Completed: 2026-04-03*
