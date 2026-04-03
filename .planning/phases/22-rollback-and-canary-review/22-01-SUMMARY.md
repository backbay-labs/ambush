---
phase: 22-rollback-and-canary-review
plan: 01
subsystem: canary-review
tags:
  - canary
  - rollback
  - review
  - operator
one-liner: Rollback is now a durable operator workflow, and one persisted canary report links verification, shadow, live metrics, threshold verdicts, and recommendation state.
requires:
  - 21-bounded-canary-execution-and-metrics
provides:
  - automatic rollback on threshold or budget failure
  - manual halt and rollback actions with persisted reason history
  - stable-ID canary review artifacts exposed through `swarmctl`
affects: []
tech-stack:
  added: []
  patterns:
    - rollback reason history stays durable and operator-readable
    - canary evidence remains one serializable report instead of a separate hidden control path
    - nonzero CLI exit on rolled-back canary event supports automation and guardrails
key-files:
  created:
    - crates/swarm-runtime/src/canary.rs
  modified:
    - .gitignore
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - crates/swarm-runtime/src/replay.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Treat the persisted canary run report as the first canary review packet instead of inventing a second artifact type."
  - "Preserve both automatic and manual rollback history in the same durable record."
  - "Make `canary-event` exit nonzero on rollback so automation can detect blocked candidates immediately."
patterns-established:
  - "Live rollout evidence remains addressable by stable IDs and inspectable through the repo-owned operator CLI."
requirements-completed:
  - RLB-01
  - RLB-02
  - PRM-03
  - PRM-04
duration: 45min
completed: 2026-04-03
---

# Phase 22: Rollback And Canary Review Summary

**Rollback is now real instead of aspirational: the runtime blocks bad canary behavior automatically, operators can stop or revert a run manually, and the persisted canary artifact already carries the evidence needed for promotion review.**

## Performance

- **Duration:** 45 min
- **Completed:** 2026-04-03T20:03:20Z
- **Tasks:** 4
- **Files modified:** 6

## Accomplishments

- Added automatic rollback on threshold or budget failure with explicit rollback triggers.
- Added manual halt and rollback commands that persist operator reasons, slot identity, and reverted baseline strategy.
- Added stable-ID canary reload and human-readable canary report rendering in `swarmctl`.
- Extended docs and test coverage to cover automatic block behavior plus manual halt or rollback.

## Decisions Made

- The canary run report itself is the first review surface; it already contains verification ID, shadow ID, lineage, metrics, threshold results, and rollback history.
- Manual halt and manual rollback both block the candidate, but they preserve distinct triggers for later operator interpretation.
- Automatic rollback is keyed to threshold names so later budget additions can reuse the same durable review path.

## Deviations from Plan

The milestone did not add a separate promotion-review packet for canaries. The persisted canary report already provided the evidence chain needed for the next decision, so duplicating it would have added storage and state without new operator value.

## Issues Encountered

The first compile pass failed because `SwarmConfig` test helpers in `control.rs` and `service.rs` had not yet been updated for the new `canary` block. The fix was a minimal default config addition in both test modules.

## User Setup Required

Inspect a completed or rolled-back canary by stable ID:

```bash
cargo run -p swarm-runtime --bin swarmctl -- canary-result --run-id canary:canary-primary:office_baseline_control:<timestamp>
```

## Next Phase Readiness

The repo now has a credible experiment -> verification -> shadow -> canary ladder. The next milestone can decide whether to add bounded production promotion, richer operator review, or governance without reopening the canary safety seam.

---
*Phase: 22-rollback-and-canary-review*
*Completed: 2026-04-03*
