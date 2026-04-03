---
phase: 34-canary-launch-from-handoff
plan: 01
subsystem: evolution-handoff-launch
tags:
  - evolution
  - handoff
  - canary
  - cli
one-liner: Added operator-launched canary entry from stable handoff packets with durable canary-run references preserved on the handoff artifact.
requires:
  - 32-queue-handoff-artifacts
  - 33-queue-to-canary-admission-gate
provides:
  - `swarmctl evolution-handoff-launch-canary`
  - durable handoff launch state and resulting canary-run references
  - queue-to-canary launch lineage preserved without manual artifact translation
affects: []
tech-stack:
  added: []
  patterns:
    - handoff launch reuses the existing canary harness instead of creating a second rollout path
    - canary launch remains operator-triggered even after proposal acceptance
key-files:
  modified:
    - crates/swarm-runtime/src/evolution.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Launch canary from the handoff artifact, not directly from queue review state."
  - "Persist the resulting canary run ID back onto the handoff packet so queue review and rollout stay linked."
  - "Reuse the existing canary harness rather than fork a second launch mechanism."
patterns-established:
  - "Accepted proposal review can now progress into bounded rollout through a durable bridge: accepted proposal -> handoff -> canary run."
requirements-completed:
  - HAND-01
  - HAND-04
  - HAND-05
duration: 30min
completed: 2026-04-03
---

# Phase 34: Canary Launch From Handoff Summary

**Operators can now launch the bounded canary lane directly from a stable handoff packet, and the handoff record preserves the resulting canary run ID and launch status.**

## Performance

- **Duration:** 30 min
- **Completed:** 2026-04-03T22:42:24Z
- **Tasks:** 4
- **Files modified:** 3

## Accomplishments

- Added `DefaultEvolutionHandoffHarness::launch_canary` to bridge launchable handoff packets into the existing canary harness.
- Added `swarmctl evolution-handoff-launch-canary`.
- Persisted `launch_status`, `launched_at_ms`, and `canary_run_id` back onto the handoff artifact.
- Verified the full CLI flow from proposal acceptance through handoff creation and canary launch.

## Decisions Made

- Handoff launch status is stored on the handoff packet instead of rewriting queue review state.
- Launch is still an explicit operator action.
- The existing canary gates remain authoritative; handoff only packages the reviewed queue evidence for launch.

## Deviations from Plan

The first launch slice does not add handoff listing or multi-slot routing. One stable handoff ID and the existing single canary slot are enough for the current runtime.

## Issues Encountered

The new launch seam needed to protect against repeat launch attempts, so handoff packets now reject a second canary launch once a run ID has been recorded.

## User Setup Required

Inspect the shipped queue-to-canary commands:

```bash
sed -n '576,613p' docs/CONFIGURATION.md
```

## Next Phase Readiness

The next milestone can now focus on carrying rollout lineage forward from canary into later promotion or governance handoff without reopening the manual translation gap.

---
*Phase: 34-canary-launch-from-handoff*
*Completed: 2026-04-03*
