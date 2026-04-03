---
phase: 32-queue-handoff-artifacts
plan: 01
subsystem: evolution-handoff
tags:
  - evolution
  - handoff
  - runtime
  - cli
one-liner: Added durable queue-to-canary handoff packets with stable IDs and linked queue, proof, verification, and shadow evidence.
requires:
  - 31-operator-queue-review-and-decisions
provides:
  - file-backed handoff storage rooted under `data/evolution-handoffs/`
  - durable handoff reports that bind accepted proposals to passed shadow artifacts
  - stable handoff-ID reload through `swarmctl`
affects: []
tech-stack:
  added:
    - serde-backed handoff reports and index files
  patterns:
    - queue-to-canary handoff reuses existing evidence artifacts instead of reconstructing rollout inputs manually
    - handoff packets remain repo-owned and CLI-first
key-files:
  modified:
    - crates/swarm-runtime/src/evolution.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Persist queue-to-canary handoff as its own artifact type instead of overloading proposal or canary reports."
  - "Carry experiment path forward on proposal artifacts so later rollout stages do not require manual re-entry."
  - "Keep handoff creation separate from canary launch so acceptance and launch remain distinct operator actions."
patterns-established:
  - "The rollout ladder now extends through handoff packaging: proposal -> handoff packet -> canary launch."
requirements-completed:
  - HAND-02
duration: 25min
completed: 2026-04-03
---

# Phase 32: Queue Handoff Artifacts Summary

**The runtime now persists queue-to-canary handoff packets that bind one accepted proposal to one passed shadow artifact and preserve rollout-ready evidence in one durable record.**

## Performance

- **Duration:** 25 min
- **Completed:** 2026-04-03T22:42:24Z
- **Tasks:** 4
- **Files modified:** 3

## Accomplishments

- Added `EvolutionHandoffReport`, `EvolutionHandoffRecord`, and `FileEvolutionHandoffStore` in `crates/swarm-runtime/src/evolution.rs`.
- Implemented `DefaultEvolutionHandoffHarness::create_handoff` to assemble handoff packets from queue and shadow evidence.
- Added `swarmctl evolution-handoff-create` and `evolution-handoff-result`.
- Covered handoff persistence and stable-ID reload behavior with dedicated runtime tests.

## Decisions Made

- Handoff is its own artifact type instead of a transient CLI-only conversion step.
- Proposal artifacts now preserve `experiment_path` so queue review can hand off into canary without manual translation.
- Handoff creation remains separate from canary launch.

## Deviations from Plan

The first slice keeps handoff storage, admission checks, and launch metadata inside `evolution.rs` rather than splitting them into another rollout module. That kept the evidence chain local to the existing queue implementation.

## Issues Encountered

The proposal artifact model needed one backward-compatible expansion, `experiment_path`, so the handoff packet could preserve launchable canary inputs instead of only abstract experiment IDs.

## User Setup Required

Inspect the shipped handoff workflow docs:

```bash
sed -n '576,613p' docs/CONFIGURATION.md
```

## Next Phase Readiness

Phase 33 can now fail handoff creation closed because the handoff lane has a durable place to record blocking reasons.

---
*Phase: 32-queue-handoff-artifacts*
*Completed: 2026-04-03*
