---
phase: 29-evolution-queue-and-proposal-artifacts
plan: 01
subsystem: evolution-queue
tags:
  - evolution
  - runtime
  - cli
  - storage
one-liner: Added durable evolution proposal artifacts with stable IDs, lineage, advisory evidence, and review-state persistence.
requires:
  - 28-strategy-review-and-advisory-selection
provides:
  - file-backed evolution proposal storage rooted under `data/evolution-queue/`
  - durable proposal reports with stable proposal IDs and review state
  - queue assembly from experiment, verification, proof, and advisory evidence
affects: []
tech-stack:
  added:
    - serde-backed evolution proposal reports and index files
  patterns:
    - proposal artifacts are derived from existing persisted evidence instead of mutable runtime state
    - stable-ID queue lookup remains repo-owned and CLI-first
key-files:
  created:
    - crates/swarm-runtime/src/evolution.rs
  modified:
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - crates/swarm-runtime/src/lib.rs
    - .gitignore
key-decisions:
  - "Store queued detector proposals as first-class durable artifacts instead of embedding review state into scorecards or experiments."
  - "Attach advisory evidence to each proposal at creation time so queue review does not require recomputing context on every lookup."
  - "Keep the queue deterministic and operator-controlled: proposal creation persists evidence but does not mutate canary or production state."
patterns-established:
  - "The review ladder now extends beyond advisory scoring: experiment -> verification -> proof -> proposal queue."
requirements-completed:
  - EVOL-02
  - EVOL-04
duration: 35min
completed: 2026-04-03
---

# Phase 29: Evolution Queue And Proposal Artifacts Summary

**The runtime now persists verified detector proposals as durable queue artifacts with stable IDs, lineage, verification references, proof summaries, and advisory scorecard context.**

## Performance

- **Duration:** 35 min
- **Completed:** 2026-04-03T22:31:19Z
- **Tasks:** 4
- **Files modified:** 4

## Accomplishments

- Added `EvolutionProposalReport`, `EvolutionProposalRecord`, `EvolutionProposalList`, and `FileEvolutionProposalStore` in `crates/swarm-runtime/src/evolution.rs`.
- Implemented `DefaultEvolutionQueueHarness` to assemble queue artifacts from persisted experiment, verification, proof, and advisory evidence.
- Added stable proposal-ID lookup and filtered queue listing through `swarmctl evolution-queue-result` and `evolution-queue-list`.
- Covered proposal persistence, reload, and filtered listing behavior with dedicated runtime tests.

## Decisions Made

- Proposal records are their own artifact type instead of an attached field on strategy scorecards.
- Queue creation derives artifacts from persisted evidence and repo-owned manifests only.
- Proposal creation stays off the hot path and does not mutate live rollout state.

## Deviations from Plan

The first slice keeps proposal storage, proof validation, and review-state handling in one `evolution.rs` runtime module instead of splitting them across separate crates. That kept the queue lane aligned with the existing replay and strategy artifact patterns.

## Issues Encountered

The queue needed a durable index plus path sanitization so proposal lookup by stable ID or filtered state would not depend on directory scanning or implicit filename conventions.

## User Setup Required

Inspect the shipped queue workflow docs:

```bash
sed -n '508,575p' docs/CONFIGURATION.md
```

## Next Phase Readiness

Phase 30 can now enforce fail-closed admission because the proposal lane has a durable home for proof status and blocking reasons.

---
*Phase: 29-evolution-queue-and-proposal-artifacts*
*Completed: 2026-04-03*
