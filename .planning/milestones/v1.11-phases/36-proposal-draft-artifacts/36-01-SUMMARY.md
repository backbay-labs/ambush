---
phase: 36-proposal-draft-artifacts
plan: 01
subsystem: evolution-drafting
tags:
  - evolution
  - drafting
  - runtime
  - cli
one-liner: Added durable proposal-draft artifacts that package operator hints with selection-pressure evidence without auto-enqueuing them.
requires:
  - 35-selection-pressure-signals
provides:
  - file-backed draft storage rooted under `data/evolution-drafts/`
  - stable draft artifacts with lineage hints and source evidence references
  - stable-ID reload through `swarmctl evolution-draft-result`
affects: []
tech-stack:
  added:
    - serde-backed draft reports and index files
  patterns:
    - draft creation stays deterministic and operator-triggered
    - draft artifacts remain separate from queue proposals until explicit promotion
key-files:
  modified:
    - crates/swarm-runtime/src/drafting.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Use operator-supplied strategy, mutation, and rationale hints instead of auto-generating candidate strategy IDs."
  - "Keep draft creation free of queue side effects so the operator can inspect or discard draft artifacts later."
patterns-established:
  - "Selection pressure now packages into draft artifacts before reviewed queue entry."
requirements-completed:
  - DRAFT-03
duration: 18min
completed: 2026-04-03
---

# Phase 36: Proposal Draft Artifacts Summary

**The runtime now persists stable proposal drafts that combine one pressure report with explicit operator hints, without auto-enqueueing the draft into the evolution queue.**

## Performance

- **Duration:** 18 min
- **Completed:** 2026-04-04T02:43:15Z
- **Tasks:** 4
- **Files modified:** 3

## Accomplishments

- Added `EvolutionDraftReport`, `EvolutionDraftRecord`, and `FileEvolutionDraftStore` in `crates/swarm-runtime/src/drafting.rs`.
- Implemented deterministic draft packaging from one pressure report plus operator-provided strategy and lineage hints.
- Added `swarmctl evolution-draft-create` and `evolution-draft-result`.
- Covered draft persistence and reload through focused runtime tests.

## Decisions Made

- Drafts preserve operator intent as explicit fields instead of hiding it inside free-form notes.
- Draft storage stays separate from queue storage so later queue promotion remains explicit and auditable.
- Drafts inherit source evidence references from the originating pressure report instead of re-synthesizing them.

## Deviations from Plan

None. The shipped implementation matches the planned storage, deterministic packaging, and reload surface.

## Issues Encountered

No blockers.

## User Setup Required

Inspect the shipped draft workflow docs:

```bash
sed -n '504,575p' docs/CONFIGURATION.md
```

## Next Phase Readiness

Phase 37 can now promote one stable draft into the reviewed queue because draft artifacts preserve both the pressure linkage and the operator-supplied lineage hints needed for queue entry.

---
*Phase: 36-proposal-draft-artifacts*
*Completed: 2026-04-03*
