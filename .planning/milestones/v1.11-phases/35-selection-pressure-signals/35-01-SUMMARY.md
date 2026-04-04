---
phase: 35-selection-pressure-signals
plan: 01
subsystem: evolution-drafting
tags:
  - evolution
  - drafting
  - runtime
  - cli
one-liner: Added durable selection-pressure reports derived from replay regressions, verification drift, and strategy-memory gaps.
requires:
  - 34-canary-launch-from-handoff
provides:
  - file-backed pressure storage rooted under `data/evolution-pressures/`
  - stable pressure reports sourced from experiment, verification, or scorecard evidence
  - stable-ID reload through `swarmctl evolution-pressure-result`
affects: []
tech-stack:
  added:
    - serde-backed pressure reports and index files
  patterns:
    - selection pressure remains off the hot path and CLI-first
    - replay, verification, and strategy-memory artifacts are reused instead of duplicated
key-files:
  modified:
    - crates/swarm-runtime/src/drafting.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Keep pressure analysis in a separate module so the existing verified queue and handoff code stays stable."
  - "Derive pressure from persisted experiment, verification, and scorecard artifacts instead of raw scenario files."
  - "Block pressure creation when the selected artifact shows no drafting pressure."
patterns-established:
  - "The evolution lane now has a repo-owned drafting precursor: evidence -> pressure report -> draft -> reviewed queue."
requirements-completed:
  - DRAFT-01
  - DRAFT-02
duration: 24min
completed: 2026-04-03
---

# Phase 35: Selection Pressure Signals Summary

**The runtime now persists selection-pressure reports that explain why additional detector work is warranted, using replay regressions, verification drift, or strategy-memory gaps as durable evidence.**

## Performance

- **Duration:** 24 min
- **Completed:** 2026-04-04T02:43:15Z
- **Tasks:** 4
- **Files modified:** 3

## Accomplishments

- Added `EvolutionPressureReport`, `EvolutionPressureRecord`, and `FileEvolutionPressureStore` in `crates/swarm-runtime/src/drafting.rs`.
- Implemented pressure derivation from persisted experiment, verification, and scorecard artifacts.
- Added `swarmctl evolution-pressure-create` and `evolution-pressure-result`.
- Covered pressure persistence with focused runtime tests.

## Decisions Made

- Pressure reports are stored separately from queue proposals so evidence review remains explicit and auditable.
- Strategy scorecards are treated as the strategy-memory entry point because they already preserve live-memory context and fallback state.
- Selection pressure is rejected when the chosen artifact is healthy enough that no new draft is justified.

## Deviations from Plan

The phase uses one shared `DefaultEvolutionDraftingHarness` for pressure, draft, and promotion flows rather than three separate harnesses. That kept the new off-hot-path drafting lane cohesive without changing the existing queue implementation.

## Issues Encountered

No material blockers. The only adjustment was keeping the new workflow in its own module so `evolution.rs` did not keep expanding.

## User Setup Required

Inspect the shipped drafting workflow docs:

```bash
sed -n '504,575p' docs/CONFIGURATION.md
```

## Next Phase Readiness

Phase 36 can now package stable draft artifacts because pressure reports preserve the evidence references and rationale required for deterministic draft creation.

---
*Phase: 35-selection-pressure-signals*
*Completed: 2026-04-03*
