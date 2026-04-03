---
phase: 28-strategy-review-and-advisory-selection
plan: 01
subsystem: strategy-review
tags:
  - strategy-memory
  - scorecard
  - operator
  - cli
  - docs
one-liner: Operators can now ingest rollout evidence into strategy memory, inspect strategy history, and assemble advisory baseline-vs-candidate scorecards through `swarmctl`.
requires:
  - 27-context-aware-utility-scoring
provides:
  - durable strategy-scorecard records keyed by stable scorecard ID
  - CLI review workflow for memory ingest, history lookup, scorecard creation, and scorecard reload
  - operator docs for artifact directories and advisory-only semantics
affects: []
tech-stack:
  added: []
  patterns:
    - operator review remains CLI-first and stable-ID based
    - advisory selection uses durable artifacts instead of mutable in-memory state
    - memory-backed review does not widen rollout authority
key-files:
  created: []
  modified:
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - crates/swarm-runtime/src/strategy.rs
    - docs/CONFIGURATION.md
    - .gitignore
key-decisions:
  - "Expose memory ingest and scorecard creation through the existing `swarmctl` surface instead of adding a parallel operator tool."
  - "Persist scorecards under stable IDs so recommendations and breakdowns can be reloaded after the original rollout artifacts are no longer top of mind."
  - "Document the advisory-only boundary directly in operator docs so memory scoring is not mistaken for autonomous promotion."
patterns-established:
  - "Operator review now progresses by durable IDs all the way from experiment evidence to advisory scorecard."
requirements-completed:
  - MEM-06
  - MEM-07
duration: 30min
completed: 2026-04-03
---

# Phase 28: Strategy Review And Advisory Selection Summary

**The runtime now exposes a complete memory-backed advisory review surface: operators can create memories from rollout artifacts, inspect per-strategy histories, assemble scorecards, and reload those scorecards later through stable IDs.**

## Performance

- **Duration:** 30 min
- **Completed:** 2026-04-03T21:50:18Z
- **Tasks:** 4
- **Files modified:** 4

## Accomplishments

- Added durable strategy-scorecard records with stable IDs and reload support.
- Extended `swarmctl` with strategy memory ingest, memory reload, history, scorecard creation, and scorecard reload commands.
- Documented the new artifact directories and operator flow in `docs/CONFIGURATION.md`.
- Verified the full review surface by driving verification, shadow, canary, promotion, memory ingest, and scorecard creation in one CLI-backed flow.

## Decisions Made

- The operator review seam stays in `swarmctl`; there is no separate strategy-selection binary or service.
- Scorecards render both baseline and candidate breakdowns explicitly instead of flattening to one opaque score.
- Recommendations are phrased as advisory outcomes such as `retain_baseline`, `candidate_preferred`, and `candidate_already_stable_in_production`.

## Deviations from Plan

The first operator flow uses CLI subcommands and durable artifact directories only; it does not introduce an authenticated HTTP or TUI surface. That remains future work and keeps the review lane aligned with the rest of the shipped runtime.

## Issues Encountered

The initial end-to-end verification script assumed a flat `candidate_score` field, but the shipped scorecard structure is intentionally richer: baseline and candidate breakdowns are nested under `baseline` and `candidate`.

## User Setup Required

Read the shipped strategy-memory and strategy-scorecard workflow section:

```bash
sed -n '452,506p' docs/CONFIGURATION.md
```

## Next Phase Readiness

`v1.8` is complete. The next cycle can choose governance, richer operator surfaces, or proof-backed evolution from a stronger shipped baseline.

---
*Phase: 28-strategy-review-and-advisory-selection*
*Completed: 2026-04-03*
