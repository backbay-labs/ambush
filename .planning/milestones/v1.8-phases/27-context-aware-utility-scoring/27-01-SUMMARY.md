---
phase: 27-context-aware-utility-scoring
plan: 01
subsystem: strategy-scoring
tags:
  - strategy-memory
  - scoring
  - advisory
  - runtime
one-liner: Verified strategies can now be ranked with deterministic context-aware utility scores that combine live rollout memory and replay-fitness fallback.
requires:
  - 26-strategy-outcome-memory
provides:
  - deterministic outcome, stage, recency, and context weighting over strategy memories
  - replay-fitness fallback when live memory is sparse
  - explicit score breakdowns with per-memory contribution details
affects: []
tech-stack:
  added:
    - advisory score breakdown model
  patterns:
    - live rollout memory is preferred when enough evidence exists
    - replay metrics keep baseline comparison available when live memory is sparse
    - strategy scoring remains advisory and detached from rollout mutation paths
key-files:
  created: []
  modified:
    - crates/swarm-runtime/src/strategy.rs
key-decisions:
  - "Use a minimum-live-memory threshold before trusting only rollout evidence."
  - "Blend explicit outcome weights, rollout stage weights, recency decay, and context matching instead of a single heuristic score."
  - "Keep utility scoring advisory only even when the candidate already has production memories."
patterns-established:
  - "Candidate ranking now combines rollout memory and replay evidence without widening promotion authority."
requirements-completed:
  - MEM-03
  - MEM-04
  - MEM-05
duration: 35min
completed: 2026-04-03
---

# Phase 27: Context-Aware Utility Scoring Summary

**The runtime now computes deterministic advisory utility scores from strategy memories, explains every contribution that shaped the final score, and falls back to replay fitness when live rollout evidence is not yet deep enough.**

## Performance

- **Duration:** 35 min
- **Completed:** 2026-04-03T21:50:18Z
- **Tasks:** 4
- **Files modified:** 1

## Accomplishments

- Added a strategy score breakdown model that records matching memory count, latest rollout state, replay fallback, and the final advisory score for both baseline and candidate detectors.
- Implemented deterministic scoring over strategy memories using explicit outcome weighting, rollout stage weighting, recency decay, and context matching.
- Added replay-fitness fallback so strategies with sparse or zero live memory remain comparable instead of being silently favored or excluded.
- Covered both live-memory and fallback paths with unit tests, including the case where the candidate is already stable in production.

## Decisions Made

- Strategy scoring requires a minimum live-memory threshold before it stops consulting replay fitness.
- Context matching uses persisted suite, corpus, reference strategy, and parent strategy fields so the score can explain why a memory matters.
- Advisory recommendations never mutate config or trigger rollout changes by themselves.

## Deviations from Plan

The first score model keeps baseline and candidate breakdowns in one scorecard artifact instead of creating a separate reusable scoring report type. That reduced bookkeeping while preserving explicit evidence and deterministic ranking behavior.

## Issues Encountered

The baseline detector often has no direct live memories because production evidence attaches to candidate strategy IDs. Replay-fitness fallback was required to keep baseline comparisons well-defined instead of producing empty or misleading rankings.

## User Setup Required

Inspect the strategy-scorecard commands and advisory-only notes:

```bash
sed -n '487,506p' docs/CONFIGURATION.md
```

## Next Phase Readiness

Phase 28 can now expose the new memory-backed scoring flow as a durable operator review surface through `swarmctl`.

---
*Phase: 27-context-aware-utility-scoring*
*Completed: 2026-04-03*
