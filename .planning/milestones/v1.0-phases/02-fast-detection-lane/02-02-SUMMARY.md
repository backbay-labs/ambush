---
phase: 02-fast-detection-lane
plan: 02
subsystem: substrate
tags:
  - pheromone
  - runtime
  - benchmark
provides:
  - In-memory pheromone substrate with replay support
  - Detector-to-substrate runtime pipeline
  - Published fast-path benchmark artifact
affects:
  - safe-live-response
  - audit-and-hardening
tech-stack:
  added: []
  patterns:
    - append-only in-memory substrate with replay window
    - release-mode benchmark artifact checked into docs
key-files:
  created:
    - crates/swarm-runtime/examples/fast_detection_bench.rs
    - docs/benchmarks/fast-detection.md
  modified:
    - crates/swarm-pheromone/src/lib.rs
    - crates/swarm-pheromone/src/substrate.rs
    - crates/swarm-runtime/src/pipeline.rs
key-decisions:
  - "Keep the first substrate in memory and replayable instead of introducing JetStream."
patterns-established:
  - "Runtime pipeline deposits findings through a substrate trait and returns typed outcomes."
requirements-completed:
  - DET-04
  - SUB-01
  - SUB-02
  - SUB-03
duration: 25min
completed: 2026-04-02
---

# Phase 2: Fast Detection Lane Summary

**Detector findings now flow into a real in-memory pheromone substrate, and the hot path has published release-mode latency numbers.**

## Performance

- **Duration:** 25 min
- **Started:** 2026-04-02T00:55:00Z
- **Completed:** 2026-04-02T01:20:00Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments
- Implemented `InMemoryPheromoneSubstrate` with deposit, concentration query, replay window, and evaporation garbage collection.
- Added `detect_and_deposit` runtime wiring for the detector-to-substrate path.
- Added a release-mode benchmark example and published p50/p95/p99 plus throughput numbers.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add in-memory substrate and benchmark** - `76f067a` (feat)

**Plan metadata:** `4009db9` (docs: phase contexts and plans)

## Files Created/Modified
- `crates/swarm-pheromone/src/lib.rs` - Re-exported the substrate trait and in-memory implementation.
- `crates/swarm-pheromone/src/substrate.rs` - Added the in-memory substrate contract and tests.
- `crates/swarm-runtime/src/pipeline.rs` - Added detector-to-substrate pipeline wiring and tests.
- `crates/swarm-runtime/examples/fast_detection_bench.rs` - Added the release-mode benchmark harness.
- `docs/benchmarks/fast-detection.md` - Published the measured hot-path numbers.

## Decisions Made

- Replay is provided by retaining recent deposits in memory for the v1 slice.
- The benchmark measures detector evaluation plus finding-to-deposit conversion and in-memory deposit.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

The substrate concentration query needed an explicit `f64` type annotation for the peak-confidence accumulator. After adding that annotation, the full phase-2 crate test set passed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Phase 3 can now consume real findings and pheromone deposits when evaluating response proposals.

---
*Phase: 02-fast-detection-lane*
*Completed: 2026-04-02*
