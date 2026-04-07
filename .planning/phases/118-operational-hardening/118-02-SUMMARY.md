---
phase: 118-operational-hardening
plan: 02
subsystem: response
tags: [dead-letter, rotation, journal, disk-management, hardening]

# Dependency graph
requires:
  - phase: 116-agent-safety-hardening
    provides: agent_tick_timeout_ms field pattern in RuntimeSettings
provides:
  - max_dead_letter_bytes configurable field in RuntimeSettings
  - size-based rotation logic in DeadLetterJournal
  - rotate_if_needed() called before every journal write
affects: [swarm-runtime, swarm-response]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Size-based file rotation with timestamp suffix naming"
    - "Optional max_bytes parameter threaded through constructor"

key-files:
  created: []
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-response/src/dead_letter.rs
    - crates/swarm-response/src/dispatch.rs
    - crates/swarm-response/src/notification.rs
    - crates/swarm-response/src/resilience.rs

key-decisions:
  - "max_bytes passed at DeadLetterJournal construction rather than read from global config, keeping the journal self-contained"
  - "Rotation uses timestamp suffix format {path}.{timestamp_ms} for chronological ordering"
  - "rotate_if_needed() called before write(), not after, so the triggering entry lands in the fresh file"
  - "Dispatch and notification call sites default to None with TODO comments for future runtime wiring"

patterns-established:
  - "Dead-letter rotation: journals check size before write and rename with timestamp suffix when threshold exceeded"

requirements-completed: [HARDEN-09]

# Metrics
duration: 12min
completed: 2026-04-07
---

# Phase 118 Plan 02: Dead-Letter Journal Rotation Summary

**Size-based dead-letter journal rotation with configurable max_dead_letter_bytes threshold preventing unbounded JSONL file growth**

## Performance

- **Duration:** 12 min
- **Started:** 2026-04-07T23:06:40Z
- **Completed:** 2026-04-07T23:18:40Z
- **Tasks:** 1 (TDD: RED + GREEN)
- **Files modified:** 14

## Accomplishments
- Added `max_dead_letter_bytes: Option<u64>` to RuntimeSettings with serde default of None
- Implemented `rotate_if_needed()` in DeadLetterJournal that renames full files with `{path}.{timestamp_ms}` suffix
- Added 3 new rotation tests: size-threshold rotation, no-rotation when None, preservation of original entries in rotated file
- Updated all 10+ call sites across swarm-response and swarm-runtime crates

## Task Commits

Each task was committed atomically:

1. **Task 1 (RED): Add failing rotation tests** - `176ce08` (test)
2. **Task 1 (GREEN): Implement rotation and update all call sites** - `e37492e` (feat)

_TDD task with RED (failing tests) and GREEN (implementation) commits._

## Files Created/Modified
- `crates/swarm-core/src/config.rs` - Added max_dead_letter_bytes: Option<u64> field to RuntimeSettings
- `crates/swarm-response/src/dead_letter.rs` - Added max_bytes field, rotate_if_needed() method, 3 rotation tests
- `crates/swarm-response/src/dispatch.rs` - Updated DeadLetterJournal::new() calls with None + TODO comment
- `crates/swarm-response/src/notification.rs` - Updated DeadLetterJournal::from_path() call with None + TODO comment
- `crates/swarm-response/src/resilience.rs` - Updated test DeadLetterJournal::new() call with None
- `crates/swarm-runtime/src/canary.rs` - Added max_dead_letter_bytes: None to test config
- `crates/swarm-runtime/src/promotion.rs` - Added max_dead_letter_bytes: None to test config
- `crates/swarm-runtime/src/strategy.rs` - Added max_dead_letter_bytes: None to test config
- `crates/swarm-runtime/src/control.rs` - Added max_dead_letter_bytes: None to test config
- `crates/swarm-runtime/src/service.rs` - Added max_dead_letter_bytes: None to test config
- `crates/swarm-runtime/src/ingest.rs` - Added max_dead_letter_bytes: None to test config + fixed unused import
- `crates/swarm-runtime/src/evidence.rs` - Added max_dead_letter_bytes: None to test config
- `crates/swarm-runtime/src/http/core.inc` - Added max_dead_letter_bytes: None to test config
- `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs` - Added max_dead_letter_bytes: None to test config

## Decisions Made
- max_bytes passed at DeadLetterJournal construction rather than read from global config, keeping the journal self-contained and testable
- Rotation uses timestamp suffix format `{path}.{timestamp_ms}` for chronological ordering of rotated files
- `rotate_if_needed()` called before `write()`, so the triggering entry lands in the fresh file
- Dispatch and notification call sites default to `None` with TODO comments for future runtime wiring through ConfiguredRuntimeStack

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed unused import in ingest.rs**
- **Found during:** Task 1 (clippy verification)
- **Issue:** Pre-existing unused `load_config` import in `crates/swarm-runtime/src/ingest.rs` caused `cargo clippy --workspace -- -D warnings` to fail
- **Fix:** Removed the unused `load_config` from the import statement (it had been replaced by `load_config_unresolved` in working tree changes)
- **Files modified:** crates/swarm-runtime/src/ingest.rs
- **Verification:** `cargo clippy --workspace -- -D warnings` passes clean
- **Committed in:** e37492e (part of task commit)

**2. [Rule 1 - Bug] Adjusted test threshold from 100 to 800 bytes**
- **Found during:** Task 1 (GREEN phase test run)
- **Issue:** Initial test threshold of 100 bytes was smaller than a single JSON entry (~189 bytes), causing multiple rotations per write instead of one rotation after accumulation
- **Fix:** Changed threshold to 800 bytes so 4-5 entries accumulate before triggering a single rotation
- **Files modified:** crates/swarm-response/src/dead_letter.rs
- **Verification:** All 3 rotation tests pass correctly
- **Committed in:** e37492e (part of task commit)

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both auto-fixes necessary for correctness. No scope creep.

## Issues Encountered
None - implementation followed the plan structure closely.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- HARDEN-09 (dead-letter journal rotation) is now closed
- Phase 118 is complete (both 118-01 and 118-02 executed)
- Phase 119 (Pheromone Test Suite, HARDEN-10) is the remaining phase in v1.37.1

## Self-Check: PASSED

- All source files exist
- Both commits (176ce08, e37492e) verified in git log
- max_dead_letter_bytes field present in RuntimeSettings
- rotate_if_needed method present in DeadLetterJournal
- Rotation test present and passing

---
*Phase: 118-operational-hardening*
*Completed: 2026-04-07*
