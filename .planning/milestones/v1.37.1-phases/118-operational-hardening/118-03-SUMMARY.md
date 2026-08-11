---
phase: 118-operational-hardening
plan: 03
subsystem: runtime
tags: [dead-letter, rotation, secret-rotation, config-threading, operational-hardening]

requires:
  - phase: 118-01
    provides: "reload_secrets_only() on IngestState for secret hot-rotation"
  - phase: 118-02
    provides: "DeadLetterJournal rotation when exceeding max_dead_letter_bytes"
provides:
  - "Production dead-letter journals receive max_dead_letter_bytes from RuntimeSettings"
  - "Integration test proving secret and dead-letter rotation work together without data loss"
affects: [swarm-response, swarm-runtime, operational-hardening]

tech-stack:
  added: []
  patterns: ["config-threading from RuntimeSettings through constructor chains"]

key-files:
  created:
    - "crates/swarm-runtime/tests/operational_hardening_integration.rs"
  modified:
    - "crates/swarm-response/src/dispatch.rs"
    - "crates/swarm-response/src/notification.rs"
    - "crates/swarm-runtime/src/service.rs"
    - "crates/swarm-runtime/tests/dispatch_integration.rs"
    - "crates/swarm-runtime/src/ingest.rs"

key-decisions:
  - "Added current_response_adapter_config() public accessor to IngestState to enable integration test verification of secret rotation"

patterns-established:
  - "Config threading: RuntimeSettings fields flow through constructor parameters rather than being resolved at point of use"

requirements-completed: [HARDEN-08, HARDEN-09]

duration: 9min
completed: 2026-04-07
---

# Phase 118 Plan 03: Gap Closure Summary

**Production-wired dead-letter rotation via max_dead_letter_bytes threading and integration test proving secret + dead-letter rotation cycle without data loss**

## Performance

- **Duration:** 9 min
- **Started:** 2026-04-07T23:46:22Z
- **Completed:** 2026-04-07T23:56:21Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- Threaded max_dead_letter_bytes from RuntimeSettings through DispatchingExecutor::from_config and NotificationRouter::new to production DeadLetterJournal constructors
- Removed all TODO comments for max_dead_letter_bytes threading (previously 3 across dispatch.rs and notification.rs)
- Created integration test proving both secret rotation (via reload_secrets_only) and dead-letter journal rotation work together in the same runtime context without data loss

## Task Commits

Each task was committed atomically:

1. **Task 1: Thread max_dead_letter_bytes from RuntimeSettings to production DeadLetterJournal constructors** - `b113a08` (feat)
2. **Task 2: Add integration test for secret rotation and dead-letter rotation cycling** - `8b76d70` (test)

## Files Created/Modified
- `crates/swarm-response/src/dispatch.rs` - DispatchingExecutor::from_config now accepts and threads max_dead_letter_bytes
- `crates/swarm-response/src/notification.rs` - NotificationRouter::new now accepts and threads max_dead_letter_bytes
- `crates/swarm-runtime/src/service.rs` - ConfiguredRuntimeStack::from_config and RuntimeService::new pass config.runtime.max_dead_letter_bytes
- `crates/swarm-runtime/tests/dispatch_integration.rs` - Updated all DispatchingExecutor::from_config call sites with None
- `crates/swarm-runtime/src/ingest.rs` - Added current_response_adapter_config() public accessor
- `crates/swarm-runtime/tests/operational_hardening_integration.rs` - Integration test for secret + dead-letter rotation

## Decisions Made
- Added current_response_adapter_config() accessor to IngestState to verify secret rotation from integration tests (private stack field otherwise inaccessible from external test files)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added current_response_adapter_config() accessor to IngestState**
- **Found during:** Task 2 (integration test creation)
- **Issue:** IngestState.stack field is private; integration tests cannot verify auth_token changed after secret rotation
- **Fix:** Added pub fn current_response_adapter_config() following existing pattern of current_pheromone_config()
- **Files modified:** crates/swarm-runtime/src/ingest.rs
- **Verification:** Integration test successfully verifies initial-token -> rotated-token transition
- **Committed in:** 8b76d70 (Task 2 commit)

**2. [Rule 1 - Bug] Fixed dead-letter rotation test to handle multiple rotation cycles**
- **Found during:** Task 2 (integration test creation)
- **Issue:** Initial test assumed exactly 1 rotated file, but entries exceeded threshold before expected count, causing 2 rotations
- **Fix:** Rewrote test to detect rotation dynamically and verify total entry count across all rotated files
- **Files modified:** crates/swarm-runtime/tests/operational_hardening_integration.rs
- **Verification:** Test passes reliably regardless of per-entry serialization size

---

**Total deviations:** 2 auto-fixed (1 blocking, 1 bug)
**Impact on plan:** Both fixes necessary for test correctness. No scope creep.

## Issues Encountered
None - plan executed cleanly once deviations were handled.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Phase 118 (Operational Hardening) is now fully complete with all gaps closed
- HARDEN-08 (secret hot-rotation) and HARDEN-09 (dead-letter journal rotation) are production-wired and integration-tested
- Ready for Phase 119 (Pheromone Test Suite, HARDEN-10)

---
*Phase: 118-operational-hardening*
*Completed: 2026-04-07*
