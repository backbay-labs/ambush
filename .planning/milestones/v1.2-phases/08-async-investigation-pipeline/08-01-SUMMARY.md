---
phase: 08-async-investigation-pipeline
plan: 01
subsystem: investigation
tags:
  - async
  - enrichment
  - bundles
  - durability
one-liner: The runtime can now queue deterministic investigation work off persisted replay bundles and persist durable investigation outcomes without blocking the hot path.
requires:
  - 06-persistent-audit-and-replay
  - 07-operator-visibility
provides:
  - Repository-owned investigation configuration
  - Durable investigation bundle storage
  - Background investigation queue with timeout and failure visibility
affects: []
tech-stack:
  added: []
  patterns:
    - queue-backed async enrichment off replay bundles
    - durable status transitions for background work
key-files:
  created:
    - crates/swarm-spine/src/investigation.rs
    - crates/swarm-runtime/src/investigation.rs
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/src/service.rs
    - crates/swarm-spine/src/lib.rs
    - crates/swarm-spine/src/store.rs
    - rulesets/default.yaml
key-decisions:
  - "Investigation starts from persisted replay bundles rather than a new hot-path artifact."
  - "Queue rejection, timeout, and worker failures are visible async outcomes, not critical-lane errors."
patterns-established:
  - "swarm-spine now owns a second durable artifact family beside replay bundles."
  - "RuntimeService can layer adjacent async workflows on top of persisted critical-lane output."
requirements-completed:
  - INV-01
  - INV-02
  - INV-03
duration: 90min
completed: 2026-04-03
---

# Phase 8: Async Investigation Pipeline Summary

**The runtime now queues deterministic investigation work from persisted replay bundles and persists durable investigation outcomes without waiting on enrichment completion.**

## Performance

- **Duration:** 90 min
- **Started:** 2026-04-03T13:07:00Z
- **Completed:** 2026-04-03T14:37:25Z
- **Tasks:** 3
- **Files modified:** 8
- **Files created:** 2

## Accomplishments
- Added repository-owned `investigation` config with enablement, worker count, queue depth, time budget, and bundle-store selection.
- Added durable investigation bundle types plus memory and local-files investigation stores in `swarm-spine`.
- Added an async investigation coordinator in `swarm-runtime` with queued, running, completed, failed, and timed-out states.
- Integrated investigation submission into the persisted replay-bundle path without blocking the hot lane.
- Added tests proving nonblocking submission, receipt-linked retrieval, timeout handling, and visible queue-pressure failures.

## Decisions Made

- Replay bundles are the seed artifact for investigation because they already carry hunt, trail, finding, and receipt identifiers.
- The first investigator stays deterministic and summary-oriented so the milestone remains Rust-first and easy to verify.
- Async degradation is persisted as investigation status instead of bubbling up as a service failure.

## Deviations from Plan

None.

## Issues Encountered

File-backed store tests were using reusable temp paths and could fail after interrupted runs. The phase now clears those test roots up front.

## User Setup Required

If investigation durability is enabled with `local_files`, the configured directory must be writable by the runtime process.

## Next Phase Readiness

The runtime now has durable investigation bundles and stable correlation keys, which is enough to start incident assembly in Phase 9.

---
*Phase: 08-async-investigation-pipeline*
*Completed: 2026-04-03*
