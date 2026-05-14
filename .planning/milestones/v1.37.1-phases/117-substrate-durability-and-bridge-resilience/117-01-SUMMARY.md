---
phase: 117-substrate-durability-and-bridge-resilience
plan: 01
subsystem: pheromone
tags: [rust, gc, threat-intel, ttl, journal-compaction, btreemap, jetstream]

# Dependency graph
requires:
  - phase: 116-agent-safety-hardening
    provides: signed deposits and tick timeout hardening
provides:
  - gc_expired_threat_intel() on PheromoneSubstrate trait
  - InMemory threat-intel GC with BTreeMap retain
  - LocalJournal threat-intel GC with journal file rewrite (compaction)
  - JetStream threat-intel GC with KV store key deletion
  - ConfiguredPheromoneSubstrate dispatch for all three backends
  - Structured tracing logs for purge counts
affects: [swarm-runtime, pheromone-gc-scheduling, 117-02]

# Tech tracking
tech-stack:
  added: []
  patterns: [threat-intel GC follows same retain+rewrite pattern as deposit gc_evaporated]

key-files:
  created: []
  modified:
    - crates/swarm-pheromone/src/substrate.rs
    - crates/swarm-pheromone/src/jetstream.rs

key-decisions:
  - "Followed gc_evaporated pattern: retain in-memory then rewrite journal for LocalJournal"
  - "JetStream GC iterates all intel-prefixed keys and deletes expired entries individually"
  - "Structured logging: tracing::info for purged > 0, tracing::debug for zero-purge"

patterns-established:
  - "Threat-intel GC: acquire write lock, retain non-expired, rewrite journal, log purge count"
  - "JetStream intel GC: list keys by prefix, deserialize, check expires_at, delete if expired"

requirements-completed: [HARDEN-04, HARDEN-05]

# Metrics
duration: 5min
completed: 2026-04-07
---

# Phase 117 Plan 01: Threat-Intel GC Summary

**gc_expired_threat_intel() across all three pheromone backends with journal compaction and structured logging**

## Performance

- **Duration:** 5 min
- **Started:** 2026-04-07T23:06:31Z
- **Completed:** 2026-04-07T23:11:47Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Added gc_expired_threat_intel() to the PheromoneSubstrate trait and all three backends (InMemory, LocalJournal, JetStream)
- LocalJournal implementation rewrites the threat-intel journal file during GC to prevent unbounded disk growth (HARDEN-05)
- JetStream implementation iterates intel-prefixed keys and deletes expired entries from the KV store
- All 21 non-ignored tests pass, clippy clean, workspace builds green

## Task Commits

Each task was committed atomically:

1. **Task 1: Add gc_expired_threat_intel to PheromoneSubstrate trait and InMemory/LocalJournal/Configured implementations** - `9568b51` (feat)
2. **Task 2: Add gc_expired_threat_intel to JetStream backend and verify full workspace** - `51897cd` (test)

## Files Created/Modified
- `crates/swarm-pheromone/src/substrate.rs` - gc_expired_threat_intel on trait, InMemory impl, LocalJournal impl with rewrite_jsonl, Configured dispatch, 3 tests
- `crates/swarm-pheromone/src/jetstream.rs` - gc_expired_threat_intel on JetStream (nats + non-nats stubs), integration test

## Decisions Made
- Followed existing gc_evaporated pattern for consistency: retain in-memory then rewrite journal for LocalJournal
- JetStream GC iterates all intel-prefixed keys since there is no page-based indexing for threat-intel (unlike deposits)
- Used tracing::info for non-zero purge counts and tracing::debug for zero-purge to avoid log noise

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] JetStream stubs added in Task 1 instead of Task 2**
- **Found during:** Task 1 (compilation)
- **Issue:** Adding gc_expired_threat_intel to the trait required ALL implementations to exist for compilation. JetStream stubs were needed for Task 1 tests to compile.
- **Fix:** Added full JetStream implementation (nats + non-nats stubs) during Task 1 commit. Task 2 added the integration test.
- **Files modified:** crates/swarm-pheromone/src/jetstream.rs
- **Verification:** All tests compile and pass
- **Committed in:** 9568b51 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Structural necessity of Rust trait compilation. No scope creep -- same code, different commit boundary.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- gc_expired_threat_intel is ready for runtime scheduling (caller needs to invoke it periodically, similar to gc_evaporated)
- Phase 117-02 can proceed (bridge resilience)
- HARDEN-04 and HARDEN-05 audit findings are closed

---
*Phase: 117-substrate-durability-and-bridge-resilience*
*Completed: 2026-04-07*
