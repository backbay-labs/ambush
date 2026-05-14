---
phase: 117-substrate-durability-and-bridge-resilience
plan: 02
subsystem: ingest
tags: [grpc, timeout, tetragon, bridge, sentinel, schema-validation]

requires:
  - phase: 117-01
    provides: "pheromone durability foundations and substrate hardening"
provides:
  - "Stream timeout on TetragonBridge::poll() with configurable event_timeout_secs"
  - "Sentinel '<none>' for missing or empty parent_process in Tetragon mapper"
  - "Relaxed schema validation accepting parentless init-spawned processes"
affects: [118-operational-hardening, 119-pheromone-test-suite]

tech-stack:
  added: []
  patterns: ["tokio::time::timeout wrapping async stream reads for reconnect-on-silence"]

key-files:
  created: []
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-ingest-tetragon/src/bridge.rs
    - crates/swarm-ingest-tetragon/src/mapper.rs
    - crates/swarm-runtime/src/bridge_runtime.rs

key-decisions:
  - "30-second default event_timeout_secs per HARDEN-06 spec"
  - "Sentinel '<none>' chosen over Option<String> to preserve ProcessStartEvent shape"
  - "Schema validation fully removes parent_process check rather than checking for sentinel"

patterns-established:
  - "Stream timeout pattern: wrap stream.next().await in tokio::time::timeout for reconnect-on-silence"
  - "Sentinel value pattern: use '<none>' for missing optional string fields in normalized telemetry"

requirements-completed: [HARDEN-06, HARDEN-07]

duration: 6min
completed: 2026-04-07
---

# Phase 117 Plan 02: Bridge Resilience Summary

**Stream timeout on TetragonBridge poll() with 30s configurable event_timeout_secs, and sentinel parent_process for init-spawned processes**

## Performance

- **Duration:** 6 min
- **Started:** 2026-04-07T23:06:35Z
- **Completed:** 2026-04-07T23:12:56Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- TetragonBridge::poll() now wraps stream.next() in tokio::time::timeout, triggering reconnect-backoff after configurable silence period (default 30s)
- Mapper produces "<none>" sentinel for missing or empty parent_process instead of empty string
- Schema validation no longer rejects parentless processes (init-spawned, systemd units)
- Config plumbed end-to-end: TetragonBridgeConfig -> BridgeConfig -> runtime mapping

## Task Commits

Each task was committed atomically:

1. **Task 1: Add event_timeout_secs config, stream timeout in poll(), and empty-parent fix** - `0b68430` (feat)
2. **Task 2: Add tests for stream timeout and empty-parent handling** - `d8d28aa` (test)

## Files Created/Modified
- `crates/swarm-core/src/config.rs` - Added event_timeout_secs field, serde default (30), validation (>0)
- `crates/swarm-ingest-tetragon/src/bridge.rs` - Timeout wrap in poll(), relaxed schema validation, new tests
- `crates/swarm-ingest-tetragon/src/mapper.rs` - Sentinel substitution for empty parent, updated and new tests
- `crates/swarm-runtime/src/bridge_runtime.rs` - Pass event_timeout_secs through config mapping

## Decisions Made
- 30-second default for event_timeout_secs aligns with HARDEN-06 audit spec
- Used sentinel string "<none>" rather than changing ProcessStartEvent to Option<String> -- preserves field shape across all consumers
- Completely removed parent_process from schema validation rather than checking for sentinel -- init-spawned processes legitimately have no parent

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- Pre-existing build failure in swarm-pheromone (missing gc_expired_threat_intel trait impl on JetStreamPheromoneSubstrate) prevents full `cargo build --workspace` from passing; confirmed unrelated to this plan's changes by building affected crates individually
- Pre-existing test failures in swarm-runtime (reload_secrets_only not yet implemented, evolution_queue_blocks_missing_proof) confirmed unrelated

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Phase 117 complete (both plans executed): substrate durability and bridge resilience hardened
- HARDEN-04 through HARDEN-07 closed
- Ready for Phase 118 (Operational Hardening) or Phase 119 (Pheromone Test Suite)

---
*Phase: 117-substrate-durability-and-bridge-resilience*
*Completed: 2026-04-07*
