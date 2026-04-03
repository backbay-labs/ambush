---
phase: 05-durable-substrate
plan: 01
subsystem: persistence
tags:
  - config
  - substrate
  - durability
  - readiness
one-liner: Self-contained local-journal substrate durability now survives restart and live-response mode fails closed when durability is required.
requires: []
provides:
  - Configurable in-memory vs local-journal substrate backends
  - Restart-safe pheromone recovery and filtered deposit queries
  - Fail-closed live-response durability gating
affects:
  - persistent-audit-and-replay
  - operator-visibility
tech-stack:
  added: []
  patterns:
    - repository-owned backend selection
    - journal-backed durability
    - fail-closed readiness checks
key-files:
  created: []
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-pheromone/src/lib.rs
    - crates/swarm-pheromone/src/substrate.rs
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/service.rs
    - rulesets/default.yaml
key-decisions:
  - "Chose a repo-owned local journal backend over JetStream for the first durable single-node milestone."
  - "Kept detector and policy code behind the existing substrate trait despite backend expansion."
patterns-established:
  - "Durability requirements are expressed in config and enforced at runtime readiness boundaries."
requirements-completed:
  - CFG-04
  - DUR-01
  - DUR-02
  - DUR-03
  - DUR-04
duration: 35min
completed: 2026-04-03
---

# Phase 5: Durable Substrate Summary

**The runtime can now choose a durable local-journal substrate, recover deposits after restart, and reject unsafe live-response startup when durability is required.**

## Performance

- **Duration:** 35 min
- **Started:** 2026-04-03T04:50:00Z
- **Completed:** 2026-04-03T05:25:00Z
- **Tasks:** 3
- **Files modified:** 9

## Accomplishments
- Extended the config contract with backend selection, audit defaults, and durable-live-response semantics.
- Replaced the substrate stub with a real local-journal backend that supports recovery, filtered queries, and health reporting.
- Added runtime readiness checks so `live_response` can fail closed when a durable substrate is required but unavailable.

## Files Created/Modified
- `crates/swarm-core/src/config.rs` - Added backend selection and durability validation.
- `crates/swarm-pheromone/src/substrate.rs` - Added local-journal persistence, query filters, health, and configurable backend wrapper.
- `crates/swarm-runtime/src/config.rs` - Added config tests for durable-live-response validation.
- `crates/swarm-runtime/src/service.rs` - Added substrate readiness enforcement in the runtime service.
- `rulesets/default.yaml` - Added explicit durability-related defaults.

## Decisions Made

- Local file-backed journaling is the first durable substrate because it keeps the milestone self-contained and testable.
- Durability is a runtime contract, not just a docs claim, so readiness is checked before live-response processing.

## Deviations from Plan

The original milestone draft mentioned JetStream. The implementation deliberately chose a repo-owned local journal first to stay aligned with the Rust-only, self-contained milestone goal.

## Issues Encountered

Adding new config sections initially broke default validation because serde defaults were syntactically present but semantically invalid. The audit config now provides a valid default object.

## User Setup Required

Provide a writable journal path when using the local durable substrate backend.

## Next Phase Readiness

Persistent replay and audit storage can now build on the same self-contained durability posture rather than introducing an external storage dependency first.

---
*Phase: 05-durable-substrate*
*Completed: 2026-04-03*
