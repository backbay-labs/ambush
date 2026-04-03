---
phase: 01-baseline-contracts
plan: 01
subsystem: infra
tags:
  - config
  - runtime
  - serde
  - yaml
requires: []
provides:
  - Strict runtime-owned YAML config contract for the v1 Rust lane
  - Repository config loading with validation and test coverage
affects:
  - fast-detection-lane
  - safe-live-response
tech-stack:
  added:
    - serde_yaml
  patterns:
    - strict repository-owned config loading
    - explicit runtime mode enum
key-files:
  created: []
  modified:
    - Cargo.toml
    - crates/swarm-core/src/config.rs
    - crates/swarm-runtime/Cargo.toml
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/src/service.rs
    - rulesets/default.yaml
key-decisions:
  - "Replaced the legacy swarm-population/BFT config with a runtime-owned v1 contract."
  - "Made runtime mode a typed enum shared between config loading and runtime behavior."
patterns-established:
  - "Repository configs deserialize with deny_unknown_fields and then run semantic validation."
requirements-completed:
  - CFG-01
  - CFG-02
  - CFG-03
duration: 20min
completed: 2026-04-02
---

# Phase 1: Baseline Contracts Summary

**Strict YAML-backed runtime contracts now define the Rust-first v1 slice and load cleanly from the repository ruleset.**

## Performance

- **Duration:** 20 min
- **Started:** 2026-04-02T00:00:00Z
- **Completed:** 2026-04-02T00:20:00Z
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments
- Replaced the legacy config scaffold with a typed `SwarmConfig` centered on runtime, detection, pheromone, and policy settings.
- Added repository config loading via `serde_yaml` with actionable parse and validation errors.
- Added tests for the default ruleset, unknown-field rejection, invalid runtime modes, and explicit `live_response` support.

## Task Commits

Each task was committed atomically:

1. **Task 1: Define runtime config contract** - `e98462a` (feat)

**Plan metadata:** `4009db9` (docs: phase contexts and plans)

## Files Created/Modified
- `Cargo.toml` - Added workspace `serde_yaml`.
- `crates/swarm-core/src/config.rs` - Replaced legacy config types with the v1 runtime contract and semantic validation.
- `crates/swarm-runtime/Cargo.toml` - Added runtime YAML parsing dependency.
- `crates/swarm-runtime/src/config.rs` - Added file loading, parse helpers, and config tests.
- `crates/swarm-runtime/src/lib.rs` - Reused the shared runtime mode enum.
- `crates/swarm-runtime/src/service.rs` - Aligned service config type with the new runtime settings.
- `rulesets/default.yaml` - Replaced the legacy swarm mission schema with the v1 Rust runtime ruleset.

## Decisions Made

- `swarm-runtime` owns config loading while `swarm-core` owns the reusable config contract types.
- Unknown YAML fields fail during deserialization; semantic issues fail during explicit validation.
- The default ruleset now reflects the Rust-first vertical slice instead of the earlier multi-agent/BFT shape.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

`RuntimeService` still referenced the old config type name after the loader rewrite. The service was updated to consume the new runtime settings type and tests then passed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Phase 2 can now rely on a stable repository config contract and explicit runtime mode semantics.

---
*Phase: 01-baseline-contracts*
*Completed: 2026-04-02*
