---
phase: 120-composite-detector-and-config-migration
plan: 01
subsystem: runtime
tags: [rust, detection, composite-detector, config, serde, control-plane]
requires: []
provides:
  - Composite detector composition for multi-strategy evaluation
  - Detection config support for `strategies` with legacy fallback to `strategy`
  - Control-plane factory path that builds composite detectors from config
affects: [121-network-detector, 122-cross-strategy-signals, runtime-control, replay-config]
tech-stack:
  added: []
  patterns: [composite detection strategy, legacy config fallback, profile validation across active strategies]
key-files:
  created: [crates/swarm-whisker/src/composite.rs]
  modified:
    [
      crates/swarm-core/src/config.rs,
      crates/swarm-whisker/src/lib.rs,
      crates/swarm-runtime/src/control.rs,
      crates/swarm-runtime/src/config.rs,
      rulesets/default.yaml,
    ]
key-decisions:
  - "DetectionConfig.active_strategies() prefers the new strategies list and falls back to the legacy strategy scalar for backward compatibility."
  - "DefaultControlPlane now stores a CompositeDetector while the legacy SupportedDetector API stays in place for existing runtime callers."
patterns-established:
  - "Composite detector construction happens at the control-plane boundary from config-selected strategies."
  - "Multi-strategy profile validation iterates all active strategies before detector construction."
requirements-completed: [COMPOSE-01, COMPOSE-02]
duration: 7min
completed: 2026-04-08
---

# Phase 120 Plan 01: Composite Detector And Config Migration Summary

**Composite detector composition with multi-strategy config fallback and control-plane factory wiring**

## Performance

- **Duration:** 7 min
- **Started:** 2026-04-08T01:29:26Z
- **Completed:** 2026-04-08T01:36:04Z
- **Tasks:** 2
- **Files modified:** 15

## Accomplishments
- Added `CompositeDetector` in `swarm-whisker` with unit coverage for zero-strategy, multi-strategy, and stable identifier behavior.
- Extended `DetectionConfig` with `strategies` plus `active_strategies()` so legacy single-strategy configs still parse unchanged.
- Switched `DefaultControlPlane` to construct composite detectors from config while keeping `SupportedDetector` available for legacy runtime paths.

## Task Commits

Each task was committed atomically:

1. **Task 1: CompositeDetector type and DetectionConfig migration** - `a167f13` (feat)
2. **Task 2: Composite detector factory and SupportedDetector retirement** - `bcd211f` (feat)

## Files Created/Modified
- `crates/swarm-whisker/src/composite.rs` - Composite detector implementation and unit tests.
- `crates/swarm-core/src/config.rs` - Multi-strategy config field, fallback accessor, and config parsing tests.
- `crates/swarm-runtime/src/control.rs` - Composite detector factory and control-plane migration.
- `crates/swarm-runtime/src/config.rs` - Validation helper for all active detector profiles.
- `rulesets/default.yaml` - Documented multi-strategy config syntax without changing the active default.

## Decisions Made
- Kept `SupportedDetector` and `supported_detector()` intact so Plan 02 can migrate remaining runtime and replay callers incrementally.
- Validated all active detector profiles before composite construction so multi-strategy configs fail fast on invalid overrides.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Updated direct `DetectionConfig` fixtures across runtime tests**
- **Found during:** Task 2 (Composite detector factory and SupportedDetector retirement)
- **Issue:** Adding `DetectionConfig.strategies` broke multiple workspace test builders that construct configs directly.
- **Fix:** Added `strategies: Vec::new()` to affected runtime fixtures so the workspace still compiles against the migrated config contract.
- **Files modified:** `crates/swarm-runtime/src/canary.rs`, `crates/swarm-runtime/src/evidence.rs`, `crates/swarm-runtime/src/service.rs`, `crates/swarm-runtime/src/ingest.rs`, `crates/swarm-runtime/src/strategy.rs`, `crates/swarm-runtime/src/http/core.inc`, `crates/swarm-runtime/src/promotion.rs`, `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs`, `crates/swarm-runtime/tests/operational_hardening_integration.rs`
- **Verification:** `cargo clippy --workspace -- -D warnings` passed after the fixture updates.
- **Committed in:** `bcd211f`

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** The deviation was required to keep the workspace compiling after the config migration. No scope change to runtime behavior.

## Issues Encountered
- `cargo test --workspace` did not reach a clean pass. After the detector/config changes, unrelated high-level runtime tests in `evolution`, `portfolio`, and `selection` still failed due `office_baseline_control` verification paths resolving to blocked states. This was outside the plan surface, so it was not expanded into broader governance/replay work.
- `cargo test --workspace -- --test-threads=1` reduced the failure set but still left the same unrelated high-level areas failing.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Composite detector construction and config migration are in place for downstream runtime wiring.
- Plan 02 can now migrate remaining runtime paths from single-detector dispatch to composed evaluation.

## Self-Check: PASSED
- Found `.planning/phases/120-composite-detector-and-config-migration/120-01-SUMMARY.md`.
- Found task commits `a167f13` and `bcd211f` in git history.
