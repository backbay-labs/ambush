---
phase: 122-cross-strategy-pheromone-signals-and-rollout-scoping
plan: 01
subsystem: runtime
tags: [pheromone, correlation, escalation, multi-detector, signed-deposits]
requires:
  - phase: 120-composite-detector-and-config-migration
    provides: composite detector findings with stable strategy identifiers across runtime and rollout flows
provides:
  - strategy-scoped whisker deposit identities shared by live runtime and rollout-preview deposits
  - weighted correlation scoring that ignores raw strategy-key inflation and gates on real overlap
  - escalation and pipeline regressions for cross-strategy distinct-source behavior
affects:
  - 123-multi-strategy-integration-proof
  - canary
  - promotion
tech-stack:
  added: []
  patterns:
    - strategy-scoped deposit identity via `{base_agent_id}:{strategy_id}`
    - weighted incident correlation using non-strategy overlap plus bounded cross-strategy bonus
key-files:
  created:
    - .planning/phases/122-cross-strategy-pheromone-signals-and-rollout-scoping/122-01-SUMMARY.md
  modified:
    - crates/swarm-whisker/src/stream.rs
    - crates/swarm-runtime/src/detection/pipeline.rs
    - crates/swarm-runtime/src/correlation.rs
    - crates/swarm-pheromone/src/substrate.rs
    - crates/swarm-runtime/tests/escalation_integration.rs
    - crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs
key-decisions:
  - Reused `swarm_whisker::stream` as the single source of truth for strategy-scoped deposit IDs so canary and promotion preview deposits stay aligned with live runtime deposits.
  - Left substrate concentration math unchanged and made cross-strategy escalation emerge from the scoped `agent_id` values plus regression coverage.
  - Preserved existing completion and time-window rejection reasons while adding weighted-score explanations for correlation decisions.
patterns-established:
  - "Deposit identity pattern: compute the final strategy-scoped `agent_id` before signing or persistence."
  - "Correlation pattern: require at least one shared non-strategy key, then add a `+1` bonus only when bundle strategies differ."
requirements-completed: [COMPOSE-03, COMPOSE-04]
duration: 36min
completed: 2026-04-08
---

# Phase 122 Summary

**Strategy-scoped whisker deposit IDs now drive distinct-source escalation, and incident correlation favors real cross-strategy corroboration over raw `strategy:*` overlap**

## Performance

- **Duration:** 36 min
- **Started:** 2026-04-08T03:24:00Z
- **Completed:** 2026-04-08T04:00:20Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Added `strategy_scoped_agent_id` in `swarm-whisker` and applied it to both runtime deposits and rollout-preview deposits before signing.
- Reworked correlation scoring to ignore raw `strategy:*` overlap, require one real shared key, and apply a bounded cross-strategy bonus with human-readable reasons.
- Added regression coverage proving cross-strategy findings from one base whisker agent escalate, while same-strategy duplication still collapses to one source.

## Task Commits

No task commits were created in this run. Changes are left as local workspace edits for review.

## Files Created/Modified

- `.planning/phases/122-cross-strategy-pheromone-signals-and-rollout-scoping/122-01-SUMMARY.md` - execution summary, deviations, and verification notes
- `crates/swarm-whisker/src/stream.rs` - shared strategy-scoped agent ID helper and deposit conversion tests
- `crates/swarm-runtime/src/detection/pipeline.rs` - runtime deposit scoping before signing plus signature-validating pipeline coverage
- `crates/swarm-runtime/src/correlation.rs` - weighted cross-strategy pair scoring and updated correlation tests
- `crates/swarm-pheromone/src/substrate.rs` - distinct-source regression tests for strategy-scoped agent IDs
- `crates/swarm-runtime/tests/escalation_integration.rs` - cross-strategy escalation integration coverage and same-strategy control case
- `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs` - strategy-aware whisker deposit assertions for the live pipeline

## Decisions Made

- Kept the substrate schema and concentration implementation unchanged; the feature is driven by strategy-scoped runtime deposit identities rather than substrate branching.
- Used full shared-key lists for stored incident decisions while computing inclusion thresholds from non-strategy overlap plus an optional cross-strategy bonus.
- Updated only the owned integration assertions for whisker deposits and left unrelated agent identity expectations untouched.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Corrected the pipeline test import path for signature validation**
- **Found during:** Verification after Task 1
- **Issue:** `validate_deposit_signature` is defined under `swarm_pheromone::substrate` and is not re-exported at the crate root, so the new test did not compile.
- **Fix:** Imported the helper from `swarm_pheromone::substrate` in `crates/swarm-runtime/src/detection/pipeline.rs`.
- **Files modified:** `crates/swarm-runtime/src/detection/pipeline.rs`
- **Verification:** `cargo test -p swarm-runtime --lib detection::pipeline`

**2. [Rule 1 - Bug] Fixed a duplicated investigation fixture ID in correlation tests**
- **Found during:** Verification after Task 2
- **Issue:** Two correlation test candidates reused the same `investigation_id`, so the in-memory store retained only one rejected candidate.
- **Fix:** Gave the outside-window fixture its own `investigation_id`.
- **Files modified:** `crates/swarm-runtime/src/correlation.rs`
- **Verification:** `cargo test -p swarm-runtime --lib correlation`

**3. [Rule 1 - Bug] Raised the synthetic cross-strategy escalation fixture to the configured alert threshold**
- **Found during:** Verification after Task 2
- **Issue:** Two `0.9` synthetic findings totaled `1.8`, which stayed below the configured `alert_threshold` of `2.0`, so the test was not exercising the distinct-source gate.
- **Fix:** Increased the synthetic finding confidence to `1.0` in the cross-strategy escalation fixture.
- **Files modified:** `crates/swarm-runtime/tests/escalation_integration.rs`
- **Verification:** `cargo test -p swarm-runtime --test escalation_integration`

---

**Total deviations:** 3 auto-fixed (2 bug, 1 blocking)
**Impact on plan:** All fixes were verification-driven and stayed inside the planned scope. No architectural change or scope expansion was needed.

## Issues Encountered

None beyond the verification-driven fixes listed above.

## Verification Notes

- `cargo test -p swarm-whisker --lib` passed
- `cargo test -p swarm-runtime --lib detection::pipeline` passed
- `cargo test -p swarm-pheromone --lib substrate` passed
- `cargo test -p swarm-runtime --lib correlation` passed
- `cargo test -p swarm-runtime --test escalation_integration` passed
- `cargo test -p swarm-runtime --test multi_agent_pipeline_integration` passed
- `cargo clippy -p swarm-runtime -p swarm-whisker -p swarm-pheromone -- -D warnings` passed
- Acceptance grep checks passed for `strategy_scoped_agent_id`, `finding.strategy_id`, `sign_deposit`, `weighted_score`, `strategy:`, `distinct_sources == 2`, `cross_strategy`, and `whisker-primary`
- The unrelated workspace baseline failure in `evolution::tests::evolution_handoff_persists_pending_launch_packet` was not rechecked because plan-targeted verification completed cleanly

## User Setup Required

None.

## Next Phase Readiness

Phase 123 can now assume:

- whisker deposits carry stable strategy-scoped source IDs across live runtime and rollout preview paths
- escalation uses those scoped IDs to distinguish corroborating strategies from same-strategy duplication
- incident correlation reasons expose the weighted decision path without adding new incident schema fields

No blockers remain in the owned files for the next phase.
