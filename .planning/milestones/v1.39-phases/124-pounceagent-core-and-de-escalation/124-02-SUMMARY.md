---
phase: 124-pounceagent-core-and-de-escalation
plan: 02
subsystem: runtime
tags: [deescalation, swarm-mode, cooldown, escalation]
provides:
  - explicit downward-only `SwarmModeState::transition_down()` semantics
  - cooldown-gated runtime de-escalation back to `Normal`
  - integration proof that quiet periods do not flap immediately
affects:
  - 124-03
  - 124-04
key-files:
  created:
    - .planning/phases/124-pounceagent-core-and-de-escalation/124-02-SUMMARY.md
  modified:
    - crates/swarm-core/src/agent.rs
    - crates/swarm-runtime/src/escalation.rs
    - crates/swarm-runtime/tests/escalation_integration.rs
    - .planning/phases/124-pounceagent-core-and-de-escalation/124-02-PLAN.md
    - .planning/phases/124-pounceagent-core-and-de-escalation/124-VALIDATION.md
requirements-completed: [DEESC-01, DEESC-02]
completed: 2026-04-08
---

# Phase 124 Plan 02 Summary

**Swarm mode can now return to `Normal` after sustained quiet time, and the downward transition path is explicit in code and tests**

## Accomplishments

- Added `SwarmModeState::transition_down()` as a downward-only counterpart to the existing upward-only `transition_to()` path.
- Added `ConcentrationMonitor` quiet-window tracking so the runtime de-escalates only after all threat classes remain below the alert threshold for `deescalation_cooldown_secs`.
- Added integration coverage proving the first quiet evaluation does not flap mode down immediately and the post-cooldown evaluation clears the triggering threat lineage.

## Task Commits

No task commit was created for this plan.

The workspace still contains unrelated local edits in several touched files, so the completed de-escalation work remains as local workspace state instead of being bundled into a task commit with unrelated changes.

## Decisions Made

- De-escalation goes directly back to `SwarmMode::Normal` once the quiet dwell window completes, matching the phase requirement instead of adding a stepwise `Incident -> Alert -> Normal` ladder.
- Quiet dwell tracking lives in `ConcentrationMonitor`, not policy or governance code, so the behavior stays coupled to pheromone concentration evaluation.
- Any above-threshold signal resets the quiet dwell timer, including cases where the current mode is already higher than the newly observed event mode.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Corrected the unit-test command to use the fully qualified test path**
- **Found during:** Task 1 red/green loop
- **Issue:** `cargo test -p swarm-core mode_state_transition_down_clears_triggering_threat_class -- --exact` matched zero tests because the unit test lives under `agent::tests`.
- **Fix:** Updated the plan-local verification command and validation row to use `cargo test -p swarm-core agent::tests::mode_state_transition_down_clears_triggering_threat_class -- --exact`.
- **Files modified:** `.planning/phases/124-pounceagent-core-and-de-escalation/124-02-PLAN.md`, `.planning/phases/124-pounceagent-core-and-de-escalation/124-VALIDATION.md`
- **Verification:** `cargo test -p swarm-core agent::tests::mode_state_transition_down_clears_triggering_threat_class -- --exact`

**2. [Rule 3 - Blocking] Repaired a leftover core config test fixture so swarm-core tests could compile**
- **Found during:** Task 1 red setup
- **Issue:** A Plan 124-01 fixture in `crates/swarm-core/src/config.rs` referenced a private helper when compiling `swarm-core` tests.
- **Fix:** Replaced the private helper call with the literal cooldown value used elsewhere in the config seam tests.
- **Files modified:** `crates/swarm-core/src/config.rs`
- **Verification:** `cargo test -p swarm-core agent::tests::mode_state_transition_down_clears_triggering_threat_class -- --exact`

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** No scope expansion. One deviation fixed a plan-doc verification path; the other cleared a fixture regression left by the earlier config seam work so the intended de-escalation tests could run.

## Verification Notes

- `cargo test -p swarm-core agent::tests::mode_state_transition_down_clears_triggering_threat_class -- --exact` passed
- `cargo test -p swarm-runtime --test escalation_integration concentration_monitor_deescalates_after_cooldown -- --exact` passed
- `cargo test -p swarm-runtime --test escalation_integration` passed

## Next Phase Readiness

Phase 124 can now assume:

- elevated-mode session state has an explicit downward transition path
- quiet periods do not immediately drop mode on the first below-threshold evaluation
- later PounceAgent work can key session dedupe off a real de-escalation boundary

No blocker remains for the PounceAgent behavior slice.
