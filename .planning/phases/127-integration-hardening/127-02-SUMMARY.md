---
phase: 127-integration-hardening
plan: 02
subsystem: milestone-hardening
tags: [runtime, workspace, clippy, cooldown, verification]
provides:
  - routed cooldown reset proof for burst-decay-burst escalation sequences
  - green workspace test and lint gates on the final v1.39 tree
  - fixed workspace fixture and lint drift surfaced only by milestone-wide verification
affects:
  - phase 127 verification
  - v1.39 milestone audit readiness
key-files:
  created:
    - .planning/phases/127-integration-hardening/127-02-SUMMARY.md
  modified:
    - crates/swarm-runtime/tests/dispatch_integration.rs
    - crates/swarm-pheromone/tests/jetstream.rs
    - crates/swarm-pheromone/tests/multi_instance.rs
    - crates/swarm-pheromone/src/jetstream.rs
    - crates/swarm-pheromone/src/substrate.rs
    - crates/swarm-whisker/src/stream.rs
    - crates/swarm-response/src/http_edr.rs
    - crates/swarm-runtime/src/pounce_agent.rs
    - crates/swarm-runtime/src/tom_agent.rs
requirements-completed: [DEESC-01, DEESC-02]
completed: 2026-04-08
---

# Phase 127 Plan 02 Summary

**Cooldown-driven session reset is now proven on the routed path, and the final v1.39 workspace is green under both tests and Clippy**

## Accomplishments

- Added `burst_decay_burst_does_not_retrigger_pounceagent_before_cooldown_reset`, proving one shared `SwarmModeState` prevents a second routed autonomous response until cooldown-driven de-escalation resets the session.
- Re-ran the full routed proof file after the new cooldown test landed so dry-run parity, audit lineage, governance veto, and the new hardening tests all stayed green together.
- Cleared the final milestone gates with green `cargo test --workspace` and green `cargo clippy --workspace -- -D warnings` on the settled tree.

## Task Commits

No task commit was created for this plan.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Workspace verification exposed stale `PheromoneConfig` constructors outside the original plan write set**
- **Found during:** `cargo test --workspace`
- **Issue:** `swarm-pheromone` and `swarm-whisker` still had direct `PheromoneConfig` literals missing `deescalation_cooldown_secs` and `response_playbook`, which blocked the milestone-wide test gate even though the routed runtime proofs were already green.
- **Fix:** normalized the remaining constructors in `crates/swarm-pheromone/tests/jetstream.rs`, `crates/swarm-pheromone/tests/multi_instance.rs`, `crates/swarm-pheromone/src/jetstream.rs`, `crates/swarm-pheromone/src/substrate.rs`, and `crates/swarm-whisker/src/stream.rs`.
- **Verification:** `cargo test --workspace`

**2. [Rule 3 - Blocking] Clippy surfaced pre-existing lint debt on the final milestone gate**
- **Found during:** `cargo clippy --workspace -- -D warnings`
- **Issue:** `swarm-response` returned an oversized `Err` in `http_edr`, `pounce_agent` had a needless borrow in its sort tie-breaker, and `tom_agent` used `Mutex::lock().unwrap()` on production paths.
- **Fix:** boxed the `ResponseReceipt` error in `crates/swarm-response/src/http_edr.rs`, removed the needless borrow in `crates/swarm-runtime/src/pounce_agent.rs`, and made `crates/swarm-runtime/src/tom_agent.rs` recover poisoned mutex state explicitly.
- **Verification:** `cargo clippy --workspace -- -D warnings`

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** No phase-scope expansion. The deviations only restored the workspace-wide compile and lint baseline required by the plan's final gates.

## Verification Notes

- `cargo test -p swarm-runtime --test dispatch_integration burst_decay_burst_does_not_retrigger_pounceagent_before_cooldown_reset -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration` passed
- `cargo test --workspace` passed
- `cargo clippy --workspace -- -D warnings` passed
