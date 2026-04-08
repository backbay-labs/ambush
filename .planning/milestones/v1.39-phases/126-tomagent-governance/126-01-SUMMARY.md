---
phase: 126-tomagent-governance
plan: 01
subsystem: core-contracts
tags: [core, config, dispatcher, governance]
provides:
  - shared agent-health summaries in `SwarmEnvironment`
  - targeted lifecycle and governance-veto action contracts
  - repository-owned governance degraded-tick threshold
affects:
  - 126 plan 02 TomAgent lifecycle routing
  - 126 plan 03 synchronous governance veto
key-files:
  created:
    - .planning/phases/126-tomagent-governance/126-01-SUMMARY.md
  modified:
    - crates/swarm-core/src/agent.rs
    - crates/swarm-core/src/config.rs
    - crates/swarm-core/src/types.rs
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/dispatcher.rs
    - rulesets/default.yaml
requirements-completed: [TOM-01, TOM-02]
completed: 2026-04-08
---

# Phase 126 Plan 01 Summary

**TomAgent governance now has the shared contracts it needs instead of runtime-local ad hoc types**

## Accomplishments

- Moved `AgentHealthEntry` into `swarm-core` and widened `SwarmEnvironment` with `agent_health` so every agent can see the dispatcher health snapshot during a tick.
- Extended `SwarmAction::RoleShift` and `SwarmAction::HealthReport` to target explicit agents and added `SwarmAction::GovernanceVeto` for later routing.
- Added `runtime.governance_degraded_tick_threshold` with repository default `3` and validation so Tom lifecycle escalation is config-owned.
- Updated dispatcher and test fixtures to consume the shared health-entry contract and the new runtime field without runtime-local duplication.

## Task Commits

No task commit was created for this plan.

## Verification Notes

- `cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact` passed
- `cargo check -p swarm-runtime` passed

## Next Phase Readiness

Plan 02 can now implement TomAgent against stable core contracts instead of widening the environment and action types mid-flight.
