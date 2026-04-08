---
phase: 124-pounceagent-core-and-de-escalation
plan: 01
subsystem: core
tags: [config, policy, pounceagent, deescalation]
provides:
  - expanded `PheromoneConfig` contract with de-escalation cooldown and deterministic response playbook rules
  - repo-owned default ruleset examples for autonomous response selection
  - shared response-action scope helper reusable by policy and the future `PounceAgent`
affects:
  - 124-02
  - 124-03
  - 124-04
  - 124-05
key-files:
  created:
    - .planning/phases/124-pounceagent-core-and-de-escalation/124-01-SUMMARY.md
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-policy/src/static_gate.rs
    - rulesets/default.yaml
    - .planning/phases/124-pounceagent-core-and-de-escalation/124-01-PLAN.md
    - .planning/phases/124-pounceagent-core-and-de-escalation/124-VALIDATION.md
requirements-completed: [POUNCE-03, DEESC-02]
completed: 2026-04-08
---

# Phase 124 Plan 01 Summary

**Phase 124 now has a real config seam for autonomous response and de-escalation, with the repository ruleset loading through the normal runtime path**

## Accomplishments

- Added `deescalation_cooldown_secs` and `ResponsePlaybookConfig` to `PheromoneConfig`, including validation for confidence ranges and non-empty action sequences.
- Added repo-owned `response_playbook` examples and a concrete cooldown value to `rulesets/default.yaml`.
- Published `scope_for_response_action()` from `swarm-policy` so future `PounceAgent` dedupe can share the same scope model as policy leases.
- Updated the Phase 124 validation docs after execution proved the original exact-filter command for `loads_repository_ruleset` did not exercise the unit test.

## Task Commits

No task commit was created for this plan.

The workspace already contained unrelated local edits in several touched runtime files, and the compile-restoration blocker fix for the new `PheromoneConfig` shape overlapped those files. The execution result is left as local workspace state rather than bundling unrelated in-flight changes into a task commit.

## Decisions Made

- Kept the new autonomous-response selection contract inside `PheromoneConfig` so the cooldown and playbook seam live with existing escalation/runtime settings.
- Kept the playbook structure minimal: ordered rules keyed by `ThreatClass`, `Severity`, and confidence range, each resolving to an ordered `ResponseAction` sequence.
- Reused policy scope semantics directly by exposing a helper from `swarm-policy` instead of duplicating target-scope matching inside runtime code.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Pulled forward mechanical `PheromoneConfig` literal updates across compiled runtime surfaces**
- **Found during:** Plan 124-01 verification
- **Issue:** Adding required `PheromoneConfig` fields immediately broke compiled `swarm-runtime` source and test fixtures before the repository ruleset proof could run.
- **Fix:** Added default cooldown/playbook fields to the currently compiled `swarm-runtime` library and test literals so the Phase 124 config seam could compile end-to-end.
- **Files modified:** `crates/swarm-runtime/src/canary.rs`, `crates/swarm-runtime/src/control.rs`, `crates/swarm-runtime/src/detection/pipeline.rs`, `crates/swarm-runtime/src/dispatcher.rs`, `crates/swarm-runtime/src/escalation.rs`, `crates/swarm-runtime/src/evidence.rs`, `crates/swarm-runtime/src/http/core.inc`, `crates/swarm-runtime/src/ingest.rs`, `crates/swarm-runtime/src/promotion.rs`, `crates/swarm-runtime/src/service.rs`, `crates/swarm-runtime/src/stalker_agent.rs`, `crates/swarm-runtime/src/strategy.rs`, `crates/swarm-runtime/src/whisker_agent.rs`, `crates/swarm-runtime/tests/escalation_integration.rs`, `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs`, `crates/swarm-runtime/tests/multi_strategy_integration.rs`, `crates/swarm-runtime/tests/operational_hardening_integration.rs`
- **Verification:** `cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact`

**2. [Rule 3 - Blocking] Corrected the plan-local verification command to target the exact unit test path**
- **Found during:** Verification after the repo ruleset compile restored
- **Issue:** `cargo test -p swarm-runtime loads_repository_ruleset -- --exact` compiled successfully but executed zero tests because `loads_repository_ruleset` is a unit test under `config::tests`.
- **Fix:** Updated `124-01-PLAN.md` and `124-VALIDATION.md` to use `cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact`.
- **Files modified:** `.planning/phases/124-pounceagent-core-and-de-escalation/124-01-PLAN.md`, `.planning/phases/124-pounceagent-core-and-de-escalation/124-VALIDATION.md`
- **Verification:** `cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact`

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** The config seam stayed within scope, but verification forced a partial pull-forward of the later mechanical normalization work so the new required fields could compile.

## Verification Notes

- `cargo check -p swarm-core -p swarm-policy` passed
- `cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact` passed
- The originally planned `cargo test -p swarm-runtime loads_repository_ruleset -- --exact` invocation was corrected because it matched zero tests under `--exact`

## Next Phase Readiness

Phase 124 can now assume:

- the repository ruleset has a concrete cooldown and response-playbook shape that survives normal config loading
- policy and future `PounceAgent` work can share a single action-to-scope helper
- compiled `swarm-runtime` fixtures already understand the expanded `PheromoneConfig` shape on the currently exercised surfaces

No blocker remains for the behavior plans, although Plan 124-05 will still need to reconcile any remaining non-compiled or newly touched runtime literals that were not part of this verification path.
