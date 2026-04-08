---
phase: 122-cross-strategy-pheromone-signals-and-rollout-scoping
plan: 02
subsystem: runtime
tags: [rollout, canary, promotion, replay, composite-detector]
requires:
  - phase: 120-composite-detector-and-config-migration
    provides: composite detection with stable active strategy selection
  - phase: 122-cross-strategy-pheromone-signals-and-rollout-scoping
    plan: 01
    provides: strategy-scoped deposit identities and cross-strategy correlation guards
provides:
  - validated rollout scope config for canary and promotion
  - shared detector factory reuse across control, canary, promotion, and replay
  - canary and promotion baseline selection that follows resolved rollout scope instead of detection.strategy
  - canary startup rejection for stale verification lineage and shadow baseline drift
  - replay experiment and shadow baseline selection aligned with canary rollout scope
key-files:
  created:
    - crates/swarm-runtime/src/detector_factory.rs
    - .planning/phases/122-cross-strategy-pheromone-signals-and-rollout-scoping/122-02-SUMMARY.md
  modified:
    - crates/swarm-core/src/config.rs
    - crates/swarm-runtime/src/config.rs
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/src/control.rs
    - crates/swarm-runtime/src/canary.rs
    - crates/swarm-runtime/src/promotion.rs
    - crates/swarm-runtime/src/replay/core.inc
    - crates/swarm-runtime/src/strategy.rs
    - rulesets/default.yaml
requirements-completed: [COMPOSE-05]
completed: 2026-04-08
---

# Phase 122 Summary

**Composite-mode rollout scope is now explicit, validated, and reused across canary, promotion, and replay baseline selection**

## Accomplishments

- Added optional `strategy_id` rollout scope fields to `CanaryConfig` and `PromotionConfig`, plus validation that requires `canary.strategy_id` whenever multiple `detection.strategies` are active.
- Added `DetectionConfig::validate_rollout_strategy_id()` and `DetectionConfig::resolve_rollout_strategy_id()` so rollout-scope checks live next to `active_strategies()`.
- Added `crates/swarm-runtime/src/detector_factory.rs` and rewired `control`, `canary`, `promotion`, and `replay` to use the shared detector-construction path.
- Changed canary startup to resolve its baseline strategy from rollout scope, persist that scope into the run assignment, and reject experiment, verification, or shadow artifacts when lineage or baseline scope drifted.
- Changed promotion startup to use the configured promotion scope or explicitly inherit the canary baseline, then reject mismatched configured scopes and inactive inherited baselines before baseline construction.
- Updated replay experiment and shadow evaluation so the baseline detector follows the resolved canary rollout scope rather than the legacy `detection.strategy` scalar.
- Updated strategy-memory fixtures and the shipped default ruleset so test helpers and docs reflect the new rollout-scope surface.

## Deviations From Plan

- Extended the shared detector factory to keep the in-progress `network_connect` detector path working because `crates/swarm-runtime/src/control.rs` already carried local Phase 121 changes. This stayed inside owned files and avoided breaking parallel work already present in the workspace.

## Verification Notes

- Plan-targeted verification passed:
  - `cargo test -p swarm-core --lib config::tests`
  - `cargo test -p swarm-runtime --lib config::tests`
  - `cargo test -p swarm-runtime --lib strategy`
- Additional focused rollout verification passed:
  - `cargo test -p swarm-runtime --lib canary::tests`
  - `cargo test -p swarm-runtime --lib promotion::tests`
  - `cargo test -p swarm-runtime --lib experiment_report_persists_and_flags_false_positive_regression`
  - `cargo test -p swarm-runtime --lib verification_report_persists_and_flags_false_positive_counterexample`
  - `cargo test -p swarm-runtime --lib shadow_report_persists_for_control_candidate`
- Added regression coverage for:
  - missing multi-strategy canary scope during config parsing
  - verification-lineage mismatch at canary startup
  - shadow baseline-scope mismatch at canary startup
  - configured promotion-scope mismatch against completed canary baseline
  - inherited promotion baseline drift after active-strategy config changes

## Remaining Work

- No blockers remain within the owned files for COMPOSE-05.
