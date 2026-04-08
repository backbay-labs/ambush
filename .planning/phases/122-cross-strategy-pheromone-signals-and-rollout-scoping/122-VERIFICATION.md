---
phase: 122-cross-strategy-pheromone-signals-and-rollout-scoping
verified: 2026-04-08T04:43:39Z
status: passed
score: 4/4 must-haves verified
re_verification: false
must_haves:
  truths:
    - "Strategy-scoped deposit IDs make corroborating strategies count as distinct pheromone sources while same-strategy duplication still collapses to one source"
    - "Correlation requires at least one real non-strategy overlap and adds a bounded cross-strategy bonus instead of inflating on raw `strategy:*` keys"
    - "Canary and promotion accept optional `strategy_id` scope and validate it against active strategies"
    - "Canary, promotion, replay, and shared detector-factory paths all honor the resolved rollout scope rather than the legacy single-strategy scalar"
  artifacts:
    - path: "crates/swarm-runtime/src/detection/pipeline.rs"
      provides: "strategy-scoped runtime deposit identity before signing"
      contains: "strategy_scoped_agent_id"
    - path: "crates/swarm-runtime/src/correlation.rs"
      provides: "cross-strategy weighted correlation rules"
      contains: "weighted_score"
    - path: "crates/swarm-runtime/src/detector_factory.rs"
      provides: "shared rollout detector construction for control/canary/promotion/replay"
      contains: "build_detector_from_candidate"
  key_links:
    - from: "crates/swarm-runtime/src/canary.rs"
      to: "crates/swarm-runtime/src/replay/core.inc"
      via: "resolved rollout baseline strategy"
      pattern: "resolve_rollout_strategy_id"
---

# Phase 122: Cross-Strategy Pheromone Signals And Rollout Scoping Verification Report

**Phase Goal:** Cross-strategy signals count independently for escalation, correlation favors real corroboration across strategies, and rollout controls can target one strategy inside a composite detector.
**Verified:** 2026-04-08T04:43:39Z
**Status:** passed
**Re-verification:** No

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Distinct strategies on one base agent now count as distinct pheromone sources | VERIFIED | `crates/swarm-whisker/src/stream.rs` scopes deposit IDs as `{base}:{strategy}`, `crates/swarm-runtime/src/detection/pipeline.rs` applies the same scoping before signing, and substrate/integration tests prove same-strategy duplication still collapses to one source. |
| 2 | Correlation only rewards cross-strategy evidence after at least one real shared non-strategy key | VERIFIED | `crates/swarm-runtime/src/correlation.rs` rejects strategy-only overlap, preserves rejection reasons, and adds a bounded cross-strategy bonus only when real corroboration exists. |
| 3 | Rollout scope config is explicit and validated | VERIFIED | `crates/swarm-core/src/config.rs` and `crates/swarm-runtime/src/config.rs` validate `canary.strategy_id` and `promotion.strategy_id` against active strategies and preserve single-strategy backward compatibility. |
| 4 | Rollout baseline selection and replay alignment now follow the resolved rollout scope everywhere | VERIFIED | `crates/swarm-runtime/src/canary.rs`, `crates/swarm-runtime/src/promotion.rs`, `crates/swarm-runtime/src/replay/core.inc`, and `crates/swarm-runtime/src/detector_factory.rs` consistently reuse the shared detector-factory and resolved baseline strategy logic. |

**Score:** 4/4 truths verified

### Requirements Coverage

| Requirement | Status | Evidence |
|-------------|--------|----------|
| COMPOSE-03 | SATISFIED | Strategy-scoped deposit IDs drive `distinct_sources` across runtime, rollout preview, substrate concentration queries, and escalation integration tests. |
| COMPOSE-04 | SATISFIED | Correlation weights cross-strategy incident pairs higher only when there is real non-strategy overlap. |
| COMPOSE-05 | SATISFIED | `CanaryConfig` and `PromotionConfig` accept optional `strategy_id`, validate it, and apply it through canary, promotion, and replay baseline selection. |

### ROADMAP Success Criteria Coverage

| # | Success Criterion | Status | Evidence |
|---|-------------------|--------|----------|
| 1 | Deposits from different strategies carry distinct `agent_id` values incorporating `strategy_id` | VERIFIED | Shared helper plus runtime pipeline coverage prove scoped agent IDs are signed and persisted correctly. |
| 2 | `CorrelationEngine::assemble_incident_at()` weights different strategies higher than same-strategy pairs | VERIFIED | Cross-strategy bonus tests in `crates/swarm-runtime/src/correlation.rs` verify the bonus and the rejection path for strategy-only overlap. |
| 3 | `CanaryConfig` and `PromotionConfig` accept optional `strategy_id` scope | VERIFIED | Config tests, canary tests, and promotion tests cover valid, invalid, inherited, and mismatched scope cases. |
| 4 | Distinct strategies can satisfy `min_sources_for_escalation` where same-strategy duplication cannot | VERIFIED | `crates/swarm-runtime/tests/escalation_integration.rs` proves cross-strategy findings from one base whisker agent alert, while repeated same-strategy findings do not. |

### Automated Verification

- `cargo test -p swarm-whisker --lib`
- `cargo test -p swarm-runtime --lib detection::pipeline`
- `cargo test -p swarm-pheromone --lib substrate`
- `cargo test -p swarm-runtime --lib correlation`
- `cargo test -p swarm-runtime --test escalation_integration`
- `cargo test -p swarm-runtime --test multi_agent_pipeline_integration`
- `cargo test -p swarm-core --lib config::tests`
- `cargo test -p swarm-runtime --lib config::tests`
- `cargo test -p swarm-runtime --lib strategy`
- `cargo test -p swarm-runtime --lib canary::tests`
- `cargo test -p swarm-runtime --lib promotion::tests`
- `cargo test -p swarm-runtime --lib experiment_report_persists_and_flags_false_positive_regression`
- `cargo test -p swarm-runtime --lib verification_report_persists_and_flags_false_positive_counterexample`
- `cargo test -p swarm-runtime --lib shadow_report_persists_for_control_candidate`
- `cargo clippy -p swarm-runtime -p swarm-whisker -p swarm-pheromone -- -D warnings`

### Human Verification Required

None. The phase is entirely verified through code inspection plus deterministic unit and integration coverage.

### Gaps Summary

No gaps found. Phase 122 fully satisfies `COMPOSE-03` through `COMPOSE-05` and leaves the runtime ready for milestone-level multi-strategy proof.

---
_Verified: 2026-04-08T04:43:39Z_
_Verifier: Codex_
