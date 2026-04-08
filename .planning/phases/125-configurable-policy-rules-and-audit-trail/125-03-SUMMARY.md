---
phase: 125-configurable-policy-rules-and-audit-trail
plan: 03
subsystem: policy-runtime
tags: [policy, configurable-gate, runtime, replay]
provides:
  - ordered YAML policy evaluation with fail-closed empty-rules behavior
  - rule-local UTC hour checks and per-agent one-minute rate limits
  - configured runtime wiring that instantiates `ConfigurableApprovalGate` from repository config
affects:
  - 125-04 runtime attribution plumbing
  - replay and synthetic runtime harness behavior under fail-closed policy defaults
key-files:
  created:
    - .planning/phases/125-configurable-policy-rules-and-audit-trail/125-03-SUMMARY.md
    - crates/swarm-policy/src/configurable_gate.rs
  modified:
    - crates/swarm-policy/src/lib.rs
    - crates/swarm-runtime/src/service.rs
    - crates/swarm-runtime/src/ingest.rs
    - crates/swarm-runtime/src/replay/core.inc
requirements-completed: [POLICY-03]
completed: 2026-04-08
---

# Phase 125 Plan 03 Summary

**Configured runtimes now authorize through `ConfigurableApprovalGate`, which evaluates ordered YAML rules, fails closed on empty rulesets, and falls back to `StaticApprovalGate` only when no rule matches**

## Accomplishments

- Added `ConfigurableApprovalGate` with ordered rule matching by threat class, optional action selectors, severity bounds, optional UTC hour windows, and optional per-agent rate limits.
- Made empty configured rulesets fail closed with a dedicated rule name instead of silently allowing requests.
- Extended `PolicyDecision` so configurable and static verdicts both carry `rule_name` and `reason`.
- Switched configured runtime builders in service, ingest, and replay paths from `StaticApprovalGate` to `ConfigurableApprovalGate::from_config(...)`.
- Added exact unit tests proving empty-rules denial, matching allows, out-of-window denial, per-agent limiting, and static fallback.

## Task Commits

No task commit was created for this plan.

## Decisions Made

- Composed with `StaticApprovalGate` instead of replacing it so request validation, lease issuance, and invariant fallback behavior remain intact.
- Derived threat-class matching from existing evidence payloads rather than widening the request wire shape.
- Scoped per-agent rate limiting to `(rule_name, requested_by)` so one YAML rule cannot consume another rule’s burst budget.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Configured runtime fail-closed behavior broke synthetic harnesses that previously relied on empty policy rules**
- **Found during:** phase verification across replay and runtime harness tests
- **Issue:** once configured builders instantiated `ConfigurableApprovalGate`, empty test rulesets began denying every synthetic request, which broke replay-driven harnesses that meant to stay permissive unless a test explicitly modeled policy denial
- **Fix:** kept production fail-closed behavior and injected explicit permissive named allow rules into the owned replay and runtime test helpers that need unconstrained synthetic policy behavior
- **Files modified:** `crates/swarm-runtime/src/replay/core.inc`, `crates/swarm-runtime/src/control.rs`, `crates/swarm-runtime/src/http/core.inc`, `crates/swarm-runtime/src/selection.rs`, `crates/swarm-runtime/src/evolution.rs`, `crates/swarm-runtime/src/portfolio.rs`, `crates/swarm-runtime/src/mutation.rs`
- **Verification:** `cargo test -p swarm-runtime replay::core::tests::named_suite_manifest_runs_with_metadata_and_technique_groups -- --exact`

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** No scope change. The deviation preserved the intended fail-closed production semantics while restoring permissive synthetic harness behavior only where the tests explicitly require it.

## Verification Notes

- `cargo test -p swarm-policy configurable_gate_applies_matching_allow_rule -- --exact` passed
- `cargo test -p swarm-policy` passed
- `cargo test -p swarm-runtime replay::core::tests::named_suite_manifest_runs_with_metadata_and_technique_groups -- --exact` passed
- `cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact` passed

## Next Phase Readiness

Phase 125 plan 04 can now assume:

- configured runtimes evaluate repository-owned policy rules on the live execution path
- empty configured rulesets deny by default
- no-match requests still fall back to static invariant enforcement
