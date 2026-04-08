---
phase: 126
slug: tomagent-governance
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-08
---

# Phase 126 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust `cargo test` |
| **Config file** | `rulesets/default.yaml` |
| **Quick run command** | `cargo check -p swarm-runtime` |
| **Full suite command** | `cargo test -p swarm-core -p swarm-policy -p swarm-runtime` |
| **Estimated runtime** | ~75 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo check -p swarm-runtime`
- **After every plan wave:** Run the owning crate tests for that wave
- **Before `$gsd-verify-work`:** `cargo test -p swarm-core -p swarm-policy -p swarm-runtime`
- **Max feedback latency:** 75 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 126-01-01 | 126-01 | 1 | TOM-01, TOM-02 | config smoke | `cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact` | ✅ existing | ⬜ pending |
| 126-02-01 | 126-02 | 2 | TOM-01 | test seeding | `rg -n "dispatcher_applies_targeted_role_shift_from_tom_agent|dispatcher_applies_targeted_failed_health_report_from_tom_agent|tom_agent_shifts_degraded_agents_to_tom_role|tom_agent_marks_agents_failed_after_threshold" crates/swarm-runtime/src/dispatcher.rs crates/swarm-runtime/src/tom_agent.rs` | ✅ planned | ⬜ pending |
| 126-02-02 | 126-02 | 2 | TOM-01 | unit | `cargo test -p swarm-runtime tom_agent::tests::tom_agent_shifts_degraded_agents_to_tom_role -- --exact` | ✅ planned | ⬜ pending |
| 126-03-01 | 126-03 | 3 | TOM-02 | test seeding | `rg -n "governance_policy_vetoes_destructive_actions_when_swarm_is_unhealthy|pounceagent_emits_governance_veto_for_destructive_action" crates/swarm-runtime/src/tom_agent.rs crates/swarm-runtime/tests/pounceagent_integration.rs` | ✅ planned | ⬜ pending |
| 126-03-02 | 126-03 | 3 | TOM-02 | integration smoke | `cargo test -p swarm-runtime --test pounceagent_integration pounceagent_emits_governance_veto_for_destructive_action -- --exact` | ✅ planned | ⬜ pending |
| 126-04-01 | 126-04 | 4 | TOM-02 | test seeding | `rg -n "governance_veto_records_failure_receipt_without_execution" crates/swarm-runtime/tests/dispatch_integration.rs` | ✅ extend | ⬜ pending |
| 126-04-02 | 126-04 | 4 | TOM-02 | integration | `cargo test -p swarm-runtime --test dispatch_integration governance_veto_records_failure_receipt_without_execution -- --exact` | ✅ extend | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing Rust test infrastructure is sufficient for Phase 126. Coverage lands in the plan that owns the behavior:

- `126-01` proves the new governance config contract loads through the repository config path.
- `126-02` seeds targeted dispatcher and TomAgent lifecycle tests before implementation.
- `126-03` adds governance policy and PounceAgent veto tests before wiring the synchronous veto path.
- `126-04` extends `dispatch_integration` to prove veto receipts are recorded without calling the executor.

No separate Wave 0 plan is required for Phase 126.

---

## Manual-Only Verifications

All Phase 126 behaviors should remain covered by automated unit, integration, or package-level verification. No manual-only validation is planned.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or plan-local test seeding before implementation
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Existing infrastructure plus plan-local seeding covers all missing references
- [x] No watch-mode flags
- [x] Feedback latency < 75s for per-task smoke checks
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-04-08
