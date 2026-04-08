---
phase: 125
slug: configurable-policy-rules-and-audit-trail
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-08
---

# Phase 125 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust `cargo test` |
| **Config file** | `rulesets/default.yaml` |
| **Quick run command** | `cargo check -p swarm-policy -p swarm-runtime` |
| **Full suite command** | `cargo test -p swarm-core -p swarm-policy -p swarm-runtime` |
| **Estimated runtime** | ~60 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo check -p swarm-policy -p swarm-runtime`
- **After every plan wave:** Run the owning crate tests for that wave
- **Before `$gsd-verify-work`:** `cargo test -p swarm-core -p swarm-policy -p swarm-runtime`
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 125-01-01 | 125-01 | 1 | POLICY-02, POLICY-03 | config smoke | `cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact` | ✅ existing | ✅ green |
| 125-02-01 | 125-02 | 2 | POLICY-02 | test seeding | `rg -n "scope_rate_limit_denies_burst_for_same_scope|scope_rate_limit_prunes_old_entries" crates/swarm-policy/src/static_gate.rs` | ✅ extend | ✅ green |
| 125-02-02 | 125-02 | 2 | POLICY-02 | unit | `cargo test -p swarm-policy scope_rate_limit_denies_burst_for_same_scope -- --exact` | ✅ extend | ✅ green |
| 125-03-01 | 125-03 | 3 | POLICY-03 | test seeding | `rg -n "configurable_gate_denies_when_rules_are_empty|configurable_gate_applies_matching_allow_rule|configurable_gate_denies_outside_allowed_hours|configurable_gate_enforces_per_agent_rate_limit|configurable_gate_falls_back_to_static_gate_when_no_rule_matches" crates/swarm-policy/src/configurable_gate.rs` | ✅ planned | ✅ green |
| 125-03-02 | 125-03 | 3 | POLICY-03 | unit | `cargo test -p swarm-policy configurable_gate_applies_matching_allow_rule -- --exact` | ✅ planned | ✅ green |
| 125-04-01 | 125-04 | 4 | POLICY-04 | test seeding | `rg -n "audit_trail_records_rule_name_and_reason|successful_receipts_embed_policy_audit" crates/swarm-runtime/tests/dispatch_integration.rs` | ✅ extend | ✅ green |
| 125-04-02 | 125-04 | 4 | POLICY-04 | integration | `cargo test -p swarm-runtime --test dispatch_integration audit_trail_records_rule_name_and_reason -- --exact` | ✅ extend | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing Rust test infrastructure is sufficient for Phase 125. New coverage is added in the plan that owns the behavior:

- `125-01` proves the repository ruleset and new policy config contract load through the normal runtime config path.
- `125-02` extends `crates/swarm-policy/src/static_gate.rs` unit coverage for scope-window rate limiting.
- `125-03` adds dedicated `ConfigurableApprovalGate` unit tests for empty rules, matching decisions, UTC hour limits, per-agent limits, and static fallback.
- `125-04` extends `crates/swarm-runtime/tests/dispatch_integration.rs` to prove rule attribution reaches runtime audit and receipt output.

No separate Wave 0 plan is required for Phase 125.

---

## Manual-Only Verifications

All Phase 125 behaviors should remain covered by automated config, unit, or integration tests. No manual-only validation is planned.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or plan-local test seeding before implementation
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Existing infrastructure plus plan-local seeding covers all missing references
- [x] No watch-mode flags
- [x] Feedback latency < 60s for per-task smoke checks
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-04-08
