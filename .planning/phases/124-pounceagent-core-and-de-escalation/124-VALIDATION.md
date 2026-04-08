---
phase: 124
slug: pounceagent-core-and-de-escalation
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-08
---

# Phase 124 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust `cargo test` |
| **Config file** | none |
| **Quick run command** | `cargo check -p swarm-runtime --lib` |
| **Full suite command** | `cargo test -p swarm-runtime` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo check -p swarm-runtime --lib`
- **After every plan wave:** Run `cargo test -p swarm-runtime`
- **Before `$gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 45 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 124-01-01 | 124-01 | 1 | POUNCE-03, DEESC-02 | config smoke | `cargo check -p swarm-core -p swarm-policy && cargo test -p swarm-runtime loads_repository_ruleset -- --exact` | ✅ existing | ⬜ pending |
| 124-05-01 | 124-05 | 2 | POUNCE-03, DEESC-02 | compile smoke | `cargo check -p swarm-runtime --lib` | ✅ existing | ⬜ pending |
| 124-05-02 | 124-05 | 2 | POUNCE-03, DEESC-02 | compile smoke | `cargo check -p swarm-runtime --lib` | ✅ existing | ⬜ pending |
| 124-02-01 | 124-02 | 3 | DEESC-01 | unit | `cargo test -p swarm-core mode_state_transition_down_clears_triggering_threat_class -- --exact` | ✅ extend | ⬜ pending |
| 124-02-02 | 124-02 | 3 | DEESC-02 | integration | `cargo test -p swarm-runtime --test escalation_integration concentration_monitor_deescalates_after_cooldown -- --exact` | ✅ extend | ⬜ pending |
| 124-03-01 | 124-03 | 3 | POUNCE-01, POUNCE-02, POUNCE-03 | test seeding | `rg -n "pounceagent_emits_request_response_for_alert_and_incident|pounceagent_skips_scope_present_in_peer_findings|response_playbook_selects_actions_by_threat_severity_and_confidence" crates/swarm-runtime/tests/pounceagent_integration.rs` | ✅ planned | ⬜ pending |
| 124-03-02 | 124-03 | 3 | POUNCE-01, POUNCE-02, POUNCE-03 | integration smoke | `cargo test -p swarm-runtime --test pounceagent_integration pounceagent_emits_request_response_for_alert_and_incident -- --exact` | ✅ planned | ⬜ pending |
| 124-04-01 | 124-04 | 4 | POUNCE-04, POUNCE-05, POLICY-01 | test seeding | `rg -n "request_response_routes_through_authorize_and_execute|pounceagent_dry_run_routes_through_runtime_path|expired_capability_lease_fails_closed_before_execution|receipt_preserves_original_hunt_id_and_lineage_evidence" crates/swarm-runtime/tests/dispatch_integration.rs` | ✅ extend | ⬜ pending |
| 124-04-02 | 124-04 | 4 | POUNCE-04, POUNCE-05, POLICY-01 | integration smoke | `cargo test -p swarm-runtime --test dispatch_integration request_response_routes_through_authorize_and_execute -- --exact` | ✅ extend | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing Rust test infrastructure is sufficient for this phase. Test seeding happens inside the owning plans before each implementation task verifies:

- `124-01` proves the new ruleset and config seam load through the normal runtime config path.
- `124-03` seeds `crates/swarm-runtime/tests/pounceagent_integration.rs` before PounceAgent behavior verifies.
- `124-04` extends `crates/swarm-runtime/tests/dispatch_integration.rs` before runtime-routing behavior verifies.
- `124-02` adds the `transition_down()` and de-escalation coverage in the same plan that owns the behavior.

No separate Wave 0 plan is required for Phase 124.

---

## Manual-Only Verifications

All phase behaviors should have automated verification. No manual-only validation is planned for Phase 124.

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or plan-local test seeding before implementation
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Existing infrastructure plus plan-local seeding covers all missing references
- [x] No watch-mode flags
- [x] Feedback latency < 45s for per-task smoke checks
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-04-08
