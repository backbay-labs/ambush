---
phase: 124
slug: pounceagent-core-and-de-escalation
status: draft
nyquist_compliant: false
wave_0_complete: false
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
| **Quick run command** | `cargo test -p swarm-runtime --test dispatch_integration --test escalation_integration` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~120 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p swarm-runtime --test dispatch_integration --test escalation_integration`
- **After every plan wave:** Run `cargo test -p swarm-runtime`
- **Before `$gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 120 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 124-v0-00 | 124-01 | 1 | POUNCE-03 | unit | `cargo test -p swarm-runtime loads_repository_ruleset -- --exact` | ✅ existing | ⬜ pending |
| 124-v0-01 | 124-03 | 3 | POUNCE-01 | integration | `cargo test -p swarm-runtime --test pounceagent_integration pounceagent_emits_request_response_for_alert_and_incident -- --exact` | ❌ W0 | ⬜ pending |
| 124-v0-02 | 124-03 | 3 | POUNCE-02 | integration | `cargo test -p swarm-runtime --test pounceagent_integration pounceagent_skips_scope_present_in_peer_findings -- --exact` | ❌ W0 | ⬜ pending |
| 124-v0-03 | 124-03 | 3 | POUNCE-03 | unit/integration | `cargo test -p swarm-runtime --test pounceagent_integration response_playbook_selects_actions_by_threat_severity_and_confidence -- --exact` | ❌ W0 | ⬜ pending |
| 124-v0-04 | 124-04 | 4 | POUNCE-04 | integration | `cargo test -p swarm-runtime --test dispatch_integration request_response_routes_through_authorize_and_execute -- --exact` | ✅ extend | ⬜ pending |
| 124-v0-05 | 124-04 | 4 | POUNCE-05 | integration | `cargo test -p swarm-runtime --test dispatch_integration pounceagent_dry_run_routes_through_runtime_path -- --exact` | ✅ extend | ⬜ pending |
| 124-v0-06 | 124-04 | 4 | POLICY-01 | integration | `cargo test -p swarm-runtime --test dispatch_integration expired_capability_lease_fails_closed_before_execution -- --exact` | ✅ extend | ⬜ pending |
| 124-v0-07 | 124-02 | 3 | DEESC-01 | unit | `cargo test -p swarm-core mode_state_transition_down_clears_triggering_threat_class -- --exact` | ✅ extend | ⬜ pending |
| 124-v0-08 | 124-02 | 3 | DEESC-02 | integration | `cargo test -p swarm-runtime --test escalation_integration concentration_monitor_deescalates_after_cooldown -- --exact` | ✅ extend | ⬜ pending |
| 124-v0-09 | 124-04 | 4 | POUNCE-04 | integration | `cargo test -p swarm-runtime --test dispatch_integration receipt_preserves_original_hunt_id_and_lineage_evidence -- --exact` | ✅ extend | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/swarm-runtime/tests/pounceagent_integration.rs` — new integration coverage for POUNCE-01, POUNCE-02, and POUNCE-03
- [ ] `crates/swarm-runtime/tests/dispatch_integration.rs` — extend routed `RequestResponse`, dry-run, and expired-lease assertions
- [ ] `crates/swarm-runtime/tests/escalation_integration.rs` — extend cooldown-based de-escalation proof
- [ ] `crates/swarm-core/src/agent.rs` tests — add `transition_down()` semantics coverage

---

## Manual-Only Verifications

All phase behaviors should have automated verification. No manual-only validation is planned for Phase 124.

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 120s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
