---
phase: 127
slug: integration-hardening
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-08
---

# Phase 127 — Validation Strategy

> Per-phase validation contract for milestone closeout proof and final workspace hardening.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust `cargo test` + `cargo clippy` |
| **Config file** | `rulesets/default.yaml` |
| **Quick run command** | `cargo test -p swarm-runtime --test dispatch_integration -- --nocapture` |
| **Full suite command** | `cargo test --workspace` |
| **Lint gate** | `cargo clippy --workspace -- -D warnings` |
| **Estimated runtime** | ~3-5 minutes |

---

## Sampling Rate

- **After every task-sized test edit:** run the exact owned integration test first
- **After every plan:** run the owning integration file or exact proof set
- **Before phase closeout:** run `cargo test --workspace`
- **Final gate:** run `cargo clippy --workspace -- -D warnings`
- **Max feedback latency:** 5 minutes

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 127-01-01 | 127-01 | 1 | POUNCE-01, POUNCE-02, POUNCE-04 | test seeding | `rg -n "pounceagent_routes_same_escalation_only_once_per_session|empty_ruleset_policy_fails_closed_for_routed_pounce_request|expired_lease_routing_records_failure_audit_without_execution" crates/swarm-runtime/tests/dispatch_integration.rs` | ✅ planned | ✅ green |
| 127-01-02 | 127-01 | 1 | POLICY-01, POLICY-03 | integration | `cargo test -p swarm-runtime --test dispatch_integration pounceagent_routes_same_escalation_only_once_per_session -- --exact` | ✅ planned | ✅ green |
| 127-02-01 | 127-02 | 2 | DEESC-01, DEESC-02 | test seeding | `rg -n "burst_decay_burst_does_not_retrigger_pounceagent_before_cooldown_reset" crates/swarm-runtime/tests/dispatch_integration.rs` | ✅ planned | ✅ green |
| 127-02-02 | 127-02 | 2 | DEESC-01, DEESC-02 | integration | `cargo test -p swarm-runtime --test dispatch_integration burst_decay_burst_does_not_retrigger_pounceagent_before_cooldown_reset -- --exact` | ✅ planned | ✅ green |
| 127-02-03 | 127-02 | 2 | milestone hardening | workspace | `cargo test --workspace` | ✅ existing | ✅ green |
| 127-02-04 | 127-02 | 2 | milestone hardening | lint | `cargo clippy --workspace -- -D warnings` | ✅ existing | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing Rust integration infrastructure is sufficient. Phase 127 does not need new external harnesses or manual UI validation:

- `dispatch_integration.rs` already has the router/runtime fixtures needed for routed-path proofs
- `PounceAgent` and `ConcentrationMonitor` already expose the seams required for session and cooldown validation
- workspace test and clippy are already the canonical milestone hardening gates

No separate Wave 0 plan is required.

---

## Manual-Only Verifications

None. Phase 127 is expected to close entirely through automated integration, workspace, and lint validation.

---

## Validation Sign-Off

- [x] All new behavior is pinned by exact tests before broader suite runs
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Workspace and lint gates are phase-owned, not deferred
- [x] No watch-mode flags
- [x] Feedback latency < 5 minutes
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-04-08
