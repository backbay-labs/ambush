---
phase: 126-tomagent-governance
verified: 2026-04-08T15:01:12Z
status: blocked
score: 3/3 phase truths verified; package sweep blocked
re_verification: true
blocking_scope: package-wide runtime regression cluster outside Phase 126 write set
must_haves:
  truths:
    - "TomAgent implements `SwarmAgent`, consumes dispatcher health summaries, emits targeted role shifts for degraded agents, and emits targeted failed-health escalation at the configured threshold"
    - "PounceAgent consults shared governance state synchronously inside `tick()` and emits governance-veto intent for destructive blocked actions instead of `RequestResponse`"
    - "Governance vetoes route through the runtime seam into receipt-id-bearing audit artifacts carrying veto reason and governing agent provenance without calling the response executor"
  artifacts:
    - path: "crates/swarm-runtime/src/tom_agent.rs"
      provides: "TomAgent implementation, shared `GovernancePolicy`, and exact lifecycle tests"
      contains: "tom_agent_marks_agents_failed_after_threshold"
    - path: "crates/swarm-runtime/src/pounce_agent.rs"
      provides: "Synchronous governance check before autonomous response emission"
      contains: "with_governance_policy"
    - path: "crates/swarm-runtime/src/dispatcher.rs"
      provides: "Targeted lifecycle routing and governance-veto dispatch routing"
      contains: "GovernanceVetoRoute"
    - path: "crates/swarm-runtime/src/lib.rs"
      provides: "Synthetic governance-veto receipt construction"
      contains: "audit_governance_veto"
    - path: "crates/swarm-runtime/tests/pounceagent_integration.rs"
      provides: "Proof that destructive PounceAgent actions become governance vetoes"
      contains: "pounceagent_emits_governance_veto_for_destructive_action"
    - path: "crates/swarm-runtime/tests/dispatch_integration.rs"
      provides: "Proof that governance vetoes persist auditable failure receipts without executor calls"
      contains: "governance_veto_records_failure_receipt_without_execution"
---

# Phase 126: TomAgent Governance Verification Report

**Phase Goal:** TomAgent monitors swarm health, PounceAgent consults governance synchronously before destructive autonomous execution, and vetoed actions persist durable audit receipts instead of disappearing into logs.
**Verified:** 2026-04-08T15:01:12Z
**Status:** blocked
**Re-verification:** Yes

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | TomAgent consumes dispatcher health summaries and emits targeted lifecycle actions | VERIFIED | `tom_agent::tests::tom_agent_shifts_degraded_agents_to_tom_role`, `tom_agent::tests::tom_agent_marks_agents_failed_after_threshold`, and the dispatcher targeted-action exact tests all passed. |
| 2 | PounceAgent vetoes destructive actions synchronously inside `tick()` | VERIFIED | `pounceagent_integration::pounceagent_emits_governance_veto_for_destructive_action` passed, proving the agent emits `GovernanceVeto` instead of `RequestResponse`. |
| 3 | Governance vetoes persist receipt-id-bearing audit artifacts without executor calls | VERIFIED | `dispatch_integration::governance_veto_records_failure_receipt_without_execution` passed and verified zero executor invocations plus typed governance provenance on the failure receipt. |

**Score:** 3/3 phase truths verified

### Requirements Coverage

| Requirement | Status | Evidence |
|-------------|--------|----------|
| TOM-01 | SATISFIED | `TomAgent` observes `SwarmEnvironment.agent_health`, emits targeted `RoleShift`, and escalates repeated degradation to targeted `HealthReport { status: Failed }` under the configured threshold. |
| TOM-02 | SATISFIED | `GovernancePolicy` is shared between Tom and Pounce, Pounce veto happens before dispatcher runtime routing, and the resulting veto artifacts carry receipt ids plus governing-agent provenance. |

### Automated Verification

- `cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact`
- `cargo test -p swarm-runtime tom_agent::tests::tom_agent_shifts_degraded_agents_to_tom_role -- --exact`
- `cargo test -p swarm-runtime tom_agent::tests::tom_agent_marks_agents_failed_after_threshold -- --exact`
- `cargo test -p swarm-runtime dispatcher::tests::dispatcher_applies_targeted_role_shift_from_tom_agent -- --exact`
- `cargo test -p swarm-runtime dispatcher::tests::dispatcher_applies_targeted_failed_health_report_from_tom_agent -- --exact`
- `cargo test -p swarm-runtime --test pounceagent_integration pounceagent_emits_governance_veto_for_destructive_action -- --exact`
- `cargo test -p swarm-runtime --test pounceagent_integration`
- `cargo test -p swarm-runtime --test dispatch_integration governance_veto_records_failure_receipt_without_execution -- --exact`
- `cargo test -p swarm-runtime --test dispatch_integration`
- `cargo check -p swarm-runtime`

### Package Re-Verification Blocker

`cargo test -p swarm-core -p swarm-policy -p swarm-runtime` is currently failing in a pre-existing dirty-worktree regression cluster outside the Phase 126 write set:

- `crates/swarm-runtime/src/drafting.rs`
- `crates/swarm-runtime/src/evolution.rs`
- `crates/swarm-runtime/src/mutation.rs`
- `crates/swarm-runtime/src/portfolio.rs`
- `crates/swarm-runtime/src/replay/core.inc`
- `crates/swarm-runtime/src/selection.rs`

Common failing signatures:

- `VerificationFailed { verification_id: "verification:office_baseline_control:office_baseline_control:office_detector_safety_v1" }`
- expected review states such as `ReadyForQueue`, `ReadyForManualReview`, or `PendingReview` now materializing as `Blocked`

Phase 126 did not modify those modules. The phase-specific truth set is green, but formal package-wide closeout remains blocked until that separate regression cluster is resolved.
