---
phase: 124-pounceagent-core-and-de-escalation
verified: 2026-04-08T07:31:51Z
status: passed
score: 5/5 must-haves verified
re_verification: false
must_haves:
  truths:
    - "PounceAgent emits `SwarmAction::RequestResponse` in elevated mode and dispatcher routing carries it through the canonical policy, guard, and execution path"
    - "Detect-only autonomous responses exercise the same runtime path and yield simulated receipts"
    - "Capability leases fail closed when `expires_at_ms <= now_ms`, before any adapter call"
    - "Scope-bearing peer findings suppress duplicate PounceAgent responses within an elevated session"
    - "ConcentrationMonitor de-escalates back to `Normal` after the configured cooldown and clears the triggering threat class"
  artifacts:
    - path: "crates/swarm-runtime/src/pounce_agent.rs"
      provides: "playbook-driven PounceAgent emission and same-session dedupe"
      contains: "peer_findings_cover_scope"
    - path: "crates/swarm-runtime/src/dispatcher.rs"
      provides: "dispatcher-owned request-response routing seam and scope-aware peer findings"
      contains: "RequestResponseRouter"
    - path: "crates/swarm-runtime/src/lib.rs"
      provides: "fail-closed lease expiry enforcement in both runtime execution paths"
      contains: "ensure_active_lease"
    - path: "crates/swarm-runtime/src/escalation.rs"
      provides: "cooldown-gated de-escalation back to `Normal`"
      contains: "below_threshold_since"
    - path: "crates/swarm-runtime/tests/dispatch_integration.rs"
      provides: "phase proof for routed execution, dry-run parity, lease denial, and lineage preservation"
      contains: "request_response_routes_through_authorize_and_execute"
  key_links:
    - from: "crates/swarm-runtime/src/pounce_agent.rs"
      to: "crates/swarm-runtime/src/dispatcher.rs"
      via: "`SwarmAction::RequestResponse` plus scope-bearing peer-finding summaries"
      pattern: "scope="
    - from: "crates/swarm-runtime/src/dispatcher.rs"
      to: "crates/swarm-runtime/src/lib.rs"
      via: "type-erased runtime routing into `audit_authorize_and_execute()`"
      pattern: "route_request"
    - from: "crates/swarm-runtime/src/escalation.rs"
      to: "crates/swarm-core/src/agent.rs"
      via: "cooldown completion invoking explicit downward transition"
      pattern: "transition_down"
---

# Phase 124: PounceAgent Core And De-escalation Verification Report

**Phase Goal:** Operators can observe PounceAgent autonomously consuming escalation pheromones, routing through the policy gate and guard pipeline, and emitting signed receipts with detection lineage; mode de-escalation returns the runtime to `Normal` when threat pressure drops.
**Verified:** 2026-04-08T07:31:51Z
**Status:** passed
**Re-verification:** No

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Elevated-mode PounceAgent requests route through policy, guards, and execution instead of stopping at a dispatcher no-op | VERIFIED | `pounceagent_integration` proves PounceAgent emits `RequestResponse`; `dispatch_integration::request_response_routes_through_authorize_and_execute` proves dispatcher routing invokes approval, lease issuance, guard evaluation, and execution on the canonical runtime path. |
| 2 | Detect-only autonomous responses use the same runtime path and produce simulated receipts | VERIFIED | `dispatch_integration::pounceagent_dry_run_routes_through_runtime_path` shows dispatcher-routed autonomous requests still evaluate policy and guards and return `ResponseStatus::Simulated` through `ExecutionMode::DryRun`. |
| 3 | Stale leases fail closed before any adapter call | VERIFIED | `dispatch_integration::expired_capability_lease_fails_closed_before_execution` proves `ApprovalError::Denied(\"capability lease expired\")` is returned before the executor sees the request. |
| 4 | Duplicate same-scope autonomous responses are suppressed | VERIFIED | `pounceagent_integration::pounceagent_skips_scope_present_in_peer_findings` proves scope-bearing peer findings suppress duplicate emissions, and dispatcher request-response findings now publish `scope=...` summaries for live peer visibility. |
| 5 | Quiet cooldown returns swarm mode to `Normal` and clears the triggering threat lineage | VERIFIED | `escalation_integration::concentration_monitor_deescalates_after_cooldown` proves `ConcentrationMonitor` holds elevated mode until cooldown completion, then calls `transition_down()` and clears `triggering_threat_class`. |

**Score:** 5/5 truths verified

### Requirements Coverage

| Requirement | Status | Evidence |
|-------------|--------|----------|
| POUNCE-01 | SATISFIED | `PounceAgent` emits playbook-selected `RequestResponse` actions during `Alert` and `Incident`. |
| POUNCE-02 | SATISFIED | Peer-finding scope dedupe suppresses duplicate autonomous responses within an elevated session. |
| POUNCE-03 | SATISFIED | Response playbook config loads through repo config and drives PounceAgent action selection. |
| POUNCE-04 | SATISFIED | Dispatcher routes autonomous requests through the canonical runtime execution path. |
| POUNCE-05 | SATISFIED | Routed dry-run responses traverse the same runtime path and produce simulated receipts with preserved lineage. |
| DEESC-01 | SATISFIED | `SwarmModeState::transition_down()` provides explicit downward transition semantics. |
| DEESC-02 | SATISFIED | `ConcentrationMonitor` de-escalates after `deescalation_cooldown_secs` of sustained quiet. |
| POLICY-01 | SATISFIED | Lease expiry enforcement now denies stale capability windows before execution in both runtime execution paths. |

### ROADMAP Success Criteria Coverage

| # | Success Criterion | Status | Evidence |
|---|-------------------|--------|----------|
| 1 | PounceAgent emits `RequestResponse` and dispatcher routes it through `authorize_and_execute()` | VERIFIED | Plan 03 emits the action; Plan 04 routes it through the runtime and proves the policy/guard/execute flow in `dispatch_integration`. |
| 2 | Dry-run mode produces simulated receipts through the identical code path | VERIFIED | `pounceagent_dry_run_routes_through_runtime_path` confirms policy, lease, guard, and receipt generation still happen under `RuntimeMode::DetectOnly`. |
| 3 | `authorize_and_execute()` denies expired leases before any adapter is called | VERIFIED | Explicit lease check added in both runtime execution paths and proven by the exact dispatch integration test. |
| 4 | PounceAgent skips duplicate same-scope responses based on peer findings | VERIFIED | Focused PounceAgent integration test proves scope-based suppression, and dispatcher summaries now preserve scope for peer visibility. |
| 5 | `ConcentrationMonitor::evaluate_all()` de-escalates after cooldown and clears triggering threat class | VERIFIED | Integration coverage proves quiet-window tracking, cooldown boundary behavior, and trigger reset. |

### Automated Verification

- `cargo check -p swarm-core -p swarm-policy && cargo test -p swarm-runtime config::tests::loads_repository_ruleset -- --exact`
- `cargo check -p swarm-runtime --lib`
- `cargo test -p swarm-core agent::tests::mode_state_transition_down_clears_triggering_threat_class -- --exact`
- `cargo test -p swarm-runtime --test escalation_integration concentration_monitor_deescalates_after_cooldown -- --exact`
- `cargo test -p swarm-runtime --test pounceagent_integration`
- `cargo test -p swarm-runtime --test dispatch_integration`
- `cargo check -p swarm-runtime --bin swarm_detect`
- `cargo test -p swarm-core -p swarm-policy -p swarm-runtime`

### Human Verification Required

None. Phase 124 is fully covered by automated config, unit, integration, and package-level verification.

### Gaps Summary

No gaps found. Phase 124 closes the autonomous response loop, fail-closed lease safety, and cooldown-based de-escalation with green automated verification across the affected crates.

---
_Verified: 2026-04-08T07:31:51Z_
_Verifier: Codex_
