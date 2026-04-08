# Phase 127: Integration Hardening - Research

**Date:** 2026-04-08
**Phase:** 127
**Status:** Complete

## What Already Exists

The v1.39 milestone already has strong phase-local proof points:

- `crates/swarm-runtime/tests/dispatch_integration.rs`
  - `pounceagent_dry_run_routes_through_runtime_path`
  - `expired_capability_lease_fails_closed_before_execution`
  - `receipt_preserves_original_hunt_id_and_lineage_evidence`
  - `governance_veto_records_failure_receipt_without_execution`
- `crates/swarm-runtime/tests/pounceagent_integration.rs`
  - `pounceagent_skips_scope_present_in_peer_findings`
  - `pounceagent_emits_governance_veto_for_destructive_action`
- `crates/swarm-runtime/tests/escalation_integration.rs`
  - `concentration_monitor_deescalates_after_cooldown`
- `crates/swarm-policy/src/configurable_gate.rs`
  - `configurable_gate_denies_when_rules_are_empty`

That means Phase 127 should not re-open settled feature work from Phases 124-126. The real job is to fill the remaining combined-path gaps and make the full milestone validation surface stable.

## Gaps Identified

### 1. Routed No-Double-Trigger Proof Is Missing

`PounceAgent` already has agent-local dedupe proof, but the roadmap asks for the stronger end-to-end truth: the same escalation should not cause multiple routed runtime executions while the swarm stays in the same elevated session.

Needed proof:

- A dispatcher-backed test with a real `PounceAgent`
- A counting runtime/executor/router
- Two deliveries of the same escalation signal inside one elevated session
- Exactly one routed execution

### 2. Fail-Closed Empty-Rules Proof Stops At The Policy Unit Layer

`ConfigurableApprovalGate` already denies empty rulesets in unit tests, but Phase 127 wants confidence that the fail-closed rule actually blocks routed autonomous response instead of being bypassed by runtime composition.

Needed proof:

- A runtime built with `ConfigurableApprovalGate::from_config(&PolicyConfig::default())`
- A real routed PounceAgent request
- Executor call count stays at zero
- Audit trail shows the fail-closed configurable rule attribution

### 3. Routed Lease-Expiry Path Is Not Auditable Today

`authorize_and_execute()` correctly fails closed on expired leases, but the audited routed path still propagates the error before an `AuditTrail` exists. Governance veto already has a synthetic failure receipt path; expired leases do not.

This is the one concrete runtime gap that Phase 127 should harden, because it affects operator-visible lineage for a real safety boundary.

Needed change:

- Teach `audit_authorize_and_execute_instrumented()` to convert expired-lease denial into a synthetic failure-shaped audit record
- Preserve policy attribution and lineage
- Keep executor call count at zero

### 4. Cooldown Re-Trigger Resistance Lacks A Routed Proof

`ConcentrationMonitor` de-escalation is already covered, but the milestone-specific risk is behavioral: a quiet period shorter than `deescalation_cooldown_secs` must not let a second burst re-trigger autonomous response before the session resets.

Needed proof:

- Shared `SwarmModeState` between `ConcentrationMonitor` and `AgentDispatcher`
- Burst -> response -> decay below threshold without full cooldown -> second burst
- Routed execution count remains one until de-escalation actually occurs

### 5. Canonical Verification Budget Was Too Tight For Current Debug Test Runs

The package blocker on `office_detector_safety_v1` was not a Phase 126 behavior bug. It was a repo-owned absolute detect-latency budget that had fallen below the current debug-test runtime envelope.

That is part of Phase 127 hardening because proof-backed queue/evolution flows depend on this canonical verification artifact staying green.

## Recommended Plan Shape

### Plan 127-01

Own the routed-path hardening:

- stabilize the canonical office verification latency budget
- add routed integration proof for no-double-trigger
- add routed integration proof for fail-closed empty rules
- harden lease-expiry into an auditable failure path and prove it

### Plan 127-02

Own the cooldown/session regression proof and milestone closeout:

- add burst-decay-burst proof with shared mode state and dispatcher-backed execution counts
- re-run milestone-wide validation
- require `cargo test --workspace`
- require `cargo clippy --workspace -- -D warnings`

## Implementation Guidance

- Prefer extending `dispatch_integration.rs` instead of creating a second large router/executor harness unless helper extraction becomes unavoidable.
- Reuse `PounceAgent` directly for no-double-trigger and fail-closed policy proofs; those behaviors are phase-specific and should not be tested only with `OneShotRequestAgent`.
- Reuse the existing synthetic failure pattern from `audit_governance_veto()` for expired-lease audit hardening.
- Keep workspace/clippy verification phase-owned. This phase is the milestone hardening gate, not just another test file change.
