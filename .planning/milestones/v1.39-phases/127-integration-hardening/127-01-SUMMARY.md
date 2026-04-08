---
phase: 127-integration-hardening
plan: 01
subsystem: routed-hardening
tags: [runtime, integration, audit, policy, verification]
provides:
  - canonical verification budget aligned with the current debug-test runtime envelope
  - routed exact proofs for same-session dedupe, fail-closed empty rules, and auditable expired-lease denial
  - synthetic failure-audit persistence for expired leases on the autonomous dispatcher path
affects:
  - phase 126 re-verification
  - phase 127 verification
  - v1.39 proof-backed workflow stability
key-files:
  created:
    - .planning/phases/127-integration-hardening/127-01-SUMMARY.md
  modified:
    - verifications/office-detector-safety-v1.yaml
    - crates/swarm-runtime/src/replay/core.inc
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/tests/dispatch_integration.rs
requirements-completed: [POUNCE-01, POUNCE-02, POUNCE-04, POLICY-01, POLICY-03]
completed: 2026-04-08
---

# Phase 127 Plan 01 Summary

**The routed v1.39 response path is now pinned by exact proofs and no longer blocked by a stale canonical verification budget**

## Accomplishments

- Raised the repo-owned `office_detector_safety_v1` detect-latency budget to match the current debug-test runtime envelope and mirrored that budget in the replay-core fixture/assert baseline.
- Extended `dispatch_integration` with exact routed proofs for same-session no-double-trigger behavior, fail-closed empty configurable rulesets, and expired-lease denial that persists a failure-shaped audit artifact without executor calls.
- Hardened `SwarmRuntime::audit_authorize_and_execute_instrumented()` so an already-expired lease now produces an auditable failure record with preserved lineage and policy attribution instead of disappearing before audit persistence.
- Kept the proof surface centralized in the existing dispatcher-backed integration suite rather than inventing a second milestone-only harness.

## Task Commits

No task commit was created for this plan.

## Decisions Made

- Reused `dispatch_integration.rs` as the milestone proof surface because it already owned the canonical router/runtime/counting seams needed for end-to-end assertions.
- Modeled expired-lease denial after the existing synthetic governance-veto receipt path so operator-visible audit behavior stays consistent for routed safety failures.

## Verification Notes

- `cargo test -p swarm-runtime --test dispatch_integration pounceagent_routes_same_escalation_only_once_per_session -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration empty_ruleset_policy_fails_closed_for_routed_pounce_request -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration expired_lease_routing_records_failure_audit_without_execution -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration` passed
