---
phase: 124-pounceagent-core-and-de-escalation
plan: 04
subsystem: runtime
tags: [dispatcher, runtime, lease, lineage, binary]
provides:
  - dispatcher-owned `RequestResponse` routing through the canonical runtime path
  - fail-closed lease expiry enforcement before any adapter execution
  - live serve-mode router wiring plus `PounceAgent` registration
  - dispatch integration proof for routed execution, dry-run parity, lease expiry, and lineage preservation
affects:
  - 124 verification
  - 125 planning baseline
key-files:
  created:
    - .planning/phases/124-pounceagent-core-and-de-escalation/124-04-SUMMARY.md
  modified:
    - crates/swarm-runtime/src/dispatcher.rs
    - crates/swarm-runtime/src/ingest.rs
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/src/bin/swarm_detect.rs
    - crates/swarm-runtime/tests/dispatch_integration.rs
    - crates/swarm-runtime/examples/fast_detection_bench.rs
    - .planning/phases/124-pounceagent-core-and-de-escalation/124-VALIDATION.md
requirements-completed: [POUNCE-04, POUNCE-05, POLICY-01]
completed: 2026-04-08
---

# Phase 124 Plan 04 Summary

**`RequestResponse` now routes through the same runtime path in live and dry-run mode, lease expiry fails closed before adapter execution, and routed audits keep the original hunt lineage intact**

## Accomplishments

- Added a type-erased `RequestResponseRouter` seam to `AgentDispatcher`, plus `tick_once()` for deterministic integration driving, so agents stay generic-free while dispatcher-owned routing can call the canonical runtime.
- Replaced the dispatcher no-op arm for `SwarmAction::RequestResponse` with real request reconstruction, routing, and structured logging; peer-visible request-response findings now include scope metadata for same-scope dedupe.
- Added `IngestState::current_request_response_router()` backed by the live `ArcSwap` runtime stack so serve mode routes autonomous actions through the current configured runtime even after reloads.
- Registered `PounceAgent` in `swarm_detect` using the repository response playbook and the new dispatcher router seam.
- Added explicit lease-expiry denial in both `authorize_and_execute()` and `audit_authorize_and_execute_instrumented()` so `expires_at_ms <= now_ms` fails closed before any adapter call.
- Extended `dispatch_integration` with the exact routed-execution, dry-run parity, lease-expiry, and lineage-preservation proofs required by the phase.

## Task Commits

No task commit was created for this plan.

The workspace still contains unrelated local edits across multiple runtime files, so the completed routing work remains as local workspace state rather than being mixed into a task commit with unrelated changes.

## Decisions Made

- Kept the dispatcher seam type-erased with `RequestResponseRouter` instead of threading `SwarmRuntime<P, E>` generics into agents or dispatcher callers.
- Built routed `ActionRequest` values from the existing Pounce evidence bundle, using `escalation.severity` as the policy-driving severity and preserving the original evidence payload intact.
- Reconstructed a minimal `DetectionFinding` from request lineage inside the runtime-backed router so the instrumented audit path can preserve the original `hunt_id`, `event_id`, and lineage-bearing evidence end-to-end.
- Bound the live router to `IngestState`'s `ArcSwap` stack so runtime mode changes from config reloads are reflected without recreating the dispatcher.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Repaired the benchmark example's `PheromoneConfig` literal during broader phase verification**
- **Found during:** package-wide `cargo test -p swarm-core -p swarm-policy -p swarm-runtime`
- **Issue:** `crates/swarm-runtime/examples/fast_detection_bench.rs` still initialized the pre-Phase-124 `PheromoneConfig` shape, so broad package verification failed even though the routed dispatch tests were green.
- **Fix:** Added `deescalation_cooldown_secs` and `response_playbook` to the example fixture so the owned example target compiles with the new config seam.
- **Files modified:** `crates/swarm-runtime/examples/fast_detection_bench.rs`
- **Verification:** `cargo test -p swarm-core -p swarm-policy -p swarm-runtime`

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** No scope change. The deviation only reconciled an owned example target that broad verification surfaced after the intended routing work was already complete.

## Verification Notes

- `rg -n "request_response_routes_through_authorize_and_execute|pounceagent_dry_run_routes_through_runtime_path|expired_capability_lease_fails_closed_before_execution|receipt_preserves_original_hunt_id_and_lineage_evidence" crates/swarm-runtime/tests/dispatch_integration.rs` passed
- `cargo test -p swarm-runtime --test dispatch_integration request_response_routes_through_authorize_and_execute -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration pounceagent_dry_run_routes_through_runtime_path -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration expired_capability_lease_fails_closed_before_execution -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration receipt_preserves_original_hunt_id_and_lineage_evidence -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration` passed
- `cargo check -p swarm-runtime --bin swarm_detect` passed
- `cargo test -p swarm-core -p swarm-policy -p swarm-runtime` passed

## Next Phase Readiness

Phase 125 can now assume:

- autonomous `RequestResponse` actions no longer stop at the dispatcher
- dry-run and live autonomous responses share the same runtime path
- policy leases fail closed on stale capability windows before any adapter execution
- routed audit records preserve the original hunt lineage needed for later policy/audit hardening
