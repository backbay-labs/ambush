---
phase: 84-real-response-adapters
plan: 02
subsystem: runtime
tags: [response, runtime, dispatch, audit, guards, policy]
requirements-completed: [RESP-01, RESP-02]
one-liner: "the runtime now selects live response executors from config, records dispatched outcomes in the audit trail, and proves guard, policy, success, and timeout behavior through integration tests."
completed: 2026-04-05
---

# Phase 84 Plan 02 Summary

**the runtime now selects live response executors from config, records dispatched outcomes in the audit trail, and proves guard, policy, success, and timeout behavior through integration tests.**

## Accomplishments

- Added `DispatchingExecutor` so runtime config can choose between sandbox, HTTP EDR, and webhook adapters.
- Added `response_adapter` to `SwarmConfig` with sandbox default and validation, keeping backward-compatible config loading intact.
- Added `ConfiguredRuntimeStack::from_config` and switched the production control plane and ingest stack over to config-driven response dispatch.
- Updated runtime execution reporting so timeout and failed adapter receipts become structured audit failures instead of silent successes.
- Added integration coverage for dispatched success, guard rejection, policy skip, and webhook timeout behavior in the runtime audit path.

## Files Created Or Modified

- `crates/swarm-core/src/config.rs`
- `crates/swarm-response/src/dispatch.rs`
- `crates/swarm-response/src/lib.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/tests/dispatch_integration.rs`

## Verification

- `cargo test -p swarm-runtime --test dispatch_integration`
- `cargo test --workspace`

## Notes

- `authorize_and_execute` still returns `RuntimeError::Response` on non-success receipts, but the audit path now preserves the adapter-provided timeout or failure record in `AuditResponseRecord::Failure`.
