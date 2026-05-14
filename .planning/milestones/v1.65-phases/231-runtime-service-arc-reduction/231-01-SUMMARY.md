---
phase: 231-runtime-service-arc-reduction
plan: 01
subsystem: runtime
tags: [runtime, ingest, service, ownership, request-path]
requirements-completed: [SVCMOD-02]
one-liner: "Narrowed request-facing execution paths to a separately swapped shared runtime handle so ingest routing and human-approved demo replay no longer clone the full configured stack just to reach audited execution."
completed: 2026-04-13
---

# Phase 231 Plan 01 Summary

**Narrowed request-facing execution paths to a separately swapped shared runtime handle so ingest routing and human-approved demo replay no longer clone the full configured stack just to reach audited execution.**

## Accomplishments

- Changed `RuntimeService` to own `Arc<SwarmRuntime<P, E>>` and added `shared_runtime()` so the execution runtime is now an explicit, cloneable narrow handle instead of an implementation detail hidden behind the wider service object.
- Added `request_runtime: Arc<ArcSwap<IngestRequestRuntime>>` to ingest state and updated reload to swap that handle in lockstep with the rebuilt configured stack.
- Rewired `IngestRuntimeRequestResponseRouter` to load only the shared runtime handle for request routing and governance-veto routing, which removes the previous full-stack clone from those request-facing paths.
- Updated the human-approved demo replay and approval-resume paths to execute through the narrowed runtime handle, while leaving the broader configured stack only where correlation or full service processing is still required.

## Files Created Or Modified

- `crates/swarm-runtime/src/service/runtime_service.rs`
- `crates/swarm-runtime/src/ingest/mod.rs`
- `crates/swarm-runtime/src/ingest/demo.rs`
- `.planning/phases/231-runtime-service-arc-reduction/231-CONTEXT.md`
- `.planning/phases/231-runtime-service-arc-reduction/231-01-PLAN.md`

## Verification

- `cargo check -p swarm-runtime`
- `cargo test -p swarm-runtime --lib service::`
- `cargo test -p swarm-runtime --lib human_gated_demo_replay_can_resume_and_export_proof`
- `cargo test -p swarm-runtime --lib approval_vote_endpoint_resumes_demo_runtime_and_proof_export`
- `cargo clippy -p swarm-runtime --lib --bins -- -D warnings`

## Notes

- The narrowed handle is intentionally limited to audited execution and runtime mode reads. Hot paths that still need the full configured stack, such as `process_event_with_finding_observer`, continue to use the broader stack because they genuinely depend on substrate, replay, and investigation wiring.
