# Phase 178: Response Rehearsal Harness And Blast-Radius Modeling - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 178 adds a bounded rehearsal lane for response execution. The system already has one dry-run path through policy, lease issuance, runtime execution, and adapter receipts; this phase needs to expose and persist that path as an explicit rehearsal workflow while attaching typed blast-radius and rollback evidence before any live action approval.

</domain>

<decisions>
## Implementation Decisions

- Reuse the existing `ActionRequest -> ApprovalContext -> SwarmRuntime::authorize_and_execute()` path and `ExecutionMode::DryRun` semantics instead of inventing a second executor or adapter shim.
- Build blast-radius and rollback preview from the existing `ResponseAction` kind plus scoped target data so rehearsal stays on the same bounded action model the runtime already enforces.
- Persist rehearsal artifacts separately from Providence callback or feedback audit so later review surfaces can show rehearsal proof without mutating the live action record.
- Keep approval parity strict: rehearsal must still exercise the policy and lease path, but the executor mode remains non-destructive.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/lib.rs` already maps `RuntimeMode::DetectOnly` to `ExecutionMode::DryRun`, so the runtime has the correct non-destructive execution seam.
- `crates/swarm-runtime/tests/dispatch_integration.rs` already proves Pounce dry-run requests route through the full runtime path and emit simulated receipts.
- `crates/swarm-response/src/lib.rs` and adapter implementations already return normalized dry-run receipts, which can anchor rehearsal proof without special adapter logic.
- `crates/swarm-runtime/src/service.rs` already persists replay bundles with request plus audit, giving Phase 178 a natural place to hang rehearsal artifacts or previews.

</code_context>

<deferred>
## Deferred Ideas

- Providence-facing and local combined review rendering remains Phase 179.
- Rich multi-action playbook preview and generalized response-model rollout remain later response phases.

</deferred>
