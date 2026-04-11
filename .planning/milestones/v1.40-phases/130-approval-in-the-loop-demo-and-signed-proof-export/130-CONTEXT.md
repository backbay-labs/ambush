# Phase 130: Approval-In-The-Loop Demo And Signed Proof Export - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 130 completes the human-in-the-loop demo story introduced by the replay and dashboard phases. The owned outcome is a real end-to-end approval path: demo replay must pause on `RequireHuman`, the operator approval vote endpoint must resume the paused action through the real runtime, and the finished run must export one JSON proof package with signed approval evidence, Merkle proofs, the final correlated incident, and the full demo decision timeline.

</domain>

<decisions>
## Implementation Decisions

### Keep Approval State In Runtime-Owned Demo State
- Paused demo approvals should live beside the existing replay timeline and incident state in `IngestState`, not in an operator-only store.
- The runtime already owns run IDs, replay lifecycle, and timeline state, so it is the natural place to remember which paused action is resumable.
- Proof export should read from that same runtime-owned registry so the output is one coherent demo artifact rather than an ad hoc join across unrelated stores.

### Reuse The Existing Approval Harness
- Approval-set, ledger, verdict, and receipt-pack generation already exist in `approval.rs`; Phase 130 should compose those primitives instead of introducing a second demo-only approval system.
- The operator approval vote endpoint in `http/core.inc` is the right approval trigger, because the roadmap requirement explicitly calls for approval through the approval-set vote surface.
- The runtime resume endpoint should verify the exported receipt pack before resuming execution so the approval chain remains auditable.

### Resume Through The Canonical Runtime Path
- A resumed action must execute through the same runtime authorization, guard, lease, and adapter wiring used by the rest of the live runtime.
- The only new exception is that a previously human-approved action needs a deliberate resume path that can convert a `RequireHuman` policy decision from skipped to executable while preserving audited provenance.
- The clean seam for this is `SwarmRuntime`, because it already owns audited authorization/execution and can produce the final receipt-bearing `AuditTrail`.

### Keep The Output Demo-Friendly
- `GET /v1/demo/proof` should export a ready-to-inspect JSON package instead of asking operators to reconstruct proof from multiple endpoints.
- The package needs the signed approval receipt pack, Merkle proofs over timeline receipts, the final correlated incident, and the full decision timeline because those are the pieces the live demo story needs in one place.
- The phase does not need a UI for proof inspection; that can remain a raw JSON export for now.

</decisions>

<code_context>
## Existing Code Insights

### Runtime Surfaces Already In Place
- `crates/swarm-runtime/src/ingest.rs` already owns demo replay handling, live demo state, runtime HTTP routes, and event emission. It is the right file for pause tracking, resume routing, and proof export.
- `crates/swarm-runtime/src/http/core.inc` already exposes approval-set and approval-ledger routes plus the authenticated operator surface, so it can bridge operator votes back into the runtime demo resume endpoint.
- `crates/swarm-runtime/src/lib.rs` already centralizes audited runtime authorization and execution, which makes it the correct place to add a human-approved execution path without forking runtime behavior elsewhere.

### Approval And Proof Building Blocks Exist
- `crates/swarm-runtime/src/approval.rs` already persists approval sets, ledgers, verdicts, signed receipt packs, and receipt-pack verification logic.
- `crates/swarm-crypto` already provides canonical JSON hashing plus `MerkleTree` and `MerkleProof`, so demo proof packaging can stay deterministic and verifiable.
- `crates/swarm-spine` already carries `AuditTrail`, correlated incidents, and receipt-bearing response outcomes, which can be embedded directly into the exported proof package.

### Constraints From The Current Runtime
- The live runtime stack inside `IngestState` uses `ConfigurableApprovalGate`, so tests need a non-empty repository ruleset to reach static fallback behavior instead of fail-closed empty-ruleset denial.
- Signed approval votes bind `voter_id` to the signer’s public key identity (`swarm:ed25519:...`), so approval-eligible operator identities must match that signer-derived voter ID for end-to-end approval to succeed.
- The repo is already dirty outside the Phase 130 write set, so this phase should avoid reverting unrelated work while still leaving the new approval/proof path fully verified.

</code_context>

<specifics>
## Specific Ideas

- Keep a per-run `pending_approvals` index in demo state so `/v1/demo/approvals/{approval_set_id}/resume` can resolve the paused action quickly and deterministically.
- Record both the initial skipped audit and the resumed receipt-bearing audit in the demo run so the proof package shows the full transition from `RequireHuman` pause to approved execution.
- Let the operator approval vote endpoint auto-create the verdict, export the receipt pack, and call the runtime resume endpoint once quorum is met, so the operator flow stays one click and one signed vote.

</specifics>

<deferred>
## Deferred Ideas

- A richer operator UI for proof inspection remains out of scope; Phase 130 only needs the JSON export.
- Providence delivery and external drilldown links remain Phase 131.
- Generalized alias mapping between human-friendly operator names and signer-derived approval voter identities is deferred; Phase 130 uses the existing signer-bound approval identity model.

</deferred>
