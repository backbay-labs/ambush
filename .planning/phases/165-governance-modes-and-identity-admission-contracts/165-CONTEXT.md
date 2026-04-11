# Phase 165: Governance Modes And Identity Admission Contracts - Context

**Gathered:** 2026-04-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 165 defines the canonical governance contract that operators and implementers will use. It documents the shipped runtime behavior for human gates, identity admission, receipt-backed quorum, and maintenance-only operation without inventing new governance mechanisms.

</domain>

<decisions>
## Implementation Decisions

- Treat the current runtime, config surface, and health/status outputs as the source of truth over older governance narratives.
- Keep the contract bounded: document what exists today and mark broader independent-trust-boundary governance as deferred.
- Make identity admission, approval lineage, and consensus receipts readable as one operator contract instead of three separate features.

</decisions>

<code_context>
## Existing Code Insights

- The runtime already ships identity persistence, registry admission, rotation, and fail-closed governance checks.
- `swarm-consensus` and Tom receipt flows exist, but their active semantics are not described consistently across docs.
- `docs/CONFIGURATION.md` and runtime health surfaces already expose governance-related controls that should be documented canonically.

</code_context>

<deferred>
## Deferred Ideas

- New quorum algorithms, fleet-wide governance expansion, or internet-exposed operator governance are out of scope.
- This phase should not widen autonomy beyond the current bounded receipt-backed model.

</deferred>
