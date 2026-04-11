# Phase 155: Partition Authority And Contingency Leases - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 155 adds bounded authority during quorum loss. The work spans partition detection, contingency-lease issuance and redemption, destructive-response fail-closed behavior during partition, and reconciliation when quorum returns.

</domain>

<decisions>
## Implementation Decisions

- Build partition authority on top of the Phase 154 governance seam instead of introducing a separate emergency-control path.
- Keep detection fail-open during partition while making destructive response contingent on an explicit consensus-issued lease.
- Use durable state for partition and lease tracking so healing/restart paths can reconcile authorized versus unauthorized actions deterministically.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/tom_agent.rs` now owns in-process governance receipt issuance and is the natural seam for partition-aware contingency authorization.
- `crates/swarm-runtime/src/dispatcher.rs` already fail-closes destructive routing when governance receipts are missing, which is the right enforcement point for lease-gated partition behavior.
- `crates/swarm-consensus/src/lib.rs` now exposes signed governance receipts and exclusion receipts, so lease issuance can reuse the same receipt model instead of inventing parallel approval artifacts.
- `crates/swarm-pheromone/src/substrate.rs` and runtime admission wiring now share a registry-backed allowlist, giving partition logic a trustworthy participant set to measure quorum against.

</code_context>

<deferred>
## Deferred Ideas

- Adversarial partition and Byzantine chaos injection remain Phase 156 work.
- Cross-process transport and large-cluster consensus scaling remain out of scope for this milestone.

</deferred>
