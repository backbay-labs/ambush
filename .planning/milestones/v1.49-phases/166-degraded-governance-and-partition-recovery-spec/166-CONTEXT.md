# Phase 166: Degraded Governance And Partition Recovery Spec - Context

**Gathered:** 2026-04-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 166 turns the shipped degraded-governance, contingency lease, partition, and reconciliation behavior into one explicit fail-closed runtime contract. It is specification work, not a new resilience feature milestone.

</domain>

<decisions>
## Implementation Decisions

- Use current runtime partition state, health surfaces, and reconciliation markers as the contract anchor.
- Describe contingency leases as bounded exceptions, not a second autonomous response path.
- Keep disaster recovery and operator review responsibilities explicit wherever partition-era actions can diverge.

</decisions>

<code_context>
## Existing Code Insights

- Partition authority, contingency leases, and reconciliation already shipped in phases 155 and 156.
- `docs/DR-RUNBOOK.md`, `docs/CONFIGURATION.md`, and serve-mode health surfaces already expose parts of this behavior but not as one cohesive contract.
- The planning layer needs one fail-closed statement of what happens during healthy, degraded, partitioned, and healing states.

</code_context>

<deferred>
## Deferred Ideas

- New coordination protocols, gossip meshes, or topology expansion are out of scope.
- This phase does not change the lease model; it documents and bounds it.

</deferred>
