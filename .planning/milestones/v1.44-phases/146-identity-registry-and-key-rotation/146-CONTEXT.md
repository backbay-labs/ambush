# Phase 146: Identity Registry And Key Rotation - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 146 builds on the shipped persistent-key seam by adding admission state and continuity tracking: a registry of known agent identities, startup verification against that registry, and a safe key-rotation workflow that preserves historical verification.

</domain>

<decisions>
## Implementation Decisions

### Registry Scope
- Add a repo-owned identity-registry artifact rather than hiding admission state inside the pheromone substrate.
- Treat startup registration as a local durable control-plane concern for now; cross-instance registry synchronization is deferred to distributed-governance phases.
- Reject unknown identities from governance participation first, rather than trying to reject every pheromone deposit in this phase.

### Rotation Model
- Keep the existing active key files in place for runtime use, but persist retired keys and continuity proofs alongside the registry so historical signed artifacts remain verifiable after rotation.
- Represent continuity proof as a signed handoff payload from old key to new public key with timestamps and role / slot metadata.
- Expose rotation through a repo-owned runtime seam or CLI path, not an out-of-band filesystem script.

### Verification Boundary
- Prove restart-safe admission and continuity-proof persistence locally.
- Leave multi-instance registry synchronization and global substrate-side registry enforcement to later governance work tied to consensus.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-runtime/src/agent_identity.rs` already resolves config-relative key paths and persists raw Ed25519 seed bytes per role / slot.
- `crates/swarm-runtime/src/bin/swarm_detect.rs` now loads persisted identities during serve bootstrap for every runtime agent.
- `crates/swarm-response` and `crates/swarm-runtime/src/service.rs` already carry stable `AgentId` values through action requests, receipts, and audit trails.

### Integration Points
- `swarm_detect --serve` is the correct place to admit persisted identities into a registry during runtime startup.
- `TomAgent`, `PounceAgent`, and dispatcher-governed request / veto flows are the governance surfaces that should fail closed for unknown identities first.
- `swarm-pheromone` signature verification still trusts embedded keys only; full registry-backed substrate rejection is a later governance requirement and should not be over-scoped here.

</code_context>

<deferred>
## Deferred Ideas

- Registry synchronization across nodes and substrate-wide rejection of unregistered deposits belong to the distributed-governance milestone.
- Automatic remote attestation or operator approval of unknown identities is out of scope for this phase.

</deferred>
