# Phase 153: Consensus Protocol Core - Context

**Gathered:** 2026-04-09
**Status:** Completed

<domain>
## Phase Boundary

Phase 153 is the protocol-core slice of distributed governance. It should ship the reusable Tendermint-style state machine, deterministic proposer rotation, and JetStream subject seam without yet wiring TomAgent governance execution, registry admission enforcement, or signed receipt persistence.

</domain>

<decisions>
## Implementation Decisions

- Keep the consensus implementation isolated inside `crates/swarm-consensus` so Phase 154 can integrate TomAgent and dispatcher routing without having to extract protocol code back out of `swarm-runtime`.
- Implement the round engine around explicit `proposal`, `prevote`, and `precommit` messages plus timeout-driven round advance; defer signature validation and equivocation enforcement to Phase 154.
- Derive proposer rotation from the previous commit hash plus a stable ordering of committee agent identities so every node can compute the same proposer locally with no extra coordination.
- Expose a JetStream subject layout and publish/subscribe seam in the crate, but prove correctness first with an in-process transport harness so the phase can ship deterministic protocol tests without requiring an external NATS server.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-consensus/src/lib.rs` exists only as a placeholder, so the phase can define the protocol API cleanly instead of preserving an accidental partial design.
- `crates/swarm-runtime/src/tom_agent.rs` still implements only single-instance synchronous governance veto, which confirms multi-instance governance wiring belongs to Phase 154 rather than this core protocol phase.
- `crates/swarm-pheromone/src/jetstream.rs` already establishes the project's NATS and JetStream dependency baseline, so `swarm-consensus` can reuse `async-nats` and the existing JetStream subject vocabulary without introducing a different transport stack.
- `crates/swarm-runtime/src/agent_identity.rs` and `swarm_core::types::AgentId` already provide durable stable identities, which are the right inputs for deterministic committee rotation.

</code_context>

<deferred>
## Deferred Ideas

- Signed consensus messages, equivocation detection, and exclusion receipts remain Phase 154 work.
- TomAgent BFT approval routing, registry-backed admission rejection, and governance audit receipts remain Phase 154 work.
- Partition authority, contingency leases, and reconciliation remain Phases 155 and 156 work.

</deferred>
