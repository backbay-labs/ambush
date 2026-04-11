# Phase 154: Byzantine Safety And Multi-Instance Governance - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 154 turns the unsigned consensus core into an admitted, signed, runtime-owned governance path. The work spans message authenticity, equivocation handling, TomAgent consensus routing, registry-backed admission rejection, and signed governance receipts.

</domain>

<decisions>
## Implementation Decisions

- Extend the Phase 153 `swarm-consensus` engine instead of wrapping it in a second runtime-specific protocol layer.
- Reuse persistent Ed25519 agent identities and the existing `AgentIdentityRegistry` as the root of trust for both consensus message verification and admitted governance participation.
- Keep single-instance mode working by treating it as an explicit `1-of-1` committee path through the same consensus API rather than preserving a separate Tom-only decision mechanism.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-consensus/src/lib.rs` now owns committee rotation, round timeouts, commit hashing, and message envelopes, which is the correct place to add signatures and equivocation detection next.
- `crates/swarm-runtime/src/tom_agent.rs` still enforces only local synchronous destructive-action veto, so distributed approval routing has not started yet.
- `crates/swarm-runtime/src/agent_identity.rs` already persists stable Ed25519 keys and a durable admission registry, which is the right input for consensus verification and exclusion logic.
- `crates/swarm-runtime/src/dispatcher.rs` and `crates/swarm-pheromone/src/substrate.rs` already own governance-action routing and admitted-identity checks, which are the seams that need to move from local-only to consensus-backed behavior.

</code_context>

<deferred>
## Deferred Ideas

- Partition detectors, contingency leases, and reconciliation remain Phase 155 work.
- Byzantine chaos injection, partition simulation, and cascading-failure proof remain Phase 156 work.

</deferred>
