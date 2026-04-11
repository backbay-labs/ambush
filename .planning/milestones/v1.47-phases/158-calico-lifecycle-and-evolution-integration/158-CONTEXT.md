# Phase 158: Calico Lifecycle And Evolution Integration - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 158 turns the Phase 157 core deception lane into a durable subsystem: decoys need lifecycle state, Sphinx registration, and a fitness signal path into Kitten.

</domain>

<decisions>
## Implementation Decisions

- Extend `CalicoAgent` with explicit deploy / monitor / rotate / cleanup lifecycle state instead of treating baseline playbook requests as fire-and-forget.
- Register deployed decoys in Sphinx through a typed runtime-owned metadata seam rather than trying to infer durable inventory only from generic threat deposits.
- Feed deception interactions into Kitten through the existing durable fitness path so decoy engagement becomes a positive signal that survives restart and can affect later generations.

</decisions>

<code_context>
## Existing Code Insights

- `crates/swarm-runtime/src/calico_agent.rs` now owns the playbook and high-confidence interaction logic, so lifecycle work should build on that state instead of duplicating it elsewhere.
- `crates/swarm-runtime/src/sphinx_agent.rs` already persists a file-backed typed graph and is the right seam for durable decoy registration and later correlation.
- `crates/swarm-runtime/src/kitten_agent.rs` plus `crates/swarm-evolution/src/mutation.rs` already maintain durable population and episode state, which is the right place to weight deception-trigger validation.

</code_context>

<deferred>
## Deferred Ideas

- Fileless execution detection remains Phase 159.
- Behavioral baselines remain Phase 160.
- Broader evasion-corpus and Z3 verification work remain queued in v1.48.

</deferred>
