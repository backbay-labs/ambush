# Phase 142 Context

## Goal

Make Sphinx memory usable by the swarm without breaking the indirect pheromone-based coordination model.

## Requirements

- `SPHINX-03`
- `SPHINX-04`

## Relevant Code

- `crates/swarm-runtime/src/sphinx_agent.rs`
- `crates/swarm-runtime/src/kitten_agent.rs`
- `crates/swarm-runtime/src/dispatcher.rs`
- `crates/swarm-core/src/types.rs`
- `crates/swarm-core/src/pheromone.rs`
- `crates/swarm-evolution/src/strategy.rs`

## Starting Point

- Phase 141 landed a real runtime-owned `SphinxAgent`, a durable `FileKnowledgeGraphStore`, and a typed graph model over pheromone observations.
- The dispatcher already gives agents indirect shared context through pheromones and peer findings, and `SwarmAction::DepositPheromone` is the existing auditable write seam.
- `KittenAgent` already computes replay-backed candidate fitness and durable population state, but it still falls back entirely to replay and verification artifacts instead of consulting swarm memory.

## Constraints

- Sphinx queries must stay stigmergic: no direct RPC, no mutable shared in-process service handle, and no special-case bypass around the existing pheromone substrate.
- Memory-aware fitness must degrade cleanly to replay-only scoring when Sphinx is disabled, stale, or has insufficient evidence for the query context.
- Phase 142 should reuse the new graph foundation rather than introducing a second memory cache or shadow scoring store.

## Open Integration Seams

- There is no query or answer pheromone contract yet for agents to ask Sphinx for memory-backed context.
- `SphinxAgent` persists graph state but does not yet interpret query deposits or emit memory answers back into the swarm.
- `KittenAgent` does not yet translate drift or candidate context into a Sphinx lookup or incorporate returned Q-value context into candidate fitness.
