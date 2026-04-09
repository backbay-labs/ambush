# Phase 141 Context

## Goal

Establish SphinxAgent and a durable knowledge graph store as the persistent memory substrate for the swarm.

## Requirements

- `SPHINX-01`
- `SPHINX-02`

## Relevant Code

- `crates/swarm-core/src/agent.rs`
- `crates/swarm-runtime/src/dispatcher.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-evolution/src/strategy.rs`
- `crates/swarm-pheromone/`

## Starting Point

- `AgentRole::Sphinx` already exists in `crates/swarm-core/src/agent.rs`, but no runtime-owned Sphinx agent or persistent memory store is implemented yet.
- The repo already has durable strategy-memory artifacts in `crates/swarm-evolution/src/strategy.rs`, which provide a useful model for file-backed memory records and operator-readable indexing.
- v1.42 completed a full evolution loop, so the next milestone can build on a real mutation, canary, and strategy-memory surface instead of starting from a blank slate.

## Constraints

- Sphinx must be a first-class runtime agent, not a sidecar script or out-of-process cache.
- The knowledge graph must be durable and typed; reusing the pheromone substrate directly as long-lived memory would violate the milestone boundary.
- Phase 141 should stop at foundations: graph model, durable store, agent lifecycle, and startup wiring. Query pheromones and fitness retrieval belong to Phase 142.

## Open Integration Seams

- There is no `FileKnowledgeGraphStore`, typed graph schema, or repo-owned memory config surface yet.
- Serve mode does not register a Sphinx agent, and the dispatcher has no memory-oriented runtime behavior beyond existing peer visibility.
- Strategy memory exists, but it is rollout-oriented rather than a general cross-engagement knowledge graph.
