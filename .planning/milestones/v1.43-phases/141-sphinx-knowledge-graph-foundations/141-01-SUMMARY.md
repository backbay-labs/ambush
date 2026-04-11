# Phase 141 Plan 01 Summary

## Delivered

- Added a top-level repo-owned `memory` config surface in `crates/swarm-core/src/config.rs` and `rulesets/default.yaml` so Sphinx graph persistence and temporal-correlation windows are explicit runtime configuration instead of hidden constants.
- Implemented `crates/swarm-runtime/src/sphinx_agent.rs` with a real runtime-owned `SphinxAgent`, a `FileKnowledgeGraphStore`, and a typed graph model covering threat patterns, ATT&CK techniques, entities, engagements, and temporal, causal, entity, and semantic edges.
- Wired Sphinx to ingest runtime pheromone observations into the durable graph, reuse typed node and edge identities across repeated observations, and preserve cross-engagement context through restart-safe persisted snapshots.
- Registered Sphinx in serve mode through `crates/swarm-runtime/src/bin/swarm_detect.rs` behind the new `memory.enabled` gate, keeping the startup path aligned with the existing dispatcher-owned agent lifecycle.
- Patched workspace test configurations to carry the new `memory` config surface without falling back to ad hoc field omissions in fixture construction.

## Notes

- Phase 141 intentionally stops at memory foundations. Sphinx persists and correlates graph state now, but it does not yet answer swarm-memory queries or participate in Kitten fitness retrieval.
- The current graph ingestion path is pheromone-driven because that is already the durable, runtime-owned observation seam available to Sphinx without inventing a direct RPC side channel.
