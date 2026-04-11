# Phase 142 Plan 01 Summary

## Delivered

- Added a shared Sphinx memory pheromone contract in `crates/swarm-core/src/types.rs` so query and answer deposits now have stable, auditable payload schemas instead of ad hoc indicator JSON.
- Extended `crates/swarm-runtime/src/sphinx_agent.rs` so Sphinx distinguishes runtime observations from memory queries, computes Q-value-style retrieval contributions over the durable knowledge graph, and deposits signed answer pheromones back into the shared substrate.
- Extended `crates/swarm-runtime/src/kitten_agent.rs` so Kitten emits signed memory-query pheromones, waits a bounded number of dispatcher ticks for Sphinx answers, blends retrieval into candidate fitness, and records whether replay-only fallback was applied.
- Updated `crates/swarm-runtime/src/bin/swarm_detect.rs` so serve mode registers Kitten and Sphinx against the dispatcher’s shared substrate rather than isolated per-agent substrate instances.
- Exposed `RECENCY_HALF_LIFE_HOURS` from `crates/swarm-evolution/src/strategy.rs` so Sphinx retrieval uses the same recency-decay constant as the existing strategy-memory scoring path.

## Notes

- Phase 142 keeps the swarm interaction model stigmergic: Kitten and Sphinx communicate only through signed pheromone deposits on the shared substrate, not through direct RPC or shared mutable service handles.
- The current retrieval context is intentionally bounded to live pheromone-derived threat classes, ATT&CK techniques, and entity values so the new memory seam stays auditable and cheap enough for the existing dispatcher tick cadence.
