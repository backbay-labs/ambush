# Phase 143 Plan 01 Summary

## Delivered

- Added `memory.knowledge_retention_days` in `crates/swarm-core/src/config.rs` and `rulesets/default.yaml`, including validation that fails closed when memory retention is configured as zero.
- Extended `crates/swarm-runtime/src/sphinx_agent.rs` so Sphinx prunes stale nodes, edges, and processed-observation metadata on tick using the configured retention window instead of letting the durable graph grow without bound.
- Hardened `FileKnowledgeGraphStore::persist_snapshot()` so stale node and edge bundle files are removed from disk when retention GC drops them from the index, keeping the typed graph store physically bounded as well as logically bounded.
- Added `crates/swarm-runtime/src/red_swarm.rs` with a runtime-owned `RedSwarmAdapter` trait, a deterministic suite-backed `SuiteRedSwarmAdapter`, a `ThreatContext` contract, and a `MockRedSwarm` test double for later red-blue fitness work.
- Exposed the minimal replay-manifest seam in `crates/swarm-runtime/src/replay/core.inc` so runtime-owned adversarial generation can reuse tracked suite manifests and scenario loaders directly instead of inventing a second corpus format.

## Notes

- The default red-side adapter stays Rust-native and deterministic: it loads `scenario-suites/` YAML, filters benign controls unless explicitly requested, rebases timestamps from `ThreatContext.requested_at_ms`, and prefixes generated event IDs with the requested sequence identity.
- Phase 143 stops at bounded memory plus corpus generation by design. Kitten fitness consumption of the generated corpus and durable red-blue episode logging remain Phase 144 work.
