# Phase 143 Context

## Goal

Keep Sphinx memory bounded and add a Rust-native adversarial corpus adapter that can feed the evolution lane without restoring Python-era Hellcat dependencies.

## Requirements

- `SPHINX-05`
- `HELLCAT-01`

## Relevant Code

- `crates/swarm-core/src/config.rs`
- `rulesets/default.yaml`
- `crates/swarm-runtime/src/sphinx_agent.rs`
- `crates/swarm-runtime/src/replay/core.inc`
- `scenario-suites/hellcat-office-v1.yaml`

## Starting Point

- Phase 141 shipped the durable typed knowledge graph and Phase 142 made it queryable through signed pheromone deposits with Kitten fitness integration.
- The repo already has Rust-native replay suites and tracked adversarial corpora under `scenario-suites/`, including `hellcat-office-v1.yaml`.
- There is still no retention policy for the graph and no standalone runtime-owned adapter that turns suite metadata into adversarial telemetry sequences for the evolution lane.

## Constraints

- Knowledge retention must be repo-owned, TTL-based, and implemented with the same durability expectations as the rest of the graph store.
- The adversarial adapter must stay pure Rust and deterministic; this phase should not shell out to Python or reintroduce the historical Hellcat runtime.
- Phase 143 should stop at bounded memory plus corpus generation. Phase 144 is where Kitten and episode logging actually consume the adversarial corpus.

## Open Integration Seams

- `memory` config has no retention knob yet, and `SphinxAgent` never garbage-collects stale nodes, edges, or processed observation metadata.
- The replay suite layer can execute adversarial corpora offline, but there is no `RedSwarmAdapter` abstraction or mockable sequence generator for the runtime evolution lane.
- There is no deterministic bridge yet between `scenario-suites/` manifests and a runtime-owned adversarial sequence artifact that later phases can score against.
