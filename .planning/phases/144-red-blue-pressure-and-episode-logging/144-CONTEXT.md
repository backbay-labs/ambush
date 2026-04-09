# Phase 144 Context

## Goal

Close the loop between the Rust-native adversarial corpus seam and the evolution lane by applying red-side pressure during candidate scoring and persisting one durable episode history per generation.

## Requirements

- `HELLCAT-02`
- `HELLCAT-03`

## Relevant Code

- `crates/swarm-runtime/src/kitten_agent.rs`
- `crates/swarm-runtime/src/red_swarm.rs`
- `crates/swarm-evolution/src/mutation.rs`
- `crates/swarm-runtime/src/evolution_status.rs`

## Starting Point

- Phase 138 already made replay-backed candidate population state durable and restart-safe.
- Phase 142 already gives Kitten a bounded fitness-enrichment seam through Sphinx-backed retrieval with replay fallback.
- Phase 143 now provides a deterministic `RedSwarmAdapter` contract and a suite-backed adversarial corpus generator with stable corpus metadata.

## Constraints

- Adversarial corpus snapshots must be frozen per generation for reproducibility rather than regenerated per candidate.
- Episode logging must follow the existing repo-owned file-store patterns instead of adding an opaque side channel.
- The new pressure and logging path must not bypass the safety, verification, or canary controls already enforced in phases 137-140.

## Open Integration Seams

- `KittenAgent` does not yet call `RedSwarmAdapter`, so adversarial pressure is absent from the current fitness vector.
- No durable `EvolutionEpisode` artifact exists yet to capture corpus version, genome hash, threat-class coverage, or red-blue fitness outputs.
- The evolution status surfaces do not yet expose which corpus snapshot and episode set a generation used.
