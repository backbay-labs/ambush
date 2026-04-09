# Phase 144 Plan 01 Summary

## Delivered

- Extended `crates/swarm-runtime/src/kitten_agent.rs` so Kitten now freezes one adversarial corpus snapshot per generation through `SuiteRedSwarmAdapter`, reuses that deterministic corpus identity across same-generation candidate evaluations, and folds adversarial pressure into the final proposal fitness after replay and optional Sphinx memory retrieval.
- Added durable red-blue episode persistence in `crates/swarm-evolution/src/mutation.rs` with `EvolutionEpisodeReport`, `EvolutionEpisodeRecord`, `EvolutionAdversarialPressureRequest`, and `FileEvolutionEpisodeStore`, capturing corpus sequence and version, genome hash, per-threat-class coverage, and blue-versus-red fitness vectors.
- Extended `crates/swarm-runtime/src/evolution_status.rs` so the evolution status surface now reports current generation, latest episode, corpus sequence and version, best genome hash, and adversarial detection metrics from the durable episode store.
- Updated focused runtime and evolution tests so the new replay -> memory -> adversarial fitness pipeline is exercised directly, including same-generation corpus freezing, fallback behavior, restore-path proposal emission, durable episode persistence, and operator-visible status summaries.

## Notes

- `RuntimeEvent::EvolutionStatus` did not need its own schema rewrite because it already serializes `EvolutionStatusReport`; the richer adversarial state now rides through that existing runtime-event channel automatically.
- The generation-scoped corpus snapshot is intentionally deterministic and currently anchored to the tracked `scenario-suites/hellcat-office-v1.yaml` suite. That keeps the new fitness and episode history reproducible while leaving broader corpus selection to later adversarial-breadth milestones.
