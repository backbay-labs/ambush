# Phase 158 Plan 01 Summary

## Delivered

- Extended the repo-owned `deception` config in `crates/swarm-core/src/config.rs` with durable lifecycle storage, deterministic rotation and cleanup controls, and a bounded `interaction_fitness_weight` so Calico lifecycle and fitness behavior remain fail-closed and operator-owned.
- Reworked `crates/swarm-runtime/src/calico_agent.rs` so `CalicoAgent` now persists decoy inventory across restart, advances explicit deploy -> monitor -> rotate -> cleanup lifecycle stages, emits typed deception-inventory pheromones for downstream registration, and preserves interaction metadata for later attribution.
- Extended `crates/swarm-runtime/src/sphinx_agent.rs` with a durable `DeceptionAsset` graph node so deployed decoys are registered in the knowledge graph, survive restart, and can be linked back to later attacker interactions.
- Updated `crates/swarm-runtime/src/kitten_agent.rs` and `crates/swarm-evolution/src/mutation.rs` so deception interactions act as positive fitness signals, propagate through the existing durable proposal and adversarial-pressure path, and persist into evolution episode artifacts instead of a transient side channel.
- Wired the new Calico lifecycle constructor into `crates/swarm-runtime/src/bin/swarm_detect.rs` and documented the checked-in config surface in `rulesets/default.yaml` plus `docs/CONFIGURATION.md`.

## Notes

- Phase 158 stays bounded to durable Calico lifecycle and downstream integration. It does not start the new fileless detector lane.
- The main debug correction during this phase was restart identity continuity in the lifecycle test: the persisted Calico lifecycle must reload under the same signing key bytes so inventory and interaction signatures still verify after agent restart.
