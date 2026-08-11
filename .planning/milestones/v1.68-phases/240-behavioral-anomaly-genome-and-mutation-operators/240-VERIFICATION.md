# Phase 240 Verification

status: passed

## Result

Phase 240 verification passed.

## Commands

- `CARGO_TARGET_DIR=target-v168-phase240 cargo check -p swarm-runtime`
- `CARGO_TARGET_DIR=target-v168-phase240 cargo test -p swarm-runtime --lib mutation::tests_core::behavioral_anomaly_target_genome_materializes_typed_candidate`
- `CARGO_TARGET_DIR=target-v168-phase240 cargo test -p swarm-runtime --lib mutation::tests_core::autonomous_mutation_spec_generates_behavioral_anomaly_variants`
- `CARGO_TARGET_DIR=target-v168-phase240 cargo test -p swarm-runtime --lib mutation::tests_core::autonomous_mutation_spec_generates_bounded_variants_from_population_winners`
- `CARGO_TARGET_DIR=target-v168-phase240 cargo test -p swarm-runtime --lib mutation::tests_core::mutation_spec_from_materialized_candidate_persists`

## Verified Behaviors

- Behavioral-anomaly candidates can be persisted as typed mutation target genomes instead of being forced through suspicious-process-tree overrides.
- Autonomous mutation generation now emits replayable behavioral-anomaly seed-control, bounded-perturbation, and crossover variants.
- The existing materialized-candidate persistence lane still round-trips mutation specs after the typed-genome seam landed.
- Legacy suspicious-process-tree mutation flow remains compatible while behavioral-anomaly support is added alongside it.
