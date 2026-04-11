# Phase 173 Verification

status: passed

## Result

Phase 173 verification passed.

## Commands

- `cargo test -p swarm-core config::tests::evolution_requires_non_empty_assurance_harvest_results_dir_when_enabled -- --exact`
- `cargo test -p swarm-evolution harvests_replayable_coverage_gap_cases -- --nocapture`
- `cargo test -p swarm-evolution mutation_ranking_orders_ready_candidate_first -- --nocapture`
- `cargo test -p swarm-runtime --lib evolution_status::tests::evolution_status_harness_summarizes_durable_artifacts -- --exact`
- `cargo test -p swarm-evolution --features z3 harvests_solver_counterexample_cases -- --nocapture`
- `cargo check -p swarm-core -p swarm-evolution -p swarm-runtime --tests -j 1 --message-format short`
- `cargo fmt --all`

## Verified Behaviors

- Assurance harvest configuration now validates bounded storage inputs before an enabled evolution lane can persist replayable cases.
- Blocked queue proposals now persist durable assurance-case reports and replayable scenario manifests for both coverage-floor failures and solver counterexamples, with lineage back to proposal, proof, verification, and source scenario artifacts.
- Mutation ranking now consumes harvested assurance evidence directly, attaches case counts and ids to ranked candidates and review packets, and penalizes candidates that still carry unresolved harvested cases.
- The `z3`-gated solver path now proves harvested counterexample cases come from real solver-backed proof artifacts instead of from the lightweight verification-attestation helper.
