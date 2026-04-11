# Phase 144 Verification

status: passed

## Result

Phase 144 verification passed.

## Commands

- `cargo fmt --all`
- `cargo test -p swarm-evolution mutation::tests::adversarial_pressure_persists_durable_episode_report -- --exact`
- `cargo test -p swarm-runtime kitten_agent::tests::kitten_freezes_adversarial_corpus_per_generation -- --exact`
- `cargo test -p swarm-runtime kitten_agent::tests::kitten_memory_answer_enriches_pending_proposal_fitness -- --exact`
- `cargo test -p swarm-runtime kitten_agent::tests::kitten_memory_query_falls_back_when_sphinx_is_unavailable -- --exact`
- `cargo test -p swarm-runtime kitten_agent::tests::kitten_restores_persisted_population_candidate_before_drift -- --exact`
- `cargo test -p swarm-runtime evolution_status::tests::evolution_status_harness_summarizes_durable_artifacts -- --exact`
- `cargo check -p swarm-runtime -p swarm-evolution --tests -j 1 --message-format short`

## Verified Behaviors

- Kitten now freezes adversarial corpus identity per generation, changes that identity only when generation changes, and carries the frozen corpus metadata into proposal artifacts.
- Replay fitness, Sphinx memory enrichment, and red-side adversarial pressure now resolve into one final proposal fitness without bypassing the existing proposal, safety, or canary lane.
- Durable `EvolutionEpisode` artifacts persist generation, corpus sequence and version, blue genome hash, per-threat-class coverage, and red-blue fitness vectors so the generation outcome can be explained after restart.
- `swarmctl evolution status` and the runtime `evolution_status` event lane now expose current generation, latest episode, corpus version, and best genome state through the existing status-report path.
