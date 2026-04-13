# Phase 189: JetStream Substrate Test Migration - Context

**Gathered:** 2026-04-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 189 follows the shipped Phase 188 harness by migrating the real substrate
assertion matrix onto JetStream. The repository now has a deterministic
compose-backed bring-up path and one CI smoke test, but the bulk of the
substrate semantics are still only asserted directly against in-memory and
local-journal backends.

</domain>

<decisions>
## Implementation Decisions

- Reuse the Phase 188 harness as the only supported way to boot JetStream for
  repo-owned tests instead of adding a second infrastructure path.
- Expand JetStream coverage by porting or sharing the existing substrate
  contract assertions in `crates/swarm-pheromone/src/substrate.rs`, rather than
  inventing a disconnected JetStream-only test vocabulary.
- Keep the migration centered on deposit, replay/query, concentration,
  source-diversity, and garbage-collection semantics; benchmarks and load work
  remain deferred to Phases 190 and 191.

</decisions>

<code_context>
## Existing Code Insights

- [with-nats-jetstream.sh](/Users/connor/Medica/backbay/standalone/swarm-team-six/tools/with-nats-jetstream.sh)
  already provides deterministic compose lifecycle, health wait, and exported
  `NATS_URL` for JetStream-backed commands.
- [jetstream.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-pheromone/tests/jetstream.rs)
  and [multi_instance.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-pheromone/tests/multi_instance.rs)
  now pass through that harness, but they still cover only a narrow smoke slice.
- [substrate.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-pheromone/src/substrate.rs)
  already defines the richer backend contract through in-memory and local-journal
  tests such as `recent_deposits_support_replay`, `query_deposits_filters_by_threat_class_and_time`,
  `query_deposits_filters_by_host_id`, `all_backends_reject_unsigned_deposits`,
  `deposit_round_trip_preserves_all_fields`, `concentration_decays_with_half_life`,
  `gc_evaporated_preserves_fresh_deposits`, and the threat-intel GC cases.
- The Phase 188 smoke run exposed stale unsigned-deposit fixtures in the old
  JetStream tests, so Phase 189 can assume the real backend suite must match the
  current signed-deposit contract rather than historical unsigned behavior.

</code_context>

<deferred>
## Deferred Ideas

- Criterion benchmarking and throughput measurement remain Phases 190 and 191.
- Extending the same compose-backed harness into runtime hot-path or benchmark
  workflows can build on this phase’s substrate migration instead of expanding
  scope here.

</deferred>
