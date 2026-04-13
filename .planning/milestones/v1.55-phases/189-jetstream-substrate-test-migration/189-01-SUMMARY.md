# Phase 189 Plan 01 Summary

## Delivered

- Expanded [jetstream.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-pheromone/tests/jetstream.rs) from a two-test smoke slice into a 13-test harness-backed substrate contract suite covering replay ordering, deposit round-trip integrity, filtered deposit queries, escalation history, threat-class config storage, threat-intel normalization and expiry, unsigned-deposit rejection, concentration decay, and GC semantics.
- Expanded [multi_instance.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-pheromone/tests/multi_instance.rs) so the shared JetStream backend now proves strategy-scoped source diversity and same-scope collapse in addition to the existing cross-instance visibility and minimum-source escalation behaviors.
- Fixed the JetStream backend in [jetstream.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-pheromone/src/jetstream.rs) so `gc_evaporated()` stays semantically aligned with query-time threat-class overrides. When overrides exist, GC now performs a policy-aware scan instead of relying only on default-threshold page scheduling.
- Updated [.github/workflows/ci.yml](/Users/connor/Medica/backbay/standalone/swarm-team-six/.github/workflows/ci.yml) to run the full harness-backed JetStream substrate suite instead of only one smoke test, using the same `tools/with-nats-jetstream.sh` entrypoint local developers use.

## Notes

- The broader real-backend run surfaced two correctness issues that the old smoke slice did not catch: stale fixture assertions that expected label strings instead of signer-derived `AgentId` values, and a real JetStream GC parity gap when threat-class overrides tightened the evaporation threshold. Phase 189 closes both.
- Phase 190 remains cleanly scoped to benchmark instrumentation and baseline capture. Phase 189 ends at semantic parity and CI coverage for the durable substrate contract.
