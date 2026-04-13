# Phase 189 Verification

status: passed

## Result

Phase 189 verification passed.

## Commands

- `cargo fmt --all`
- `bash tools/with-nats-jetstream.sh cargo test -p swarm-pheromone --test jetstream threat_class_override_affects_concentration_and_gc -- --ignored --exact`
- `bash tools/with-nats-jetstream.sh cargo test -p swarm-pheromone --test multi_instance escalation_requires_min_sources -- --ignored --exact`
- `bash tools/with-nats-jetstream.sh cargo test -p swarm-pheromone --test jetstream --test multi_instance -- --ignored`

## Verified Behaviors

- The repo-owned JetStream harness now exercises the substantive pheromone substrate contract, not only a reconnect smoke path.
- JetStream-backed tests cover the same deposit, query, escalation, threat-class config, threat-intel, and garbage-collection semantics already asserted against the in-memory backend.
- The durable backend now preserves parity between threat-class override reads and evaporation GC, so query-time and GC-time behavior no longer disagree when overrides tighten evaporation thresholds.
- CI uses the same harness-backed command path for the full JetStream substrate suite that local developers can run directly.
