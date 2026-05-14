# Phase 253 Verification

status: passed

## Commands

- `CARGO_TARGET_DIR=target-v171-jetstream bash tools/with-nats-jetstream.sh cargo test -p swarm-pheromone --test jetstream --test multi_instance -- --ignored`

## Verified Behaviors

- The ignored JetStream substrate suite now passes end-to-end against a containerized NATS instance.
- Cross-instance deposits, escalation quorum, replay, GC, and reconnect behavior are now proven on the same repo-owned CI harness path.
- Harness failures would emit compose status plus NATS logs instead of failing silently.
