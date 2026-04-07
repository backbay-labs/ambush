---
phase: 100-escalation-records-and-mode-aware-environment
plan: 01
subsystem: substrate
tags: [substrate, escalation, durability, jetstream]
requirements-completed: []
one-liner: "The substrate contract now persists durable `EscalationRecord` history across in-memory, local-journal, and JetStream backends."
completed: 2026-04-07
---

# Phase 100 Plan 01 Summary

**The substrate contract now persists durable `EscalationRecord` history across in-memory, local-journal, and JetStream backends.**

## Accomplishments

- Added `EscalationRecord` as a shared core type so runtime and substrate code serialize one consistent escalation-history shape.
- Extended `PheromoneSubstrate` with `record_escalation` and `query_escalations` instead of overloading the existing pheromone-deposit path.
- Implemented escalation-history persistence for the in-memory substrate with chronological query support.
- Implemented escalation-history persistence for the local-journal substrate using a sidecar `*.escalations.jsonl` journal so deposit storage and evaporation GC stay stable.
- Implemented escalation-history persistence for the JetStream substrate using dedicated `esc.*` keys while preserving deposit-only concentration, listing, and GC behavior.
- Added substrate tests covering chronological escalation queries, local-journal restart recovery, and a JetStream reconnect test path for escalation records.

## Files Created Or Modified

- `crates/swarm-core/src/pheromone.rs`
- `crates/swarm-core/src/lib.rs`
- `crates/swarm-pheromone/src/substrate.rs`
- `crates/swarm-pheromone/src/jetstream.rs`

## Verification

- `cargo fmt --all`
- `cargo test -p swarm-core --lib`
- `cargo test -p swarm-pheromone --lib`

## Notes

- JetStream escalation recovery coverage follows the repo’s existing NATS-backed test pattern: the test is compiled in `cargo test -p swarm-pheromone --lib` and runs when a JetStream-enabled NATS server is available.
- Local-journal escalation history uses a dedicated sidecar file so evaporation GC can continue rewriting deposit journals without dropping escalation records.
