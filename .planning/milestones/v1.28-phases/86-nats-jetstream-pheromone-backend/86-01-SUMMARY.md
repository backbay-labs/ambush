---
phase: 86-nats-jetstream-pheromone-backend
plan: 01
subsystem: pheromone
tags: [pheromone, nats, jetstream, durability, config]
requirements-completed: [SUB-01]
one-liner: "swarm-pheromone now ships a lazy-connect JetStream KV backend with config-selected durability and restart-safe persistence coverage."
completed: 2026-04-05
---

# Phase 86 Plan 01 Summary

**swarm-pheromone now ships a lazy-connect JetStream KV backend with config-selected durability and restart-safe persistence coverage.**

## Accomplishments

- Added `async-nats` as a workspace dependency and extended `PheromoneBackendConfig` with a durable `jet_stream` variant plus validation.
- Implemented `JetStreamPheromoneSubstrate` on top of JetStream KV with lazy connection setup so the existing runtime/bootstrap path stayed synchronous.
- Reused the existing concentration and deposit-filter helpers so in-memory, local-journal, and JetStream backends share the same decay and query semantics.
- Wired `ConfiguredPheromoneSubstrate` to select the JetStream backend from repo-owned config without refactoring the runtime service constructors to async.
- Added ignored NATS-backed restart and GC integration tests plus package-level coverage for backend selection and config behavior.

## Files Created Or Modified

- `Cargo.toml`
- `crates/swarm-core/src/config.rs`
- `crates/swarm-pheromone/Cargo.toml`
- `crates/swarm-pheromone/src/lib.rs`
- `crates/swarm-pheromone/src/substrate.rs`
- `crates/swarm-pheromone/src/jetstream.rs`
- `crates/swarm-pheromone/tests/jetstream.rs`
- `rulesets/default.yaml`

## Verification

- `cargo test -p swarm-core`
- `cargo test -p swarm-pheromone`
- `NATS_URL=nats://127.0.0.1:4223 cargo test -p swarm-pheromone --test jetstream -- --ignored --nocapture`

## Notes

- JetStream deposit keys preserve the threat-class/timestamp/agent hash prefix from the phase design and add a unique suffix so identical deposits do not overwrite each other.
