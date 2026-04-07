---
phase: 101-threat-class-pheromone-policy-storage-and-reload
plan: 01
subsystem: substrate
tags: [substrate, pheromone, policy, runtime]
requirements-completed: []
one-liner: "The substrate now persists durable `ThreatClassConfig` records and the live runtime resolves per-threat-class pheromone policy during deposit and escalation work."
completed: 2026-04-07
---

# Phase 101 Plan 01 Summary

**The substrate now persists durable `ThreatClassConfig` records and the live runtime resolves per-threat-class pheromone policy during deposit and escalation work.**

## Accomplishments

- Added shared `ThreatClassConfig` and resolved `ThreatClassPolicy` types in `swarm-core`, plus a fallback helper on `PheromoneConfig` so every backend and runtime path uses the same override semantics.
- Extended `PheromoneSubstrate` with first-class threat-class policy storage and query methods instead of overloading deposit or escalation records.
- Implemented threat-class policy persistence for in-memory and local-journal substrates, including restart recovery through a dedicated `*.threat-class-configs.jsonl` sidecar journal.
- Implemented threat-class policy persistence for JetStream with dedicated `cfg.*` keys while preserving deposit-only key scans and evaporation GC behavior.
- Updated live deposit construction in the detection pipeline and `StalkerAgent` so half-life overrides are resolved from the substrate at write time.
- Updated `ConcentrationMonitor` and backend concentration/GC logic so evaporation, alert, and incident thresholds can differ by `ThreatClass` without breaking global fallback behavior.
- Added backend and runtime tests covering stored policy queries, local-journal restart recovery, JetStream reconnect coverage, deposit half-life override resolution, and alert-threshold override behavior.

## Files Created Or Modified

- `crates/swarm-core/src/pheromone.rs`
- `crates/swarm-core/src/lib.rs`
- `crates/swarm-pheromone/src/substrate.rs`
- `crates/swarm-pheromone/src/jetstream.rs`
- `crates/swarm-runtime/src/detection/pipeline.rs`
- `crates/swarm-runtime/src/escalation.rs`
- `crates/swarm-runtime/src/stalker_agent.rs`
- `crates/swarm-runtime/tests/escalation_integration.rs`

## Verification

- `cargo fmt --all`
- `cargo test -p swarm-core --lib`
- `cargo test -p swarm-pheromone --lib`
- `cargo test -p swarm-runtime --test escalation_integration`
- `cargo test -p swarm-runtime --lib`

## Notes

- Threat-class policy stays additive: missing overrides fall back to repo-configured `PheromoneConfig`, and `min_sources_for_escalation` remains global in this phase.
- JetStream threat-class-config recovery follows the repo’s existing ignored NATS-backed test pattern and becomes active when a JetStream-enabled NATS server is available.
