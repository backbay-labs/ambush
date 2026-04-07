---
phase: 102-threat-intel-cache-and-operator-query-surface
plan: 01
subsystem: substrate
tags: [substrate, threat-intel, ttl, jetstream]
requirements-completed: []
one-liner: "The substrate now persists normalized `ThreatIntelEntry` records with TTL-aware exact lookup across in-memory, local-journal, and JetStream backends."
completed: 2026-04-07
---

# Phase 102 Plan 01 Summary

**The substrate now persists normalized `ThreatIntelEntry` records with TTL-aware exact lookup across in-memory, local-journal, and JetStream backends.**

## Accomplishments

- Added shared `ThreatIntelIndicatorType` and `ThreatIntelEntry` records in `swarm-core` so backends and runtime code use one durable threat-intel contract.
- Extended `PheromoneSubstrate` with explicit threat-intel store and exact-query methods instead of overloading deposits or escalation records.
- Implemented normalized `(indicator_type, value)` storage plus TTL-aware fail-closed lookup in the in-memory backend.
- Added local-journal threat-intel persistence through a dedicated `*.threat-intel.jsonl` sidecar with restart recovery and health-surface coverage.
- Added JetStream threat-intel persistence under `intel.*` keys and preserved deposit-only scans by excluding threat-intel keys from deposit reads, counts, and legacy GC paths.
- Added backend tests covering normalization, expiration behavior, restart recovery, and JetStream reconnect parity.

## Files Created Or Modified

- `crates/swarm-core/src/pheromone.rs`
- `crates/swarm-core/src/lib.rs`
- `crates/swarm-pheromone/src/substrate.rs`
- `crates/swarm-pheromone/src/jetstream.rs`

## Verification

- `cargo fmt --all`
- `cargo test -p swarm-core --lib`
- `cargo test -p swarm-pheromone --lib`
- `cargo test -p swarm-runtime --lib`
- `cargo test -p swarm-runtime --test escalation_integration`

## Notes

- Threat-intel lookup stays exact and TTL-aware at the substrate boundary; later runtime enrichment can derive candidate indicators, but backend storage remains precise and deterministic.
- Domain, IP, and file-hash normalization is centralized at the storage layer so operator APIs and future detection paths do not need backend-specific casing logic.
