---
phase: 112-telemetry-persistence-payloads-and-detector-contracts
plan: 02
subsystem: runtime-surfaces
tags: [runtime, replay, canary, promotion, ingest]
requirements-completed: [PERSIST-03, PERSIST-04]
one-liner: "The runtime, replay, canary, promotion, and ingest surfaces now construct and carry `persistence` and `supply_chain` detectors as first-class strategies."
completed: 2026-04-07
---

# Phase 112 Plan 02 Summary

**The runtime, replay, canary, promotion, and ingest surfaces now construct and carry `persistence` and `supply_chain` detectors as first-class strategies.**

## Accomplishments

- Added repo-owned profile loaders and validation for `PersistenceProfile` and `SupplyChainProfile` inside the runtime config layer.
- Extended `supported_detector`, replay manifests, canary rollout wiring, and promotion candidate manifests to construct the new strategy families everywhere the runtime already handles detectors.
- Updated runtime label helpers, escalation summaries, service ancestry helpers, and pheromone serialization so `ThreatClass::SupplyChain` is surfaced consistently.
- Taught the generic JSON bridge and Tetragon mapper to populate the new persistence payloads and optional process signer metadata.
- Hardened ancillary runtime consumers such as drafting, mutation, investigation, and threat-intel candidate extraction to explicitly account for the new telemetry variants.

## Files Created Or Modified

- `crates/swarm-runtime/src/config.rs`
- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-runtime/src/canary.rs`
- `crates/swarm-runtime/src/promotion.rs`
- `crates/swarm-runtime/src/replay/core.inc`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/escalation.rs`
- `crates/swarm-ingest-json/src/generic_json.rs`
- `crates/swarm-ingest-tetragon/src/mapper.rs`

## Verification

- `cargo test --workspace --no-run`
- `cargo test -p swarm-runtime --lib`
- `cargo test --workspace`

## Notes

- Replay, canary, and promotion now stay aligned with live detector selection instead of silently lagging behind the supported strategy set.
- Tetragon still leaves signer metadata unset today; the contract is present now so future bridge work can populate it without another runtime-wide schema change.
