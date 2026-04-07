---
phase: 112-telemetry-persistence-payloads-and-detector-contracts
plan: 01
subsystem: telemetry-contracts
tags: [telemetry, config, persistence, supply-chain]
requirements-completed: [PERSIST-03, PERSIST-04]
one-liner: "Shared telemetry, threat-class, and config contracts now model persistence payloads and supply-chain detection metadata without breaking existing schemas."
completed: 2026-04-07
---

# Phase 112 Plan 01 Summary

**Shared telemetry, threat-class, and config contracts now model persistence payloads and supply-chain detection metadata without breaking existing schemas.**

## Accomplishments

- Added `TelemetryPayload::RegistryPersistence` and `TelemetryPayload::FilePersistence` plus shared normalized structs in `swarm-core`.
- Extended `ProcessStartEvent` with optional `executable_path`, `signer`, and `signature_valid` metadata so supply-chain heuristics can evaluate signer trust without changing legacy callers.
- Added `ThreatClass::SupplyChain` to the shared pheromone taxonomy and exported it through the shared crate surface.
- Extended generic JSON bridge payload mappings and detector profile config contracts so repo-owned YAML can describe `persistence` and `supply_chain` families.
- Preserved serde compatibility by making the new process metadata optional and by validating new JSON Pointer fields at config-load time.

## Files Created Or Modified

- `crates/swarm-core/src/telemetry.rs`
- `crates/swarm-core/src/pheromone.rs`
- `crates/swarm-core/src/config.rs`
- `crates/swarm-core/src/lib.rs`

## Verification

- `cargo test --workspace --no-run`
- `cargo test -p swarm-ingest-json --lib`
- `cargo test --workspace`

## Notes

- The shared schema changes are intentionally additive, so older fixtures and runtime callers can keep constructing `ProcessStartEvent` values by leaving signer metadata unset.
- The threat-class addition was wired at the shared domain layer first so runtime labels, escalation logic, and downstream adapters all read the same taxonomy.
