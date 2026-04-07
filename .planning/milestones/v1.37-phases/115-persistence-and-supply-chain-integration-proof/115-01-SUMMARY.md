---
phase: 115-persistence-and-supply-chain-integration-proof
plan: 01
subsystem: integration
tags: [integration, runtime, deposits, persistence, supply-chain]
requirements-completed: [PERSIST-05]
one-liner: "Runtime-facing integration proof now drives persistence and supply-chain telemetry through config-selected detectors into non-zero pheromone deposits."
completed: 2026-04-07
---

# Phase 115 Plan 01 Summary

**Runtime-facing integration proof now drives persistence and supply-chain telemetry through config-selected detectors into non-zero pheromone deposits.**

## Accomplishments

- Added a dedicated runtime integration test that constructs synthetic `RegistryPersistence` telemetry and proves `strategy: persistence` produces a `ThreatClass::Persistence` finding plus a non-zero deposit.
- Added a matching runtime integration test that constructs synthetic supply-chain `ProcessStart` telemetry and proves `strategy: supply_chain` produces a `ThreatClass::SupplyChain` finding plus a non-zero deposit.
- Asserted the new findings carry concrete `mitre_technique_id` values in evidence before deposit persistence.
- Extended the existing runtime strategy factory smoke test so all shipped strategies, including `persistence` and `supply_chain`, remain selectable from config.

## Files Created Or Modified

- `crates/swarm-runtime/tests/persistence_supply_chain_integration.rs`
- `crates/swarm-runtime/tests/critical_path_integration.rs`

## Verification

- `cargo test -p swarm-runtime --test persistence_supply_chain_integration --test critical_path_integration`
- `cargo test --workspace`

## Notes

- The integration proof intentionally uses the same repo-owned config loading path as production runtime construction instead of building detectors through test-only helpers.
