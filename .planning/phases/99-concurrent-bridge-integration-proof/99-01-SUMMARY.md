---
phase: 99-concurrent-bridge-integration-proof
plan: 01
subsystem: integration
tags: [bridges, runtime, integration, pheromones]
requirements-completed: []
one-liner: "The runtime now has a deterministic concurrent bridge proof that runs CloudTrail and generic JSON bridge workers together against the shared Whisker detection lane."
completed: 2026-04-07
---

# Phase 99 Plan 01 Summary

**The runtime now has a deterministic concurrent bridge proof that runs CloudTrail and generic JSON bridge workers together against the shared Whisker detection lane.**

## Accomplishments

- Added `crates/swarm-runtime/tests/bridge_registry_integration.rs` as a bounded end-to-end proof that uses the shipped `BridgeRuntimeRegistry` rather than a custom fake harness.
- Started one `CloudTrailBridge` instance and one `GenericJsonBridge` instance concurrently against the same runtime input channel with file-backed fixtures written at test time.
- Reused the existing `WhiskerAgent` detection path so the proof exercises real runtime wiring from bridge poll -> shared `telemetry_tx` -> detector evaluation -> pheromone deposit.
- Chose `credential_access` as the shared detection strategy because both bridge types can emit normalized `AuthenticationEvent` payloads with deterministic fixture inputs.
- Asserted on persisted `PheromoneDeposit` output and source tags instead of only raw event delivery, which proves the concurrent bridge path reaches the substrate.

## Files Created Or Modified

- `crates/swarm-runtime/tests/bridge_registry_integration.rs`

## Verification

- `cargo fmt --all`
- `cargo test -p swarm-runtime --test bridge_registry_integration`

## Notes

- The proof deliberately avoids external services and live Tetragon dependencies so it remains bounded for routine CI execution.
- The test uses distinct source tags from CloudTrail and generic JSON fixtures, which makes it obvious that both bridges contributed deposits to the shared substrate.
