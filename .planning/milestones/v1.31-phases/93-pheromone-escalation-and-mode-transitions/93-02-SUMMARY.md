---
phase: 93-pheromone-escalation-and-mode-transitions
plan: 02
subsystem: runtime
tags: [pheromones, escalation, integration-tests]
requirements-completed: [AGENT-05]
one-liner: "runtime escalation coverage now proves the dual-source gate, alert and incident threshold crossings, and sequential Normal→Alert→Incident progression on the real in-memory substrate."
completed: 2026-04-06
---

# Phase 93 Plan 02 Summary

**runtime escalation coverage now proves the dual-source gate, alert and incident threshold crossings, and sequential Normal→Alert→Incident progression on the real in-memory substrate.**

## Accomplishments

- Added `crates/swarm-runtime/tests/escalation_integration.rs` with five end-to-end escalation scenarios over `InMemoryPheromoneSubstrate`.
- Proved that below-threshold deposits stay silent and that a single noisy source cannot trigger escalation even when total strength crosses the alert threshold.
- Proved that two distinct sources crossing the alert threshold emit `Alert` escalation and that larger multi-source concentrations emit `Incident`.
- Proved sequential mode progression from `Normal` to `Alert` to `Incident` using the real monitor and substrate instead of mocks.
- Kept the integration tests aligned with the repo-owned pheromone defaults (`alert_threshold = 2.0`, `incident_threshold = 5.0`, `min_sources_for_escalation = 2`).

## Files Created Or Modified

- `crates/swarm-runtime/tests/escalation_integration.rs`

## Verification

- `cargo test -p swarm-runtime --test escalation_integration`
- `cargo test --workspace`

## Notes

- The integration coverage intentionally uses the in-memory substrate for determinism and speed; JetStream-specific multi-instance tests remain in the pheromone crate and continue to require an external NATS server.
