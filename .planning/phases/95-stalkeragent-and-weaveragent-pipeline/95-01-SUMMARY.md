---
phase: 95-stalkeragent-and-weaveragent-pipeline
plan: 01
subsystem: runtime
tags: [agents, investigation, replay, serve-mode]
requirements-completed: [MULTI-04]
one-liner: "`StalkerAgent` now turns live Whisker pheromones into persisted investigation work and republishes completed investigation output back into the substrate inside the shared dispatcher runtime."
completed: 2026-04-06
---

# Phase 95 Plan 01 Summary

**`StalkerAgent` now turns live Whisker pheromones into persisted investigation work and republishes completed investigation output back into the substrate inside the shared dispatcher runtime.**

## Accomplishments

- Added `StalkerAgent` as a concrete `SwarmAgent` implementation that watches Whisker-owned pheromones, loads replay bundles by hunt id, submits them into the existing `InvestigationCoordinator`, and emits `ClaimInvestigation` plus `PublishFindings` actions at the right points in the lifecycle.
- Reused the shipped replay and investigation stack instead of adding a second async review path, keeping live multi-agent execution aligned with the existing persisted bundle model.
- Published completed investigation output back into the shared pheromone substrate as second-stage investigation-result deposits that downstream agents can consume.
- Extended `IngestState` with accessors for the live replay store, investigation coordinator, and investigation store so serve mode can construct runtime agents from the same shared stack already exposed on the HTTP surface.
- Updated `swarm_detect --serve` so `StalkerAgent` is registered automatically whenever investigation is enabled, alongside the already-live `WhiskerAgent`.

## Files Created Or Modified

- `crates/swarm-runtime/src/stalker_agent.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-runtime/src/lib.rs`

## Verification

- `cargo test -p swarm-runtime stalker_agent --lib`
- `cargo test -p swarm-runtime ingest --lib`
- `cargo test -p swarm-runtime --bin swarm_detect`
- `cargo build --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace`

## Notes

- Detection pheromones are intentionally keyed through `indicator.event_id`, which already matches the hot-path hunt id generated from the primary finding.
- `StalkerAgent` avoids duplicate submission and duplicate publication with local queued/published hunt tracking, while the durable stores remain the source of truth for completed investigation state.
