---
phase: 95-stalkeragent-and-weaveragent-pipeline
plan: 02
subsystem: runtime
tags: [agents, correlation, incidents, integration]
requirements-completed: [MULTI-05, MULTI-07]
one-liner: "`WeaverAgent` now consumes investigation pheromones inside the live registry and the runtime has an end-to-end integration proof for detect -> investigate -> correlate incident assembly."
completed: 2026-04-06
---

# Phase 95 Plan 02 Summary

**`WeaverAgent` now consumes investigation pheromones inside the live registry and the runtime has an end-to-end integration proof for detect -> investigate -> correlate incident assembly.**

## Accomplishments

- Added `WeaverAgent` as a concrete `SwarmAgent` that reads Stalker investigation-result pheromones, invokes the existing `CorrelationEngine`, and persists `CorrelatedIncident` records through the configured incident store.
- Registered `WeaverAgent` in serve mode behind `config.correlation.enabled`, which means live runtime startup now wires Whisker, Stalker, and Weaver into one shared dispatcher registry when the async pipeline is enabled.
- Added a bounded integration test that bootstraps the real in-memory runtime stack, runs the dispatcher with all three agents, injects suspicious telemetry, and proves the pipeline from detection to investigation to incident assembly.
- Verified the workspace remains green after the live multi-agent pipeline landed, including binary compilation, strict clippy, and full workspace tests.
- Kept the correlation path aligned with the pre-existing runtime services rather than introducing a second incident-assembly implementation just for agents.

## Files Created Or Modified

- `crates/swarm-runtime/src/weaver_agent.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs`

## Verification

- `cargo test -p swarm-runtime weaver_agent --lib`
- `cargo test -p swarm-runtime --test multi_agent_pipeline_integration`
- `cargo test -p swarm-runtime --bin swarm_detect`
- `cargo build --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace`

## Notes

- The integration harness uses the real memory-backed stores and substrate so the multi-agent proof stays deterministic and fast enough for routine verification.
- `WeaverAgent` currently publishes a correlation summary action after incident assembly but leaves richer downstream orchestration for later milestones.
