---
phase: 93-pheromone-escalation-and-mode-transitions
plan: 01
subsystem: runtime
tags: [pheromones, escalation, mode-transitions, serve]
requirements-completed: [AGENT-03, AGENT-04]
one-liner: "swarm-core now defines escalation events and monotonic `SwarmModeState`, while `swarm-runtime` runs a live concentration monitor that drives shared swarm mode transitions in serve mode."
completed: 2026-04-06
---

# Phase 93 Plan 01 Summary

**swarm-core now defines escalation events and monotonic `SwarmModeState`, while `swarm-runtime` runs a live concentration monitor that drives shared swarm mode transitions in serve mode.**

## Accomplishments

- Added `EscalationEvent` and `SwarmModeState` to `swarm-core`, including monotonic escalation semantics from `Normal` to `Alert` to `Incident`.
- Extended `AgentDispatcher` with shared swarm mode state so agent environments can read the runtime’s current swarm mode instead of remaining pinned to `Normal`.
- Added `crates/swarm-runtime/src/escalation.rs` with a generic `ConcentrationMonitor`, typed escalation outcomes, shared-mode-state syncing, and a live `run_until_shutdown` loop.
- Wired `swarm_detect --serve` to spawn the concentration monitor beside the dispatcher and HTTP server, using a shared `SwarmModeState` for runtime-visible transitions.
- Logged escalation events and mode transitions with structured tracing fields that include threat class, source count, threshold crossing strength, and target mode.

## Files Created Or Modified

- `crates/swarm-core/src/agent.rs`
- `crates/swarm-core/src/types.rs`
- `crates/swarm-core/src/lib.rs`
- `crates/swarm-runtime/src/lib.rs`
- `crates/swarm-runtime/src/dispatcher.rs`
- `crates/swarm-runtime/src/escalation.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`

## Verification

- `cargo test -p swarm-core agent`
- `cargo test -p swarm-runtime escalation`
- `cargo build --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace`

## Notes

- Mode transitions remain monotonic in this phase: de-escalation and hysteresis are still deferred.
- The shared swarm mode is now live in memory for the serve path, which gives later agent phases a real mode signal without forcing durable cross-restart storage yet.
