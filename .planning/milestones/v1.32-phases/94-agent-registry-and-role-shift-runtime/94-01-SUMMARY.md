---
phase: 94-agent-registry-and-role-shift-runtime
plan: 01
subsystem: runtime
tags: [agents, registry, role-shifts, dispatcher]
requirements-completed: [MULTI-01, MULTI-02]
one-liner: "swarm-runtime now owns a keyed `AgentRegistry` plus a dispatcher event bus so agents can emit `RoleShift` actions and update mutable roles without hard-coded roster state."
completed: 2026-04-06
---

# Phase 94 Plan 01 Summary

**swarm-runtime now owns a keyed `AgentRegistry` plus a dispatcher event bus so agents can emit `RoleShift` actions and update mutable roles without hard-coded roster state.**

## Accomplishments

- Replaced the dispatcher's positional `Vec<Box<dyn SwarmAgent>>` with a keyed `AgentRegistry` that supports duplicate rejection, runtime deregistration, and stable keyed health summaries.
- Added `AgentFinding` and `SwarmEvent` to `swarm-core`, and extended `SwarmAgent` with `observe_event()` so runtime broadcasts are part of the core agent contract.
- Made `AgentId` orderable so the runtime can maintain a deterministic keyed registry without introducing a new dependency for ordered maps.
- Updated `WhiskerAgent` to hold mutable role state and react to broadcast `SwarmEvent::RoleShift` events targeted at its own agent id.
- Added dispatcher tests covering registry deregistration, broadcast role-shift propagation, and role mutation on the emitting agent plus observing peers.

## Files Created Or Modified

- `crates/swarm-core/src/agent.rs`
- `crates/swarm-core/src/lib.rs`
- `crates/swarm-core/src/types.rs`
- `crates/swarm-runtime/src/dispatcher.rs`
- `crates/swarm-runtime/src/whisker_agent.rs`

## Verification

- `cargo test -p swarm-core agent --lib`
- `cargo test -p swarm-runtime dispatcher --lib`
- `cargo test -p swarm-runtime whisker_agent --lib`
- `cargo build --workspace`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace`

## Notes

- The registry is now live and reload-ready in-process, but concrete Stalker/Weaver factories still arrive in Phase 95.
- Role-shift propagation is intentionally narrow for now: the dispatcher broadcasts events to all agents, and concrete agents decide whether the event changes their own internal role.
