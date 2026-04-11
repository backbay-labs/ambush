# Phase 140 Context

## Goal

Make the evolution subsystem observable through the same runtime event stream and operator CLI surfaces already used for the rest of the product.

## Requirements

- `EVOLVE-OBS-01`
- `EVOLVE-OBS-02`

## Relevant Code

- `crates/swarm-runtime/src/runtime_events.rs`
- `crates/swarm-runtime/src/dispatcher.rs`
- `crates/swarm-runtime/src/ingest.rs`
- `crates/swarm-runtime/src/kitten_agent.rs`
- `crates/swarm-runtime/src/service.rs`
- `crates/swarm-runtime/src/control.rs`
- `crates/swarm-cli/src/core.inc`
- `crates/swarm-evolution/src/mutation.rs`
- `crates/swarm-evolution/src/selection.rs`
- `crates/swarm-evolution/src/canary.rs`

## Starting Point

- Phase 137 introduced the bounded `KittenAgent` state machine and repo-owned drift activation.
- Phase 138 added durable population state, replay-backed fitness, and restart-safe proposal restore.
- Phase 139 routed Kitten proposals through the real formal-safety, selection, bridge, handoff, and canary path.
- The runtime already has an SSE broadcaster and operator status surface, but neither one currently surfaces evolution-specific metrics or admission outcomes.

## Constraints

- Observability must derive from the persisted evolution artifacts and the shipped runtime broadcaster, not a second cache or sidecar state model.
- `swarmctl evolution status` should read the same durable state that drives admission, so operator output and SSE metrics cannot drift apart semantically.
- Adding evolution telemetry must not block the Kitten tick loop or reintroduce heavy synchronous work into dispatcher routing.

## Open Integration Seams

- `RuntimeEvent` has no evolution-specific event kind yet, so SSE can show generic `agent_action` emissions but not stable evolution metrics.
- `OperatorStatusReport` and `swarmctl status` currently omit the evolution lane even though the population, selection, and canary artifacts now exist.
- The CLI has many flat evolution workflow commands, but no concise runtime-facing `swarmctl evolution status` command that summarizes current generation, fitness, verification, and admission state.
