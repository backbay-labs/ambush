# Phase 139 Context

## Goal

Gate evolved strategies through deterministic safety checks and canary admission so `KittenAgent` proposals can enter the shipped rollout lane instead of stopping at warning-only peer visibility.

## Requirements

- `KITTEN-04`
- `SAFETY-01`
- `SAFETY-02`
- `SAFETY-03`

## Relevant Code

- `crates/swarm-runtime/src/kitten_agent.rs`
- `crates/swarm-runtime/src/dispatcher.rs`
- `crates/swarm-evolution/src/evolution.rs`
- `crates/swarm-evolution/src/selection.rs`
- `crates/swarm-evolution/src/canary.rs`
- `crates/swarm-evolution/src/promotion.rs`

## Starting Point

- Phase 137 delivered bounded `KittenAgent` mutation, validation, and proposal orchestration.
- Phase 138 delivered durable population fitness, replay-backed survivor selection, restart-safe candidate restore, and persisted proposal throttling.
- The repo already has proof, selection, promotion, and canary harnesses in `swarm-evolution`; they are not yet wired into the runtime-owned Kitten proposal path.

## Constraints

- Safety verification must remain deterministic and repo-owned. No opaque external judge may become the admission authority.
- The safety lane must persist both pass artifacts and failure counterexamples so rejected candidates remain auditable.
- Candidate admission must stay asynchronous enough that `KittenAgent` does not block its tick loop on proof or canary launch work.

## Open Integration Seams

- `SwarmAction::ProposeStrategy` is currently visible to peers but not yet converted into a real safety-gated canary handoff.
- Existing selection and canary harnesses already understand proof-backed admission states such as `accepted_for_canary`; Phase 139 should reuse that machinery instead of creating a second queue model.
- `rulesets/safety/` does not yet exist as a repo-owned invariant source for evolved-candidate admission.
