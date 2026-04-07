---
phase: 100-escalation-records-and-mode-aware-environment
type: context
created_at: 2026-04-07
depends_on: [99]
---

# Phase 100 Context

## Goal

Persist swarm-mode escalation transitions as substrate-owned records and expose explicit mode-aware accessors to agents so the next substrate milestone can build on durable escalation history instead of process-local state only.

## Why This Phase Exists

`v1.33` proved the runtime can ingest concurrent telemetry bridges into one live detection path, but swarm-mode escalation still lives only inside `ConcentrationMonitor` and the shared in-process `SwarmModeState`. The next milestone needs durable escalation history for operators and later threat-intel flows, plus a clearer runtime contract for agents that want to react to `Alert` or `Incident` mode without reaching into raw environment fields.

## What Is Already True

- `ConcentrationMonitor` already evaluates all standard `ThreatClass` values and emits `EscalationEvent::Alert` or `EscalationEvent::Incident` when pheromone concentration crosses thresholds.
- `SwarmModeState` already tracks `current`, `last_transition_at`, and `triggering_threat_class`, and dispatcher state can share that snapshot across runtime agents through `ArcSwap`.
- `PheromoneSubstrate` backends already persist and query deposits across in-memory, local-journal, and JetStream implementations, so there is an existing storage seam for adjacent substrate-owned records.
- `SwarmEnvironment` already carries the current mode and timestamp, but agents still access those as raw fields rather than through explicit helper methods.

## Constraints

- Preserve the existing deposit query and concentration behavior; escalation history is additive and must not break hot-path pheromone math.
- Keep backend behavior aligned across in-memory, local-journal, and JetStream implementations.
- Record only true upward transitions, not repeated threshold observations for the same already-active mode.
- Avoid forcing large agent rewrites; mode-aware helpers should improve the contract without destabilizing current agents.

## Decisions

- `EscalationRecord` should live in shared core types so both substrate backends and runtime tests can serialize and inspect the same durable record shape.
- The substrate contract will need a first-class write path for escalation records in addition to the new `query_escalations` read path; forcing escalation history through `deposit` would blur distinct semantics.
- `SwarmEnvironment` should keep its existing fields for compatibility while adding explicit `current_mode()` and `mode_transition_at()` helpers.
- `ConcentrationMonitor` should persist escalation records only when `SwarmModeState::transition_to` succeeds so the durable history matches the monotonic runtime mode model.

## Phase Direction

- Split the work into substrate persistence first, then runtime/environment wiring and verification.
- Reuse the existing local-journal and JetStream storage conventions rather than creating a second standalone persistence subsystem.
- Prefer integration coverage that proves both: persisted escalation history can be queried, and agents can consume the mode-aware environment helpers without bespoke test-only scaffolding.
