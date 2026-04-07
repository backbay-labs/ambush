---
phase: 112-telemetry-persistence-payloads-and-detector-contracts
type: context
created_at: 2026-04-07
depends_on: [111]
---

# Phase 112 Context

## Goal

Extend the shared telemetry, threat taxonomy, and detector profile contracts so persistence and supply-chain detectors can be added without breaking ingest, replay, canary, promotion, or operator control flows.

## Why This Phase Exists

The runtime already recognizes process, network, DNS, registry-access, and authentication signals, but persistence and supply-chain coverage need richer telemetry than generic registry access alone. The new milestone also introduces a new threat family, so the shared taxonomy and every detector-construction surface need one coordinated contract update before any strategy code lands.

## What Is Already True

- `TelemetryEvent` and `TelemetryPayload` live in `swarm-core` and are shared by bridges, ingest, replay, operator, and evidence code.
- `DetectorProfilesConfig` already supports strategy-specific profile overrides that inherit top-level confidence thresholds.
- Control, replay, canary, and promotion each have explicit supported-detector routing that must stay in sync with the live runtime.
- Existing detectors already attach structured evidence and stable `strategy_id` values that later surfaces reuse.

## Constraints

- Preserve serde compatibility and deny-unknown-field behavior for existing payloads.
- Keep the shared detector plumbing explicit; silent fallback to unsupported strategies would create runtime ambiguity.
- Add `SupplyChain` everywhere threat-class labels surface so metrics, status, and replay reports remain coherent.
- Land the shared contract first so the detector phases can stay focused on heuristics and proof.

## Decisions

- Introduce `RegistryPersistence` and `FilePersistence` as distinct normalized payloads instead of overloading `RegistryAccess`.
- Add `ThreatClass::SupplyChain` as a first-class enum variant instead of using `Custom`.
- Add dedicated `PersistenceProfile` and `SupplyChainProfile` entries to `DetectorProfilesConfig`.
- Update replay, canary, and promotion support in the same phase so later detector work has one consistent strategy surface.

## Phase Direction

- Start in `swarm-core` and `swarm-whisker` with the shared payload/profile contracts.
- Then update runtime detector selection, candidate manifests, and any label helpers that match exhaustively on payloads or threat classes.
- Keep this phase focused on shared contracts and plumbing; detection heuristics land in the next two phases.
