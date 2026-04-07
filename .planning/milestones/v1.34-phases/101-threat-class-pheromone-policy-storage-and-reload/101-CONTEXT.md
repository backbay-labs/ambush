---
phase: 101-threat-class-pheromone-policy-storage-and-reload
type: context
created_at: 2026-04-07
depends_on: [100]
---

# Phase 101 Context

## Goal

Persist per-threat-class pheromone policy as substrate-owned records and make the live runtime honor those overrides for deposit and escalation behavior without requiring a process restart.

## Why This Phase Exists

Phase 100 made escalation history durable, but the pheromone runtime still treats `PheromoneConfig` as one global static policy. That blocks later milestones that need tighter control over specific threat classes and makes operator-managed threat-intel work less useful, because every class still shares the same half-life and escalation thresholds. This phase moves threat-class policy into the substrate so operators can tune behavior through durable runtime state instead of editing base YAML for every adjustment.

## What Is Already True

- `PheromoneSubstrate` already owns durable deposit and escalation storage across in-memory, local-journal, and JetStream backends.
- The live detection lane converts `DetectionFinding` values into `PheromoneDeposit` records through `detect_and_deposit`, and `StalkerAgent` also writes follow-on pheromones directly.
- `ConcentrationMonitor` already queries the substrate for concentration and evaluates alert and incident thresholds on every poll.
- The authenticated operator HTTP surface already exposes repo-owned read and write actions against runtime-owned stores through bearer-token-protected endpoints.

## Constraints

- Keep the repo-configured `PheromoneConfig` as the fallback default; threat-class records are overrides, not a replacement config source.
- Preserve backend parity across in-memory, local-journal, and JetStream substrate implementations.
- Do not require `swarm-detect` restart to pick up policy changes; the live runtime must resolve the latest stored override during normal operation.
- Keep the hot-path contract stable enough that existing detection, escalation, and operator tests can be extended instead of rewritten.

## Decisions

- `ThreatClassConfig` should be a shared core type so substrate backends, runtime code, and operator endpoints serialize the same durable record shape.
- The substrate should expose explicit threat-class policy write and query methods instead of overloading deposit or escalation journals with mixed record types.
- Runtime deposit paths should resolve half-life overrides through the substrate at the moment a deposit is materialized, which keeps operator changes live without adding process-local cache invalidation first.
- Runtime concentration logic should keep `min_sources_for_escalation` global for now, while per-threat-class policy overrides cover half-life, evaporation threshold, alert threshold, and incident threshold.
- The operator surface should expose authenticated JSON endpoints for listing and upserting threat-class policy records so operators never edit backend storage files directly.

## Phase Direction

- Start with the shared threat-class policy model and backend persistence/query behavior.
- Wire the live runtime to consult substrate-backed overrides during both deposit creation and escalation evaluation.
- Finish by surfacing authenticated operator endpoints and verification proving that operator-written policy takes effect in the live runtime path without restart.
