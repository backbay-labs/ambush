---
phase: 102-threat-intel-cache-and-operator-query-surface
type: context
created_at: 2026-04-07
depends_on: [101]
---

# Phase 102 Context

## Goal

Persist TTL-bound threat-intel indicators in the substrate and expose authenticated operator endpoints for seeding and querying those indicators without direct file edits.

## Why This Phase Exists

Phase 101 made per-threat-class pheromone policy substrate-owned and operator-managed, but the runtime still has no durable cache for operator-supplied external intelligence. Phase 103 depends on exact lookup primitives for domains, IP addresses, and file hashes, and those lookups need a write surface plus fail-closed expiration behavior before detectors can safely consume them.

## What Is Already True

- `PheromoneSubstrate` now persists multiple non-deposit record families across in-memory, local-journal, and JetStream backends.
- The authenticated operator surface already exposes JSON list and upsert routes for substrate-owned runtime state through bearer-token protection.
- `TelemetryEvent` already exposes DNS query names and network destination IPs directly, and future detector enrichment only needs an exact-value lookup seam.
- Threat-class pheromone policy writes now prove the runtime can observe operator-managed substrate changes without restart.

## Constraints

- Threat-intel entries must stay additive and advisory at this phase; no detector behavior changes land until phase 103.
- Expired entries must fail closed during lookup so stale intelligence cannot silently influence later detector confidence shaping.
- Backend behavior must remain aligned across in-memory, local-journal, and JetStream substrates.
- Operators must manage entries through the authenticated surface instead of editing backend journals or KV buckets directly.

## Decisions

- `ThreatIntelEntry` should live in shared core types so substrate backends, operator routes, and later detector enrichment all reuse one durable record shape.
- Threat-intel storage should be keyed by normalized indicator type plus value so operator writes naturally upsert the current record for one indicator.
- Query behavior should be exact-match by type and value at this phase because phase 103 only needs deterministic indicator hits, not prefix or fuzzy search.
- Lookup methods should enforce TTL on read rather than relying on background cleanup so expired entries fail closed even before any compaction work exists.
- The operator surface should mirror the phase 101 pattern: one authenticated route family for upsert and exact query, returning JSON instead of requiring CLI-only workflows.

## Phase Direction

- Start with shared threat-intel record types plus substrate storage/query primitives.
- Add backend tests for persistence and expiration-aware exact lookup behavior.
- Finish by exposing authenticated operator endpoints and verification proving seeded entries can be queried through the control surface.
