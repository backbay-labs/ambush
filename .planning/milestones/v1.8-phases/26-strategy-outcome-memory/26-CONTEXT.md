# Phase 26 Context

## Goal

Turn completed canary and production-promotion artifacts into durable strategy-memory records with stable history lookup.

## Current Reality

- `v1.7` already persists completed canary and production-promotion artifacts with stable IDs.
- The runtime has no repo-owned strategy-memory record or lookup surface yet.
- Operators cannot inspect per-strategy rollout history without reading raw canary or promotion files.

## Constraints

- Stay pure Rust and reuse the existing file-backed store and `swarmctl` patterns.
- Do not rerun telemetry to build memory records.
- Keep the lane advisory-only and off the hot path.
- Memory IDs must be stable and idempotent when the same artifact is ingested again.

## Likely Implementation Shape

- Add a new runtime module for strategy-memory records, stores, and renderers.
- Build memory records directly from completed canary and production-promotion artifacts.
- Support stable lookup by memory ID and filtered history by strategy ID.
- Persist one strategy-memory artifact per source rollout artifact.

## Success Checks

- A completed canary artifact can be ingested into a durable strategy-memory record.
- A completed production-promotion artifact can be ingested into a durable strategy-memory record.
- Operators can reload one memory by stable ID and list history for one strategy through `swarmctl`.
