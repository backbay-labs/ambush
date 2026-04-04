# Phase 38 Context

## Goal

Materialize durable candidate experiment artifacts from one stable draft without hand-editing repo manifests.

## Inputs

- `v1.11` already shipped pressure reports, draft artifacts, and reviewed queue promotion.
- Draft-backed queue entries still had placeholder experiment references and no concrete proof-capable candidate manifest.
- The repo already had stable experiment manifest types and replay evaluation logic in `crates/swarm-runtime/src/replay.rs`.

## Constraints

- Keep the flow operator-triggered and off the hot path.
- Reuse the existing repo-owned experiment manifest type instead of inventing a second candidate schema.
- Preserve lineage and source references from the draft and originating pressure report.
