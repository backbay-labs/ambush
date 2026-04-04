# Phase 41 Context

## Goal

Derive durable mutation-spec artifacts from reviewed drafts or materialized candidates without hand-editing multiple manifests.

## Inputs

- `v1.12` already shipped reviewed drafts, draft promotion, single-candidate materialization, and validation refresh.
- Operators needed a durable artifact to hold several explicit candidate branches before batch evaluation work could start.
- The current runtime only supports suspicious process-tree detector candidates, so guided mutation should stay scoped to that profile shape.

## Constraints

- Keep mutation design operator-authored and offline.
- Preserve source lineage, pressure references, and any existing reviewed queue reference.
- Avoid inventing a second drafting system; mutation specs should sit above the current draft/materialization lane.
