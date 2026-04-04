# Phase 40 Context

## Goal

Reconcile draft-backed queue entries with materialized candidate and refreshed evidence so the existing handoff and canary path can use them.

## Inputs

- Phase 37 already created durable reviewed queue entries from drafts.
- Phase 39 now produces validation bundles with refreshed experiment and proof evidence.
- The queue-to-canary handoff path already expects verified proposal state plus shadow evidence.

## Constraints

- Do not create duplicate queue proposals during reconciliation.
- Preserve original draft-promotion lineage and operator review state.
- Keep handoff launch explicit; reconciliation only prepares the reviewed queue entry.
