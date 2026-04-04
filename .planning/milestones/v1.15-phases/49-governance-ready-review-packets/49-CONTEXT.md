# Phase 49 Context

## Goal

Generate governance-ready review packets from curated portfolio entries using preserved evidence references instead of re-encoding artifacts.

## Inputs

- Phase 48 now persists curated portfolio entries with explicit operator review state and decision history.
- Portfolio entries already preserve ranking, selection, experiment, validation, proof, advisory, shadow, and queue-lineage references.
- The roadmap still defers real distributed governance, but the runtime needed one durable packet format that later governance work can consume without restating evidence.

## Constraints

- Keep governance prep artifact-first and fail-closed.
- Reuse preserved portfolio evidence instead of regenerating verification, proof, or shadow artifacts.
- Persist blocked governance-prep packets for later inspection when entry state or experiment lineage drifts.
