# Phase 43 Context

## Goal

Rank or shortlist validated candidates using deterministic evidence and emit durable review packets for later operator decisions.

## Inputs

- Phase 42 now persists mutation validation batches with per-candidate readiness, proof status, and advisory evidence.
- The runtime already preserves reviewed queue state for the parent draft when that state exists.
- Operators needed a stable artifact that summarizes which validated candidates are most worth carrying forward.

## Constraints

- Keep ranking advisory only; do not mutate queue state or rollout state automatically.
- Reuse persisted validation evidence and existing queue records instead of recomputing fresh artifacts.
- Emit durable review packets that preserve materialization, validation, and reviewed-queue references.
