# Phase 44 Context

## Goal

Create durable ranked-candidate selection artifacts from shortlist review packets without re-materializing candidate manifests.

## Inputs

- Phase 43 now persists ranking reports plus shortlist review packets under `data/evolution-rankings/`.
- Each review packet already preserves materialization, validation, advisory, and reviewed-queue references.
- Operators needed one stable artifact that turns a chosen packet into a reviewable candidate without mutating queue, canary, or production state.

## Constraints

- Keep selection creation operator-triggered and fail-closed.
- Reuse ranking and validation artifacts instead of regenerating experiment evidence.
- Persist blocked selections for later inspection instead of dropping them on error.
