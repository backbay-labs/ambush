# Phase 48 Context

## Goal

Add explicit operator curation decisions over portfolio entries while preserving immutable upstream evidence.

## Inputs

- Phase 47 now persists reloadable portfolio artifacts with stable entry IDs.
- Portfolio entries already carry ranking, selection, cohort, validation, and rollout-lineage references.
- Operators needed a durable curation lane above portfolio entries that could include, defer, or drop candidates without rewriting ranked selection evidence.

## Constraints

- Keep curation advisory and non-mutating for queue, canary, and production state.
- Preserve immutable ranked selection evidence and append decision history onto the portfolio artifact instead.
- Fail closed when blocked entries are incorrectly pushed into the included state.
