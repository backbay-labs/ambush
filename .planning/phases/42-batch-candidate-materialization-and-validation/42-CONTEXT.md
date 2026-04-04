# Phase 42 Context

## Goal

Materialize and refresh multiple candidate variants from one mutation spec while preserving per-candidate evidence chains.

## Inputs

- Phase 41 now provides durable mutation specs with explicit variants.
- The runtime already had single-candidate materialization and validation refresh in the drafting lane.
- Operators needed a batch artifact that preserved per-candidate IDs instead of collapsing all variants into one result.

## Constraints

- Reuse the existing materialization and validation logic instead of forking a new evaluation path.
- Preserve per-candidate materialization and validation IDs under one batch artifact.
- Fail closed on blocked candidates while keeping the blocked evidence available.
