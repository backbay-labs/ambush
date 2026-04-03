# Phase 31 Context

## Goal

Surface queued proposals, proof status, advisory ranking, and operator decisions through `swarmctl`.

## Current Repo State

- The repo already exposes stable-ID artifact workflows through `swarmctl`.
- Proposal and proof stores will exist after phases 29 and 30.
- No operator workflow exists yet for listing queue state or recording decisions.

## Constraints

- Queue decisions must not directly mutate production detector configuration.
- Operators need one durable CLI-readable surface for proof status, advisory ranking, and review state.
- Listing and reload should support stable proposal IDs plus simple filters such as strategy ID and review state.

## Implementation Notes

- Add queue list, result, and decision commands to `swarmctl`.
- Persist operator decision history on the proposal artifact itself.
- Document the evolution queue workflow and its advisory boundary.
