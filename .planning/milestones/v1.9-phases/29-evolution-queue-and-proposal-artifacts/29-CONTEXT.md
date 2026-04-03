# Phase 29 Context

## Goal

Persist repo-owned evolution proposals with stable IDs, lineage, evidence references, and durable review state.

## Current Repo State

- `v1.8` already ships durable strategy memories and advisory scorecards in `crates/swarm-runtime/src/strategy.rs`.
- Candidate detector evidence already exists as persisted experiment, verification, shadow, canary, promotion, and scorecard artifacts.
- `swarmctl` is the existing operator seam and already manages stable-ID artifact workflows.

## Constraints

- Proposal creation must not mutate production detector configuration or rollout state.
- Queue artifacts must stay file-backed, repo-owned, and deterministic.
- Queue records should reuse existing experiment, verification, and scorecard contracts rather than introducing parallel lineage types.

## Implementation Notes

- Add a new runtime module for evolution proofs and queued proposals.
- Reuse scorecard creation as the advisory evidence source for queued proposals.
- Keep queue state CLI-first and store-backed.
