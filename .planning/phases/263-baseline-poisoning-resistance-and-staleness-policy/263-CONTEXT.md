# Phase 263 Context

## Goal

Reduce trust in aged learned-state snapshots instead of silently treating stale baselines as fresh truth.

## Repo State

- The repo already signs learned-state artifacts and rejects tampered or replayed older snapshots.
- Earlier phases in v1.73 are intended to introduce recruitment and benchmark evidence over baseline shift pressure.
- No shipped policy currently reduces confidence because a baseline snapshot has simply gone stale.

## Phase Focus

- Add one configurable staleness threshold for learned baseline trust.
- Apply graduated confidence reduction instead of a binary stale/fresh toggle.
- Reuse the signed-state persistence lane so stale-state handling stays aligned with the earlier learned-state integrity work.

## Verification Target

- Repo-owned tests proving stale baselines reduce detector confidence on the live decision path.
- Configuration and persistence proof that the staleness policy survives restart cleanly.
