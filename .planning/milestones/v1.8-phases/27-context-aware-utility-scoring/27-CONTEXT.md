# Phase 27 Context

## Goal

Compute deterministic advisory utility scores from strategy memories with replay-fitness fallback and explicit score explanations.

## Current Reality

- Phase 26 establishes durable strategy-memory records and history lookup.
- The repo still relies on offline replay fitness alone when comparing baseline and candidate detectors.
- Operators have no persisted explanation for how live rollout history should influence detector preference.

## Constraints

- Keep scoring deterministic and repo-owned.
- Use live rollout memories only as advisory input; do not mutate config or promote strategies.
- Fall back cleanly to replay fitness when live memory is sparse.
- Preserve enough explanation that operators can inspect the score inputs instead of trusting one opaque number.

## Likely Implementation Shape

- Add a strategy-scoring model that weights outcome, rollout stage, recency, and context matching.
- Build one persisted score breakdown for a baseline strategy and one verified candidate.
- Blend live memory and replay-fitness fallback when the live sample is too small.

## Success Checks

- The runtime can score a verified candidate deterministically from durable memory records.
- Sparse memory history falls back to replay fitness instead of producing an empty or unstable score.
- Score output preserves contributing memories, weights, recency effects, and context matches.
