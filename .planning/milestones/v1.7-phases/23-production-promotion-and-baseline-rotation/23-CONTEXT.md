# Phase 23 Context

## Goal

Promote a ready canary artifact into the production detector role with explicit baseline rotation, fallback retention, and stable promotion identity.

## Current Reality

- `v1.6` already ships `experiment -> verification -> shadow -> canary`.
- The canary artifact is now the documented handoff into the next decision step.
- The runtime has no repo-owned production-promotion harness yet.
- There is no persisted production-promotion record or CLI for starting a promotion from canary evidence.

## Constraints

- Stay pure Rust and reuse the existing CLI/store patterns.
- Do not add quorum governance, BFT, or multi-node rollout semantics.
- Promotion must remain fail-closed and baseline-aware.
- The previous production detector must remain the explicit rollback target.

## Likely Implementation Shape

- Add a `PromotionConfig` block to the shared config model.
- Add a repo-owned promotion harness and file-backed store in `swarm-runtime`.
- Start promotions from a completed canary artifact instead of ad hoc config edits.
- Persist one stable promotion ID with baseline lineage, canary evidence, and observation state.

## Success Checks

- Operator can start a promotion from a ready canary run ID.
- Promotion artifact persists baseline rotation and stable identity.
- Starting promotion fails if the canary is blocked, incomplete, or mismatched with the current baseline.
