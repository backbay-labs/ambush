---
phase: 37-draft-review-and-queue-promotion
plan: 01
subsystem: evolution-drafting
tags:
  - evolution
  - drafting
  - queue
  - cli
one-liner: Added draft inspection and durable draft-promotion records that create reviewed queue entries without auto-launching rollout.
requires:
  - 36-proposal-draft-artifacts
provides:
  - file-backed draft-promotion storage rooted under `data/evolution-draft-promotions/`
  - reviewed queue entry creation from one stable draft
  - stable-ID reload through `swarmctl evolution-draft-promotion-result`
affects:
  - existing evolution queue artifacts under `data/evolution-queue/`
tech-stack:
  added:
    - serde-backed draft-promotion reports and index files
  patterns:
    - queue promotion preserves operator reason and source-draft lineage
    - reviewed queue entry remains blocked from canary admission until proof-backed evidence exists
key-files:
  modified:
    - crates/swarm-runtime/src/drafting.rs
    - crates/swarm-runtime/src/bin/swarmctl.rs
    - docs/CONFIGURATION.md
key-decisions:
  - "Promote drafts into the existing reviewed queue instead of inventing a second review lane."
  - "Keep promoted draft proposals in `pending_review` with explicit blocking reasons so they are visible but cannot be admitted to canary."
  - "Persist a dedicated draft-promotion record that links pressure report, draft, operator reason, and resulting queue proposal."
patterns-established:
  - "The drafting lane now hands off into the reviewed queue without bypassing later proof-backed rollout gates."
requirements-completed:
  - DRAFT-04
  - DRAFT-05
duration: 20min
completed: 2026-04-03
---

# Phase 37: Draft Review And Queue Promotion Summary

**Operators can now inspect one draft, promote it into the reviewed queue, and reload a durable promotion record that links the pressure source, draft artifact, operator reason, and resulting queue proposal.**

## Performance

- **Duration:** 20 min
- **Completed:** 2026-04-04T02:43:15Z
- **Tasks:** 4
- **Files modified:** 3

## Accomplishments

- Added `EvolutionDraftPromotionReport`, `EvolutionDraftPromotionRecord`, and `FileEvolutionDraftPromotionStore` in `crates/swarm-runtime/src/drafting.rs`.
- Implemented `promote_draft` to create a reviewed queue entry and preserve a durable promotion record.
- Added `swarmctl evolution-draft-promote` and `evolution-draft-promotion-result`.
- Verified that promoted drafts remain blocked from canary admission until later proof-backed evidence exists.

## Decisions Made

- Draft promotion reuses `EvolutionProposalReport` so the existing queue, list, and decision surfaces remain the single review lane.
- Promoted drafts stay visible in `pending_review` instead of being auto-rejected or hidden.
- Promotion is idempotent per draft; repeated promotions fail closed with the original queue proposal reference.

## Deviations from Plan

The resulting queue entry is created directly through `FileEvolutionProposalStore` rather than a new queue-harness method. That avoided broad changes to the existing verified-queue code while still preserving one consistent queue artifact format.

## Issues Encountered

The existing queue model assumed proof-backed proposals. Draft promotion solved that by creating `pending_review` entries with explicit blocking reasons and `proof_status=missing`.

## User Setup Required

Run the shipped end-to-end draft workflow:

```bash
cargo run -p swarm-runtime --bin swarmctl -- evolution-draft-promote --draft-id YOUR_DRAFT_ID --reason "queue this draft for explicit operator review"
```

## Next Phase Readiness

`v1.11` is complete. The next planning step is `$gsd-new-milestone`.

---
*Phase: 37-draft-review-and-queue-promotion*
*Completed: 2026-04-03*
