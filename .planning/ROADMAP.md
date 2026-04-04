# Milestone v1.14: Ranked Candidate Rollout Bridge

**Status:** READY FOR PLANNING
**Date:** 2026-04-04
**Milestone Goal:** Turn shortlisted ranked candidates into operator-reviewed rollout candidates that can re-enter the existing handoff and canary path without re-materializing evidence.

## Overview

`v1.13` closed the multi-candidate offline mutation bench. The runtime can now derive mutation specs, materialize and validate multiple variants, and rank shortlisted candidates with preserved queue lineage. What it still cannot do is take one selected ranked candidate and feed it back into the later rollout ladder without rebuilding or translating the evidence by hand.

`v1.14` closes that seam. It introduces durable ranked-candidate selection artifacts, explicit operator review decisions, and a bridge into the existing handoff and canary path using the experiment, validation, and lineage artifacts that already exist. This milestone stays CLI-first, operator-controlled, and fail-closed.

## Phase Plan

### Phase 44: Ranked Candidate Selection Artifacts

**Status:** READY

**Goal:** Create durable ranked-candidate selection artifacts from shortlist review packets without re-materializing the candidate manifest.

**Requirements:** EVOL-17, EVOL-18

**Depends on:** Phase 43

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can create one durable ranked-candidate selection from a stable ranking packet through `swarmctl`.
- Selection artifacts preserve ranking, review packet, materialization, validation, advisory, and parent queue lineage in one stable record.
- Selection creation remains operator-triggered and does not mutate queue, canary, or production state.
- Selection artifacts are reloadable later without reading raw storage files.

### Phase 45: Ranked Candidate Review Decisions

**Status:** READY

**Goal:** Add explicit operator review decisions for ranked-candidate selections while preserving immutable ranking evidence.

**Requirements:** EVOL-19, EVOL-20

**Depends on:** Phase 44

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can list and inspect ranked-candidate selections by stable ID through `swarmctl`.
- Operators can record accepted, deferred, or rejected review state for ranked-candidate selections without rewriting the underlying ranking bundle.
- Review decisions preserve operator reason, selected candidate lineage, and current decision state in one durable artifact or record.
- Review remains advisory to later rollout lanes until an explicit bridge artifact is created.

### Phase 46: Rollout Bridge For Selected Candidates

**Status:** READY

**Goal:** Let accepted ranked-candidate selections feed the existing handoff and canary launch path using preserved evidence references.

**Requirements:** EVOL-21, EVOL-22

**Depends on:** Phase 45

**Plans:** 0/1 plans complete

**Success Criteria:**
- Accepted ranked-candidate selections can create or feed the existing handoff path using the preserved experiment and validation references instead of re-materializing evidence.
- Stale, blocked, or inconsistent ranked-candidate selections fail closed and persist inspectable blocked artifacts.
- The bridge remains operator-triggered and reuses the existing canary and rollout safety boundaries.
- Documentation explains how ranked-candidate selections re-enter the rollout ladder without widening autonomy.

## Traceability

| Requirement | Phase |
|-------------|-------|
| EVOL-17 | Phase 44 |
| EVOL-18 | Phase 44 |
| EVOL-19 | Phase 45 |
| EVOL-20 | Phase 45 |
| EVOL-21 | Phase 46 |
| EVOL-22 | Phase 46 |

## Deferred Work

- Quorum-based approval and signed governance receipts remain deferred until independent trust boundaries exist.
- Automatic selection, automatic queue mutation, and automatic rollout remain out of scope for this cycle.
- Cross-batch or multi-cohort portfolio ranking remains deferred while the runtime focuses on bridging one ranked batch back into rollout review.
- Authenticated HTTP or TUI operator surfaces remain secondary to the repo-owned CLI and durable artifact flow.

## Next Step

`$gsd-plan-phase 44`

---
*Roadmap created: 2026-04-04*
*Last updated: 2026-04-04 after milestone v1.14 roadmap creation*
