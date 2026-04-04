# Milestone v1.13: Guided Mutation And Candidate Ranking

**Status:** READY FOR PLANNING
**Date:** 2026-04-03
**Milestone Goal:** Turn the single-candidate draft bridge into an operator-controlled multi-candidate evolution bench with structured mutation specs, batch validation, and deterministic ranking.

## Overview

`v1.12` closed the single-candidate continuity gap from reviewed drafts back into the verified rollout ladder. The runtime can now materialize one draft-backed candidate, refresh its validation evidence, reconcile it into the reviewed queue, and hand it toward canary through the existing operator-controlled path.

The next useful step is to widen that bench without widening autonomy. `v1.13` focuses on operator-authored mutation intent, batch candidate generation, batch evidence refresh, and deterministic ranking so teams can compare several validated candidates before any later queue or rollout decision. This milestone stays offline, CLI-first, and evidence-driven.

## Phase Plan

### Phase 41: Structured Mutation Specs

**Status:** COMPLETE

**Goal:** Derive durable mutation-spec artifacts from reviewed drafts or materialized candidates without hand-editing multiple manifests.

**Requirements:** EVOL-10, EVOL-11

**Depends on:** Phase 40

**Plans:** 1/1 plans complete

**Success Criteria:**
- Operators can create one durable mutation spec from an existing draft or materialized candidate through `swarmctl`.
- Mutation specs preserve stable IDs, source lineage, intended mutation dimensions, and operator rationale.
- Mutation specs remain operator-authored and do not generate new candidates automatically.
- Mutation artifacts are reloadable later without reading raw storage files.

### Phase 42: Batch Candidate Materialization And Validation

**Status:** COMPLETE

**Goal:** Materialize and refresh multiple candidate variants from one mutation spec while preserving per-candidate evidence chains.

**Requirements:** EVOL-12, EVOL-13, EVOL-14

**Depends on:** Phase 41

**Plans:** 1/1 plans complete

**Success Criteria:**
- Teams can materialize a deterministic batch of candidate manifests from one mutation spec through a repo-owned CLI flow.
- Each candidate preserves stable references back to the mutation spec, parent draft lineage, and concrete profile changes.
- Validation refresh can run across the batch without overwriting or collapsing per-candidate evidence.
- Blocked or drifted candidates fail closed while still persisting inspectable validation artifacts.

### Phase 43: Candidate Ranking And Review Packets

**Status:** READY

**Goal:** Rank or shortlist validated candidates using deterministic evidence and emit durable review packets for later operator decisions.

**Requirements:** EVOL-15, EVOL-16

**Depends on:** Phase 42

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can compute a deterministic ranking or shortlist from validated candidate batches through `swarmctl`.
- Ranking packets preserve references to each candidate's materialization, validation bundle, and reviewed queue state.
- Ranking remains advisory and does not auto-promote candidates into queue, canary, or production lanes.
- Documentation explains how ranked batches extend the existing offline evolution workflow.

## Traceability

| Requirement | Phase |
|-------------|-------|
| EVOL-10 | Phase 41 |
| EVOL-11 | Phase 41 |
| EVOL-12 | Phase 42 |
| EVOL-13 | Phase 42 |
| EVOL-14 | Phase 42 |
| EVOL-15 | Phase 43 |
| EVOL-16 | Phase 43 |

## Deferred Work

- Quorum-based approval and signed governance receipts remain deferred until independent trust boundaries exist.
- Automatic mutation, automatic queue promotion, and automatic rollout remain out of scope for this cycle.
- Multi-node or partial-fleet rollout remains deferred while the runtime stays single-node and self-contained.
- Authenticated HTTP or TUI operator surfaces remain secondary to the repo-owned CLI and durable artifact flow.

## Next Step

`$gsd-plan-phase 41`

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.13 definition*
