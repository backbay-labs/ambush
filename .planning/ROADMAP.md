# Milestone v1.10: Queue Handoff And Canary Launch

**Status:** NOT STARTED
**Date:** 2026-04-03
**Milestone Goal:** Bridge accepted evolution proposals into the bounded canary lane through durable handoff artifacts and operator-launched rollout, without introducing automatic launch or quorum governance.

## Overview

This milestone turns the new proof-backed queue into a rollout bridge. The runtime already persists experiments, verifications, proofs, proposals, shadows, and canary runs; the next useful step is to bind accepted proposals to the shadow evidence required for canary entry and preserve that handoff as a first-class artifact.

The milestone stays deliberately narrow. It does not add automatic launch, production promotion, quorum approval, or richer HTTP or TUI operator surfaces. The goal is to remove manual artifact translation between queue review and bounded canary while keeping rollout initiation explicit and operator-controlled.

## Phase Plan

### Phase 32: Queue Handoff Artifacts

**Goal:** Persist durable handoff packets that bind an accepted proposal to the shadow evidence required for canary entry.

**Requirements:** HAND-02

**Depends on:** Phase 31

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can create a durable handoff packet from one accepted proposal plus one passed shadow artifact.
- Handoff records preserve stable IDs, queue references, verification references, proof summary, advisory summary, and shadow summary in one artifact.
- Handoff artifacts can be reloaded later without reading raw storage files.
- The handoff lane remains repo-owned and CLI-first.

### Phase 33: Queue-To-Canary Admission Gate

**Goal:** Fail handoff creation closed when accepted proposal, proof, verification, or shadow evidence is missing or inconsistent.

**Requirements:** HAND-03

**Depends on:** Phase 32

**Plans:** 0/1 plans complete

**Success Criteria:**
- Handoff creation requires an accepted proposal with proved status and a passed shadow artifact for the same experiment.
- Handoff creation records explicit blocking reasons when proposal state, proof status, verification linkage, or shadow evidence is invalid.
- Failed handoff attempts remain auditable and off the hot path.
- Admission checks never mutate canary state directly.

### Phase 34: Canary Launch From Handoff

**Goal:** Let operators inspect a stable handoff artifact and launch canary from it through `swarmctl`.

**Requirements:** HAND-01, HAND-04, HAND-05

**Depends on:** Phase 33

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can reload handoff packets by stable ID and launch bounded canary without manually restating experiment, verification, or shadow metadata.
- Launch records preserve queue proposal, proof, verification, shadow, and resulting canary-run references in one durable artifact.
- Launch remains operator-triggered; accepted proposals do not start canary implicitly.
- Documentation explains how queue handoff fits between proposal review and bounded canary.

## Traceability

| Requirement | Phase |
|-------------|-------|
| HAND-01 | Phase 34 |
| HAND-02 | Phase 32 |
| HAND-03 | Phase 33 |
| HAND-04 | Phase 34 |
| HAND-05 | Phase 34 |

## Deferred Work

- Quorum-based approval and signed governance receipts remain deferred until independent trust boundaries exist.
- Multi-node or partial-fleet rollout remains out of scope while the runtime is still single-node.
- Authenticated HTTP or TUI operator surfaces remain secondary to the repo-owned CLI and durable artifact flow.
- Automatic canary launch, automatic selection, and automatic promotion remain future work after the queue-to-canary handoff proves useful.

## Next Step

`$gsd-plan-phase 32`

---
*Roadmap created: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.10 creation*
