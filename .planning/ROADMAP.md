# Milestone v1.22: Portable Review Capsules And External Handoff

**Status:** NOT STARTED
**Date:** 2026-04-04
**Milestone Goal:** Make cross-lane review portable and independently verifiable across trust boundaries without granting direct store access or widening into live multi-user control.

## Overview

`v1.21` unified governance-prep, canary, and production evidence into one lane-aware advisory review flow. That closed the local comparison gap, but those sessions still live entirely inside one local store boundary and cannot yet be handed off cleanly for external verification or delegated continuation.

`v1.22` closes that portability gap. It focuses on signed review capsule export, imported capsule verification with explicit local trust status, and delegation packets that preserve review continuity across handoff boundaries. Quorum approvals, signed votes, and direct remote control remain deferred.

## Phase Plan

### Phase 68: Signed Review Capsule Export

**Status:** NOT STARTED

**Goal:** Package cross-lane review state into one signed portable capsule.

**Requirements:** OPS-24

**Depends on:** Phase 67

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can export a portable review capsule from one cross-lane session or readiness artifact without granting direct store access.
- Capsule export preserves signed evidence references, lane summaries, unresolved gaps, and signer metadata.
- Exported capsules can be verified later without needing the original local store layout.

### Phase 69: Imported Capsule Verification

**Status:** NOT STARTED

**Goal:** Import a foreign review capsule and evaluate its trust locally.

**Requirements:** OPS-25

**Depends on:** Phase 68

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can import and inspect a foreign review capsule by stable ID through `swarmctl` and the local review surface.
- Imported capsules preserve remote signer lineage, local trust status, and related stable refs.
- Failed or untrusted imports remain inspectable as durable blocked artifacts.

### Phase 70: Delegation Packets And Review Continuity

**Status:** NOT STARTED

**Goal:** Preserve review continuity when a signed review is delegated across trust boundaries.

**Requirements:** OPS-20

**Depends on:** Phase 69

**Plans:** 0/1 plans complete

**Success Criteria:**
- Operators can create delegation packets that preserve source session lineage, imported capsule context, and review intent.
- Delegated review continuity stays advisory-only and does not grant direct rollout, promotion, or governance authority.
- The local review surface and `swarmctl` can reload portable review continuity artifacts by stable ID.

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OPS-24 | Phase 68 | Planned |
| OPS-25 | Phase 69 | Planned |
| OPS-20 | Phase 70 | Planned |

## Deferred Follow-On Milestones

**Queued next:** `v1.23 Approval Ledger And Quorum Readiness`
- Phase 71: Approval Set Definition — `GOV-03`
- Phase 72: Signed Approval Ledger — `GOV-04`
- Phase 73: Promotion Approval Readiness Surface — `GOV-01`

**Queued after that:** `v1.24 Approval Receipt Packs And Human Gate Prep`
- Phase 74: Threshold Verdict Assembly — `GOV-05`
- Phase 75: Signed Approval Receipt Packs — `GOV-06`, `GOV-02`
- Phase 76: Critical-Action Human Review Packets — `GOV-07`

## Next Step

`$gsd-plan-phase 68`

---
*Roadmap created: 2026-04-04*
*Last updated: 2026-04-04 for milestone v1.22 planning and queued v1.23-v1.24*
