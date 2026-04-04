# Milestone v1.20: Evidence Workbench And Review Handoffs

**Status:** ACTIVE
**Date:** 2026-04-04
**Milestone Goal:** Turn the local evidence review surface into a practical operator workbench for multi-artifact comparison, export, and bounded action handoff without widening into quorum governance or a browser-first control plane.

## Overview

`v1.19` closed the JSON-first inspection gap by adding a local authenticated HTML review surface for evidence bundles, verification reports, and promotion evidence packets. That surface is useful, but it still treats artifacts mostly one at a time, and operators still have to drop back to raw API or CLI flows to compare multiple artifacts, export a reviewed set, or carry reviewed evidence into a bounded maintenance action.

`v1.20` closes that operator workflow gap without widening autonomy. It focuses on durable review sessions built from existing stable IDs, side-by-side evidence comparison and export above the authenticated operator API, and review-driven maintenance handoffs that reuse the existing bounded maintenance audit trail. Quorum approvals, signed votes, multi-user collaboration, and direct rollout or governance writes remain deferred.

## Phase Plan

### Phase 62: Review Session Assembly

**Status:** PLANNED

**Goal:** Create durable local review sessions from existing evidence and promotion artifact stable IDs.

**Requirements:** OPS-15

**Depends on:** Phase 61

**Plans:** 0/0 plans complete

**Success Criteria:**
- Operators can assemble one review session from multiple evidence bundle, verification, and promotion packet IDs.
- Review sessions persist a stable session ID and can be reloaded without rereading raw store files.
- Session creation stays local, authenticated, and read-mostly, reusing the existing stable-ID artifact contracts.

### Phase 63: Evidence Comparison And Export

**Status:** PLANNED

**Goal:** Compare multiple reviewed artifacts side by side and export the reviewed evidence set with preserved trust metadata.

**Requirements:** OPS-14, OPS-16

**Depends on:** Phase 62

**Plans:** 0/0 plans complete

**Success Criteria:**
- Operators can compare multiple reviewed evidence artifacts in one local session instead of flipping through one detail page at a time.
- The workbench can export the reviewed set with preserved digests, signer metadata, verification state, and related stable refs.
- Comparison and export stay above the authenticated operator API instead of introducing a second artifact or file-reading protocol.

### Phase 64: Review-Driven Maintenance Handoffs

**Status:** PLANNED

**Goal:** Hand reviewed evidence into bounded maintenance actions from the workbench while preserving the existing audit trail and safety boundary.

**Requirements:** OPS-13, OPS-17, OPS-18

**Depends on:** Phase 63

**Plans:** 0/0 plans complete

**Success Criteria:**
- Operators can trigger bounded maintenance actions from the review client using the existing authenticated maintenance scope.
- Review-driven action requests preserve source session lineage, selected artifact refs, operator rationale, and resulting action IDs.
- The workbench cannot bypass rollout, promotion, or governance gates and remains explicitly bounded to maintenance handoff.

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OPS-15 | Phase 62 | Pending |
| OPS-14 | Phase 63 | Pending |
| OPS-16 | Phase 63 | Pending |
| OPS-13 | Phase 64 | Pending |
| OPS-17 | Phase 64 | Pending |
| OPS-18 | Phase 64 | Pending |

## Deferred Work

- Quorum-based approval, signed vote collection, and durable consensus receipts remain deferred until independent trust boundaries exist.
- Multi-user RBAC, federated operator workflows, and internet-exposed review surfaces remain out of scope for this cycle.
- Direct rollout, promotion, or governance mutation from the review workbench remains deferred; bounded writes stay on the existing maintenance path.

## Next Step

`$gsd-plan-phase 62`

---
*Roadmap created: 2026-04-04*
*Last updated: 2026-04-04 for milestone v1.20 planning*
