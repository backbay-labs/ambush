# Roadmap

**Status:** ACTIVE MILESTONE
**Current Milestone:** `v1.21 Cross-Lane Promotion Review`
**Queued Milestones:** `v1.22 Portable Review Capsules And External Handoff`, `v1.23 Approval Ledger And Quorum Readiness`
**Date:** 2026-04-04

## Current Milestone: v1.21 Cross-Lane Promotion Review

**3 phases** | **4 requirements mapped** | All covered ✓

| # | Phase | Goal | Requirements | Success Criteria |
|---|-------|------|--------------|------------------|
| 65 | Cross-Lane Session Assembly | unify governance-prep, canary, and production evidence into one lane-aware review session model | OPS-19, OPS-21 | 3 |
| 66 | Lane Comparison And Export | persist signed cross-lane comparisons with freshness and evidence-gap visibility | OPS-22 | 3 |
| 67 | Promotion Readiness Review | derive advisory promotion-readiness artifacts without widening rollout authority | OPS-23 | 3 |

### Phase Details

**Phase 65: Cross-Lane Session Assembly**
Goal: let operators assemble and reload one review session that spans governance-prep, canary, and production evidence.

Success criteria:
- operator can create one session from mixed lane refs and stable IDs without reading raw store files
- reloaded sessions preserve lane labels, lineage, freshness markers, and unresolved evidence gaps
- the authenticated local review surface and `swarmctl` expose the same lane-aware session model

**Phase 66: Lane Comparison And Export**
Goal: make cross-lane comparison durable, signed, and inspectable.

Success criteria:
- operators can produce a signed comparison snapshot with per-lane summaries and verification state
- comparison output highlights unresolved gaps, stale evidence, and mismatched lineage across lanes
- exported comparison snapshots can be reloaded by stable ID through existing review surfaces

**Phase 67: Promotion Readiness Review**
Goal: turn cross-lane evidence into one advisory promotion-readiness workflow.

Success criteria:
- operators can derive one promotion-readiness review from governance-prep, canary, and production evidence
- blocked or stale evidence states fail closed and remain inspectable as durable artifacts
- the workflow remains advisory-only and does not bypass maintenance, canary, or production controls

## Queued Milestone: v1.22 Portable Review Capsules And External Handoff

**Planned phases:** 3 | **Target phase range:** 68-70

| # | Phase | Goal | Planned Requirements |
|---|-------|------|----------------------|
| 68 | Signed Review Capsule Export | package reviewed sessions as portable signed capsules | OPS-24 |
| 69 | Imported Capsule Verification | verify and inspect foreign review capsules locally | OPS-25 |
| 70 | Delegation Packets And Review Continuity | preserve delegation lineage and handoff context without opening multi-user live control | OPS-20 |

## Queued Milestone: v1.23 Approval Ledger And Quorum Readiness

**Planned phases:** 3 | **Target phase range:** 71-73

| # | Phase | Goal | Planned Requirements |
|---|-------|------|----------------------|
| 71 | Approval Set Definition | define eligible voters, thresholds, and supporting evidence for promotion review | GOV-03 |
| 72 | Signed Approval Ledger | persist local signed approval statements and missing-quorum state | GOV-04, GOV-02 |
| 73 | Promotion Approval Readiness Surface | expose quorum-readiness and approval gaps without claiming distributed consensus exists | GOV-01 |

## Next Step

`$gsd-plan-phase 65`

---
*Last updated: 2026-04-04 after starting milestone v1.21 and queueing v1.22-v1.23*
