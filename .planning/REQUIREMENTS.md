# Requirements: Swarm Team Six

**Defined:** 2026-04-04
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.14 Requirements

### Ranked Candidate Selection

- [ ] **EVOL-17**: Operator can create a durable ranked-candidate selection from one shortlist review packet through `swarmctl` without re-materializing the candidate manifest
- [ ] **EVOL-18**: Ranked-candidate selection artifacts preserve ranking, review packet, materialization, validation, advisory, and parent queue lineage in one durable record

### Review Decisions

- [ ] **EVOL-19**: Operator can list and inspect ranked-candidate selections by stable ID through `swarmctl`
- [ ] **EVOL-20**: Operator can record accepted, deferred, or rejected review state for ranked-candidate selections without rewriting underlying ranking evidence

### Rollout Bridge

- [ ] **EVOL-21**: Accepted ranked-candidate selections can feed the existing handoff and canary launch path using the preserved experiment and validation artifacts
- [ ] **EVOL-22**: Stale, blocked, or inconsistent ranked-candidate selections fail closed and persist inspectable blocked records instead of mutating queue, canary, or production state

## Future Requirements

### Governance

- **GOV-01**: Strategy promotion to production requires quorum-based approval once independent trust boundaries exist
- **GOV-02**: Promotion records include signed votes and durable consensus receipts

### Rich Operator Surfaces

- **OPS-04**: Operator can use an authenticated HTTP or TUI control surface in addition to the initial repo-owned CLI
- **OPS-05**: Operator can trigger approved maintenance operations from the control surface with explicit audit trails

### Advanced Evolution

- **EVOL-23**: Ranked-candidate selections can feed a later governance-backed or multi-node rollout review path without re-encoding existing evidence
- **EVOL-24**: Operators can compare and curate shortlisted candidates across multiple mutation batches or campaign cohorts

## Out of Scope

| Feature | Reason |
|---------|--------|
| Automatic ranked-candidate selection from batch scores | `v1.14` keeps selection explicit and operator-reviewed |
| Automatic canary or production launch from ranked candidates | Existing rollout gates remain explicit and separate from offline ranking |
| Quorum or BFT approval for ranked candidates | Independent trust boundaries still do not exist, and governance remains explicitly deferred |
| Cross-batch tournament ranking | This cycle bridges one ranked batch back into rollout review before building broader portfolio workflows |
| Hot-path mutation, selection, or rollout bridging | Fast detection remains the core value, so all ranked-candidate work stays off the critical lane |
| Authenticated HTTP or TUI control plane | CLI-first remains the smallest practical operator surface for the current runtime |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| EVOL-17 | Pending roadmap | Pending |
| EVOL-18 | Pending roadmap | Pending |
| EVOL-19 | Pending roadmap | Pending |
| EVOL-20 | Pending roadmap | Pending |
| EVOL-21 | Pending roadmap | Pending |
| EVOL-22 | Pending roadmap | Pending |

**Coverage:**
- v1.14 requirements: 6 total
- Mapped to phases: 0
- Unmapped: 6 ⚠️

---
*Requirements defined: 2026-04-04*
*Last updated: 2026-04-04 after milestone v1.14 requirements definition*
