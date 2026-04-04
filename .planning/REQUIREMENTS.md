# Requirements: Swarm Team Six

**Defined:** 2026-04-04
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.15 Requirements

### Portfolio Assembly

- [ ] **EVOL-24**: Operators can compare and curate shortlisted candidates across multiple mutation batches or campaign cohorts
- [ ] **EVOL-25**: Team can assemble a durable portfolio artifact from ranked selections across multiple batches or cohorts through `swarmctl`

### Portfolio Review

- [ ] **EVOL-26**: Operator can record include, defer, or drop decisions for portfolio candidates without mutating queue, canary, or production state
- [ ] **EVOL-27**: Portfolio review artifacts preserve source ranking, selection, cohort, and rollout-lineage context in one durable record

### Governance Prep

- [ ] **EVOL-23**: Ranked-candidate selections can feed a later governance-backed or multi-node rollout review path without re-encoding existing evidence
- [ ] **EVOL-28**: Operator can generate governance-ready review packets from curated portfolio entries using preserved evidence references
- [ ] **EVOL-29**: Governance-prep review packets fail closed and persist blocked records when evidence is stale, inconsistent, or incomplete

## Future Requirements

### Governance

- **GOV-01**: Strategy promotion to production requires quorum-based approval once independent trust boundaries exist
- **GOV-02**: Promotion records include signed votes and durable consensus receipts

### Rich Operator Surfaces

- **OPS-04**: Operator can use an authenticated HTTP or TUI control surface in addition to the initial repo-owned CLI
- **OPS-05**: Operator can trigger approved maintenance operations from the control surface with explicit audit trails

### Advanced Evolution

- **EVOL-30**: Operators can merge or split governance-ready review packets across portfolio groups without losing evidence traceability
- **EVOL-31**: Portfolio history can measure cross-cohort survival, rollout outcomes, and review debt over time

## Out of Scope

| Feature | Reason |
|---------|--------|
| Actual quorum voting or distributed consensus for promotion | Independent trust boundaries still do not exist, and governance remains explicitly deferred |
| Multi-node rollout execution | This cycle prepares governance-ready packets only; it does not introduce distributed rollout machinery |
| Automatic portfolio inclusion, curation, or promotion | Portfolio review remains explicit and operator-controlled |
| Automatic canary or production launch from portfolio entries | Existing rollout gates remain explicit and separate from portfolio work |
| Authenticated HTTP or TUI control plane | CLI-first remains the smallest practical operator surface for the current runtime |
| Cross-organization or federated review exchange | This cycle stays repo-owned and single-node while preparing packet formats and durable artifacts |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| EVOL-24 | Phase 47 | Pending |
| EVOL-25 | Phase 47 | Pending |
| EVOL-26 | Phase 48 | Pending |
| EVOL-27 | Phase 48 | Pending |
| EVOL-23 | Phase 49 | Pending |
| EVOL-28 | Phase 49 | Pending |
| EVOL-29 | Phase 49 | Pending |

**Coverage:**
- v1.15 requirements: 7 total
- Mapped to phases: 7
- Unmapped: 0

---
*Requirements defined: 2026-04-04*
*Last updated: 2026-04-04 after starting milestone v1.15*
