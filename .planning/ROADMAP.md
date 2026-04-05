# Roadmap: Swarm Team Six

## Milestones

<details>
<summary>Previous milestones (v1.0 through v1.22) -- see MILESTONES.md</summary>

Phases 1-70 shipped across milestones v1.0 through v1.22. Full history in `.planning/MILESTONES.md`.

</details>

<details>
<summary>v1.23 Cryptographic Foundation And Guard Pipeline (Shipped 2026-04-05)</summary>

**Milestone Goal:** Port battle-tested hush-core crypto and clawdstrike guard implementations into STS crates, wire the guard pipeline into response authorization, and establish CI quality gates.

#### Phase 71: Cryptographic Foundation
**Goal**: swarm-crypto provides real cryptographic primitives from hush-core so downstream crates can sign, verify, hash, and prove inclusion without minimal stubs
**Status**: Complete (2026-04-05 UTC)
**Plans:** 2/2 complete

#### Phase 72: Guard Trait And Implementations
**Goal**: swarm-guard provides a fail-closed pluggable guard pipeline with four concrete guards covering filesystem, shell, secret, and egress safety
**Status**: Complete (2026-04-05 UTC)
**Plans:** 2/2 complete

#### Phase 73: Spine Enhancement And Runtime Integration
**Goal**: swarm-spine can construct and verify signed envelopes and checkpoint statements using swarm-crypto, and the guard pipeline gates response actions in the runtime before execution
**Status**: Complete (2026-04-05 UTC)
**Plans:** 2/2 complete

#### Phase 74: CI Pipeline And Quality Gates
**Goal**: Every push and pull request is automatically checked for formatting, lint, build, and test correctness, and dependency governance prevents unapproved licenses or known vulnerabilities
**Status**: Complete (2026-04-05 UTC)
**Plans:** 1/1 complete

</details>

### v1.24 Approval Ledger And Quorum Readiness (In Progress)

**Milestone Goal:** Prepare local approval ledgers, signed vote artifacts, threshold-based quorum validation, approval receipt packs, and human-gate pending states for critical-severity promotion candidates -- all without requiring distributed consensus.

## Phases

- [ ] **Phase 75: Approval Set Definition And Signed Ledgers** - Define approval sets with voters and thresholds, create signed ledger artifacts that preserve vote lineage
- [ ] **Phase 76: Approval Verdict And Receipt Packs** - Assemble local verdicts from ledger entries, export signed receipt packs with approval lineage
- [ ] **Phase 77: Human Gate And Promotion Integration** - Hold critical-severity candidates in human-approval-pending state, wire quorum requirement and signed votes into promotion records

## Phase Details

### Phase 75: Approval Set Definition And Signed Ledgers
**Goal**: Operators can define who is eligible to approve, what threshold is required, and the runtime can persist signed approval ledger entries that preserve vote lineage and quorum state
**Depends on**: Nothing (first phase this milestone; builds on swarm-crypto signing and swarm-spine envelopes from v1.23)
**Requirements**: GOV-03, GOV-04
**Success Criteria** (what must be TRUE):
  1. Operator can create an approval set through `swarmctl` specifying eligible voter identities, a threshold rule, and a reference to supporting promotion evidence
  2. Approval set persists as a durable artifact with a stable ID and can be reloaded by that ID
  3. Signed votes can be appended to an approval ledger where each entry carries a voter identity, Ed25519 signature, and timestamp
  4. The approval ledger tracks current vote count against the threshold and exposes explicit missing-quorum state when the threshold is not yet met
  5. Ledger entries and approval sets are accessible through `swarmctl` and the authenticated HTTP surface
**Plans:** 1 plan

Plans:
- [ ] 75-01-PLAN.md -- Core approval types, file-backed stores, harness, swarmctl subcommands, and HTTP endpoints

### Phase 76: Approval Verdict And Receipt Packs
**Goal**: Operators can evaluate a completed or partial ledger against threshold rules to produce a deterministic verdict, and export the full approval chain as a signed receipt pack for later verification
**Depends on**: Phase 75 (approval sets and signed ledger entries must exist)
**Requirements**: GOV-05, GOV-06
**Success Criteria** (what must be TRUE):
  1. Operator can assemble a local approval verdict from an approval ledger that evaluates signed entries against the approval set threshold rules
  2. The verdict is deterministic: the same ledger state and threshold rules always produce the same approved or not-approved result
  3. Operator can export a signed approval receipt pack that bundles the approval set, ledger entries, final verdict, and audit references into one portable artifact
  4. The receipt pack is signed using swarm-crypto Ed25519 and can be independently verified without access to the local store
**Plans:** 1 plan

Plans:
- [ ] 76-01-PLAN.md -- Verdict evaluation, receipt pack types, stores, harness, and swarmctl subcommands

### Phase 77: Human Gate And Promotion Integration
**Goal**: Critical-severity promotion candidates are held in a human-approval-pending state until an operator explicitly clears them, and promotion records now carry signed votes and durable consensus receipts
**Depends on**: Phase 76 (verdicts and receipt packs feed into promotion gating)
**Requirements**: GOV-07, GOV-01, GOV-02
**Success Criteria** (what must be TRUE):
  1. A promotion candidate tagged as critical-severity enters an explicit human-approval-pending state instead of proceeding directly through the promotion pipeline
  2. The pending state persists a review packet and durable audit history that an operator can inspect through `swarmctl` and the authenticated HTTP surface
  3. Promotion records now include signed vote references and a durable consensus receipt that links back to the approval ledger and verdict
  4. The quorum-approval requirement is structurally present in the promotion path so that when independent trust boundaries arrive, the gate activates without changing the promotion model
**Plans**: TBD

Plans:
- [ ] 77-01: TBD
- [ ] 77-02: TBD

## Progress

**Execution Order:** 75 -> 76 -> 77

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 75. Approval Set Definition And Signed Ledgers | v1.24 | 0/1 | Planning complete | - |
| 76. Approval Verdict And Receipt Packs | v1.24 | 0/1 | Planning complete | - |
| 77. Human Gate And Promotion Integration | v1.24 | 0/TBD | Not started | - |

---
*Roadmap created: 2026-04-05 for milestone v1.24*
