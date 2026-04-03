# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.11 Requirements

### Selection Pressure

- [ ] **DRAFT-01**: Team can derive selection-pressure signals from replay regressions, verification drift, or strategy-memory gaps without mutating live rollout state
- [ ] **DRAFT-02**: Selection-pressure reports preserve stable IDs, source evidence references, and rationale for why a new detector proposal draft should exist

### Proposal Drafts

- [ ] **DRAFT-03**: Team can persist draft proposal artifacts with stable IDs, rationale, and source evidence references without auto-enqueuing them
- [ ] **DRAFT-04**: Operator can inspect one draft artifact and promote it into the reviewed evolution queue through `swarmctl`

### Operator Control

- [ ] **DRAFT-05**: Draft promotion preserves the originating pressure signal, operator reason, and resulting queue proposal reference in one durable artifact

## Future Requirements

### Governance

- **GOV-01**: Strategy promotion to production requires quorum-based approval once independent trust boundaries exist
- **GOV-02**: Promotion records include signed votes and durable consensus receipts

### Rich Operator Surfaces

- **OPS-04**: Operator can use an authenticated HTTP or TUI control surface in addition to the initial repo-owned CLI
- **OPS-05**: Operator can trigger approved maintenance operations from the control surface with explicit audit trails

### Advanced Evolution

- **EVOL-08**: Queue-approved detector proposals can feed a later governance-backed rollout path without manual artifact translation
- **EVOL-09**: Selection pressure from replay regressions or production memory can seed candidate proposal drafts before operator review

## Out of Scope

| Feature | Reason |
|---------|--------|
| Quorum or BFT approval for queued proposal promotion | Independent trust boundaries still do not exist, and governance remains explicitly deferred |
| Multi-node or partial-fleet production rollout | The runtime is still single-node and self-contained; this cycle focuses on draft generation and queue promotion, not distributed traffic management |
| Automatic draft enqueue or canary launch | `v1.11` keeps draft promotion explicit and operator-triggered |
| Hot-path selection-pressure scoring on live events | Fast detection remains the core value, so pressure analysis and draft assembly stay off the critical lane |
| Authenticated HTTP or TUI control plane | CLI-first remains the smallest practical operator surface for the current runtime |
| Autonomous strategy mutation in the live hot path | Production detection remains deterministic and operator-controlled |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| DRAFT-01 | Phase 35 | Pending |
| DRAFT-02 | Phase 35 | Pending |
| DRAFT-03 | Phase 36 | Pending |
| DRAFT-04 | Phase 37 | Pending |
| DRAFT-05 | Phase 37 | Pending |

**Coverage:**
- v1.11 requirements: 5 total
- Mapped to phases: 5
- Unmapped: 0

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.11 creation*
