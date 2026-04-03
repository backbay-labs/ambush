# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.10 Requirements

### Queue Handoff

- [x] **HAND-01**: Accepted queue proposals can feed the existing canary rollout path without manual artifact translation
- [x] **HAND-02**: Team can persist a durable handoff artifact that binds one accepted proposal, one verification reference, one proof summary, and one passed shadow artifact
- [x] **HAND-03**: Handoff creation fails closed when proposal state, proof status, verification linkage, or shadow evidence is missing or inconsistent

### Canary Launch

- [x] **HAND-04**: Operator can inspect a stable handoff artifact and launch canary from it through `swarmctl`
- [x] **HAND-05**: Queue-to-canary launch records preserve source proposal, proof, verification, shadow, and resulting canary-run references in one durable artifact

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
| Multi-node or partial-fleet production rollout | The runtime is still single-node and self-contained; this cycle focuses on queue-to-canary handoff, not distributed traffic management |
| Automatic canary launch from accepted proposals | `v1.10` keeps rollout launch explicit and operator-triggered |
| Hot-path proposal scoring or handoff evaluation on live events | Fast detection remains the core value, so queue and handoff assembly stay off the critical lane |
| Authenticated HTTP or TUI control plane | CLI-first remains the smallest practical operator surface for the current runtime |
| Autonomous strategy mutation in the live hot path | Production detection remains deterministic and operator-controlled |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| HAND-01 | Phase 34 | Complete |
| HAND-02 | Phase 32 | Complete |
| HAND-03 | Phase 33 | Complete |
| HAND-04 | Phase 34 | Complete |
| HAND-05 | Phase 34 | Complete |

**Coverage:**
- v1.10 requirements: 5 total
- Mapped to phases: 5
- Unmapped: 0

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.10 completion*
