# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.9 Requirements

### Evolution Queue

- [ ] **EVOL-01**: Candidate detector strategies carry proof-backed safety artifacts rather than heuristic invariant summaries alone
- [ ] **EVOL-02**: Team can propose verified detector strategy updates through a repo-owned evolution queue without widening live autonomy beyond operator-controlled rollout
- [ ] **EVOL-03**: Evolution queue admission fails closed when proof artifacts, verification evidence, or lineage metadata are missing or inconsistent

### Queue Records

- [ ] **EVOL-04**: Queue records preserve lineage, replay or verification evidence, advisory scorecard references, and current review state in one durable artifact
- [ ] **EVOL-05**: Operator can list and reload queued proposals by stable proposal ID, strategy ID, or review state through `swarmctl`

### Operator Review

- [ ] **EVOL-06**: Operator can record queue decisions such as accept for canary, defer, or reject without mutating production detector configuration directly
- [ ] **EVOL-07**: Queue review surfaces explain proof status and advisory ranking so operators can understand why a proposal is ready, blocked, or deferred

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
| Multi-node or partial-fleet production rollout | The runtime is still single-node and self-contained; this cycle focuses on queued detector proposals, not distributed traffic management |
| Automatic detector promotion from queue decisions | `v1.9` keeps review operator-controlled and stops short of live rollout mutation |
| Hot-path proposal scoring on live events | Fast detection remains the core value, so queue assembly and proof review stay off the critical lane |
| Authenticated HTTP or TUI control plane | CLI-first remains the smallest practical operator surface for the current runtime |
| Autonomous strategy mutation in the live hot path | Production detection remains deterministic and operator-controlled |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| EVOL-01 | Phase 30 | Pending |
| EVOL-02 | Phase 29 | Pending |
| EVOL-03 | Phase 30 | Pending |
| EVOL-04 | Phase 29 | Pending |
| EVOL-05 | Phase 31 | Pending |
| EVOL-06 | Phase 31 | Pending |
| EVOL-07 | Phase 31 | Pending |

**Coverage:**
- v1.9 requirements: 7 total
- Mapped to phases: 7
- Unmapped: 0

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.9 roadmap creation*
