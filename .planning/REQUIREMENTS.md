# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.7 Requirements

### Production Promotion

- [ ] **PROD-01**: Team can promote a canary-approved detector to production while retaining the previous production detector as an explicit rollback target
- [ ] **PROD-02**: Operator can start a production promotion from a ready canary artifact and persist a stable promotion ID with baseline lineage

### Promotion Observation

- [ ] **PROD-03**: Production promotion records detection, divergence, latency, and budget metrics over a configurable post-promotion observation window
- [ ] **PROD-04**: Production promotion automatically rolls back when observation-window metrics diverge beyond configured thresholds or resource budgets

### Promotion Review

- [ ] **PROD-05**: Operator can manually halt or roll back a production promotion and retrieve the reason, restored baseline, and affected observation window
- [ ] **PROD-06**: Promotion records persist canary evidence, promoted strategy lineage, rollback target, and final recommendation in one durable artifact
- [ ] **PROD-07**: Operator CLI can inspect active or completed production promotions and rollback history by stable ID

## Future Requirements

### Governance

- **GOV-01**: Strategy promotion to production requires quorum-based approval once independent trust boundaries exist
- **GOV-02**: Promotion records include signed votes and durable consensus receipts

### Adaptive Selection

- **MEM-01**: Team can score verified strategies with context-aware utility memories instead of replay fitness alone

### Rich Operator Surfaces

- **OPS-04**: Operator can use an authenticated HTTP or TUI control surface in addition to the initial repo-owned CLI
- **OPS-05**: Operator can trigger approved maintenance operations from the control surface with explicit audit trails

## Out of Scope

| Feature | Reason |
|---------|--------|
| Quorum or BFT approval for promotion | Independent trust boundaries still do not exist, and governance remains explicitly deferred |
| Multi-node or partial-fleet production rollout | The runtime is still single-node and self-contained; this cycle focuses on baseline rotation and observation, not distributed traffic management |
| MemRL-backed automatic strategy selection | Production memory should follow a real promotion path, not precede it |
| Authenticated HTTP or TUI control plane | CLI-first remains the smallest practical operator surface for the current runtime |
| Autonomous strategy mutation in the live hot path | Production detection remains deterministic and operator-controlled |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| PROD-01 | Phase 23 | Pending |
| PROD-02 | Phase 23 | Pending |
| PROD-03 | Phase 24 | Pending |
| PROD-04 | Phase 24 | Pending |
| PROD-05 | Phase 25 | Pending |
| PROD-06 | Phase 25 | Pending |
| PROD-07 | Phase 25 | Pending |

**Coverage:**
- v1.7 requirements: 7 total
- Mapped to phases: 7
- Unmapped: 0

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.7 definition*
