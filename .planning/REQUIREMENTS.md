# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.6 Requirements

### Canary Deployment

- [ ] **CAN-01**: Team can assign a verified candidate detector to a bounded canary slot without replacing the production baseline
- [ ] **CAN-02**: Canary execution emits live detections only within the scoped canary lane and cannot by itself trigger fleet-wide escalation semantics
- [ ] **CAN-03**: Canary observation records detection, false-positive, latency, and resource metrics over a configurable live window

### Rollback And Safety

- [ ] **RLB-01**: Canary runs automatically roll back when configured metrics diverge beyond thresholds or resource budgets
- [ ] **RLB-02**: Operator can manually halt or roll back a canary and retrieve the reason, affected slot, and reverted baseline

### Canary Review

- [ ] **PRM-03**: Team can assemble a canary evaluation report that links verification, shadow, and canary evidence into one ready-for-promotion or blocked recommendation
- [ ] **PRM-04**: Operator CLI can inspect active or completed canary runs and rollback history by stable ID

## Future Requirements

### Production Promotion

- **PROD-01**: Team can promote a canary-approved strategy to production while retaining the previous production detector as an explicit rollback target
- **PROD-02**: Production promotion automatically rolls back when post-promotion metrics diverge during the configured observation window

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
| Fleet-wide production promotion of candidate strategies | This milestone stops at bounded canary execution and rollback |
| BFT or quorum approval for promotion | Independent trust boundaries still do not exist |
| Fully autonomous mutation or continuous evolution in the hot path | Production detection remains deterministic and operator-controlled |
| Python Kitten runtime revival | Conflicts with the Rust-first implementation direction |
| Multi-user HTTP control plane or auth/RBAC | Secondary to bounded canary execution and rollback |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CAN-01 | Phase 20 | Planned |
| CAN-02 | Phase 21 | Planned |
| CAN-03 | Phase 21 | Planned |
| RLB-01 | Phase 22 | Planned |
| RLB-02 | Phase 22 | Planned |
| PRM-03 | Phase 22 | Planned |
| PRM-04 | Phase 22 | Planned |

**Coverage:**
- v1.6 requirements: 7 total
- Mapped to phases: 7
- Unmapped: 0

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 for milestone v1.6 definition*
