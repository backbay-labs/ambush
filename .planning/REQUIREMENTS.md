# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.4 Requirements

### Adversarial Replay Corpus

- [ ] **RED-01**: Team can run Hellcat-inspired adversarial scenario corpora against the offline replay harness
- [ ] **RED-02**: Team can group adversarial scenarios into named suites with campaign, technique, and benign-vs-adversarial metadata for repeatable execution
- [ ] **RED-03**: Evaluation reports can identify which adversarial scenarios, suites, or technique groups regressed

### Strategy Experiments

- [ ] **EVO-01**: Team can register a candidate detection strategy as a repo-owned experiment input without changing the production detector configuration
- [ ] **EVO-02**: Team can compare baseline and candidate strategies against the same replay corpus on detection quality, false positives, and latency
- [ ] **EVO-03**: Candidate strategy experiments persist lineage, corpus version, and score summaries for offline review
- [ ] **EVO-04**: Offline experiment gates fail when a candidate regresses known-bad coverage or misses configured comparison thresholds

## Future Requirements

### Advanced Governance

- **GOV-01**: Runtime can support independent multi-node policy authorities when real trust boundaries exist
- **GOV-02**: Runtime can require quorum-based approval for high-impact response actions once independent fault domains are operationally justified

### Rich Operator Surfaces

- **OPS-04**: Operator can use an authenticated HTTP or TUI control surface in addition to the initial repo-owned CLI
- **OPS-05**: Operator can trigger approved maintenance operations from the control surface with explicit audit trails

### Promotion Workflow

- **EVO-05**: Verified candidate strategies can progress through explicit shadow, canary, and human-approved promotion stages
- **EVO-06**: Strategy promotion records include formal verification evidence and rollback metadata

## Out of Scope

| Feature | Reason |
|---------|--------|
| Live canary deployment or production promotion of candidate strategies | This milestone is restricted to offline experimentation and bench tooling |
| Automatic mutation or self-evolution in the live runtime | The production hot path remains deterministic and static |
| Full Z3 deployment gate integration | Offline experiment semantics come first; deployment proof gates can follow later |
| Distributed red swarm execution against production targets | The roadmap still treats red-team pressure as offline evaluation work |
| Distributed governance or quorum approvals | No independent trust domains exist yet |
| Multi-user HTTP control plane or auth/RBAC | Secondary to adversarial replay and strategy bench workflows |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| RED-01 | Phase 14 | Pending |
| RED-02 | Phase 14 | Pending |
| RED-03 | Phase 16 | Pending |
| EVO-01 | Phase 15 | Pending |
| EVO-02 | Phase 15 | Pending |
| EVO-03 | Phase 16 | Pending |
| EVO-04 | Phase 16 | Pending |

**Coverage:**
- v1.4 requirements: 7 total
- Mapped to phases: 7
- Unmapped: 0

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.4 definition*
