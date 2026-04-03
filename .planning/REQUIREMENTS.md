# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.3 Requirements

### Operator Control

- [ ] **OPS-01**: Operator can inspect runtime status, recent decisions, investigations, and incidents through a repo-owned control surface
- [ ] **OPS-02**: Operator can retrieve a replay bundle, investigation bundle, or incident by stable IDs without reading raw storage files
- [ ] **OPS-03**: Operator can distinguish live runtime data from offline replay results in the control surface

### Replay

- [ ] **RPLY-01**: Team can run deterministic offline replay from persisted bundles or fixture corpora without executing live response actions
- [ ] **RPLY-02**: Replay run records findings, policy decisions, response receipts, investigations, and incidents into a durable result bundle
- [ ] **RPLY-03**: Team can define named replay scenarios with expected outcomes and run them repeatably from repo-owned manifests

### Evaluation

- [ ] **EVAL-01**: Team can generate a regression report comparing replay outcomes against expected detections, response decisions, investigations, and incidents
- [ ] **EVAL-02**: Local or CI verification can fail when replay expectations or configured hot-path latency thresholds regress past accepted limits

## Future Requirements

### Advanced Governance

- **GOV-01**: Runtime can support independent multi-node policy authorities when real trust boundaries exist
- **GOV-02**: Runtime can require quorum-based approval for high-impact response actions once independent fault domains are operationally justified

### Rich Operator Surfaces

- **OPS-04**: Operator can use an authenticated HTTP or TUI control surface in addition to the initial repo-owned CLI
- **OPS-05**: Operator can trigger approved maintenance operations from the control surface with explicit audit trails

### Red-Team And Evolution Labs

- **RED-01**: Team can run Hellcat-inspired adversarial scenario corpora against the offline replay harness
- **EVO-01**: Team can evaluate new detection strategies against replay corpora before any production promotion workflow is considered

## Out of Scope

| Feature | Reason |
|---------|--------|
| Distributed governance or quorum approvals | Roadmap marks governance as optional and current runtime still lacks independent trust domains |
| Live replay against production response adapters | Replay must stay offline and non-destructive in this milestone |
| Automatic policy updates from evaluation results | Humans remain authoritative for response policy and regression interpretation |
| Multi-user HTTP control plane or auth/RBAC | CLI-first keeps the operational seam narrow and avoids premature service scope |
| Python runtime resurrection or PyO3 expansion | Conflicts with the Rust-first production path |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OPS-01 | Phase 11 | Complete |
| OPS-02 | Phase 11 | Complete |
| OPS-03 | Phase 11 | Complete |
| RPLY-01 | Phase 12 | Complete |
| RPLY-02 | Phase 12 | Complete |
| RPLY-03 | Phase 12 | Complete |
| EVAL-01 | Phase 13 | Complete |
| EVAL-02 | Phase 13 | Complete |

**Coverage:**
- v1.3 requirements: 8 total
- Mapped to phases: 8
- Unmapped: 0

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 after Phase 13*
