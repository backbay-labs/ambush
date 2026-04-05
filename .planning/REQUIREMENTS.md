# Requirements: Swarm Team Six

**Defined:** 2026-04-05
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.28 Requirements

### Durable Substrate

- [ ] **SUB-01**: NATS JetStream pheromone substrate backend persists deposits across restarts

### Multi-Instance Coordination

- [ ] **SUB-02**: Multiple swarm-detect instances contribute deposits to shared substrate with correct concentration aggregation
- [ ] **SUB-03**: min_sources_for_escalation enforcement works correctly across multiple instances

### Legacy Cleanup

- [ ] **CLEAN-01**: swarm-bridge (dead PyO3 shim) and kernel/ Python stubs are removed or archived

## Out of Scope

| Feature | Reason |
|---------|--------|
| Distributed consensus or BFT | Multi-instance substrate sharing is not consensus; BFT remains deferred |
| Automatic fleet scaling | Manual multi-instance deployment; orchestration is future work |
| Cross-instance response coordination | Each instance responds independently; coordinated response is future |
| NATS cluster HA configuration | Single NATS instance sufficient for v1.28; HA is operational concern |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SUB-01 | Phase 86 | Pending |
| SUB-02 | Phase 87 | Pending |
| SUB-03 | Phase 87 | Pending |
| CLEAN-01 | Phase 87 | Pending |

**Coverage:**
- v1.28 requirements: 4 total
- Mapped to phases: 4
- Unmapped: 0

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-04-05 after v1.28 roadmap creation*
