# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.1 Requirements

### Configuration

- [ ] **CFG-04**: Operator can configure durable substrate and receipt storage backends through repository-owned config files without code changes

### Durability

- [ ] **DUR-01**: Operator can switch the pheromone substrate between in-memory and JetStream-backed implementations without changing detector or policy contracts
- [ ] **DUR-02**: Operator can recover recent pheromone state after restart when durable mode is enabled
- [ ] **DUR-03**: Operator can query persisted deposits by threat class and recency window for operational inspection
- [ ] **DUR-04**: Operator can require durable substrate readiness before the runtime accepts `live_response`

### Audit And Replay

- [ ] **AUD-03**: Operator can persist receipt and replay bundles outside process memory
- [ ] **AUD-04**: Operator can retrieve a replay bundle by hunt ID or receipt ID after restart
- [ ] **AUD-05**: Operator can replay a persisted decision flow without re-executing the live response action

### Operations

- [ ] **OPS-03**: Operator can inspect runtime mode and component readiness for detector, substrate, policy, and response services from one status surface
- [ ] **OPS-04**: Operator can inspect counters and latency metrics for detect, policy, persist, and response stages
- [ ] **OPS-05**: Operator can correlate a runtime trace, receipt trail, and replay bundle using stable identifiers

## Future Requirements

### Investigation And Correlation

- **INV-01**: Runtime can attach slower investigation context to findings without blocking the hot path
- **INV-02**: Runtime can correlate multiple findings into a higher-confidence incident narrative

### Advanced Governance

- **GOV-01**: Runtime can support independent multi-node policy authorities
- **GOV-02**: Runtime can reintroduce consensus only if independent fault domains are operationally required

### Evaluation And Replay Labs

- **EVA-01**: Team can run offline replay and adversarial evaluation workflows against durable runtime artifacts
- **EVA-02**: Team can experiment with detector evolution without coupling it to the live response runtime

## Out of Scope

| Feature | Reason |
|---------|--------|
| Async investigation on the hot path | Would destabilize the just-shipped critical lane before durability is proven |
| Distributed governance / quorum approvals | Still premature without independent nodes and trust boundaries |
| Gossip membership / CRDT state sharing | Not required for the current single-node operational milestone |
| Python runtime or PyO3 expansion | Conflicts with the Rust-first production path |
| Live evolution loops | Better handled as offline evaluation after durable artifacts exist |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CFG-04 | Phase 5 | Pending |
| DUR-01 | Phase 5 | Pending |
| DUR-02 | Phase 5 | Pending |
| DUR-03 | Phase 5 | Pending |
| DUR-04 | Phase 5 | Pending |
| AUD-03 | Phase 6 | Pending |
| AUD-04 | Phase 6 | Pending |
| AUD-05 | Phase 6 | Pending |
| OPS-03 | Phase 7 | Pending |
| OPS-04 | Phase 7 | Pending |
| OPS-05 | Phase 7 | Pending |

**Coverage:**
- v1.1 requirements: 11 total
- Mapped to phases: 11
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.1 definition*
