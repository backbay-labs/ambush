# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.2 Requirements

### Async Investigation

- [ ] **INV-01**: Operator can enable automatic post-decision investigation for selected findings without delaying the original detect or response path
- [ ] **INV-02**: Operator can configure investigation workers, concurrency limits, and time budgets separately from the live-response hot path
- [ ] **INV-03**: Operator can retrieve a persisted investigation bundle linked to the originating hunt ID and receipt trail

### Correlation

- [ ] **COR-01**: Operator can group related findings and investigation bundles into one incident narrative using stable identifiers, time windows, and shared evidence
- [ ] **COR-02**: Operator can inspect which findings and evidence caused a correlation decision and which inputs were rejected

### Operator Review

- [ ] **REV-01**: Operator can view investigation status, summary, and failure state from one runtime surface without reading raw storage files
- [ ] **REV-02**: Operator can distinguish hot-path response decisions from later async enrichment and see freshness timestamps for both layers

## Future Requirements

### Advanced Governance

- **GOV-01**: Runtime can support independent multi-node policy authorities
- **GOV-02**: Runtime can reintroduce consensus only if independent fault domains are operationally required

### Evaluation And Replay Labs

- **EVA-01**: Team can run offline replay and adversarial evaluation workflows against durable runtime artifacts
- **EVA-02**: Team can experiment with detector evolution without coupling it to the live response runtime

### Deferred Investigation Follow-Ons

- **COR-03**: Runtime can let correlated incidents influence later automated policy only after operator review and explicit safeguards
- **REV-03**: Operator can manage investigation and incident review through a richer CLI or HTTP control surface

## Out of Scope

| Feature | Reason |
|---------|--------|
| Async investigation on the hot path | Enrichment must not weaken the fast-detection latency proof point |
| Correlation directly changing automated response policy | Incident grouping should stay operator-context-first in this milestone |
| Distributed governance / quorum approvals | Still premature without independent nodes and trust boundaries |
| Gossip membership / CRDT state sharing | Not required for the current single-node operating model |
| Python runtime or PyO3 expansion | Conflicts with the Rust-first production path |
| Live evolution loops | Better handled as offline evaluation after durable artifacts exist |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| INV-01 | TBD | Planned |
| INV-02 | TBD | Planned |
| INV-03 | TBD | Planned |
| COR-01 | TBD | Planned |
| COR-02 | TBD | Planned |
| REV-01 | TBD | Planned |
| REV-02 | TBD | Planned |

**Coverage:**
- v1.2 requirements: 7 total
- Mapped to phases: 0
- Unmapped: 7
- Future requirements: 6

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 for milestone v1.2 definition*
