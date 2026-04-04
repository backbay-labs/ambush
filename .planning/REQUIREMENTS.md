# Requirements: Swarm Team Six

**Defined:** 2026-04-03
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.13 Requirements

### Structured Mutation

- [ ] **EVOL-10**: Operator can derive a structured mutation spec from a reviewed draft or materialized candidate through `swarmctl` without hand-editing multiple manifests
- [ ] **EVOL-11**: Mutation specs preserve parent candidate references, intended mutation dimensions, and operator rationale in one durable artifact

### Batch Candidate Generation

- [ ] **EVOL-12**: Team can materialize a batch of candidate variants from one mutation spec through a repo-owned CLI flow
- [ ] **EVOL-13**: Batch candidate generation preserves stable per-candidate links back to the source mutation spec and parent draft lineage

### Batch Validation And Ranking

- [ ] **EVOL-14**: Team can refresh validation bundles for multiple materialized candidates in one batch without overwriting per-candidate evidence artifacts
- [ ] **EVOL-15**: Operator can rank or shortlist validated candidates for later review using deterministic criteria derived from validation and advisory evidence
- [ ] **EVOL-16**: Ranking packets preserve references to each candidate's materialization, validation bundle, and reviewed queue state so later review does not require rewriting evidence artifacts

## Future Requirements

### Governance

- **GOV-01**: Strategy promotion to production requires quorum-based approval once independent trust boundaries exist
- **GOV-02**: Promotion records include signed votes and durable consensus receipts

### Rich Operator Surfaces

- **OPS-04**: Operator can use an authenticated HTTP or TUI control surface in addition to the initial repo-owned CLI
- **OPS-05**: Operator can trigger approved maintenance operations from the control surface with explicit audit trails

### Advanced Evolution

- **EVOL-08**: Queue-approved detector proposals can feed a later governance-backed rollout path without manual artifact translation
- **EVOL-17**: Ranked candidate batches can be promoted into later governance or fleet rollout review without re-materializing evidence

## Out of Scope

| Feature | Reason |
|---------|--------|
| Autonomous mutation from pressure signals | `v1.13` turns operator hints into structured mutation specs only; it does not let the runtime invent new mutations by itself |
| Automatic queue promotion for ranked candidates | Ranking remains advisory and operator-reviewed |
| Automatic canary or production launch from ranked batches | Existing rollout gates remain explicit and separate from offline candidate ranking |
| Quorum or BFT approval for ranked candidates | Independent trust boundaries still do not exist, and governance remains explicitly deferred |
| Multi-node or partial-fleet rollout | The runtime is still single-node and self-contained; this cycle focuses on offline candidate comparison |
| Authenticated HTTP or TUI control plane | CLI-first remains the smallest practical operator surface for the current runtime |
| Hot-path mutation or ranking | Fast detection remains the core value, so batch mutation and ranking stay off the critical lane |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| EVOL-10 | Phase 41 | Pending |
| EVOL-11 | Phase 41 | Pending |
| EVOL-12 | Phase 42 | Pending |
| EVOL-13 | Phase 42 | Pending |
| EVOL-14 | Phase 42 | Pending |
| EVOL-15 | Phase 43 | Pending |
| EVOL-16 | Phase 43 | Pending |

**Coverage:**
- v1.13 requirements: 7 total
- Mapped to phases: 7
- Unmapped: 0

---
*Requirements defined: 2026-04-03*
*Last updated: 2026-04-03 after milestone v1.13 requirements definition*
