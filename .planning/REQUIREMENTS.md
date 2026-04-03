# Requirements: Swarm Team Six

**Defined:** 2026-04-02
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1 Requirements

### Configuration

- [x] **CFG-01**: Operator can load runtime and ruleset configuration from repository-owned config files
- [x] **CFG-02**: Runtime rejects malformed or unknown configuration fields at load time
- [x] **CFG-03**: Operator can enable `detect_only` or `live_response` mode explicitly

### Detection

- [x] **DET-01**: Runtime accepts a normalized telemetry event in Rust without crossing a Python boundary
- [x] **DET-02**: Runtime evaluates at least one concrete detector against incoming telemetry
- [x] **DET-03**: Detector emits a structured finding with threat class, severity, confidence, and evidence
- [x] **DET-04**: Team can publish p50, p95, p99, and throughput numbers for the detector path

### Substrate

- [x] **SUB-01**: Runtime can deposit findings into an in-memory pheromone substrate
- [x] **SUB-02**: Runtime can query concentration with decay and source-diversity semantics
- [x] **SUB-03**: Runtime can reconstruct recent deposits for replay or debugging

### Policy

- [ ] **POL-01**: Runtime evaluates response proposals through a deterministic Rust policy gate
- [ ] **POL-02**: Policy gate can deny, authorize, or require human approval based on action type and severity
- [ ] **POL-03**: Authorized requests receive a short-lived capability lease with explicit scope

### Response

- [ ] **RSP-01**: Runtime supports dry-run response execution for safe validation
- [ ] **RSP-02**: Runtime supports at least one sandboxed enforced response adapter
- [ ] **RSP-03**: Response execution returns a normalized receipt or failure record

### Audit And Operations

- [ ] **AUD-01**: Runtime records a receipt trail for detection, policy, and response decisions
- [ ] **AUD-02**: Team can replay an end-to-end detect -> authorize -> execute flow from saved artifacts
- [ ] **OPS-01**: Runtime exports structured traces or logs for the critical path
- [ ] **OPS-02**: Integration tests cover detect -> substrate -> policy -> response -> receipt

## v2 Requirements

### Investigation And Correlation

- **INV-01**: Runtime can attach slower investigation context to findings without blocking the hot path
- **INV-02**: Runtime can correlate multiple findings into a higher-confidence incident narrative

### Durability

- **DUR-01**: Pheromone substrate can persist to JetStream without changing the public contract
- **DUR-02**: Receipt and replay artifacts survive restart and are queryable by hunt or receipt ID

### Advanced Governance

- **GOV-01**: Runtime can support independent multi-node policy authorities
- **GOV-02**: Runtime can reintroduce consensus only if independent fault domains are operationally required

## Out of Scope

| Feature | Reason |
|---------|--------|
| Python-first orchestration runtime | Conflicts with the Rust-only fast-detection and live-response direction |
| PyO3 as a required production seam | Adds avoidable complexity before contracts are stable |
| BFT / VRF governance in v1 | Not required to prove the first trusted single-node slice |
| Gossip mesh membership | Premature without a concrete multi-node deployment problem |
| Live co-evolution engine | Research-heavy and not needed for the first product milestone |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CFG-01 | Phase 1 | Complete |
| CFG-02 | Phase 1 | Complete |
| CFG-03 | Phase 1 | Complete |
| DET-01 | Phase 2 | Complete |
| DET-02 | Phase 2 | Complete |
| DET-03 | Phase 2 | Complete |
| DET-04 | Phase 2 | Complete |
| SUB-01 | Phase 2 | Complete |
| SUB-02 | Phase 2 | Complete |
| SUB-03 | Phase 2 | Complete |
| POL-01 | Phase 3 | Pending |
| POL-02 | Phase 3 | Pending |
| POL-03 | Phase 3 | Pending |
| RSP-01 | Phase 3 | Pending |
| RSP-02 | Phase 3 | Pending |
| RSP-03 | Phase 3 | Pending |
| AUD-01 | Phase 4 | Pending |
| AUD-02 | Phase 4 | Pending |
| OPS-01 | Phase 4 | Pending |
| OPS-02 | Phase 4 | Pending |

**Coverage:**
- v1 requirements: 20 total
- Mapped to phases: 20
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-02*
*Last updated: 2026-04-02 after initialization*
