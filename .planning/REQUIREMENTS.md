# Requirements: Swarm Team Six

**Defined:** 2026-04-04
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.20 Requirements

### Review Sessions

- [ ] **OPS-15**: Operator can assemble a multi-artifact review session from evidence bundle, verification, and promotion packet IDs and reload it by stable session ID

### Comparison And Export

- [ ] **OPS-14**: Operator can compare multiple evidence artifacts in one local review session
- [ ] **OPS-16**: Operator can export a selected evidence session with preserved digests, signer metadata, verification state, and related stable refs

### Review-Driven Actions

- [ ] **OPS-13**: Operator can trigger bounded maintenance actions from the review client while preserving the existing authenticated audit trail
- [ ] **OPS-17**: Review-driven maintenance requests preserve source review-session IDs, selected artifact refs, operator rationale, and resulting action IDs
- [ ] **OPS-18**: Review-driven actions remain bounded to the existing maintenance scope and cannot bypass rollout or governance gates

## Future Requirements

### Governance

- **GOV-01**: Strategy promotion to production requires quorum-based approval once independent trust boundaries exist
- **GOV-02**: Promotion records include signed votes and durable consensus receipts

### Operator Surfaces

- **OPS-19**: Operator can compare governance-prep, canary, and production evidence lanes in one cross-lane review session
- **OPS-20**: Operator can share or delegate signed review sessions across independent trust boundaries once multi-user governance exists

## Out of Scope

| Feature | Reason |
|---------|--------|
| Actual quorum voting or distributed consensus for promotion | Independent trust boundaries still do not exist, and governance remains explicitly deferred |
| Multi-user RBAC or federated operator workflows | The runtime still operates as a local single-node control surface |
| Internet-exposed evidence or operator service | This cycle keeps the review surface local-only and loopback-oriented |
| Direct rollout, promotion, or governance actions from the review client | Browser-triggered writes must stay bounded to the existing maintenance scope and durable audit trail |
| Fleet-wide or partial-fleet promotion approvals | The rollout path remains bounded to one single-node production lane |
| Replacing the authenticated JSON API with a separate UI-only protocol | The review client should layer above the existing operator surface instead of forking it |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OPS-15 | Phase 62 | Pending |
| OPS-14 | Phase 63 | Pending |
| OPS-16 | Phase 63 | Pending |
| OPS-13 | Phase 64 | Pending |
| OPS-17 | Phase 64 | Pending |
| OPS-18 | Phase 64 | Pending |

**Coverage:**
- v1.20 requirements: 6 total
- Mapped to phases: 6
- Unmapped: 0

---
*Requirements defined: 2026-04-04*
*Last updated: 2026-04-04 for milestone v1.20 planning*
