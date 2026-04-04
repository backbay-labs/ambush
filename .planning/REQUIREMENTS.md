# Requirements: Swarm Team Six

**Defined:** 2026-04-04
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.17 Requirements

### Authenticated Control Surface

- [ ] **OPS-04**: Operator can use an authenticated HTTP control surface in addition to the initial repo-owned CLI
- [ ] **OPS-06**: Operator can retrieve runtime status, stable-ID artifact views, and portfolio or governance-prep summaries through authenticated endpoints without reading raw storage files

### Maintenance Operations

- [ ] **OPS-05**: Operator can trigger approved maintenance operations from the control surface with explicit audit trails
- [ ] **OPS-07**: Maintenance action records preserve actor identity, reason, target, and final result in durable audit artifacts that can be reloaded by stable ID

## Future Requirements

### Governance

- **GOV-01**: Strategy promotion to production requires quorum-based approval once independent trust boundaries exist
- **GOV-02**: Promotion records include signed votes and durable consensus receipts

## Out of Scope

| Feature | Reason |
|---------|--------|
| Actual quorum voting or distributed consensus for promotion | Independent trust boundaries still do not exist, and governance remains explicitly deferred |
| Multi-user RBAC or federated operator workflows | The next control surface stays local and single-node |
| Internet-exposed operator service | This cycle introduces a narrow authenticated local surface, not a remotely exposed control plane |
| Terminal UI implementation | HTTP is the smaller next step because the runtime already emits serializable reports and artifact views |
| Fleet-wide rollout control | The runtime still supports only a bounded single-node promotion path |
| Automatic maintenance actions or unattended control-plane workflows | Control-plane actions remain explicit, bounded, and operator-triggered |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| OPS-04 | Phase 53 | Planned |
| OPS-06 | Phase 54 | Planned |
| OPS-05 | Phase 55 | Planned |
| OPS-07 | Phase 55 | Planned |

**Coverage:**
- v1.17 requirements: 4 total
- Mapped to phases: 4
- Unmapped: 0

---
*Requirements defined: 2026-04-04*
*Last updated: 2026-04-04 for milestone v1.17 planning*
