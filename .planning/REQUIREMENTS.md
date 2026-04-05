# Requirements: Swarm Team Six

**Defined:** 2026-04-05
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.24 Requirements

### Approval Ledger Readiness

- [ ] **GOV-03**: Operator can define an approval set with eligible voters, threshold rules, and supporting promotion evidence without executing distributed consensus
- [ ] **GOV-04**: Signed approval ledgers preserve vote lineage, missing quorum state, and related promotion evidence refs for later independent verification
- [ ] **GOV-01**: Strategy promotion to production requires quorum-based approval once independent trust boundaries exist

### Receipt And Human Gate Prep

- [ ] **GOV-05**: Operator can assemble a local approval verdict from signed approval-ledger entries and threshold rules without contacting distributed voters
- [ ] **GOV-06**: Operator can export a signed approval receipt pack with approval lineage, final verdict, and audit references for later independent verification
- [ ] **GOV-07**: Critical-severity promotion candidates can remain in an explicit human-approval-pending state with review packets and durable audit history
- [ ] **GOV-02**: Promotion records include signed votes and durable consensus receipts

## Future Requirements

### Operational Hardening (v1.25)

- **OPS-26**: Detection hot path runs as a standalone binary separate from the operator workbench
- **OPS-27**: Rulesets and scenarios are wired into detection config rather than only the workbench CLI
- **OPS-28**: Critical path emits structured Prometheus metrics for detection latency, policy evaluation time, and response execution time
- **OPS-29**: Integration tests cover the full critical path from telemetry to verified receipt
- **OPS-30**: Workspace enforces clippy unwrap_used and expect_used denial across all crates

## Out of Scope

| Feature | Reason |
|---------|--------|
| Distributed consensus or multi-node voting | Independent trust boundaries do not yet exist; all approval logic is local and single-node |
| Multi-user RBAC or federated operator workflows | The runtime still operates as a local single-node control surface |
| Internet-exposed approval or governance service | Approval ledgers and receipt packs are local artifacts, not network services |
| Automatic promotion from approval verdicts | Approval remains advisory; promotion still requires explicit operator action through existing rollout gates |
| Fleet-wide or partial-fleet promotion approvals | The rollout path remains bounded to one single-node production lane |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| GOV-03 | — | Pending |
| GOV-04 | — | Pending |
| GOV-01 | — | Pending |
| GOV-05 | — | Pending |
| GOV-06 | — | Pending |
| GOV-07 | — | Pending |
| GOV-02 | — | Pending |

**Coverage:**
- v1.24 requirements: 7 total
- Mapped to phases: 0
- Unmapped: 7

---
*Requirements defined: 2026-04-05*
*Last updated: 2026-04-05 after milestone v1.24 definition*
