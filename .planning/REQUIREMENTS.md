# Requirements: Swarm Team Six

**Defined:** 2026-04-04
**Core Value:** Detect real threats quickly enough to take safe action before the window to respond closes.

## v1.23 Requirements

### Cryptographic Foundation

- [ ] **CRYPTO-01**: swarm-crypto provides Ed25519 key generation, signing, and verification using hush-core primitives replacing the minimal existing implementation
- [ ] **CRYPTO-02**: swarm-crypto provides RFC 8785 canonical JSON serialization for deterministic cross-platform signing
- [ ] **CRYPTO-03**: swarm-crypto provides RFC 6962 Merkle tree construction and inclusion proof verification
- [ ] **CRYPTO-04**: swarm-crypto provides SHA-256 content hashing and hex utilities

### Guard Pipeline

- [ ] **GUARD-01**: swarm-guard exports a Guard trait with pluggable evaluation semantics and fail-closed pipeline composition
- [ ] **GUARD-02**: swarm-guard includes a ForbiddenPathGuard preventing response actions from accessing sensitive filesystem paths
- [ ] **GUARD-03**: swarm-guard includes a ShellCommandGuard blocking destructive commands in response execution
- [ ] **GUARD-04**: swarm-guard includes a SecretLeakGuard detecting credentials in response action arguments
- [ ] **GUARD-05**: swarm-guard includes an EgressAllowlistGuard controlling network destinations for response adapters
- [ ] **GUARD-06**: Guard pipeline is wired into swarm-runtime response authorization path so response actions pass through guards before execution

### Spine Enhancement

- [ ] **SPINE-01**: swarm-spine provides signed envelope construction and verification using swarm-crypto primitives
- [ ] **SPINE-02**: swarm-spine provides checkpoint statement creation and witness co-signature verification

### Quality Infrastructure

- [ ] **CI-01**: GitHub Actions workflow enforces cargo fmt, clippy, build, and test on pushes and pull requests
- [ ] **CI-02**: Workspace includes deny.toml for dependency license allowlist and security vulnerability scanning

## Future Requirements

### Approval Ledger Readiness (v1.24)

- **GOV-03**: Operator can define an approval set with eligible voters, threshold rules, and supporting promotion evidence without executing distributed consensus
- **GOV-04**: Signed approval ledgers preserve vote lineage, missing quorum state, and related promotion evidence refs for later independent verification
- **GOV-01**: Strategy promotion to production requires quorum-based approval once independent trust boundaries exist

### Receipt And Human Gate Prep (v1.24)

- **GOV-05**: Operator can assemble a local approval verdict from signed approval-ledger entries and threshold rules without contacting distributed voters
- **GOV-06**: Operator can export a signed approval receipt pack with approval lineage, final verdict, and audit references for later independent verification
- **GOV-07**: Critical-severity promotion candidates can remain in an explicit human-approval-pending state with review packets and durable audit history
- **GOV-02**: Promotion records include signed votes and durable consensus receipts

### Operational Hardening (v1.25)

- **OPS-26**: Detection hot path runs as a standalone binary separate from the operator workbench
- **OPS-27**: Rulesets and scenarios are wired into detection config rather than only the workbench CLI
- **OPS-28**: Critical path emits structured Prometheus metrics for detection latency, policy evaluation time, and response execution time
- **OPS-29**: Integration tests cover the full critical path from telemetry to verified receipt
- **OPS-30**: Workspace enforces clippy unwrap_used and expect_used denial across all crates

## Out of Scope

| Feature | Reason |
|---------|--------|
| Spider Sense cosine-similarity detector | Valuable but depends on embedding infrastructure not yet available; defer to future guard expansion |
| WASM guard plugin SDK | ClawdStrike has this but swarm-guard should start with compiled-in guards |
| Async guards requiring network access | Start with sync guards; async guard trait can be added later |
| swarm-consensus implementation | No upstream BFT source; remains deferred until governance milestones need it |
| SIEM export from arc | Useful but not blocking; defer to operational hardening or later |
| Full hush-core receipt types | swarm-spine already has receipt types; only envelope and checkpoint are needed now |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CRYPTO-01 | — | Pending |
| CRYPTO-02 | — | Pending |
| CRYPTO-03 | — | Pending |
| CRYPTO-04 | — | Pending |
| GUARD-01 | — | Pending |
| GUARD-02 | — | Pending |
| GUARD-03 | — | Pending |
| GUARD-04 | — | Pending |
| GUARD-05 | — | Pending |
| GUARD-06 | — | Pending |
| SPINE-01 | — | Pending |
| SPINE-02 | — | Pending |
| CI-01 | — | Pending |
| CI-02 | — | Pending |

**Coverage:**
- v1.23 requirements: 14 total
- Mapped to phases: 0
- Unmapped: 14

---
*Requirements defined: 2026-04-04*
*Last updated: 2026-04-04 after milestone v1.23 definition*
