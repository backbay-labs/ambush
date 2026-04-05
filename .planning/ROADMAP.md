# Roadmap: Swarm Team Six

## Milestones

<details>
<summary>Previous milestones (v1.0 through v1.22) -- see MILESTONES.md</summary>

Phases 1-70 shipped across milestones v1.0 through v1.22. Full history in `.planning/MILESTONES.md`.

</details>

### v1.23 Cryptographic Foundation And Guard Pipeline (In Progress)

**Milestone Goal:** Port battle-tested hush-core crypto and clawdstrike guard implementations into STS crates, wire the guard pipeline into response authorization, and establish CI quality gates.

## Phases

- [ ] **Phase 71: Cryptographic Foundation** - Port hush-core primitives into swarm-crypto replacing minimal stubs
- [ ] **Phase 72: Guard Trait And Implementations** - Build pluggable guard framework with four production guards from clawdstrike
- [ ] **Phase 73: Spine Enhancement And Runtime Integration** - Add signed envelopes and checkpoints to swarm-spine and wire guard pipeline into runtime
- [ ] **Phase 74: CI Pipeline And Quality Gates** - Establish GitHub Actions workflow and dependency governance

## Phase Details

### Phase 71: Cryptographic Foundation
**Goal**: swarm-crypto provides real cryptographic primitives from hush-core so downstream crates can sign, verify, hash, and prove inclusion without minimal stubs
**Depends on**: Nothing (first phase this milestone)
**Requirements**: CRYPTO-01, CRYPTO-02, CRYPTO-03, CRYPTO-04
**Success Criteria** (what must be TRUE):
  1. `cargo test -p swarm-crypto` passes with Ed25519 key generation, signing, and verification round-tripping correctly
  2. Canonical JSON serialization produces identical byte output for semantically equivalent JSON inputs across re-serialization
  3. Merkle tree construction from a known leaf set produces a deterministic root hash and inclusion proofs verify against it
  4. SHA-256 content hashing and hex encoding are available as public swarm-crypto APIs and match known test vectors
**Plans**: TBD

Plans:
- [ ] 71-01: TBD

### Phase 72: Guard Trait And Implementations
**Goal**: swarm-guard provides a fail-closed pluggable guard pipeline with four concrete guards covering filesystem, shell, secret, and egress safety
**Depends on**: Nothing (independent of Phase 71)
**Requirements**: GUARD-01, GUARD-02, GUARD-03, GUARD-04, GUARD-05
**Success Criteria** (what must be TRUE):
  1. Guard trait is exported from swarm-guard with evaluate semantics and a pipeline combinator that fails closed on any guard rejection
  2. ForbiddenPathGuard blocks response actions targeting sensitive filesystem paths (e.g., /etc/shadow, ~/.ssh) and passes benign paths
  3. ShellCommandGuard blocks destructive shell commands (e.g., rm -rf, mkfs) in response action arguments and passes safe commands
  4. SecretLeakGuard detects credential patterns (API keys, tokens, passwords) in response action arguments and blocks the action
  5. EgressAllowlistGuard blocks network destinations not on the configured allowlist and passes allowed destinations
**Plans**: TBD

Plans:
- [ ] 72-01: TBD

### Phase 73: Spine Enhancement And Runtime Integration
**Goal**: swarm-spine can construct and verify signed envelopes and checkpoint statements using swarm-crypto, and the guard pipeline gates response actions in the runtime before execution
**Depends on**: Phase 71 (crypto primitives for signing), Phase 72 (guard trait and implementations for runtime wiring)
**Requirements**: SPINE-01, SPINE-02, GUARD-06
**Success Criteria** (what must be TRUE):
  1. swarm-spine can construct a signed envelope over an arbitrary payload using swarm-crypto Ed25519 keys and a separate caller can verify the envelope signature
  2. swarm-spine can create a checkpoint statement and verify a witness co-signature against it
  3. Response actions in swarm-runtime pass through the guard pipeline before execution, and a guard rejection prevents the response adapter from firing
  4. A response action that would have executed under the old path is now blocked when a guard rejects it, with the rejection reason preserved in the audit record
**Plans**: TBD

Plans:
- [ ] 73-01: TBD

### Phase 74: CI Pipeline And Quality Gates
**Goal**: Every push and pull request is automatically checked for formatting, lint, build, and test correctness, and dependency governance prevents unapproved licenses or known vulnerabilities
**Depends on**: Phase 71, Phase 72, Phase 73 (CI validates the full workspace)
**Requirements**: CI-01, CI-02
**Success Criteria** (what must be TRUE):
  1. A GitHub Actions workflow runs cargo fmt --check, clippy, build, and test on every push and pull request to main
  2. deny.toml exists in the workspace root with a license allowlist and advisory-db vulnerability checks configured
  3. `cargo deny check` passes against the current workspace dependency tree
**Plans**: TBD

Plans:
- [ ] 74-01: TBD

## Progress

**Execution Order:** 71 -> 72 -> 73 -> 74
(Phases 71 and 72 have no mutual dependency and could execute in parallel.)

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 71. Cryptographic Foundation | v1.23 | 0/? | Not started | - |
| 72. Guard Trait And Implementations | v1.23 | 0/? | Not started | - |
| 73. Spine Enhancement And Runtime Integration | v1.23 | 0/? | Not started | - |
| 74. CI Pipeline And Quality Gates | v1.23 | 0/? | Not started | - |

---
*Roadmap created: 2026-04-04 for milestone v1.23*
