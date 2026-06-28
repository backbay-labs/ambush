# Gap Report: Doc 07 Self-Protection and Swarm-Hardening Series Coherence

| Field       | Value                                    |
|-------------|------------------------------------------|
| Date        | 2026-04-08                               |
| Scope       | swarm-hardening/07 gap analysis + cross-series coherence with sentinel-convergence |
| Reviewed by | Security architecture gap analysis       |
| Status      | Initial findings                         |

---

## Preamble

The `swarm-hardening` research series does not yet contain any documents. The
directory `docs/research/swarm-hardening/` exists but is empty. No `00-OVERVIEW.md`
through `07-SECURE-UPDATE-AND-SELF-PROTECTION.md` have been written. This report
therefore serves a dual purpose:

1. **Part A** identifies what a Doc 07 (Secure Update and Self-Protection) must
   address, grounded in the actual codebase and existing tooling.
2. **Part B** analyzes coherence between the *planned* swarm-hardening series and
   the existing sentinel-convergence series (14 documents, all in draft).

All findings reference concrete code paths, config files, and CI artifacts in
the current repo state (branch `rescue/v1.39-snapshot`).

---

## Part A: Doc 07 Self-Protection -- Required Coverage

### A1. Supply Chain of Dependencies

**Current state:** The repo has a well-configured `deny.toml` at the workspace
root. It pins the advisory DB to RustSec, restricts licenses to a sensible
allowlist (MIT, Apache-2.0, BSD-3-Clause, etc.), warns on multiple versions and
unknown registries, and limits allowed registries to `crates.io`. CI
(`.github/workflows/ci.yml`) runs `cargo deny check` on every PR.

**Gaps:**

- **No `cargo-audit` in CI.** `cargo deny check` covers license and ban checks
  and can check advisories, but the `[advisories]` section has an empty `ignore`
  list and no `vulnerability = "deny"` directive -- meaning advisory violations
  produce warnings, not failures. Doc 07 must specify whether advisory matches
  should be hard-blocking or warning-only, and justify the decision.
- **No dependency pinning policy.** `Cargo.lock` is committed (good), but
  there is no documented policy on when lockfile updates are permitted, who
  reviews them, or whether `cargo update` runs are gated behind audit.
- **`deny.toml` `[bans]` is permissive.** `wildcards = "allow"` and
  `multiple-versions = "warn"` are weak defaults for a security product. A
  hardened stance would deny wildcard version specs and at minimum track which
  crates are duplicated.
- **No SBOM generation.** For compliance (SOC 2, FedRAMP) a Software Bill of
  Materials is increasingly required. No `cargo-cyclonedx` or equivalent is
  configured.

**Recommendation:** Doc 07 should include a "Dependency Integrity" section that
references `deny.toml`, tightens the advisory policy to `vulnerability = "deny"`,
adds `cargo-audit` as a CI step, documents the lockfile update policy, and
evaluates SBOM generation.

### A2. Runtime Memory Protection

**Current state:** The codebase is overwhelmingly safe Rust. `unsafe` blocks
exist in only three locations:

- `crates/swarm-ingest-tetragon/build.rs` (protobuf codegen boundary)
- `crates/swarm-runtime/src/config.rs` (two test-only `unsafe` blocks)
- `crates/swarm-runtime/src/ingest.rs` (one test-only `unsafe` block)

All production-path `unsafe` usage is confined to the Tetragon protobuf build
script. The guard pipeline (`swarm-guard`) uses `catch_unwind` to fail closed
on panics, which is a strong defensive measure.

**Gaps:**

- **No documented `unsafe` audit policy.** The three `unsafe` blocks are not
  annotated with `// SAFETY:` comments explaining why they are sound. Clippy's
  `undocumented_unsafe_blocks` lint is not enabled.
- **No compile-time hardening flags.** The project does not configure
  `RUSTFLAGS` for stack canaries (`-C overflow-checks=yes` is default in debug
  but should be verified for release), ASLR (OS-level, but PIE should be
  confirmed), or CFI (`-Zsanitizer=cfi` is nightly-only but should be tracked).
- **No discussion of allocator hardening.** For a security-critical binary,
  using `mimalloc` or `jemalloc` with hardened configurations (guard pages,
  canary values) vs the system allocator is a meaningful decision.
- **Panic behavior in release mode.** The CLAUDE.md specifies `-D warnings` for
  clippy, but whether release builds use `panic = "abort"` vs `panic = "unwind"`
  is security-relevant (abort prevents stack unwinding exploitation).

**Recommendation:** Doc 07 should include a "Process Hardening" section covering
unsafe block audit policy, release profile compiler flags, allocator choice, and
panic strategy. Cross-reference the v1.41 HARD-01 requirement which already
addresses panic-free critical paths.

### A3. Network-Level Self-Protection

**Current state:** The operator HTTP surface (`crates/swarm-runtime/src/http/`)
uses bearer token authentication via the `require_bearer_auth` middleware. The
token is read from an environment variable configured in `operator_surface.auth.token_env`.
Planned requirement HARD-03b (v1.41) specifies optional TLS via `tokio-rustls`
with optional mTLS when `tls.client_ca_cert` is set. The `reqwest` dependency
uses `rustls-tls`.

**Gaps:**

- **No rate limiting on the operator HTTP surface.** Policy rate limiting exists
  for response actions (`scope_rate_limit_decision` in `static_gate.rs`,
  notification rate limits), but the HTTP API itself has no request rate limiting.
  An attacker who obtains the bearer token could flood the API.
- **No token rotation mechanism.** The bearer token is a static env var. There
  is no documented token rotation story, no token expiry, and no support for
  multiple valid tokens during rotation windows.
- **mTLS is planned but not analyzed.** HARD-03b is a requirement, not a
  research document. Doc 07 should analyze the threat model for the operator
  surface: who connects, from where, what trust boundaries exist, and why mTLS
  is the right (or insufficient) control.
- **No CORS/CSP analysis.** The operator surface serves HTML (review workbench).
  Browser-facing surfaces need CORS and CSP headers to prevent XSS and CSRF.
- **Health endpoints are unauthenticated.** `/healthz`, `/readyz`, `/livez`,
  `/metrics` are exposed without auth (necessary for K8s probes). Doc 07 should
  analyze what information leaks these endpoints permit and whether a separate
  listen address is warranted.

**Recommendation:** Doc 07 should include an "API Surface Hardening" section
covering rate limiting, token lifecycle, mTLS threat model, browser security
headers, and health endpoint exposure analysis.

### A4. Secrets at Rest

**Current state:** The project supports `@secret:env:VARIABLE_NAME` and
`@secret:file-name` (resolved from `runtime.secret_dir`). Phase 118 shipped
independent file-watch for hot secret rotation. Secret resolution happens in
`crates/swarm-runtime/src/config.rs`. The `SecretLeakGuard` in `swarm-guard`
detects credential patterns in outbound content.

**Gaps:**

- **No encryption at rest for secret files.** `@secret:file-name` reads
  plaintext files from `secret_dir`. In a Kubernetes deployment (HELM-01a),
  these map to K8s Secrets which are base64-encoded, not encrypted, unless the
  cluster has encryption-at-rest configured. Doc 07 should analyze the threat of
  secret exposure on disk.
- **No secret zeroization.** After resolving a `@secret:` reference, the
  plaintext token lives in heap memory as a `String`. There is no use of
  `zeroize` or `secrecy` crates to ensure secrets are wiped from memory after
  use.
- **No secret access logging.** When a secret is resolved, there is no audit
  trail of which secret was accessed, by which component, at what time.
- **Hardcoded test secrets.** Test code in `swarm-response` uses literals like
  `"secret"`, `"splunk-secret"`, `"notify-secret"`. While these are test-only,
  they set a pattern. Doc 07 should note the boundary between test fixtures and
  production secret handling.

**Recommendation:** Doc 07 should include a "Secrets Lifecycle" section covering
encryption at rest, in-memory zeroization, access auditing, and the Kubernetes
Secrets integration story.

### A5. Multi-Instance Trust

**Current state:** The runtime is single-instance. The sentinel-convergence
series (Doc 01, 04, 06) extensively designs multi-agent consensus, partition
tolerance, and distributed coordination, but all of this is Phase 6+ and not
implemented. The current pheromone substrate supports an in-memory backend and a
NATS JetStream backend.

**Gaps:**

- **No instance-to-instance authentication.** If multiple swarm instances share
  a JetStream backend, there is no mechanism for one instance to verify that
  pheromone deposits came from a legitimate peer. The `signed_by` field on
  deposits exists but there is no trust root or key distribution story for
  multi-instance deployments.
- **No anti-replay between instances.** Sequence numbers are per-issuer within
  the spine envelope chain, but there is no global ordering or deduplication
  across instances sharing a substrate.
- **Sentinel-convergence Doc 01 proposes Ed25519 identity + mTLS for Sybil
  resistance**, but the swarm-hardening series needs to specify how this maps
  to the single-node-first path. What is the minimum viable multi-instance
  trust story before full BFT consensus?

**Recommendation:** Doc 07 should include a "Multi-Instance Trust Bootstrap"
section that specifies the minimum key distribution and mutual authentication
requirements for the JetStream shared-substrate case, deferring full BFT to
the sentinel-convergence governance track.

### A6. Backup and Recovery

**Current state:** A disaster recovery runbook exists (`docs/DR-RUNBOOK.md`)
covering four specific failure modes: JetStream connection loss, dead-letter
disk full, circuit breaker stuck open, and policy denial. The audit trail uses
in-memory or file-backed stores. The pheromone substrate can use in-memory or
JetStream backends.

**Gaps:**

- **No audit trail backup strategy.** The `audit.bundle_store` defaults to
  `memory`. File-backed stores are not documented for backup/rotation. If the
  process restarts with an in-memory store, all audit history is lost.
- **No pheromone state snapshot/restore.** The in-memory pheromone backend has
  no durability. JetStream provides some durability but there is no documented
  backup or point-in-time recovery procedure for pheromone state.
- **No configuration version control beyond git.** Runtime config changes
  (hot-reloaded `@secret:` files, potential future API-driven config) have no
  change history outside of git commits.
- **DR runbook does not cover corruption.** The four scenarios in
  `docs/DR-RUNBOOK.md` address availability failures. There is no procedure for
  detecting or recovering from data corruption in the audit chain, pheromone
  substrate, or dead-letter journal.
- **No RTO/RPO targets.** The DR runbook has no stated recovery time or
  recovery point objectives.

**Recommendation:** Doc 07 should include a "Continuity and Recovery" section
that defines RTO/RPO for each data store (audit, pheromone, dead-letter,
config), specifies backup procedures, and extends the DR runbook with
corruption recovery scenarios.

---

## Part B: Cross-Series Coherence Analysis

### B1. Topic Overlap

The following topics appear in sentinel-convergence and would also need
coverage in swarm-hardening. Where conclusions could diverge, explicit
cross-references are needed.

| Topic | Sentinel-Convergence Doc | Swarm-Hardening Need | Risk of Divergence |
|-------|-------------------------|---------------------|--------------------|
| Resilience patterns (circuit breaker, backoff, bulkhead) | SC-08 | SH should reference, not re-derive | Medium -- SC-08 covers both Sentinel and STS patterns but from a distributed perspective; SH needs the single-node lens |
| Guard pipeline fail-closed semantics | SC-08 Section 13, SC-12 | SH should own this topic as the authoritative source | High -- SC-08 already describes guard panic recovery; SH must not contradict |
| Audit chain integrity | SC-07 | SH should cover single-node audit integrity; SC-07 covers distributed reconciliation | Medium -- different scopes but shared crypto primitives (Ed25519, SHA-256, Merkle trees from swarm-spine) |
| Partition-mode authority | SC-04, SC-11, SC-13 | SH does not need to cover partition behavior but must define the single-node trust assumptions that partition designs build on | Low |
| Secret and credential handling | Not covered in SC | SH must own this entirely | None |

### B2. Missing Bridges

Topics that fall between the two series and are not adequately covered by either:

1. **Binary integrity and update verification.** SC assumes binaries exist and
   are trustworthy. SH has not yet been written. Neither series analyzes how the
   swarm binary itself is verified at startup, how updates are authenticated, or
   how rollback works after a failed update. This is the core of "secure update"
   that Doc 07 should address.

2. **Operator identity and RBAC.** The current system has a single
   `operator_id` and one bearer token. Neither series designs role-based access
   control, operator key management, or privilege escalation prevention for the
   operator surface. SC-14 discusses operator review interfaces but assumes
   identity is solved.

3. **Telemetry pipeline self-monitoring.** SC-05 designs telemetry bridges
   (Sentinel, Tetragon, JSON) but neither series asks: who watches the watcher?
   If the detection pipeline itself is compromised or degraded, what detects
   that? SC-08 covers health checks but not integrity verification of the
   detection path itself.

4. **Configuration tampering detection.** Both series assume repo-owned YAML
   config is trustworthy. Neither analyzes runtime detection of config
   tampering (e.g., an attacker modifying `rulesets/default.yaml` to disable
   detection or weaken policy gates).

5. **Log and audit export security.** The SIEM forward path
   (`siem_forward` in config) sends findings to external sinks via HTTP. Neither
   series analyzes the confidentiality and integrity of this export path beyond
   bearer token auth.

### B3. Roadmap Alignment

| Sentinel-Convergence Position | Swarm-Hardening Position | Alignment |
|-------------------------------|-------------------------|-----------|
| SC docs 01, 04, 06, 07, 11, 13, 14: Phase 6+ governance | SH series not yet written | Aligned in principle -- both defer distributed governance |
| SC-08: "near-term actionable" resilience patterns | SH should cross-reference | Aligned -- v1.37.1 (Phases 116-119) already shipped operational hardening |
| SC-12: failure-injection experiments | SH should own guard/pipeline hardening tests | Needs bridge -- SC-12 proposes experiments but SH should define pass/fail criteria for self-protection |
| v1.41 HARD-03a/b: auth + TLS on HTTP surfaces | Neither series provides research backing | Gap -- the requirement exists but no research document analyzes the threat model |
| v1.41 HARD-01: panic-free critical paths | SH should provide the analysis | Gap -- requirement without research justification |

### B4. Terminology Consistency

| Concept | Sentinel-Convergence Term | Codebase/Roadmap Term | Notes |
|---------|--------------------------|----------------------|-------|
| Response action authorization | "contingency lease" (SC-04, SC-11) | `CapabilityLease` (swarm-policy) | SC introduces a distinct `ContingencyLease` concept (SC-13) that does not exist in code; SH should use codebase terms |
| Agent health states | "crash failure", "omission failure" (SC-08) | `AgentHealth::Healthy/Degraded/Failed` (swarm-core) | SC uses distributed-systems taxonomy; codebase uses simpler enum; SH should map between them |
| Detection confidence | "high_confidence_threshold" (config) | "min_confidence" (policy rules) | Same concept, different config keys in different subsystems; SH should standardize |
| Trust boundary | "mutual TLS", "Ed25519 identity" (SC-07) | `require_bearer_auth` (http), `Keypair` (swarm-crypto) | SC-07 mentions mTLS for Sybil resistance; codebase has only bearer tokens; SH must bridge |
| Fail-closed | Used in SC-04, SC-08, SC-13, codebase guard pipeline | Consistent | No divergence |
| Pheromone substrate | Consistent across SC-06 and codebase | Consistent | No divergence |

---

## Part C: Recommended Additions

### New Research Topics for swarm-hardening

| # | Topic | Priority | Rationale |
|---|-------|----------|-----------|
| SH-01 | Binary integrity: signed releases, startup self-verification, secure update channel | P0 | Core of Doc 07's charter; not covered anywhere |
| SH-02 | Dependency supply chain: `deny.toml` hardening, advisory policy, SBOM, lockfile governance | P0 | Tooling exists but policy is weak; unique to SH |
| SH-03 | Secrets lifecycle: zeroization, encryption at rest, rotation, access audit | P1 | Production blocker for real deployments |
| SH-04 | API surface hardening: rate limiting, token rotation, mTLS threat model, browser headers | P1 | Provides research backing for v1.41 HARD-03a/b |
| SH-05 | Process hardening: unsafe audit, release flags, allocator, panic strategy | P1 | Low effort, high signal for security posture |
| SH-06 | Configuration integrity: tamper detection, signed config, runtime validation | P2 | Prevents silent policy weakening |
| SH-07 | Continuity and recovery: RTO/RPO, audit backup, corruption detection, state snapshots | P2 | Extends DR-RUNBOOK into research-grade analysis |
| SH-08 | Detection pipeline self-monitoring: integrity of the watcher itself | P2 | Addresses "who watches the watchmen" for STS |
| SH-09 | Multi-instance trust bootstrap: key distribution for shared substrate | P3 | Bridge between single-node and Phase 6 governance |
| SH-10 | Operator RBAC: role-based access, operator key management, privilege separation | P3 | Needed before multi-operator deployments |

### Cross-Series Actions

| # | Action | Owner Series |
|---|--------|-------------|
| X-01 | Add explicit cross-reference from SC-08 Section 13 (fail-closed) to future SH guard-hardening doc | sentinel-convergence |
| X-02 | Reconcile SC-13 `ContingencyLease` type proposal with existing `CapabilityLease` before SH references either | sentinel-convergence |
| X-03 | SC-07 audit chain design should note that single-node audit integrity is a prerequisite covered by SH | sentinel-convergence |
| X-04 | SH-04 (API hardening) should cite SC-08 rate-limiting patterns rather than re-deriving them | swarm-hardening |
| X-05 | Unify confidence threshold terminology across config (`high_confidence_threshold`, `min_confidence`, `medium_confidence_threshold`) in a shared glossary | both |

---

## Priority Ranking Summary

**P0 -- Must be in Doc 07:**
- SH-01: Binary integrity and secure update
- SH-02: Dependency supply chain hardening

**P1 -- Should be in Doc 07 or a companion document:**
- SH-03: Secrets lifecycle
- SH-04: API surface hardening
- SH-05: Process hardening

**P2 -- Separate research documents in the swarm-hardening series:**
- SH-06: Configuration integrity
- SH-07: Continuity and recovery
- SH-08: Detection pipeline self-monitoring

**P3 -- Deferred until multi-instance work begins:**
- SH-09: Multi-instance trust bootstrap
- SH-10: Operator RBAC

---

## Appendix: Source References

| Artifact | Path |
|----------|------|
| deny.toml | `deny.toml` |
| CI workflow | `.github/workflows/ci.yml` |
| Guard pipeline | `crates/swarm-guard/src/lib.rs` |
| Secret resolution | `crates/swarm-runtime/src/config.rs` |
| Operator auth middleware | `crates/swarm-runtime/src/http/core.inc` |
| Ed25519 signing | `crates/swarm-crypto/src/signing.rs` |
| SHA-256 hashing | `crates/swarm-crypto/src/hashing.rs` |
| Default config | `rulesets/default.yaml` |
| DR runbook | `docs/DR-RUNBOOK.md` |
| v1.41 hardening reqs | `.planning/REQUIREMENTS.md` (HARD-01 through HARD-04) |
| Sentinel-convergence overview | `docs/research/sentinel-convergence/00-OVERVIEW.md` |
