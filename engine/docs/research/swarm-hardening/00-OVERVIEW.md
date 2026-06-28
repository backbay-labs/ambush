# Swarm-Hardening Series Overview

| Field   | Value                                              |
|---------|----------------------------------------------------|
| Series  | swarm-hardening                                    |
| Version | 0.3 (gap-addressed)                                |
| Date    | 2026-04-08                                         |
| Status  | Draft -- initial series structure with gap-addressed content |

---

## Purpose

The `swarm-hardening` research series covers security hardening of the Swarm
Team Six runtime as a single-node, self-contained detection and live-response
engine. It is the companion to the `sentinel-convergence` series, which
covers distributed governance, consensus, and multi-agent coordination
(Phase 6+).

This series focuses on:

- Self-protection of the runtime binary and its dependencies
- Hardening of operator-facing API surfaces
- Secrets lifecycle and credential management
- Process-level and memory-level security properties
- Continuity and recovery guarantees
- Single-node trust foundations that distributed designs build on

## Relationship to sentinel-convergence

The two series are complementary, not overlapping. The boundary:

| Concern | Owner Series | Notes |
|---------|-------------|-------|
| Supply chain, dependency integrity | swarm-hardening | Not covered in SC |
| Secret and credential handling | swarm-hardening | Not covered in SC |
| Process hardening (unsafe audit, panic strategy, allocator) | swarm-hardening | Not covered in SC |
| API surface hardening (rate limiting, token lifecycle, browser headers) | swarm-hardening | Provides research backing for v1.41 HARD-03a/b |
| Guard pipeline fail-closed semantics | swarm-hardening (authoritative) | SC-08 Section 13 describes from distributed perspective; SH owns single-node analysis |
| Single-node audit chain integrity | swarm-hardening | SC-07 covers distributed reconciliation |
| Resilience patterns (circuit breaker, backoff, bulkhead) | sentinel-convergence SC-08 | SH cross-references, does not re-derive |
| Distributed consensus and BFT | sentinel-convergence SC-01 | SH defers |
| Partition-mode authority | sentinel-convergence SC-04, SC-11, SC-13 | SH defines single-node trust assumptions that partition designs build on |
| Audit reconciliation across partitions | sentinel-convergence SC-07 | SH covers single-node prerequisite |

---

## Terminology Reconciliation

The sentinel-convergence series and the current codebase use different terms
for overlapping concepts. This section provides the canonical mapping.

| Concept | sentinel-convergence Term | Codebase Term | Reconciliation |
|---------|--------------------------|---------------|----------------|
| Response action authorization lease | `ContingencyLease` (SC-13, SC-11) | `CapabilityLease` (swarm-policy) | SC-13 proposes `ContingencyLease` as a *new, parallel type* (ADR Option A) alongside existing `CapabilityLease`. They are not synonyms: `CapabilityLease` is the single-use normal-mode lease; `ContingencyLease` is the proposed multi-use partition-mode lease. Both series should use both terms precisely. |
| Agent health states | "crash failure", "omission failure" (SC-08) | `AgentHealth::Healthy / Degraded / Failed` (swarm-core) | SC uses distributed-systems taxonomy; codebase uses a simpler enum. SH maps: `Healthy` = no failure; `Degraded` = omission failure; `Failed` = crash failure. |
| Detection confidence | `high_confidence_threshold` (detection config) | `min_confidence` (policy rules) | Same concept, different config keys in different subsystems. Future work should unify under a shared glossary (cross-series action X-05 in the gap report). |
| Trust boundary mechanism | "mutual TLS", "Ed25519 identity" (SC-07) | `require_bearer_auth` (http), `Keypair` (swarm-crypto) | SC-07 designs mTLS for Sybil resistance in distributed mode; codebase has bearer tokens for single-node operator auth. SH-07 Section 12 bridges the gap. |
| Fail-closed | Consistent across SC-04, SC-08, SC-13, codebase guard pipeline | Consistent | No divergence. |
| Pheromone substrate | Consistent across SC-06 and codebase | Consistent | No divergence. |

---

## Document Index

| Doc | Title | Status | Scope |
|-----|-------|--------|-------|
| `00` | Overview (this document) | v0.3 draft | Series structure, reading order, cross-series mapping |
| `01` | [Adversarial Evasion and Detection Robustness](01-ADVERSARIAL-EVASION-AND-DETECTION-ROBUSTNESS.md) | v0.3 draft | Evasion techniques against the detector; hardening recommendations |
| `02` | [MITRE ATT&CK Coverage Analysis](02-MITRE-ATTCK-COVERAGE-ANALYSIS.md) | v0.3 draft | Mapping detection strategies to MITRE ATT&CK; coverage gaps |
| `03` | [Threat Intelligence Lifecycle and Enrichment](03-THREAT-INTELLIGENCE-LIFECYCLE-AND-ENRICHMENT.md) | v0.3 draft | IOC taxonomy, feed sourcing, enrichment pipeline design |
| `04` | [Performance Characterization Under Load](04-PERFORMANCE-CHARACTERIZATION-UNDER-LOAD.md) | v0.3 draft | Throughput, latency budgets, performance profiling |
| `05` | [Kill Chain Reconstruction and Graph Correlation](05-KILL-CHAIN-RECONSTRUCTION-AND-GRAPH-CORRELATION.md) | v0.3 draft | Attack-graph DAGs, temporal-causal correlation |
| `06` | [Behavioral Baseline and Anomaly Detection](06-BEHAVIORAL-BASELINE-AND-ANOMALY-DETECTION.md) | v0.3 draft | Statistical anomaly detection, baseline drift, cold start |
| `07` | [Secure Update and Self-Protection](07-SECURE-UPDATE-AND-SELF-PROTECTION.md) | v0.3 draft | Self-protection analysis across integrity-at-rest, integrity-at-runtime, and integrity-across-deployments (also covers dependency supply chain [Section 10], process hardening [Section 11], API surface [Section 12], and secrets lifecycle [Section 13]) |
| `08` | *Reserved: Detection Pipeline Self-Monitoring* | Not started | Integrity verification of the detection path itself (SH-08) |

---

## Known Cross-Series Gaps

The following topics fall between the swarm-hardening and sentinel-convergence
series and are not adequately covered by either. They are listed here to
prevent them from being forgotten.

### Gap 1: Binary Integrity Lifecycle (Partially Addressed)

Doc `07` Sections 3 (Binary Attestation) and 6 (Secure Update Channel) now
analyze startup self-verification, release signing, update authentication,
and rollback protection. However, no implementation exists yet, and a
dedicated SH-01 document may still be warranted for the full binary
integrity lifecycle including CI integration and key ceremony procedures.

### Gap 2: Operator RBAC

The current system has a single `operator_id` and one bearer token. Neither
series designs role-based access control, operator key management, or
privilege escalation prevention for the operator surface. SC-14 discusses
operator review interfaces but assumes identity is solved. A future SH-10
document should address this before multi-operator deployments.

### Gap 3: Telemetry Pipeline Self-Monitoring

SC-05 designs telemetry bridges (Sentinel, Tetragon, JSON) but neither series
asks: who watches the watcher? If the detection pipeline itself is
compromised or degraded, what detects that? SC-08 covers health checks but
not integrity verification of the detection path itself. A future SH-08
document should address this.

### Gap 4: Configuration Tamper Detection (Partially Addressed)

Doc `07` Section 4 (Configuration Integrity) now analyzes signed rulesets
and a filesystem watchdog for runtime tamper detection. A dedicated SH-06
document may still be warranted for broader configuration integrity
concerns (e.g., tamper detection for non-YAML config, runtime API-driven
config mutations).

### Gap 5: Log and Audit Export Security

The SIEM forward path (`siem_forward` in config) sends findings to external
sinks via HTTP. Neither series analyzes the confidentiality and integrity of
this export path beyond bearer token authentication. The export surface
should be analyzed for TLS enforcement, payload signing, and replay
protection.

---

## v1.41 Hardening Requirements -- Research Coverage

The v1.41 milestone defines hardening requirements HARD-01 through HARD-04.
The following table tracks which requirements have research backing from
either series.

| Requirement | Description | Research Coverage | Gap? |
|-------------|-------------|-------------------|------|
| HARD-01 | Panic-free critical paths | SH-07 Section 11 (panic strategy analysis) | Partial -- SH-07 provides the analysis; implementation guidance is in the requirement itself |
| HARD-02 | Evolution/CLI crate extraction | Not a security research topic | No -- this is an architectural refactor |
| HARD-03a | Bearer auth on detect server | SH-07 Section 12 (API surface analysis) | Partial -- SH-07 identifies gaps in the auth model but does not design the detect-server auth solution |
| HARD-03b | Optional TLS + mTLS | SH-07 Section 12 (G-NET-3: mTLS unresearched) | **Yes** -- the requirement exists but no research document analyzes the threat model; SH-07 recommends a dedicated mTLS threat model analysis |
| HARD-04 | Structured tracing instrumentation | Not a security research topic | No -- this is an observability feature |

---

## Reading Order

For a first read:

1. Start with this document (`00`)
2. Read `01` through `06` for detection-focused hardening research
   (adversarial evasion, MITRE coverage, threat intel, performance,
   kill chain reconstruction, behavioral baselines)
3. Read `07` (Secure Update and Self-Protection) for the runtime
   self-protection gap analysis
4. Read the gap report (`GAPS-07-SERIES-COHERENCE.md`) for methodology and
   the full cross-series coherence analysis
5. Read sentinel-convergence `00-OVERVIEW.md` for the companion series context

For implementation planning:

1. Use the priority map in `07` Section 18 to sequence self-protection work
2. Cross-reference v1.41 HARD requirements against the research coverage
   table above
3. Check the Known Cross-Series Gaps section for topics that need new
   research documents before implementation can proceed

---

## Source References

| Artifact | Path |
|----------|------|
| Gap report | `docs/research/swarm-hardening/GAPS-07-SERIES-COHERENCE.md` |
| deny.toml | `deny.toml` |
| CI workflow | `.github/workflows/ci.yml` |
| Guard pipeline | `crates/swarm-guard/src/lib.rs` |
| Secret resolution | `crates/swarm-runtime/src/config.rs` |
| Operator auth middleware | `crates/swarm-runtime/src/http/core.inc` |
| Ed25519 signing | `crates/swarm-crypto/src/signing.rs` |
| Default config | `rulesets/default.yaml` |
| DR runbook | `docs/DR-RUNBOOK.md` |
| Workspace Cargo.toml | `Cargo.toml` |
| v1.41 hardening reqs | `.planning/REQUIREMENTS.md` (HARD-01 through HARD-04) |
| Sentinel-convergence overview | `docs/research/sentinel-convergence/00-OVERVIEW.md` |
| SC-13 ContingencyLease ADR | `docs/research/sentinel-convergence/13-ADR-MINIMAL-PARTITION-AUTHORITY-TYPES.md` |
