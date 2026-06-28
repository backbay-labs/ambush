# 11 -- Partition Authority Matrix

## Convergence Series: Hard Decision Matrix for Partitioned Response

| Metadata    | Value                                                          |
|-------------|----------------------------------------------------------------|
| **Version** | 1.0                                                            |
| **Date**    | 2026-04-07                                                     |
| **Status**  | Proposed                                                       |
| **Series**  | Sentinel Convergence Research (supplemental)                   |
| **Authors** | Sentinel + Swarm convergence working group                     |
| **Scope**   | Candidate bounded-authority defaults for a future partition-mode policy gate |

> **Reading Convention**
> Every cell in the matrix below contains a single proposed working default.
> This document is intentionally concrete, but it does **not** override the
> repo's current rule from `docs/CONSENSUS.md` that consequential actions
> require consensus. The matrix applies only if a future partition-mode
> contingency-lease design is explicitly adopted.

---

## Table of Contents

1. [Complete Action Inventory](#1-complete-action-inventory)
2. [Partition Authority Matrix](#2-partition-authority-matrix)
3. [Blast Radius Definitions](#3-blast-radius-definitions)
4. [Lease Pre-Staging Protocol](#4-lease-pre-staging-protocol)
5. [Escalation Ladder](#5-escalation-ladder)
6. [Forbidden Actions](#6-forbidden-actions)

---

## 1. Complete Action Inventory

Source: `swarm-core/src/types.rs` -- `ResponseAction` enum (5 variants),
`SwarmAction` enum (7 variants), plus `GuardAction` from `swarm-guard`.

### 1.1 ResponseAction Variants (Pouncer-Executable)

These are the actions that flow through `ActionRequest` -> `StaticApprovalGate`
-> `CapabilityLease` -> `ResponseExecutor`. They are the scope of this matrix.

| # | Variant | Fields | Destructive? | Current Gate Behavior |
|---|---------|--------|--------------|-----------------------|
| R1 | `BlockEgress` | `target: String` | Yes | Deny @ Low; RequireHuman @ High+; Allow @ Medium |
| R2 | `IsolateHost` | `host_id: String` | Yes | Deny @ Low; RequireHuman @ High+; Allow @ Medium |
| R3 | `RevokeCredential` | `credential_id: String` | Yes | Deny @ Low; RequireHuman @ High+; Allow @ Medium |
| R4 | `DeployDecoy` | `decoy_type: String, target_zone: String` | No | Deny @ Low; Allow @ Medium+ |
| R5 | `Escalate` | `summary: String, urgency: Severity` | No | Allow at all severity levels |

### 1.2 SwarmAction Variants (Agent Tick Outputs)

These are emitted by any agent's `tick()` method. Most are informational.
Only `RequestResponse` triggers the policy gate.

| # | Variant | Policy-Gated? | Partition Impact |
|---|---------|---------------|------------------|
| S1 | `DepositPheromone` | No | Must continue -- detection availability |
| S2 | `ClaimInvestigation` | No | Must continue -- prevents duplicate work |
| S3 | `PublishFindings` | No | Must continue -- evidence capture |
| S4 | `RequestResponse` | Yes (enters ActionRequest pipeline) | Subject to this matrix |
| S5 | `ProposeStrategy` | No | Suspend -- not time-critical |
| S6 | `RoleShift` | No | Permit with local-only scope |
| S7 | `HealthReport` | No | Must continue -- liveness signal |

### 1.3 GuardAction Variants (Safety Pipeline)

These are checked by `GuardPipeline` and are orthogonal to policy. The guard
pipeline runs in both normal and partition mode and is **never relaxed**.

| # | Variant | Guard Pipeline |
|---|---------|----------------|
| G1 | `FileAccess(path)` | ForbiddenPathGuard |
| G2 | `FileWrite(path, bytes)` | ForbiddenPathGuard + SecretLeakGuard |
| G3 | `ShellCommand(cmd)` | ShellCommandGuard |
| G4 | `NetworkEgress(host, port)` | EgressAllowlistGuard |
| G5 | `ResponseAction(&ResponseAction)` | All guards that handle it |

---

## 2. Partition Authority Matrix

**Assumptions baked in:**
- Partition is detected by Layer 3+ circuit breakers (governance bus + peer mesh).
- The agent holds pre-staged contingency leases issued during the last renewal
  window. Those leases are not part of the current repo types today; they are a
  proposed extension described in Section 4.
- The `GuardPipeline` runs unconditionally; a guard block overrides any lease.
- `Deny` verdicts from `StaticApprovalGate` are invariant under partition.

### 2.1 The Matrix

| Action | Normal-Mode Authorization | Partition Mode | Pre-Staged Lease Type | Max TTL | Max Blast Radius | Degraded Version | Rollback Mechanism | Reconciliation on Heal |
|--------|--------------------------|----------------|-----------------------|---------|------------------|------------------|--------------------|----------------------|
| **R1: BlockEgress** | Allow @ Medium; RequireHuman @ High+; lease TTL 60s | **ALLOWED** | `contingency:block_egress` | 30 min | 10 IPs per lease | N/A -- full action permitted | Remove firewall/ACL rule; flush conntrack entry | G-Set union of all block rules; human reviews for over-blocking |
| **R2: IsolateHost** | Allow @ Medium; RequireHuman @ High+; lease TTL 60s | **DEGRADED** | `contingency:isolate_host` | 15 min | 1 host per lease | Soft-isolate: block egress from host but preserve inbound monitoring and management ports | Re-enable host network interfaces; verify host health before full restore | Keep isolated until human confirms; `CheckAndRecoverNode` pattern from Sentinel |
| **R3: RevokeCredential** | Allow @ Medium; RequireHuman @ High+; lease TTL 60s | **DENIED** | N/A | N/A | N/A | N/A | N/A | N/A -- see Forbidden Actions (Section 6) |
| **R4: DeployDecoy** | Allow @ Medium+; lease TTL 60s | **ALLOWED** | `contingency:deploy_decoy` | 60 min | 3 decoys per lease, 1 per zone | N/A -- full action permitted | Tear down decoy assets; remove DNS/route entries | G-Set union of decoy placements; deduplicate by (decoy_type, target_zone) |
| **R5: Escalate** | Allow at all severities; no lease required | **ALLOWED** | No lease needed -- informational | N/A | Unlimited (informational) | Buffer locally if substrate unreachable; flush on heal | N/A -- escalation is append-only | Merge escalation records; deduplicate by hunt_id + summary hash |

### 2.2 Severity Gate Under Partition

The normal-mode `Deny` floor is **never relaxed**. Only `RequireHuman` changes.

| Severity | Normal: Destructive Action | Partition: Destructive Action |
|----------|---------------------------|-------------------------------|
| Low | Deny | Deny |
| Medium | Allow (60s lease) | Allow (pre-staged lease, capped TTL) |
| High | RequireHuman | Allow IF pre-staged lease exists; Deny otherwise |
| Critical | RequireHuman | Allow IF pre-staged lease exists; Deny otherwise |

The key invariant: a partitioned agent with no pre-staged lease for High/Critical
destructive actions **does nothing**. The lease is the authority. No lease, no action.

---

## 3. Blast Radius Definitions

Every pre-staged lease carries a `MaxBlastRadius` scope constraint. These are
hard caps enforced by the partition-mode policy gate. Exceeding them is a
`Deny` regardless of severity.

### 3.1 Per-Action Caps

| Action | Cap Name | Hard Limit | Unit | Rationale |
|--------|----------|------------|------|-----------|
| **BlockEgress** | `max_targets` | 10 | IP addresses or CIDR /32s | Prevents accidental broad network blackholing; CIDR ranges wider than /24 are rejected outright |
| **BlockEgress** | `max_cidr_width` | /24 | Prefix length floor | A single lease cannot block more than 256 addresses via CIDR |
| **IsolateHost** (degraded) | `max_hosts` | 1 | Host IDs | One host per lease, one lease per 15-minute window; prevents cascading isolation |
| **DeployDecoy** | `max_decoys` | 3 | Decoy instances | Capped to avoid resource exhaustion on the partitioned segment |
| **DeployDecoy** | `max_per_zone` | 1 | Decoy per target zone | Prevents zone saturation; one honeypot per zone is sufficient for detection |
| **Escalate** | None | Unlimited | Messages | Informational; no destructive side-effect |

### 3.2 Aggregate Caps (Per Partition Episode)

These caps apply across all leases consumed during a single partition episode,
tracked by the partitioned Pouncer agent locally.

| Metric | Hard Limit | Enforcement |
|--------|------------|-------------|
| Total IPs blocked | 50 | Local counter; Deny new BlockEgress when reached |
| Total hosts soft-isolated | 3 | Local counter; Deny new IsolateHost when reached |
| Total decoys deployed | 9 | Local counter; Deny new DeployDecoy when reached |
| Total leases consumed | 20 | Local counter; triggers Tier 3 escalation ladder |

---

## 4. Lease Pre-Staging Protocol

### 4.1 Rust Types

The types below are **proposed future extensions**. They do not exist in the
current `swarm-policy` or `swarm-core` crates today.

```rust
use serde::{Deserialize, Serialize};
use swarm_core::types::Severity;

/// A contingency lease issued during normal operation, activated on partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContingencyLease {
    /// Opaque lease identifier. Format: "contingency:{action}:{hunt_id}:{seq}"
    pub lease_id: String,
    /// Response action class this lease authorizes.
    pub action_class: ContingencyActionClass,
    /// Minimum threat severity required to exercise this lease.
    pub min_severity: Severity,
    /// Wall-clock time (unix ms) when this lease was issued.
    pub issued_at_ms: i64,
    /// Wall-clock time (unix ms) after which this lease is void.
    pub expires_at_ms: i64,
    /// Maximum times this lease may be exercised.
    pub max_uses: u32,
    /// Times exercised so far (locally tracked, reconciled on heal).
    pub uses: u32,
    /// Scope constraints bounding what this lease can target.
    pub scope: ContingencyScope,
    /// Ed25519 signature from the issuing Tom agent over (lease_id, action_class,
    /// min_severity, expires_at_ms, max_uses, scope).
    pub issuer_signature: Vec<u8>,
    /// Hash of the spine envelope that carried this lease.
    pub spine_envelope_hash: String,
}

/// Action classes that can be pre-authorized via contingency lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContingencyActionClass {
    BlockEgress,
    IsolateHost,
    DeployDecoy,
}

/// Scope constraints for a contingency lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContingencyScope {
    /// Exact targets this lease may act on. Empty = any target within blast radius.
    pub allowed_targets: Vec<String>,
    /// CIDR ranges this lease may block (BlockEgress only).
    pub allowed_cidrs: Vec<String>,
    /// Host patterns this lease may isolate (IsolateHost only). Glob syntax.
    pub host_patterns: Vec<String>,
    /// Target zones this lease may deploy decoys into (DeployDecoy only).
    pub allowed_zones: Vec<String>,
    /// Hard blast radius cap.
    pub max_blast_radius: u32,
}

/// Activation condition for a contingency lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseActivation {
    /// Active only when governance bus circuit breaker is open.
    OnGovernancePartition,
    /// Active only when peer mesh detects partition (Layer 4).
    OnPeerPartition,
}

/// Local store of pre-staged leases on a Pouncer agent.
#[derive(Debug, Default)]
pub struct ContingencyLeaseStore {
    /// Active leases keyed by action class.
    pub leases: std::collections::HashMap<String, Vec<ContingencyLease>>,
    /// Leases that expired before use (audit record).
    pub expired_unused: Vec<ContingencyLease>,
    /// Leases consumed during current partition episode.
    pub consumed: Vec<ContingencyLease>,
}
```

### 4.2 Pre-Staging Lifecycle

```
 NORMAL OPERATION
 ================
 Tom agent evaluates threat landscape every 10 minutes.
     |
     v
 Tom issues ContingencyLease set via signed spine envelope.
     |
     v
 Pouncer receives, verifies signature, stores in ContingencyLeaseStore.
     |
     v
 Previous lease set expires. New set replaces it.
 Renewal interval: 15 minutes.
 Lease TTL: 30 minutes (2x renewal interval -- provides overlap).

 PARTITION DETECTED
 ==================
 Pouncer checks ContingencyLeaseStore for leases matching:
   1. action_class matches requested ResponseAction
   2. min_severity <= current threat severity
   3. expires_at_ms > now (lease not expired)
   4. uses < max_uses (lease not exhausted)
   5. scope constraints satisfied by request target
     |
     v
 If match found: execute under lease, increment uses, log to local audit.
 If no match: DENY. Log denial. Buffer for post-partition human review.
```

### 4.3 Expired Lease During Partition

When a pre-staged lease expires during partition:

1. The lease becomes **void immediately**. No grace period.
2. Any in-flight action authorized by that lease runs to completion (the lease
   was valid at dispatch time).
3. No new actions may use the expired lease.
4. The agent logs the expiration event to the local audit trail.
5. If no other valid lease covers the action class, the agent enters the
   escalation ladder (Section 5).

The maximum window of autonomous authority is therefore: lease TTL (30 min)
minus time-since-last-renewal. In the worst case (partition occurs 1ms after
renewal), the agent has 30 minutes of authority. In the best case (partition
occurs 1ms before renewal), the agent has 15 minutes.

**Hard number: maximum autonomous authority window is 30 minutes.**

After 30 minutes of uninterrupted partition with no lease renewal, the
Pouncer has zero contingency leases and can execute zero destructive actions.
It continues detection, evidence capture, and local escalation buffering.

---

## 5. Escalation Ladder

When a Pouncer exhausts its pre-staged leases during a prolonged partition,
it does not gain new authority. It loses capability in a controlled descent.

### Tier 0: Full Contingency Authority (t=0 to lease expiry)

| Property | Value |
|----------|-------|
| **Entry condition** | Partition detected; valid contingency leases exist |
| **Available actions** | BlockEgress, IsolateHost (degraded), DeployDecoy, Escalate |
| **Authority source** | Pre-staged ContingencyLease signed by Tom |
| **Duration** | Up to 30 minutes (lease TTL) |
| **Monitoring** | All actions logged to local audit trail with partition context |

### Tier 1: Detection-Only Mode (lease expiry to +60 min)

| Property | Value |
|----------|-------|
| **Entry condition** | All contingency leases expired; partition persists |
| **Available actions** | Escalate (buffered), DepositPheromone, PublishFindings, HealthReport |
| **Forbidden** | All destructive actions (BlockEgress, IsolateHost, RevokeCredential) |
| **Forbidden** | DeployDecoy (no active lease) |
| **Behavior** | Whisker-mode: detect, record, buffer. No response. |
| **Duration** | 60 minutes |
| **Monitoring** | Threat detections continue; response requests queued in dead-letter journal |

### Tier 2: Passive Observation (lease expiry +60 min to +4 hr)

| Property | Value |
|----------|-------|
| **Entry condition** | Tier 1 duration exceeded; partition persists |
| **Available actions** | DepositPheromone, HealthReport |
| **Forbidden** | Everything except pheromone deposits and health reports |
| **Behavior** | Minimal footprint. Agent reduces sampling rate to 50% to conserve resources. |
| **Duration** | Up to 4 hours from partition start |
| **Monitoring** | Periodic health beacon (every 30s) to enable fast recovery detection |

### Tier 3: Hibernation (partition > 4 hr)

| Property | Value |
|----------|-------|
| **Entry condition** | Partition exceeds 4 hours |
| **Available actions** | HealthReport only (every 60s) |
| **Forbidden** | All actions including pheromone deposit |
| **Behavior** | Agent assumes it is compromised or on a fully adversarial segment. Minimizes activity to avoid providing signal to attacker. Preserves local audit log. |
| **Duration** | Indefinite until partition heals or operator intervenes locally |
| **Recovery** | On partition heal: full audit log upload before resuming any operations |

### Escalation Ladder Summary

```
t=0          Partition detected
             |
             v
  [Tier 0]   CONTINGENCY AUTHORITY (max 30 min)
             BlockEgress, IsolateHost(degraded), DeployDecoy, Escalate
             |
             | All leases expired
             v
  [Tier 1]   DETECTION-ONLY (60 min)
             Detect, record, buffer. No response.
             |
             | 60 min elapsed
             v
  [Tier 2]   PASSIVE OBSERVATION (up to 4 hr total)
             Pheromone + health only. 50% sampling.
             |
             | 4 hr total elapsed
             v
  [Tier 3]   HIBERNATION (indefinite)
             Health beacon only. Assume hostile segment.
```

---

## 6. Forbidden Actions

These actions are **never** permitted during partition, at any severity, with
any lease, under any threat condition.

### 6.1 RevokeCredential -- ALWAYS DENIED

**Justification**: Credential revocation is irreversible in practice. A revoked
credential must be re-issued through an identity provider workflow that requires
the governance plane. During partition, the agent cannot:
- Verify that the credential is not in active legitimate use by a service on
  the other side of the partition.
- Coordinate re-issuance after revocation.
- Distinguish a compromised credential from one that appears compromised due to
  partition-induced communication anomalies.

A false-positive credential revocation during partition can cause cascading
authentication failures across services that depend on that credential, with
no path to recovery until the partition heals and a human re-issues.

**Alternative**: Buffer the revocation request in the dead-letter journal with
full evidence. On partition heal, it is processed with priority by the
governance plane. If the credential is truly compromised, the 30-minute delay
(max contingency window) plus partition duration is the cost. This cost is
accepted because the blast radius of a false revocation exceeds the blast
radius of delayed revocation.

### 6.2 Full Host Isolation -- ALWAYS DENIED (Degraded Version Permitted)

**Justification**: Full host isolation (severing all network connectivity
including management interfaces) renders the host unreachable for
post-partition remediation. During partition, the agent cannot guarantee that:
- The isolated host is not running critical services for the partitioned segment.
- Management access will be restorable without physical intervention.
- The isolation signal itself is not attacker-induced (luring the system into
  self-denial-of-service).

**What is permitted instead**: Soft-isolation via `BlockEgress` applied to the
host's known egress paths. This blocks outbound C2 communication while
preserving inbound monitoring and SSH/management access. The degraded
`IsolateHost` lease authorizes this soft-isolation pattern, not full network
severance.

### 6.3 Cross-Partition Scope Actions -- ALWAYS DENIED

**Justification**: A partitioned agent has no visibility into the other side
of the partition. Any action whose target is known to reside outside the
agent's reachable segment is denied because:
- The agent cannot verify current state of the target.
- The action may conflict with decisions made by agents on the other side.
- Execution may fail silently (target unreachable), leaving the agent with
  a false belief that containment succeeded.

**Enforcement**: The `ContingencyScope.allowed_targets` field is populated by
the Tom agent with only targets reachable from the Pouncer's network segment.
The partition-mode gate rejects any request targeting an address not in scope.

### 6.4 Strategy Mutation -- ALWAYS DENIED

**Justification**: `ProposeStrategy` modifies the swarm's detection logic.
During partition, strategy mutations cannot be validated by the full swarm
and risk introducing detection blind spots that persist after partition heals.
Strategy proposals are buffered and evaluated post-partition.

### 6.5 Guard Pipeline Bypass -- ALWAYS DENIED

**Justification**: The `GuardPipeline` (ForbiddenPathGuard, ShellCommandGuard,
SecretLeakGuard, EgressAllowlistGuard) is a safety invariant, not a policy
decision. It is never relaxed, suspended, or bypassed. A guard `block` result
overrides any lease, any severity, any partition state. The pipeline
`catch_unwind` behavior (fail-closed on panic) applies identically during
partition.

---

## Appendix A: Sentinel Decision Type Cross-Reference

For completeness, mapping Sentinel's autonomous `DecisionType` values to
the partition authority rules above:

| Sentinel DecisionType | Swarm Equivalent | Partition Authority |
|-----------------------|------------------|---------------------|
| `pod_reschedule` | No direct equivalent (infrastructure layer) | N/A for Swarm |
| `node_cordon` | `IsolateHost` (degraded: soft-isolate) | DEGRADED -- 1 host/lease, 15 min TTL |
| `service_failover` | `BlockEgress` + `DeployDecoy` (redirect via decoy) | ALLOWED -- within blast radius caps |
| `resource_scale` | No direct equivalent | N/A for Swarm |

## Appendix B: Reconciliation Quick-Reference

| Action | CRDT Strategy | Auto-Merge? | Human Review Required? |
|--------|---------------|-------------|----------------------|
| BlockEgress | G-Set union | Yes | Only if total blocks > 30 |
| IsolateHost (soft) | Security-biased LWW (favor isolate) | No | Always |
| DeployDecoy | G-Set union, deduplicate by (type, zone) | Yes | No |
| Escalate | G-Set union, deduplicate by hunt_id | Yes | No |
| RevokeCredential | N/A (forbidden during partition) | N/A | Always (queued request) |

---

*Cross-references: [04-AUTONOMOUS-RESPONSE-UNDER-PARTITION](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md), [07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION](07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md), [08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md)*
