# 04 -- Autonomous Response Under Partition

## Convergence Series: Sentinel Patterns Applied to Swarm-Team-Six

| Metadata    | Value                                                          |
|-------------|----------------------------------------------------------------|
| **Version** | 0.2                                                            |
| **Date**    | 2026-04-07                                                     |
| **Status**  | Draft                                                          |
| **Series**  | Sentinel Convergence Research (document 4 of 8)                |
| **Authors** | Sentinel + Swarm convergence working group                     |
| **Scope**   | Partition-tolerant autonomous response in distributed security |

> **Series Note**
> - Partition tolerance in this series means preserving detection, evidence
>   capture, and reporting under degraded connectivity.
> - Consequential response remains bounded by fail-closed guards, policy, and
>   any contingency lease that explicitly authorizes a narrow action class.
> - This is Phase 6+/governance research, not the current near-term runtime
>   plan.

---

## Table of Contents

1. [The Partition Problem in Distributed Security Systems](#1-the-partition-problem-in-distributed-security-systems)
2. [CAP Theorem Implications for Security Response](#2-cap-theorem-implications-for-security-response)
3. [Sentinel's Partition Resilience Patterns](#3-sentinels-partition-resilience-patterns)
4. [Mapping to Swarm-Team-Six](#4-mapping-to-swarm-team-six)
5. [Pre-Delegated Authority and Capability Lease Pre-Staging](#5-pre-delegated-authority-and-capability-lease-pre-staging)
6. [Decision Conflict Resolution](#6-decision-conflict-resolution)
7. [Reconciliation Protocols](#7-reconciliation-protocols)
8. [Circuit Breaker Patterns for Degraded Connectivity](#8-circuit-breaker-patterns-for-degraded-connectivity)
9. [Split-Brain Prevention in Security Context](#9-split-brain-prevention-in-security-context)
10. [Formal Safety Properties](#10-formal-safety-properties)
11. [Industry Precedents](#11-industry-precedents)
12. [Reference Architecture for Partition-Aware Swarm Response](#12-reference-architecture-for-partition-aware-swarm-response)
13. [Conclusion and Recommendations](#13-conclusion-and-recommendations)
14. [Cross-References](#cross-references)

---

## 1. The Partition Problem in Distributed Security Systems

### 1.1 Problem Statement

A distributed security system that cannot respond during a network partition
fails precisely when it is most needed. Attackers actively create
partitions -- severing management plane connectivity, disrupting inter-cluster
communication, isolating endpoint agents from their command infrastructure --
because traditional architectures treat disconnected nodes as inert.

The fundamental tension: security response systems are **distributed** by
nature (agents run where threats appear) yet **centralized** by design (policy
authority lives in a control plane). When that link breaks, the system faces
a question with no universally safe default:

> Should an isolated agent act on incomplete information, or wait for
> authority that may never arrive?

### 1.2 Anatomy of a Security Partition

Partitions in security systems differ from generic distributed systems because
the partition itself may be adversarial. We distinguish three categories:

| Category | Cause | Duration | Adversarial? |
|---|---|---|---|
| **Infrastructure partition** | Switch failure, BGP flap, cloud AZ isolation | Minutes to hours | Rarely |
| **Control-plane partition** | API server overload, certificate expiry, DNS failure | Seconds to minutes | Sometimes |
| **Adversarial partition** | Attacker disabling agent comms, C2 disruption, firewall manipulation | Indefinite | Always |

The third category is the critical one for security systems: the partition
is the attack. If an attacker can isolate a detection node from its policy
authority, and that node refuses to act without authorization, the attacker
has effectively neutralized the entire security posture at that location.

### 1.3 What Happens When Detection Nodes Lose Contact

In Sentinel, the cascade is: control plane unreachable (t=0) -> circuit breaker
accumulates 5 consecutive failures (duration depends on call rate) -> circuit
opens -> partition detector callback fires (100ms tick) -> edge consensus
forms among reachable peers -> leader election completes (~150-300ms with
randomized timeout) -> autonomous decisions begin (cordon, migrate, failover).
The circuit breaker's 30-second timeout governs recovery probing, not
time-to-open.

In Swarm-Team-Six, Whiskers lose contact with Tom governance agents, and the
pheromone substrate itself may partition -- some agents communicate via local
NATS segments while others are fully isolated.

The critical insight: partition detection must use a **separate channel** from
the partitioned resource. Sentinel uses direct peer TCP connections independent
of the K8s API server. Swarm-Team-Six should use local pheromone substrate
segments that function independently of the central governance bus.

---

## 2. CAP Theorem Implications for Security Response

### 2.1 The CAP Trilemma Applied to Threat Response

Brewer's CAP theorem states that a distributed system can guarantee at most two
of Consistency, Availability, and Partition tolerance. For security response
systems, these map to specific operational properties:

| CAP Property | Security Meaning | Failure Mode if Sacrificed |
|---|---|---|
| **Consistency** | All agents agree on policy and threat state | Contradictory responses: one agent blocks traffic another permits |
| **Availability** | Every agent can respond to threats it detects | Threats go unaddressed during partition |
| **Partition Tolerance** | System functions despite network splits | N/A -- partitions are inevitable in distributed security |

Since partitions are not optional (they are a given, especially when adversarial),
the real choice is between **CP** (consistent but potentially unavailable) and
**AP** (available but potentially inconsistent).

### 2.2 Why Detection Paths Must Preserve Availability

Traditional IT systems often choose CP because stale data is worse than no data
(financial transactions, inventory management). Security systems cannot apply a
single CAP posture to every behavior. The safer split is:

- **Detection, evidence capture, local buffering, and reporting** should favor
  availability during partition.
- **Destructive or environment-modifying response** should remain fail-closed
  unless bounded authority has been pre-delegated through policy and leases.

A missed detection or lost evidence window has unbounded downside. By contrast,
an unconstrained autonomous response can also create unbounded downside if a
partitioned node acts outside policy. The design goal is therefore not "AP for
everything"; it is "preserve availability where observation and containment
signal matter, while keeping consequential action behind explicit bounded
authority."

This does not mean consistency is abandoned. It means consistency is
**eventually** restored through reconciliation, while availability is
maintained immediately. Sentinel's architecture explicitly implements this
model:

```
During Partition:  AP for detection/reporting/logging
During Partition:  Fail-closed response unless contingency lease authorizes action
After Partition:   Reconcile evidence, lease use, and decision logs
```

### 2.3 The PACELC Extension

Abadi's PACELC theorem refines CAP by asking what happens when there is no
partition (the normal case). The full classification for security systems:

- **During Partition (PAC)**: Favor **A** (availability of response) over **C** (policy consistency)
- **Else (ELC)**: Favor **C** (strict policy enforcement) over **L** (low latency)

This means:
- Normal operation: every response goes through the full policy gate with human
  approval for destructive actions at or above `Severity::High`
- Partitioned operation: pre-delegated authority enables autonomous response
  within bounded scope, with all decisions logged for post-partition audit

Swarm-Team-Six's `StaticApprovalGate` already implements the normal-case side:

```rust
// From swarm-policy/src/static_gate.rs -- normal operation path (simplified)
impl ApprovalGate for StaticApprovalGate {
    fn evaluate(
        &self,
        request: &ActionRequest,
        _context: &ApprovalContext,
    ) -> Result<PolicyDecision, ApprovalError> {
        self.validate_request(request)?;

        // Hard deny: destructive actions at low severity are never authorized
        if Self::destructive_action(request) && request.severity == Severity::Low {
            return Ok(PolicyDecision::deny(
                "destructive actions require at least medium severity",
            ));
        }

        // Human gate: destructive actions at or above the configured severity
        if Self::destructive_action(request) && request.severity >= self.human_gate_severity {
            return Ok(PolicyDecision::require_human(
                "authorized but held for human approval",
            ));
        }

        Ok(PolicyDecision::allow("authorized for immediate execution"))
    }
}
```

The gate enforces three tiers: hard `Deny` for low-severity destructive
requests, `RequireHuman` for high-severity destructive requests, and `Allow`
for everything else. During partition, the `RequireHuman` verdict becomes
impossible to fulfill. The system needs a partition-aware gate that can
downgrade `RequireHuman` to a time-bounded autonomous authorization -- while
preserving the `Deny` floor, which must remain unconditional.

---

## 3. Sentinel's Partition Resilience Patterns

### 3.1 Architecture Overview

Sentinel implements a four-phase partition resilience cycle:

```
 +-------------------+     +--------------------+     +-------------------+
 |  1. DETECTION     | --> |  2. LOCAL          | --> |  3. AUTONOMOUS    |
 |  Partition         |     |  CONSENSUS         |     |  ACTION           |
 |  detected via     |     |  Raft-lite among   |     |  Cordon, migrate, |
 |  circuit breaker  |     |  reachable peers   |     |  failover per     |
 |  + peer health    |     |  elects leader     |     |  local quorum     |
 +-------------------+     +--------------------+     +-------------------+
                                                             |
                                                             v
                                                      +-------------------+
                                                      |  4. RECONCILE     |
                                                      |  Merge decision   |
                                                      |  logs with        |
                                                      |  control plane    |
                                                      +-------------------+
```

### 3.2 Phase 1: Partition Detection

Sentinel uses two independent detection mechanisms:

**Circuit Breaker on API Server Calls** (from `pkg/k8s/circuit_breaker.go`):

```go
// CircuitBreaker state machine: Closed -> Open -> HalfOpen -> Closed
type CircuitBreaker struct {
    config *CircuitBreakerConfig
    mu                  sync.RWMutex
    state               CircuitState
    failures            int
    successes           int
    lastFailureTime     time.Time
    lastStateChangeTime time.Time
}

func (cb *CircuitBreaker) Allow() bool {
    cb.mu.Lock()
    defer cb.mu.Unlock()
    switch cb.state {
    case CircuitClosed:
        return true
    case CircuitOpen:
        if time.Since(cb.lastStateChangeTime) >= cb.config.Timeout {
            cb.transitionTo(CircuitHalfOpen)
            return true
        }
        return false
    case CircuitHalfOpen:
        return true
    default:
        return false
    }
}
```

The circuit breaker tracks consecutive failures against the Kubernetes API
server. With the default configuration (threshold=5, timeout=30s), the circuit
opens after 5 consecutive failures and remains open for 30 seconds before
allowing a probe request in half-open state.

**Peer Connectivity Monitoring** (from `pkg/consensus/raft_lite.go`):

```go
func (n *Node) partitionDetector() {
    // ...
    // Count healthy peers
    healthyPeers := 0
    for _, peer := range n.peers {
        if peer.healthy && time.Since(peer.lastSeen) < 5*time.Second {
            healthyPeers++
        }
    }
    // Partition if we can't reach majority of peers
    quorum := len(n.peers) / 2
    wasPartitioned := n.partitioned
    n.partitioned = healthyPeers < quorum
}
```

The partition detector runs on a 100ms tick and declares a partition when
fewer than a quorum of peers have been seen within 5 seconds. This is
deliberately more aggressive than the circuit breaker -- the system wants to
know about peer loss before the API server circuit opens.

**Key design principle**: partition detection uses a **separate channel** (direct
TCP peer connections) from the partitioned resource (Kubernetes API server). This
prevents the system from being blind to partitions that affect the detection
channel itself.

### 3.3 Phase 2: Local Consensus

Once a partition is detected, Sentinel's Raft-lite protocol enables reachable
peers to elect a local leader and make decisions. The protocol is a simplified
Raft designed for small edge clusters:

```go
type Decision struct {
    ID        string          `json:"id"`
    Type      DecisionType    `json:"type"`
    Timestamp time.Time       `json:"timestamp"`
    Term      uint64          `json:"term"`
    LeaderID  string          `json:"leader_id"`
    Payload   json.RawMessage `json:"payload"`
    Committed bool            `json:"committed"`
}
```

The decision types are scoped to operations that are safe to perform
autonomously:

| Decision Type | Description | Reversibility |
|---|---|---|
| `pod_reschedule` | Move pods away from failing node | Fully reversible |
| `node_cordon` | Mark node unschedulable | Fully reversible |
| `service_failover` | Redirect service endpoints | Reversible with reconciliation |
| `resource_scale` | Adjust resource limits | Reversible |

Decisions require quorum (`len(peers)/2 + 1` acknowledgements), even during
partition. This means a minority partition cannot make decisions -- only the
majority side can act. This is a critical safety property that prevents
conflicting actions from parallel partitions.

### 3.4 Phase 3: Autonomous Action

The `Migrator` (from `pkg/k8s/migrator.go`) executes the decisions:

```go
func (m *Migrator) RequestMigration(ctx context.Context, req MigrationRequest) (*MigrationResult, error) {
    m.mu.Lock()
    if m.inProgress {
        m.mu.Unlock()
        return nil, fmt.Errorf("migration already in progress")
    }
    m.inProgress = true
    // ...
    drainResult, err := m.client.DrainNode(ctx, req.GracePeriod)
    // ...
}
```

The migrator enforces single-flight execution (only one migration at a time)
and records full history for reconciliation. The migration pipeline is:

1. Cordon node (mark unschedulable)
2. List evictable pods (skip DaemonSets, mirror pods, terminal pods)
3. Sort by QoS priority (evict BestEffort first, Guaranteed last)
4. Evict pods with grace period
5. Record result (evicted count, failed count, errors)

### 3.5 Phase 4: Reconciliation

The `PartitionReconciler` runs after the partition heals:

```go
func (r *PartitionReconciler) Reconcile(ctx context.Context,
    actions []ReconciliationAction) (*ReconciliationResult, error) {
    // Check current node state from control plane
    node, err := r.client.GetNode(ctx)
    // ...
    for _, action := range actions {
        switch action.Type {
        case "cordon":
            // Verify cordon state matches expectation
        case "taint":
            // Verify taint is still present
        case "evict":
            // Evictions are final -- just log
        }
    }
}
```

The reconciler compares the decisions made during partition against the
current control plane state and identifies conflicts. It then decides
whether to roll back, roll forward, or flag for human review.

---

## 4. Mapping to Swarm-Team-Six

### 4.1 Architectural Correspondence

The two systems have different domains but structurally equivalent partition
problems. The following table maps Sentinel concepts to Swarm equivalents:

| Sentinel Concept | Swarm-Team-Six Equivalent | Notes |
|---|---|---|
| Kubernetes API server | Tom governance agents / Policy authority | Central authority that may become unreachable |
| Edge node | Whisker detection agent | Autonomous unit that detects and must respond |
| Raft-lite consensus | `swarm-consensus` (Tendermint-style BFT) | Local agreement among reachable agents |
| Circuit breaker (k8s) | `ResilientExecutor` circuit breaker | Detects backend unreachability; Sentinel uses 3-state (Closed/Open/HalfOpen), Swarm uses 2-state (threshold + cooldown) |
| Decision log | `swarm-spine` audit trail (`AuditTrail`) | Immutable record of autonomous decisions |
| `MigrationRequest` | `ActionRequest` | Structured request for autonomous action |
| `MigrationResult` | `ResponseReceipt` | Outcome record with success/failure |
| `PartitionReconciler` | (Not yet implemented) | Post-partition merge of decision logs |
| `DrainResult` | `DeadLetterJournal` entries | Records of actions taken or failed |
| Node cordon/taint | `BlockEgress`, `IsolateHost` | Containment actions |

### 4.2 Current Gap Analysis

Swarm-Team-Six has the building blocks but lacks the partition-specific
orchestration layer. Here is what exists and what is missing:

**Exists:**

- `StaticApprovalGate` -- deterministic policy evaluation, but no partition mode
- `CapabilityLease` -- time-bounded authorization tokens
- `ResilientExecutor` -- retry + circuit breaker for response adapters
- `DeadLetterJournal` -- durable record of failed executions
- `AuditTrail` / `ReplayBundle` -- full decision audit chain
- `swarm-spine` envelope signing and chain verification
- `GuardPipeline` -- fail-closed safety checks
- `AutonomyTier` -- defined tiers (Tier1: autonomous, Tier2: report, Tier3: human-approved)
- `swarm-consensus` crate -- module structure and doc comments define the BFT
  design (Tendermint-style propose-prevote-precommit), but the implementation
  is a TODO placeholder

**Missing:**

- Partition detection independent of the pheromone substrate
- Partition-mode policy gate that relaxes `RequireHuman` to bounded autonomous authority
- Pre-staged capability leases for partition scenarios
- Decision conflict resolution when multiple partitions rejoin
- Reconciliation protocol for merging divergent audit trails
- Split-brain prevention guarantees for destructive actions

### 4.3 How Policy Gate Decisions Should Work Under Partition

The current `PolicyVerdict` enum has three states:

```rust
pub enum PolicyVerdict {
    Deny,
    Allow,
    RequireHuman,
}
```

Under partition, `RequireHuman` becomes a blocking state with no resolution.
We propose extending the policy system with a partition-aware evaluation path:

```
Normal Mode:                    Partition Mode:
  Deny     -> Deny               Deny     -> Deny (invariant: never auto-allow denied actions)
  Allow    -> Allow              Allow    -> Allow (with partition receipt)
  RequireHuman -> wait           RequireHuman -> evaluate partition policy:
                                     - Has pre-delegated lease? -> Allow (bounded)
                                     - Severity >= Critical?    -> Allow (bounded, escalate on heal)
                                     - Otherwise                -> Deny (log for human review on heal)
```

This preserves the invariant that `Deny` is always respected (a hard safety
boundary) while converting `RequireHuman` into a conditional authorization
during partition.

---

## 5. Pre-Delegated Authority and Capability Lease Pre-Staging

### 5.1 The Pre-Delegation Model

The core idea: during normal operation, the Tom governance authority issues
**contingency leases** -- capability leases that are dormant during normal
operation but activate automatically when a partition is detected. This
transforms the partition response from "what should I do with no authority?"
to "which pre-authorized actions can I execute now?"

### 5.2 Lease Structure Extension

The current `CapabilityLease` in swarm-policy:

```rust
pub struct CapabilityLease {
    pub capability_id: String,
    pub expires_at_ms: i64,
    pub action: String,
    pub scope: Option<String>,
}
```

A partition-aware extension would add:

```rust
/// Extended capability lease with partition-awareness.
pub struct PartitionCapabilityLease {
    /// Base lease fields
    pub base: CapabilityLease,
    /// Activation condition: when does this lease become usable?
    pub activation: LeaseActivation,
    /// Maximum number of times this lease can be exercised
    pub max_uses: u32,
    /// Severity floor: only activates for threats at or above this level
    pub min_severity: Severity,
    /// Scope constraints: which targets this lease authorizes
    pub scope_constraints: Vec<ScopeConstraint>,
    /// Cryptographic signature from the issuing Tom agent
    pub issuer_signature: Vec<u8>,
    /// Chain reference: links back to the spine envelope that created this lease
    pub spine_envelope_hash: String,
}

pub enum LeaseActivation {
    /// Always active (normal lease behavior)
    Immediate,
    /// Active only when partition is detected
    OnPartition { min_duration_ms: i64 },
    /// Active only when specific threat conditions are met during partition
    OnPartitionWithThreat {
        min_duration_ms: i64,
        threat_classes: Vec<ThreatClass>,
    },
}
```

### 5.3 Pre-Staging Protocol

During normal operation, Tom agents evaluate the threat landscape and issue
contingency leases: `BlockEgress` for known-bad C2 ranges, `IsolateHost` for
hosts with active IOCs, `DeployDecoy` for elevated pheromone zones. Leases
are distributed to Pouncers via signed spine envelopes and stored locally,
expiring and renewing on a rolling basis (e.g., every 15 minutes).

The renewal period determines maximum staleness of autonomous authority -- a
tunable tradeoff between responsiveness and stale-policy risk.

### 5.4 Scope Constraints

Pre-delegated leases must be **narrowly scoped** via `ScopeConstraint` variants:
`ExactTarget(String)`, `CidrRange(String)`, `HostPattern(String)`, and critically
`MaxBlastRadius(u32)` -- which prevents a single lease from isolating an entire
network segment during partition, even if it technically authorizes `IsolateHost`
for matching hosts.

---

## 6. Decision Conflict Resolution

### 6.1 The Contradictory Decision Problem

When a network partitions into two or more segments, each segment may
independently detect threats and make response decisions. When the partition
heals, these decisions may be contradictory:

```
Partition A sees:              Partition B sees:
  Host-X acting suspicious       Host-X responding to remediation
  -> IsolateHost(Host-X)         -> No action on Host-X

Partition A sees:              Partition B sees:
  Egress to 203.0.113.10         Egress to 203.0.113.10 is legitimate
  -> BlockEgress(203.0.113.10)   -> Allow (no action)
```

### 6.2 Conflict Categories

| Conflict Type | Example | Risk | Resolution Strategy |
|---|---|---|---|
| **Agree-agree** | Both partitions isolate same host | Redundant work | Merge (idempotent) |
| **Act-silent** | One partition acts, other does nothing | Potential over-reaction | Validate action was justified |
| **Contradict** | One blocks, other allows same target | Security gap or over-block | Conservative merge (favor block) |
| **Scope overlap** | One blocks IP range, other blocks specific IP | Redundant partial overlap | Merge ranges |

### 6.3 Resolution Rules

Sentinel's reconciler uses a simple but effective set of rules:

1. **Cordon is idempotent**: if both sides cordoned the same node, the reconciled
   state is cordoned. The `CheckAndRecoverNode` method only uncordons if the
   node is healthy:

```go
func (r *PartitionReconciler) CheckAndRecoverNode(ctx context.Context,
    wasCordonedDuringPartition bool) error {
    // ...
    for _, cond := range node.Status.Conditions {
        if cond.Type == corev1.NodeReady && cond.Status != corev1.ConditionTrue {
            return fmt.Errorf("node not ready, keeping cordoned")
        }
        // ...also check MemoryPressure, DiskPressure
    }
    return r.client.UncordonNode(ctx)
}
```

2. **Evictions are irreversible**: once a pod is evicted, it is rescheduled by the
   control plane. The reconciler treats evictions as final facts.

3. **Taints require verification**: the reconciler checks if taints applied during
   partition are still present, flagging discrepancies for review.

For Swarm-Team-Six, the equivalent rules would be:

| Action | Idempotent? | Reversible? | Reconciliation |
|---|---|---|---|
| `BlockEgress` | Yes | Yes | Union of all block rules; review for over-blocking |
| `IsolateHost` | Yes | Yes | Keep isolated until human review confirms safety |
| `RevokeCredential` | No | Partially | Credential must be re-issued; flag for review |
| `DeployDecoy` | Yes | Yes | Merge decoy placements; remove duplicates |
| `Escalate` | Yes | N/A | Merge escalation records; deduplicate |

### 6.4 Decision Ordering via Term Numbers

Sentinel uses Raft term numbers (`Decision.Term` + `Decision.LeaderID`) to
establish total ordering. Higher terms take precedence; equal terms defer to
the majority partition.

For Swarm-Team-Six, the spine envelope's `seq` + `prev_envelope_hash` chain
provides cryptographically verifiable per-issuer ordering. During
reconciliation, chains from different partitions are interleaved by
`issued_at` timestamp and verified via `verify_chain_link()`, which checks
sequence continuity and prev_hash linkage.

---

## 7. Reconciliation Protocols

### 7.1 Sentinel's Approach: State-Based Reconciliation

Sentinel reconciles by comparing the **current state** (what the control plane
shows) against the **intended state** (what the partitioned nodes tried to
achieve). This is a state-based approach:

```go
func (r *PartitionReconciler) Reconcile(ctx context.Context,
    actions []ReconciliationAction) (*ReconciliationResult, error) {
    // 1. Fetch current state from control plane
    node, err := r.client.GetNode(ctx)
    // 2. For each action taken during partition:
    //    - Compare intended effect with current state
    //    - Flag conflicts where state diverged
    // 3. Return conflicts for human review
}
```

**Strengths**: Simple, deterministic, no complex merge logic.  
**Weaknesses**: Cannot handle cases where two partitions acted on the same
resource in conflicting ways -- it can only report the conflict, not
automatically resolve it.

### 7.2 CRDT-Based Alternative for Swarm-Team-Six

CRDTs (Conflict-free Replicated Data Types) offer a mathematically guaranteed
merge strategy that always converges, regardless of partition topology. For
security response, the relevant CRDT types are:

**G-Set (Grow-only Set) for Block Rules**: Block rules are monotonically
additive. Partition A blocks `{203.0.113.10, 198.51.100.0/24}`, Partition B
blocks `{203.0.113.10, 192.0.2.50}`, merged result is the union. You never
auto-remove a block that another partition added.

**Security-Biased LWW-Register for Host Isolation**: Standard LWW is dangerous
because a later "clear" could override an earlier "isolate." We need
security-biased merge that favors the more restrictive state:

```rust
fn merge_host_state(a: HostAction, b: HostAction) -> HostAction {
    match (a.action_type, b.action_type) {
        (Isolate, _) | (_, Isolate) => {
            if a.timestamp > b.timestamp { a } else { b }
                .with_action_type(Isolate) // Always keep Isolate
        }
        (Clear, Clear) => {
            if a.timestamp > b.timestamp { a } else { b }
        }
    }
}
```

**OR-Set for Credential Revocations**: Revocations observed by any partition
must be preserved. Partition A revokes `cred-123` on evidence of compromise;
Partition B takes no action. Merged result: revocation preserved.

### 7.3 Proposed Hybrid Protocol

For Swarm-Team-Six, we propose a hybrid reconciliation protocol that combines
Sentinel's state-based verification with CRDT merge semantics:

```
Phase 1: Chain Verification
  - Each partition submits its spine envelope chain
  - verify_chain_link() validates per-issuer chain integrity
  - Detect and flag any chain breaks (indicates tampering or data loss)

Phase 2: Decision Extraction
  - Extract all AuditTrail records from each partition
  - Group by target (host, IP, credential)
  - Classify each group by conflict type (agree/silent/contradict)

Phase 3: CRDT Merge
  - Block rules: G-Set union (always additive)
  - Host isolation: Security-biased LWW (favor restriction)
  - Credential revocation: OR-Set (preserve all observed revocations)
  - Decoy deployments: G-Set union (additive, deduplicate by zone)
  - Escalations: G-Set union (merge all, deduplicate by hunt_id)

Phase 4: Validation
  - Verify merged state against current system state
  - Flag contradictions between merged intent and actual state
  - Generate reconciliation report for human review

Phase 5: Application
  - Apply non-controversial merged actions automatically
  - Queue controversial items for human decision
  - Record reconciliation in spine as a signed reconciliation envelope
```

### 7.4 Decision Log Format for Reconciliation

The spine `AuditTrail` captures trail_id, hunt_id, detection, policy, and
response records. For reconciliation, we additionally need a `PartitionContext`
struct attached to each partition-mode audit trail: `partition_id`,
`reachable_peer_count`, `total_peer_count`, `used_contingency_lease`,
`contingency_lease_id`, and `partition_duration_ms`. This metadata enables
reconciliation to assess the confidence and authority level of each decision.

---

## 8. Circuit Breaker Patterns for Degraded Connectivity

### 8.1 Sentinel's Implementation

Sentinel implements a three-state circuit breaker (from `pkg/k8s/circuit_breaker.go`):

```
  CLOSED --failure (>= 5)--> OPEN --timeout (30s)--> HALF-OPEN
    ^                                                    |
    |  success resets                                    |
    |  failure counter         +-------failure (any)-----+
    |                          |                         |
    |                          v                         |
    |                        OPEN          success (>= 2)|
    +-----------------------------------------------------+
```

Configuration defaults for edge environments:

```go
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
    return &CircuitBreakerConfig{
        FailureThreshold: 5,
        SuccessThreshold: 2,
        Timeout:          30 * time.Second,
    }
}
```

The design choices here are deliberate:
- **5 failure threshold**: tolerates transient errors without over-reacting
- **2 success threshold in half-open**: requires sustained recovery, not just one lucky probe
- **30-second timeout**: long enough for brief network blips to resolve, short enough for responsive partition detection

### 8.2 Swarm-Team-Six's Implementation

The `ResilientExecutor` in `swarm-response/src/resilience.rs` implements a
circuit breaker for outbound response execution rather than inbound API calls.
Unlike Sentinel's three-state model (Closed/Open/HalfOpen with explicit
`SuccessThreshold`), the Swarm implementation uses a simpler two-state model:
the circuit is "open" when consecutive failures exceed a threshold AND the
most recent failure is within the cooldown window. Recovery is implicit --
the circuit re-closes when the cooldown expires, without requiring probe
successes:

```rust
fn circuit_is_open(&self) -> bool {
    let threshold = self.circuit_breaker.threshold;
    if self.state.consecutive_failures.load(Ordering::SeqCst) < threshold {
        return false;
    }
    self.last_failure_time()
        .as_ref()
        .is_some_and(|last_failure| {
            last_failure.elapsed() < Duration::from_millis(self.circuit_breaker.cooldown_ms)
        })
}
```

When the circuit opens, the executor returns a synthetic receipt:

```rust
fn circuit_open_receipt(
    &self,
    request: &ActionRequest,
    mode: ExecutionMode,
) -> ResponseReceipt {
    ResponseReceipt {
        receipt_id: format!("resp-circuit-open:{}:{}", request.hunt_id.0,
                           request.action.kind()),
        status: ResponseStatus::Failed,
        summary: format!("{} circuit breaker open", self.adapter),
        // ...
    }
}
```

### 8.3 Layered Circuit Breakers for Partition Detection

The combination of Sentinel's and Swarm's circuit breakers suggests a
**layered** approach where different circuit breakers detect different
types of degradation:

```
Layer 1: Response Adapter Circuit Breaker (swarm-response)
  - Detects: EDR platform unreachable, webhook endpoint down
  - Action: Switch to dead-letter journal, queue for retry
  - Does NOT indicate partition (external service may be down independently)

Layer 2: Pheromone Substrate Circuit Breaker (new)
  - Detects: NATS/JetStream unreachable, substrate write failures
  - Action: Buffer deposits locally, switch to local-only mode
  - MAY indicate partition (substrate is distributed)

Layer 3: Governance Bus Circuit Breaker (new)
  - Detects: Tom agents unreachable, policy updates stale
  - Action: Activate contingency leases, switch to partition policy mode
  - STRONG partition indicator

Layer 4: Peer Mesh Circuit Breaker (new, Sentinel-inspired)
  - Detects: Direct peer-to-peer connectivity loss
  - Action: Form local consensus group, elect local leader
  - DEFINITIVE partition indicator
```

Each layer independently tracks its circuit state. Partition confidence
increases with open circuit count: 0=Connected, 1=Degraded,
2=LikelyPartitioned, 3-4=Partitioned. This avoids single-signal false
positives while enabling rapid detection when multiple layers fail.

### 8.4 Exponential Backoff with Jitter

Sentinel implements exponential backoff with jitter for peer reconnection
(from `pkg/consensus/raft_lite.go`):

```go
func calculateBackoff(failures int, cfg backoffConfig) time.Duration {
    // ...
    delay := cfg.initialDelay
    for i := 0; i < failures && delay < cfg.maxDelay; i++ {
        delay = time.Duration(float64(delay) * cfg.multiplier)
    }
    if delay > cfg.maxDelay {
        delay = cfg.maxDelay
    }
    // Add jitter (10% of delay)
    jitter := time.Duration(mathrand.Int63n(int64(delay / 10)))
    return delay + jitter
}
```

The defaults (100ms initial, 30s max, 2x multiplier) produce delays from
200ms (1 failure) through 3.2s (5 failures) to 30s cap (9+ failures), with
10% jitter to prevent **thundering herd** reconnection storms when a partition
heals. This is directly applicable to Swarm-Team-Six's substrate reconnection.

---

## 9. Split-Brain Prevention in Security Context

### 9.1 The Security Split-Brain Problem

In generic distributed systems, split-brain means two partitions both believe
they are authoritative. In security systems, split-brain is more nuanced because
the two failure modes are asymmetric:

- **False Negative** (missed response): attacker succeeds because no partition
  had authority to act. This is the catastrophic failure mode.
- **False Positive** (redundant response): legitimate traffic blocked or host
  unnecessarily isolated. This is recoverable.

Therefore, split-brain prevention in security systems must be **biased toward
false positives** rather than false negatives. This is the opposite of most
distributed system designs.

### 9.2 Quorum-Based Safety in Sentinel

Sentinel's Raft-lite protocol uses majority quorum to prevent the minority
partition from making decisions:

```go
func (n *Node) ProposeDecision(ctx context.Context, ...) (*Decision, error) {
    // ...
    acks := 1 // Count self
    required := (len(n.peers) / 2) + 1
    // ...
    if acks >= required {
        // Commit decision
    }
    return nil, fmt.Errorf("failed to reach quorum: got %d, need %d", acks, required)
}
```

In a 5-node cluster, only the partition with 3+ nodes can make decisions.
This prevents conflicting actions but creates a problem: the minority partition
(2 nodes) is completely inert, even if it is the one under attack.

### 9.3 BFT Quorum for Swarm-Team-Six

The `swarm-consensus` crate (currently a placeholder) is designed for
Tendermint-style BFT with propose-prevote-precommit phases:

```rust
// From swarm-consensus/src/lib.rs
// Tolerates f Byzantine faults with 2f+1 agreement out of 3f+1 voters.
// TODO: Implement ConsensusRound, VRF-based committee rotation, signed vote tallying
```

BFT consensus is stronger than Raft (tolerates arbitrary failures, not just
crash failures) but requires a larger quorum (2/3 instead of 1/2). For a
swarm of 10 agents, Raft needs 6 for quorum while BFT needs 7. This means
BFT is **more conservative** about allowing autonomous action, which may be
appropriate for security-critical decisions.

### 9.4 Graduated Authority Based on Partition Geometry

Rather than a binary can-act/cannot-act split, we propose graduated authority
based on partition size and composition:

```
Partition Size as % of Swarm    Authority Level
-----------------------------   ----------------------------------------
>= 67% (BFT quorum)            Full autonomous authority (all actions)
>= 50% (Raft quorum)           Containment actions only (block, isolate)
>= 33%                         Detection + alerting only (deploy decoy, escalate)
< 33% (minority)               Detection only (log findings, no response)
Single agent (fully isolated)  Local defense only (self-protection actions)
```

This graduated model maps to the existing `AutonomyTier` in swarm-core, but
the mapping is inverted relative to tier numbering. Higher partition fractions
unlock higher-authority tiers:

```rust
pub enum AutonomyTier {
    Tier1,  // Fully autonomous (routine actions)    -- available at any partition size
    Tier2,  // Autonomous with reporting (novel)     -- requires >= 50% (Raft quorum)
    Tier3,  // Human-approved (response actions)     -- requires >= 67% (BFT quorum)
}
```

Under partition, the available tier ceiling decreases with partition size:
a >= 67% partition can execute up to Tier3 actions autonomously, a >= 50%
partition is capped at Tier2, and smaller fragments are limited to Tier1
detection and alerting.

### 9.5 The Fully Isolated Agent Problem

Sentinel's quorum requirement (`healthyPeers < quorum`) means a lone agent
cannot achieve quorum and therefore cannot act. For security, this is
unacceptable -- a fully isolated agent detecting an active intrusion must
retain some capability.

The solution is **pre-delegated authority with escalating scope restrictions**:
full swarm = all authorized actions; majority partition = all actions with
partition receipt; minority partition = containment only (block, isolate);
**fully isolated** = self-protection only (log findings, block known-bad
egress from pre-loaded IOC list, send emergency beacon, but DO NOT isolate
other hosts or revoke credentials without peer verification).

### 9.6 Preventing False Positive Cascades

Biasing toward availability risks a **false positive cascade** where
partitioned agents over-react. Sentinel prevents this via the `Migrator`'s
single-flight constraint (`m.inProgress` mutex). For Swarm-Team-Six:

1. **Rate limiting**: at most N response actions per partition interval
2. **Blast radius limits**: leases specify `MaxBlastRadius`
3. **Escalation-only mode**: after action limit, switch to detect + alert only
4. **Guard pipeline enforcement**: the `GuardPipeline` runs regardless of
   partition state, using `catch_unwind` to fail closed on any panic. No
   pre-delegated lease or autonomous decision can bypass the guard pipeline.

---

## 10. Formal Safety Properties

### 10.1 Invariants That Must Hold Under Partition

We define the safety properties that the autonomous response system must
maintain, even during partition. These are expressed as temporal logic
properties over the system's state:

**INV-1: Guard Pipeline Inviolability**
```
ALWAYS: for all actions a, if GuardPipeline.evaluate(a) = Block, then a is not executed.
```
No partition mode, pre-delegated lease, or autonomous decision can override
a guard pipeline rejection. The guard pipeline is the absolute floor of
safety.

**INV-2: Lease Scope Enforcement**
```
ALWAYS: for all executions e using lease l, e.target IN l.scope_constraints.
```
A pre-delegated lease authorizes specific scopes. The execution layer must
verify scope membership before acting, even when the governance authority
is unreachable.

**INV-3: Deny Verdict Persistence**
```
ALWAYS: if StaticApprovalGate.evaluate(r) = Deny in any mode, then r is not executed.
```
The `Deny` verdict is never overridden by partition logic. Partition mode
only affects `RequireHuman` verdicts.

**INV-4: Audit Trail Completeness**
```
ALWAYS: for all executed actions a, EXISTS audit_trail t where t.action = a.
```
Every action taken during partition must have a corresponding audit trail
entry that survives the partition and is available for reconciliation.

**INV-5: Monotonic Restriction Under Isolation**
```
As isolation increases (fewer reachable peers), available action scope
monotonically decreases.
```
A more isolated agent can never have more authority than a less isolated one.
This prevents an attacker from isolating an agent to expand its autonomous
authority.

**INV-6: Bounded Action Count**
```
During any partition of duration D, the total number of autonomous response
actions is bounded by f(D, partition_size, pre_delegated_leases).
```
Autonomous actions during partition are bounded, not unbounded. This prevents
infinite cascade.

### 10.2 Liveness Properties

- **LIVE-1 (Detection Never Stops)**: If threat T occurs in agent A's scope, A produces a finding within bounded time. Detection continues regardless of partition.
- **LIVE-2 (Reconciliation Completes)**: When partition heals, reconciliation terminates and produces a result within bounded time.
- **LIVE-3 (Authority Restoration)**: When partition heals, autonomous authority is relinquished and normal governance resumes.

### 10.3 Proof Sketch for INV-1

The guard pipeline's inviolability holds because of two properties:

1. **No external dependencies.** `GuardPipeline::evaluate()` is a pure
   synchronous function of the action, guard context, and guard configuration.
   It makes no network calls, so partition state cannot affect its evaluation.

2. **Fail-closed by construction.** The pipeline wraps each guard in
   `catch_unwind(AssertUnwindSafe(...))` and returns `GuardResult::block` on
   any panic. An empty guard name also triggers a block. Short-circuit
   evaluation halts on the first rejection.

The guard pipeline is evaluated in the runtime *before* the action reaches
the `DispatchingExecutor -> ResilientExecutor -> adapter` chain. A `Block`
result prevents the executor from being invoked at all. Because the pipeline
sits upstream of the executor and has no partition-sensitive inputs, INV-1
holds regardless of connectivity state.

---

## 11. Industry Precedents

### 11.1 CrowdStrike Falcon: Disconnected Endpoint Behavior

Falcon maintains a **local prevention policy cache** (24-72 hour staleness
window) with pre-loaded IOC lists and local ML models. Response actions
(isolate host, kill process) execute locally when the cloud is unreachable.
All actions are logged locally and synchronized on reconnection.

**Relevance**: Validates the pre-delegated authority model. Falcon's local
policy cache is functionally equivalent to pre-staged contingency leases.

### 11.2 Microsoft Defender for Endpoint: Offline Response

Defender distinguishes "automated response" (continues offline with local
policy) from "live response" (requires cloud connectivity). Detection and
forensic collection continue to local storage. Delta sync uploads telemetry
on reconnection.

**Relevance**: The automated/live distinction maps to our graduated authority
model: Tier 1 actions continue autonomously; Tier 3 actions require reconnection.

### 11.3 SentinelOne: Autonomous Endpoint Protection

SentinelOne treats cloud connectivity as an enhancement, not a requirement.
The local AI engine classifies threats independently. Responses (quarantine,
kill, remediate) and snapshot-based rollback all operate without cloud.

**Relevance**: Demonstrates that fully autonomous endpoint response is
commercially proven -- equivalent to always running in "partition mode."

### 11.4 Kubernetes PDBs and Google BeyondCorp

**PDBs** provide "bounded autonomous action": they define how many pods can
be simultaneously disrupted and the eviction API enforces this independently
of the requester. Sentinel respects PDBs through the eviction API.
Swarm-Team-Six should implement an analogous **Response Disruption Budget**.

**BeyondCorp** caches policy decisions with configurable TTL for degraded
operation. The key insight: access control fails closed (deny when uncertain)
but threat response must fail open (respond when uncertain) because missed
threats have unbounded cost while over-response is recoverable.

---

## 12. Reference Architecture for Partition-Aware Swarm Response

### 12.1 System Diagram

```
NORMAL:     Whisker -> Pheromone Substrate -> Tom Governance -> Pouncer Execution
                |              |                   |                  |
                v              v                   v                  v
            AuditTrail    Signed Envelopes    PolicyDecisions   ResponseReceipts

PARTITION:  Whisker -> Local Pheromone Buffer -> Partition Policy Gate -> Pouncer (bounded)
                |              |                      |                       |
                v              v                      v                       v
            Local Audit   BFT Consensus         Decision Log w/         Dead Letter
                                                Partition Context        Journal

RECONCILE:  Merge Decision Logs -> CRDT Conflict Resolution -> Validate vs Current State
                ^                                                     |
            Chain Verify                                   Apply or Queue for Human Review
```

### 12.2 Component Responsibilities

| Component | Normal Mode | Partition Mode | Reconciliation |
|---|---|---|---|
| **Whisker Detection** | Deposit pheromones to substrate | Deposit to local buffer + local substrate segment | Replay buffered deposits |
| **Pheromone Substrate** | Shared NATS-backed substrate | Local in-memory segment | Merge segments via CRDT |
| **Policy Gate** | `StaticApprovalGate` with human gate | Partition-aware gate using contingency leases | Return to normal gate |
| **Guard Pipeline** | Evaluate all guards | Evaluate all guards (unchanged) | Evaluate all guards (unchanged) |
| **Response Executor** | `ResilientExecutor` with retry + CB | Same, with dead-letter for unreachable targets | Replay dead-letter entries |
| **Consensus** | BFT among all Tom agents | BFT among reachable agents (graduated quorum) | Merge consensus logs |
| **Audit Trail** | Spine envelopes to central store | Local signed envelopes with partition context | Chain verification + merge |

### 12.3 State Machine for Agent Partition Mode

```
NORMAL --(CB layers 3+4 open)--> DEGRADED --(peer mesh CB open)--> PARTITION MODE
   ^                                                                     |
   |                                                              (healed or timeout)
   +--- NORMAL <--(resume full policy)-- HEALING --(reconcile logs)------+
```

States: **NORMAL** (full policy), **DEGRADED** (buffer deposits, CB accumulating),
**PARTITION MODE** (contingency leases active, autonomous bounded response),
**HEALING** (reconcile decision logs, verify chain integrity, apply or queue).

### 12.4 Configuration Surface

Proposed additions to `SwarmConfig`:

```rust
pub struct PartitionConfig {
    pub partition_detection_delay_ms: i64,
    pub max_partition_duration_ms: i64,
    pub contingency_lease_renewal_ms: i64,
    pub contingency_lease_ttl_ms: i64,
    pub max_autonomous_actions_per_partition: u32,
    pub quorum_thresholds: QuorumThresholds,  // full=0.67, containment=0.50, detect=0.33
    pub autonomous_action_allowlist: Vec<String>,
    pub reconciliation_strategy: ReconciliationStrategy,  // CrdtWithHumanReview | FullHumanReview | HybridByActionType
}
```

### 12.5 Integration Points with Existing Crates

The implementation touches the following existing crates:

| Crate | Changes |
|---|---|
| `swarm-policy` | Add `PartitionApprovalGate` implementing `ApprovalGate` trait; extend `CapabilityLease` with activation conditions |
| `swarm-response` | Add partition receipt annotation; extend `ResilientExecutor` with partition-aware dead-letter behavior |
| `swarm-spine` | Add `PartitionContext` to `AuditTrail`; add reconciliation envelope type; add CRDT merge functions for envelope chains |
| `swarm-guard` | No changes (guard pipeline is partition-independent by design) |
| `swarm-consensus` | Implement the BFT protocol with graduated quorum support |
| `swarm-core` | Add `PartitionConfig` to `SwarmConfig`; add `PartitionState` to agent environment |
| `swarm-pheromone` | Add local buffering mode; add CRDT merge for substrate segments |
| `swarm-runtime` | Add partition detection loop; add reconciliation orchestration; add contingency lease management |

---

## 13. Conclusion and Recommendations

### 13.1 Key Takeaways

1. **Partition is the attack surface**: Security systems that stop functioning
   during partition are vulnerable by design. Autonomous response under
   partition is not a nice-to-have -- it is a security requirement.

2. **Availability for detection, bounded authority for response**: During
   partition, the system should preserve detection/reporting availability, while
   keeping consequential response fail-closed unless a narrow contingency lease
   explicitly authorizes it. Consistency is restored during reconciliation.

3. **Pre-delegated authority works**: Sentinel's model of making decisions during
   partition, combined with industry precedents from CrowdStrike, Microsoft,
   and SentinelOne, validates that pre-staged autonomous authority is both
   practical and commercially proven.

4. **Guard pipeline is the safety floor**: The fail-closed guard pipeline in
   `swarm-guard` provides an unconditional safety boundary that holds regardless
   of partition state, consensus outcome, or autonomous decision. This is the
   system's most important invariant.

5. **Graduated authority prevents cascades**: Rather than binary act/don't-act,
   graduated authority based on partition geometry provides proportional response
   capability while limiting blast radius.

6. **CRDT-based reconciliation automates conflict resolution**: State-based
   reconciliation (Sentinel's approach) is simple and sufficient for single-resource
   conflicts but cannot automatically resolve contradictions across partitions.
   CRDT-based reconciliation with security-biased merge semantics provides
   deterministic convergence at the cost of additional implementation complexity,
   making it the right choice for multi-partition swarm scenarios.

### 13.2 Implementation Priority

| Priority | Component | Effort | Impact |
|---|---|---|---|
| P0 | Partition detection (layered circuit breakers) | Medium | Enables all partition-aware behavior |
| P0 | Contingency lease pre-staging | Medium | Core autonomous authority mechanism |
| P1 | `PartitionApprovalGate` | Small | Connects detection to authorization |
| P1 | Partition context in audit trail | Small | Enables reconciliation |
| P1 | Local pheromone buffering | Medium | Maintains detection during partition |
| P2 | BFT consensus implementation | Large | Enables coordinated autonomous response |
| P2 | CRDT-based reconciliation | Large | Automates post-partition merge |
| P3 | Graduated authority model | Medium | Refines blast radius control |
| P3 | Response disruption budget | Small | Additional cascade prevention |

### 13.3 Open Questions

1. **Lease staleness threshold**: Maximum acceptable contingency lease age (15min? 24h per CrowdStrike?) depends on deployment context.
2. **Adversarial partition detection**: Distinguishing infrastructure vs. adversarial partitions may require different response aggressiveness.
3. **Multi-partition reconciliation**: 3+ partition fragments increase operational complexity; CRDT commutativity ensures correctness regardless of merge order.
4. **Cryptographic freshness**: Should leases include offline-capable revocation if the signing Tom keypair is compromised during partition?
5. **Regulatory compliance**: Audit trail must demonstrate autonomous action was both necessary and bounded to satisfy frameworks requiring human approval.

---

## Appendix A: Source File Index

**Sentinel** (`playground/sentinel/`): `pkg/consensus/raft_lite.go` (consensus), `pkg/k8s/circuit_breaker.go` (circuit breaker), `pkg/k8s/client.go` (K8s operations), `pkg/k8s/migrator.go` (migration + reconciliation), `pkg/healthscore/predictor.go` (failure prediction).

**Swarm-Team-Six** (`standalone/swarm-team-six/crates/`): `swarm-policy/src/{lib,static_gate}.rs` (policy gate + leases), `swarm-response/src/{lib,dispatch,resilience,dead_letter}.rs` (execution + resilience), `swarm-spine/src/{lib,envelope,chain,checkpoint}.rs` (audit trail + chain verification), `swarm-guard/src/lib.rs` (guard pipeline), `swarm-consensus/src/lib.rs` (BFT placeholder), `swarm-core/src/{types,verdict,agent,pheromone}.rs` (core types), `swarm-runtime/src/escalation.rs` (concentration monitoring).

## Appendix B: Glossary

- **BFT**: Byzantine Fault Tolerance -- consensus tolerating arbitrary failures
- **Contingency Lease**: Pre-delegated capability lease activating during partition
- **CRDT**: Conflict-free Replicated Data Type -- deterministic merge guarantees
- **Dead Letter**: Failed action record preserved for retry or audit
- **Guard Pipeline**: Ordered safety checks that fail closed on any rejection/error/panic
- **Pheromone**: Stigmergic signal deposited by agents for threat communication
- **Raft-lite**: Sentinel's simplified Raft for small edge clusters
- **Reconciliation**: Merging divergent decision logs after partition heals
- **Spine Envelope**: Cryptographically signed audit record with chain integrity
- **Tom/Whisker Agent**: Governance/detection roles in the swarm

---

## Cross-References

This document is part of the Sentinel Convergence Research series.

| # | Document | Relevance to This Document |
|---|----------|---------------------------|
| 01 | [Distributed Consensus for Autonomous Agent Swarms](01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) | Foundation for the Raft-lite and BFT consensus protocols discussed in Sections 3.3 and 9.2-9.3 |
| 02 | [Predictive Infrastructure Failure as a Threat Signal](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | Sentinel's failure prediction feeds the partition detection signals analyzed in Section 3.2 |
| 03 | [Edge-Native Security Detection](03-EDGE-NATIVE-SECURITY-DETECTION.md) | Covers the detection layer that must continue operating autonomously during partition (Section 9.5, LIVE-1) |
| 05 | [Telemetry Bridge Architecture](05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Defines the `swarm-ingest-sentinel` bridge whose telemetry flow is disrupted by the partitions modeled here |
| 06 | [Stigmergic Coordination and Swarm Intelligence](06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) | Pheromone substrate partitioning (Section 8.3, Layer 2) and local buffering (Section 12.2) |
| 07 | [Audit Trails and Decision Reconciliation](07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md) | Deep treatment of the reconciliation protocols introduced in Sections 7.1-7.4 |
| 08 | [Resilience Patterns for Distributed Agent Systems](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) | Generalizes the circuit breaker and backoff patterns from Section 8 across both projects |
