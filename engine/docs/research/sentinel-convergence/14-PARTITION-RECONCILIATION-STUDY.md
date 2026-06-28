# 14 -- Partition Reconciliation Study

## Concrete Reconciliation Protocol for Lease Lifecycle, Rollback, and Post-Heal Review

| Metadata    | Value                                                          |
|-------------|----------------------------------------------------------------|
| **Version** | 1.0                                                            |
| **Date**    | 2026-04-07                                                     |
| **Status**  | Proposed                                                       |
| **Series**  | Sentinel Convergence Research (supplemental)                   |
| **Authors** | Sentinel + Swarm convergence working group                     |
| **Scope**   | Fills the data-flow gap between doc-11 (partition authority matrix) and doc-07 (audit trails and decision reconciliation) |

> **Gap Statement**
> Doc-11 defines *what* autonomous actions are permitted during partition.
> Doc-07 defines *how* decisions are recorded with signed envelopes and Merkle proofs.
> Neither specifies how lease activation, action execution, rollback, and
> post-heal operator review are concretely recorded and replayed. This document
> fills that gap with exact envelope payload types, rollback mechanics, a
> step-by-step reconciliation sequence, and a comparison to Sentinel's
> `PartitionReconciler`.

---

## Table of Contents

1. [Lease Lifecycle Audit Trail](#1-lease-lifecycle-audit-trail)
2. [Rollback Protocol](#2-rollback-protocol)
3. [Post-Heal Reconciliation Sequence](#3-post-heal-reconciliation-sequence)
4. [Operator Review Interface](#4-operator-review-interface)
5. [Replay Correctness](#5-replay-correctness)
6. [Sentinel Comparison](#6-sentinel-comparison)

---

## 1. Lease Lifecycle Audit Trail

Every contingency lease from doc-11 (BlockEgress, soft-IsolateHost, DeployDecoy,
Escalate) produces a sequence of signed envelopes across its lifecycle. These
envelopes chain into the agent's existing per-issuer spine chain via
`prev_envelope_hash`, ensuring no gap between normal-mode and partition-mode audit
records.

### 1.1 Envelope Payload Types

All partition-mode envelopes use the existing `build_signed_envelope` function from
`swarm-spine/src/envelope.rs`. The `fact` field carries a typed JSON payload whose
`type` string determines the schema. Below are the Rust types that serialize into
those payloads.

```rust
use serde::{Deserialize, Serialize};
use swarm_core::types::{ResponseAction, Severity};

/// Emitted when the agent detects partition. Always the first partition-mode
/// envelope. Anchors the partition episode to the pre-partition chain head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionDetectedFact {
    pub r#type: String,              // "partition.detected.v1"
    pub agent_id: String,
    pub pre_partition_checkpoint_hash: String,
    pub pre_partition_chain_seq: u64,
    pub detected_at: String,         // RFC 3339
    pub detection_sources: Vec<String>,
    pub initial_tier: u8,            // Always 0
}

/// Emitted when a pre-staged contingency lease transitions from dormant to active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseActivationFact {
    pub r#type: String,              // "partition.lease_activation.v1"
    pub lease_id: String,
    pub action_class: String,        // "block_egress" | "isolate_host" | "deploy_decoy"
    pub min_severity: Severity,
    pub max_uses: u32,
    pub expires_at_ms: i64,
    pub scope_summary: String,
    pub lease_origin_envelope_hash: String,
    pub issuer_signature_hex: String, // Tom agent's Ed25519 sig over lease fields
}

/// Emitted each time a lease is exercised. One per use. Links to activation envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseActionFact {
    pub r#type: String,              // "partition.lease_action.v1"
    pub lease_id: String,
    pub action: ResponseAction,
    pub severity_at_execution: Severity,
    pub use_number: u32,             // 1-indexed
    pub remaining_uses: u32,
    pub blast_radius_consumed: BlastRadiusSnapshot,
    pub hunt_id: String,
    pub response_receipt_id: Option<String>,
    pub activation_envelope_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusSnapshot {
    pub ips_blocked_this_action: u32,  pub ips_blocked_total: u32,
    pub hosts_isolated_this_action: u32, pub hosts_isolated_total: u32,
    pub decoys_deployed_this_action: u32, pub decoys_deployed_total: u32,
    pub leases_consumed_total: u32,
}

/// Emitted when a lease can no longer be used (exhausted, expired, or partition healed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseTerminationFact {
    pub r#type: String,              // "partition.lease_termination.v1"
    pub lease_id: String,
    pub reason: LeaseTerminationReason, // Exhausted | Expired | PartitionHealed
    pub uses_consumed: u32,
    pub max_uses: u32,
    pub activation_envelope_hash: String,
    pub last_action_envelope_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseTerminationReason { Exhausted, Expired, PartitionHealed }

/// Emitted when the agent transitions between escalation tiers (doc-11, Section 5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierTransitionFact {
    pub r#type: String,              // "partition.tier_transition.v1"
    pub from_tier: u8,
    pub to_tier: u8,
    pub transitioned_at: String,
    pub minutes_since_partition: f64,
    pub capabilities: Vec<String>,
    pub active_leases_remaining: u32,
}
```

### 1.2 Envelope Emission Sequence

Concrete example -- Pouncer uses a `BlockEgress` lease twice during a 25-minute partition:

```
 ...E(seq=48, normal) --> E(seq=49, PartitionDetectedFact)
                          --> E(seq=50, LeaseActivationFact: block_egress, max_uses=10)
                          --> E(seq=51, LeaseActionFact: BlockEgress 10.0.1.45, use 1/10)
                          --> E(seq=52, LeaseActionFact: BlockEgress 10.0.1.46, use 2/10)
                          --> E(seq=53, LeaseTerminationFact: PartitionHealed, 2/10 used)
                          --> E(seq=54, PartitionHealedFact)
```

Every envelope is Ed25519-signed, hash-chained via `prev_envelope_hash`, and
monotonically sequenced. Inserting, removing, or reordering any envelope breaks
chain verification in `swarm-spine/src/chain.rs`.

### 1.3 Escalate Action (No Lease Required)

Escalate actions (R5 from doc-11) do not consume a lease. They are recorded as
standard `AuditTrail` entries wrapped in spine envelopes. During partition, escalation
records are buffered locally and flushed on heal. The envelope `fact` uses the existing
`AuditTrail` schema with an added `partition_context` field containing the partition
episode ID and current tier.

---

## 2. Rollback Protocol

Doc-11's matrix specifies reversible actions. This section defines the rollback
mechanics, triggers, and audit recording for each.

### 2.1 Rollback Actions Per Response Type

| Original Action | Rollback Action | Reversible? | Rollback Mechanism |
|----------------|-----------------|-------------|-------------------|
| **BlockEgress** (target IP) | Remove firewall/ACL rule; flush conntrack entry | Yes | API call to firewall controller to delete the rule matching the original target |
| **Soft-IsolateHost** (block egress from host) | Re-enable host egress; verify host health | Yes, with health check | Remove host-specific egress block rules; run health probe before declaring host recovered |
| **DeployDecoy** (honeypot/canary) | Tear down decoy assets; remove DNS/route entries | Yes | API call to decoy controller; DNS record deletion |
| **RevokeCredential** | N/A | No | Forbidden during partition (doc-11, Section 6.1) |
| **Escalate** | N/A | N/A | Append-only; cannot and need not be rolled back |

### 2.2 Rollback Triggers

Rollback is triggered by exactly one of three conditions:

1. **Partition heals and operator ratifies rollback** (Section 3, Step 6). The
   operator reviews the autonomous action and decides it should be reversed.

2. **Partition heals and policy replay rejects the action** (Section 3, Step 3).
   The authority replays the decision against current policy and determines it
   would not have been approved.

3. **Lease expires during partition** (doc-11, Section 4.3). Lease expiry does
   NOT auto-trigger rollback. The action's effect persists until partition heals
   and an explicit rollback decision is made. Rationale: auto-rollback on expiry
   could re-expose a compromised host to C2 communication with no human in the loop.

**Rollback is never automatic.** Even when policy replay says "would not approve",
the rollback is queued for operator confirmation. The only exception: if the operator
has pre-configured an auto-rollback policy for specific action classes at specific
severity levels.

### 2.3 Rollback Envelope Types

```rust
/// Emitted when a rollback is initiated for a partition-mode action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackInitiatedFact {
    pub r#type: String,              // "partition.rollback_initiated.v1"
    pub rollback_id: String,
    pub original_action_envelope_hash: String,
    pub original_action: ResponseAction,
    pub trigger: RollbackTrigger,
    pub authorized_by: RollbackAuthorizer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackTrigger {
    OperatorReview { operator_id: String, review_item_id: String },
    PolicyReplayRejection { replay_verdict: String, rule_name: String },
    AutoRollbackPolicy { policy_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackAuthorizer {
    Operator { operator_id: String },
    AuthorityWithPreApproval { policy_id: String },
}

/// Emitted when rollback execution completes (success or failure).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollbackCompletedFact {
    pub r#type: String,              // "partition.rollback_completed.v1"
    pub rollback_id: String,
    pub original_action_envelope_hash: String,
    pub outcome: RollbackOutcome,
    pub response_receipt_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackOutcome {
    Success,
    Failed { error: String },
    Unnecessary { reason: String },
}
```

### 2.4 Rollback Failure Handling

When rollback fails (e.g., firewall API unreachable): a `RollbackCompletedFact`
with `outcome: Failed { error }` is emitted, the review item escalates to
`Investigate`, and the system retries on a backoff schedule (1min, 5min, 15min,
1hr). Each retry emits a new `RollbackInitiatedFact` / `RollbackCompletedFact`
pair. After 3 failed retries, the item is flagged `ManualInterventionRequired`.

---

## 3. Post-Heal Reconciliation Sequence

When connectivity is restored, the following six-step protocol executes. The
sequence diagram below shows the data flow between the partitioned agent
(Pouncer), the authority service (Tom/governance bus), and the operator.

### 3.1 Sequence Diagram

```
  Pouncer                    Authority                      Operator
     |                           |                              |
  [Partition heals]              |                              |
     |--1: PartitionDecisionLog->|                              |
     |   (envelopes+checkpoint)  |                              |
     |                     2: Verify chain (sigs, hashes, seq)  |
     |                     3: Policy replay per action           |
     |                     4: Cross-agent conflict detection     |
     |                     5: Build review queue                 |
     |                           |------- ReviewItems --------->|
     |                           |                        6: Ratify/Rollback/Investigate
     |                           |<------ Dispositions ---------|
     |<--- RollbackOrders -------|                              |
     |  Execute, emit envelopes  |                              |
     |--- Confirmations -------->|--- FinalReport ------------->|
```

### 3.2 Step 1: Submit Partition Decision Log

The agent submits all envelopes emitted during the partition episode as a
`PartitionDecisionLog`.

```rust
/// Submitted by the Pouncer to the authority on partition heal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionDecisionLog {
    pub agent_id: String,
    /// All signed envelopes from PartitionDetectedFact through PartitionHealedFact.
    /// JSON Values matching swarm-spine's envelope schema.
    pub envelopes: Vec<serde_json::Value>,
    /// Local checkpoint statement covering the partition-mode envelopes.
    pub partition_checkpoint: serde_json::Value,
    /// Witness signature from the agent over the checkpoint.
    pub checkpoint_witness: serde_json::Value,
    /// Hash of the last pre-partition checkpoint (anchoring point).
    pub pre_partition_checkpoint_hash: String,
    /// Agent's chain head after the last partition envelope.
    pub chain_head: IssuerChainHead,
}

/// Emitted as envelope fact when partition heals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionHealedFact {
    /// "partition.healed.v1"
    pub r#type: String,
    pub agent_id: String,
    pub partition_duration_seconds: u64,
    pub max_tier_reached: u8,
    pub total_leases_consumed: u32,
    pub total_actions_taken: u32,
    pub total_blast_radius: BlastRadiusSnapshot,
    /// Envelope hash of the PartitionDetectedFact that started this episode.
    pub partition_detected_envelope_hash: String,
}
```

### 3.3 Step 2: Verify Chain Integrity

The authority runs the following checks using existing swarm-spine primitives:

```rust
use swarm_spine::{verify_envelope, verify_chain_link, chain_head_from_envelope,
                  verify_witness_signature, checkpoint_hash};

/// Result of verifying a partition decision log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationResult {
    pub agent_id: String,
    pub envelopes_verified: u64,
    pub chain_valid: bool,
    pub signatures_valid: bool,
    pub checkpoint_valid: bool,
    pub lease_signatures_valid: bool,
    /// Non-empty if any check failed.
    pub errors: Vec<ChainVerificationError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationError {
    pub envelope_seq: u64,
    pub error_type: String, // "signature_invalid", "chain_break", "seq_gap", etc.
    pub detail: String,
}
```

Verification procedure: (1) `verify_envelope()` on each envelope for Ed25519 + SHA-256.
(2) `verify_chain_link()` on consecutive pairs for `prev_envelope_hash` and `seq`.
(3) Confirm first partition envelope links to `pre_partition_checkpoint_hash`.
(4) Rebuild Merkle tree from envelopes, compare root against checkpoint.
(5) `verify_witness_signature()` on the checkpoint witness.
(6) For each `LeaseActivationFact`, verify `issuer_signature_hex` against Tom's pubkey.

### 3.4 Step 3: Policy Replay

For each `LeaseActionFact` envelope, the authority extracts the original
`ActionRequest` and re-evaluates it against the current policy configuration.

```rust
/// Result of replaying one partition action against current policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyReplayResult {
    /// Envelope hash of the LeaseActionFact being replayed.
    pub action_envelope_hash: String,
    pub original_action: ResponseAction,
    pub original_severity: Severity,
    /// What the current policy gate would return for this request.
    pub current_verdict: PolicyVerdict,
    pub current_rule_name: String,
    pub current_reason: String,
    /// Did the original partition-mode decision align with current policy?
    pub aligned: bool,
}
```

An action is `aligned` if the current policy would produce `Allow` for the same
request. If current policy returns `Deny` or `RequireHuman`, the action is flagged
for operator review.

### 3.5 Step 4: Conflict Detection

The authority collects `PartitionDecisionLog` submissions from all agents that
were partitioned and checks for cross-agent conflicts.

```rust
/// A conflict detected between two partition-mode actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionConflict {
    pub conflict_id: String,
    pub conflict_type: PartitionConflictType,
    pub agent_a: String,
    pub agent_b: String,
    pub action_a_envelope_hash: String,
    pub action_b_envelope_hash: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionConflictType {
    /// Both agents acted on the same target (e.g., both blocked same IP).
    DuplicateAction,
    /// Agents took contradictory actions (one blocked, one would have unblocked).
    Contradiction,
    /// Aggregate blast radius across agents exceeds per-episode caps from doc-11.
    BlastRadiusOverflow,
}
```

Conflict detection rules: (1) **DuplicateAction** -- same resource targeted by
multiple agents; resolve via G-Set union (doc-11 Appendix B), deduplicate on merge.
(2) **Contradiction** -- one agent's action conflicts with another's (e.g., blocking
an IP that a decoy needs); flag for operator review. (3) **BlastRadiusOverflow** --
aggregate `blast_radius_consumed` exceeds doc-11 Section 3.2 caps; operator decides
which actions to keep.

### 3.6 Step 5: Operator Review Queue

The authority builds a `ReconciliationReviewQueue` from the results of steps 2-4.
See Section 4 for the data structure.

### 3.7 Step 6: Rollback or Ratification

For each review item, the operator selects a disposition. The authority emits:

```rust
/// Recorded when the authority finalizes the disposition of a partition action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationDispositionFact {
    /// "partition.reconciliation_disposition.v1"
    pub r#type: String,
    pub review_item_id: String,
    pub action_envelope_hash: String,
    pub disposition: ReconciliationDisposition,
    pub decided_by: String,  // operator_id or "authority:auto"
    pub decided_at: String,
    /// For rollbacks: the rollback_id linking to RollbackInitiatedFact.
    pub rollback_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationDisposition {
    /// Action was appropriate. No rollback. Becomes permanent record.
    Ratified,
    /// Action should be reversed. Triggers rollback protocol (Section 2).
    Rollback,
    /// Action requires deeper investigation before disposition.
    Investigate,
}
```

---

## 4. Operator Review Interface

### 4.1 Review Item Data Structure

```rust
/// One item in the operator's reconciliation review queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationReviewItem {
    // ---- Identity ----
    pub review_item_id: String,
    pub agent_id: String,
    pub partition_episode_id: String,

    // ---- Original Threat Context ----
    pub hunt_id: String,
    pub detection_summary: String,
    pub threat_severity: Severity,
    pub threat_confidence: f64,
    pub threat_evidence_hash: String,

    // ---- Action Taken ----
    pub action: ResponseAction,
    pub action_envelope_hash: String,
    pub executed_at: String,

    // ---- Lease Used ----
    pub lease_id: String,
    pub lease_action_class: String,
    pub lease_use_number: u32,
    pub lease_max_uses: u32,
    pub lease_time_remaining_at_execution_secs: i64,

    // ---- Blast Radius ----
    pub blast_radius_this_action: BlastRadiusSnapshot,
    pub blast_radius_cumulative: BlastRadiusSnapshot,
    pub blast_radius_percentage_of_cap: f64,

    // ---- Policy Replay ----
    pub current_policy_would_approve: bool,
    pub current_policy_verdict: PolicyVerdict,
    pub current_policy_rule: String,
    pub current_policy_reason: String,

    // ---- Conflicts ----
    pub conflicts: Vec<PartitionConflict>,

    // ---- Recommended Disposition ----
    pub recommended_disposition: ReconciliationDisposition,
    pub recommendation_reason: String,
}
```

### 4.2 Recommendation Logic

The authority auto-computes `recommended_disposition` using this priority stack:

| Condition | Recommendation | Reason |
|-----------|---------------|--------|
| Chain verification failed for this envelope | **Investigate** | "Envelope integrity check failed" |
| Lease signature invalid | **Investigate** | "Lease authority cannot be verified" |
| `current_policy_would_approve == false` AND action is destructive | **Rollback** | "Current policy would deny this action" |
| `conflicts` contains a `Contradiction` | **Investigate** | "Contradictory actions detected across agents" |
| `conflicts` contains `BlastRadiusOverflow` | **Rollback** | "Aggregate blast radius exceeds episode cap" |
| `blast_radius_percentage_of_cap > 80%` | **Investigate** | "Action consumed >80% of blast radius cap" |
| `current_policy_would_approve == true` AND no conflicts | **Ratify** | "Action aligns with current policy, no conflicts" |

The operator can override any recommendation.

### 4.3 Review Queue Summary View

The operator sees a table with columns: Item ID, Agent, Action, Target, Lease Use#,
Policy Aligned?, Recommendation. Drill-down for each item shows the full
`ReconciliationReviewItem`, the original signed envelope (verifiable via the
Ed25519 public key), and links to the detection finding and response receipt.

---

## 5. Replay Correctness

### 5.1 Completeness Proof

The audit chain is complete (no gaps, no reordering) if all of the following hold:

1. **Sequential numbering with no gaps**: The `seq` field in each envelope is
   strictly `prev_seq + 1`. Verified by `verify_chain_link()` in
   `swarm-spine/src/chain.rs`, which returns `ChainLinkVerdict::SequenceMismatch`
   on any gap.

2. **Hash chain integrity**: Each envelope's `prev_envelope_hash` equals the
   `envelope_hash` of the immediately preceding envelope. Verified by
   `verify_chain_link()`, which returns `ChainLinkVerdict::HashMismatch` on
   any break.

3. **Signature binding**: Each envelope's Ed25519 signature covers the canonical
   unsigned payload (including `seq` and `prev_envelope_hash`). Reordering or
   removing an envelope breaks the signature of all subsequent envelopes.
   Verified by `verify_envelope()` in `swarm-spine/src/envelope.rs`.

4. **Merkle inclusion**: Every partition-mode envelope appears as a leaf in the
   partition checkpoint's Merkle tree. An envelope omitted from the tree will
   cause the recomputed Merkle root to differ from `partition_checkpoint.merkle_root`.

### 5.2 Anchoring to Pre-Partition State

The first partition envelope (`PartitionDetectedFact`) carries
`pre_partition_chain_seq` and `pre_partition_checkpoint_hash`. These fields
create a verifiable link to the last known-good state before partition:

```
  Normal-mode checkpoint (seq=45, merkle_root=R1)
       |
  E(seq=46, normal)  --->  E(seq=47, normal)  --->  E(seq=48, normal)
                                                          |
                                                    prev_envelope_hash
                                                          |
                                                          v
  E(seq=49, PartitionDetectedFact)
       pre_partition_checkpoint_hash = H(checkpoint at seq=45)
       pre_partition_chain_seq = 48
```

The authority verifies this anchor by:

1. Looking up the checkpoint with hash `pre_partition_checkpoint_hash` in its store.
2. Confirming that envelope seq=48 is covered by that checkpoint or a subsequent one.
3. Confirming that `E(seq=49).prev_envelope_hash == E(seq=48).envelope_hash`.

If the agent fabricated or skipped envelopes between seq=48 and seq=49, the chain
link check fails.

### 5.3 Replay Without Re-Execution

Following swarm-spine's `ReplayPreview` pattern (from `store.rs`), partition-mode
replay never re-executes actions. The replay produces a `PartitionReplayReport`:

```rust
/// Result of replaying a partition episode for forensic or review purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionReplayReport {
    pub agent_id: String,
    pub partition_duration_seconds: u64,
    pub envelopes_replayed: u64,
    pub chain_integrity: ChainVerificationResult,
    pub policy_replays: Vec<PolicyReplayResult>,
    pub conflicts: Vec<PartitionConflict>,
    pub review_items: Vec<ReconciliationReviewItem>,
    pub note: String,
    // "replay uses persisted envelopes only; no actions were re-executed"
}
```

---

## 6. Sentinel Comparison

### 6.1 Sentinel's Reconciliation Approach

Sentinel's `PartitionReconciler` (in `pkg/k8s/migrator.go`) provides:

```go
type PartitionReconciler struct {
    client   *Client
    nodeName string
}

func (r *PartitionReconciler) Reconcile(
    ctx context.Context,
    actions []ReconciliationAction,
) (*ReconciliationResult, error)
```

Where `ReconciliationAction` is:

```go
type ReconciliationAction struct {
    Type      string          `json:"type"`      // "cordon", "evict", "taint"
    Target    string          `json:"target"`
    Timestamp time.Time       `json:"timestamp"`
    Payload   json.RawMessage `json:"payload,omitempty"`
}
```

And `GetUnreconciledDecisions()` from `raft_lite.go` returns all committed
decisions:

```go
func (n *Node) GetUnreconciledDecisions() []Decision {
    return n.GetDecisions()  // All committed decisions
}
```

### 6.2 What Sentinel Does That We Should Adopt

1. **Live state comparison**: `Reconcile()` checks current node state against partition
   actions (e.g., "node was cordoned but is now schedulable"). We adopt this in Step 4 --
   compare partition actions against current system state, not just other agents' actions.

2. **Health-gated recovery**: `CheckAndRecoverNode()` verifies NodeReady / no pressure
   conditions before uncordoning. Our rollback protocol (Section 2) must include health
   checks before reversing isolation.

3. **Action-type dispatch**: `Reconcile()` switches on action type with per-type logic.
   Our review system applies per-action-class rules matching doc-11's matrix.

4. **Conflict accumulation**: `Reconcile()` accumulates `Conflicts []string`, returns
   `Success = len(Conflicts) == 0`. Adopted in our `PartitionConflict` type.

### 6.3 What Sentinel Skips That We Need

1. **No cryptographic integrity**: Decisions are unsigned `[]Decision` in memory.
   We wrap every action in a signed, hash-chained envelope (Section 1).

2. **No chain verification**: `GetUnreconciledDecisions()` returns a raw slice with
   no gap or reorder detection. We use `verify_chain_link()` + Merkle proofs (Section 5).

3. **No policy replay**: `Reconcile()` checks infra state but never asks "would current
   policy approve this?" Our Step 3 replays against the policy gate (Section 3.4).

4. **No blast radius tracking**: We track cumulative impact via `BlastRadiusSnapshot`
   in every `LeaseActionFact` against doc-11's caps.

5. **No operator review queue**: Sentinel returns conflicts as strings. We provide
   structured `ReconciliationReviewItem` with dispositions (Section 4).

6. **No rollback protocol**: `CheckAndRecoverNode()` handles uncordoning only. We
   provide a full rollback envelope lifecycle with failure handling (Section 2).

7. **Reconciliation not audited**: `ReconciliationResult` is a return value, not
   a persisted record. We emit signed `ReconciliationDispositionFact` envelopes.

8. **No lease concept**: Raft quorum authorizes any decision. We use contingency
   leases with blast radius caps, TTLs, and use limits (doc-11, Section 4).

### 6.4 Convergence Summary

Sentinel contributes live state comparison, health-gated recovery, and action-type
dispatch. Swarm Team Six contributes signed envelope chains, lease lifecycle
recording, Merkle checkpoint proofs, policy replay, structured operator review,
and rollback-with-audit. The merged approach wraps Sentinel's pragmatic
reconciliation in swarm-spine's cryptographic infrastructure.

---

*Cross-references: [07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION](07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md), [11-PARTITION-AUTHORITY-MATRIX](11-PARTITION-AUTHORITY-MATRIX.md), [04-AUTONOMOUS-RESPONSE-UNDER-PARTITION](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md), [08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md)*
