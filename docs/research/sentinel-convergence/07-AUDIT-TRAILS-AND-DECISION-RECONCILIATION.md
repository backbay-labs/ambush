# 07 -- Audit Trails and Decision Reconciliation

## Cryptographically Verifiable Decision Histories for Partitioned Autonomous Agents

| Metadata          | Value                                                                      |
|-------------------|----------------------------------------------------------------------------|
| Series            | Sentinel-Convergence Research (Document 7 of 8)                           |
| Version           | 0.2                                                                        |
| Status            | Draft                                                                      |
| Date              | 2026-04-07                                                                 |
| Scope             | Sentinel (Go, raft-lite) + Swarm Team Six (Rust, swarm-spine/swarm-crypto) |
| Prerequisites     | [01 -- Distributed Consensus](./01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md), [04 -- Autonomous Response Under Partition](./04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) |

> **Series Note**
> - This design depends on partition-aware authority and future consensus work;
>   it is not part of the current near-term runtime plan.
> - Use it to shape future Phase 6+/forensics work once the underlying
>   governance path is real.
> - See [00-OVERVIEW.md](00-OVERVIEW.md) for current series posture.

---

## Table of Contents

1. [Introduction and Motivation](#1-introduction-and-motivation)
2. [Requirements for Security Audit Trails](#2-requirements-for-security-audit-trails)
3. [Sentinel's Decision Log Architecture](#3-sentinels-decision-log-architecture)
4. [Swarm Team Six Audit Infrastructure](#4-swarm-team-six-audit-infrastructure)
5. [Merging the Approaches](#5-merging-the-approaches)
6. [Reconciliation Protocols for Divergent Decision Histories](#6-reconciliation-protocols-for-divergent-decision-histories)
7. [Cryptographic Audit Chain Design](#7-cryptographic-audit-chain-design)
8. [Compliance Mapping](#8-compliance-mapping)
9. [Forensic Reconstruction](#9-forensic-reconstruction)
10. [Performance Considerations](#10-performance-considerations)
11. [Distributed Audit Across Partitioned Swarms](#11-distributed-audit-across-partitioned-swarms)
12. [Industry Precedents](#12-industry-precedents)
13. [Reference Implementation](#13-reference-implementation)
14. [Conclusion](#14-conclusion)
15. [Cross-References](#cross-references)

---

## 1. Introduction and Motivation

Autonomous agents operating in edge environments face a fundamental tension: they must
make decisions when disconnected from central authority, yet every decision must be
auditable, attributable, and reconstructable after the fact. This tension is acute in two
domains that this research series bridges:

- **Infrastructure triage** (Sentinel): An edge Kubernetes cluster loses connectivity
  to its control plane. Nodes must autonomously decide to cordon failing hardware,
  reschedule pods, or trigger service failovers. These decisions happen under Raft-lite
  consensus within a small partition, producing a term-ordered decision log that exists
  only in local memory until the partition heals.

- **Security incident response** (Swarm Team Six): A swarm of threat-hunting agents
  detects suspicious activity, evaluates it against policy, and dispatches automated
  responses (isolate host, deploy decoy, block process). Every step -- detection,
  policy verdict, response execution -- must be captured in a signed, chain-linked
  audit trail that can survive agent restarts and withstand forensic scrutiny.

Neither system alone solves the full problem. Sentinel provides causal ordering
(Raft terms) and partition-aware decision logging but lacks cryptographic integrity.
Swarm Team Six provides Ed25519 signatures, RFC 6962 Merkle trees, and hash-chained
envelopes but does not model network partitions or divergent decision histories. This
document designs the convergence: a unified audit architecture that is both
partition-tolerant and cryptographically verifiable. It builds on the consensus
foundations from [01 -- Distributed Consensus](./01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) and the partition-tolerance
model from [04 -- Autonomous Response Under Partition](./04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md).

### 1.1 Threat Model

The combined system must defend against:

| Threat                       | Description                                        | Mitigation Layer        |
|------------------------------|----------------------------------------------------|-------------------------|
| Post-hoc decision tampering  | Attacker modifies logged decisions after partition  | Hash chains, signatures |
| Decision insertion           | Attacker injects fabricated decisions into log      | Sequence + chain verification |
| Decision omission            | Attacker deletes inconvenient decisions             | Merkle inclusion proofs |
| Causal reordering            | Attacker reorders decisions to change apparent causality | Vector clocks, term ordering |
| Partition exploitation       | Attacker prolongs partition to prevent reconciliation | Quorum requirements, timeouts |
| Sybil (fake node)            | Attacker introduces rogue nodes into consensus     | Ed25519 identity, mutual TLS |
| Replay attacks               | Attacker replays old valid decisions                | Sequence numbers, nonces |

---

## 2. Requirements for Security Audit Trails

### 2.1 Tamper Evidence

Every audit record must be linked to its predecessors such that modifying any record
invalidates all subsequent records. This is the hash-chain property: given a chain
`R_0 -> R_1 -> ... -> R_n`, modifying `R_k` changes its hash, which breaks the
`prev_hash` link in `R_{k+1}`, cascading through the remainder of the chain.

Swarm-spine implements this via `prev_envelope_hash` in each signed envelope:

```rust
// From swarm-spine/src/envelope.rs
let unsigned = json!({
    "schema": ENVELOPE_SCHEMA_V1,
    "issuer": issuer,
    "seq": seq,
    "prev_envelope_hash": prev_envelope_hash,  // Chain link
    "issued_at": issued_at,
    "capability_token": Value::Null,
    "fact": fact,
});
```

Sentinel currently lacks this property -- decisions are stored in a flat `[]Decision`
slice with no hash linkage between entries.

### 2.2 Causal Ordering

Decisions made by autonomous agents must preserve their causal relationships. If
decision A caused decision B, the audit trail must encode this ordering even if
wall-clock timestamps are unreliable (common in edge environments without reliable NTP).

Sentinel provides this via Raft terms:

```go
// From sentinel/pkg/consensus/raft_lite.go
type Decision struct {
    ID        string          `json:"id"`
    Type      DecisionType    `json:"type"`
    Timestamp time.Time       `json:"timestamp"`
    Term      uint64          `json:"term"`          // Causal epoch
    LeaderID  string          `json:"leader_id"`     // Attribution
    Payload   json.RawMessage `json:"payload"`
    Committed bool            `json:"committed"`
}
```

The term field serves as a coarse-grained Lamport clock. Within a term, decisions are
totally ordered by their position in the leader's log. Across terms, the term number
establishes happened-before relationships.

### 2.3 Completeness

An audit trail is complete if it can prove that no events have been omitted. This
requires either:

1. **Sequential numbering with gap detection** -- If decisions are numbered 1, 2, 3, 5,
   the gap at 4 is detectable. Swarm-spine's chain verification enforces this:

```rust
// From swarm-spine/src/chain.rs
let Some(expected_seq) = head.seq.checked_add(1) else {
    return Ok(ChainLinkVerdict::InvalidChainHead {
        reason: format!("known head sequence overflow for issuer {}", head.issuer),
    });
};
if seq != expected_seq {
    return Ok(ChainLinkVerdict::SequenceMismatch {
        expected_seq,
        actual_seq: seq,
    });
}
```

2. **Merkle inclusion proofs** -- Given a Merkle root over all decisions in a
   checkpoint period, any decision can prove its inclusion. Swarm-crypto provides this:

```rust
// From swarm-crypto/src/merkle.rs -- RFC 6962 leaf hashing
pub fn leaf_hash(leaf_bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);       // Domain separation
    hasher.update(leaf_bytes);
    let result = hasher.finalize();
    // ...
}
```

### 2.4 Non-Repudiation

The agent (or node) that made a decision must not be able to deny having made it. This
requires cryptographic signatures tied to the agent's identity.

Sentinel uses `LeaderID` (a string) for attribution but does not sign decisions.
Swarm Team Six uses Ed25519 keypairs:

```rust
// From swarm-crypto/src/signing.rs
pub struct Keypair {
    signing_key: SigningKey,  // ed25519-dalek
}

impl Keypair {
    pub fn sign(&self, message: &[u8]) -> Signature {
        let signature = self.signing_key.sign(message);
        Signature { inner: signature }
    }
}
```

And swarm-spine binds signatures to issuer identity:

```rust
// From swarm-spine/src/envelope.rs
pub fn issuer_from_keypair(keypair: &Keypair) -> String {
    format!("swarm:ed25519:{}", keypair.public_key().to_hex())
}
```

This gives us a URI-style identity (`swarm:ed25519:<64-hex-chars>`) that is
self-certifying -- knowing the public key is sufficient to verify any signature.

---

## 3. Sentinel's Decision Log Architecture

### 3.1 Raft-Lite Consensus Model

Sentinel implements a simplified Raft protocol optimized for small edge clusters (3-10
nodes). The core state machine is:

```
                    timeout
    +-----------+  --------->  +------------+
    |  Follower |              | Candidate  |
    +-----------+  <---------  +------------+
         ^          lost vote        |
         |                           | won election
         |         heartbeat         v
         +---------------------  +--------+
                                 | Leader |
                                 +--------+
```

Key design choices relevant to audit:

| Property              | Sentinel's Approach                          |
|-----------------------|----------------------------------------------|
| Decision identity     | `{nodeID}-{term}-{logIndex}`                 |
| Ordering guarantee    | Total order within a term; term-order across terms |
| Commitment criterion  | Quorum of `(peers/2) + 1` acknowledgments    |
| Persistence           | In-memory only (no WAL)                      |
| Integrity             | None (no hashing or signing)                 |
| Reconciliation        | Caller-responsible (via `GetUnreconciledDecisions`) |

### 3.2 Decision Lifecycle

```
  ProposeDecision()
        |
        v
  +--Append to log--+
  |  (uncommitted)   |
  +------------------+
        |
        v
  Replicate to peers (MsgDecisionProposal)
        |
        v
  Wait for acks (100ms timeout per peer)
        |
        v
  Quorum reached?  ---no---> Return error
        |
       yes
        |
        v
  Mark committed, update commitIndex
        |
        v
  Invoke DecisionCallback
```

The decision ID format `{nodeID}-{term}-{logIndex}` is significant: it encodes the
causal context. Two decisions with the same term were proposed by the same leader within
the same leadership epoch. A decision with term=5 causally follows all decisions with
term<=4.

### 3.3 Partition Detection and Autonomous Operation

Sentinel detects partitions by monitoring peer health:

```go
// From sentinel/pkg/consensus/raft_lite.go
quorum := len(n.peers) / 2
wasPartitioned := n.partitioned
n.partitioned = healthyPeers < quorum
```

During partitions, each partition may elect its own leader and make its own decisions.
This creates the fundamental reconciliation challenge: two legitimate decision histories
that must be merged when the partition heals.

### 3.4 Prediction-Decision Coupling

Sentinel's healthscore predictor generates `Prediction` structs with failure
probability, confidence, time-to-failure, reasons (e.g., `cpu_temp_critical`,
`memory_pressure`), and a recommendation string. These predictions are the evidence
that motivates autonomous decisions (see [02 -- Predictive Failure as Threat Signal](./02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md)
for the prediction model). In a merged architecture, each decision envelope carries
the prediction that triggered it as a signed fact, creating a causal chain:
telemetry -> prediction -> decision -> action.

---

## 4. Swarm Team Six Audit Infrastructure

### 4.1 Layered Architecture

Swarm Team Six separates audit concerns across four crates:

```
swarm-crypto       Primitives: Ed25519, SHA-256, Merkle trees, JCS canonicalization
     |
swarm-spine        Chain integrity: signed envelopes, hash chains, checkpoints,
     |             AuditTrail, ReplayBundle
     |
swarm-response     Execution receipts: ResponseReceipt, ResponseFailure
     |
swarm-runtime      Composition: EvidenceBundle, correlation, replay orchestration
```

### 4.2 The Audit Trail Record

The `AuditTrail` struct captures the full pipeline for one handled event:

```rust
// From swarm-spine/src/lib.rs
pub struct AuditTrail {
    pub trail_id: String,
    pub hunt_id: String,
    pub related_receipt_ids: Vec<String>,
    pub detection: DetectionFinding,
    pub policy: PolicyRecord,
    pub response: AuditResponseRecord,
    pub created_at_ms: i64,
}
```

This is wrapped in a `ReplayBundle` that adds the originating telemetry event,
intermediate detection findings, pheromone deposits (see [06 -- Stigmergic Coordination](./06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md)),
and the action request:

```rust
pub struct ReplayBundle {
    pub bundle_id: String,
    pub event: TelemetryEvent,
    pub findings: Vec<DetectionFinding>,
    pub deposits: Vec<PheromoneDeposit>,
    pub action_request: ActionRequest,
    pub audit: AuditTrail,
}
```

### 4.3 Signed Envelope Protocol

Every significant fact flows through the spine envelope protocol:

```
                    +---------------------+
                    |  Unsigned Envelope   |
                    |  schema, issuer,     |
                    |  seq, prev_hash,     |
                    |  issued_at, fact     |
                    +---------------------+
                              |
                    canonicalize (RFC 8785 JCS)
                              |
                              v
                    +---------------------+
                    |  SHA-256 of canon.   |
                    |  = envelope_hash     |
                    +---------------------+
                              |
                    Ed25519.sign(canonical_bytes)
                              |
                              v
                    +---------------------+
                    |  Signed Envelope     |
                    |  + envelope_hash     |
                    |  + signature         |
                    +---------------------+
```

Key properties enforced by the protocol:

1. **Canonical serialization** (RFC 8785 / JCS): Keys are sorted by UTF-16 code unit
   order, numbers are canonicalized, strings are escaped deterministically. This ensures
   the same logical payload always produces the same byte sequence for signing.

```rust
// From swarm-crypto/src/canonical.rs
pub fn canonicalize(value: &Value) -> Result<String> {
    match value {
        Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by(|(a, _), (b, _)| cmp_utf16_code_units(a.as_str(), b.as_str()));
            // ...
        }
        // ...
    }
}
```

2. **Hash-then-sign**: The envelope hash is computed over the canonical unsigned
   payload, then the same canonical bytes are signed with Ed25519. Verification
   recomputes both and compares.

3. **Per-issuer chains**: Each issuer maintains its own sequence-numbered, hash-linked
   chain. The `IssuerChainHead` tracks the frontier:

```rust
pub struct IssuerChainHead {
    pub issuer: String,
    pub seq: u64,
    pub envelope_hash: String,
}
```

### 4.4 Checkpoint and Witness Protocol

Periodically, the system creates checkpoint statements that summarize a batch of
envelopes into a Merkle root:

```rust
// From swarm-spine/src/checkpoint.rs
pub fn checkpoint_statement(
    log_id: &str,
    checkpoint_seq: u64,
    prev_checkpoint_hash: Option<String>,
    merkle_root: String,
    tree_size: u64,
    issued_at: String,
) -> Value { /* ... */ }
```

Witnesses co-sign checkpoint statements using domain-separated messages:

```rust
pub fn checkpoint_witness_message(checkpoint_hash: &Hash) -> Vec<u8> {
    let tag = b"SwarmCheckpointHashV1";
    let mut message = Vec::with_capacity(tag.len() + 1 + 32);
    message.extend_from_slice(tag);
    message.push(0x00);          // Domain separator
    message.extend_from_slice(checkpoint_hash.as_bytes());
    message
}
```

The domain separation tag `SwarmCheckpointHashV1\x00` prevents cross-protocol
signature confusion (a signature over a checkpoint cannot be reinterpreted as a
signature over an envelope, even if the hash values happen to collide).

### 4.5 Evidence Export and Verification

The telemetry bridge that feeds Sentinel data into the swarm pipeline is detailed in
[05 -- Telemetry Bridge Architecture](./05-TELEMETRY-BRIDGE-ARCHITECTURE.md).

The runtime's evidence system (`swarm-runtime/src/evidence.rs`) wraps audit artifacts
in `EvidenceBundle` structs carrying canonical payload, SHA-256 payload hash, and an
`EvidenceSignature` (detached Ed25519 signature with signer identity). The
`Ed25519Signer` supports deterministic key derivation from secret material
(`SHA-256(secret) -> seed -> keypair`), enabling reproducible signing in tests.

---

## 5. Merging the Approaches

### 5.1 Design Principles

The merged architecture applies three principles:

1. **Sentinel owns causal structure**: Term-based ordering, partition detection, and
   quorum semantics come from Sentinel's Raft-lite protocol.

2. **Swarm-spine owns integrity**: Hash chains, Ed25519 signatures, Merkle proofs, and
   canonical serialization come from swarm-spine/swarm-crypto.

3. **Neither system is modified in isolation**: The bridge layer composes both, wrapping
   Sentinel decisions in swarm-spine envelopes without changing either system's core
   invariants.

### 5.2 Unified Decision Envelope

A Sentinel decision wrapped in a spine envelope carries the standard envelope fields
(`schema`, `issuer`, `seq`, `prev_envelope_hash`, `issued_at`, `envelope_hash`,
`signature`) plus a `fact` of type `sentinel.decision.v1` containing: `decision_id`,
`decision_type`, `term`, `leader_id`, `committed`, `quorum_size`, `partition_id`,
`vector_clock`, the embedded `prediction` (failure probability, confidence, reasons),
and the original `payload`.

### 5.3 Identity Bridge

Sentinel uses string node IDs; swarm-spine uses `swarm:ed25519:{pubkey_hex}`. The
bridge requires each node to hold an Ed25519 keypair with a registered mapping
(`node-1 -> swarm:ed25519:3a7f...`). The registry is a signed document distributed
via Raft during bootstrap; membership changes require quorum-committed decisions.

### 5.4 Chain Management During Partitions

Per-issuer chains naturally handle partitions: each node continues appending to its
own chain independently. Node-1's chain in partition-A and node-2's chain in
partition-B remain individually valid. The challenge is not chain integrity but
causal ordering across chains, addressed in Section 6.

---

## 6. Reconciliation Protocols for Divergent Decision Histories

### 6.1 The Reconciliation Problem

After a partition heals, the system faces divergent decision logs. The examples
below illustrate a two-partition split (the most common case). For three-or-more-way
splits, reconciliation proceeds pairwise: merge the two largest partitions first,
then reconcile the result with each remaining partition in order of decreasing size.
Each pairwise merge produces a reconciliation envelope (Section 6.6).

```
Partition A (term 5, leader node-1):
  D5.0: cordon node-4 (prediction: thermal_critical, p=0.91)
  D5.1: reschedule pod/nginx from node-4 to node-1
  D5.2: scale replicas of svc/api from 2 to 1

Partition B (term 6, leader node-2):
  D6.0: failover svc/api to node-2 (prediction: network_timeout, p=0.78)
  D6.1: cordon node-4 (prediction: unreachable, p=0.95)
```

Decisions D5.2 and D6.0 conflict: A scaled down the API service while B failed it over.
Both were legitimate responses to the information available in each partition.

### 6.2 Vector Clocks for Causal Ordering

Raft terms provide a partial order but do not capture concurrent decisions made in
different partitions. We augment each decision with a vector clock:

```
VectorClock: map[NodeID]uint64

Decision in partition A:
  vclock = {node-1: 5, node-2: 3, node-3: 5}
  (node-2's last known state was 3 before partition)

Decision in partition B:
  vclock = {node-1: 3, node-2: 6, node-3: 3}
  (node-1 and node-3's last known states were 3 before partition)
```

Two decisions are **concurrent** if neither vector clock dominates the other. Concurrent
decisions from different partitions require explicit conflict resolution.

The happens-before relation using vector clocks:

```
VC(A) < VC(B)  iff  forall i: VC(A)[i] <= VC(B)[i]
                and  exists j: VC(A)[j] < VC(B)[j]

VC(A) || VC(B)  iff  not(VC(A) < VC(B)) and not(VC(B) < VC(A))
```

### 6.3 Conflict Detection

Conflicts are detected by analyzing concurrent decisions for semantic overlap:

```
ConflictDetector:
  1. Collect all decisions from all partitions
  2. Sort by vector clock partial order
  3. For each pair of concurrent decisions (D_a, D_b):
     a. If D_a.type == D_b.type and D_a.target == D_b.target:
        -> DIRECT CONFLICT (same action on same target)
     b. If D_a.target overlaps D_b.target (e.g., pod on cordoned node):
        -> TRANSITIVE CONFLICT
     c. If D_a reverses D_b's effect:
        -> SEMANTIC CONFLICT
  4. Non-conflicting concurrent decisions are merged directly
```

### 6.4 Resolution Strategies

| Strategy                  | When to Use                                    | Mechanism                         |
|---------------------------|------------------------------------------------|-----------------------------------|
| Last-writer-wins (LWW)   | Idempotent operations                          | Compare wall-clock timestamps     |
| Higher-term-wins          | When Raft term indicates more recent leadership | Compare term numbers              |
| Higher-confidence-wins    | When predictions drove the decisions           | Compare prediction.confidence     |
| Majority-partition-wins   | When one partition had quorum                  | Compare partition sizes           |
| Merge (both apply)        | Non-conflicting concurrent decisions           | Apply both in vector-clock order  |
| Manual reconciliation     | Semantic conflicts that cannot be auto-resolved | Flag for operator review          |

The recommended default strategy stack:

```
1. If decisions are non-conflicting:        MERGE
2. If one partition had strict quorum:       MAJORITY-PARTITION-WINS
3. If terms differ:                          HIGHER-TERM-WINS
4. If predictions differ in confidence:      HIGHER-CONFIDENCE-WINS (delta > 0.15)
5. Otherwise:                                FLAG FOR MANUAL REVIEW
```

### 6.5 Operational Transform vs CRDT-Based Merge

**Operational Transform (OT)** treats each decision as a state transformation and
computes concurrent-aware versions when transformations fork from a common state.
OT works well for algebraically well-defined operations but is hard to generalize
for infrastructure decisions where semantics are domain-specific.

**CRDTs** model cluster state as convergent data structures: LWW-Registers for node
status (keyed by node ID, Raft term as timestamp), OR-Sets for pod placement, and
G-Counters for replica counts (merge via per-node `max`, ensuring the count never
decreases -- a safety-preserving choice for minimum replica guarantees).

**Recommendation**: Use CRDTs for the reconciled cluster state and OT-style
transformation only for the audit trail narrative (rewriting the "story" of what
happened to reflect the reconciled outcome).

### 6.6 Reconciliation Envelope

The reconciliation itself is captured as a signed envelope with fact type
`sentinel.reconciliation.v1`. The fact includes: summaries of each partition
(leader, term range, decision count, chain head hash), a `conflicts` array
(each with decision IDs, conflict type, resolution strategy, winner, and reason),
lists of `merged_decisions` and `superseded_decisions`, and a `reconciled_at`
timestamp. This creates a permanent, signed record of how divergent histories
were unified.

---

## 7. Cryptographic Audit Chain Design

### 7.1 Ed25519 Signing Architecture

The signing architecture follows swarm-crypto's existing Ed25519 implementation, built
on `ed25519-dalek`:

```
Keypair Generation:
  signing_key = SigningKey::generate(&mut OsRng)  // 32 bytes entropy
  verifying_key = signing_key.verifying_key()     // Curve25519 point

Deterministic Derivation (for reproducible testing):
  seed = SHA-256(secret_material)
  signing_key = SigningKey::from_bytes(&seed)

Signing:
  message = canonical_json_bytes(envelope_without_hash_and_sig)
  signature = signing_key.sign(message)           // 64-byte Ed25519 signature

Verification:
  recompute canonical bytes from unsigned envelope
  recompute SHA-256 hash, compare with claimed hash
  verify Ed25519 signature over canonical bytes using public key
```

Ed25519 properties relevant to audit trails:

| Property                | Value                                          |
|-------------------------|------------------------------------------------|
| Key size                | 32 bytes (private), 32 bytes (public)          |
| Signature size          | 64 bytes                                       |
| Sign latency            | ~50 us (x86-64); ~70 us (ARM Cortex-A72)      |
| Verify latency          | ~100 us (x86-64); ~180 us (ARM Cortex-A72)    |
| Security level          | ~128-bit equivalent                            |
| Deterministic           | Yes (same key + message = same signature)      |
| Resistance to fault attacks | ed25519-dalek 2.x uses RFC 8032 verification with reject-on-small-order checks |

### 7.2 Hash Chain Construction

Each node maintains a per-issuer hash chain. The chain construction follows
swarm-spine's existing protocol:

```
Envelope N:
  unsigned_N = {schema, issuer, seq=N, prev_hash=H(N-1), issued_at, fact}
  canonical_N = JCS(unsigned_N)
  H(N) = SHA-256(canonical_N)
  sig_N = Ed25519.sign(keypair, canonical_N)
  envelope_N = unsigned_N + {envelope_hash: H(N), signature: sig_N}
```

Chain verification (from `chain.rs`):

```
verify_chain_link(envelope, known_head):
  1. Extract issuer, seq, prev_envelope_hash from envelope
  2. If known_head is None:
     - seq must be 1
     - prev_envelope_hash must be null
     -> NewChain
  3. If known_head is Some(head):
     - Issuer must match head.issuer
     - seq must be head.seq + 1
     - prev_envelope_hash must equal head.envelope_hash
     -> ValidContinuation or error variant
```

### 7.3 Merkle Tree for Checkpoint Verification

Checkpoints aggregate a window of envelopes into a single Merkle root. Using
swarm-crypto's RFC 6962-compatible implementation:

```
Envelopes E_1, E_2, ..., E_k in checkpoint window:

Leaf hashes:
  L_i = SHA-256(0x00 || canonical_json_bytes(E_i))   // RFC 6962 leaf prefix

Internal nodes:
  N = SHA-256(0x01 || left_hash || right_hash)        // RFC 6962 node prefix

Checkpoint statement:
  {
    "schema": "swarm.spine.checkpoint_statement.v1",
    "log_id": "sentinel-cluster-alpha",
    "checkpoint_seq": 42,
    "prev_checkpoint_hash": "0x{H(checkpoint_41)}",
    "merkle_root": "0x{root_of_tree}",
    "tree_size": k,
    "issued_at": "2026-04-07T14:25:00Z"
  }
```

Inclusion proofs allow verifying that a specific decision was part of a checkpoint
without accessing all other decisions in that window:

```
Proof for E_3 in a tree of 4 leaves (E_1..E_4):

         root
        /    \
      h01     h23
     /  \    /  \
    h0  h1  h2  h3     <- Level 0 (leaf hashes of E_1..E_4)

Audit path for leaf index 2 (E_3):
  [h3, h01]

Verification:
  computed = node_hash(leaf_hash(E_3), h3)  // = h23
  computed = node_hash(h01, computed)        // = root
  assert computed == checkpoint.merkle_root
```

### 7.4 Domain-Separated Witness Signatures

Witness signatures use domain separation to prevent cross-protocol confusion:

```
witness_message = b"SwarmCheckpointHashV1" || 0x00 || checkpoint_hash

signature = Ed25519.sign(witness_keypair, witness_message)
```

The `\x00` byte between tag and hash ensures that no valid checkpoint hash can be
interpreted as part of the tag (since `\x00` cannot appear in the ASCII tag string).

For the merged architecture, we introduce additional domain separation tags:

| Context                    | Domain Tag                          |
|----------------------------|-------------------------------------|
| Spine envelope             | (implicit: sign canonical payload)  |
| Checkpoint witness         | `SwarmCheckpointHashV1\x00`         |
| Reconciliation attestation | `SentinelReconciliationV1\x00`      |
| Partition boundary marker  | `SentinelPartitionBoundaryV1\x00`   |
| Node identity certificate  | `SentinelNodeIdentityV1\x00`        |

---

## 8. Compliance Mapping

### 8.1 SOC 2 Type II

SOC 2 Trust Services Criteria relevant to audit trails:

| Criterion   | Requirement                                           | Architecture Mapping                                |
|-------------|-------------------------------------------------------|-----------------------------------------------------|
| CC6.1       | Logical access security controls                      | Ed25519 keypair-per-node; only leader signs decisions |
| CC6.3       | Authorized users can access audit information          | Replay bundles indexed by hunt_id, receipt_id        |
| CC7.2       | System operations monitoring                          | AuditTrail captures detection -> policy -> response  |
| CC7.3       | Evaluation of detected events                         | PolicyRecord.verdict + reason; Prediction.reasons    |
| CC7.4       | Response to security incidents                        | ResponseReceipt with execution mode and status       |
| CC8.1       | Authorization and approval for changes                | Quorum-committed decisions; CapabilityLease scoping  |
| CC6.8       | Controls to prevent or detect unauthorized changes    | Hash chains detect tampering; Merkle inclusion proofs verify completeness |

The signed envelope chain directly satisfies CC6.8. An auditor can:

1. Obtain the latest checkpoint statement with its Merkle root
2. Request an inclusion proof for any specific decision
3. Verify the Ed25519 signature on the checkpoint
4. Verify witness co-signatures from multiple nodes
5. Confirm no decisions were omitted (sequential numbering + gap detection)

### 8.2 NIST 800-53 Rev. 5

The AU (Audit and Accountability) control family is comprehensively addressed:

- **AU-2/AU-3/AU-12** (event logging, content, generation): `AuditTrail` records
  all pipeline stages automatically via the spine envelope protocol. Decision struct
  fields (type, term, leader, payload, timestamp, prediction) satisfy AU-3(1)
  additional information requirements.
- **AU-8** (timestamps): RFC 3339 `issued_at` for wall-clock; vector clocks for
  partition-tolerant causal ordering. AU-8(1) (synchronization with authoritative
  time source) is partially addressed -- vector clocks compensate when NTP is
  unavailable during partitions.
- **AU-9** (protection): Ed25519 signatures satisfy AU-9(3) (cryptographic
  protection); hash chains provide tamper evidence; checkpoint witnesses
  distributed across multiple nodes satisfy AU-9(2) (storage on separate
  physical systems).
- **AU-10** (non-repudiation): Per-node Ed25519 keypairs with issuer identity.
- **AU-11** (retention): `FileReplayBundleStore` and `FileIncidentStore` provide
  durable persistence.
- **SI-4** (monitoring): Sentinel health predictor and swarm-whisker detection
  (see [03 -- Edge-Native Security Detection](./03-EDGE-NATIVE-SECURITY-DETECTION.md)).

### 8.3 PCI-DSS v4.0

PCI-DSS Requirement 10 (Log and Monitor All Access) maps directly:

- **10.2.1** (audit log content): Decision log captures ID, type, timestamp, term,
  leader (10.2.1.2 administrative action attribution), and `ResponseStatus` for
  success/failure indication.
- **10.3.1-10.3.2** (protection from modification): Hash chains + Ed25519 signatures
  ensure tamper evidence; Merkle inclusion proofs provide cryptographic integrity
  verification.
- **10.5.1** (retention): `FileReplayBundleStore` with `durable=true` satisfies the
  12-month retention requirement. Checkpoint chain enables verification even after
  individual envelopes move to cold storage.
- **10.4.1** (anomaly review): `CorrelatedIncident` with correlation keys enables
  anomaly detection across partitioned decision histories.

---

## 9. Forensic Reconstruction

### 9.1 Decision Chain Replay

Forensic reconstruction proceeds in four phases:

1. **Collection**: Gather all signed envelopes, checkpoint statements, witness
   signatures, and reconciliation envelopes from all nodes.
2. **Verification**: Verify per-issuer chain integrity (seq monotonic, prev_hash
   matches, Ed25519 signatures valid), rebuild Merkle trees from checkpoint windows,
   verify witness co-signatures against threshold (e.g., 2/3).
3. **Ordering**: Build partial order from per-issuer sequences, Raft terms, and
   vector clocks. Wall-clock timestamps are used for display only. Identify
   concurrent decision sets at partition boundaries.
4. **Narrative construction**: For each decision in causal order, extract the
   motivating prediction, action taken, and response receipt. Link to correlated
   incidents and produce a human-readable timeline.

### 9.2 Replay Validation

Swarm Team Six's `ReplayBundle` and `ReplayPreview` provide replay-safe
reconstruction:

```rust
// From swarm-spine/src/store.rs
pub struct ReplayPreview {
    pub bundle_id: String,
    pub hunt_id: String,
    pub trail_id: String,
    pub action_kind: String,
    pub response_kind: String,
    pub receipt_ids: Vec<String>,
    pub note: String,  // "replay preview uses persisted artifacts only;
                        //  no live response action was re-executed"
}
```

The explicit `note` field is a deliberate design choice: replay must never re-execute
actions. The replay is for understanding, not for side effects. This is critical in
incident response where replaying an "isolate host" action during forensic review
would cause a new outage.

### 9.3 Cross-Partition Timeline Interleaving

When reconstructing a partition-spanning incident, events from both partitions are
interleaved by wall-clock time and annotated with their partition origin. Decisions
listed in the reconciliation envelope's `superseded_decisions` field are marked as
SUPERSEDED in the timeline narrative.

---

## 10. Performance Considerations

### 10.1 Signing Overhead

Ed25519 operations on typical edge hardware (ARM Cortex-A72, Raspberry Pi 4):

| Operation          | Latency (single core) | Throughput           |
|--------------------|-----------------------|----------------------|
| Key generation     | ~80 microseconds      | ~12,500 ops/sec      |
| Sign               | ~70 microseconds      | ~14,000 ops/sec      |
| Verify             | ~180 microseconds     | ~5,500 ops/sec       |
| SHA-256 (1 KB)     | ~2 microseconds       | ~500,000 ops/sec     |
| JCS canonicalize   | ~10 microseconds      | ~100,000 ops/sec     |

For Sentinel's workload (decisions at human-reaction timescales, typically
seconds-to-minutes apart), signing overhead is negligible. Even at the extreme of
100 decisions per second during a cascading failure, the total signing overhead is
~7ms of CPU time per second -- less than 1%.

### 10.2 Storage Growth

Per-envelope storage cost:

| Component              | Size (bytes)  | Notes                              |
|------------------------|---------------|------------------------------------|
| Envelope JSON          | ~800-2000     | Depends on fact payload size       |
| Ed25519 signature      | 64            | Fixed                              |
| SHA-256 hash           | 32            | Fixed, stored as 66-char hex       |
| Canonical form         | ~600-1500     | Compact JSON (no whitespace)       |
| Merkle proof (8 deep)  | 256           | 8 * 32 bytes                       |

Estimated storage growth for a 5-node Sentinel cluster:

| Decisions/day | Raw envelopes | With Merkle proofs | With checkpoints (daily) |
|---------------|---------------|--------------------|-----------------------------|
| 100           | ~150 KB       | ~175 KB            | ~180 KB                      |
| 1,000         | ~1.5 MB       | ~1.75 MB           | ~1.8 MB                      |
| 10,000        | ~15 MB        | ~17.5 MB           | ~17.6 MB                     |

At 10,000 decisions per day (an extreme scenario), annual storage is ~6.4 GB, well
within edge device capacity.

### 10.3 Pruning Strategies

Storage follows four tiers:

| Tier     | Retention | Contents                                | Medium             |
|----------|-----------|----------------------------------------|--------------------|
| Hot      | 24 hours  | Full envelopes + Merkle proofs          | Memory / SSD       |
| Warm     | 90 days   | Full envelopes                          | Local disk         |
| Cold     | 90d-1yr   | Checkpoint statements + Merkle roots    | Object storage     |
| Archive  | >1yr      | Checkpoint chain only                   | Deep archive       |

Checkpoint statements (~500 bytes each) form their own hash chain via
`prev_checkpoint_hash`, preserving verifiability even after individual envelopes
are archived. Retrieving an archived envelope and computing its inclusion proof
against the retained checkpoint root remains possible at any tier.

### 10.4 Batching Optimizations

During high-activity periods, three strategies reduce overhead:

1. **Batch signing**: Accumulate decisions into a short-window Merkle tree; sign the
   root rather than each decision individually.
2. **Aggregated witness signatures**: BLS or Schnorr multi-signatures would reduce
   witness overhead to O(1). Not yet implemented in swarm-crypto.
3. **Lazy chain linking**: Defer `prev_envelope_hash` computation asynchronously,
   trading immediate integrity verification for reduced decision latency. Appropriate
   only when the threat model tolerates a brief window of unlinked decisions.

---

## 11. Distributed Audit Across Partitioned Swarms

### 11.1 Multi-Node Chain Topology

In a healthy cluster, the topology is:

```
                  Checkpoint
                  Statement
                     |
           +---------+---------+
           |         |         |
  Node-1 Chain  Node-2 Chain  Node-3 Chain
  (issuer A)    (issuer B)    (issuer C)
  E_A1->E_A2   E_B1->E_B2    E_C1->E_C2
```

Each node maintains its own chain (per-issuer isolation, as verified in
`chain.rs::per_issuer_isolation` test). Checkpoint statements aggregate all chains
into a single Merkle root.

### 11.2 Partition-Aware Checkpoint Protocol

Each partition produces its own checkpoint series during the split. Partition-local
checkpoints are valid but have reduced witness strength (2/3 witnesses is stronger
evidence than 1/3). Post-healing, the reconciliation envelope references the final
checkpoint from each partition, and a new unified checkpoint resumes the global
series.

### 11.3 Gossip-Based Chain Synchronization

After partition healing, nodes synchronize chains in three steps:

1. **Advertise**: Each node broadcasts its per-issuer chain heads (seq + hash).
2. **Request**: Nodes request missing envelopes from peers by sequence range.
3. **Verify-then-accept**: Each received envelope is verified (Ed25519 signature +
   chain link via `verify_chain_link`) before the local chain head advances.

The protocol converges when all nodes hold all chains. Convergence is guaranteed
provided that (a) the network eventually delivers all messages and (b) no node
holds a chain with a forged signature -- both ensured by TCP reliability and
Ed25519 verification respectively. See [08 -- Resilience Patterns](./08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) for
failure mode analysis.

### 11.4 Split-Brain Checkpoint Resolution

If both partitions checkpoint the same `checkpoint_seq`, the protocol detects the fork
(same seq, different `merkle_root`, different witness sets), preserves both as
evidence, and creates a merge checkpoint referencing both fork checkpoints as
`merge_predecessors` -- forming a DAG rather than a linear chain at the fork point.

---

## 12. Industry Precedents

### 12.1 Certificate Transparency (RFC 6962)

Google's Certificate Transparency (CT) project is the closest industry precedent to
this architecture. CT logs are append-only Merkle trees of TLS certificates, operated
by independent log servers, with periodic Signed Tree Heads (STHs) that correspond
directly to our checkpoint statements.

| CT Concept                  | Merged Architecture Equivalent                  |
|-----------------------------|--------------------------------------------------|
| CT Log                      | Per-issuer envelope chain                        |
| Signed Certificate Timestamp (SCT) | Envelope signature                       |
| Signed Tree Head (STH)     | Checkpoint statement with witness signatures      |
| Inclusion proof             | Merkle inclusion proof for decision envelope     |
| Consistency proof           | Checkpoint chain (prev_checkpoint_hash)          |
| Log monitor                 | Reconciliation protocol (detects omissions)      |
| Log auditor                 | Forensic reconstruction engine                   |

Swarm-crypto's Merkle tree implementation is explicitly RFC 6962-compatible:

```rust
// From swarm-crypto/src/merkle.rs
/// Compute a leaf hash per RFC 6962: `SHA256(0x00 || leaf)`.
pub fn leaf_hash(leaf_bytes: &[u8]) -> Hash { /* ... */ }

/// Compute a node hash per RFC 6962: `SHA256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash { /* ... */ }
```

This is not accidental -- using the same Merkle construction as CT means existing
verification tooling and auditor expertise transfer directly.

### 12.2 Blockchain-Inspired Audit Logs

The envelope chain structure is analogous to a blockchain without the consensus
overhead:

| Blockchain Concept    | Merged Architecture Equivalent                   |
|-----------------------|---------------------------------------------------|
| Block                 | Signed envelope                                   |
| Block hash            | envelope_hash (SHA-256 of canonical unsigned)     |
| Previous block hash   | prev_envelope_hash                                |
| Miner signature       | Ed25519 signature of canonical bytes              |
| Merkle root of txns   | Checkpoint Merkle root of envelopes               |
| Proof of Work         | Replaced by Raft quorum (proof of authority)      |
| Fork resolution       | Reconciliation protocol with conflict resolution  |

The critical difference: blockchains require global consensus on a single chain, which
is exactly what we cannot have during a partition. Our architecture deliberately permits
multiple concurrent chains during partitions and reconciles them afterward, which is
closer to a DAG-based ledger (like IOTA's Tangle or Hedera's Hashgraph) than to a
traditional blockchain.

### 12.3 Raft Log Replication and Trillian

Standard Raft uses persistent log replication; Sentinel's Raft-lite simplifies this
to in-memory decision slices with no log compaction or membership changes. The merged
architecture delegates persistence and integrity to swarm-spine, effectively using
the envelope chain as Raft's write-ahead log.

Google's Trillian project generalizes CT into a framework for verifiable data
structures. Its "Log mode" maps to our checkpoint-based audit; its "Map mode" (sparse
Merkle trees) could extend the architecture to support efficient inclusion lookups
without sequential scanning.

---

## 13. Reference Implementation

### 13.1 Bridge Types (Go Side)

The Sentinel side requires a bridge package (`auditbridge`) with these core types:

```go
// SignedDecisionEnvelope wraps a Sentinel decision in a spine-compatible envelope.
// NOTE: CapabilityToken must be included (as null) to match the Rust canonical form.
// Omitting it produces a different JCS serialization and breaks cross-language verification.
type SignedDecisionEnvelope struct {
    Schema           string          `json:"schema"`             // "swarm.spine.envelope.v1"
    Issuer           string          `json:"issuer"`             // "swarm:ed25519:{hex}"
    Seq              uint64          `json:"seq"`
    PrevEnvelopeHash *string         `json:"prev_envelope_hash"`
    IssuedAt         string          `json:"issued_at"`
    CapabilityToken  *string         `json:"capability_token"`   // Always null for Sentinel
    Fact             json.RawMessage `json:"fact"`
    EnvelopeHash     string          `json:"envelope_hash"`
    Signature        string          `json:"signature"`
}

// DecisionFact is the fact payload embedded in each envelope.
type DecisionFact struct {
    Type         string            `json:"type"`          // "sentinel.decision.v1"
    DecisionID   string            `json:"decision_id"`
    DecisionType string            `json:"decision_type"`
    Term         uint64            `json:"term"`
    LeaderID     string            `json:"leader_id"`
    Committed    bool              `json:"committed"`
    QuorumSize   int               `json:"quorum_size"`
    PartitionID  string            `json:"partition_id,omitempty"`
    VectorClock  map[string]uint64 `json:"vector_clock"`
    Prediction   *PredictionSnapshot `json:"prediction,omitempty"`
    Payload      json.RawMessage   `json:"payload"`
}
```

The `VectorClock` type implements `Increment`, `Merge`, `HappensBefore`, and
`IsConcurrent` using standard element-wise comparison semantics.

The `AuditBridge` struct holds a `NodeIdentity` (Ed25519 keypair + `swarm:ed25519:`
issuer URI), a `ChainState` (current seq + last envelope hash), and the local vector
clock. Its `WrapDecision` method:

1. Increments the vector clock for the local node
2. Serializes the `DecisionFact` (including embedded prediction) as the envelope fact
3. Advances the chain sequence, linking to the previous envelope hash
4. Canonicalizes the unsigned envelope (RFC 8785 JCS)
5. Computes SHA-256 hash and Ed25519 signature over canonical bytes
6. Returns the complete `SignedDecisionEnvelope`

### 13.2 Verification (Rust Side)

The Rust side extends swarm-spine's existing verification. The key function
`verify_decision_chain` iterates a batch of envelopes and for each:

1. Calls `verify_envelope()` to check signature and hash integrity
2. Calls `verify_chain_link()` against the tracked `IssuerChainHead` per issuer
3. Advances the chain head via `chain_head_from_envelope()`
4. Deserializes the `fact` field into a `SentinelDecisionFact` struct
5. Validates that `fact_type == "sentinel.decision.v1"`

The `SentinelDecisionFact` mirrors the Go `DecisionFact` -- it carries the decision
ID, type, term, leader, vector clock, optional prediction, and original payload.

A companion `checkpoint_decisions` function canonicalizes all envelopes in a batch
and feeds them into `MerkleTree::from_leaves()`, returning the Merkle root and tree
for subsequent inclusion proof generation.

### 13.3 Reconciliation Engine

The reconciliation engine has three functions:

**`detect_conflicts`**: Takes decision lists from two partitions, computes the
cross-product of concurrent decision pairs (using vector clock comparison), and
classifies each conflict as `Direct` (same decision type on same target), `Semantic`
(contradictory types, e.g. `resource_scale` vs `service_failover`), or `Transitive`
(indirect dependency).

**`is_concurrent`**: Implements the standard vector clock concurrency check -- neither
clock dominates the other element-wise.

**`resolve_conflict`**: Applies the strategy stack from Section 6.4 in order:

1. **Majority-partition-wins**: If one partition had quorum and the other did not
2. **Higher-term-wins**: If the decisions belong to different Raft terms
3. **Higher-confidence-wins**: If the motivating predictions differ in confidence
   by more than 0.15
4. **Manual review**: Fallback when no automated strategy applies

Each resolution produces a `Resolution` struct with winner/loser decision IDs,
the strategy name, and a human-readable reason string. These are aggregated into
the reconciliation envelope (Section 6.6) for the permanent audit record.

---

## 14. Conclusion

### 14.1 Summary of Contributions

This document designs a unified audit trail architecture that combines:

1. **Sentinel's strengths**: Term-based causal ordering, partition detection, quorum
   consensus, and lightweight operation suitable for edge deployment.

2. **Swarm Team Six's strengths**: Ed25519 signatures (via `swarm-crypto`),
   RFC 6962-compatible Merkle trees, RFC 8785 canonical JSON serialization,
   per-issuer hash chains (via `swarm-spine`), and checkpoint-based bundling.

3. **Novel contributions**:
   - Vector clock augmentation for cross-partition causal ordering
   - Conflict detection and multi-strategy resolution for divergent decision histories
   - Partition-aware checkpoint protocol with merge semantics
   - Domain-separated witness signatures for reconciliation attestation
   - Compliance mapping to SOC 2, NIST 800-53, and PCI-DSS requirements

### 14.2 Key Design Decisions

| Decision                               | Rationale                                      |
|----------------------------------------|------------------------------------------------|
| Ed25519 over ECDSA                     | Deterministic, faster, simpler; already in swarm-crypto |
| RFC 8785 JCS for canonicalization      | Industry standard; already in swarm-crypto     |
| RFC 6962 Merkle trees                  | CT compatibility; existing tooling ecosystem   |
| Per-issuer chains (not global chain)   | Partition-tolerant by construction              |
| Vector clocks over Lamport timestamps  | Detect concurrency, not just ordering          |
| CRDTs for reconciled state             | Automatic convergence without coordination     |
| Checkpoint witnesses over BFT          | Simpler; sufficient for trusted-but-partitioned model |

### 14.3 Open Questions

1. **Key rotation**: Requires quorum-committed config changes linking old chain to new.
2. **Cross-cluster reconciliation**: Federated edge sites need gossip-based checkpoint exchange.
3. **Formal verification**: Conflict resolution convergence should be proven in TLA+ or Alloy.
4. **Aggregated signatures**: BLS/Schnorr multi-sig would reduce witness overhead to O(1).
5. **HSM integration**: TPM 2.0 key storage via swarm-crypto's `Signer` trait abstraction.
6. **Multi-way partition reconciliation**: The pairwise merge strategy (Section 6.1)
   needs formal analysis for commutativity -- does the merge order affect the final
   reconciled state?

### 14.4 Implementation Roadmap

| Phase | Scope                                               | Effort    |
|-------|------------------------------------------------------|-----------|
| 0     | Add Ed25519 keypair to Sentinel node identity        | 1 week    |
| 1     | Implement AuditBridge (Go): wrap decisions in envelopes | 2 weeks |
| 2     | Add vector clock to Sentinel decision struct         | 1 week    |
| 3     | Implement verification bridge (Rust): validate Sentinel envelopes | 1 week |
| 4     | Implement reconciliation engine                      | 3 weeks   |
| 5     | Checkpoint protocol with partition-aware witnesses   | 2 weeks   |
| 6     | Forensic reconstruction CLI tool                     | 2 weeks   |
| 7     | Compliance documentation and audit tooling           | 2 weeks   |

Total estimated effort: 14 engineering weeks.

---

## Appendix A: Cryptographic Parameter Summary

| Parameter                  | Value                                         |
|----------------------------|-----------------------------------------------|
| Signature algorithm        | Ed25519 (RFC 8032)                            |
| Hash algorithm             | SHA-256 (FIPS 180-4)                          |
| Merkle tree construction   | RFC 6962 Section 2                            |
| Canonicalization           | RFC 8785 (JSON Canonicalization Scheme)        |
| Key size (private)         | 32 bytes                                       |
| Key size (public)          | 32 bytes                                       |
| Signature size             | 64 bytes                                       |
| Hash output size           | 32 bytes                                       |
| Domain separation prefix   | Variable-length ASCII tag + `\x00` separator  |
| Issuer URI format          | `swarm:ed25519:{64_hex_chars}`                |
| Envelope hash format       | `0x{64_hex_chars}` (SHA-256 hex with prefix)  |
| Timestamp format           | RFC 3339 with second precision, UTC           |

## Appendix B: Fact Type Registry

| Fact type                         | Schema version | Produced by          |
|-----------------------------------|----------------|----------------------|
| `sentinel.decision.v1`           | envelope.v1    | AuditBridge          |
| `sentinel.reconciliation.v1`     | envelope.v1    | Reconciliation engine |
| `sentinel.partition_boundary.v1` | envelope.v1    | Partition detector   |
| `sentinel.node_identity.v1`      | envelope.v1    | Cluster bootstrap    |

Each fact type's wire format is specified in the envelope's `fact` field.
Example decision fact fields: `decision_id`, `decision_type`, `term`, `leader_id`,
`committed`, `quorum_size`, `partition_id`, `vector_clock`, `prediction`, `payload`.
Example reconciliation fact fields: `partition_a` / `partition_b` summaries,
`conflicts` array (with resolution strategy and winner), `merged_decisions`,
`superseded_decisions`. Checkpoint statements and witness signatures follow the
schemas defined in `swarm-spine/src/checkpoint.rs`.

---

## Cross-References

This document is part of the Sentinel-Convergence Research series (8 documents).
Each document below is linked with a brief note on its relevance to audit trails
and decision reconciliation.

| # | Document | Relevance to This Document |
|---|----------|---------------------------|
| 01 | [Distributed Consensus for Agent Swarms](./01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) | Foundation for Raft-lite consensus model, term ordering, and quorum semantics used throughout Sections 3 and 6. |
| 02 | [Predictive Failure as Threat Signal](./02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | Defines the `Prediction` struct that motivates autonomous decisions; predictions are embedded as signed facts in decision envelopes (Section 5.2). |
| 03 | [Edge-Native Security Detection](./03-EDGE-NATIVE-SECURITY-DETECTION.md) | Detection layer that produces `DetectionFinding` records captured in the `AuditTrail` struct (Section 4.2). |
| 04 | [Autonomous Response Under Partition](./04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) | Partition-tolerance model that creates the divergent decision histories reconciled in Section 6. |
| 05 | [Telemetry Bridge Architecture](./05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Designs the `swarm-ingest-sentinel` bridge that feeds Sentinel telemetry into the swarm detection pipeline, providing the raw data that becomes auditable decisions. |
| 06 | [Stigmergic Coordination and Swarm Intelligence](./06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) | Pheromone deposits captured in `ReplayBundle` (Section 4.2) originate from this coordination model. |
| 08 | [Resilience Patterns for Distributed Agents](./08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) | Failure mode analysis and circuit breaker patterns that inform the gossip-based chain synchronization protocol (Section 11.3) and partition detection thresholds. |
