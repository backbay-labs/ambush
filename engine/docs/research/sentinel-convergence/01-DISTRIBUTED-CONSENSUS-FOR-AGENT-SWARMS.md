---
title: "01 -- Distributed Consensus for Autonomous Agent Swarms"
series: Sentinel Convergence (1 of 8)
version: "0.2"
date: 2026-04-07
status: Draft
authors: Sentinel Convergence Research Team
---

# Distributed Consensus for Autonomous Agent Swarms

## Cross-Project Research: Sentinel Raft-Lite to Swarm Team Six BFT Consensus

> Research document for the `swarm-consensus` crate.
> Sources: Sentinel (`playground/sentinel`), Swarm Team Six (`standalone/swarm-team-six`)

> **Series Note**
> - `swarm-consensus` remains deferred until the single-node live-response path
>   is proven.
> - Use this document as Phase 6 design input, not as the near-term execution
>   plan.
> - Series-wide status and reading order live in
>   [00-OVERVIEW.md](00-OVERVIEW.md).

---

## Table of Contents

1. [Introduction and Motivation](#1-introduction-and-motivation)
2. [Survey of Consensus Algorithms for Agent Swarms](#2-survey-of-consensus-algorithms-for-agent-swarms)
3. [Deep Analysis of Sentinel's Raft-Lite Implementation](#3-deep-analysis-of-sentinels-raft-lite-implementation)
4. [Swarm Team Six Consensus Requirements](#4-swarm-team-six-consensus-requirements)
5. [Mapping Sentinel Patterns to Swarm Needs](#5-mapping-sentinel-patterns-to-swarm-needs)
6. [Porting Considerations: Go to Rust](#6-porting-considerations-go-to-rust)
7. [Alternative Approaches: CRDTs, Virtual Synchrony, Epidemic Protocols](#7-alternative-approaches-crdts-virtual-synchrony-epidemic-protocols)
8. [Reference Architecture for swarm-consensus](#8-reference-architecture-for-swarm-consensus)
9. [Academic References and Industry Precedents](#9-academic-references-and-industry-precedents)
10. [Open Questions and Trade-offs](#10-open-questions-and-trade-offs)
- [Appendix A: Sentinel Source Reference](#appendix-a-sentinel-source-reference)
- [Appendix B: STS Source Reference](#appendix-b-sts-source-reference)
- [Appendix C: Implementation Priority Matrix](#appendix-c-implementation-priority-matrix)
- [Appendix D: Glossary](#appendix-d-glossary)
- [Cross-References](#cross-references)

---

## 1. Introduction and Motivation

Two Backbay projects converge on the same fundamental problem: how do autonomous
agents make collective decisions when network conditions are adversarial, nodes may
be compromised, and the cost of incorrect action is high?

**Sentinel** is a Go-based predictive failure detection system for Kubernetes edge
nodes. It implements a Raft-lite consensus protocol that enables small clusters of
edge nodes (3-10) to make autonomous decisions -- pod rescheduling, node cordoning,
service failover -- when partitioned from the Kubernetes control plane. Its threat
model assumes crash faults and network unreliability, not Byzantine behavior.

**Swarm Team Six (STS)** is a Rust-based autonomous security detection and response
engine. Its `swarm-consensus` crate is currently a stub (`// TODO: Implement`),
with a design document (docs/CONSENSUS.md) specifying a Tendermint-style BFT
protocol for governing response actions, evolution commits, and trust decisions
among a Tom committee. Its threat model is adversarial: agents may be compromised,
and a single rogue agent must not be able to trigger damaging response actions
unilaterally.

The gap between these two systems is instructive. Sentinel has a working, tested
implementation of leader-based consensus with practical engineering patterns
(rate limiting, exponential backoff, partition detection, decision logging). STS
has a rigorous design for BFT consensus but no implementation. This document
surveys the consensus landscape, analyzes what Sentinel does well, identifies what
must change for the BFT swarm context, and proposes a reference architecture that
draws from both projects.

### Why This Matters Now

The STS roadmap (docs/ROADMAP.md) lists distributed consensus as Phase 6 --
"Optional Advanced Governance." The Rust-first migration document
(docs/RUST_FIRST_MIGRATION.md) explicitly states: "distributed consensus is
deferred until the single-node live-response path is real." This is correct
prioritization. But when Phase 6 arrives, the team will need concrete
implementation decisions. This document provides the research foundation by asking:
what can we learn from Sentinel's working consensus, what does the academic
literature recommend, and what does STS's threat model demand?

---

## 2. Survey of Consensus Algorithms for Agent Swarms

### 2.1 Classical Raft

Raft (Ongaro & Ousterhout, 2014) was designed explicitly for understandability.
It decomposes consensus into three sub-problems: leader election, log replication,
and safety. The protocol guarantees that:

- At most one leader exists per term.
- The leader's log is authoritative.
- Committed entries are durable across majorities.

Raft assumes a crash-fault model: nodes may fail by stopping, but they do not
send malicious messages. This is a critical limitation for security applications.

**Applicability to agent swarms:** Raft is well-suited when agents are trusted but
may crash or become unreachable. It provides strong consistency (linearizability)
and is straightforward to implement. It is not suitable when agents may be
compromised and send conflicting messages to different peers.

| Property              | Raft                          |
|-----------------------|-------------------------------|
| Fault model           | Crash-fault (f of 2f+1 nodes) |
| Consistency           | Linearizable                  |
| Leader required       | Yes                           |
| Message complexity    | O(n) per heartbeat            |
| Partition behavior    | Minority side halts           |
| Byzantine resistance  | None                          |

### 2.2 Raft-Lite (Sentinel's Variant)

Sentinel's implementation is a deliberate simplification of Raft, optimized for
small edge clusters where full Raft features (log compaction, membership changes,
snapshotting) are unnecessary overhead. Key simplifications:

- **No persistent log.** Decisions are stored in memory. This is acceptable for
  edge clusters where the decision set is small and partition durations are bounded.
- **No log compaction or snapshots.** The decision list grows linearly with
  committed decisions, which is bounded by cluster lifetime.
- **Simplified replication.** Heartbeats carry the full decision list rather than
  incremental log entries. This trades bandwidth for implementation simplicity.
- **JSON wire format.** Messages are serialized as JSON over TCP, not a binary
  protocol. This simplifies debugging at the cost of throughput.

**Applicability to agent swarms:** Raft-lite provides a working foundation for
leader-based consensus with practical engineering patterns. Its simplifications
make it suitable for prototyping but insufficient for production security systems
where Byzantine fault tolerance is required. For edge-specific detection
patterns, see [03-EDGE-NATIVE-SECURITY-DETECTION.md](03-EDGE-NATIVE-SECURITY-DETECTION.md).

### 2.3 PBFT (Practical Byzantine Fault Tolerance)

PBFT (Castro & Liskov, 1999) was the first practical protocol for Byzantine
fault tolerance. It tolerates f Byzantine faults among 3f+1 nodes and uses a
three-phase protocol: pre-prepare, prepare, commit.

```
Client --> Primary: REQUEST
Primary --> All: PRE-PREPARE(v, n, d)
All --> All: PREPARE(v, n, d, i)        [wait for 2f PREPARE messages]
All --> All: COMMIT(v, n, d, i)          [wait for 2f+1 COMMIT messages]
All --> Client: REPLY
```

PBFT's message complexity is O(n^2) per decision, which limits scalability to
approximately 20-30 nodes in practice.

**Applicability to agent swarms:** PBFT provides the Byzantine tolerance STS needs
but has high message complexity. For a Tom committee of 4-10 members, O(n^2)
is acceptable. For larger swarm coordination, it is not.

| Property              | PBFT                           |
|-----------------------|--------------------------------|
| Fault model           | Byzantine (f of 3f+1 nodes)    |
| Consistency           | Linearizable                   |
| Leader required       | Yes (primary, view-changeable) |
| Message complexity    | O(n^2) per decision            |
| Partition behavior    | Both sides halt                |
| Byzantine resistance  | Full (up to f faults)          |

### 2.4 Tendermint (What STS Specifies)

Tendermint (Buchman, 2016 thesis; Buchman, Kwon & Milosevic, 2018, "The latest
gossip on BFT consensus") is a BFT consensus protocol designed for blockchain
applications. It uses a propose-prevote-precommit three-phase pattern with a
rotating proposer. STS's docs/CONSENSUS.md specifies this as the target protocol.

Key Tendermint properties relevant to STS:

- **Deterministic proposer rotation.** The proposer for each round is determined
  by a function of the round number and validator set. STS extends this with VRF
  (Verifiable Random Function) rotation for unpredictability.
- **Locked values.** Once a validator precommits to a value, it is "locked" and
  must prevote for that value in subsequent rounds. This prevents equivocation
  across rounds.
- **Round-based timeout.** If a round does not complete within the timeout, it
  fails and advances to the next round with a new proposer.

**Applicability to agent swarms:** Tendermint is the right choice for STS's Tom
committee consensus. It provides BFT with clear round semantics, handles proposer
failure via round advancement, and the locked-value mechanism prevents split-brain.
Message complexity is O(n^2) per round, which is acceptable for committee sizes
of 4-10.

```
+-------+     +-------+     +-------+     +-------+
| Tom-1 |     | Tom-2 |     | Tom-3 |     | Tom-4 |
+---+---+     +---+---+     +---+---+     +---+---+
    |             |             |             |
    |  Propose    |             |             |
    |------------>|------------>|------------>|
    |             |             |             |
    |  Prevote    |  Prevote    |  Prevote    |  Prevote
    |<----------->|<----------->|<----------->|
    |             |             |             |
    |  Precommit  |  Precommit  |  Precommit  |  Precommit
    |<----------->|<----------->|<----------->|
    |             |             |             |
    |  COMMITTED  |  COMMITTED  |  COMMITTED  |  COMMITTED
    |             |             |             |
```

### 2.5 Gossip Protocols (SWIM, Serf)

Gossip protocols propagate information through random peer-to-peer exchanges.
The SWIM protocol (Das, Gupta & Muthukrishnan, 2002) combines failure detection
with membership management through three message types: ping, ping-req, and
compound (piggybacking membership updates on pings).

HashiCorp's Serf (used by Consul) implements SWIM with extensions:
- Infection-style dissemination for membership events
- Suspicion mechanism before declaring node failure
- Configurable probe intervals and timeouts

**Applicability to agent swarms:** Gossip protocols are excellent for membership
management and failure detection but do not provide consensus on ordered decisions.
They provide eventual consistency, not linearizability. For STS, gossip is the
right substrate for agent health monitoring and swarm membership (the
`swarm.gossip.{agent_id}` NATS subjects), but not for response action
authorization.

| Property              | Gossip (SWIM)                  |
|-----------------------|--------------------------------|
| Fault model           | Crash-fault                    |
| Consistency           | Eventual                       |
| Leader required       | No                             |
| Message complexity    | O(log n) dissemination time    |
| Partition behavior    | Graceful degradation           |
| Byzantine resistance  | None (basic); extensions exist |

### 2.6 Stigmergic Consensus (Pheromone-Based)

Stigmergic consensus is an emergent property of the pheromone substrate, not a
classical consensus protocol. STS already implements this via the pheromone system
documented in docs/PHEROMONES.md (see also
[06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md](06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md)).
The key mechanism:

1. Agents independently deposit signed pheromones into a shared substrate.
2. Pheromone concentration is computed with exponential decay.
3. Source diversity enforcement prevents single-agent domination.
4. Quorum sensing triggers mode transitions when thresholds are exceeded.

This is not consensus in the distributed systems sense (there is no agreement on
a single value), but it achieves coordination without explicit communication
between agents. It is analogous to how ant colonies "decide" which food source to
exploit through differential pheromone trail reinforcement.

**Applicability to agent swarms:** Stigmergic coordination is the right mechanism
for detection-phase coordination (mode transitions, resource allocation,
investigation prioritization). It should NOT be used for response actions because
it provides no atomicity guarantee -- the "decision" is a gradual emergence, not
a discrete commitment.

```
                    Pheromone Substrate (NATS JetStream)
                    ====================================
 Whisker-1 ------> | deposit(lateral_movement, 0.92) |
                    |                                  |
 Whisker-2 ------> | deposit(lateral_movement, 0.88) |
                    |                                  |
 Whisker-3 ------> | deposit(c2_beacon, 0.75)        |
                    |                                  |
                    | concentration(lateral_movement)  |
                    | = sum(decay(deposits))           |
                    | = 1.73  [2 distinct sources]     |
                    |                                  |
                    | if strength >= 1.5 AND           |
                    |    sources >= 2:                  |
                    |      TRANSITION -> Alert          |
                    ====================================
```

### 2.7 Comparison Matrix

| Algorithm       | Fault Model  | Consistency    | Msg Complexity | BFT | Leader | Best For                    |
|-----------------|-------------|----------------|---------------|-----|--------|-----------------------------|
| Raft            | Crash       | Linearizable   | O(n)          | No  | Yes    | Infra consensus (Sentinel)  |
| Raft-lite       | Crash       | Linearizable   | O(n)          | No  | Yes    | Small edge clusters         |
| PBFT            | Byzantine   | Linearizable   | O(n^2)        | Yes | Yes    | Small BFT committees        |
| Tendermint      | Byzantine   | Linearizable   | O(n^2)        | Yes | Yes    | STS Tom committee           |
| Gossip/SWIM     | Crash       | Eventual       | O(log n)      | No  | No     | Membership, health          |
| Stigmergy       | Byzantine*  | Emergent       | O(1) per agent| Yes*| No     | Detection coordination      |
| CRDTs           | Byzantine*  | Eventual       | O(n) merge    | Yes*| No     | Shared state (investigation)|

\* Byzantine resistance via Ed25519 signatures and source diversity, not via protocol mechanics.

---

## 3. Deep Analysis of Sentinel's Raft-Lite Implementation

### 3.1 Architecture Overview

Sentinel's Raft-lite implementation lives in a single file
(`pkg/consensus/raft_lite.go`, 917 lines) with comprehensive tests
(`pkg/consensus/raft_lite_test.go`, 633 lines). The implementation is
self-contained with no external dependencies beyond the Go standard library.

```
+------------------+
|      Node        |
|                  |
|  +------------+  |       TCP
|  | Election   |--+-----> Peers
|  | Loop       |  |
|  +------------+  |
|                  |
|  +------------+  |
|  | Leader     |--+-----> Heartbeats + Decision Replication
|  | Loop       |  |
|  +------------+  |
|                  |
|  +------------+  |
|  | Partition  |--+-----> Partition Callbacks
|  | Detector   |  |
|  +------------+  |
|                  |
|  +------------+  |
|  | Peer       |--+-----> Connection Management + Backoff
|  | Connector  |  |
|  +------------+  |
|                  |
|  +------------+  |
|  | Accept     |--+-----> Incoming Connection Handling
|  | Loop       |  |
|  +------------+  |
|                  |
|  +------------+  |
|  | Rate       |  |
|  | Limiter    |  |
|  +------------+  |
+------------------+
```

### 3.2 What Sentinel Does Well

#### 3.2.1 Pragmatic Decision Model

Sentinel's `Decision` type is well-designed for its problem domain:

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

The `DecisionType` enum covers the four autonomous actions an edge cluster
needs: `pod_reschedule`, `node_cordon`, `service_failover`, `resource_scale`.
This is a closed set of well-understood operations, each with bounded blast
radius.

The `json.RawMessage` payload allows type-specific data without forcing a rigid
schema. STS should adopt this pattern -- the `ConsensusValue` enum already
mirrors it with variants for response actions, evolution commits, and trust
decisions (see Section 8.2).

#### 3.2.2 Exponential Backoff with Jitter

Sentinel implements exponential backoff for peer reconnection with proper jitter:

```go
func calculateBackoff(failures int, cfg backoffConfig) time.Duration {
    if failures <= 0 {
        return cfg.initialDelay
    }
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

The default configuration (initial: 100ms, max: 30s, multiplier: 2x) is sensible
for LAN-connected edge nodes. The jitter prevents thundering herd effects when
multiple nodes attempt to reconnect simultaneously after a partition heals.

This pattern transfers directly to STS. When Tom committee members lose contact
with the NATS cluster or each other, exponential backoff with jitter prevents
reconnection storms that could amplify a partial outage.

#### 3.2.3 Token Bucket Rate Limiting

Sentinel implements per-peer rate limiting using a token bucket algorithm:

```go
type tokenBucket struct {
    mu         sync.Mutex
    tokens     int
    maxTokens  int
    refillRate int
    lastRefill time.Time
}
```

The double-check locking pattern in `getOrCreateLimiter` is correct:

```go
func (n *Node) getOrCreateLimiter(addr string) *tokenBucket {
    n.incomingLimitersMu.RLock()
    limiter, exists := n.incomingLimiters[addr]
    n.incomingLimitersMu.RUnlock()
    if exists {
        return limiter
    }
    n.incomingLimitersMu.Lock()
    defer n.incomingLimitersMu.Unlock()
    // Double-check after acquiring write lock
    if limiter, exists = n.incomingLimiters[addr]; exists {
        return limiter
    }
    // ... create new limiter
}
```

For STS, rate limiting on NATS subjects is essential. A compromised agent could
flood consensus subjects with invalid proposals or votes. The token bucket pattern
from Sentinel, adapted to per-agent-ID rate limits on NATS message ingestion,
provides the necessary protection.

#### 3.2.4 Partition Detection

Sentinel's partition detector counts healthy peers and declares a partition when
fewer than quorum peers are reachable:

```go
func (n *Node) partitionDetector() {
    // ...
    healthyPeers := 0
    for _, peer := range n.peers {
        if peer.healthy && time.Since(peer.lastSeen) < 5*time.Second {
            healthyPeers++
        }
    }
    quorum := len(n.peers) / 2
    n.partitioned = healthyPeers < quorum
    // ...
}
```

Note that Sentinel computes partition quorum as `len(n.peers) / 2` -- a count
of *peers only*, excluding self. This is looser than the decision-commit quorum
(`(len(n.peers)/2)+1` including self-vote) and serves as an early-warning
heuristic rather than a strict majority check.

The partition callback system (`PartitionCallback func(partitioned bool)`)
enables higher-level systems to react to partition state changes. This is
directly applicable to STS: when the Tom committee is partitioned, the swarm
should halt response actions (safety) while continuing detection (liveness).
See [04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md)
for the full analysis of partition-tolerant response strategies.

#### 3.2.5 Circuit Breaker Pattern (Adjacent Code)

While not in the consensus module itself, Sentinel's circuit breaker
(`pkg/k8s/circuit_breaker.go`) implements a three-state machine
(Closed -> Open -> Half-Open) that complements the consensus protocol.
The circuit breaker protects Kubernetes API calls from cascading failures:

```
Closed    --[failures >= threshold]---> Open
Open      --[timeout elapsed]---------> Half-Open
Half-Open --[successes >= threshold]--> Closed
Half-Open --[any failure]-------------> Open
```

STS should apply this pattern to NATS connection management and to the
consensus round initiation path. If repeated consensus rounds fail (timeout
or insufficient votes), a circuit breaker can prevent the system from
continuously initiating rounds that have no chance of succeeding.

### 3.3 Limitations of Sentinel's Approach

#### 3.3.1 No Byzantine Fault Tolerance

This is the fundamental limitation. Sentinel assumes crash-fault behavior:
nodes fail by stopping, not by sending malicious messages. The vote-counting
logic trusts all messages:

```go
func (n *Node) handleVoteRequest(msg *Message) *Message {
    if msg.Term >= n.currentTerm &&
        (n.votedFor == "" || n.votedFor == msg.FromID) &&
        msg.LastLogIndex >= len(n.decisions)-1 {
        resp.VoteGranted = true
        n.votedFor = msg.FromID
        // ...
    }
    return resp
}
```

There is no signature verification on messages. A network adversary can forge
vote requests, heartbeats, or decision proposals. For Kubernetes edge
infrastructure where the network is trusted, this is acceptable. For a
security agent swarm operating in adversarial environments, it is not.

**STS requirement:** Every message in the consensus protocol must be Ed25519-signed
and verified before processing. The `swarm-crypto` crate provides the primitives.

#### 3.3.2 No Cryptographic Identity

Sentinel identifies nodes by string IDs (`NodeID string`). There is no
cryptographic binding between a node's identity and its network presence.
An attacker who gains network access can impersonate any node by sending
messages with a forged `FromID`.

**STS requirement:** Agent identity is Ed25519 keypair-based (`AgentId` bound to
a public key). The Tom-managed agent registry controls admission. All consensus
messages must include a signature verifiable against the sender's registered
public key.

#### 3.3.3 In-Memory Decision Log

Sentinel stores decisions in a Go slice:

```go
decisions   []Decision
commitIndex int
lastApplied int
```

This is lost on process restart. For edge clusters with bounded partition
durations, this is a pragmatic trade-off. For STS, where audit trail
requirements demand durable, Merkle-anchored receipts of every consensus
decision, in-memory storage is insufficient.

**STS requirement:** Consensus decisions must be persisted to the spine audit trail
(NATS JetStream + Merkle tree) with signed receipts. See
[07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md](07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md)
for the full audit trail design.

#### 3.3.4 Synchronous Replication with Blocking Reads

Sentinel's `ProposeDecision` blocks while waiting for peer acknowledgments:

```go
peer.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
resp, err := n.recvMessage(peer.conn)
if err == nil && resp.Success {
    acks++
}
```

This sequential loop through peers means decision latency scales linearly with
peer count. In a 10-node cluster with 100ms timeout per peer, worst case
latency is 1 second. For Sentinel's use case (infrequent autonomous decisions),
this is acceptable. For STS's Tom committee making time-sensitive security
decisions, parallel message dispatch with async acknowledgment collection is
necessary.

**STS requirement:** Consensus message dispatch must be asynchronous. Tokio tasks
for each peer connection, with a `select!` over acknowledgment channels and a
round timeout.

#### 3.3.5 Full Decision List in Every Heartbeat

```go
decisions := make([]Decision, len(n.decisions))
copy(decisions, n.decisions)
// ...
msg := Message{
    Type:         MsgHeartbeat,
    Decisions:    decisions,
    // ...
}
```

Every heartbeat carries the complete decision list. For a small edge cluster
with a handful of decisions, this is fine. It would not scale to thousands of
consensus decisions over the lifetime of a swarm mission.

**STS requirement:** Incremental replication. Heartbeats carry only decisions
after the follower's known commit index, similar to Raft's `nextIndex`
per-follower tracking.

#### 3.3.6 No Formal View Change / Proposer Rotation

Sentinel relies on Raft's standard election mechanism: when the leader fails,
followers time out and start a new election. There is no formal view change
protocol and no deterministic proposer rotation.

**STS requirement:** VRF-based proposer rotation as specified in docs/CONSENSUS.md.
The proposer for each round must be deterministically derivable from the VRF
output and round number, preventing targeted attacks on a known proposer.

### 3.4 Design Decision Analysis

| Decision                        | Sentinel Choice        | STS Equivalent                    | Assessment      |
|---------------------------------|------------------------|-----------------------------------|-----------------|
| Fault model                     | Crash-fault            | Byzantine                         | Must change     |
| Identity                        | String ID              | Ed25519 keypair                   | Must change     |
| Wire format                     | JSON/TCP               | Signed envelopes/NATS             | Must change     |
| Decision log                    | In-memory slice        | JetStream + Merkle                | Must change     |
| Rate limiting                   | Token bucket           | Token bucket (per-agent)          | Reuse pattern   |
| Backoff                         | Exponential + jitter   | Exponential + jitter              | Reuse directly  |
| Partition detection             | Healthy peer counting  | Healthy peer counting + SWIM      | Extend pattern  |
| Replication                     | Full list per HB       | Incremental per follower          | Must change     |
| Quorum calculation              | (peers/2) + 1         | (2f+1) of (3f+1)                 | Must change     |
| Leader election                 | Randomized timeout     | VRF-based rotation                | Must change     |
| Message authentication          | None                   | Ed25519 signatures                | Must add        |

---

## 4. Swarm Team Six Consensus Requirements

### 4.1 Decision Categories

STS requires consensus for three categories of decisions, each with different
urgency and safety profiles:

**Response Actions** (highest urgency, highest risk):

```
BlockEgress { target }              -- Blocks network traffic
IsolateHost { host_id }             -- Removes host from network
RevokeCredential { credential_id }  -- Invalidates credential
DeployDecoy { decoy_type, target_zone } -- Deploys honeypot
Escalate { summary, urgency }       -- Alerts human operator
```

These modify the external environment and are irreversible (or costly to reverse).
Consensus must complete within the 5-second round timeout. False-positive
authorization is expensive; false-negative (failure to act) may allow an active
attacker to progress.

**Evolution Commits** (medium urgency, medium risk):

A Kitten agent proposes promoting an evolved detection strategy from canary to
production. The Tom committee evaluates Z3 verification proof and canary metrics.
A compromised Kitten could propose a blind-spot strategy. Consensus prevents
unilateral deployment.

**Trust Decisions** (low urgency, high irreversibility):

Agent admission (new Ed25519 key registered), agent revocation (key revoked,
pheromone deposits flagged), tier promotion/demotion. These change the swarm's
trust boundary and must not be rushed.

### 4.2 Committee Structure

From docs/CONSENSUS.md:

```
Committee size = 3f + 1    (f = max Byzantine faults)
Required votes = 2f + 1

Default: f=1, committee=4, required=3
Scalable: f=2, committee=7, required=5
```

The committee is a subset of Tom agents, rotated via VRF every epoch (default:
3600 seconds). This bounds the collusion window and prevents targeted attacks.

### 4.3 Integration with Middleware Pipeline

Consensus is stage 7 of the 9-stage middleware pipeline:

```
1. IdentityVerification     -- Ed25519 delegation token
2. TierAuthorization        -- autonomy level enforcement
3. PheromoneInjection       -- load relevant NATS trails
4. ContextCompression       -- token-aware summarization
5. GuardPipeline            -- ClawdStrike guard evaluation
6. ToolBoundary             -- action-specific access control
7. ConsensusGate            -- BFT for response actions      <-- HERE
8. EvidenceCollection       -- receipt signing, audit trail
9. EvolutionTracking        -- strategy mutation logging
```

The ConsensusGate blocks the pipeline until consensus is reached or timeout
occurs. This means the consensus implementation must be embeddable as an
async function within the Rust pipeline, not a separate service.

### 4.4 Interaction with Pheromone Substrate

The pheromone substrate provides the evidence context for consensus decisions.
When a Pouncer proposes a response action, stage 3 (PheromoneInjection) attaches
current concentration data. Tom committee members evaluate the proposal partly
based on pheromone evidence -- is the threat signal corroborated by multiple
independent sources?

This creates a bidirectional dependency:

```
Pheromone Substrate                   Consensus Protocol
===================                   ==================
deposits -> concentration -------> evidence for proposals
                                  <------- committed response
                                           actions modify
                                           environment, which
                                           affects future
                                           detections and
                                           pheromone deposits
```

### 4.5 Autonomy Tier Interaction

Not all actions traverse the consensus gate. The tier system filters:

| Tier   | Consensus Required | Example Actions                       |
|--------|-------------------|---------------------------------------|
| Tier 1 | No                | Pheromone deposits, detection, queries |
| Tier 2 | No (report only)  | Investigations, correlation, proposals |
| Tier 3 | Yes               | Response actions, evolution commits    |

Only Tier 3 actions enter the consensus pipeline. This is enforced by
TierAuthorization (stage 2) before the pipeline reaches ConsensusGate (stage 7).

---

## 5. Mapping Sentinel Patterns to Swarm Needs

### 5.1 Pattern: Leader-Based Decision Proposal

**Sentinel:** The leader proposes decisions and replicates them to followers.
Only the leader can call `ProposeDecision`.

**STS mapping:** The VRF-selected proposer for each round proposes an action.
Unlike Raft where the leader persists across multiple decisions, Tendermint
rotates the proposer per round.

**What to keep:** The concept of a designated proposer who serializes decision
ordering. This prevents duplicate or conflicting proposals from being processed
concurrently.

**What to change:** Remove leader stickiness. Each round has a fresh proposer
selected by VRF. If the proposer fails, the round times out and the next
proposer takes over.

### 5.2 Pattern: Quorum-Based Commitment

**Sentinel:**

```go
acks := 1 // Count self
required := (len(n.peers) / 2) + 1
// ...
if acks >= required {
    decision.Committed = true
}
```

**STS mapping:**

```rust
// Tendermint BFT quorum
let f = config.max_byzantine_faults;
let committee_size = 3 * f + 1;
let required = 2 * f + 1;
```

**What to keep:** The quorum check structure. A tally of acknowledgments compared
against a threshold.

**What to change:** The quorum formula changes from majority (n/2 + 1) to
supermajority (2f+1 of 3f+1). The acknowledgment messages must be signed.
The tally must verify signatures and detect equivocation (a Tom sending different
votes to different recipients).

### 5.3 Pattern: Partition Detection and Recovery

**Sentinel:**

```go
healthyPeers := 0
for _, peer := range n.peers {
    if peer.healthy && time.Since(peer.lastSeen) < 5*time.Second {
        healthyPeers++
    }
}
quorum := len(n.peers) / 2
n.partitioned = healthyPeers < quorum
```

**STS mapping:** The Tom committee must detect when it cannot reach quorum.
During a partition, no response actions should be authorized (safety over
liveness). Detection and investigation continue independently via the pheromone
substrate.

**What to keep:** The healthy-peer-counting approach. The partition callback
system for notifying higher-level systems.

**What to extend:** Combine with SWIM-style gossip for more accurate membership
views. Add partition duration tracking (Sentinel already has `PartitionDuration()`)
to enable graduated degradation -- short partitions pause consensus, long
partitions trigger human escalation.

### 5.4 Pattern: Rate Limiting on Consensus Messages

**Sentinel:** Per-peer token bucket rate limiting with configurable burst.

**STS mapping:** Per-agent-ID rate limiting on consensus NATS subjects. A
compromised Tom could flood the consensus channel with invalid proposals or
votes. Rate limiting ensures that even a Byzantine agent cannot consume all
available bandwidth.

```
Sentinel:                          STS:
+-----------+                      +------------------+
| TCP conn  |                      | NATS subject     |
| from peer |   token              | swarm.consensus  |   token
| 10.0.1.5  |-->bucket             | from Tom-0x3f    |-->bucket
+-----------+   (per IP)           +------------------+   (per AgentId)
```

### 5.5 Pattern: Exponential Backoff for Peer Reconnection

**Sentinel:** `calculateBackoff(failures, cfg)` with 100ms initial, 30s max,
2x multiplier, 10% jitter.

**STS mapping:** Apply to NATS connection retry, peer-to-peer consensus channel
establishment, and failed round retry (when a proposer is repeatedly
unreachable).

This pattern transfers directly with no modification needed. The default
parameters are reasonable for both LAN (Sentinel) and NATS-connected (STS)
deployments.

### 5.6 Pattern: Callback-Driven State Notifications

**Sentinel:**

```go
type Config struct {
    DecisionCallback  func(Decision)
    PartitionCallback func(partitioned bool)
}
```

**STS mapping:**

```rust
pub trait ConsensusObserver: Send + Sync {
    fn on_decision_committed(&self, result: &ConsensusResult);
    fn on_partition_detected(&self, partitioned: bool);
    fn on_round_timeout(&self, round: u64);
    fn on_proposer_change(&self, new_proposer: &AgentId, epoch: u64);
}
```

The trait-based approach in Rust is more ergonomic than Go function pointers
and supports multiple observers.

---

## 6. Porting Considerations: Go to Rust

### 6.1 Concurrency Model: goroutines to tokio tasks

Sentinel uses Go's goroutine model extensively:

```go
func (n *Node) Start() error {
    n.wg.Add(1)
    go n.acceptLoop()     // goroutine
    n.wg.Add(1)
    go n.peerConnector()  // goroutine
    n.wg.Add(1)
    go n.electionLoop()   // goroutine
    n.wg.Add(1)
    go n.partitionDetector() // goroutine
    return nil
}
```

In Rust with tokio:

```rust
impl ConsensusNode {
    pub async fn start(&self) -> Result<()> {
        let accept_handle = tokio::spawn(self.clone().accept_loop());
        let election_handle = tokio::spawn(self.clone().election_loop());
        let partition_handle = tokio::spawn(self.clone().partition_detector());

        // Store JoinHandles for graceful shutdown
        self.handles.lock().await.extend([
            accept_handle,
            election_handle,
            partition_handle,
        ]);

        Ok(())
    }
}
```

Key differences:

| Aspect                | Go (Sentinel)               | Rust/tokio (STS)                     |
|-----------------------|-----------------------------|--------------------------------------|
| Spawn cost            | ~2KB stack, cheap           | ~256B future, cheaper                |
| Cancellation          | `context.Context`           | `CancellationToken` or `select!`     |
| Shared state          | `sync.RWMutex`              | `tokio::sync::RwLock` or `Arc<Mutex>`|
| Channel communication | `chan`                       | `tokio::sync::mpsc`                  |
| Timer                 | `time.NewTicker`            | `tokio::time::interval`              |
| Graceful shutdown     | `sync.WaitGroup`            | `JoinSet` or `JoinHandle` collection |

### 6.2 Synchronization: sync.RWMutex to tokio primitives

Sentinel uses `sync.RWMutex` for protecting shared state:

```go
n.mu.Lock()
// mutate state
n.mu.Unlock()
```

In async Rust, standard `std::sync::Mutex` cannot be held across `.await` points.
The options:

**Option A: `tokio::sync::RwLock`**

```rust
let state = self.state.read().await;
// read state
drop(state);
```

Pro: Direct port of the Go pattern. Con: Holding locks across await points can
cause deadlocks under contention.

**Option B: Actor model with `mpsc` channels**

```rust
enum ConsensusCommand {
    ProposeDecision { decision_type: DecisionType, payload: Vec<u8>, reply: oneshot::Sender<Result<Decision>> },
    HandleMessage { msg: Message, reply: oneshot::Sender<Option<Message>> },
    GetState { reply: oneshot::Sender<NodeState> },
}

async fn consensus_actor(mut rx: mpsc::Receiver<ConsensusCommand>, state: ConsensusState) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            ConsensusCommand::ProposeDecision { decision_type, payload, reply } => {
                let result = state.propose(decision_type, payload).await;
                let _ = reply.send(result);
            }
            // ...
        }
    }
}
```

Pro: No lock contention, natural serialization of state mutations.
Con: More boilerplate, indirect call semantics.

**Recommendation for STS:** Use the actor model. Consensus state mutations are
inherently sequential (one round at a time, one proposer at a time). The actor
pattern makes this explicit, avoids async lock deadlocks, and the
`ConsensusCommand` enum doubles as documentation of the consensus API surface.

### 6.3 Network Layer: TCP to NATS

For the broader telemetry bridge design between Sentinel and STS, see
[05-TELEMETRY-BRIDGE-ARCHITECTURE.md](05-TELEMETRY-BRIDGE-ARCHITECTURE.md).

Sentinel uses raw TCP connections with JSON encoding:

```go
func (n *Node) sendMessage(conn net.Conn, msg *Message) error {
    encoder := json.NewEncoder(conn)
    return encoder.Encode(msg)
}
```

STS should use NATS subjects for consensus communication:

```rust
// Publish proposal to consensus subject
nats_client.publish(
    format!("swarm.consensus.{round_id}.propose"),
    serde_json::to_vec(&signed_proposal)?,
).await?;

// Subscribe to prevotes for this round
let mut prevote_sub = nats_client.subscribe(
    format!("swarm.consensus.{round_id}.prevote"),
).await?;
```

Advantages of NATS over raw TCP for consensus:

| Aspect              | Raw TCP (Sentinel)           | NATS (STS)                        |
|---------------------|------------------------------|-----------------------------------|
| Connection mgmt     | Manual per-peer              | Client handles reconnection       |
| Message routing     | Point-to-point               | Pub/sub (natural broadcast)       |
| Durability          | None                         | JetStream persistence             |
| Discovery           | Static peer list             | Subject-based (dynamic)           |
| TLS                 | Manual setup                 | NATS TLS configuration            |
| Backpressure        | Manual flow control          | NATS flow control                 |

### 6.4 Serialization: JSON to Signed Envelopes

Sentinel's message format is plain JSON:

```go
type Message struct {
    Type   MessageType `json:"type"`
    Term   uint64      `json:"term"`
    FromID string      `json:"from_id"`
    // ...
}
```

STS must wrap every consensus message in a signed envelope:

```rust
pub struct SignedConsensusMessage {
    /// The consensus message payload
    pub payload: ConsensusPayload,
    /// Ed25519 signature over canonical JSON of payload
    pub signature: Vec<u8>,
    /// Signer's public key (for verification without registry lookup)
    pub signer_key: Vec<u8>,
    /// Agent ID of the signer
    pub signer_id: AgentId,
}

pub enum ConsensusPayload {
    Propose {
        round: u64,
        epoch: u64,
        value: ConsensusValue,
        evidence: Vec<SignedReceipt>,
    },
    Prevote {
        round: u64,
        epoch: u64,
        value_hash: Option<[u8; 32]>,  // None = NIL vote
    },
    Precommit {
        round: u64,
        epoch: u64,
        value_hash: Option<[u8; 32]>,
    },
}
```

The `swarm-crypto` crate provides Ed25519 signing and RFC 8785 canonical JSON
serialization (JCS), ensuring deterministic signature computation.

### 6.5 Error Handling: Go errors to Rust Result/thiserror

Sentinel uses Go's error pattern:

```go
if n.state != Leader {
    return nil, fmt.Errorf("not the leader")
}
```

STS should use typed errors with `thiserror`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("not the current proposer for round {round}")]
    NotProposer { round: u64 },

    #[error("round {round} timed out after {timeout_ms}ms")]
    RoundTimeout { round: u64, timeout_ms: u64 },

    #[error("insufficient votes: got {got}, need {required}")]
    InsufficientVotes { got: u32, required: u32 },

    #[error("invalid signature from agent {agent_id}")]
    InvalidSignature { agent_id: String },

    #[error("equivocation detected: agent {agent_id} sent conflicting votes")]
    Equivocation { agent_id: String },

    #[error("proposal rejected by guard pipeline: {reason}")]
    GuardDenied { reason: String },

    #[error("network partition: cannot reach quorum")]
    Partitioned,
}
```

### 6.6 Testing: Go table-driven to Rust parameterized

Sentinel's test suite is well-structured with table-driven tests:

```go
tests := []struct {
    name        string
    msg         *Message
    wantGranted bool
}{
    {
        name: "grant vote for higher term",
        msg: &Message{Term: 1, FromID: "candidate", LastLogIndex: 0},
        wantGranted: true,
    },
    // ...
}
```

Rust equivalent using `rstest` or manual parameterization:

```rust
#[test]
fn test_prevote_evaluation() {
    let cases = vec![
        ("valid proposal with evidence", proposal_with_evidence(), true),
        ("proposal without evidence", proposal_no_evidence(), false),
        ("proposal from non-proposer", proposal_wrong_proposer(), false),
        ("proposal with invalid signature", proposal_bad_sig(), false),
    ];
    for (name, proposal, expected_prevote) in cases {
        let result = tom.evaluate_proposal(&proposal);
        assert_eq!(result.prevote_yes, expected_prevote, "case: {name}");
    }
}
```

---

## 7. Alternative Approaches: CRDTs, Virtual Synchrony, Epidemic Protocols

### 7.1 CRDTs for Eventual Consistency

Conflict-Free Replicated Data Types (Shapiro et al., 2011) provide eventual
consistency without coordination. STS already uses OR-Set CRDTs for
investigation lead claiming (docs/AGENTS.md: "Stalkers claim a lead, preventing
duplication via OR-Set CRDTs").

**Where CRDTs fit in STS:**

| Use Case                    | CRDT Type   | Why                                         |
|-----------------------------|-------------|---------------------------------------------|
| Investigation lead claiming | OR-Set      | Add-wins semantics; concurrent claims merge  |
| Pheromone concentration     | G-Counter   | Each agent's deposits are monotonically added|
| Agent health registry       | LWW-Map     | Last-writer-wins for health status           |
| Known-bad indicator set     | OR-Set      | Concurrent additions merge correctly         |

**Where CRDTs do NOT fit:**

CRDTs cannot provide the ordering guarantee needed for response actions.
Two concurrent `BlockEgress` proposals cannot both be "right" -- the committee
must choose one or neither. CRDTs provide commutativity and convergence, not
agreement on a single value.

```
+----------------------------------------------+
|           STS Consistency Spectrum            |
|                                              |
| Eventual (CRDTs)  |  Stigmergic  |  Strong  |
| - OR-Set claims    |  - Pheromone |  - BFT   |
| - Health registry  |    substrate |  Tendermint|
| - Indicator sets   |  - Mode      |  - Response|
|                    |    transitions|    actions |
|                    |              |  - Evolution|
|                    |              |    commits  |
+----------------------------------------------+
```

### 7.2 Virtual Synchrony

Virtual synchrony (Birman & Joseph, 1987) provides a membership service with
the guarantee that all members of a group observe the same sequence of membership
changes and message deliveries. Systems like Isis2 and JGroups implement this.

**Relevance to STS:** The Tom committee's epoch transitions (VRF-based rotation)
are essentially a form of virtual synchrony -- all committee members must agree
on who is in the current committee and who the proposer is for each round.

**Assessment:** Virtual synchrony is more complex than STS needs. The VRF-based
rotation already provides the "view change" semantics, and Tendermint's round
mechanism handles the "message ordering within a view" guarantee. Implementing
full virtual synchrony would add complexity without clear benefit.

### 7.3 Epidemic (Gossip) Protocols

Epidemic protocols (Demers et al., 1987) disseminate information through random
peer exchanges. Each node periodically contacts a random peer and exchanges
state updates. Information spreads like an epidemic -- O(log n) rounds to reach
all nodes with high probability.

**STS application:** Gossip is ideal for two STS subsystems:

1. **Agent health and membership** (`swarm.gossip.{agent_id}`). Each agent
   periodically gossips its health status. SWIM-style failure detection provides
   fast, distributed failure detection without a central monitor.

2. **Pheromone concentration dissemination**. While pheromone deposits go through
   NATS JetStream (reliable, ordered), concentration summaries can be gossipped
   for fast propagation of threat-level estimates.

Gossip should NOT be used for consensus decisions. It provides eventual
consistency but no agreement on a single value. A gossip-propagated "consensus"
can result in different agents observing different "decisions."

```
Agent Health Gossip (SWIM-style):
==================================

Round 1:  Tom-1 pings Tom-3          Round 2:  Tom-2 pings Tom-4
          Tom-2 pings Tom-1                    Tom-3 pings Tom-1
          Tom-3 pings Tom-4                    Tom-4 pings Tom-2
          Tom-4 pings Tom-2                    Tom-1 pings Tom-3

          Piggyback: "Tom-3 alive"             Piggyback: "Tom-3 alive"
                                               "Tom-1 updated health"

After O(log n) rounds, all agents have consistent membership view.
```

### 7.4 Hybrid Approach (Recommended for STS)

The recommended architecture uses different consistency mechanisms for
different concerns:

```
+-------------------------------------------------------------------+
|                     STS Consistency Stack                          |
|                                                                   |
|  Layer 4: BFT Consensus (Tendermint)                              |
|           - Response action authorization                         |
|           - Evolution commits                                     |
|           - Trust decisions                                       |
|           - Linearizable, 2f+1 agreement                          |
|                                                                   |
|  Layer 3: Stigmergic Coordination (Pheromones)                    |
|           - Detection signal aggregation                          |
|           - Mode transitions                                      |
|           - Source-diverse, decay-weighted, emergent               |
|                                                                   |
|  Layer 2: Gossip (SWIM)                                           |
|           - Agent health monitoring                               |
|           - Committee membership view                             |
|           - Eventual consistency, O(log n) convergence             |
|                                                                   |
|  Layer 1: CRDTs                                                   |
|           - Investigation lead claiming (OR-Set)                  |
|           - Indicator registry (OR-Set)                           |
|           - Agent health map (LWW-Map)                            |
|           - Conflict-free, eventually consistent                  |
|                                                                   |
+-------------------------------------------------------------------+
```

---

## 8. Reference Architecture for swarm-consensus

### 8.1 Crate Structure

```
crates/swarm-consensus/
  src/
    lib.rs              -- Public API and re-exports
    config.rs           -- ConsensusConfig, CommitteeConfig
    types.rs            -- ConsensusRound, Vote, Proposal, ConsensusResult
    committee.rs        -- VRF rotation, membership management
    protocol.rs         -- Tendermint state machine (propose/prevote/precommit)
    transport.rs        -- NATS-backed message dispatch and collection
    crypto.rs           -- Thin wrapper around swarm-crypto for consensus sigs
    rate_limit.rs       -- Token bucket rate limiter (ported from Sentinel)
    backoff.rs          -- Exponential backoff with jitter (ported from Sentinel)
    partition.rs        -- Partition detection (adapted from Sentinel)
    error.rs            -- ConsensusError enum
    observer.rs         -- ConsensusObserver trait
  tests/
    round_test.rs       -- Single-round consensus tests
    partition_test.rs   -- Partition and recovery tests
    byzantine_test.rs   -- Byzantine fault tests (equivocation, invalid sigs)
    committee_test.rs   -- VRF rotation tests
    integration_test.rs -- Multi-node integration tests
```

### 8.2 Core Types

```rust
/// Configuration for the consensus subsystem.
pub struct ConsensusConfig {
    /// Maximum Byzantine faults tolerated.
    /// Committee size = 3f+1, required votes = 2f+1.
    pub max_byzantine_faults: u32,

    /// Timeout for a single consensus round in milliseconds.
    pub round_timeout_ms: u64,

    /// How often to rotate committee membership via VRF (seconds).
    pub committee_rotation_interval_secs: u64,

    /// Rate limiting for incoming consensus messages.
    pub rate_limit: RateLimitConfig,
}

/// A proposal submitted to the consensus protocol.
pub struct Proposal {
    /// Unique proposal ID.
    pub id: String,

    /// Round number within the current epoch.
    pub round: u64,

    /// Current epoch (VRF rotation period).
    pub epoch: u64,

    /// The proposed value (response action, evolution commit, or trust decision).
    pub value: ConsensusValue,

    /// Supporting evidence chain (signed receipts from detection agents).
    pub evidence: Vec<SignedReceipt>,

    /// Ed25519 signature of the proposer.
    pub signature: Vec<u8>,

    /// Public key of the proposer.
    pub proposer_key: Vec<u8>,
}

/// The value being proposed for consensus.
pub enum ConsensusValue {
    ResponseAction(ResponseAction),
    EvolutionCommit(EvolutionCommit),
    TrustDecision(TrustDecision),
}

/// A signed vote (prevote or precommit).
pub struct Vote {
    /// Round this vote applies to.
    pub round: u64,

    /// Epoch this vote applies to.
    pub epoch: u64,

    /// Hash of the proposed value (None = NIL vote).
    pub value_hash: Option<[u8; 32]>,

    /// Vote phase.
    pub phase: VotePhase,

    /// Voter identity.
    pub voter_id: AgentId,

    /// Ed25519 signature.
    pub signature: Vec<u8>,
}

pub enum VotePhase {
    Prevote,
    Precommit,
}

/// Result of a consensus round.
pub struct ConsensusResult {
    pub hunt_id: HuntId,
    pub round: u64,
    pub epoch: u64,
    pub reached: bool,
    pub approve_count: u32,
    pub deny_count: u32,
    pub total_voters: u32,
    pub threshold: u32,
    /// Collected votes with signatures (for audit trail).
    pub votes: Vec<Vote>,
    /// The committed value (if consensus reached).
    pub committed_value: Option<ConsensusValue>,
}
```

### 8.3 Tendermint State Machine

The core protocol is a state machine driven by incoming messages and timeouts:

```
                          +-------------------+
                          |                   |
                          v                   |
                  +---------------+           |
     +----------->|   NewRound    |           |
     |            +-------+-------+           |
     |                    |                   |
     |                    | (if proposer)     |
     |                    v                   |
     |            +-------+-------+           |
     |            |    Propose    |           |
     |            +-------+-------+           |
     |                    |                   |
     |                    | (broadcast)       |
     |                    v                   |
     |            +-------+-------+           |
     |            |    Prevote    |           |
     |  timeout   +-------+-------+           |
     |  OR            |       |               |
     |  round         |       |               |
     |  advance       | 2f+1  | timeout       |
     |                | YES   | OR < 2f+1     |
     |                v       v               |
     |            +---+-------+---+           |
     |            |   Precommit   |           |
     |            +---+-------+---+           |
     |                |       |               |
     |                | 2f+1  | timeout       |
     |                | YES   |               |
     |                v       +---------------+
     |            +---+-------+
     |            |   Commit   |
     |            +---+--------+
     |                |
     +----------------+
         (next round)
```

### 8.4 Protocol Implementation Sketch

```rust
/// The consensus protocol state machine.
pub struct ProtocolState {
    /// Current round within the epoch.
    round: u64,

    /// Current epoch (VRF rotation period).
    epoch: u64,

    /// Current phase of the round.
    phase: RoundPhase,

    /// This node's agent identity.
    agent_id: AgentId,

    /// The active committee for this epoch.
    committee: Committee,

    /// Collected prevotes for the current round.
    prevotes: BTreeMap<AgentId, Vote>,

    /// Collected precommits for the current round.
    precommits: BTreeMap<AgentId, Vote>,

    /// Locked value (Tendermint locking mechanism).
    /// If set, this node must prevote for this value in subsequent rounds.
    locked_value: Option<(u64, [u8; 32])>,  // (locked_round, value_hash)

    /// Valid value (last value for which 2f+1 prevotes were observed).
    valid_value: Option<ConsensusValue>,
}

enum RoundPhase {
    NewRound,
    Propose,
    Prevote,
    Precommit,
    Committed,
}

impl ProtocolState {
    /// Process an incoming consensus message.
    /// Returns zero or more outgoing messages to broadcast.
    pub fn handle_message(
        &mut self,
        msg: &SignedConsensusMessage,
        verifier: &dyn SignatureVerifier,
    ) -> Result<Vec<SignedConsensusMessage>, ConsensusError> {
        // 1. Verify signature
        verifier.verify(&msg.payload_bytes(), &msg.signature, &msg.signer_key)
            .map_err(|_| ConsensusError::InvalidSignature {
                agent_id: msg.signer_id.to_string(),
            })?;

        // 2. Verify sender is in current committee
        if !self.committee.contains(&msg.signer_id) {
            return Err(ConsensusError::NotCommitteeMember {
                agent_id: msg.signer_id.to_string(),
            });
        }

        // 3. Check for equivocation
        self.detect_equivocation(msg)?;

        // 4. Dispatch by message type
        match &msg.payload {
            ConsensusPayload::Propose { .. } => self.handle_propose(msg),
            ConsensusPayload::Prevote { .. } => self.handle_prevote(msg),
            ConsensusPayload::Precommit { .. } => self.handle_precommit(msg),
        }
    }

    fn handle_prevote(
        &mut self,
        msg: &SignedConsensusMessage,
    ) -> Result<Vec<SignedConsensusMessage>, ConsensusError> {
        // Store the prevote
        if let ConsensusPayload::Prevote { round, value_hash, .. } = &msg.payload {
            self.prevotes.insert(msg.signer_id.clone(), Vote { /* ... */ });
        }

        // Check if we have 2f+1 prevotes for the same value
        let f = self.committee.max_byzantine_faults();
        let required = 2 * f + 1;

        let prevote_counts = self.count_prevotes_by_value();
        for (value_hash, count) in &prevote_counts {
            if *count >= required {
                // Transition to precommit phase
                self.phase = RoundPhase::Precommit;

                if let Some(hash) = value_hash {
                    // Lock on this value
                    self.locked_value = Some((self.round, *hash));
                }

                // Broadcast our precommit
                let precommit = self.create_precommit(*value_hash)?;
                return Ok(vec![precommit]);
            }
        }

        Ok(vec![])
    }
}
```

### 8.5 Rate Limiter (Ported from Sentinel)

Direct port of Sentinel's token bucket, adapted for Rust:

```rust
/// Token bucket rate limiter.
/// Direct port from Sentinel's `raft_lite.go` tokenBucket.
pub struct TokenBucket {
    tokens: u32,
    max_tokens: u32,
    refill_rate: u32,  // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Check if a request is allowed and consume a token if so.
    pub fn allow(&mut self) -> bool {
        // Refill tokens based on elapsed time
        let elapsed = self.last_refill.elapsed();
        let tokens_to_add = (elapsed.as_secs_f64() * self.refill_rate as f64) as u32;
        if tokens_to_add > 0 {
            self.tokens = (self.tokens + tokens_to_add).min(self.max_tokens);
            self.last_refill = Instant::now();
        }

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Per-agent rate limiter registry.
/// Adapted from Sentinel's getOrCreateLimiter pattern.
pub struct RateLimiterRegistry {
    limiters: DashMap<AgentId, Mutex<TokenBucket>>,
    config: RateLimitConfig,
}

impl RateLimiterRegistry {
    pub fn check(&self, agent_id: &AgentId) -> bool {
        let entry = self.limiters.entry(agent_id.clone()).or_insert_with(|| {
            Mutex::new(TokenBucket::new(
                self.config.burst_size,
                self.config.max_messages_per_second,
            ))
        });
        entry.lock().unwrap().allow()
    }
}
```

### 8.6 Backoff (Ported from Sentinel)

```rust
/// Exponential backoff configuration.
/// Direct port from Sentinel's `backoffConfig`.
pub struct BackoffConfig {
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
    pub jitter_fraction: f64,  // 0.0-1.0, Sentinel uses 0.1
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
            jitter_fraction: 0.1,
        }
    }
}

/// Calculate backoff duration for a given failure count.
/// Direct port from Sentinel's `calculateBackoff`.
pub fn calculate_backoff(failures: u32, config: &BackoffConfig) -> Duration {
    if failures == 0 {
        return config.initial_delay;
    }

    let mut delay = config.initial_delay;
    for _ in 0..failures {
        delay = Duration::from_secs_f64(
            (delay.as_secs_f64() * config.multiplier).min(config.max_delay.as_secs_f64())
        );
    }

    // Add jitter
    let jitter_range = (delay.as_secs_f64() * config.jitter_fraction) as u64;
    if jitter_range > 0 {
        let jitter = Duration::from_millis(rand::thread_rng().gen_range(0..=jitter_range * 1000));
        delay + jitter
    } else {
        delay
    }
}
```

### 8.7 Partition Detector (Adapted from Sentinel)

```rust
/// Partition detector adapted from Sentinel's partitionDetector.
/// Extended with SWIM-style indirect probing.
pub struct PartitionDetector {
    /// Known committee members and their last-seen timestamps.
    peers: HashMap<AgentId, PeerHealth>,

    /// Current partition state.
    partitioned: bool,

    /// When the current partition started (if partitioned).
    partition_start: Option<Instant>,

    /// Configuration.
    config: PartitionConfig,
}

struct PeerHealth {
    last_seen: Instant,
    healthy: bool,
    consecutive_failures: u32,
    next_probe_time: Instant,
}

pub struct PartitionConfig {
    /// How long before a peer is considered unhealthy.
    pub health_timeout: Duration,

    /// Minimum healthy peers to not be partitioned.
    /// Derived from BFT quorum: need 2f+1 of 3f+1 committee members.
    pub quorum_size: u32,

    /// Probe interval.
    pub probe_interval: Duration,

    /// Backoff config for probing unhealthy peers.
    pub backoff: BackoffConfig,
}

impl PartitionDetector {
    /// Evaluate current partition state.
    /// Adapted from Sentinel's partitionDetector goroutine tick.
    pub fn evaluate(&mut self) -> Option<PartitionEvent> {
        let now = Instant::now();
        let mut healthy_count = 0u32;

        for (_, peer) in &self.peers {
            if peer.healthy && now.duration_since(peer.last_seen) < self.config.health_timeout {
                healthy_count += 1;
            }
        }

        let was_partitioned = self.partitioned;
        self.partitioned = healthy_count < self.config.quorum_size;

        match (was_partitioned, self.partitioned) {
            (false, true) => {
                self.partition_start = Some(now);
                Some(PartitionEvent::Detected {
                    healthy_peers: healthy_count,
                    required: self.config.quorum_size,
                })
            }
            (true, false) => {
                let duration = self.partition_start
                    .map(|start| now.duration_since(start))
                    .unwrap_or_default();
                self.partition_start = None;
                Some(PartitionEvent::Healed { duration })
            }
            _ => None,
        }
    }
}
```

### 8.8 End-to-End Flow

```
Pouncer proposes BlockEgress:

1. Pouncer -> Middleware Pipeline
   Stages 1-6 pass (identity verified, tier authorized, guard approved)

2. Stage 7: ConsensusGate
   a. Pouncer submits proposal to consensus actor
   b. Consensus actor checks: is this node the current proposer?
      - If yes: broadcast Propose to committee via NATS
      - If no: forward to current proposer, wait for proposal

3. Proposal broadcast:
   swarm.consensus.{round}.propose <- SignedProposal

4. Each Tom evaluates independently:
   a. Verify proposal signature
   b. Verify proposer is VRF-selected for this round
   c. Verify evidence chain signatures
   d. Run proposal through guard pipeline
   e. Check autonomy tier
   f. If all pass: broadcast Prevote(YES)
      If any fail: broadcast Prevote(NIL)

5. Prevote collection:
   swarm.consensus.{round}.prevote <- SignedPrevote (from each Tom)

6. Each Tom observes prevotes:
   - If 2f+1 Prevote(YES): broadcast Precommit(YES), lock on value
   - If timeout: broadcast Precommit(NIL)

7. Precommit collection:
   swarm.consensus.{round}.precommit <- SignedPrecommit (from each Tom)

8. Each Tom observes precommits:
   - If 2f+1 Precommit(YES): COMMIT
     -> Create ConsensusResult
     -> Sign receipt
     -> Publish to swarm.audit.receipt.{agent_id}
   - If timeout: advance to next round with new proposer

9. Stage 8: EvidenceCollection
   Signed receipt anchored in Merkle audit trail

10. Pouncer executes BlockEgress with capability lease from committed result
```

---

## 9. Academic References and Industry Precedents

### 9.1 Foundational Papers

**Raft: In Search of an Understandable Consensus Algorithm**
(Ongaro & Ousterhout, 2014, USENIX ATC)

The canonical Raft paper. Sentinel's implementation follows this design with
simplifications for edge deployment. Key insight for STS: Raft's leader-based
approach is efficient but requires trust in the leader. BFT variants (like
Tendermint) remove this trust assumption at the cost of additional message
rounds.

**Practical Byzantine Fault Tolerance**
(Castro & Liskov, 1999, OSDI)

Proved BFT consensus is practical (not just theoretically possible). PBFT's
three-phase protocol (pre-prepare, prepare, commit) directly influenced
Tendermint's propose-prevote-precommit design. The O(n^2) message complexity
is the key scalability constraint inherited by all PBFT-derived protocols.

**Tendermint: Byzantine Fault Tolerance in the Age of Blockchains**
(Buchman, 2016, Master's thesis; Buchman, Kwon & Milosevic, 2018)

STS's target protocol. Key innovations over PBFT: deterministic proposer
rotation (vs. view changes), locked-value mechanism (vs. view-change proofs),
and round-based progression (vs. sequence-number-based).

**The latest gossip on BFT consensus**
(Buchman, Kwon & Milosevic, 2018)

Formal specification of Tendermint consensus with correctness proofs. Essential
reading for implementing the locked-value mechanism and understanding the
conditions under which safety and liveness are guaranteed.

### 9.2 Failure Detection and Membership

**SWIM: Scalable Weakly-consistent Infection-style Process Group Membership
Protocol**
(Das, Gupta & Muthukrishnan, 2002, DSN)

The foundation for modern membership protocols (used by Consul's Serf, Akka
Cluster). SWIM combines failure detection with membership dissemination through
infection-style gossip. For STS, SWIM is the right substrate for the
`swarm.gossip.{agent_id}` layer.

**Lifeguard: Local Health Awareness for More Accurate Failure Detection**
(Butcher et al., 2018, HashiCorp Research)

Extends SWIM with local health awareness. A node that suspects its own health
is degraded adjusts its gossip behavior to avoid being falsely declared dead.
Relevant for STS agents that may experience temporary resource pressure (e.g.,
a Whisker processing a burst of telemetry events).

### 9.3 CRDTs and Eventual Consistency

**A Comprehensive Study of Convergent and Commutative Replicated Data Types**
(Shapiro et al., 2011, INRIA Research Report)

The foundational CRDT taxonomy. OR-Sets (observed-remove sets) are directly
applicable to STS's investigation lead claiming and indicator set management.

**Conflict-Free Replicated Data Types: An Overview**
(Shapiro et al., 2018, Encyclopedia of Database Systems)

Accessible overview of CRDTs with implementation guidance. Key insight for
STS: CRDTs are composable -- an OR-Set of `AgentId` for membership combined
with a G-Counter per agent for pheromone deposits creates a conflict-free
pheromone substrate.

### 9.4 Security-Specific Consensus

**BFT for AI Safety**
(arXiv 2504.14668, 2025)

Formalizes the treatment of unreliable AI agents as Byzantine nodes. Directly
supports STS's design decision to use BFT consensus for response actions.
Demonstrates that standard BFT mechanisms apply to multi-agent AI systems.

**Formal Verification Properties for Agent Systems**
(arXiv 2510.14133, 2025)

Defines temporal logic properties for multi-agent systems. STS's safety
property ("Pouncer never acts without 2/3 Tom consensus") is expressible in
LTL and verifiable by Z3.

**NATO AICA Reference Architecture**
(Kott et al., 2019)

The NATO reference for autonomous cyber-defense agents. Validates that
cyber-defense agents must be Byzantine-fault-tolerant by default, as they
operate in environments where the adversary may control infrastructure.

### 9.5 Industry Precedents

**HashiCorp Consul**

Consul uses Raft for service discovery consensus and SWIM (via Serf) for
membership and failure detection. This two-layer approach -- strong consistency
for coordination decisions, eventual consistency for membership -- maps directly
to STS's architecture (BFT consensus for response actions, gossip for agent
health).

**CockroachDB**

Uses Raft groups per range for distributed SQL consensus. CockroachDB's
experience shows that Raft performance degrades significantly beyond ~10 nodes
per group, validating STS's decision to keep the Tom committee small (4-10
members) and use gossip for broader membership.

**Tendermint/CometBFT (Cosmos SDK)**

Production implementation of Tendermint consensus for blockchain applications.
The CometBFT codebase (Go) is a reference implementation for STS's Rust port.
Key lessons: the locked-value mechanism is essential for safety across rounds;
evidence collection (detecting and proving equivocation) is necessary for
accountability.

**Narwhal and Tusk (Mysten Labs/Sui)**

DAG-based BFT consensus that separates data availability from consensus
ordering. Achieves higher throughput than traditional BFT protocols.
Potentially relevant for future STS versions where consensus throughput
becomes a bottleneck (e.g., many concurrent evolution proposals).

---

## 10. Open Questions and Trade-offs

### 10.1 When to Implement Consensus

The STS roadmap places consensus at Phase 6 ("Optional Advanced Governance").
The Rust-first migration doc explicitly defers it: "distributed consensus is
deferred until the single-node live-response path is real."

This is correct. The deterministic policy gate (`swarm-policy`) provides
sufficient safety for a single-node deployment. BFT consensus adds value only
when multiple nodes exist that might disagree or be compromised.

**Recommendation:** Implement the policy gate (Phase 2) first. When multi-node
deployment is needed, start with the rate limiter, backoff, and partition
detector (portable patterns from Sentinel). Only then build the Tendermint
state machine.

### 10.2 Committee Size vs. Latency

Larger committees provide stronger Byzantine resistance but increase consensus
latency (more messages, more signature verifications):

```
f=1, n=4:   3 signatures to verify per phase, 3 phases = 9 verifications
f=2, n=7:   5 signatures per phase, 3 phases = 15 verifications
f=3, n=10:  7 signatures per phase, 3 phases = 21 verifications
```

Ed25519 verification is fast (~71us per verification on modern hardware), so
even f=3 adds only ~1.5ms of verification overhead. The real cost is network
round-trip time per phase. With NATS (typically <1ms intra-cluster), three
phases cost ~3ms plus verification. The 5-second round timeout provides ample
margin.

**Recommendation:** Default to f=1 (committee of 4). Allow f=2 (committee of 7)
for high-security deployments. Do not exceed f=3 unless the deployment has
demonstrable need.

### 10.3 Locking Mechanism Complexity

Tendermint's locked-value mechanism prevents equivocation across rounds but
adds significant state management complexity. An agent that precommits in
round R is locked and must prevote for the same value in round R+1.

**The risk of omitting locking:** Without locking, a Byzantine proposer in
round R+1 could propose a different value, and honest agents might prevote
for it (because they did not lock on the round R value). This can lead to
two different values being committed by different subsets of honest agents --
a safety violation.

**Recommendation:** Implement locking. It is essential for safety. The
complexity is manageable in a well-structured state machine. Sentinel's
simpler approach (no locking, single leader) is insufficient for BFT.

### 10.4 VRF Implementation

The VRF (Verifiable Random Function) for proposer rotation requires a
cryptographic VRF implementation. Options:

| Implementation         | Language | Curve      | Notes                          |
|------------------------|----------|------------|--------------------------------|
| `vrf-rs`               | Rust     | Ed25519    | Thin wrapper, limited audit    |
| `ecvrf` (draft-irtf)   | Rust     | P-256      | IETF draft standard            |
| Custom on ed25519-dalek | Rust     | Ed25519    | Possible building block, but do not ship an ad hoc VRF without review |

**Recommendation:** Do **not** treat a plain Ed25519 signature as a VRF. For
an initial implementation, prefer deterministic proposer rotation
(round-robin or Tendermint-style weighted rotation) until the team selects an
audited VRF/ECVRF implementation with documented security properties. If
unpredictable committee rotation becomes a hard requirement, adopt an audited
VRF crate and record the choice in an ADR before implementation.

### 10.5 Recovery After Partition

When a partition heals, the committee may have diverged:

- Different sides may have advanced to different rounds.
- One side may have committed a value that the other side has not seen.
- Locked values from pre-partition rounds may conflict with post-partition
  proposals.

Tendermint handles this through the round advancement mechanism: when agents
reconnect, they exchange their current round and lock state. The agent in the
higher round "catches up" the agent in the lower round. Committed values are
propagated through the gossip layer.

**Open question:** How does STS handle decisions made during partition that
need reconciliation with the control plane? Sentinel has
`GetUnreconciledDecisions()` for this, but it pushes reconciliation to the
caller. STS may need a formal reconciliation protocol for post-partition
recovery.

### 10.6 Consensus vs. Policy Gate

A key trade-off in the STS architecture:

```
Policy Gate (deterministic, single-node)
  Pro: Fast, deterministic, no network dependency, no Byzantine risk
  Con: No distributed agreement, single point of failure

BFT Consensus (distributed, multi-node)
  Pro: Resilient to compromised nodes, distributed agreement
  Con: Slower (3 network round-trips), requires committee availability
```

For many deployment scenarios, the policy gate alone is sufficient. Consensus
adds value specifically when:

1. Multiple nodes must agree before acting (distributed response coordination).
2. Individual nodes may be compromised (Byzantine fault tolerance).
3. Audit requirements demand proof of multi-party agreement.

**Recommendation:** Make consensus optional. The `swarm-policy` crate provides
the safety floor. `swarm-consensus` provides the governance ceiling. A
deployment can run with policy-only (single-node, Phases 1-5) and add
consensus (Phase 6) when operationally justified.

### 10.7 Async Runtime Coupling

STS's `Cargo.toml` already specifies `tokio.workspace = true` for
swarm-consensus. This couples the consensus implementation to tokio.

**Trade-off:**
- Pro: Consistency with the rest of the STS runtime. Tokio's `select!`,
  `JoinSet`, `mpsc`, and `Interval` are natural fits for consensus protocol
  implementation.
- Con: Testing requires a tokio test runtime. Deterministic testing (simulated
  time, simulated network) requires tokio test utilities or a custom clock
  abstraction.

**Recommendation:** Accept the tokio coupling. Use `tokio::time::pause()` in
tests for deterministic timer behavior. Inject a `Clock` trait if wall-clock
independence becomes necessary for replay testing.

### 10.8 What Sentinel Teaches That Papers Do Not

The most valuable patterns from Sentinel are not consensus-specific -- they are
engineering patterns for building reliable distributed systems:

1. **Rate limiting at the protocol layer.** Most consensus papers assume a
   well-behaved network. Sentinel's token bucket rate limiter protects against
   message floods that could overwhelm the consensus node. This is essential in
   adversarial environments.

2. **Exponential backoff with jitter.** The thundering herd problem after
   partition healing is real. Sentinel's backoff implementation with 10% jitter
   is a pragmatic solution that consensus papers rarely address.

3. **Partition detection as a first-class concern.** Sentinel does not just
   handle partitions -- it actively detects them and notifies the application.
   This enables graduated degradation: continue detection (safe), halt
   response actions (prevent split-brain), escalate to humans (if partition
   persists).

4. **Circuit breaker composition.** Sentinel's adjacent circuit breaker pattern
   (in `pkg/k8s/circuit_breaker.go`) shows how to protect upstream services
   from cascading failures during consensus disruptions.

5. **Decision callback system.** Simple, effective. The callback pattern lets
   higher-level systems react to consensus events without polling.

These patterns should be ported to STS regardless of which consensus algorithm
is chosen. They represent production engineering wisdom that is orthogonal to
the theoretical consensus guarantees. For a comprehensive catalog of these
resilience patterns, see
[08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md).

---

## Appendix A: Sentinel Source Reference

### File Inventory

| File                                    | Lines | Purpose                              |
|-----------------------------------------|-------|--------------------------------------|
| `pkg/consensus/raft_lite.go`            | 917   | Raft-lite consensus implementation   |
| `pkg/consensus/raft_lite_test.go`       | 633   | Unit and integration tests           |
| `pkg/k8s/circuit_breaker.go`            | 196   | Circuit breaker pattern              |
| `pkg/k8s/circuit_breaker_test.go`       | 211   | Circuit breaker tests                |
| `pkg/healthscore/predictor.go`          | 751   | Predictive failure scoring (see [02](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md)) |
| `pkg/healthscore/predictor_test.go`     | 1080  | Predictor tests                      |

### Key Constants (Sentinel Defaults)

```go
// Consensus timing
ElectionTimeout:   150ms   (randomized: [150ms, 300ms])
HeartbeatInterval: 50ms

// Rate limiting
MaxMessagesPerSecond: 100
BurstSize:           20

// Exponential backoff
initialDelay: 100ms
maxDelay:     30s
multiplier:   2.0
jitter:       10% of delay

// Partition detection
healthTimeout: 5s
probeInterval: 100ms

// Circuit breaker (adjacent)
FailureThreshold: 5
SuccessThreshold: 2
Timeout:          30s
```

---

## Appendix B: STS Source Reference

### Consensus-Related Files

| File                                          | Status   | Purpose                            |
|-----------------------------------------------|----------|------------------------------------|
| `crates/swarm-consensus/src/lib.rs`           | Stub     | BFT consensus (TODO)               |
| `crates/swarm-consensus/Cargo.toml`           | Complete | Dependencies declared              |
| `docs/CONSENSUS.md`                           | Complete | Protocol specification             |
| `docs/AGENTS.md`                              | Complete | Agent archetypes and tiers         |
| `docs/PHEROMONES.md`                          | Complete | Stigmergic coordination layer      |
| `docs/EVOLUTION.md`                           | Complete | Co-evolutionary arms race          |
| `docs/INTEGRATION.md`                         | Complete | System integration architecture    |
| `docs/ROADMAP.md`                             | Complete | Rust-first implementation roadmap  |
| `.planning/research/ARCHITECTURE.md`          | Complete | Component boundaries               |

### STS Consensus Configuration (from docs/CONSENSUS.md)

```yaml
consensus:
  max_byzantine_faults: 1
  round_timeout_ms: 5000
  committee_rotation_interval_secs: 3600

autonomy:
  tier1_confidence: 0.9
  tier2_confidence: 0.7
  require_human_above_severity: high
```

### Existing swarm-consensus Dependencies

```toml
[dependencies]
swarm-core.workspace = true
async-trait.workspace = true
ed25519-dalek.workspace = true
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
tracing.workspace = true
thiserror.workspace = true
```

All necessary cryptographic and async dependencies are already declared.
The crate is ready for implementation.

---

## Appendix C: Implementation Priority Matrix

Based on this research, the recommended implementation order for swarm-consensus
when Phase 6 begins:

| Priority | Component              | Source           | Effort | Risk  |
|----------|------------------------|------------------|--------|-------|
| 1        | Rate limiter           | Port Sentinel    | Low    | Low   |
| 2        | Backoff with jitter    | Port Sentinel    | Low    | Low   |
| 3        | Partition detector     | Adapt Sentinel   | Low    | Low   |
| 4        | Consensus types        | New (from spec)  | Medium | Low   |
| 5        | Signed message layer   | swarm-crypto     | Medium | Low   |
| 6        | Committee/VRF          | New (from spec)  | Medium | Med   |
| 7        | Tendermint state mach. | New (from spec)  | High   | High  |
| 8        | NATS transport         | New              | Medium | Med   |
| 9        | Equivocation detection | New              | Medium | Med   |
| 10       | Integration tests      | New              | Medium | Low   |

Items 1-3 can be implemented and tested independently of the consensus protocol
itself. They provide immediate value for reliability even before BFT consensus
is online.

---

## Appendix D: Glossary

| Term                   | Definition                                                            |
|------------------------|-----------------------------------------------------------------------|
| BFT                    | Byzantine Fault Tolerance -- resilience to arbitrarily malicious nodes|
| CRDT                   | Conflict-Free Replicated Data Type                                   |
| Epoch                  | VRF rotation period (default: 1 hour)                                |
| Equivocation           | A node sending conflicting votes to different recipients             |
| Locked value           | Tendermint mechanism preventing cross-round equivocation             |
| OR-Set                 | Observed-Remove Set (CRDT with add-wins semantics)                   |
| Proposer               | The committee member designated to propose a value for a round       |
| Quorum                 | Minimum number of votes for a decision (2f+1 in BFT)                |
| Round                  | A single attempt to reach consensus on a value                       |
| Stigmergy              | Indirect coordination through environmental modification            |
| SWIM                   | Scalable Weakly-consistent Infection-style Membership protocol       |
| Tom committee          | The BFT consensus committee in STS                                   |
| VRF                    | Verifiable Random Function -- deterministic, unpredictable selection  |

---

## Cross-References

This document is part 1 of the 8-part Sentinel Convergence research series. Each
document explores a different facet of the integration between Sentinel's
infrastructure-level patterns and STS's security-focused agent architecture.

| # | Document | Relevance to This Document |
|---|----------|---------------------------|
| 02 | [Predictive Failure as Threat Signal](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | How Sentinel's health-score predictor feeds threat signals into the STS detection pipeline -- the upstream data that consensus decisions act upon. |
| 03 | [Edge-Native Security Detection](03-EDGE-NATIVE-SECURITY-DETECTION.md) | Adapting Sentinel's edge-optimized detection patterns (resource constraints, intermittent connectivity) for STS Whisker agents. |
| 04 | [Autonomous Response Under Partition](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) | The safety/liveness trade-offs when the Tom committee is partitioned -- directly extends Section 5.3 (Partition Detection) and Section 10.5 (Recovery After Partition). |
| 05 | [Telemetry Bridge Architecture](05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | Design of `swarm-ingest-sentinel`, the bridge crate connecting Sentinel telemetry to STS. Defines the transport layer that consensus messages may share. |
| 06 | [Stigmergic Coordination and Swarm Intelligence](06-STIGMERGIC-COORDINATION-AND-SWARM-INTELLIGENCE.md) | Deep analysis of the pheromone substrate as a complement to BFT consensus -- extends Section 2.6 and the hybrid approach in Section 7.4. |
| 07 | [Audit Trails and Decision Reconciliation](07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md) | Merkle-anchored receipt chains for consensus decisions -- the durability layer that replaces Sentinel's in-memory decision log (Section 3.3.3). |
| 08 | [Resilience Patterns for Distributed Agents](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) | Comprehensive catalog of the engineering patterns identified in Section 10.8 (rate limiting, backoff, circuit breakers, partition detection). |
