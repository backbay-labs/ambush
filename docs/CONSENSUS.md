# BFT Consensus and Governance

> Historical note: this document describes a deferred governance track. Consensus is no longer on the first critical path for STS.

Technical reference for the Byzantine fault-tolerant consensus protocol and autonomy governance model in Swarm Team Six.

---

## Table of Contents

1. [When Consensus Is Required](#when-consensus-is-required)
2. [Tendermint-Style Protocol](#tendermint-style-protocol)
3. [Tom Committee and VRF Rotation](#tom-committee-and-vrf-rotation)
4. [Autonomy Tiers](#autonomy-tiers)
5. [Consensus and the Guard Pipeline](#consensus-and-the-guard-pipeline)
6. [Byzantine Fault Tolerance Guarantees](#byzantine-fault-tolerance-guarantees)
7. [Configuration Reference](#configuration-reference)

---

## When Consensus Is Required

Not all swarm actions require consensus. The system distinguishes between autonomous actions (detection, investigation, correlation) and consequential actions that require collective agreement. The design principle is: **the swarm observes freely but acts only with consensus**.

Three categories of decisions require BFT consensus among the Tom committee:

### 1. Response Actions

Any action that modifies the environment outside the swarm's own state. These are the `ResponseAction` variants defined in `crates/swarm-core/src/types.rs`:

| Response Action | Effect | Risk |
|---|---|---|
| `BlockEgress { target }` | Blocks network traffic to a destination | Disrupts legitimate traffic if target is misidentified |
| `IsolateHost { host_id }` | Removes a host from the network | Takes a production system offline |
| `RevokeCredential { credential_id }` | Invalidates a credential or capability | Locks out legitimate users or services |
| `DeployDecoy { decoy_type, target_zone }` | Deploys a honeypot or canary token | Low risk, but consumes infrastructure resources |
| `Escalate { summary, urgency }` | Alerts a human operator | Low risk, but alert fatigue if overused |

Response actions are proposed by Pouncer agents via the `RequestResponse` swarm action and cannot execute without 2f+1 approval from the Tom committee. This is a hard gate -- no code path bypasses it.

### 2. Evolution Commits

When a Kitten agent evolves a new detection strategy and it passes Z3 verification, deploying it to the production detection pipeline requires consensus. A compromised Kitten could propose a strategy that deliberately misses certain attack patterns (a "blind spot" strategy). Consensus ensures multiple Toms evaluate the strategy's fitness metrics and Z3 verification proof before it enters the live pipeline.

Evolution commits cover:
- New detection strategies promoted to production
- Modified correlation rules in the Weaver pipeline
- Updated investigation playbooks for Stalkers
- Threshold adjustments to the pheromone configuration

### 3. Trust Decisions

Changes to the swarm's membership and trust boundaries:
- **Agent admission**: A new agent joining the swarm. Its Ed25519 public key must be registered by consensus.
- **Agent revocation**: Removing an agent suspected of compromise. Its key is revoked and all its active pheromone deposits are flagged as untrusted.
- **Tier promotion/demotion**: Changing an agent's autonomy tier (e.g., promoting a Stalker from Tier 2 to Tier 1 after it has demonstrated reliability).

---

## Tendermint-Style Protocol

The consensus protocol follows Tendermint's three-phase commit pattern, adapted for the swarm's NATS-based transport. The protocol is implemented in `crates/swarm-consensus/src/`.

### Three Phases

```
Propose --> Prevote --> Precommit --> Commit
```

**Phase 1: Propose**

A designated proposer (selected by the VRF rotation schedule) broadcasts a proposal to the Tom committee. The proposal contains:

- The action to be authorized (response action, evolution commit, or trust decision)
- The supporting evidence chain (signed receipts from Whiskers, Stalkers, Weavers, and/or Kittens)
- The proposer's assessment and recommended outcome
- The round number and block height (monotonically increasing)

Only the current round's proposer may issue a valid proposal. Proposals from non-proposers are ignored.

**Phase 2: Prevote**

Each Tom committee member evaluates the proposal independently:

1. Verify the proposer is the legitimate proposer for this round (VRF check).
2. Verify all evidence signatures in the chain.
3. Evaluate the proposed action against the current swarm policy (guard pipeline).
4. Check that the proposed action is appropriate for the current autonomy tier.

If the proposal passes all checks, the Tom casts a signed `PREVOTE_YES`. If any check fails, it casts a signed `PREVOTE_NIL` (abstain, but not an explicit rejection). Prevotes are broadcast to all committee members.

A Tom does **not** prevote `YES` if:
- Evidence signatures are invalid
- The proposed action violates current policy
- The action exceeds the relevant autonomy tier
- The proposal is for an already-decided round

**Phase 3: Precommit**

Once a Tom observes 2f+1 `PREVOTE_YES` messages for the same proposal, it casts a signed `PRECOMMIT_YES`. If it does not observe 2f+1 prevotes within the round timeout, it casts `PRECOMMIT_NIL`.

Precommits are broadcast to all committee members.

**Commit**

Once 2f+1 `PRECOMMIT_YES` messages are observed for the same proposal, the action is committed. The commit is recorded as a signed `ConsensusResult`:

```rust
pub struct ConsensusResult {
    pub hunt_id: HuntId,
    pub reached: bool,
    pub approve_count: u32,
    pub deny_count: u32,
    pub total_voters: u32,
    pub threshold: u32,
}
```

The `is_bft_consensus()` method verifies that `reached == true` and `approve_count >= threshold`.

### Timeout and Round Advancement

If a round does not complete within `round_timeout_ms` (default: 5000ms), the round fails and advances to the next round with a new proposer. This handles:

- A crashed or partitioned proposer (no proposal arrives)
- Insufficient prevotes (not enough Toms online)
- Network delays causing timeout

The timeout is intentionally short. Security decisions should not block for extended periods. If the committee cannot reach consensus within 5 seconds, the situation is either not urgent enough (and can wait for the next round) or the committee is degraded (and cannot safely act).

### Locked Values

Tendermint's locking mechanism prevents equivocation across rounds. Once a Tom has precommitted to a value in round R, it is "locked" on that value and must prevote for it in subsequent rounds (or prevote NIL if a different value is proposed). This prevents the split-brain scenario where different Toms commit different values in different rounds.

---

## Tom Committee and VRF Rotation

The Tom committee is the set of agents authorized to participate in consensus. Committee membership rotates on a configurable interval to prevent long-term collusion and ensure no fixed subset of agents controls all governance decisions.

### Committee Size

The committee must have at least `3f + 1` members to tolerate `f` Byzantine faults. With the default `max_byzantine_faults = 1`:

```
Committee size = 3(1) + 1 = 4
Required for consensus = 2(1) + 1 = 3
```

The default mission configuration spawns 3 Tom agents with a maximum of 5. In practice, the committee should have at least 4 members for single-fault tolerance.

### VRF-Based Rotation

Committee membership rotates using a Verifiable Random Function (VRF). The VRF takes as input:

- The current epoch number (incremented every `committee_rotation_interval_secs`, default: 3600 seconds)
- The previous epoch's randomness seed (chain of VRF outputs)
- Each candidate Tom's public key

The VRF output determines:

1. **Committee membership**: Which Tom agents are in the active committee for this epoch. All healthy Toms are candidates; the VRF selects `3f + 1` from the pool.
2. **Proposer schedule**: Within an epoch, the proposer for each round is deterministically derived from the VRF output and the round number.

### Why VRF Over Static Assignment

| Property | Static Committee | VRF Rotation |
|---|---|---|
| Predictability | Attacker knows exactly who to target | Committee composition is unpredictable until epoch begins |
| Collusion window | Permanent (same members can coordinate indefinitely) | Bounded by epoch length (default: 1 hour) |
| Adaptability | Manual reconfiguration required | Automatically incorporates new Toms, excludes failed ones |
| Verifiability | Trivial | VRF proofs are publicly verifiable -- any agent can confirm committee legitimacy |

### Epoch Transitions

At each epoch boundary:

1. The current committee computes the next epoch's VRF seed from the current seed and epoch number.
2. The VRF output selects the next committee.
3. Any pending consensus rounds from the previous epoch are finalized or timed out.
4. The new committee begins accepting proposals.

There is a brief overlap window (one round timeout) where both the old and new committees are considered valid. This prevents proposals from being dropped during the transition.

---

## Autonomy Tiers

The swarm operates under a tiered autonomy model that determines which actions agents can take independently versus which require consensus or human approval. Tiers are defined in `crates/swarm-core/src/verdict.rs`:

```rust
pub enum AutonomyTier {
    Tier1,  // Fully autonomous
    Tier2,  // Autonomous with reporting
    Tier3,  // Human-approved
}
```

### Tier Definitions

**Tier 1: Fully Autonomous**

Actions the swarm can take without any consensus or human involvement. These are low-risk, high-confidence, well-understood operations.

Examples:
- Pheromone deposits (all agents deposit freely)
- Detection strategy evaluation (Whiskers run detection on every event)
- IOC matching against known-bad indicators
- Honeypot interaction monitoring (Calico observes, does not respond)
- Memory consolidation (Sphinx updates knowledge graph)
- Health reporting and self-monitoring

Default population at Tier 1: Whisker, Sphinx, Calico

Confidence gate: actions are autonomous when the swarm's confidence in the threat assessment exceeds `tier1_confidence` (default: 0.9).

**Tier 2: Autonomous with Reporting**

Actions the swarm executes autonomously but must report for post-hoc human validation. These are moderate-risk operations where the swarm's judgment is good enough to act but human oversight prevents drift.

Examples:
- Opening a new investigation (Stalker claims an investigation lead)
- Hypothesis generation for threat analysis
- Cross-hunt correlation and attack narrative construction (Weaver)
- Proposing evolved detection strategies (Kitten proposes, but deployment requires consensus)
- Deploying deception assets to low-value zones (Calico)

Default population at Tier 2: Stalker, Weaver, Kitten

Confidence gate: actions are autonomous-with-reporting when confidence exceeds `tier2_confidence` (default: 0.7) but is below `tier1_confidence`.

**Tier 3: Human-Approved**

Actions that require explicit consensus from the Tom committee and, for critical-severity threats, human operator approval. These are high-risk, irreversible, or environment-modifying operations.

Examples:
- Blocking network egress (`BlockEgress`)
- Isolating a production host (`IsolateHost`)
- Revoking credentials (`RevokeCredential`)
- Deploying evolved detection strategies to production (evolution commit)
- Admitting or revoking swarm agents (trust decisions)
- Any response action when severity is Critical (governed by `require_human_above_severity`)

Default population at Tier 3: Pouncer, Tom

The `require_human_above_severity` parameter (default: `critical`) adds a human-in-the-loop gate on top of BFT consensus. Even if the Tom committee unanimously approves a response action for a Critical-severity threat, the action is held pending human confirmation. This is the ultimate safety valve.

### Tier Assignment

Each agent archetype has a default tier assigned in the population configuration:

```yaml
population:
  whisker:
    tier: tier1      # Fully autonomous detection
  stalker:
    tier: tier2      # Autonomous investigation, reported
  weaver:
    tier: tier2      # Autonomous correlation, reported
  pouncer:
    tier: tier3      # Response requires consensus
  tom:
    tier: tier3      # Governance requires consensus
  kitten:
    tier: tier2      # Strategy proposal is autonomous; deployment is tier3
  sphinx:
    tier: tier1      # Memory management is autonomous
  calico:
    tier: tier1      # Observation is autonomous; active deception may be tier2
```

Tiers can be adjusted per-mission based on the operational context. A red team exercise might lower Pouncer to Tier 2 for faster iteration. A production environment might raise Stalker to Tier 3 for stricter oversight.

### Tier Interaction with Severity

The tier system interacts with threat severity to create a decision matrix:

| Severity | Tier 1 | Tier 2 | Tier 3 |
|---|---|---|---|
| Low | Autonomous | Autonomous + report | BFT consensus |
| Medium | Autonomous | Autonomous + report | BFT consensus |
| High | Autonomous | Autonomous + report | BFT consensus |
| Critical | Autonomous | Autonomous + report | BFT consensus + **human approval** |

The `require_human_above_severity: critical` parameter governs the last row. Setting it to `high` would require human approval for both High and Critical severity Tier 3 actions.

---

## Consensus and the Guard Pipeline

The BFT consensus protocol does not operate in isolation. It is one layer in the middleware pipeline that every swarm action traverses. From the brainstorm design:

```
1. IdentityVerification    (Ed25519 delegation token)
2. TierAuthorization       (autonomy level enforcement)
3. PheromoneInjection      (load relevant NATS trails)
4. ContextCompression      (token-aware summarization)
5. GuardPipeline           (ClawdStrike guard evaluation)
6. ToolBoundary            (action-specific access control)
7. ConsensusGate           (BFT for response actions)
8. EvidenceCollection      (receipt signing, audit trail)
9. EvolutionTracking       (strategy mutation logging)
```

### Pipeline Integration

When a Pouncer proposes a response action via `RequestResponse`, the action traverses the full middleware stack:

1. **IdentityVerification**: Verify the Pouncer's Ed25519 delegation token is valid and non-revoked.
2. **TierAuthorization**: Confirm the action is permitted at the Pouncer's assigned tier (Tier 3 requires consensus -- proceed to later gate).
3. **PheromoneInjection**: Attach current pheromone concentration data to the request context so the consensus committee can evaluate the threat landscape.
4. **ContextCompression**: Summarize the evidence chain to fit within token budgets for any LLM-backed evaluation steps.
5. **GuardPipeline**: Run the ClawdStrike guard pipeline against the proposed action. Guards check: Is this path/target allowed by policy? Does this action violate any forbidden-path rules? Is the egress target in the allowlist?
6. **ToolBoundary**: Verify the Pouncer has the specific capability to execute this type of response (e.g., a Pouncer authorized for `BlockEgress` may not have capability for `IsolateHost`).
7. **ConsensusGate**: The action enters the BFT consensus protocol. Proposal is broadcast to the Tom committee. The pipeline blocks until consensus is reached or timeout occurs.
8. **EvidenceCollection**: On consensus approval, a signed receipt is generated. The receipt contains the proposal, all votes, the final verdict, and the Merkle proof anchoring it to the audit trail.
9. **EvolutionTracking**: If this response action results in learning (e.g., the response was effective and the detection strategy should be reinforced), the outcome is logged for Kitten agents.

### Guard Denial vs. Consensus Denial

These are distinct failure modes:

- **Guard denial** (step 5): The action violates static policy. It is rejected before the consensus protocol ever sees it. No votes are cast. The Pouncer receives a `GuardDenied` error.
- **Consensus denial** (step 7): The action is policy-compliant but the Tom committee votes against it. The action was valid but the committee judged it unwise given the current context. The Pouncer receives a `ConsensusFailed` error.

Both are fail-closed. A denied action does not execute.

### Receipt Signing

Every consensus outcome -- whether approved or denied -- produces an Ed25519-signed receipt. This receipt is:

1. Published to the spine audit trail (NATS JetStream + Merkle tree)
2. Available for post-hoc review by human operators
3. Usable as evidence in subsequent consensus rounds (e.g., "the committee denied this action 30 minutes ago; new evidence has emerged")

---

## Byzantine Fault Tolerance Guarantees

The consensus protocol provides standard BFT guarantees based on the Tendermint model.

### Core Invariants

Given a committee of `n = 3f + 1` members where `f` is the maximum number of Byzantine (compromised, crashed, or malicious) agents:

**Safety**: No two honest Tom agents commit different values for the same round. Even if `f` agents send conflicting messages, the locking mechanism ensures that once a value is precommitted by any honest agent, no other value can gather 2f+1 prevotes.

**Liveness**: If fewer than `f + 1` agents are faulty and the network is eventually synchronous, the protocol will eventually commit a value. The round timeout and proposer rotation ensure progress even when individual proposers crash.

**Agreement threshold**: `2f + 1` votes are required out of `3f + 1` total. This means:

| f (max faults) | Committee size (3f+1) | Required votes (2f+1) | Fault tolerance |
|---|---|---|---|
| 1 | 4 | 3 | Tolerates 1 compromised Tom |
| 2 | 7 | 5 | Tolerates 2 compromised Toms |
| 3 | 10 | 7 | Tolerates 3 compromised Toms |

### Failure Scenarios

**Scenario: Proposer crash**

The proposer for round R crashes before broadcasting the proposal. No prevotes are cast. After `round_timeout_ms` (5 seconds), the round times out and advances to round R+1 with the next proposer in the VRF schedule. Liveness is preserved.

**Scenario: One Byzantine Tom**

With `f = 1` (committee of 4), one Tom sends conflicting prevotes to different committee members (equivocation). Honest Toms detect equivocation by comparing received prevotes. The Byzantine Tom's votes are discarded. The remaining 3 honest Toms can still reach 2f+1 = 3 agreement.

**Scenario: Compromised Tom proposes malicious action**

A compromised Tom is selected as proposer and proposes blocking a legitimate production host. Each honest Tom independently evaluates the proposal through the guard pipeline and evidence chain. If the evidence does not support the action, honest Toms prevote NIL. With 3 honest Toms and only 1 Byzantine, the malicious proposal cannot reach 2f+1 = 3 prevotes (only the compromised Tom votes YES). The proposal is rejected.

**Scenario: Network partition**

The committee is split into two groups by a network partition. Neither group can have more than `2f` members (since the total is `3f + 1`). Neither group can reach `2f + 1` votes. No commits occur during the partition. When the partition heals, the locked-value mechanism ensures all honest agents converge on the same decision. Safety is preserved; liveness resumes after partition heals.

### Relationship to Swarm Health

The BFT guarantee bounds the swarm's safety even when agents are compromised. Combined with:

- **Pheromone source diversity**: A single compromised Whisker cannot trigger mode transitions
- **Guard pipeline**: A compromised Pouncer cannot bypass static policy
- **Consensus**: A compromised Tom cannot unilaterally approve response actions
- **VRF rotation**: A compromised committee is automatically refreshed at the next epoch

The swarm degrades gracefully under attack. An adversary must compromise more than `f` Toms in the same epoch AND bypass source diversity AND bypass the guard pipeline to execute an unauthorized response action. Each layer is independent.

---

## Configuration Reference

Consensus parameters are configured via the `consensus` block in the mission YAML. The complete default configuration from `rulesets/default.yaml`:

```yaml
consensus:
  max_byzantine_faults: 1
  round_timeout_ms: 5000
  committee_rotation_interval_secs: 3600
```

Autonomy parameters are in the `autonomy` block:

```yaml
autonomy:
  tier1_confidence: 0.9
  tier2_confidence: 0.7
  require_human_above_severity: critical
```

### Consensus Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `max_byzantine_faults` | `u32` | `1` | Maximum number of Byzantine faults the protocol tolerates (`f`). Committee size must be at least `3f + 1`. |
| `round_timeout_ms` | `u64` | `5000` | Timeout for a single consensus round in milliseconds. If the round does not complete within this window, it fails and advances to the next round with a new proposer. |
| `committee_rotation_interval_secs` | `u64` | `3600` | How often to rotate committee membership via VRF. Default is 1 hour. Shorter intervals increase security against collusion but increase coordination overhead. |

### Autonomy Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `tier1_confidence` | `f64` | `0.9` | Minimum confidence threshold for fully autonomous action. Actions above this confidence operate without consensus or reporting. |
| `tier2_confidence` | `f64` | `0.7` | Minimum confidence threshold for autonomous-with-reporting action. Actions above this confidence but below `tier1_confidence` execute autonomously but are reported for human review. |
| `require_human_above_severity` | `String` | `"critical"` | Severity level at or above which Tier 3 actions require human approval in addition to BFT consensus. Valid values: `low`, `medium`, `high`, `critical`. |

### Rust Types

```rust
pub struct ConsensusConfig {
    pub max_byzantine_faults: u32,
    pub round_timeout_ms: u64,
    pub committee_rotation_interval_secs: u64,
}

pub struct AutonomyConfig {
    pub tier1_confidence: f64,
    pub tier2_confidence: f64,
    pub require_human_above_severity: String,
}
```
