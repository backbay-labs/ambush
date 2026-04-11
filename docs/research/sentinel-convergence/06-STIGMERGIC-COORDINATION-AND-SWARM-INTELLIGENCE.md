# 06 -- Stigmergic Coordination and Swarm Intelligence

## Convergence of Pheromone-Based Threat Hunting with Raft-Lite Consensus

| | |
|---|---|
| **Series** | Sentinel-Convergence Research (Document 06 of 08) |
| **Version** | 0.3.0 |
| **Date** | 2026-04-07 |
| **Status** | Draft |
| **Sentinel** | `playground/sentinel` -- Go, Raft-lite consensus for edge-cluster orchestration |
| **Swarm Team Six** | `standalone/swarm-team-six` -- Rust, pheromone-based stigmergic threat hunting |

> **Series Note**
> - This document is conceptual background for the series.
> - Canonical implementation decisions live primarily in
>   [01](01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md),
>   [04](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md),
>   [05](05-TELEMETRY-BRIDGE-ARCHITECTURE.md), and
>   [08](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md).

---

## Abstract

This document analyzes stigmergic coordination as implemented in Swarm Team Six's
pheromone substrate and its complementary relationship with Sentinel's Raft-lite
consensus protocol. We examine the biological foundations of stigmergy, formalize
the mathematical models of pheromone decay and aggregation, analyze the Rust and
Go implementations, and propose a hybrid architecture combining indirect
pheromone-based "soft consensus" with direct Raft-based "hard consensus."

The core argument: stigmergic coordination excels at distributed threat detection
where speed and resilience matter more than agreement precision, while Raft-lite
consensus excels at authorizing irreversible response actions where correctness
matters more than latency. Neither alone suffices. Their combination yields an
architecture that is both responsive and safe.

---

## Table of Contents

1. [Biological Foundations of Stigmergy](#1-biological-foundations-of-stigmergy)
2. [Mathematical Formalism](#2-mathematical-formalism)
3. [Swarm Team Six: Pheromone Substrate Implementation](#3-swarm-team-six-pheromone-substrate-implementation)
4. [Sentinel: Raft-Lite Consensus Implementation](#4-sentinel-raft-lite-consensus-implementation)
5. [Direct vs. Indirect Coordination](#5-direct-vs-indirect-coordination)
6. [Hybrid Coordination Model](#6-hybrid-coordination-model)
7. [Multi-Agent Threat Hunting via Pheromone Trails](#7-multi-agent-threat-hunting-via-pheromone-trails)
8. [Emergent Behavior in Security Swarms](#8-emergent-behavior-in-security-swarms)
9. [Distributed Substrate Across Network Partitions](#9-distributed-substrate-across-network-partitions)
10. [Swarm Resilience and Failure Tolerance](#10-swarm-resilience-and-failure-tolerance)
11. [Comparison with Other Multi-Agent Coordination Models](#11-comparison-with-other-multi-agent-coordination-models)
12. [Application to Cybersecurity: Literature Survey](#12-application-to-cybersecurity-literature-survey)
13. [Reference Architecture](#13-reference-architecture)
14. [Theoretical Contributions](#14-theoretical-contributions)
15. [Conclusion](#15-conclusion)
16. [References](#16-references)
17. [Cross-References](#17-cross-references)

---

## 1. Biological Foundations of Stigmergy

### 1.1 Definition and Origin

The term *stigmergy* was coined by Pierre-Paul Grasse in 1959 to describe the
coordination mechanism observed in termite nest construction [1]. The word derives
from the Greek *stigma* (sign, mark) and *ergon* (work, action): coordination
through marks left in the environment. Termites do not communicate directly to
build complex structures. Each termite modifies its local environment (deposits a
pellet of mud), and other termites respond to those modifications. Global structure
emerges without any individual possessing a blueprint.

This differs fundamentally from direct communication (e.g., the honeybee waggle
dance, which encodes direction and distance to food sources). In stigmergy, the
environment *is* the communication channel. Agents write to the environment; other
agents read from it. The agents need not know about each other.

### 1.2 Ant Colony Optimization

Marco Dorigo formalized ant colony foraging as Ant Colony Optimization (ACO) in
his 1992 doctoral thesis [2, 3]. The mechanism: an ant finds food, deposits
pheromone on the return trail, other ants probabilistically follow
high-concentration trails, successful trails get reinforced, and pheromone
evaporates over time to eliminate stale paths.

This produces *positive feedback* (successful trails attract more ants) with
*negative regulation* (evaporation removes suboptimal paths). Dorigo's
transition probability for an ant at node *i* choosing edge *(i, j)*:

```
            [tau(i,j)]^alpha * [eta(i,j)]^beta
p(i,j) = ----------------------------------------
          SUM_k [tau(i,k)]^alpha * [eta(i,k)]^beta
```

Where `tau(i,j)` is pheromone concentration, `eta(i,j)` is heuristic
desirability (e.g., inverse distance), and `alpha`/`beta` control relative
influence. This purely local rule produces globally near-optimal solutions to
combinatorial problems (TSP, graph coloring, scheduling).

### 1.3 Pheromone Dynamics in Biology

Biological trail pheromones exhibit exponential decay (half-lives from minutes
to hours), spatial diffusion, and deposition rates proportional to food quality
[8]. The chemical kinetics follow a reaction-diffusion equation:

```
dC/dt = D * nabla^2(C) + S(x,t) - lambda * C
```

Where `C(x,t)` is concentration, `D` is the diffusion coefficient, `S(x,t)` is
the source term (deposition), and `lambda` is the first-order decay rate. For our
digital substrate, the spatial diffusion term vanishes -- pheromones are deposited
into named channels, not physical space -- simplifying to `dC/dt = S(t) - lambda * C`.

### 1.4 Bonabeau's Swarm Intelligence Framework

Eric Bonabeau, Marco Dorigo, and Guy Theraulaz provided the canonical
theoretical framework for swarm intelligence in their 1999 monograph [5].
They identified four necessary properties:

1. **Positive feedback** -- amplification of successful behaviors (trail
   reinforcement)
2. **Negative feedback** -- counterbalancing mechanisms that prevent runaway
   amplification (evaporation, saturation)
3. **Randomness** -- stochastic exploration that prevents premature convergence
   (random walk component)
4. **Multiple interactions** -- sufficient agent count for statistical robustness
   (minimum viable swarm size)

All four properties are present in Swarm Team Six's pheromone substrate:

| Property | STS Implementation |
|---|---|
| Positive feedback | Stalker-confirmed threats get reinforced deposits with higher confidence |
| Negative feedback | Exponential decay with configurable half-life (default: 3600s) |
| Randomness | Whisker detection operates on stochastic telemetry streams; confidence values carry uncertainty |
| Multiple interactions | Source diversity enforcement requires `min_sources_for_escalation >= 2` |

### 1.5 Reynolds' Flocking

Craig Reynolds' 1987 "Boids" paper [6] demonstrated that complex flocking
behavior emerges from three local rules: separation, alignment, and cohesion.
Reynolds' model uses direct neighbor sensing rather than environmental
modification, but shares the fundamental insight: global coordination from
local rules. The mapping to STS is approximate: separation corresponds to
source diversity enforcement (agents must not cluster on redundant signals),
alignment to swarm mode transitions (agents synchronize operational posture),
and cohesion to pheromone concentration gradients attracting agents toward
active threat classes.

---

## 2. Mathematical Formalism

### 2.1 Exponential Decay Model

Swarm Team Six implements pheromone decay using a half-life model isomorphic
to radioactive decay. For a single deposit with initial confidence `c_0`,
deposited at time `t_0` with half-life `h`:

```
S(t) = c_0 * 2^(-(t - t_0) / h)
```

Equivalently, using the natural exponential:

```
S(t) = c_0 * e^(-lambda * (t - t_0))
```

Where the decay constant `lambda = ln(2) / h`.

The implementation in `PheromoneDeposit::strength_at` (from
`crates/swarm-core/src/pheromone.rs`):

```rust
pub fn strength_at(&self, now: i64) -> f64 {
    if now <= self.timestamp {
        return self.confidence;
    }
    let elapsed = (now - self.timestamp) as f64;
    self.confidence * (0.5_f64).powf(elapsed / self.decay_half_life)
}
```

This correctly handles the boundary condition `t <= t_0` (clock skew or
same-instant query) by returning full confidence.

### 2.2 Concentration Aggregation

For a threat class `T` at query time `t`, the aggregate concentration is:

```
C(T, t) = SUM_{d in D(T)} S_d(t) * I(S_d(t) >= epsilon)
```

Where:
- `D(T)` is the set of all deposits with threat class T
- `S_d(t)` is the effective strength of deposit d at time t
- `epsilon` is the evaporation threshold (default: 0.01)
- `I(...)` is the indicator function (1 if true, 0 if false)

The evaporation threshold acts as a noise gate, eliminating negligible
contributions from ancient deposits. Without it, every deposit ever made would
contribute a nonzero (but vanishingly small) amount to concentration, requiring
unbounded storage.

### 2.3 Evaporation Time

The time until a deposit with initial confidence `c_0` reaches the evaporation
threshold `epsilon`:

```
t_evap = h * log_2(c_0 / epsilon)
```

Derivation:

```
epsilon = c_0 * 2^(-t_evap / h)
epsilon / c_0 = 2^(-t_evap / h)
log_2(epsilon / c_0) = -t_evap / h
t_evap = h * log_2(c_0 / epsilon)
```

With default parameters (`h = 3600s`, `epsilon = 0.01`):

| Initial Confidence `c_0` | Evaporation Time | Hours |
|---|---|---|
| 1.00 | `3600 * log2(100) = 23,900s` | ~6.64h |
| 0.95 | `3600 * log2(95) = 23,613s` | ~6.56h |
| 0.50 | `3600 * log2(50) = 20,295s` | ~5.64h |
| 0.10 | `3600 * log2(10) = 11,950s` | ~3.32h |
| 0.05 | `3600 * log2(5) = 8,350s` | ~2.32h |

This shows the self-cleaning property: low-confidence signals evaporate
significantly faster than high-confidence ones, naturally biasing the substrate
toward actionable intelligence.

### 2.4 Threshold Crossing Dynamics

A mode transition from Normal to Alert requires:

```
C(T, t) >= theta_alert  AND  |sources(T, t)| >= n_min
```

Where `theta_alert = 2.0` (default), `n_min = 2` (default), and
`sources(T, t)` is the set of distinct agent IDs contributing non-evaporated
deposits to threat class T at time t.

The dual requirement (strength AND diversity) creates a two-dimensional
threshold surface. For a single-agent deposit of confidence `c`:

```
C(T, t) = c   (single source)
|sources| = 1 < n_min = 2
```

The transition fails regardless of `c`. Even with `c = 100.0`, a single
agent cannot trigger escalation. This is the anti-Sybil guarantee.

For `n` independent agents each depositing with identical confidence `c` at
the same time:

```
C(T, t) = n * c
|sources| = n
```

The minimum configuration to trigger alert mode is:

```
n >= 2  AND  n * c >= 2.0
```

So two agents with `c >= 1.0` each, or three agents with `c >= 0.67` each,
etc. Since confidence is bounded to [0.0, 1.0], the practical minimum is
two agents with confidence summing to at least 2.0 -- which requires both
at confidence 1.0. More realistically, multiple agents contribute over time:

```
C(T, t) = SUM_i c_i * 2^(-(t - t_i) / h)
```

The time-decayed sum means agents must corroborate *within a temporal window*
defined by the half-life. Ancient corroborations decay away. This is a temporal
locality constraint enforced by physics (decay), not by explicit windowing.

### 2.5 Monotonic Escalation (and Future Hysteresis)

The current `SwarmModeState::transition_to` implementation in `agent.rs`
enforces **strictly monotonic escalation**: transitions are accepted only when
`mode > self.current`, and rejected otherwise. Once the swarm reaches Incident
mode, it remains there. De-escalation is not yet implemented.

```rust
// From crates/swarm-core/src/agent.rs
pub fn transition_to(&mut self, mode: SwarmMode, threat_class: ThreatClass, now: i64) -> bool {
    if mode <= self.current {
        return false;
    }
    // ... update state
}
```

A natural extension is Schmitt-trigger hysteresis, where de-escalation from
Incident requires concentration to drop below a *lower* threshold (e.g.,
`theta_alert`) rather than `theta_incident`. The formal model would be:

```
Mode(t) = Incident  if  C(t) >= theta_incident  OR
                        (Mode(t-1) = Incident AND C(t) >= theta_alert)
          Alert     if  C(t) >= theta_alert  OR
                        (Mode(t-1) = Alert AND C(t) > 0)
          Normal    otherwise
```

This would prevent mode oscillation when concentration fluctuates near a
boundary. For now, the monotonic-only design is a deliberate safety choice:
the swarm errs on the side of remaining escalated until an operator or the
Tom governance agent explicitly resets the mode. See [04](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md)
for the partition-safety implications of this design.

### 2.6 Continuous-Time Concentration Dynamics

For `N` agents depositing at rate `r_i(t)` with confidence `c_i(t)`:

```
dC/dt = SUM_i r_i(t) * c_i(t) - lambda * C(t)
```

At steady state (`dC/dt = 0`): `C_ss = SUM_i (r_i * c_i) / lambda = (h / ln(2)) * SUM_i r_i * c_i`.
With default parameters (`h = 3600s`, `lambda = ln(2)/3600 ~= 0.000193 s^-1`),
maintaining alert mode (`C_ss >= 2.0`) requires the swarm to collectively deposit
~0.000386 confidence-units per second -- roughly one deposit at confidence 0.8
every ~35 minutes. This is a plausible sustained rate during an active incident.

---

## 3. Swarm Team Six: Pheromone Substrate Implementation

### 3.1 Architecture Overview

The pheromone substrate is implemented across two Rust crates:

- **`swarm-core`** (`crates/swarm-core/`) -- Defines the core types:
  `PheromoneDeposit`, `PheromoneConcentration`, `ThreatClass`, `Severity`,
  `SwarmMode`, and the `SwarmAgent` trait.
- **`swarm-pheromone`** (`crates/swarm-pheromone/`) -- Implements the
  substrate backends and the `PheromoneSubstrate` async trait.

The separation is deliberate: `swarm-core` has minimal dependencies and can
be imported by any component that needs to work with pheromone types.
`swarm-pheromone` pulls in the heavier dependencies (NATS client, ed25519,
file I/O) needed for actual substrate operations.

### 3.2 The PheromoneDeposit Type

The `PheromoneDeposit` struct (from `crates/swarm-core/src/pheromone.rs`) carries:
the observable (`indicator: serde_json::Value`), MITRE ATT&CK-aligned
classification (`threat_class: ThreatClass`), `severity: Severity`,
`confidence: f64` (initial strength, [0.0, 1.0]), `timestamp: i64` (unix
seconds), per-deposit `decay_half_life: f64`, `agent_id: AgentId`, and
Ed25519 `signature: Vec<u8>` with `agent_key: Vec<u8>`. Key design choices:

- **Per-deposit half-life** allows individual signals to control their own decay.
  Lateral movement (fast, urgent) can use shorter half-lives than data
  exfiltration (slow, developing over days).
- **Embedded cryptographic identity** (signature + public key per deposit) means
  verification requires no PKI infrastructure or key lookup service.
- **`Custom(String)` threat class variant** allows organization-specific threat
  categories without modifying the core enum's 12 MITRE-aligned variants.

### 3.3 ThreatClass Taxonomy and Per-Class Tuning

The `ThreatClass` enum's 12 MITRE-aligned variants double as the substrate's
threat-class routing/indexing dimension. The crate-level design notes describe
a conceptual hierarchy (`swarm.pheromone.{threat_class}.{severity}`), but the
current JetStream KV implementation keys deposits by threat class without a
severity segment. Concentration is still computed per-threat-class by design;
cross-class correlation is the Weaver agent's responsibility.

Per-class `ThreatClassConfig` overrides allow operators to tune half-life,
evaporation threshold, and escalation thresholds independently. Credential
access might warrant faster escalation than discovery activity.

### 3.4 Substrate Backends

The `PheromoneSubstrate` async trait (from `crates/swarm-pheromone/src/substrate.rs`)
defines the core operations: `deposit`, `query_concentration`, `query_deposits`,
`record_escalation`, `store_threat_class_config`, `store_threat_intel_entry`,
`gc_evaporated`, `gc_expired_threat_intel`, and `health`. Three backends implement it:

| Backend | Durability | Use Case | Partition Behavior |
|---|---|---|---|
| `InMemoryPheromoneSubstrate` | None (volatile) | Dev, testing, replay | Lost on restart |
| `LocalJournalPheromoneSubstrate` | Single-node (JSONL) | Edge deployment | Survives restart, not partitions |
| `JetStreamPheromoneSubstrate` | Distributed (NATS KV) | Multi-node production | Survives partitions within NATS quorum |

Runtime backend selection is via the `ConfiguredPheromoneSubstrate` enum, which
dispatches all trait methods to the selected backend and validates Ed25519
signatures on every deposit before storage.

### 3.5 Concentration Computation

The `concentration_for` function implements the aggregation algorithm
(from `crates/swarm-pheromone/src/substrate.rs`):

```rust
pub(crate) fn concentration_for(
    deposits: &[PheromoneDeposit],
    threat_class: &ThreatClass,
    now: i64,
    policy: &ThreatClassPolicy,
) -> PheromoneConcentration {
    let mut sources = HashSet::new();
    let mut total_strength = 0.0;
    let mut peak_confidence: f64 = 0.0;

    for deposit in deposits
        .iter()
        .filter(|deposit| &deposit.threat_class == threat_class)
    {
        if deposit.is_evaporated(now, policy.evaporation_threshold) {
            continue;
        }
        total_strength += deposit.strength_at(now);
        peak_confidence = peak_confidence.max(deposit.confidence);
        sources.insert(deposit.agent_id.0.clone());
    }

    PheromoneConcentration {
        threat_class: threat_class.clone(),
        total_strength,
        distinct_sources: sources.len(),
        peak_confidence,
    }
}
```

This is a single-pass O(N) scan over all deposits, which is acceptable for
the expected deposit volumes (hundreds to low thousands of active deposits).
The `HashSet<String>` tracks distinct agent IDs for the source diversity check.

### 3.6 Source Diversity, Signature Verification, and Garbage Collection

**Anti-Sybil enforcement:** `PheromoneConcentration::exceeds_threshold` requires
both `total_strength >= threshold` AND `distinct_sources >= min_sources`. A
compromised agent flooding the substrate cannot trigger escalation because all
its deposits count as one source, deposits are Ed25519-signed (no impersonation),
and agent admission is Tom-governed. Default `min_sources_for_escalation: 2`.

**Signature verification:** `validate_deposit_signature` is fail-closed. It
rejects empty signatures/keys, parses Ed25519 keys, reconstructs the canonical
`DepositSigningPayload`, and verifies. Any failure discards the deposit.

**Garbage collection:** `gc_evaporated` removes deposits below the evaporation
threshold. For InMemory, this is an in-place `retain`. For LocalJournal, it
rewrites the journal file. For JetStream, it deletes keys in paginated batches
(default page size: 512). GC is a storage optimization, not a correctness
requirement -- evaporated deposits already contribute nothing to concentration.

---

## 4. Sentinel: Raft-Lite Consensus Implementation

### 4.1 Design Philosophy

Sentinel's Raft-lite protocol (implemented in
`pkg/consensus/raft_lite.go`) is optimized for a fundamentally different
problem than Swarm Team Six's pheromone substrate. Where pheromones provide
probabilistic signal aggregation, Raft-lite provides deterministic agreement.

The protocol is a simplified Raft [Ongaro & Ousterhout, 2014] tailored for
small edge clusters (3--10 nodes) operating during network partitions from
the Kubernetes control plane. The key innovation: enabling autonomous
decision-making when edge nodes are partitioned from central management.

### 4.2 Core Mechanics

**State machine:** Standard Raft: Follower -> Candidate (on election timeout) ->
Leader (on winning majority). Election timeout is randomized within
`[150ms, 300ms]` to prevent split votes. Heartbeats at 50ms intervals.

**Decision types:** Four autonomous actions -- `pod_reschedule`, `node_cordon`,
`service_failover`, `resource_scale`. Each is deterministic, reversible, and
auditable -- properties that justify requiring explicit consensus.

**Quorum commitment:** `ProposeDecision` counts the leader itself as one ack
and requires `floor(|peers|/2) + 1` total acks (where `|peers|` excludes
self). For a 3-node cluster (2 peers), this means 2 total acks = self + 1
peer, i.e., majority of the cluster. This guarantees: at most one decision
per log position, quorum overlap ensures consistency, and minority partitions
cannot commit. See [01](01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) for the
full Raft-to-BFT analysis.

**Partition detection:** Runs every 100ms. If fewer than `len(peers)/2`
peers are reachable (healthy within 5 seconds), the node marks itself
partitioned and invokes `PartitionCallback`. In the hybrid system, this
signals degradation to pheromone-only coordination (see Section 9.2).

**Rate limiting and backoff:** Token-bucket rate limiting on incoming
connections (default: 100 msg/s, burst 20). Exponential backoff with 10%
jitter for peer reconnection (100ms initial, 2x multiplier, 30s max)
prevents thundering-herd reconnection storms after partition recovery.

---

## 5. Direct vs. Indirect Coordination

### 5.1 Taxonomy of Multi-Agent Coordination

Multi-agent coordination mechanisms fall on a spectrum from fully indirect
(stigmergic) to fully direct (message-passing):

```
Stigmergy <-----> Blackboard <-----> Publish/Subscribe <-----> RPC/Consensus
(indirect)                                                      (direct)
```

| Property | Stigmergy (STS) | Consensus (Sentinel) |
|---|---|---|
| Communication | Through shared environment | Direct peer-to-peer messages |
| Coupling | None (agents unaware of each other) | Tight (nodes track peers, terms, votes) |
| Consistency | Eventual (probabilistic convergence) | Strong (quorum-based linearizability) |
| Latency | O(1) deposit, async aggregation | O(N) vote round-trip |
| Partition tolerance | Graceful degradation | Safety (refuses to commit without quorum) |
| Failure mode | Gradual signal loss | Binary (leader/no-leader) |
| State | Append-only, conflict-free | Mutable, requires coordination |
| Scalability | O(1) per-agent (deposit and read) | O(N) per-decision (vote collection) |

### 5.2 When to Use Each

**Use stigmergic coordination (pheromones) when:**

- Speed of signal propagation matters more than agreement precision
- The system can tolerate false positives (detection, not response)
- Agent count is large or variable (agents join/leave freely)
- Network partitions should degrade gracefully, not halt operations
- The "decision" is a continuous quantity (concentration) not a discrete action

**Use direct consensus (Raft-lite) when:**

- The action is irreversible or high-cost (block traffic, isolate host)
- Exactly-once semantics are required (cannot duplicate the action)
- Auditability requires explicit vote records
- The group is small and stable (3--10 known nodes)
- Correctness is more important than availability

### 5.3 The Gap Between Detection and Response

Traditional security architectures conflate detection and response into a
single pipeline: SIEM collects signals, SOAR decides what to do, response
executes. This creates a latency bottleneck at the decision point and a
single point of failure at the SOAR.

The Sentinel convergence insight (explored in detail in
[03](03-EDGE-NATIVE-SECURITY-DETECTION.md) and
[04](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md)) is that detection and
response have *fundamentally different coordination requirements*:

- **Detection** needs speed, breadth, and resilience. Missing a signal is
  worse than a false positive. The system should be biased toward sensitivity.
  This maps to stigmergic coordination.

- **Response** needs correctness, auditability, and agreement. A false
  positive response (blocking legitimate traffic, isolating a production
  host) is worse than a delayed response. The system should be biased toward
  specificity. This maps to consensus coordination.

Forcing both through the same coordination mechanism produces either:
1. A detection system that is too slow (consensus overhead on every signal), or
2. A response system that is too aggressive (acting on probabilistic signals
   without agreement).

---

## 6. Hybrid Coordination Model

### 6.1 Two-Layer Architecture

The proposed hybrid model layers stigmergic coordination (pheromones) below
consensus coordination (Raft-lite):

```
+----------------------------------------------------------+
|                    Response Layer                         |
|         Raft-Lite Consensus (Hard Agreement)              |
|  - Response authorization (block, isolate, revoke)        |
|  - Policy changes (detection strategy promotion)          |
|  - Agent lifecycle (admit, revoke)                        |
|  Latency: 10-100ms    Consistency: Strong                 |
+---------------------------+------------------------------+
                            |
                   Escalation Bridge
                            |
+---------------------------+------------------------------+
|                   Detection Layer                         |
|       Pheromone Substrate (Soft Consensus)                 |
|  - Threat signal aggregation                              |
|  - Swarm mode transitions (Normal/Alert/Incident)         |
|  - Investigation coordination (claim/release)             |
|  Latency: <1ms deposit   Consistency: Eventual            |
+----------------------------------------------------------+
```

### 6.2 Escalation Bridge

The critical integration point is the **Escalation Bridge** -- the mechanism
by which pheromone concentration (soft consensus) triggers a consensus round
(hard consensus). The bridge operates as follows:

1. Pheromone concentration for threat class T crosses `incident_threshold`
   with sufficient source diversity.
2. The swarm transitions to Incident mode (see Section 2.5).
3. Tom (governance agent) observes the Incident transition.
4. Tom evaluates the evidence chain (pheromone deposits, Stalker findings,
   Weaver correlations) and formulates a response proposal.
5. Tom initiates a BFT consensus round among the Tom committee. (See
   [01](01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) for BFT mechanics.)
6. If consensus is reached (2f+1 agreement), the Pouncer is authorized to
   execute the response action.
7. The Pouncer executes via Sentinel's Raft-lite to ensure the response is
   applied consistently across the edge cluster.

This pipeline ensures:
- **No single agent can trigger a response** (source diversity + consensus).
- **Detection is fast** (pheromone deposit is O(1), no consensus required).
- **Response is safe** (requires explicit majority agreement).
- **Graceful degradation** under partition: pheromones still work, but
  response authorization may be delayed until quorum is reestablished.
  See [04](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) for partition behavior.

### 6.3 Consensus Scope Mapping

| Action Category | Coordination Mechanism | Justification |
|---|---|---|
| Deposit pheromone | None (autonomous, Tier 1) | Low cost, reversible (evaporates naturally) |
| Adjust sampling rate | Pheromone-driven (mode transition) | Continuous adaptation, no irreversible effect |
| Claim investigation | Pheromone substrate (CRDT) | Coordination without consensus, conflict-free |
| Publish findings | Pheromone substrate (append-only) | Information sharing, no side effects |
| Deploy decoy | Pheromone-driven (Calico, Tier 1) | Low risk (bait deployment, not blocking) |
| Block egress | BFT consensus + Raft-lite | Irreversible network impact, requires agreement |
| Isolate host | BFT consensus + Raft-lite | High-impact, could cause outage |
| Revoke credential | BFT consensus + Raft-lite | Irreversible, affects authentication |
| Promote detection strategy | BFT consensus | Changes swarm behavior globally |
| Admit/revoke agent | BFT consensus | Trust boundary modification |

### 6.4 Formal Coordination Protocol

The hybrid protocol `(P, R, B)` operates as:

- **P (Pheromone):** Agent detects anomaly -> deposits signed pheromone
  autonomously -> substrate aggregates concentration -> mode transition on
  threshold crossing with diversity.
- **B (Bridge):** Incident mode triggers Tom -> assembles evidence (deposits,
  Stalker findings, Weaver correlations) -> formulates `ResponseProposal` ->
  initiates BFT consensus -> 2f+1 Toms approve -> authorizes Pouncer.
- **R (Raft-lite):** Pouncer proposes `Decision` to Raft leader -> leader
  replicates to followers -> quorum acks -> commit and execute -> signed
  receipt published to substrate for audit.

---

## 7. Multi-Agent Threat Hunting via Pheromone Trails

### 7.1 The Threat Hunting Analogy

Ant colony foraging maps directly to distributed threat hunting:

| Ant Colony | Threat Hunting Swarm |
|---|---|
| Nest | Security operations center (virtual) |
| Food source | Threat actor / compromised asset |
| Pheromone trail | Sequence of corroborating threat indicators |
| Ant following trail | Agent investigating a lead |
| Trail reinforcement | Stalker confirming threat, depositing higher-confidence pheromone |
| Trail evaporation | Threat signal losing relevance over time |
| Colony mode (foraging/defense) | Swarm mode (Normal/Alert/Incident) |

### 7.2 Trail Formation

A threat hunting trail forms through iterative reinforcement:

**Phase 1: Initial Detection** (telemetry ingestion per [05](05-TELEMETRY-BRIDGE-ARCHITECTURE.md))
```
T+0:  Whisker-7a3f detects anomalous SSH tunnel
      -> deposit(CommandAndControl, HIGH, {dst: "185.220.101.x"}, 0.85)
      Concentration: 0.85, sources: 1
      No mode transition (single source)
```

**Phase 2: Independent Corroboration**
```
T+2m: Whisker-2b1c detects DNS beaconing to same IP range
      -> deposit(CommandAndControl, HIGH, {domain: "x.evil.com"}, 0.90)
      Concentration: ~1.74, sources: 2
      Source diversity met, strength below alert_threshold
```

**Phase 3: Critical Mass**
```
T+4m: Whisker-9d4e detects new SSH variant
      -> deposit(CommandAndControl, MEDIUM, {dst: "185.220.102.x"}, 0.80)
      Concentration: ~2.50, sources: 3
      Both thresholds exceeded -> ALERT MODE
```

**Phase 4: Investigation Reinforcement**
```
T+8m: Stalker-2e1b follows trail, confirms C2 channel
      -> deposit(CommandAndControl, CRITICAL, {confirmed_c2: true}, 0.95)
      -> deposit(LateralMovement, HIGH, {src: "10.0.1.50"}, 0.92)
      C2 concentration: ~3.8, sources: 4
      LM concentration: 0.92, sources: 1
```

**Phase 5: Cross-Domain Escalation**
```
T+12m: Weaver correlates C2 + lateral movement
       Multiple threat classes now elevated
       Combined cross-class signal exceeds incident_threshold
       -> INCIDENT MODE
```

### 7.3 Trail Branching and Convergence

Unlike ant trails, threat hunting trails *branch* (one compromised host
producing C2, lateral movement, exfiltration, and credential access pheromones
across four threat classes) and *converge* (two independent investigations
discovering shared infrastructure via the Weaver's entity graph). This
multi-dimensional concentration profile is the pheromone model's key
advantage over single-signal alert systems.

### 7.4 Adaptive Resource Allocation

Pheromone concentration drives agent resource allocation analogously to ant
recruitment:

| Concentration Range | Agent Response |
|---|---|
| 0.0 -- 0.5 | Background: Whiskers maintain standard sampling |
| 0.5 -- 2.0 | Elevated: Whiskers increase sampling on relevant threat classes |
| 2.0 -- 5.0 (Alert) | Active: Stalkers activate, Whiskers focus, Calico deploys targeted decoys |
| 5.0+ (Incident) | All-hands: Maximum sampling, all Stalkers investigating, Pouncers on standby |

This is emergent resource allocation: no central scheduler decides which
agents work on which threats. The pheromone concentration gradient naturally
directs agent attention to the highest-priority threat classes.

---

## 8. Emergent Behavior in Security Swarms

### 8.1 Positive Feedback Loops

Three feedback loops amplify genuine threats while allowing noise to fade:

1. **Detection-Reinforcement:** Whisker deposits increase concentration,
   which increases Whisker sampling rate, which produces more detections.
   Bounded by evaporation -- if the threat stops, the loop breaks.

2. **Investigation-Confirmation:** Concentration triggers Stalker activation;
   Stalkers confirm threats with higher-confidence deposits; concentration
   increases further. Bounded by finite Stalker population.

3. **Trail Convergence:** Independent trails share infrastructure discovered
   by Weavers; Stalkers redirect to overlapping threat classes; multi-class
   concentration spike triggers incident mode.

### 8.2 Self-Organization and Resilience

The swarm self-organizes without explicit orchestration: agents specialize based
on pheromone gradients (emergent division of labor), mode transitions drive
adaptive resource scaling (no capacity planner), and the substrate itself serves
as collective short-term memory (decaying trails encode threat recency).

Individual failure is tolerated by design: a failed Whisker reduces coverage
but does not eliminate detection; a failed Stalker leaves a pheromone trail for
others to pick up; a single NATS node failure in a 3-node cluster is transparent
to the substrate. Section 10 provides a detailed failure-tolerance analysis.

---

## 9. Distributed Substrate Across Network Partitions

### 9.1 Backend Partition Behavior

**InMemory:** No partition concern (single-process, volatile). **LocalJournal:**
Survives restarts via JSONL replay but does not replicate. **JetStream:** NATS
Raft-based replication; 3-node cluster tolerates 1 failure. During partition:
majority continues reads/writes, minority retains local state but loses writes,
recovery replays missed writes.

### 9.2 Partition Scenario: Hybrid Behavior

Consider a 5-node deployment with 3 NATS nodes and 5 Sentinel nodes:

```
Partition A (majority): Nodes 1, 2, 3 (2 NATS, 3 Sentinel)
Partition B (minority): Nodes 4, 5 (1 NATS, 2 Sentinel)
```

**Partition A:**
- NATS majority (2/3) -- JetStream substrate operational.
- Sentinel majority (3/5) -- Raft-lite can elect leader and commit decisions.
- Full hybrid coordination: pheromone detection + consensus response.

**Partition B:**
- NATS minority (1/3) -- JetStream substrate read-only (stale).
- Sentinel minority (2/5) -- Cannot reach quorum for decisions.
- Degraded mode: Whiskers can still detect (local processing), but cannot
  deposit to shared substrate. Stalkers can investigate locally. Pouncers
  are locked (no consensus available).

This is the correct behavior: the minority partition can *observe* but
cannot *act*. Detection continues (agents process local telemetry), but
response is blocked (no quorum for authorization). When the partition heals,
the minority's observations are integrated into the substrate (NATS replay)
and any pending response requests enter the consensus pipeline.

### 9.3 Local Fallback with Journal Substrate

For edge deployments where NATS infrastructure is not available, the
`LocalJournalPheromoneSubstrate` combined with Sentinel's Raft-lite provides
an alternative partition strategy:

1. Each node runs a local journal substrate (per-node pheromone state).
2. Sentinel's Raft-lite provides cross-node coordination for decisions.
3. Pheromone deposits are replicated via Raft-lite's decision log (piggybacked
   on heartbeat messages, similar to how `Decision` structs are replicated).
4. Concentration computation uses the replicated deposit set.

This trades NATS's dedicated streaming infrastructure for Raft-lite's
built-in replication, at the cost of higher latency (pheromone deposits
travel through the Raft log instead of a purpose-built pub/sub system).

---

## 10. Swarm Resilience and Failure Tolerance

### 10.1 No Single Point of Failure

The combined architecture eliminates every category of single-point-of-failure:

| Component | Failure Impact | Mitigation |
|---|---|---|
| Single Whisker | Slight reduction in detection coverage | Other Whiskers compensate; source diversity still met |
| Single Stalker | One investigation stalls | Dispatcher reassigns; pheromone trail persists for pickup |
| Single Tom | Reduced consensus committee | BFT tolerates f failures in 3f+1 committee |
| Single Pouncer | Response capacity reduced | Other Pouncers can execute authorized actions |
| Raft-lite leader | Temporary decision halt | New election within ~300ms (2x election timeout) |
| Single NATS node | JetStream quorum maintained (2/3) | Transparent failover, no deposit loss |
| Entire pheromone substrate | Detection reverts to local-only | Agents process local telemetry; lose collective signal |
| Entire consensus layer | Response authorization halted | Detection continues; responses queued for quorum recovery |

### 10.2 Graceful Degradation Hierarchy

| Level | Condition | Detection | Coordination | Response |
|---|---|---|---|---|
| 0 | Full hybrid | Operational | Pheromone + consensus | Authorized |
| 1 | Consensus partitioned | Operational | Pheromone only | BLOCKED (queued) |
| 2 | Substrate partitioned | Local only | None | BLOCKED |
| 3 | All peers lost | Local only | None | BLOCKED (journal for recovery) |

A centralized SIEM/SOAR would fail completely at levels 1--3. The hybrid swarm
maintains detection capability at every level; only response authorization
degrades, which is the correct safety trade-off. See
[08](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) for a broader
treatment of resilience patterns across both systems.

---

## 11. Comparison with Other Multi-Agent Coordination Models

The following table compares the pheromone substrate against four established
multi-agent coordination paradigms:

| Dimension | Blackboard [13] | Market-Based [15] | Contract Net [12] | Tuple Space [14] | Pheromone Substrate |
|---|---|---|---|---|---|
| Write semantics | Mutable overwrite | Bid messages | Announce-bid-award | `out()` tuple | Append-only deposit |
| Conflict resolution | Explicit scheduler | Auction mechanism | Manager selects bid | Pattern matching | Decay + diversity threshold |
| Temporal model | Snapshot | Per-auction | Per-task cycle | Persistent tuples | Continuous decay |
| Failure handling | Re-schedule | Re-auction | Re-announce | Tuple persists | Trail persists for pickup |
| Single-point risk | Blackboard monitor | Auctioneer | Manager | Space server | None (distributed NATS) |
| Overhead per signal | O(1) write | O(N) bids | O(N) bids | O(1) write | O(1) deposit |

STS uses *both* pheromones and a blackboard: pheromones for continuous
time-varying threat signals, and `swarm.blackboard.L{0-4}.{topic}` for
discrete investigation findings. The pheromone substrate's key differentiator
from all four paradigms is the temporal decay dimension -- signal relevance
decreases monotonically with time, which is essential for cybersecurity
where stale indicators must not drive current decisions.

---

## 12. Application to Cybersecurity: Literature Survey

### 12.1 Swarm-Based Intrusion Detection Systems

**Digital Ants** [16]: Mobile agents depositing digital pheromones at anomalous
nodes. Key findings relevant to STS: evaporation rate must match threat
dynamics, source diversity reduces false positives, and the system tolerates
sensor failure. STS's per-deposit `decay_half_life` and
`min_sources_for_escalation` directly address these findings. Kephart's
earlier work on biologically inspired computer immune systems [18] provides
foundational concepts for autonomous agent-based defense.

**AntNet** [17]: Stigmergic network routing that outperforms distance-vector
under dynamic conditions. STS's NATS subject hierarchy serves an analogous
function, routing agent attention via pheromone concentration.

**BeeHive IDS** [20]: Honeybee-inspired IDS with forager and scout agents.
STS's Whisker/Kitten division parallels forager/scout specialization.

### 12.2 Consensus-Based Security Systems

Most prior work uses blockchain consensus for tamper-proof alert logs, but
blockchain finality latency (seconds to minutes) and throughput limitations
make it unsuitable for real-time detection loops. Sentinel's lightweight Raft
is novel in applying distributed consensus specifically to security response
authorization on small edge clusters where sub-second latency is essential.

### 12.3 Hybrid Approaches

The combination of stigmergic detection with consensus-based response appears
novel. Existing literature treats detection and response as either fully
centralized (SIEM/SOAR) or fully decentralized (swarm-only). The Sentinel
convergence model separates coordination by action risk: stigmergy for
low-risk (detection, signaling), consensus for high-risk (response, policy).
This mirrors biological systems where social insects use stigmergy for routine
activities but switch to direct communication for colony-level decisions.

---

## 13. Reference Architecture

### 13.1 Component Diagram

Each edge node runs swarm agents + local pheromone substrate + NATS client +
Raft-lite consensus. Agents deposit pheromones locally; NATS JetStream
replicates across nodes. Raft-lite nodes communicate peer-to-peer over TCP.

```
+-----------------------+   +-----------------------+   +-----------------------+
|     Edge Node 1       |   |     Edge Node 2       |   |     Edge Node 3       |
| [Whisker]  [Stalker]  |   | [Whisker]  [Whisker]  |   | [Stalker]  [Weaver]   |
|         |             |   |         |             |   |         |             |
|  Pheromone Substrate  |   |  Pheromone Substrate  |   |  Pheromone Substrate  |
|         |             |   |         |             |   |         |             |
|    NATS Client  <-----+---+-->  NATS Client  <----+---+-->  NATS Client      |
|         |             |   |         |             |   |         |             |
|   Raft-Lite Node <----+---+-> Raft-Lite Node <----+---+-> Raft-Lite Node     |
+-----------------------+   +-----------------------+   +-----------------------+
```

### 13.2 Data Flow

```
Telemetry -> Whisker -> PheromoneDeposit -> Substrate -> Concentration
  -> SwarmMode Transition -> Tom -> BFT Consensus -> Pouncer
  -> Raft-Lite ProposeDecision -> Quorum Ack -> Response Executed
  -> Signed Receipt -> Substrate (audit)
```

### 13.3 Message Flow During Active Incident

```
T+0   Whisker-7a3f   deposit(C2, HIGH, 0.85)             Pheromone
T+2m  Whisker-2b1c   deposit(C2, HIGH, 0.90)             Pheromone
T+4m  Whisker-9d4e   deposit(C2, MED, 0.80)  -> Alert    Pheromone
T+5m  Stalker-2e1b   ClaimInvestigation(H-0042)          CRDT
T+8m  Stalker-2e1b   deposit(C2, CRIT, 0.95)             Pheromone
T+12m Substrate      Multi-class > 5.0       -> Incident  Internal
T+13m Tom committee  BFT: 3/3 APPROVE BlockEgress        BFT
T+14m Pouncer-8f2a   Execute via Raft-Lite                Raft-Lite
T+14m Raft-Lite      Decision committed, receipt signed   Raft-Lite
```

### 13.4 Integration Points

| Integration Point | STS Component | Sentinel Component | Protocol |
|---|---|---|---|
| Response execution | Pouncer | ProposeDecision | Raft-Lite over TCP |
| Partition awareness | Tom posture machine | PartitionCallback | Callback |
| Health monitoring | SubstrateHealth | IsPartitioned() | Health endpoint |
| Decision audit | EscalationRecord | Decision log | Append-only journals (see [07](07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md)) |

---

## 14. Theoretical Contributions

This research surfaces several potentially novel design combinations at the
intersection of swarm intelligence and distributed systems security. They
should be treated as implementation hypotheses to validate, not as established
claims of novelty:

1. **Risk-stratified coordination** -- Explicit mapping of action risk level
   to coordination mechanism (stigmergy for detection, consensus for response)
   appears to be new in the literature. See Section 6.3.

2. **Cryptographic pheromones** -- Digital pheromones with Ed25519 signatures,
   source diversity enforcement, and anti-Sybil guarantees provide a practical
   scheme for authenticated stigmergic coordination not found in biological
   analogs or prior digital ant systems.

3. **Hysteresis mode transitions** -- The Schmitt trigger approach to swarm mode
   transitions improves on simple threshold models in the biological stigmergy
   literature. See Section 2.5.

4. **Continuous-time concentration with discrete consensus gates** -- The model
   of continuously-decaying pheromone concentration feeding into discrete BFT
   consensus rounds bridges continuous and discrete coordination theories.

---

## 15. Conclusion

The convergence of Swarm Team Six's pheromone-based stigmergic coordination
with Sentinel's Raft-lite consensus produces a hybrid architecture that
addresses the fundamental tension in autonomous security systems: the need
for both speed (in detection) and safety (in response).

Stigmergic coordination (Sections 1--3) provides sub-millisecond signal
propagation, graceful degradation under failure, emergent threat prioritization
via concentration gradients, self-cleaning temporal dynamics, and Byzantine
resistance through source diversity enforcement.

Raft-lite consensus (Section 4) provides deterministic agreement on irreversible
actions, quorum-based safety, auditable decision logs, and sub-second leader
election.

The hybrid model (Section 6) layers them appropriately: pheromones for the
high-volume, latency-sensitive detection layer; consensus for the low-volume,
safety-critical response layer; and the escalation bridge translating
probabilistic concentration thresholds into deterministic consensus proposals.

The resulting system tolerates individual agent failures, network partitions,
and even Byzantine agents (through the combination of Ed25519 signatures,
source diversity, and BFT consensus) while maintaining continuous threat
detection capability. No single point of failure exists at any layer.

This architecture is a practical instantiation of biological swarm intelligence
principles -- positive feedback, negative regulation, randomness, and multiple
interactions -- adapted for the constraints of autonomous cybersecurity: cryptographic
authentication, regulatory auditability, and the asymmetric cost structure of false
positive responses versus missed detections. Sentinel's predictive failure signals
(see [02](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md)) provide an additional class
of pheromone source, enabling infrastructure health metrics to feed into the same
stigmergic detection layer alongside pure security telemetry.

---

## 16. References

[1] Grasse, P.-P. (1959). La reconstruction du nid et les coordinations interindividuelles chez *Bellicositermes natalensis* et *Cubitermes* sp. *Insectes Sociaux,* 6(1), 41--80.

[2] Dorigo, M. (1992). *Optimization, Learning and Natural Algorithms.* PhD thesis, Politecnico di Milano.

[3] Dorigo, M., Maniezzo, V., & Colorni, A. (1996). Ant System: Optimization by a Colony of Cooperating Agents. *IEEE Trans. Systems, Man, and Cybernetics, Part B,* 26(1), 29--41.

[4] Dorigo, M., & Gambardella, L. M. (1997). Ant Colony System: A Cooperative Learning Approach to the Traveling Salesman Problem. *IEEE Trans. Evolutionary Computation,* 1(1), 53--66.

[5] Bonabeau, E., Dorigo, M., & Theraulaz, G. (1999). *Swarm Intelligence: From Natural to Artificial Systems.* Oxford University Press.

[6] Reynolds, C. W. (1987). Flocks, Herds, and Schools: A Distributed Behavioral Model. *Computer Graphics,* 21(4), 25--34.

[7] Kennedy, J., & Eberhart, R. (1995). Particle Swarm Optimization. *Proc. IEEE International Conf. on Neural Networks,* 4, 1942--1948.

[8] Camazine, S., et al. (2001). *Self-Organization in Biological Systems.* Princeton University Press.

[9] Ongaro, D., & Ousterhout, J. (2014). In Search of an Understandable Consensus Algorithm. *USENIX ATC,* 305--319.

[10] Lamport, L. (1998). The Part-Time Parliament. *ACM Trans. Computer Systems,* 16(2), 133--169.

[11] Castro, M., & Liskov, B. (1999). Practical Byzantine Fault Tolerance. *OSDI,* 173--186.

[12] Smith, R. G. (1980). The Contract Net Protocol. *IEEE Trans. Computers,* C-29(12), 1104--1113.

[13] Hayes-Roth, B. (1985). A Blackboard Architecture for Control. *Artificial Intelligence,* 26(3), 251--321.

[14] Gelernter, D. (1985). Generative Communication in Linda. *ACM TOPLAS,* 7(1), 80--112.

[15] Wellman, M. P. (1993). A Market-Oriented Programming Environment and Its Application to Distributed Multicommodity Flow Problems. *JAIR,* 1, 1--23.

[16] Zhong, Y., Zhang, B., & Lu, H. (2009). Network Security Monitoring with Digital Ants. *J. Computer Science and Technology,* 24(4), 672--688.

[17] Di Caro, G., & Dorigo, M. (1998). AntNet: Distributed Stigmergetic Control for Communications Networks. *JAIR,* 9, 317--365.

[18] Kephart, J. O. (1994). A Biologically Inspired Immune System for Computers. *Proc. Artificial Life IV,* 130--139.

[19] Roth, M., Simmons, R., & Veloso, M. (2008). Decentralized Communication Strategies for Coordinated Multi-Agent Policies. *Multi-Robot Systems,* 93--106.

[20] Zheng, J., et al. (2011). Intrusion Detection Based on Honeybee Colony Optimization. *Information Sciences,* 181(12), 2602--2614.

---

## 17. Cross-References

This document is part of the Sentinel-Convergence research series (8 documents).
Related documents and their connection to stigmergic coordination:

| # | Document | Relevance to This Document |
|---|---|---|
| 01 | [Distributed Consensus for Agent Swarms](01-DISTRIBUTED-CONSENSUS-FOR-AGENT-SWARMS.md) | Formalizes the Raft-to-BFT consensus pipeline that this document's "hard consensus" layer relies on |
| 02 | [Predictive Failure as Threat Signal](02-PREDICTIVE-FAILURE-AS-THREAT-SIGNAL.md) | Sentinel's health-score predictions as an additional pheromone source class feeding the stigmergic layer |
| 03 | [Edge-Native Security Detection](03-EDGE-NATIVE-SECURITY-DETECTION.md) | Edge deployment constraints that motivate the lightweight pheromone substrate backends |
| 04 | [Autonomous Response Under Partition](04-AUTONOMOUS-RESPONSE-UNDER-PARTITION.md) | Partition behavior of the hybrid model; safety properties when consensus is unavailable |
| 05 | [Telemetry Bridge Architecture](05-TELEMETRY-BRIDGE-ARCHITECTURE.md) | How raw telemetry reaches Whisker agents before pheromone deposition occurs |
| 07 | [Audit Trails and Decision Reconciliation](07-AUDIT-TRAILS-AND-DECISION-RECONCILIATION.md) | Cryptographic audit chain for decisions authorized through the escalation bridge |
| 08 | [Resilience Patterns for Distributed Agents](08-RESILIENCE-PATTERNS-FOR-DISTRIBUTED-AGENTS.md) | Broader failure-tolerance analysis that extends this document's Section 10 |

---

*This document is part of the Sentinel-Convergence research series examining
the integration of Backbay's edge-cluster orchestration (Sentinel) with
autonomous threat hunting (Swarm Team Six).*
