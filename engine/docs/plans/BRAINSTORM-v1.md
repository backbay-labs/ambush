# Swarm Team Six: Brainstorm Synthesis

> Autonomous, self-evolving threat hunting swarm built on ClawdStrike

---

## The Big Idea

Turn ClawdStrike's security enforcement engine *outward*. Instead of guarding agents, **deploy** agents. A swarm of specialized autonomous hunters that share threat intelligence through cryptographic pheromone trails, coordinate investigations without central command, evolve their detection strategies through adversarial co-evolution, and do it all under the governance of a formally-verified policy engine.

**One sentence:** ClawdStrike already enforces the rules -- Swarm Team Six hunts the rulebreakers.

---

## Why This, Why Now

The threat hunting landscape has a gap nobody's filled:

| Layer | State of the Art | What's Missing |
|-------|-----------------|----------------|
| SIEM | Passive log aggregation (Splunk, Elastic) | No autonomous hunting |
| SOAR | Playbook automation (XSOAR, Swimlane) | Rigid, no hypothesis generation |
| XDR | Endpoint telemetry + ML (CrowdStrike, SentinelOne) | Centralized brain, single evasion strategy |
| AI-native | LLM wrappers on alerts | No formal governance, no audit trail |

**The category "formally-verified autonomous threat hunting" is empty.** No one has an open-source, multi-agent, cryptographically-auditable hunting swarm. DARPA's CHASE program (2020-2023) proved autonomous hunting is feasible. The academic provenance systems (HOLMES, ATLAS, SHADEWATCHER) proved kill-chain reconstruction works. The swarm intelligence literature proves multi-agent coordination outperforms single-detector systems for novel threats. But nobody's assembled the full stack.

ClawdStrike has the pieces: guard pipeline, Ed25519 receipts, Spine transport, delegation tokens, formal verification, Spider Sense embeddings. STS is the orchestration layer that makes them hunt.

---

## Architecture Overview

### Core Insight

Biological swarms solve the same problems security teams face: monitoring vast environments with limited resources, detecting novel threats, coordinating responses without central command, and adapting to adversaries that are themselves adapting. We augment swarm patterns with things ant colonies lack: **cryptographic trust** (Ed25519), **formal safety guarantees** (Lean 4 + Z3), and **deterministic policy enforcement** (guard pipeline).

### Layered Architecture

```
+-----------------------------------------------------------+
|                      SWARM LAYER                          |
|  +----------+ +----------+ +----------+ +-----------+     |
|  | Whiskers | |  Stalkers| | Pouncers | |  Kittens  |     |
|  | (detect) | | (invest) | | (respond)| |  (evolve) |     |
|  +----+-----+ +----+-----+ +----+-----+ +-----+-----+    |
|       |             |            |              |          |
|  +----+-------------+------------+--------------+------+  |
|  |            Pheromone Substrate                      |  |
|  |       (NATS JetStream + Merkle Audit Trail)        |  |
|  +----+------------------------------------------------+  |
|       |                                                    |
|  +----+------------------------------------------------+  |
|  |         Gossip Mesh (SWIM + CRDTs)                  |  |
|  +-----------------------------------------------------+  |
+----------------------------+------------------------------+
                             |
+----------------------------+------------------------------+
|                   EXISTING CLAWDSTRIKE                     |
|  +---------+ +--------+ +-------+ +---------+ +---------+ |
|  |  Spine  | | Policy | | Guards| | Receipts| |  Logos  | |
|  |(envelope| | Engine | | (13   | | (Ed25519| | (Z3+Lean| |
|  | +NATS)  | |(v1.5.0)| |builtin| | signed) | |verified)| |
|  +---------+ +--------+ +-------+ +---------+ +---------+ |
+------------------------------------------------------------+
```

**Fail-closed extends to the swarm**: if the swarm fails (agents down, NATS partition), the existing static guard pipeline continues enforcing last-known-good policy. The swarm enhances; it never replaces the deterministic engine.

### The Hunt Cycle

Modeled on real feline hunting behavior:

```
  DETECT -----> STALK -----> AMBUSH -----> EVOLVE
    ^                                        |
    +----------------------------------------+
```

1. **Detect** -- Whisker agents sense anomalies (embedding similarity, pattern matching)
2. **Stalk** -- Stalker agents investigate leads, reconstruct timelines, correlate events
3. **Ambush** -- Pouncer agents execute coordinated response (after consensus)
4. **Evolve** -- Kitten agents mutate detection strategies, test against history, promote winners

---

## Agent Archetypes

Each agent role maps to both a biological swarm role and a real threat-hunting function:

| Agent | Role | Biological Analog | ClawdStrike Integration |
|-------|------|-------------------|------------------------|
| **Whisker** | Sensor/detection | Cat whiskers sensing air currents | Wraps Spider Sense fast path (embedding similarity) |
| **Stalker** | Investigation | Cat stalking prey | Full `HushEngine` capability, issues signed receipts |
| **Weaver** | Correlation | Cat weaving between objects | Connects Whisker signals into attack narratives |
| **Pouncer** | Response | Explosive kill strike | Issues capabilities through broker subsystem |
| **Tom** | Governance | Tomcat (dominant leader) | Enforces policy, validates receipts, manages lifecycle |
| **Kitten** | Evolution | Kittens learning to hunt | GA/memetic engine, shadow-mode testing |
| **Sphinx** | Memory | Keeper of knowledge | Long-term threat intel, pattern DB curator |
| **Calico** | Deception | Camouflage patterns | Honeypots, canary tokens, deceptive infrastructure |

**Roles are behavioral modes, not fixed assignments.** Agents shift based on swarm needs -- like honeybee workers shifting from nurse to forager based on colony demographics. When pheromone concentration spikes, Weavers can promote to Stalker mode. Idle agents raise their activation thresholds, becoming generalists.

### What Logs Look Like

```
[Whisker-7a3f] anomaly: unusual egress to 185.220.101.x (sim=0.91)
[Stalker-2e1b] investigating Whisker-7a3f lead, 6h timeline reconstruction
[Weaver-9c4d] correlated: matches hypothesis H-0042 (lateral movement via SSH)
[Tom-0001]    policy check passed, authorizing Pouncer response
[Pouncer-8f2a] executed: block egress 185.220.101.0/24, receipt 0xae3f...
```

Every line is backed by a signed receipt anchored in the Merkle trail.

---

## Swarm Coordination Mechanisms

### 1. Stigmergy (Pheromone Trails)

Agents communicate by depositing signed threat indicators into the shared environment:

```rust
ThreatPheromone {
    indicator: ThreatIndicator,
    deposit_strength: f64,       // agent confidence (0.0-1.0)
    timestamp: u64,
    decay_rate: f64,             // half-life in seconds
    agent_id: Ed25519PublicKey,
    signature: Ed25519Signature,
    corroboration_count: u32,    // independent agents agreeing
}
```

- **Concentration = escalation**: multiple independent agents flagging the same thing compounds naturally
- **Evaporation**: indicators decay (configurable half-life), preventing stale threat fixation
- **Trail reinforcement**: confirmed investigations deposit stronger pheromones
- **Source diversity**: one agent depositing 1000 pheromones = same as 1 (prevents Sybil flooding)

Maps directly to NATS: `swarm.pheromone.{threat_class}.{severity}`

### 2. Quorum Sensing (Escalation)

Borrowed from bacterial quorum sensing -- agents broadcast state signals; when high-threat density exceeds a threshold, the swarm shifts mode:

| Mode | Behavior |
|------|----------|
| **Normal** | Whiskers on patrol, Weavers passive, few active Stalkers |
| **Alert** | Whiskers increase sampling, Weavers activate aggressive matching, Stalkers spawn |
| **Incident** | Stalkers dominate, Pouncers unlocked, all agents focused on active threat |

Transition is local -- each agent independently decides based on neighbor signals. No central coordinator.

### 3. BFT Consensus (Critical Decisions)

Full consensus only when it matters:
- **Response actions** (block, quarantine, revoke) -- quorum of Stalkers must agree
- **Evolution commits** (new detection strategy goes live) -- quorum validates against benchmarks
- **Trust decisions** (admit/revoke agents)

Lightweight BFT (Tendermint-style) among a rotating committee. Committee membership via VRF seeded from the Merkle trail.

### 4. Gossip (State Sync)

SWIM protocol for failure detection + CRDTs for investigation state:
- G-Counter for pheromone concentrations
- OR-Set for active investigation claims
- Partition-tolerant: sub-swarms continue operating and reconcile when reconnected

---

## Evolution Engine

### What Evolves

1. Detection signatures (what Whiskers look for)
2. Correlation rules (how Weavers connect signals)
3. Investigation playbooks (how Stalkers follow leads)
4. Threshold parameters (escalation tuning)
5. Agent population composition (role distribution)

### Co-Evolutionary Arms Race

The most powerful mechanism: pair the detection swarm against an adversarial **red swarm** that evolves evasion strategies:

- Detection strategies that can be evaded have low fitness
- Evasion strategies that are detected have low fitness
- Both populations push each other to improve continuously

**The formal verification layer is the safety floor**: evolved strategies must pass `clawdstrike-logos` Z3 verification before deployment. Evolution explores freely above the floor but cannot weaken proven invariants.

### Fitness Function (Multi-Objective)

```
fitness = alpha * true_positive_rate
        + beta  * (1.0 - false_positive_rate)
        + gamma * detection_speed
        + delta * resource_efficiency
        - epsilon * evasion_success_rate
```

Where `evasion_success_rate` comes from the red swarm -- forcing genuine adversarial robustness.

### Staged Deployment

1. Kitten generates candidate strategy via mutation/crossover
2. Shadow mode: runs against historical traffic replay
3. Z3 verification gate: must maintain policy invariants
4. Differential test gate: must match Lean 4 spec behavior
5. Canary deployment: small population tests in production
6. Quorum consensus: Toms approve promotion to full deployment

---

## What ClawdStrike Already Has (Reuse Inventory)

| Existing Component | Swarm Application |
|---|---|
| **Guard pipeline** (13 guards, 3-stage evaluation) | Threat scoring pipeline: fast path detection -> deep investigation |
| **Spider Sense** (embedding cosine similarity) | Whisker agent fast path -- pure sync, WASM-compatible |
| **Async guards** (timeout, circuit breaker, rate limit) | Async threat intel queries (VirusTotal, Snyk) for Stalkers |
| **Delegation tokens** (Ed25519, capability attenuation) | Agents spawn sub-agents with scoped, time-bounded capabilities |
| **Signed messages** (replay-resistant, nonce-based) | Swarm inter-agent communication with integrity |
| **Spine envelopes** (NATS + Merkle proofs) | Pheromone substrate + immutable audit trail |
| **Posture system** (state machine, budget-aware) | Agent mode switching: observation -> investigation -> response |
| **Broker capabilities** (proof binding, TTL, path-scoped) | Hushd issues capabilities to hunting agents for data access |
| **Correlation context** (W3C traceparent) | Trace hunts across autonomous agents |
| **Logos/Z3** verification | Safety gate for evolved strategies |
| **Lean 4 spec** + differential tests | Formal correctness for evolved behaviors |
| **Policy composition** (`extends`, merge strategies) | Agents inherit base policy, override per role |

---

## The Devil's Advocate Speaks

The skeptic on the team raised critical concerns that shape the design:

### Concern 1: False Positive Cascades
**Risk**: Swarm reinforcement turns one false positive into a coordinated denial-of-service against your own infrastructure. CrowdStrike's July 2024 incident bricked 8.5M machines from a *centralized* push -- autonomous agents are worse.

**Design response**: Pheromone source diversity (one agent can't flood), decay functions, and the static policy engine as a hard floor. The swarm recommends; the verified engine enforces.

### Concern 2: Self-Evolution Alignment
**Risk**: Every fitness function has a Goodhart's Law failure mode. The swarm optimizes for the metric, not the goal. Evolving to classify everything as a threat maximizes "threats detected."

**Design response**: Multi-objective fitness with adversarial red swarm pressure. Z3 verification gate rejects strategies that violate proven invariants. Human approval for any strategy that changes effective security posture.

### Concern 3: The Swarm is Itself a Target
**Risk**: Poisoning evolution, exploiting inter-agent communication, manipulating consensus, extracting evolved heuristics as an evasion roadmap.

**Design response**: Ed25519 identity on all messages, BFT consensus for critical decisions, canary integrity monitoring, capability-based Sybil resistance, staged rollout with auto-rollback.

### Concern 4: Complexity vs. Value
**Risk**: For known threats, a single well-tuned detector beats a swarm of mediocre ones. The 13 built-in guards are deterministic, verified, and fast. A swarm can't improve on deterministic correctness.

**Design response**: The swarm is for *high-ambiguity, novel threats* -- the zone where existing guards return "uncertain." Spider Sense's ambiguous band is literally where the swarm adds value. Don't swarm what's already solved.

### Concern 5: Regulatory/Liability
**Risk**: SOC2 wants deterministic controls. GDPR Article 22 restricts automated decisions. "The swarm decided" is not an auditable control.

**Design response**: Tiered autonomy. Tier 1 (autonomous): routine hunting, known-bad detection. Tier 2 (autonomous + report): novel detections, hypothesis generation. Tier 3 (human-approved): response actions, policy changes. Every action produces a signed receipt.

### The Verdict
> Build the swarm for **detection and triage**, not autonomous response. Keep the existing policy engine as the enforcement layer. Use the swarm as an advisory layer that feeds diverse detection signals into the proven decision pipeline. Evolution is constrained: agents evolve *detection heuristics*, not *response actions*.

**The strongest version of STS is a diverse sensor array that makes the existing, verified engine smarter -- with humans making the final call on evolved behavior changes.**

---

## Naming & Identity

### Project Name: "Swarm Team Six"
Strong codename. Instant recognition from SEAL Team Six. "Swarm" is technically accurate. But it breaks from the cat/claw brand DNA.

### Product Name Candidates

| Name | Concept | Verdict |
|------|---------|---------|
| **Clowder** | A group of cats is literally called a "clowder" | Top pick for community/OSS identity |
| **Ambush** | A group of cats is also called an "ambush" | Top pick for product branding -- it's what cats do to prey |
| **Clowder Six** | Clowder + military "Six" callsign | Best of both worlds |
| **NineLife** | Threat hunting that won't die | Great for resilience narrative |
| **Prowl Pack** | Pack-hunting cats | Action-oriented |

**Recommendation**: Ship as **ClawdStrike Ambush** (or **The Clowder** for the community). Keep "Swarm Team Six" as the internal codename.

### Core Metaphor: Feline Ambush Predator

Cats are **solitary hunters that form cooperative colonies when resources are shared**. This is exactly the architecture: independent specialized agents that cooperate through shared infrastructure (Spine/NATS) and shared governance (policy engine).

The hunt cycle language:
- "The swarm is **stalking** 3 active leads"
- "Hypothesis H-0042 has been **pounced** (confirmed TP)"
- "7 **kittens** in shadow mode, 2 promoted this week"
- "Tom governance layer blocked unauthorized **prowl**"

---

## Proposed Crate Structure

```
crates/
  swarm/
    swarm-core/          # SwarmAgent trait, pheromone types, config
    swarm-whisker/       # Detection agents (wraps Spider Sense)
    swarm-stalker/       # Investigation agents + timeline reconstruction
    swarm-weaver/        # Correlation engine + hypothesis promotion
    swarm-pouncer/       # Response agents (capability-gated)
    swarm-tom/           # Governance + policy enforcement
    swarm-kitten/        # Evolution engine (GA/memetic + fitness eval)
    swarm-sphinx/        # Long-term memory + threat intel store
    swarm-calico/        # Deception infrastructure
    swarm-pheromone/     # Pheromone substrate (deposit/query/decay)
    swarm-gossip/        # SWIM membership + CRDT state sync
    swarm-consensus/     # BFT consensus for critical decisions
    swarm-orchestrator/  # Lifecycle management + scaling
```

### Core Trait

```rust
#[async_trait]
pub trait SwarmAgent: Send + Sync {
    fn identity(&self) -> &Ed25519PublicKey;
    fn role(&self) -> AgentRole;
    async fn tick(&mut self, env: &SwarmEnvironment) -> Result<Vec<SwarmAction>>;
    async fn handle_message(&mut self, msg: SignedEnvelope<SwarmMessage>) -> Result<()>;
    fn health(&self) -> AgentHealth;
}
```

### NATS Subject Hierarchy

```
swarm.pheromone.{threat_class}.{severity}
swarm.blackboard.L{0-4}.{topic}
swarm.gossip.membership
swarm.gossip.state
swarm.consensus.{committee_id}.{phase}
swarm.evolution.proposal
swarm.evolution.validation
swarm.canary.{test|alert}
swarm.agent.{id}.{heartbeat|role_change}
```

---

## Key References

**Autonomous Hunting**: DARPA CHASE (2020-2023), HOLMES (IEEE S&P 2019), ATLAS (USENIX Security 2021), SHADEWATCHER (IEEE S&P 2022)

**Swarm Intelligence**: Bonabeau et al. "Swarm Intelligence" (1999), Dorigo & Stutzle "Ant Colony Optimization" (2004), NATO AICA Reference Architecture (Kott et al. 2019)

**Adversarial ML**: Pendlebury et al. "TESSERACT" (USENIX Security 2019), Arp et al. "Dos and Don'ts of ML in Security" (USENIX Security 2022)

**Frameworks**: MITRE ATT&CK + CALDERA, Sigma Rules (~3000+), Elastic detection-rules (1200+), DeTT&CT coverage scoring

---

## Open Questions for Next Phase

1. **Scope**: Full swarm from day one, or start with Whisker + Stalker pair and expand?
2. **Telemetry sources**: eBPF (Tetragon bridge exists), network flows (Hubble bridge exists), what else?
3. **Evolution speed**: How fast should the swarm adapt? Real-time feels risky; daily batch feels slow.
4. **Red swarm**: Build the adversarial co-evolution from the start, or bolt it on later?
5. **Deployment model**: Sidecar per workload? Centralized swarm? Hybrid?
6. **LLM integration**: Use LLMs for hypothesis generation (expensive but creative) or pure algorithmic (cheap but narrow)?
7. **Data gravity**: Where does the swarm's state live? Edge? Central? Federated?
