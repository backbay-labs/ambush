# Agent Reference

> Historical note: this document describes the earlier Python-heavy swarm shape. As of April 2, 2026 it is reference material, not the active implementation path.

Detailed reference for each Swarm Team Six agent archetype.

---

## Overview

Eight agent archetypes form the blue swarm. Each maps to a biological swarm role and a real threat-hunting function. Roles are behavioral modes, not fixed assignments -- agents can shift based on swarm needs.

| Agent | Hunt Phase | Language | Autonomy |
|-------|-----------|----------|----------|
| [Whisker](#whisker) | Detect | Rust | Tier 1 |
| [Stalker](#stalker) | Stalk | Python | Tier 2 |
| [Weaver](#weaver) | Stalk | Python | Tier 2 |
| [Pouncer](#pouncer) | Ambush | Python | Tier 3 |
| [Tom](#tom) | Ambush | Python | Tier 3 |
| [Kitten](#kitten) | Evolve | Python | Tier 2 |
| [Sphinx](#sphinx) | All | Python | Tier 1 |
| [Calico](#calico) | Detect | Python | Tier 1 |

---

## Whisker

**Role:** Sensor/detection -- deposits pheromones on anomaly detection.
**Biological analog:** Cat whiskers sensing air currents.
**Language:** Rust (crate: `swarm-whisker`)
**Autonomy tier:** Tier 1 (fully autonomous)

### What It Does

Whiskers are long-running, stateful stream processors operating on NATS telemetry subjects. They consume telemetry events (eBPF syscalls from Tetragon, network flows from Hubble, tool invocations from the guard pipeline) and apply fast Rust-native detection. No LLM per signal -- microsecond budget per event.

Detection methods:
- Embedding cosine similarity (Spider Sense fast path)
- Rule matching (Sigma-style patterns)
- Statistical anomaly detection (sliding window state)

On detection, a Whisker deposits a signed `PheromoneDeposit` into the substrate. Other agents sense the concentration and react.

### Key Types

```rust
// crates/swarm-whisker/src/detector.rs

pub trait DetectionStrategy: Send + Sync {
    fn id(&self) -> &str;
    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionMatch>;
}

pub struct TelemetryEvent {
    pub source: String,       // "tetragon", "hubble", "guard_pipeline"
    pub event_type: String,
    pub timestamp: i64,
    pub payload: serde_json::Value,
}

pub struct DetectionMatch {
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub confidence: f64,
    pub indicator: serde_json::Value,
    pub strategy_id: String,
}
```

### Communication

- **Subscribes to:** Telemetry NATS subjects (source-specific)
- **Publishes to:** `swarm.pheromone.{threat_class}.{severity}`
- **Emits:** `SwarmAction::DepositPheromone`

### Triggers

- Incoming telemetry events on subscribed NATS subjects (continuous)
- Swarm mode escalation to Alert or Incident (increases sampling rate)

### Produces

- `PheromoneDeposit` signed with the agent's Ed25519 key
- Aggregated `PheromoneConcentration` triggers mode transitions

### Notes

Detection strategies are pluggable via the `DetectionStrategy` trait. Strategies are evolved by Kitten agents, verified by Z3, and hot-loaded into Whiskers at runtime. The streaming runtime (`swarm-whisker/src/stream.rs`) maintains sliding window state for temporal correlation across events.

---

## Stalker

**Role:** Investigation -- follows leads, reconstructs timelines, gathers evidence.
**Biological analog:** Cat stalking prey.
**Language:** Python (`kernel/archetypes/stalker/`)
**Autonomy tier:** Tier 2 (autonomous with reporting)

### What It Does

Stalkers activate when pheromone concentration crosses the alert threshold. They claim a lead (preventing duplication via OR-Set CRDTs), spawn an isolated investigation context (Cyntra workcell), and use LLM-powered hypothesis-driven investigation to reconstruct attack timelines.

Each Stalker has full `HushEngine` capability -- it can evaluate the ClawdStrike guard pipeline, issue delegation tokens to sub-agents, and produce signed receipts attesting to its findings.

### Key Capabilities

- Timeline reconstruction via hunt-query patterns
- Hypothesis generation using Claude
- Evidence gathering from telemetry streams
- Cross-reference against Sphinx knowledge graph
- Signed receipt production on investigation completion

### Communication

- **Subscribes to:** `swarm.pheromone.*.*` (filtered by current investigation focus)
- **Publishes to:** `swarm.blackboard.L{0-4}.{topic}` (investigation findings)
- **Emits:** `SwarmAction::ClaimInvestigation`, `SwarmAction::PublishFindings`, `SwarmAction::RequestResponse`, `SwarmAction::DepositPheromone`

### Triggers

- Pheromone concentration crossing alert threshold from >= 2 distinct sources
- Direct assignment by Tom governance agent
- Automatic spawn by Cyntra dispatcher when investigation queue exceeds capacity

### Produces

- Investigation findings (published to blackboard)
- Reinforced pheromone deposits (confirmed threats get stronger signals)
- Response recommendations (forwarded to Pouncer via `RequestResponse`)
- Ed25519-signed receipts for every investigation conclusion

### Notes

Stalkers are the primary LLM consumer in the swarm. They use the `anthropic` SDK for hypothesis generation and evidence evaluation. Investigation contexts are isolated (Cyntra workcells) to prevent cross-contamination between concurrent investigations. The dispatcher monitors Stalker health and reassigns leads if an agent times out.

---

## Weaver

**Role:** Correlation -- connects independent signals into coherent attack narratives.
**Biological analog:** Cat weaving between objects.
**Language:** Python (`kernel/archetypes/weaver/`)
**Autonomy tier:** Tier 2 (autonomous with reporting)

### What It Does

Weavers maintain MAGMA-style multi-graph threat context across four orthogonal graphs:

1. **Temporal graph** -- attack timeline ordering (what happened when)
2. **Causal graph** -- kill chain / dependency relationships (what caused what)
3. **Entity graph** -- adversary infrastructure (IPs, domains, tools, credentials)
4. **Semantic graph** -- TTP pattern similarity (embedding-based, which attacks look alike)

When multiple Whisker and Stalker signals arrive, the Weaver attempts to correlate them into a unified attack narrative. A single IP flagged by one Whisker is noise. The same IP appearing in Whisker pheromones, correlated with lateral movement by a Stalker, and matching a known TTP in the semantic graph, is a hypothesis worth promoting.

### Communication

- **Subscribes to:** `swarm.pheromone.*.*`, `swarm.blackboard.L{0-4}.*`
- **Publishes to:** `swarm.blackboard.L{2-4}.{topic}` (correlated hypotheses)
- **Emits:** `SwarmAction::PublishFindings`, `SwarmAction::RequestResponse`

### Triggers

- New pheromone deposits (continuous background processing)
- New Stalker findings on the blackboard
- Swarm mode escalation (activates aggressive cross-correlation in Alert/Incident mode)

### Produces

- Correlated hypotheses with cross-graph evidence chains
- MITRE ATT&CK technique mappings
- Kill chain reconstructions
- Escalation recommendations when correlation confidence exceeds threshold

### Notes

The 4-graph architecture is based on MAGMA (arXiv 2601.03236), which demonstrated 45.5% higher reasoning accuracy versus single-graph approaches. Graphs are maintained using NetworkX in-process, with periodic snapshots to Sphinx for long-term memory. Cross-hunt correlation allows the Weaver to connect signals from separate investigations that share infrastructure or TTPs.

---

## Pouncer

**Role:** Response execution -- executes coordinated response actions after consensus.
**Biological analog:** Explosive kill strike.
**Language:** Python (`kernel/archetypes/pouncer/`)
**Autonomy tier:** Tier 3 (human-approved)

### What It Does

Pouncers never act alone. Every response action requires BFT consensus from the Tom committee (2f+1 agreement). Actions are executed through the ClawdStrike broker subsystem -- time-bounded, path-scoped, cryptographically audited.

Available response actions:

| Action | What It Does |
|--------|-------------|
| `BlockEgress` | Block network egress to a target IP/CIDR |
| `IsolateHost` | Isolate a host from the network |
| `RevokeCredential` | Revoke a credential or capability token |
| `DeployDecoy` | Deploy a deception asset (coordinated with Calico) |
| `Escalate` | Escalate to human operator with summary and urgency |

### Communication

- **Subscribes to:** `swarm.consensus.{committee_id}.{phase}` (consensus results)
- **Publishes to:** Broker capability requests, `swarm.agent.{id}.heartbeat`
- **Emits:** `SwarmAction::RequestResponse` (which triggers consensus pipeline)

### Triggers

- Authorized `RequestResponse` action from Stalker or Weaver, approved by Tom consensus
- Direct human operator command (Tier 3 override)

### Produces

- Executed response actions
- Ed25519-signed receipts with full evidence chain
- Broker capability tokens (time-bounded, path-scoped, auditable)

### Notes

The Pouncer is the most constrained agent in the swarm. It cannot independently decide to act. The middleware pipeline enforces this: stage 7 (ConsensusGate) blocks until BFT consensus is reached, and stage 2 (TierAuthorization) rejects any Tier 3 action from an agent not operating at Tier 3 with proper authorization. This is a direct design response to the false-positive cascade risk identified in brainstorm analysis.

---

## Tom

**Role:** Governance -- enforces policy, manages lifecycle, runs consensus.
**Biological analog:** Tomcat (dominant leader).
**Language:** Python (`kernel/archetypes/tom/`)
**Autonomy tier:** Tier 3 (human-approved)

### What It Does

Tom agents are the swarm's governance layer:

- **Policy enforcement** -- evaluates all actions against the ClawdStrike policy engine
- **Autonomy tier management** -- sets and enforces what each archetype can do autonomously
- **BFT consensus committee** -- participates in Tendermint-style consensus for response actions and evolution commits
- **Agent lifecycle** -- admits new agents, revokes compromised agents, manages population scaling
- **Posture state machine** -- manages swarm-wide mode transitions (Normal -> Alert -> Incident)
- **Veto authority** -- can veto false-positive-prone strategies before deployment
- **Receipt validation** -- verifies evidence chains and signed receipts from other agents

### Communication

- **Subscribes to:** `swarm.consensus.{committee_id}.*`, `swarm.evolution.proposal`, `swarm.agent.*.role_change`
- **Publishes to:** `swarm.consensus.{committee_id}.{phase}`, `swarm.agent.{id}.heartbeat`
- **Emits:** Consensus votes, policy decisions, lifecycle commands

### Triggers

- Consensus round initiated (propose/prevote/precommit phases)
- Evolution strategy proposal (Z3 verification + consensus vote)
- Agent health degradation (triggers lifecycle management)
- Trust decision requests (admit/revoke agents)

### Produces

- Consensus votes (signed)
- Policy decisions (signed receipts)
- Agent lifecycle commands (admit, revoke, scale)
- Posture state transitions

### Notes

Tom committee membership rotates via VRF seeded from the latest Merkle checkpoint hash. Default rotation: every hour. Default population: 3 Toms (tolerating f=1 Byzantine fault). Committee size can scale to 5 for larger deployments (tolerating f=1 with wider consensus, or configurable to f=2 with 7 members). Tom agents themselves require Tier 3 authorization for destructive actions (revoking agents, changing policy).

---

## Kitten

**Role:** Evolution -- mutates detection strategies, drives the co-evolutionary arms race.
**Biological analog:** Kittens learning to hunt.
**Language:** Python (`kernel/archetypes/kitten/`)
**Autonomy tier:** Tier 2 (autonomous with reporting)

### What It Does

Kittens evolve detection strategies through genetic/memetic algorithms, test them against Hellcat red swarm replays, and submit verified strategies for Tom consensus approval.

Evolution pipeline:

1. **Generate** -- create candidate strategy via mutation/crossover of existing strategies
2. **Shadow test** -- run candidate against historical traffic replay (no live impact)
3. **Z3 gate** -- verify that the strategy maintains all safety invariants (compiled to Z3 formula via `clawdstrike-logos`)
4. **Canary deployment** -- small Whisker population tests the strategy in production
5. **Tom consensus** -- BFT vote approves promotion to full deployment

Strategy selection uses MemRL Q-value scoring -- past strategies are scored by actual hunting utility (not just semantic similarity), and the Kitten selects parents with high learned effectiveness.

### Communication

- **Subscribes to:** `swarm.evolution.validation`, `swarm.canary.{test|alert}`
- **Publishes to:** `swarm.evolution.proposal`, `swarm.canary.test`
- **Emits:** `SwarmAction::ProposeStrategy`

### Triggers

- Red swarm evasion event (a Hellcat operator successfully evaded blue detection)
- Scheduled evolution cadence (configurable: continuous, batch, or event-triggered)
- Fitness degradation detected (detection rate dropping)

### Produces

- Evolved detection strategies (submitted as proposals)
- Fitness metrics (blue detection rate vs red evasion rate over time)
- Strategy lineage tracking (mutation/crossover history)
- Z3 verification results

### Notes

Kittens evolve detection heuristics only, never response actions. Response actions are governed by the static, verified ClawdStrike policy engine. This is a hard architectural constraint -- the co-evolutionary engine in `kernel/evolution/` enforces it. The Z3 gate is not optional; it is a required step in the middleware pipeline (stage 9, EvolutionTracking, validates that all proposals have Z3 certification).

---

## Sphinx

**Role:** Memory -- maintains the swarm's long-term threat knowledge.
**Biological analog:** Keeper of knowledge.
**Language:** Python (`kernel/archetypes/sphinx/`)
**Autonomy tier:** Tier 1 (fully autonomous)

### What It Does

Sphinx maintains the swarm's collective memory across three scopes:

| Scope | Contents | Retention |
|-------|----------|-----------|
| **Individual** | Per-agent recent observations, investigation notes | Short-term, high fidelity |
| **Collective** | Aggregated swarm findings, confirmed threats, resolved incidents | Medium-term, consolidated |
| **World** | Threat landscape context, MITRE ATT&CK mappings, external intel | Long-term, curated |

The memory system is backed by a knowledge graph (pluggable backend: in-memory for dev, SQLite for single-node, Neo4j/KuzuDB for production). Knowledge is grounded in structured data -- Ed25519-signed receipts, STIX objects, MITRE technique IDs -- to prevent hallucinated threats.

Memory types adapted from Cyntra:
- **Pattern memory** -- recurring threat patterns and detection strategies
- **Failure memory** -- past false positives and investigation dead ends
- **Dynamic memory** -- active investigation state
- **Context memory** -- environmental context (what's normal for this network)
- **Playbook memory** -- investigation procedures and their outcomes
- **Frontier memory** -- unresolved hypotheses and leads for future investigation

### Communication

- **Subscribes to:** `swarm.blackboard.L{0-4}.*` (all investigation findings)
- **Publishes to:** Knowledge graph queries return directly to requesting agents
- **Emits:** `SwarmAction::DepositPheromone` (when historical pattern matches current activity)

### Triggers

- New findings published to the blackboard (continuous ingestion)
- Direct queries from Stalkers and Weavers needing historical context
- Scheduled consolidation (short-term to long-term memory migration)

### Produces

- Knowledge graph entries (signed, timestamped)
- Historical pattern matches (deposited as pheromones)
- Investigation context for Stalker hypothesis generation
- Cross-engagement correlation data for Weavers
- Curated pattern DB updates for Whisker detection strategies

### Notes

Sphinx prevents the "hallucinated threat" problem identified in brainstorm analysis. Every knowledge graph entry must be grounded in a signed receipt or structured external intelligence (STIX/TAXII). LLM-generated summaries are stored as supplementary context, never as primary evidence. The MiroFish-inspired architecture ensures that all agent reasoning derives from the structured graph, not from LLM memory.

---

## Calico

**Role:** Deception -- deploys honeypots and canary tokens.
**Biological analog:** Camouflage patterns.
**Language:** Python (`kernel/archetypes/calico/`)
**Autonomy tier:** Tier 1 (fully autonomous)

### What It Does

Calico deploys and manages deception infrastructure:

- **Honeypots** -- service emulators that appear to be real targets
- **Canary tokens** -- tripwire credentials and files that alert when accessed
- **Decoy network segments** -- fake network infrastructure to attract reconnaissance

Calico agents coordinate with Whiskers to monitor interactions with deception assets. Any interaction with a honeypot or canary token is inherently suspicious -- legitimate users and systems don't touch them. This gives Calico's detections unusually high confidence.

### Communication

- **Subscribes to:** Telemetry from deception infrastructure, `swarm.pheromone.initial_access.*`, `swarm.pheromone.discovery.*`
- **Publishes to:** `swarm.pheromone.{threat_class}.{severity}`, deployment records to Sphinx
- **Emits:** `SwarmAction::DepositPheromone`

### Triggers

- Swarm initialization (deploys baseline deception infrastructure)
- Stalker investigation findings (deploys targeted decoys in active investigation zones)
- Tom directive (deploys specific decoy types in specific zones)

### Produces

- Deployed deception assets (honeypots, canaries, decoys)
- High-confidence pheromone deposits when deception assets are triggered
- Deception asset inventory (maintained in Sphinx)

### Notes

Calico is Tier 1 (fully autonomous) because deploying bait is low-risk -- it does not block traffic, isolate hosts, or revoke credentials. The worst case for a false positive is a wasted honeypot. This makes Calico a safe first-mover in the hunt cycle, deploying deception infrastructure ahead of confirmed threats and providing high-signal-to-noise detection when assets are triggered.

---

## Red Swarm Agents (Hellcat-based)

The red swarm is not part of the STS blue swarm codebase. It is adapted from the Hellcat kernel and runs as the adversarial opponent in the co-evolutionary arms race. Included here for completeness.

| Agent | Hellcat Source | Role |
|-------|---------------|------|
| **ReconOp** | 9-phase recon pipeline | Discovers attack surface, feeds TargetGraph |
| **InjectionOp** | SQLi/cmd injection operator | Probes for injection vulnerabilities |
| **AuthOp** | Auth bypass operator | Tests authentication weaknesses |
| **EvasionOp** | Evasion classifier + strategy engine | Adapts to blue swarm detection patterns |
| **ChainOp** | ChainAnalyzer | Finds multi-step exploit chains |
| **OpsecOp** | NoiseMonitor + StealthBudget | Detects when blue swarm is watching |

Red swarm fitness degrades when blue swarm detects its activity. Blue swarm fitness degrades when red swarm evades detection. Both sides co-evolve.

---

## Log Format

Agent radio chatter follows a consistent format. Every line is backed by a signed receipt anchored in the Merkle trail.

```
[Whisker-7a3f] anomaly: unusual egress to 185.220.101.x (sim=0.91)
[Stalker-2e1b] investigating Whisker-7a3f lead, 6h timeline
[Weaver-9c4d] correlated: H-0042 lateral movement via SSH
[Tom-0001]    consensus: 3/5 approve, authorizing Pouncer
[Pouncer-8f2a] response: block 185.220.101.0/24 (receipt 0xae3f)
[Kitten-4d1c] evolved: strategy S-0087 promoted (Z3 verified, fitness +12%)
[Sphinx-1b0e] indexed: H-0042 -> ATT&CK T1021.004, linked to campaign C-0019
[Calico-3e7a] deployed: canary token in /srv/data/finance (tripwire active)
```

Format: `[{Role}-{short_id}] {action}: {detail}`

The `AgentId` is constructed as `{role}-{short_id}` where `short_id` is the first 4 hex characters of the agent's Ed25519 public key hash:

```rust
pub struct AgentId(pub String);

impl AgentId {
    pub fn new(role: &str, short_id: &str) -> Self {
        Self(format!("{role}-{short_id}"))
    }
}
```

---

## Autonomy Tier Reference

| Tier | Can Do Autonomously | Requires |
|------|-------------------|----------|
| **Tier 1** | Deposit pheromones, run detection, deploy decoys, query memory, publish findings | Nothing -- fully autonomous |
| **Tier 2** | All Tier 1 actions, plus: claim investigations, generate hypotheses, propose strategies, correlate signals | Must report findings for human validation before escalation |
| **Tier 3** | All Tier 2 actions, plus: execute response actions, change policy, deploy evolved strategies, admit/revoke agents | BFT consensus (2f+1 Tom committee) AND human approval |

Confidence thresholds (from `rulesets/default.yaml`):
- Tier 1: confidence >= 0.9
- Tier 2: confidence >= 0.7
- Below 0.7: requires human guidance
- Any action above `critical` severity: requires human approval regardless of confidence
