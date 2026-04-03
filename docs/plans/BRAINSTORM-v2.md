# Swarm Team Six: Brainstorm v2

> Autonomous, self-evolving threat hunting swarm built on ClawdStrike + Cyntra + Hellcat

---

## What Changed Since v1

Wave 2 research revealed that the foundation is far stronger than initially scoped. Three internal systems (ClawdStrike, Cyntra, Hellcat) already provide ~90% of the primitives needed. External research (DeerFlow, MiroFish, 2026 SOTA) validated architectural choices and added new patterns.

**The big reframe**: STS is not a greenfield project. It's an **orchestration layer** that wires together:
- **ClawdStrike** = security enforcement, crypto, transport, formal verification
- **Cyntra** = scheduling, dispatching, verification, memory, sentinels
- **Hellcat** = the red swarm (autonomous red teaming kernel, 16 attack operators, OPSEC, learning)

Hellcat is the breakthrough finding. **The co-evolutionary arms race already has one side built.** Hellcat IS the red swarm. STS is the blue swarm. They co-evolve against each other.

---

## Architecture v2: The Three-Kernel Stack

```
+================================================================+
|                     SWARM TEAM SIX                              |
|         (orchestration + coordination + evolution)              |
|                                                                 |
|  +------------------+  +------------------+  +----------------+ |
|  |   BLUE SWARM     |  |   RED SWARM      |  |  EVOLUTION     | |
|  |   (detection &    |  |   (adversarial   |  |  (co-evolve    | |
|  |    hunting)       |  |    pressure)     |  |   both sides)  | |
|  +--------+---------+  +--------+---------+  +-------+--------+ |
|           |                      |                    |          |
|  +--------+----------------------+--------------------+--------+ |
|  |              Pheromone Substrate (NATS JetStream)           | |
|  +--------+----------------------+--------------------+--------+ |
+===========|======================|====================|=========+
            |                      |                    |
+-----------+----------+-----------+----------+---------+---------+
| CYNTRA KERNEL        | HELLCAT KERNEL       | CLAWDSTRIKE       |
| (orchestration)      | (red teaming)        | (enforcement)     |
|                      |                      |                   |
| - Scheduler          | - TargetGraph        | - Guard pipeline  |
| - Dispatcher         | - AttackPlanner      | - Ed25519 receipts|
| - Verifier           | - 16 Operators       | - Spine/NATS      |
| - StateManager       | - OPSEC/Noise        | - Delegation tkns |
| - Memory/Learning    | - Proof gates L1-L4  | - Spider Sense    |
| - Sentinels          | - Prompt evolution   | - Posture states  |
| - Event system       | - AttackPatternDB    | - Broker caps     |
| - Ralph (loop ctrl)  | - Evasion engine     | - Logos/Z3/Lean4  |
+-----------+----------+-----------+----------+---------+---------+
```

### Why Three Kernels

Each kernel owns a distinct concern:

| Kernel | Concern | Language | Reuse % |
|--------|---------|----------|---------|
| **Cyntra** | "What to do next" -- scheduling, dispatching, verification, memory | Python | ~80% direct |
| **Hellcat** | "How to attack" -- red team operators, evasion, OPSEC, proof gates | Python | ~70% as red swarm |
| **ClawdStrike** | "Is it safe" -- policy enforcement, crypto, transport, formal proofs | Rust | ~90% direct |

STS itself is thin glue: pheromone substrate, archetype routing, co-evolutionary fitness, and the blue swarm agent implementations.

---

## The Co-Evolutionary Arms Race (Now Concrete)

This was theoretical in v1. With Hellcat, it's implementable:

```
BLUE SWARM (STS)                    RED SWARM (Hellcat)
================                    ===================
Whiskers detect anomalies    <--->  Operators probe targets
Stalkers investigate leads   <--->  Evasion engine adapts
Weavers correlate signals    <--->  ChainAnalyzer finds paths
Pouncers respond             <--->  OPSEC monitors detection
Kittens evolve detection     <--->  Prompt evolution mutates TTPs
Sphinx remembers             <--->  AttackPatternDB learns
Tom governs                  <--->  StealthBudget constrains
```

**Fitness functions become concrete:**
- Blue fitness = `detection_rate * (1 - false_positive_rate) * speed`
- Red fitness = `evasion_rate * exploit_success * stealth`
- Co-evolutionary pressure: each side's fitness degrades the other's

**Hellcat already has:**
- TargetGraph (attack surface model with nodes: targets, vulns, creds, defenses)
- AttackScorer (CVSS + EPSS + chain multiplier - stealth cost)
- Proof validation gates (L1 informational -> L4 exploited with reproducibility)
- OPSEC NoiseMonitor (weighted ensemble: analyzer 35% + circuit 20% + trap 15% + rate 15% + session 15%)
- Prompt genome evolution (Pareto selection, curriculum-based)
- AttackPatternDB (cross-engagement technique outcome tracking)

**What STS adds (the blue side):**
- Detection strategy evolution (mirroring Hellcat's prompt evolution)
- Pheromone-based threat signal aggregation
- Multi-agent consensus on response actions
- Formal verification gate (Z3/Lean 4) for evolved strategies
- Knowledge-graph-grounded detection (not LLM hallucination)

---

## Agent Archetypes v2 (Refined)

### Blue Swarm Agents

| Agent | Implementation Base | Key Innovation |
|-------|-------------------|----------------|
| **Whisker** (detect) | Spider Sense fast path + Flink-style streaming | Long-running stateful stream processor on NATS. No LLM per-signal -- Rust-native embedding similarity + rule matching. LLM only for ambiguous signals. |
| **Stalker** (investigate) | Cyntra Dispatcher + workcell isolation | Spawns isolated investigation contexts (Cyntra workcells). Full HushEngine capability. Timeline reconstruction via hunt-query. |
| **Weaver** (correlate) | Cyntra Verifier + MAGMA multi-graph memory | Maintains 4 parallel graphs: temporal (attack timeline), causal (kill chain), entity (adversary infra), semantic (TTP patterns). Cross-hunt correlation. |
| **Pouncer** (respond) | Broker capability model + BFT consensus | Never acts alone. Requires 2f+1 consensus from Tom committee. Response actions go through broker (time-bounded, path-scoped, audited). |
| **Tom** (govern) | ClawdStrike policy engine + posture state machine | Sets autonomy tiers, validates receipts, manages agent lifecycle. Rotating BFT committee membership via VRF. |
| **Kitten** (evolve) | Hellcat's cognition/evolve loop + Z3 gate | Mutates detection strategies. Tests against Hellcat red swarm replays. Z3 verifies safety invariants. MemRL Q-value scoring for strategy selection. |
| **Sphinx** (memory) | Cyntra Memory + knowledge graph | Multi-scope memory (individual agent, collective swarm, world/threat landscape). MiroFish-inspired knowledge-graph grounding prevents hallucinated threats. |
| **Calico** (deception) | New -- honeypot/canary infrastructure | Deploys and manages deception assets. Coordinates with Whiskers to monitor honeypot interactions. Low-risk autonomous action. |

### Red Swarm Agents (Hellcat-based)

| Agent | Hellcat Source | Role in Arms Race |
|-------|---------------|-------------------|
| **ReconOp** | 9-phase recon pipeline | Discovers attack surface, feeds TargetGraph |
| **InjectionOp** | SQLi/cmd injection operator | Probes for injection vulnerabilities |
| **AuthOp** | Auth bypass operator | Tests authentication weaknesses |
| **EvasionOp** | Evasion classifier + strategy engine | Adapts to blue swarm detection patterns |
| **ChainOp** | ChainAnalyzer | Finds multi-step exploit chains |
| **OpsecOp** | NoiseMonitor + StealthBudget | Detects when blue swarm is watching |

---

## Key Patterns Adopted from Research

### From Cyntra: Scheduling & Orchestration

**Ready-Set + Critical Path scheduling.** Cyntra computes which tasks have satisfied dependencies, finds the critical path (longest chain weighted by effort), and packs into parallel lanes respecting resource budgets. Direct reuse for hunt prioritization.

**Speculate + Vote.** Spawn multiple agents on the same investigation, compare results, vote on consensus. Already exists in Cyntra for code quality; adapt for threat confidence.

**Memory-Informed Priority.** Cyntra's KernelMemoryBridge adjusts scheduling based on learned success/failure patterns. Direct reuse: boost priority for threat types where detection previously succeeded; deprioritize known false positive patterns.

**Sentinel Background Work.** Long-running daemons for housekeeping (prune old threats, consolidate findings, rebalance archetypes). Cyntra already has the BaseSentinel abstract class.

**Failure -> New Issue Cycle.** Failed investigation automatically creates a new tracked task with dependency edges. Self-healing investigation pipeline.

### From DeerFlow: Agent Construction

**Ordered Middleware Pipeline.** DeerFlow's 14-middleware pattern for cross-cutting concerns. Proposed STS middleware:

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

**Config-Driven Agent Assembly.** Hunt missions defined in YAML -- which archetypes participate, autonomy tiers, allowed tools, pheromone subscriptions, escalation rules. The swarm assembles from config, not code.

**Harness, Not Framework.** STS is a complete threat hunting runtime you extend, not a library of primitives you assemble. Provides isolation, transport, verification, and coordination out of the box.

**Harness/App Layer Separation.** `swarm-core` (reusable) never imports from `swarm-deployment` (environment-specific). Strict unidirectional dependency.

### From MiroFish: Knowledge Grounding

**Knowledge-Graph-Grounded Agent Personas.** Every agent's worldview derives from a structured threat knowledge graph (MITRE ATT&CK, org IOCs, historical incidents). Prevents hallucinated threats. The Sphinx archetype maintains this graph; all agents read from it.

**Tiered Memory.** Short-term (recent signals, chronological) + long-term (summarized, semantic) with periodic consolidation. Whiskers need high-fidelity short-term; Sphinx needs consolidated long-term.

**"God's-Eye View" Variable Injection.** Operators inject hypothetical conditions mid-hunt ("what if this IP is C2?") and watch the swarm reorganize. Powerful for threat modeling exercises.

**Dual-Environment Execution.** Run detection across structurally different telemetry streams (network = high-velocity/low-depth; endpoint = low-velocity/high-depth) with Weavers bridging correlations.

### From 2026 SOTA: Latest Patterns

**Hybrid Architecture (Validated).** Classical swarm mechanics for coordination (fast, O(1) per agent), LLMs for reasoning (hypothesis generation, strategy evolution). "Don't LLM the swarming." LLMs showed better convergence in learning tasks (ACO experiments) -- use them specifically in the Kitten/Evolve role.

**MAGMA Multi-Graph Memory.** Represent threat context across orthogonal semantic, temporal, causal, and entity graphs. 45.5% higher reasoning accuracy vs single-graph approaches. Direct fit for Weaver's correlation engine.

**MemRL Q-Value Retrieval.** Past hunting strategies scored by utility (not just semantic similarity). Filter by relevance, then select by learned effectiveness. Kitten's strategy selection should use this pattern.

**Flink Agents Streaming Pattern.** Long-running, stateful, event-triggered agents monitoring streams. This is the Whisker archetype's operating model -- not request-response, but continuous stream processing with state.

**BFT for AI Safety (Validated).** Treating unreliable AI agents as Byzantine nodes. Consensus mechanisms so multiple agents collectively validate decisions. System resilient to minority compromised agents. Published research (arXiv 2504.14668) directly supports the Pouncer consensus model.

**A2A Agent Cards.** Each swarm archetype could expose an Agent Card for interop with external agent systems. The pheromone protocol could be wrapped in A2A-compatible interface.

**AutoRedTeamer Dual-Agent Pattern.** Attacker + strategy proposer (analyzes latest research to discover new attack patterns). Hellcat's operators + Hellcat's evolve loop already implement this.

---

## What We're NOT Doing (Anti-Patterns)

Validated by both devil's advocate analysis and external research:

| Anti-Pattern | Source | Why Not |
|---|---|---|
| LLM per signal decision | MiroFish, DeerFlow | 300x slower than classical (validated by 2026 hybrid paper). Whiskers must be Rust-native. |
| Centralized supervisor | DeerFlow | Single point of failure, latency bottleneck, doesn't scale. Use stigmergic coordination. |
| Shared mutable state | DeerFlow | Race conditions in concurrent swarm. Use append-only pheromone trails (Spine). |
| Autonomous response without consensus | Devil's advocate | False positive cascade risk. Require BFT consensus + broker capability for all response actions. |
| Self-evolving response actions | Devil's advocate | Only evolve *detection heuristics*, not response actions. Response governed by static, verified policy. |
| Memory as LLM-summarized text | DeerFlow, MiroFish | Lossy, non-deterministic. Use Ed25519-signed receipts + structured knowledge graph. |
| Evolving without formal gate | 2026 SOTA | Every evolved strategy must pass Z3/Lean 4 before deployment. No exceptions. |

---

## Concrete Implementation Path

### Phase 0: Wire the Kernels (foundation)
- Create `swarm-team-six` crate/package in standalone/
- Define `SwarmAgent` trait and archetype configs (YAML)
- Build pheromone substrate on NATS JetStream (deposit/query/decay)
- Wire Cyntra Scheduler for hunt task prioritization
- Wire ClawdStrike guard pipeline as middleware

### Phase 1: Whisker + Stalker Pair (prove the loop)
- Implement Whisker as Flink-style streaming agent on NATS
  - Spider Sense fast path (Rust-native embedding similarity)
  - Pheromone deposit on detection
- Implement Stalker with Cyntra Dispatcher
  - Workcell isolation per investigation
  - hunt-query timeline reconstruction
  - Signed receipt on completion
- Prove: Whisker detects -> deposits pheromone -> Stalker activates -> investigates -> reports
- No LLM in Whisker. LLM in Stalker for hypothesis-driven investigation.

### Phase 2: Weaver + Tom (correlation + governance)
- Implement Weaver with MAGMA-style multi-graph
  - Temporal, causal, entity, semantic graphs
  - Cross-hunt correlation
- Implement Tom with posture state machine + BFT consensus
  - Rotating committee via VRF
  - Tiered autonomy enforcement
- Prove: multiple Whisker signals -> Weaver correlates -> Tom authorizes escalation

### Phase 3: Co-Evolutionary Arms Race (Hellcat integration)
- Wire Hellcat as the red swarm
  - Hellcat operators probe; blue Whiskers detect
  - Hellcat evasion adapts to blue detection patterns
  - Blue Kittens evolve detection to counter Hellcat evasion
- Implement Kitten with Hellcat's cognition/evolve loop
  - Prompt/strategy mutation with Pareto selection
  - Z3 verification gate before deployment
  - MemRL Q-value scoring for strategy selection
- Fitness tracking: blue detection rate vs red evasion rate over time

### Phase 4: Full Swarm (all archetypes)
- Implement Pouncer (capability-gated response)
- Implement Sphinx (multi-scope memory + knowledge graph)
- Implement Calico (deception infrastructure)
- Implement gossip mesh (SWIM + CRDTs for state sync)
- BFT consensus for response actions
- Staged evolution rollout (shadow -> canary -> production)

### Phase 5: Hardening + Certification
- AIUC-1 style security harness (342-test pattern)
- Canary integrity monitoring (detect swarm compromise)
- Red team the swarm itself
- Formal verification of swarm coordination invariants
  - "Pouncer never acts without 2/3 Tom consensus" (temporal logic)
  - "Evolution never weakens proven guard invariants" (Z3 gate)

---

## Naming (Confirmed)

| Context | Name |
|---------|------|
| Internal codename | **Swarm Team Six** |
| Product name | **ClawdStrike Ambush** |
| Community name | **The Clowder** |
| Crate prefix | `clawdstrike-swarm-*` |
| CLI subcommand | `clawdstrike hunt swarm` |
| NATS subject prefix | `swarm.*` |

Agent log format:
```
[Whisker-7a3f] anomaly: unusual egress to 185.220.101.x (sim=0.91)
[Stalker-2e1b] investigating Whisker-7a3f lead, 6h timeline
[Weaver-9c4d] correlated: H-0042 lateral movement via SSH
[Tom-0001]    consensus: 3/5 approve, authorizing Pouncer
[Pouncer-8f2a] response: block 185.220.101.0/24 (receipt 0xae3f)
[Kitten-4d1c] evolved: strategy S-0087 promoted (Z3 verified, fitness +12%)
```

---

## Open Questions (Narrowed)

1. **Language split**: Cyntra + Hellcat are Python; ClawdStrike is Rust. Whiskers MUST be Rust (performance). Does the swarm orchestration layer live in Python (reuse Cyntra) or Rust (performance)? Or a Python orchestrator dispatching Rust agents?

2. **Deployment topology**: Hellcat currently runs as a single-process kernel. Making it a NATS-connected red swarm requires refactoring its operators into independent agents. How deep is that refactor?

3. **Telemetry sources for v1**: Start with what's wired (Tetragon bridge for eBPF, Hubble bridge for network flows) or add new sources?

4. **Evolution cadence**: Kittens evolve strategies. How often? Continuous (risky), daily batch (safe but slow), triggered by red swarm evasion events (adaptive)?

5. **Sphinx backend**: In-memory graph for dev, Neo4j/KuzuDB for production? Or extend Cyntra's SQLite-based memory?

---

## Key References (Updated)

**Internal Systems:**
- ClawdStrike: Guard pipeline, Spine, delegation tokens, Spider Sense, Logos/Z3, Lean 4 spec
- Cyntra Kernel: Scheduler, Dispatcher, Verifier, Memory, Sentinels, Ralph
- Hellcat: TargetGraph, AttackPlanner, 16 Operators, OPSEC, Proof gates, Prompt evolution

**External Frameworks:**
- DeerFlow (ByteDance): Middleware pipeline, config-driven assembly, harness concept, guardrail providers
- MiroFish: Knowledge-graph grounding, tiered memory, God's-eye view injection, dual-environment execution

**2026 SOTA:**
- Hybrid swarm architecture validated: "LLM-Powered Swarms: A New Frontier?" (arXiv 2506.14496) -- classical for coordination, LLM for reasoning
- MAGMA multi-graph memory (arXiv 2601.03236) -- 45.5% higher reasoning accuracy
- MemRL Q-value retrieval (arXiv 2601.03192) -- utility-based strategy selection
- BFT for AI Safety (arXiv 2504.14668) -- Byzantine agents as threat model
- Formal verification of agent systems (arXiv 2510.14133) -- temporal logic properties
- Apache Flink Agents 0.1.0 -- streaming agent pattern
- AutoRedTeamer (NeurIPS 2025) -- lifelong attack memory
- Chimera-RL -- hash-chained forensic logging
- CrowdStrike Charlotte AI AgentWorks, Palo Alto Cortex AgentiX, Stellar Cyber Autonomous SOC
- A2A protocol (Google -> Linux Foundation), MCP (Anthropic -> AAIF)
- AIUC-1 certification standard (342-test harness)
