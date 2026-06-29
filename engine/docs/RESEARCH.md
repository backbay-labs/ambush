# Ambush Engine: Research Synthesis

> Comprehensive findings from two waves of research agents, consolidated as the project's research foundation.

---

## 1. Autonomous Threat Hunting Landscape

### 1.1 DARPA CHASE

The Cyber Hunting at Scale (CHASE) program (2020-2023) was the first large-scale government initiative to prove that autonomous threat hunting is technically feasible. CHASE funded research into automated hypothesis generation, evidence collection, and kill-chain reconstruction across enterprise networks. Key outcomes included demonstrating that AI-driven hunters could surface threats that human SOC analysts missed during triage, particularly low-and-slow lateral movement campaigns. CHASE validated two principles that Ambush Engine adopts: (1) autonomous hunting works best as a complement to human analysts, not a replacement, and (2) hypothesis-driven hunting outperforms alert-driven triage for advanced persistent threats.

### 1.2 Commercial XDR/EDR Platforms

**CrowdStrike OverWatch** represents the current commercial ceiling for managed threat hunting. OverWatch pairs human hunters with the Falcon platform's endpoint telemetry and Charlotte AI's LLM-powered triage. It is effective but fundamentally centralized -- a single detection brain, a single evasion strategy for adversaries to study. CrowdStrike's July 2024 incident (8.5 million machines bricked by a single centralized content update) demonstrated the catastrophic fragility of centralized push models.

**Microsoft Sentinel** provides cloud-native SIEM/SOAR with KQL-based hunting queries and Fusion ML for multi-stage attack detection. Sentinel excels at log aggregation and correlation at cloud scale but relies on predefined analytics rules and playbooks. It has no autonomous hypothesis generation and no mechanism for self-evolving detection logic.

**Elastic Security** offers open detection rules (1,200+ as of 2026) and an extensible agent framework. Its strength is transparency -- detection logic is version-controlled and community-auditable. However, Elastic's detection model is fundamentally reactive: rules are written after threats are characterized. There is no adversarial pressure driving rule evolution.

### 1.3 Academic Provenance and Detection Systems

**HOLMES** (Milajerdi et al., IEEE S&P 2019) introduced real-time APT detection through provenance graph analysis. HOLMES maps audit logs to a high-level scenario graph based on the kill chain, enabling detection of multi-stage attacks that span hours or days. The system demonstrated that provenance graphs are a viable substrate for automated kill-chain reconstruction -- a pattern directly applicable to Ambush Engine's Weaver archetype.

**ATLAS** (Alsaheel et al., USENIX Security 2021) extended provenance-based detection by incorporating sequence-based models to identify APT attack stages from audit logs. ATLAS demonstrated that learning temporal patterns in system-call-level provenance data could detect novel attack variants that signature-based systems miss.

**SHADEWATCHER** (Zengy et al., IEEE S&P 2022) applied graph neural networks to system audit logs for threat detection, showing that GNN-based approaches to provenance graphs outperform both rule-based and sequence-based methods on detection accuracy. SHADEWATCHER's insight -- that structural patterns in provenance graphs carry detection signal -- informs Ambush Engine's multi-graph correlation design.

**NODOZE** (Hassan et al., NDSS 2019) addressed alert fatigue by scoring the contextual relevance of threat alerts using provenance graphs. NODOZE reduces false positives by computing anomaly scores based on data flow dependencies, demonstrating that graph-aware triage dramatically outperforms flat alert ranking.

### 1.4 The Gap Ambush Engine Fills

The current landscape has a clear stratification:

| Layer | State of the Art | What Is Missing |
|-------|-----------------|-----------------|
| SIEM | Passive log aggregation (Splunk, Elastic) | No autonomous hunting |
| SOAR | Playbook automation (XSOAR, Swimlane) | Rigid; no hypothesis generation |
| XDR | Endpoint telemetry + ML (CrowdStrike, SentinelOne) | Centralized brain; single evasion strategy |
| AI-native | LLM wrappers on alerts | No formal governance; no audit trail |
| Academic | Provenance-graph detection (HOLMES, ATLAS) | Research prototypes; not production swarms |

The category "formally-verified autonomous threat hunting" is empty. No existing system combines multi-agent coordination, cryptographic auditability, self-evolving detection, and formal safety guarantees. DARPA CHASE proved the concept. The provenance systems proved kill-chain reconstruction works. The swarm intelligence literature proves multi-agent coordination outperforms single-detector systems for novel threats. But nobody has assembled the full stack. Ambush Engine occupies this gap.

---

## 2. Swarm Intelligence in Cybersecurity

### 2.1 Classical Swarm Optimization for IDS

The application of swarm intelligence to intrusion detection has a two-decade history, dominated by using swarm algorithms as optimizers rather than coordination models.

**Ant Colony Optimization (ACO) for IDS.** Banerjee et al. (2005) and subsequent work applied ACO to feature selection for network intrusion detection, using artificial ant trails to identify optimal subsets of network flow features. Ramos and Abraham (2005) proposed AntNet-based IDS where digital ants traverse network graphs, depositing pheromones on paths that correlate with anomalous traffic. These systems demonstrated that pheromone-based signal accumulation naturally handles the "many weak signals" problem in threat detection, but they used swarm metaphors only for optimization -- the actual detection remained a single centralized classifier.

**Particle Swarm Optimization (PSO) for IDS.** Aburomman and Ibne Reaz (2017) used PSO to optimize ensemble classifier parameters for intrusion detection. PSO-IDS systems consistently outperform single classifiers on benchmark datasets (KDD Cup 99, NSL-KDD), but like ACO approaches, they use swarm intelligence as a training-time optimizer, not as a runtime coordination mechanism.

**The common limitation:** Nearly all prior work treats swarm intelligence as a function optimizer applied to a static detection problem. The swarm runs during training to find good parameters, then a conventional classifier runs at inference time. Ambush Engine inverts this: the swarm IS the runtime system. Agents coordinate through stigmergy during live threat hunting, not during offline training.

### 2.2 Multi-Agent Security Systems

**MAIDS (Multi-Agent Intrusion Detection System)** frameworks (Herrero et al., 2009) proposed distributing detection across cooperating agents, each monitoring a network segment. These systems demonstrated that distributed detection reduces single points of failure and improves coverage, but they used simple message-passing (not stigmergy) and had no mechanism for evolving detection strategies.

**AAFID (Autonomous Agents for Intrusion Detection)** (Balasubramaniyan et al., 1998) was one of the earliest proposals for autonomous agent-based IDS, introducing the concept of mobile detection agents that traverse network hosts. AAFID established the principle that autonomous agents can provide detection coverage that centralized systems cannot, particularly in large, heterogeneous networks.

### 2.3 NATO AICA Reference Architecture

Kott et al. (2019) published the NATO reference architecture for Autonomous Intelligent Cyber-defense Agents (AICA). The AICA architecture defines five functional components: sensing, planning, action, collaboration, and learning. The collaboration component specifies that agents must coordinate without relying on centralized command, operating in contested environments where communication may be degraded or adversary-controlled. AICA's threat model -- agents operating in environments where the adversary controls the infrastructure -- directly motivates Ambush Engine's BFT consensus and Ed25519-signed communication. The AICA reference architecture validates the design principle that cyber-defense agents must be Byzantine-fault-tolerant by default.

### 2.4 Why Prior Work Falls Short

Most prior swarm-security work uses biological metaphors for mathematical optimization, not for runtime coordination. The actual systems are conventional classifiers with swarm-optimized parameters. Ambush Engine departs from this tradition by implementing swarm behavior at runtime:

- **Stigmergy** (pheromone trails) for asynchronous threat signal accumulation
- **Quorum sensing** for adaptive swarm mode transitions
- **BFT consensus** for critical response decisions
- **Role plasticity** for dynamic agent specialization

This is swarm intelligence as an architecture, not as a training algorithm.

---

## 3. Self-Evolving Detection

### 3.1 Concept Drift in Malware Detection

**TESSERACT** (Pendlebury et al., USENIX Security 2019) demonstrated that machine learning malware classifiers degrade dramatically under temporal concept drift -- the natural evolution of both malware and benign software over time. TESSERACT showed that standard evaluation practices (random train/test splits) overestimate real-world performance by 20-40 percentage points. The paper established that any ML-based detection system must explicitly account for temporal drift, either through periodic retraining or online adaptation.

**Transcend** (Jordaney et al., USENIX Security 2017) proposed conformal evaluation to detect when a deployed malware classifier has drifted out of its competence region. Transcend provides a statistical signal that triggers retraining, rather than relying on scheduled updates. Ambush Engine adopts this principle: the Kitten evolution engine activates based on detected drift (blue detection rate declining, red evasion rate increasing), not on a fixed schedule.

**Arp et al., "Dos and Don'ts of Machine Learning in Computer Security"** (USENIX Security 2022) provided a comprehensive survey of pitfalls in applying ML to security, including temporal bias, spatial bias, and label bias. The paper's recommendation -- that ML security systems must be evaluated under realistic temporal conditions with concept drift -- shapes Ambush Engine's requirement that evolved detection strategies are tested against temporally ordered historical data, never randomly shuffled.

### 3.2 Automated Rule Generation

**YARA-Forge** and the broader YARA ecosystem represent the most mature automated signature generation pipeline. YARA rules are handwritten by analysts, but tools like yarGen (Roth, 2015) automate generation from malware samples by extracting distinctive string sets and byte patterns. The limitation is that YARA generation is reactive -- rules are created after samples are obtained.

**Sigma** is a generic signature format for SIEM systems with 3,000+ community-contributed rules as of 2026. Sigma's strength is cross-platform portability (rules compile to Splunk SPL, Elastic KQL, Microsoft KQL, etc.). The Sigma ecosystem demonstrates that standardized rule formats enable collaborative evolution, but rule creation remains manual.

**DeTT&CT** provides coverage scoring against MITRE ATT&CK, enabling quantitative measurement of detection gaps. Ambush Engine uses the DeTT&CT pattern: evolved detection strategies are scored against ATT&CK coverage to ensure evolution fills real gaps rather than over-fitting to observed traffic.

### 3.3 Genetic Algorithms for Signature Evolution

Genetic algorithms (GA) and genetic programming (GP) have been applied to evolve IDS rules since the early 2000s (Lu and Bhargava, 2004). Crosbie and Spafford (1995) proposed using GP to evolve agent detection programs. More recently, Kayacik et al. (2011) used GP to evolve Snort rules from network traffic. These approaches demonstrate that evolutionary computation can produce effective detection rules, but they lack:

1. **Adversarial pressure** -- rules evolve against static datasets, not against an adapting adversary
2. **Safety guarantees** -- evolved rules are not formally verified before deployment
3. **Multi-objective fitness** -- most work optimizes detection rate alone, ignoring false positive cost

Ambush Engine addresses all three: the co-evolutionary arms race with Hellcat provides adversarial pressure, the Z3/Lean 4 verification gate provides safety guarantees, and the multi-objective fitness function balances detection rate, false positive rate, detection speed, resource efficiency, and evasion resistance.

### 3.4 What Works in Practice vs. Theory

The practical state of self-evolving detection is sobering. Most academic systems demonstrate evolution on benchmark datasets but are never deployed. The systems that work in production (YARA-Forge, Sigma, Elastic detection-rules) use human-in-the-loop evolution with community review. The gap between theory (fully autonomous evolution) and practice (human-curated rule updates) is large.

Ambush Engine bridges this gap through staged deployment: autonomous evolution in shadow mode, formal verification gates, canary deployment, and quorum consensus for promotion. The swarm evolves freely in the Kitten sandbox; only verified, tested, consensus-approved strategies reach production.

---

## 4. External Framework Analysis

### 4.1 DeerFlow (ByteDance)

DeerFlow is ByteDance's open-source multi-agent framework for research and content workflows. Its architecture reveals patterns directly applicable to Ambush Engine.

**Ordered Middleware Pipeline.** DeerFlow implements a 14-middleware pipeline for cross-cutting concerns (auth, rate limiting, logging, etc.) that every agent invocation traverses. This pattern separates agent logic from infrastructure concerns. Ambush Engine adopts a 9-middleware pipeline:

1. IdentityVerification (Ed25519 delegation token validation)
2. TierAuthorization (autonomy level enforcement)
3. PheromoneInjection (load relevant NATS pheromone trails)
4. ContextCompression (token-aware summarization for LLM-using agents)
5. GuardPipeline (Ambush Engine guard evaluation)
6. ToolBoundary (action-specific access control)
7. ConsensusGate (BFT gate for response actions)
8. EvidenceCollection (receipt signing, audit trail)
9. EvolutionTracking (strategy mutation logging)

**Config-Driven Agent Assembly.** DeerFlow agents are assembled from YAML configuration specifying tools, models, and behaviors. Ambush Engine adopts this for hunt missions -- YAML defines which archetypes participate, autonomy tiers, allowed tools, pheromone subscriptions, and escalation rules. The swarm assembles from config, not code.

**Harness, Not Framework.** DeerFlow positions itself as a complete runtime, not a library of primitives. Ambush Engine follows this: `swarm-core` is a reusable swarm runtime that provides isolation, transport, verification, and coordination out of the box.

**What to Avoid from DeerFlow.** DeerFlow uses a centralized supervisor pattern (a "coordinator" agent that delegates to specialists). This creates a single point of failure and a latency bottleneck. Ambush Engine explicitly avoids centralized supervision in favor of stigmergic coordination. DeerFlow also uses shared mutable state between agents, which creates race conditions in concurrent systems. Ambush Engine uses append-only pheromone trails (via Spine) to avoid shared mutable state entirely.

### 4.2 MiroFish

MiroFish is a knowledge-graph-grounded multi-agent system designed for complex reasoning tasks. Its architecture offers three key lessons.

**Knowledge-Graph-Grounded Agent Personas.** MiroFish grounds every agent's worldview in a structured knowledge graph, preventing hallucinated reasoning. For Ambush Engine, this means every agent's threat model derives from structured data -- MITRE ATT&CK technique graphs, organizational IOC databases, historical incident records -- not from LLM-generated speculation. The Sphinx archetype maintains this graph; all agents read from it. This is the single most important architectural lesson from MiroFish: agents grounded in knowledge graphs produce dramatically fewer false positives than agents reasoning from unstructured context.

**Tiered Memory.** MiroFish implements short-term memory (recent events, chronological, high-fidelity) and long-term memory (summarized, semantic, consolidated). Periodic consolidation moves short-term signals into durable knowledge. Ambush Engine maps this directly: Whisker agents need high-fidelity short-term memory for recent telemetry signals; the Sphinx archetype maintains consolidated long-term threat intelligence.

**"God's-Eye View" Variable Injection.** MiroFish allows operators to inject hypothetical conditions into the agent system mid-execution and observe how agents reorganize. For Ambush Engine, this enables threat modeling exercises: an operator injects "assume this IP is C2" and watches the swarm reorganize around the hypothesis. This is a powerful capability for proactive threat hunting.

**Dual-Environment Execution.** MiroFish supports running agents across structurally different data environments. For Ambush Engine, this maps to processing structurally different telemetry streams -- network flows (high-velocity, low-depth) and endpoint events (low-velocity, high-depth) -- with Weaver agents bridging cross-environment correlations.

---

## 5. 2026 State of the Art

### 5.1 LLM-Powered Swarms

**"LLM-Powered Swarms: A New Frontier?"** (arXiv 2506.14496, 2025) validated the hybrid architecture that Ambush Engine adopts: classical algorithms for swarm coordination (fast, O(1) per agent, deterministic), LLMs for reasoning tasks (hypothesis generation, strategy evolution, natural language analysis). The paper demonstrated that using LLMs for per-signal swarm decisions is approximately 300x slower than classical approaches with no accuracy improvement for coordination tasks. However, LLMs showed superior convergence in learning tasks (ACO experiments), confirming their value specifically in the Kitten/Evolve role. The paper's central conclusion -- "don't LLM the swarming" -- is a foundational design principle for Ambush Engine.

### 5.2 Agent Memory Systems

**MAGMA (Multi-Annotated Graph Memory Architecture)** (arXiv 2601.03236, 2026) represents agent context across four orthogonal graph types: temporal, causal, entity, and semantic. MAGMA demonstrated 45.5% higher reasoning accuracy compared to single-graph approaches on complex multi-step tasks. Ambush Engine adopts this directly for the Weaver archetype's correlation engine, maintaining four parallel graphs: temporal (attack timeline), causal (kill chain), entity (adversary infrastructure), and semantic (TTP patterns). Cross-graph queries enable the kind of multi-dimensional correlation that single-graph provenance systems like HOLMES cannot achieve.

**MemRL (Memory-augmented Reinforcement Learning)** (arXiv 2601.03192, 2026) introduced Q-value-based retrieval for agent memory: past strategies are scored by utility (actual outcome effectiveness), not just semantic similarity to the current context. When selecting which past strategy to apply, MemRL filters by relevance and then ranks by learned effectiveness. Ambush Engine applies this pattern in the Kitten evolution engine: candidate detection strategies are scored not just by similarity to the current threat landscape but by their historical effectiveness, as measured by detection rate and false positive rate across prior deployments.

**Mem0** provides production-ready memory patterns for AI agents, including hierarchical memory stores, automatic consolidation, and retrieval optimization. Mem0's architecture validates the tiered memory model that Ambush Engine implements through the Sphinx archetype.

### 5.3 Agent Protocols and Standards

**A2A (Agent-to-Agent Protocol).** Originally proposed by Google and subsequently donated to the Linux Foundation, A2A defines standard Agent Cards and inter-agent communication patterns. Each Ambush Engine swarm archetype could expose an A2A Agent Card for interoperability with external agent systems. The pheromone protocol could be wrapped in an A2A-compatible interface, enabling integration with external SOC agent ecosystems.

**MCP (Model Context Protocol).** Developed by Anthropic and contributed to the AAIF (AI Agent Interoperability Foundation), MCP standardizes tool interfaces for AI agents. Ambush Engine already has an MCP adapter (`ambush-engine-claude`); Ambush Engine agents inherit this interface for tool access.

**AAIF Governance Standards.** The AI Agent Interoperability Foundation is developing governance frameworks for autonomous agent systems, including certification standards. The AIUC-1 standard defines a 342-test certification harness for agent safety, directly applicable to Ambush Engine Phase 5 hardening.

### 5.4 Formal Verification of Agent Systems

**Formal Verification Properties for Agent Systems** (arXiv 2510.14133) defines temporal logic properties that multi-agent systems should satisfy, including safety (agents never perform unauthorized actions), liveness (the system eventually makes progress), and fairness (all agents get service). Ambush Engine maps these directly:

- Safety: "Pouncer never acts without 2/3 Tom consensus" (expressible in temporal logic, verifiable by Z3)
- Liveness: "Every Whisker detection eventually receives a Stalker investigation"
- Fairness: "Agent role rotation ensures no agent is permanently excluded from evolution proposals"

**BFT for AI Safety** (arXiv 2504.14668) formalized the treatment of unreliable AI agents as Byzantine nodes in a distributed system. The paper demonstrated that standard BFT consensus mechanisms (Tendermint-style) can be applied to multi-agent AI systems, providing resilience against minority compromised or malfunctioning agents. This directly supports Ambush Engine's Pouncer consensus model: response actions require 2f+1 agreement from a rotating Tom committee, ensuring that no single compromised agent can trigger autonomous response.

**Leanstral** (Mistral, 2026) is Mistral's Lean 4 formal verification agent, demonstrating that LLM-assisted formal verification is practical for production systems. Ambush Engine already maintains a Lean 4 specification with 35+ theorem statements and differential tests. Ambush Engine extends this verification infrastructure to cover swarm coordination invariants.

### 5.5 Streaming Agent Patterns

**Apache Flink Agents 0.1.0** introduced the streaming agent pattern: long-running, stateful, event-triggered agents that monitor data streams continuously rather than operating in request-response mode. This is the operational model for Ambush Engine's Whisker archetype -- Whisker agents are persistent stream processors on NATS JetStream subjects, maintaining windowed state (recent signal history, pheromone concentrations) and emitting detections when anomaly thresholds are crossed. The Flink Agents pattern validates that stateful streaming is the correct execution model for high-throughput detection agents, not the request-response model used by most LLM agent frameworks.

### 5.6 Agentic SOC Platforms

The 2026 security vendor landscape has converged on "agentic SOC" as a product category:

**CrowdStrike Charlotte AI AgentWorks** layers LLM-powered triage agents on top of the Falcon platform. Charlotte AI can summarize alerts, suggest investigation paths, and draft response playbooks. However, Charlotte AI operates as a centralized reasoning layer, not as a distributed swarm. It lacks formal verification, has no self-evolving detection, and provides no cryptographic audit trail for AI decisions.

**Palo Alto Cortex AgentiX** integrates AI agents into the Cortex XSIAM platform for automated triage and response. AgentiX uses a supervisor-worker pattern with a central orchestrator dispatching tasks to specialist agents. Like Charlotte AI, it is centralized and lacks formal governance.

**Stellar Cyber Autonomous SOC** provides AI-driven detection and response across a unified data lake. Stellar Cyber's "Open XDR" approach aggregates signals from multiple sources but uses centralized ML models for detection, not distributed agents.

**AutoRedTeamer** (NeurIPS 2025) introduced the dual-agent pattern for automated red teaming: an attacker agent generates exploits while a strategy proposer agent analyzes the latest attack research to discover new attack patterns. This pattern is already implemented in Hellcat's operator + evolve loop architecture.

**Chimera-RL** proposed hash-chained forensic logging for AI agent actions, ensuring that agent decision histories are tamper-evident. Ambush Engine inherits this property from Ambush Engine's Spine envelope system, which provides Merkle-tree-anchored audit trails for all swarm actions.

The common limitation across all commercial agentic SOC platforms: none combines autonomous hunting, self-evolving detection, formal verification, and cryptographic audit trails. They are LLM-powered triage layers on conventional detection stacks.

---

## 6. Internal System Analysis

### 6.1 Ambush Engine

Ambush Engine is a runtime security enforcement system for AI agents, providing policy-driven security checks at the tool boundary. Ambush Engine reuses approximately 90% of Ambush Engine's infrastructure directly.

**Guard Pipeline.** 13 built-in guards organized in a 3-stage evaluation pipeline (BuiltIn -> Custom -> Extra -> Async). The pipeline evaluates actions through ForbiddenPathGuard, PathAllowlistGuard, EgressAllowlistGuard, SecretLeakGuard, PatchIntegrityGuard, ShellCommandGuard, McpToolGuard, PromptInjectionGuard, JailbreakGuard, ComputerUseGuard, RemoteDesktopSideChannelGuard, InputInjectionCapabilityGuard, and SpiderSenseGuard. For Ambush Engine, this pipeline becomes the threat scoring pipeline: fast-path detection through Spider Sense, deep investigation through the full guard stack.

**Spider Sense.** Hierarchical threat screening implementing the approach of Yu et al. (2026): embedding-based cosine similarity for fast-path screening, with an optional LLM deep path for ambiguous signals. Spider Sense is the direct implementation base for the Whisker archetype. Its "ambiguous band" -- signals that are neither clearly benign nor clearly malicious -- is precisely the zone where swarm coordination adds value over single-detector systems.

**Spine Transport.** Signed envelopes over NATS JetStream with Merkle proof anchoring. Spine provides the pheromone substrate: agents deposit threat indicators as signed envelopes on NATS subjects, creating an append-only, cryptographically verifiable pheromone trail. The existing NATS subject hierarchy extends naturally to swarm subjects (`swarm.pheromone.*`, `swarm.gossip.*`, `swarm.consensus.*`).

**Delegation Tokens.** Ed25519-based capability tokens with attenuation -- a parent agent can issue sub-capabilities that are strictly less powerful than its own. This provides the Sybil resistance and capability scoping that swarm agents need: a Tom governance agent issues time-bounded, role-scoped delegation tokens to Stalker and Pouncer agents.

**Posture System.** A state machine for agent operating modes with budget awareness. The posture system maps directly to swarm mode transitions (Normal -> Alert -> Incident) and agent role switching.

**Broker Subsystem.** The brokered egress tier (hushd -> brokerd -> upstream API) ensures that agents never touch raw credentials. For Ambush Engine, broker capabilities gate Pouncer response actions: time-bounded, path-scoped, audited access to response infrastructure.

**Formal Verification Stack.** Logos (Z3 policy-to-formula compilation with 69 tests), Lean 4 specification (2,988 lines, 35+ theorem statements, `lake build` passes), and differential tests (43 proptest-based tests comparing Lean spec vs. Rust implementation). This is the safety floor for evolved strategies: every detection strategy the Kitten engine proposes must pass Z3 verification before deployment, ensuring it does not weaken proven policy invariants.

**Correlation Context.** W3C traceparent-based correlation IDs enable tracing hunts across autonomous agents, providing end-to-end visibility from initial Whisker detection through Stalker investigation to Pouncer response.

### 6.2 Cyntra

Cyntra is the Python-based scheduling, dispatching, and verification kernel used for AI agent orchestration. Ambush Engine reuses approximately 80% of Cyntra's infrastructure.

**Scheduler.** Ready-Set + Critical Path scheduling: Cyntra computes which tasks have satisfied dependencies, finds the critical path (longest chain weighted by effort), and packs tasks into parallel lanes respecting resource budgets. For Ambush Engine, this drives hunt task prioritization -- when multiple Whisker detections compete for Stalker investigation resources, the scheduler allocates based on threat severity, pheromone concentration, and critical path through the investigation graph.

**Dispatcher.** Workcell-based task isolation: each dispatched task runs in an isolated context with defined inputs, outputs, and resource limits. For Ambush Engine, each Stalker investigation runs in an isolated workcell, preventing cross-investigation contamination and enabling independent timeout/retry policies.

**Verifier.** Speculate + Vote pattern: spawn multiple agents on the same task, compare results, vote on consensus. Cyntra uses this for code quality; Ambush Engine adapts it for threat confidence -- multiple Stalkers independently investigate the same lead, and their findings are compared to establish confidence scores.

**StateManager / Memory.** KernelMemoryBridge adjusts scheduling based on learned success/failure patterns. For Ambush Engine: boost priority for threat types where detection previously succeeded; deprioritize known false positive patterns. Cyntra's memory system provides the foundation for the Sphinx archetype's multi-scope memory.

**Sentinels.** Long-running background daemons based on the BaseSentinel abstract class. For Ambush Engine, sentinels handle housekeeping: pruning decayed pheromones, consolidating findings, rebalancing archetype populations, monitoring swarm health metrics.

**Ralph (Loop Control).** Cyntra's main control loop, managing the sense-plan-act cycle. For Ambush Engine, Ralph's loop structure informs the swarm's tick cycle: each agent's `tick()` method follows the same sense (read environment) -> plan (decide action) -> act (execute) -> learn (update memory) cycle.

**Event System.** Cyntra's event bus for inter-component communication. For Ambush Engine, this maps to NATS subjects for swarm events, with Cyntra's event types extended to cover swarm-specific events (pheromone deposit, role transition, consensus request).

### 6.3 Hellcat

Hellcat is the autonomous red teaming kernel -- the adversarial other half of the co-evolutionary arms race. Ambush Engine reuses approximately 70% of Hellcat as the red swarm.

**TargetGraph.** An attack surface model with typed nodes (targets, vulnerabilities, credentials, defenses) and weighted edges (reachability, exploitability). For Ambush Engine, TargetGraph provides the adversary's view of the network that the blue swarm must learn to defend. The red swarm's TargetGraph evolves as it discovers new attack paths; the blue swarm must evolve detection to cover them.

**AttackPlanner + AttackScorer.** CVSS + EPSS scoring with chain multipliers and stealth cost penalties. The AttackPlanner generates multi-step attack plans; the AttackScorer evaluates their expected value considering detection risk. For Ambush Engine, this scoring function is one half of the co-evolutionary fitness: red fitness = evasion_rate * exploit_success * stealth.

**16 Operators.** Specialized attack agents covering reconnaissance (9-phase pipeline), SQL injection, command injection, authentication bypass, privilege escalation, lateral movement, and more. Each operator encapsulates domain-specific attack expertise. For Ambush Engine, these operators become the red swarm agents that probe blue swarm defenses.

**OPSEC / NoiseMonitor.** A weighted ensemble (analyzer 35% + circuit breaker 20% + trap detector 15% + rate limiter 15% + session monitor 15%) that tracks how much "noise" the red team is generating and adjusts attack aggressiveness accordingly. This is the red swarm's awareness of blue swarm detection -- when NoiseMonitor detects increased blue attention, the red swarm shifts to stealthier tactics.

**Proof Validation Gates.** Four-level proof system (L1 informational -> L2 demonstrable -> L3 validated -> L4 exploited with reproducibility). For Ambush Engine, proof gates ensure that the red swarm's claimed evasions are genuine, preventing the co-evolutionary fitness function from being gamed by unverified claims.

**Prompt Evolution.** Pareto selection over a genome of attack prompts, with curriculum-based progression from simple to complex attacks. For Ambush Engine, this is the template for blue swarm evolution: detection strategies are represented as mutable genomes, evolved through Pareto selection, with curriculum progression from known to novel threats.

**AttackPatternDB.** Cross-engagement technique outcome tracking: which attack patterns succeeded against which defenses under which conditions. For Ambush Engine, this is the red swarm's institutional memory, mirrored by the blue swarm's Sphinx archetype maintaining defense outcome tracking.

**Evasion Engine.** Adapts attack strategies based on observed detection patterns. For Ambush Engine, the evasion engine is the adversarial pressure that forces blue swarm detection to continuously improve -- any detection strategy that the evasion engine can consistently bypass has low fitness.

The key insight from Hellcat analysis: **the co-evolutionary arms race already has one side built.** Hellcat IS the red swarm. Ambush Engine is the blue swarm. They co-evolve against each other. This transforms what was a theoretical design in Brainstorm v1 into a concrete implementation plan.

---

## 7. Key References

### Autonomous Threat Hunting

- DARPA CHASE (Cyber Hunting at Scale) Program, 2020-2023. Defense Advanced Research Projects Agency.
- Milajerdi, S. M., Gjomemo, R., Eshete, B., Sekar, R., and Venkatakrishnan, V. N. "HOLMES: Real-Time APT Detection through Correlation of Suspicious Information Flows." IEEE Symposium on Security and Privacy (S&P), 2019.
- Alsaheel, A., Nan, Y., Ma, S., Yu, L., Walkup, G., Celik, Z. B., Zhang, X., and Xu, D. "ATLAS: A Sequence-based Learning Approach for Attack Investigation." USENIX Security Symposium, 2021.
- Zengy, J., Wang, X., Liu, J., Chen, Y., Liang, Z., Chua, T.-S., and Cai, Z. "SHADEWATCHER: Recommendation-guided Cyber Threat Analysis using System Audit Records." IEEE Symposium on Security and Privacy (S&P), 2022.
- Hassan, W. U., Guo, S., Li, D., Chen, Z., Jee, K., Li, Z., and Bates, A. "NODOZE: Combatting Threat Alert Fatigue with Automated Provenance Triage." Network and Distributed System Security Symposium (NDSS), 2019.

### Swarm Intelligence

- Bonabeau, E., Dorigo, M., and Theraulaz, G. *Swarm Intelligence: From Natural to Artificial Systems.* Oxford University Press, 1999.
- Dorigo, M. and Stutzle, T. *Ant Colony Optimization.* MIT Press, 2004.
- Kott, A., Stump, T., Manso, M., Mancini, F., Theron, P., and Kamhoua, C. "Autonomous Intelligent Cyber-defense Agent (AICA) Reference Architecture." NATO IST-152 Technical Report, 2019.
- Ramos, V. and Abraham, A. "ANTIDS: Self Organized Ant-Based Clustering Model for Intrusion Detection System." Soft Computing as Transdisciplinary Science and Technology, Springer, 2005.
- Banerjee, S., Grosan, C., and Abraham, A. "IDEAS: Intrusion Detection Based on Emotional Ants." International Conference on Intelligent Systems Design and Applications, 2005.
- Aburomman, A. A. and Ibne Reaz, M. B. "A Survey of Intrusion Detection Systems Based on Ensemble and Hybrid Classifiers." Computers & Security, 2017.

### Multi-Agent Security

- Herrero, A., Corchado, E., Pellicer, M. A., and Abraham, A. "MOVIH-IDS: A Mobile-Visualization Hybrid Intrusion Detection System." Neurocomputing, 2009.
- Balasubramaniyan, J. S., Garcia-Fernandez, J. O., Isacoff, D., Spafford, E. H., and Zamboni, D. "An Architecture for Intrusion Detection Using Autonomous Agents." Annual Computer Security Applications Conference (ACSAC), 1998.

### Concept Drift and Adversarial ML

- Pendlebury, F., Pierazzi, F., Jordaney, R., Kinder, J., and Cavallaro, L. "TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time." USENIX Security Symposium, 2019.
- Jordaney, R., Sharad, K., Dash, S. K., Wang, Z., Papini, D., Nouretdinov, I., and Cavallaro, L. "Transcend: Detecting Concept Drift in Malware Classification Models." USENIX Security Symposium, 2017.
- Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Wressnegger, C., Cavallaro, L., and Rieck, K. "Dos and Don'ts of Machine Learning in Computer Security." USENIX Security Symposium, 2022.

### Evolutionary Detection

- Lu, W. and Bhargava, B. "Implementing Intrusion Detection Using Genetic Algorithms." Technical Report, Purdue University, 2004.
- Crosbie, M. and Spafford, E. H. "Applying Genetic Programming to Intrusion Detection." AAAI Fall Symposium on Genetic Programming, 1995.
- Kayacik, H. G., Zincir-Heywood, A. N., and Heywood, M. I. "On Evolving Buffer Overflow Attacks Using Genetic Programming." Genetic and Evolutionary Computation Conference (GECCO), 2011.
- Roth, F. "yarGen -- YARA Rule Generator." GitHub, 2015.

### Detection Rule Ecosystems

- MITRE ATT&CK Framework. https://attack.mitre.org/
- MITRE CALDERA. Automated Adversary Emulation. https://caldera.mitre.org/
- Sigma Rules. Generic Signature Format for SIEM Systems. https://github.com/SigmaHQ/sigma (~3,000+ rules as of 2026)
- Elastic Detection Rules. https://github.com/elastic/detection-rules (1,200+ rules as of 2026)
- DeTT&CT: Detect Tactics, Techniques & Combat Threats. https://github.com/rabobank-cdc/DeTTECT

### 2026 LLM-Powered Agents and Swarms

- "LLM-Powered Swarms: A New Frontier?" arXiv 2506.14496, 2025. (Hybrid classical-LLM swarm architecture validation.)
- MAGMA: Multi-Annotated Graph Memory Architecture. arXiv 2601.03236, 2026. (Multi-graph agent memory, 45.5% reasoning accuracy improvement.)
- MemRL: Memory-augmented Reinforcement Learning for Agent Memory. arXiv 2601.03192, 2026. (Q-value-based utility retrieval for strategy selection.)
- "BFT for AI Safety: Byzantine Fault Tolerance Mechanisms for Multi-Agent AI Systems." arXiv 2504.14668, 2025. (Byzantine agents as threat model for AI consensus.)
- "Formal Verification Properties for Agent Systems." arXiv 2510.14133, 2025. (Temporal logic properties: safety, liveness, fairness.)
- Apache Flink Agents 0.1.0, 2026. (Streaming agent pattern: long-running, stateful, event-triggered.)
- AutoRedTeamer. NeurIPS, 2025. (Dual-agent automated red teaming with lifelong attack memory.)
- Chimera-RL. 2026. (Hash-chained forensic logging for AI agent actions.)
- Mem0. Production memory patterns for AI agents. https://mem0.ai/

### Agent Protocols and Standards

- A2A (Agent-to-Agent Protocol). Google, donated to Linux Foundation, 2025-2026.
- MCP (Model Context Protocol). Anthropic, contributed to AAIF, 2025-2026.
- AAIF (AI Agent Interoperability Foundation). Governance frameworks and certification standards.
- AIUC-1. Agent certification standard, 342-test safety harness.

### Commercial Agentic SOC

- CrowdStrike Charlotte AI AgentWorks. CrowdStrike, 2025-2026.
- Palo Alto Cortex AgentiX. Palo Alto Networks, 2026.
- Stellar Cyber Autonomous SOC. Stellar Cyber, 2025-2026.

### External Frameworks

- DeerFlow. ByteDance. Open-source multi-agent research framework. https://github.com/bytedance/deer-flow
- MiroFish. Knowledge-graph-grounded multi-agent system.

### Formal Verification

- Leanstral. Mistral, 2026. Lean 4 formal verification agent.
- Yu, J. et al. "Hierarchical Threat Screening." 2026. (Spider Sense embedding-based cosine similarity approach.)

### Internal Systems

- Ambush Engine. Guard pipeline, Spider Sense, Spine transport, delegation tokens, broker subsystem, Logos/Z3, Lean 4 specification. `/Users/connor/Medica/backbay/standalone/ambush-engine/`
- Cyntra Kernel. Scheduler, Dispatcher, Verifier, Memory, Sentinels, Ralph. `/Users/connor/Medica/backbay/platform/kernel/`
- Hellcat. TargetGraph, AttackPlanner, 16 Operators, OPSEC/NoiseMonitor, Proof gates, Prompt evolution, AttackPatternDB, Evasion engine.
