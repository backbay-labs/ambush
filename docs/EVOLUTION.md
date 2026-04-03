# Co-Evolutionary Arms Race

> Historical note: this document is currently a deferred research track. It is not part of the first Rust live-response milestone.

Technical reference for the co-evolutionary system in Swarm Team Six, where blue swarm detection strategies and red swarm attack techniques evolve against each other under formal verification constraints.

---

## Table of Contents

1. [Blue vs. Red: The Arms Race](#blue-vs-red-the-arms-race)
2. [What Evolves](#what-evolves)
3. [Fitness Functions](#fitness-functions)
4. [Genetic and Memetic Algorithms](#genetic-and-memetic-algorithms)
5. [Z3 Verification Gate](#z3-verification-gate)
6. [MemRL Q-Value Scoring](#memrl-q-value-scoring)
7. [Staged Deployment Pipeline](#staged-deployment-pipeline)
8. [Kitten Agent Lifecycle](#kitten-agent-lifecycle)

---

## Blue vs. Red: The Arms Race

Swarm Team Six implements a co-evolutionary system where two adversarial swarms -- blue (detection and hunting) and red (attack and evasion) -- evolve against each other. The red swarm is based on the Hellcat kernel, an autonomous red teaming system with 16 attack operators, evasion engines, OPSEC monitoring, and prompt genome evolution.

The co-evolutionary dynamic works as follows:

```
Blue Swarm (STS)                     Red Swarm (Hellcat)
=================                    ====================
Whiskers detect anomalies    <--->   Operators probe targets
Stalkers investigate leads   <--->   Evasion engine adapts
Weavers correlate signals    <--->   ChainAnalyzer finds paths
Pouncers respond             <--->   OPSEC monitors detection
Kittens evolve detection     <--->   Prompt evolution mutates TTPs
Sphinx remembers             <--->   AttackPatternDB learns
Tom governs                  <--->   StealthBudget constrains
```

Each side's improvements degrade the other's fitness. When blue Kittens evolve a detection strategy that catches a previously evasive technique, the red swarm's evasion fitness drops and its prompt evolution mechanism generates new evasion variants. When the red swarm discovers a blind spot in blue detection, that blind spot becomes selection pressure for the next generation of blue strategies.

This is not a game-theoretic equilibrium -- it is an open-ended arms race where both sides continuously improve. The purpose is not to "win" but to ensure the detection swarm is pressure-tested against realistic, adaptive adversaries rather than static threat models.

### What Hellcat Already Provides

The red swarm is not built from scratch. Hellcat brings:

| Component | Function | Reuse in Arms Race |
|---|---|---|
| **TargetGraph** | Attack surface model (targets, vulns, creds, defenses) | Defines what the blue swarm must defend |
| **AttackPlanner** | Multi-step attack chain planning | Generates the attack sequences blue must detect |
| **16 Operators** | Specialized attack agents (recon, injection, auth bypass, etc.) | Diverse attack portfolio forces diverse detection |
| **Evasion Engine** | Classifier + strategy engine that adapts to detection | Direct adversarial pressure on blue strategies |
| **OPSEC NoiseMonitor** | Weighted ensemble: analyzer 35% + circuit 20% + trap 15% + rate 15% + session 15% | Detects when blue is watching and adapts behavior |
| **StealthBudget** | Constrains red actions to maintain stealth | Prevents red from using unrealistic attack patterns |
| **Prompt Genome Evolution** | Pareto selection, curriculum-based mutation | The red side's strategy evolution mechanism |
| **AttackPatternDB** | Cross-engagement technique outcome tracking | Red's long-term memory of what works |
| **Proof Gates (L1-L4)** | Informational -> Exploited with reproducibility | Ensures red claims are validated, not hallucinated |

### What the Blue Side Adds

| Component | Function |
|---|---|
| **Detection Strategy Evolution** | Mirrors Hellcat's prompt evolution, but for detection rules |
| **Pheromone-Based Signal Aggregation** | Collective threat sensing, not individual agent decisions |
| **BFT Consensus for Responses** | Prevents single-agent false positive cascades |
| **Z3 Verification Gate** | Formal safety floor for evolved strategies |
| **Knowledge-Graph Grounding** | Prevents hallucinated threats (Sphinx + MITRE ATT&CK) |
| **MemRL Q-Value Scoring** | Utility-based strategy selection, not just fitness ranking |

---

## What Evolves

Only detection-side artifacts evolve. Response actions are governed by static, verified policy and never mutate. This is a deliberate safety constraint: evolved behavior in the detection plane is bounded by the Z3 verification gate, but evolved response actions could cause unbounded damage.

### Evolvable Artifacts

**1. Detection Strategies**

The primary unit of evolution. A detection strategy is an implementation of the `DetectionStrategy` trait (`crates/swarm-whisker/src/detector.rs`):

```rust
pub trait DetectionStrategy: Send + Sync {
    fn id(&self) -> &str;
    fn evaluate(&self, event: &TelemetryEvent) -> Vec<DetectionMatch>;
}
```

Strategies are parameterized by:
- Embedding similarity thresholds (Spider Sense cosine similarity cutoffs)
- Rule patterns (regex, YARA-like signatures, behavioral sequences)
- Temporal window sizes (how far back to correlate events)
- Feature weights (which telemetry fields to prioritize)
- Threat class mappings (which observations map to which MITRE ATT&CK tactics)

A "mutation" to a detection strategy changes one or more of these parameters. A "crossover" combines parameters from two parent strategies.

**2. Correlation Rules**

Weaver agents use multi-graph correlation across temporal, causal, entity, and semantic dimensions. The rules governing how signals are correlated -- which patterns indicate lateral movement chains, which entity relationships suggest C2 infrastructure -- are evolvable. A correlation rule is a template with configurable thresholds and edge-weight functions.

**3. Investigation Playbooks**

Stalker agents follow playbooks when investigating leads. A playbook defines: what data sources to query, in what order, what constitutes sufficient evidence, and when to escalate. Playbook parameters (query priorities, evidence thresholds, escalation triggers) evolve. The playbook structure itself does not.

**4. Pheromone Parameters**

While the core pheromone mechanics (exponential decay, source diversity) are fixed, per-threat-class tuning parameters can evolve:
- Decay half-life overrides for specific threat classes
- Confidence calibration (mapping raw detection scores to deposit confidence)
- Severity classification boundaries

These are subject to the Z3 gate like all other evolved artifacts.

### What Does NOT Evolve

| Artifact | Reason |
|---|---|
| Response actions (block, isolate, revoke) | Unbounded damage potential. Governed by static, human-authored policy. |
| Consensus protocol parameters | Safety-critical. BFT guarantees depend on fixed thresholds. |
| Cryptographic operations | Must remain deterministic and formally verified. |
| Agent identity and trust model | Trust decisions require consensus, not automated evolution. |
| Guard pipeline policy | Static ClawdStrike policy. Guards are the safety floor that constrains evolved behavior. |

---

## Fitness Functions

Strategy fitness is evaluated as a multi-objective function. The swarm does not optimize for a single metric; it maintains a Pareto front of strategies that trade off between detection quality, speed, and resource cost.

### Blue Fitness Function

```
F_blue = w_d * detection_rate
       * (1 - w_f * false_positive_rate)
       * w_s * speed_score
       * w_c * coverage_score
```

Where:

| Component | Symbol | Definition | Weight (default) |
|---|---|---|---|
| Detection rate | `detection_rate` | Fraction of known-bad events correctly identified (true positives / total positives) | `w_d = 0.40` |
| False positive rate | `false_positive_rate` | Fraction of benign events incorrectly flagged (false positives / total negatives) | `w_f = 0.30` |
| Speed score | `speed_score` | Normalized inverse of detection latency. `1.0` if detection occurs within the Whisker's microsecond budget; degrades toward `0.0` as latency increases. | `w_s = 0.15` |
| Coverage score | `coverage_score` | Fraction of MITRE ATT&CK technique IDs covered by the strategy's threat class mappings. A strategy that only detects lateral movement scores lower than one that also catches C2 and exfiltration. | `w_c = 0.15` |

The multiplicative structure means a strategy that is excellent at detection but has a high false positive rate is penalized severely. This is intentional: false positives in a response-capable swarm can trigger consensus votes for unnecessary actions, wasting committee time and potentially causing disruption.

### Red Fitness Function

```
F_red = w_e * evasion_rate
      * w_x * exploit_success_rate
      * w_t * stealth_score
```

Where:

| Component | Symbol | Definition | Weight (default) |
|---|---|---|---|
| Evasion rate | `evasion_rate` | Fraction of attack actions that did not trigger blue detection | `w_e = 0.40` |
| Exploit success rate | `exploit_success_rate` | Fraction of attack chains that reached their objective (based on Hellcat proof gates L1-L4) | `w_x = 0.35` |
| Stealth score | `stealth_score` | Derived from Hellcat's OPSEC NoiseMonitor. A weighted ensemble: analyzer 35% + circuit 20% + trap 15% + rate 15% + session 15%. Higher is stealthier. | `w_t = 0.25` |

### Co-Evolutionary Pressure

The key dynamic: each side's fitness is measured **against the current best of the other side**. Specifically:

- Blue `detection_rate` is measured against the current generation of red attack replays, not a static test corpus.
- Red `evasion_rate` is measured against the current generation of blue detection strategies, not a static detector.

This means fitness values are not absolute -- a strategy with fitness 0.85 in generation N might have fitness 0.72 in generation N+1 if the opposing side has improved. Absolute fitness can decrease even as capability increases, which is the hallmark of a productive arms race.

### Fitness Evaluation Protocol

1. The Kitten agent selects a candidate strategy (mutation or crossover of existing strategies).
2. The strategy is evaluated against a **replay corpus**: a set of recorded telemetry streams containing both benign activity and red swarm attack sequences from the most recent Hellcat campaign.
3. The replay is deterministic (same inputs, same ordering) to ensure reproducible fitness scores.
4. The four fitness components are computed from the replay results.
5. The composite fitness score is recorded along with the strategy's parameters and lineage (parent strategies, mutation applied).

---

## Genetic and Memetic Algorithms

Strategy evolution uses a hybrid genetic/memetic algorithm. The genetic component handles population-level selection and recombination. The memetic component allows individual strategies to be locally refined before fitness evaluation.

### Population Structure

The Kitten agent maintains a population of candidate strategies. Population size is bounded by the `max_count` for Kitten agents in the mission configuration (default: 2 Kitten agents, each maintaining its own population).

Each strategy in the population is represented as a **genome**: a vector of parameters that fully specify the strategy's behavior. The genome includes:

- Numerical parameters (thresholds, weights, window sizes) as floating-point genes
- Categorical parameters (threat class mappings, rule selections) as discrete genes
- Structural parameters (which rules are active, rule ordering) as permutation genes

### Selection: Pareto Tournament

Because fitness is multi-objective, selection uses Pareto dominance rather than scalar ranking. Strategy A dominates strategy B if A is at least as good as B on all fitness components and strictly better on at least one.

The selection procedure:
1. Randomly sample a tournament of `k` strategies from the population (default `k = 4`).
2. Identify the non-dominated strategies in the tournament (the Pareto front within the sample).
3. Select one strategy from the Pareto front uniformly at random.

This preserves diversity: strategies that are excellent at detection but slow, or fast but with lower coverage, can survive alongside balanced strategies.

### Mutation

Mutation operates on individual genes in the genome:

| Gene Type | Mutation Operator |
|---|---|
| Floating-point (thresholds, weights) | Gaussian perturbation: `gene += N(0, sigma)`, where `sigma` decays over generations |
| Discrete (threat class mappings) | Uniform random swap: replace with a randomly chosen valid value |
| Permutation (rule ordering) | Adjacent swap: swap two neighboring elements in the permutation |
| Structural (rule activation) | Bit flip: activate an inactive rule or deactivate an active one |

Mutation rate is adaptive. When the population's fitness diversity is low (convergence), mutation rate increases to explore new regions. When diversity is high, mutation rate decreases to exploit known-good regions.

### Crossover

Crossover combines two parent strategies to produce offspring:

| Crossover Type | Description |
|---|---|
| Single-point | Split both parents at a random point; child gets the first segment from parent A and the second from parent B |
| Uniform | Each gene is independently drawn from parent A or parent B with 50% probability |
| Arithmetic (for floats) | Child gene = `alpha * parent_A_gene + (1 - alpha) * parent_B_gene` where `alpha` is uniform in [0, 1] |

Crossover probability is configurable but defaults to 0.7 (70% of offspring are crossovers; 30% are pure mutations of a single parent).

### Memetic Local Search

After mutation/crossover produces a candidate, a local search phase refines it before fitness evaluation:

1. Evaluate the candidate's fitness on a small, fast subset of the replay corpus (the "validation split").
2. Attempt `m` local perturbations (default `m = 5`) to individual genes.
3. If a perturbation improves validation fitness, accept it. Otherwise, revert.
4. The refined candidate is then evaluated on the full replay corpus for official fitness scoring.

This memetic step accelerates convergence without reducing exploration, because the genetic operators maintain population diversity while local search sharpens individual strategies.

### Elitism

The top `e` strategies (default `e = 2`) from each generation survive unconditionally into the next generation. This ensures that the best-known strategies are never lost due to random selection. Elites can still be outcompeted in subsequent generations if better strategies emerge.

---

## Z3 Verification Gate

Every evolved detection strategy must pass through a formal verification gate before deployment. The gate uses Z3 (via the `clawdstrike-logos` crate's compilation and verification infrastructure) to prove that the strategy satisfies a set of safety invariants.

This is the critical safety mechanism that separates evolution from unconstrained self-modification. The swarm can mutate freely, but only provably safe mutations reach production.

### Safety Invariants

The Z3 gate checks a set of invariants that define the **safety floor** -- the minimum guarantees any deployed strategy must provide:

**I1: No regression on known-bad indicators.**

```
forall indicator in KNOWN_BAD_SET:
    strategy.evaluate(indicator) produces at least one DetectionMatch
```

The strategy must detect all indicators in the canonical known-bad set (maintained by Sphinx in the knowledge graph). An evolved strategy that develops a blind spot to known threats is rejected.

**I2: No self-suppression.**

```
forall threat_class in ThreatClass:
    exists event_template in CANONICAL_TEMPLATES[threat_class]:
        strategy.evaluate(event_template).threat_class == threat_class
```

The strategy must be capable of detecting at least one canonical example of every threat class it claims to cover. This prevents evolutionary drift where a strategy technically covers a threat class but its thresholds are set so high that nothing ever matches.

**I3: False positive bound.**

```
let fp_rate = count(strategy.evaluate(BENIGN_CORPUS) produces match) / |BENIGN_CORPUS|
fp_rate <= MAX_FP_RATE
```

The strategy's false positive rate on the canonical benign corpus must not exceed a configurable maximum (default: 5%). This is a hard gate, not a soft fitness penalty.

**I4: Pheromone parameter bounds.**

```
forall param in strategy.pheromone_overrides:
    param.decay_half_life >= MIN_HALF_LIFE
    param.confidence >= 0.0 AND param.confidence <= 1.0
```

Evolved pheromone parameter overrides must stay within sane bounds. A strategy cannot set a decay half-life of zero (which would make all its pheromones instantly evaporate) or a confidence above 1.0 (which would allow it to dominate concentration).

**I5: Resource budget compliance.**

```
strategy.estimated_latency_per_event <= WHISKER_LATENCY_BUDGET
strategy.estimated_memory <= WHISKER_MEMORY_BUDGET
```

The strategy must fit within the Whisker's resource budget. Microsecond-per-event latency is not negotiable. An evolved strategy that is more accurate but 10x slower is rejected -- it would degrade the streaming detection pipeline.

### Verification Process

1. The Kitten serializes the candidate strategy's parameters into a logical formula using the `clawdstrike-logos` compilation layer (the same infrastructure used for ClawdStrike policy verification).
2. Each safety invariant is encoded as a Z3 assertion.
3. Z3 checks satisfiability of the negation (i.e., searches for a counterexample that violates the invariant).
4. If Z3 finds a counterexample for any invariant, the strategy is **rejected** with a proof of violation (the counterexample).
5. If Z3 proves no counterexample exists (UNSAT on the negation), the strategy **passes** and is eligible for staged deployment.
6. If Z3 times out (inconclusive), the strategy is **rejected**. This is fail-closed: inability to prove safety is treated as a safety failure.

### Invariant Evolution

The invariants themselves do not evolve. They are authored by human operators and represent non-negotiable safety properties. However, the **known-bad set** and **canonical templates** referenced by the invariants are maintained by Sphinx and updated as the threat landscape changes. New threats discovered by the swarm are added to the known-bad set, raising the bar for future strategy generations.

---

## MemRL Q-Value Scoring

Beyond the multi-objective fitness function, the Kitten uses MemRL (Memory-augmented Reinforcement Learning) Q-value scoring for strategy selection at deployment time. This addresses a gap in pure genetic fitness: two strategies may have similar fitness on the replay corpus but very different real-world performance due to environmental factors the replay does not capture.

### How It Works

MemRL scores strategies by their historical utility in production, not just their performance on replays.

1. **Memory store**: Every time a detection strategy produces a true positive, false positive, true negative, or false negative in production, the outcome is recorded with the strategy ID, the event context, and the swarm mode at the time.

2. **Q-value computation**: For a candidate strategy `s` being considered for deployment in context `c`:

```
Q(s, c) = sum over relevant_memories m:
    relevance(m, c) * outcome_reward(m) * recency_decay(m)
```

Where:
- `relevance(m, c)` is the semantic similarity between the memory's context and the current deployment context (e.g., same threat class, similar network topology).
- `outcome_reward(m)` is `+1` for true positives, `-1` for false positives, `+0.1` for true negatives, `-0.5` for false negatives. The asymmetric rewards reflect the cost structure: false negatives (missed threats) are worse than false positives (unnecessary alerts), but false positives are still penalized.
- `recency_decay(m)` is an exponential decay based on memory age, so recent outcomes weigh more than old ones. This allows the Q-value to adapt as the threat landscape shifts.

3. **Selection**: When multiple Z3-verified strategies are available for the same detection role, the Kitten selects the one with the highest Q-value for the current context. If no production memories exist (new strategy), the Q-value defaults to the replay fitness, providing a smooth transition from evolution to production.

### MemRL vs. Pure Fitness

| Criterion | Genetic Fitness | MemRL Q-Value |
|---|---|---|
| Data source | Replay corpus (historical, curated) | Production outcomes (live, noisy) |
| Adaptation speed | Generational (minutes to hours) | Per-event (seconds) |
| Context sensitivity | None (same fitness regardless of deployment context) | Context-aware (different Q-values for different environments) |
| Cold start | Full fitness from first evaluation | Defaults to replay fitness, improves over time |
| Failure mode | Overfitting to replay corpus | Recency bias (mitigated by decay floor) |

The two systems complement each other: genetic fitness drives long-term capability improvement; MemRL Q-values drive short-term deployment decisions.

---

## Staged Deployment Pipeline

An evolved strategy that passes the Z3 gate does not immediately enter production. It proceeds through a three-stage pipeline that progressively increases exposure.

### Pipeline Stages

```
Z3 Gate --> Shadow --> Canary --> Production
```

**Stage 1: Shadow**

The strategy runs in parallel with the production strategy but does not produce pheromone deposits. Its outputs are recorded for comparison.

- Duration: configurable, default 1 hour
- Exit criteria: shadow fitness >= production fitness * 0.95 (the shadow strategy must be within 5% of production performance)
- Failure mode: if the shadow strategy produces significantly more false positives or misses significantly more threats than production, it is rolled back to the Kitten population for further evolution

Shadow mode has zero risk: the strategy cannot influence swarm behavior, consensus decisions, or pheromone concentration.

**Stage 2: Canary**

The strategy is deployed to a subset of Whisker agents (default: 1 Whisker out of the active population). It produces real pheromone deposits, but only from the canary Whisker.

- Duration: configurable, default 4 hours
- Exit criteria: canary Whisker's detection metrics are within acceptable bounds, no anomalous false positive spikes, no resource budget violations
- Failure mode: if the canary Whisker's metrics diverge from the fleet, the strategy is rolled back and the canary Whisker reverts to the previous production strategy

Canary mode has bounded risk: at most one Whisker is affected, and source diversity enforcement means a single canary cannot trigger mode transitions alone.

**Stage 3: Production**

The strategy is deployed to all Whisker agents running the detection role it covers. The previous production strategy is retained as a fallback.

- Rollback: if production metrics degrade within a configurable observation window (default: 24 hours), the strategy is automatically rolled back to the previous version
- The strategy enters the MemRL memory store and begins accumulating Q-value data from production outcomes

### Deployment as Consensus Decision

Promotion from canary to production is an **evolution commit** that requires BFT consensus from the Tom committee (see [CONSENSUS.md](./CONSENSUS.md)). The Kitten agent proposes the promotion with:

- The strategy's genome and parameters
- Z3 verification proof (the proof that all safety invariants hold)
- Shadow performance comparison (fitness vs. production baseline)
- Canary performance metrics (detection rate, false positive rate, latency, resource usage)

The Tom committee evaluates this evidence and votes. If consensus is reached, the strategy is promoted. If not, it remains in canary or is rolled back.

This consensus gate prevents a compromised Kitten from pushing a blind-spot strategy to production. Even if the Kitten fabricates fitness metrics, the Tom committee can independently verify the Z3 proof and compare canary metrics against the fleet baseline.

---

## Kitten Agent Lifecycle

The Kitten is the agent archetype responsible for strategy evolution. It operates at Tier 2 (autonomous with reporting) for strategy proposal and evaluation, but requires Tier 3 (consensus) for production deployment.

### Lifecycle Phases

```
Observe --> Mutate --> Evaluate --> Verify --> Propose --> Deploy
  ^                                                        |
  +------ feedback from production MemRL Q-values ---------+
```

**1. Observe**

The Kitten monitors:
- Current production strategy fitness (via MemRL Q-values and real-time metrics)
- Red swarm evasion events (Hellcat operators that evaded blue detection)
- Pheromone concentration patterns (which threat classes are saturated, which are underserved)
- Swarm mode transitions (was the swarm slow to escalate? did it over-escalate?)

This observation phase identifies **selection pressure**: which aspects of detection need improvement.

**2. Mutate**

Based on observed pressure, the Kitten applies genetic operators:
- If red evasion increased for a specific threat class, increase mutation focus on that class's detection parameters
- If false positives spiked, apply mutations that tighten thresholds
- If coverage gaps are identified, activate dormant rules via structural mutation
- Apply crossover between high-performing strategies from different threat class specializations

**3. Evaluate**

Run the candidate strategy against the replay corpus:
- Compute multi-objective fitness (detection rate, false positive rate, speed, coverage)
- Compare against the current production strategy baseline
- Rank within the population using Pareto dominance

**4. Verify**

Submit the candidate to the Z3 verification gate:
- Encode strategy parameters as logical formulae
- Check all safety invariants (I1-I5)
- If any invariant fails, the strategy is returned to the population for further mutation
- If Z3 times out, the strategy is rejected (fail-closed)

**5. Propose**

If the strategy passes Z3 verification and its fitness exceeds the production baseline:
- The Kitten emits a `ProposeStrategy` swarm action:
  ```rust
  ProposeStrategy {
      strategy_id: String,
      strategy: serde_json::Value,  // serialized genome
      fitness: f64,                  // composite fitness score
  }
  ```
- This action is published to the pheromone substrate for Tom committee review
- The strategy enters the shadow stage of the deployment pipeline

**6. Deploy**

Progression through shadow -> canary -> production, as described in [Staged Deployment Pipeline](#staged-deployment-pipeline). At each stage transition, the Kitten monitors performance and can initiate rollback if metrics degrade.

### Evolution Cadence

Evolution is **triggered**, not continuous or batched. The Kitten activates when:

- A red swarm evasion event is detected (Hellcat evaded blue detection)
- MemRL Q-values for the current production strategy drop below a threshold
- A new threat pattern is added to the knowledge graph (Sphinx updates)
- A Tom agent explicitly requests strategy review (manual trigger)
- A configurable time interval has elapsed since the last evolution cycle (fallback, ensures periodic refresh)

This adaptive cadence means evolution runs frequently when under adversarial pressure and infrequently when the current strategies are performing well. It avoids both the risk of continuous mutation and the staleness of fixed-interval batches.

### Agent Population and Specialization

Multiple Kitten agents can operate simultaneously (default `max_count: 2`). When multiple Kittens are active, they specialize by threat class:

- Kitten-A focuses on evolving detection strategies for network-layer threats (C2, exfiltration, lateral movement)
- Kitten-B focuses on evolving strategies for host-layer threats (privilege escalation, persistence, credential access)

Specialization is dynamic: Kittens claim threat classes via the pheromone substrate (similar to how Stalkers claim investigations). This prevents duplication of effort and ensures all threat classes receive evolutionary pressure.

### Failure and Recovery

| Failure Mode | Recovery |
|---|---|
| Kitten crashes mid-evolution | Population state is persisted to JetStream. A replacement Kitten resumes from the last checkpoint. |
| Z3 gate rejects all candidates | The Kitten widens mutation parameters (increase sigma) and introduces random immigrants (fresh random strategies) to escape local optima. |
| Shadow stage fails repeatedly | The Kitten flags the replay corpus as potentially stale and requests Sphinx to update it with recent telemetry. |
| Canary stage causes false positive spike | Automatic rollback. The strategy is returned to the population with a fitness penalty proportional to the spike severity. |
| Red swarm overwhelms blue detection | Emergency mode: all Kittens activate regardless of specialization, mutation rate is maximized, shadow stage duration is shortened. |
