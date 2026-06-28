# Pheromone Substrate

Technical reference for the pheromone-based stigmergic coordination layer in Swarm Team Six.

---

## Table of Contents

1. [Overview: Why Stigmergy](#overview-why-stigmergy)
2. [PheromoneDeposit Type](#pheromonedeposit-type)
3. [Exponential Decay Model](#exponential-decay-model)
4. [Concentration Computation](#concentration-computation)
5. [Source Diversity Enforcement](#source-diversity-enforcement)
6. [NATS Subject Hierarchy](#nats-subject-hierarchy)
7. [Evaporation and Garbage Collection](#evaporation-and-garbage-collection)
8. [Quorum Sensing and Mode Transitions](#quorum-sensing-and-mode-transitions)
9. [Security Model](#security-model)
10. [Configuration Reference](#configuration-reference)

---

## Overview: Why Stigmergy

Traditional multi-agent coordination relies on a centralized supervisor that receives all signals, decides what to do, and dispatches tasks. This creates three problems for an autonomous threat hunting swarm:

1. **Single point of failure.** If the supervisor is compromised or crashes, the entire swarm is blind.
2. **Latency bottleneck.** Every signal must round-trip through the supervisor before agents can react.
3. **Scaling wall.** The supervisor must process O(N) messages from N agents, becoming the throughput ceiling.

Stigmergy -- indirect coordination through environmental modification -- eliminates all three. Agents deposit **pheromones** (signed threat indicators) into a shared substrate. Other agents sense the concentration of pheromones and adjust their behavior accordingly. There is no central coordinator. The substrate is the coordination mechanism.

This is the same pattern used by ant colonies: individual ants deposit chemical trails on the ground; other ants follow trails with higher concentration. No ant knows the global plan. The global behavior emerges from local interactions with the shared environment.

In Swarm Team Six, the substrate is backed by NATS JetStream. Pheromones are append-only, cryptographically signed, and subject to exponential decay. The swarm's collective threat picture emerges from the concentration gradients across threat classes, not from any single agent's view.

### Properties of Stigmergic Coordination

| Property | Centralized Supervisor | Pheromone Substrate |
|---|---|---|
| Failure mode | Total loss of coordination | Graceful degradation (individual agents still deposit/sense) |
| Latency | O(2) round-trips through supervisor | O(1) local pub/sub |
| Throughput | Bounded by supervisor capacity | Bounded by NATS cluster throughput |
| State | Mutable, race-prone | Append-only, conflict-free |
| Trust | Implicit (supervisor is trusted) | Explicit (deposits are Ed25519-signed) |

---

## PheromoneDeposit Type

The fundamental unit of stigmergic communication is the `PheromoneDeposit`, defined in `crates/swarm-core/src/pheromone.rs`:

```rust
pub struct PheromoneDeposit {
    pub indicator: serde_json::Value,
    pub threat_class: ThreatClass,
    pub severity: Severity,
    pub confidence: f64,
    pub timestamp: i64,
    pub decay_half_life: f64,
    pub agent_id: AgentId,
    pub signature: Vec<u8>,
    pub agent_key: Vec<u8>,
}
```

### Field Reference

| Field | Type | Description |
|---|---|---|
| `indicator` | `serde_json::Value` | The raw observable -- an IP address, a file hash, a process tree, a network flow, or any structured JSON payload that describes what was observed. |
| `threat_class` | `ThreatClass` | MITRE ATT&CK-aligned classification. One of: `LateralMovement`, `DataExfiltration`, `PrivilegeEscalation`, `CommandAndControl`, `InitialAccess`, `Persistence`, `DefenseEvasion`, `CredentialAccess`, `Discovery`, `Execution`, `Impact`, or `Custom(String)`. |
| `severity` | `Severity` | Ordered severity level: `Low < Medium < High < Critical`. |
| `confidence` | `f64` | The depositing agent's confidence in this signal, in the range [0.0, 1.0]. This is the initial strength of the pheromone before decay. |
| `timestamp` | `i64` | Unix timestamp (seconds) of when the deposit was made. Used as the decay origin. |
| `decay_half_life` | `f64` | Half-life in seconds controlling how quickly this pheromone evaporates. A deposit with `decay_half_life = 3600.0` retains 50% of its strength after one hour. |
| `agent_id` | `AgentId` | Identity of the depositing agent, formatted as `{role}-{short_id}` (e.g., `Whisker-7a3f`). |
| `signature` | `Vec<u8>` | Ed25519 signature over the canonical (RFC 8785 JCS) serialization of the deposit content (all fields except `signature` itself). |
| `agent_key` | `Vec<u8>` | The agent's Ed25519 public key, allowing any reader to verify the signature without a key lookup. |

### ThreatClass Taxonomy

The `ThreatClass` enum is aligned with MITRE ATT&CK tactics. The `Custom(String)` variant allows extension for organization-specific threat categories without modifying the core type.

```rust
pub enum ThreatClass {
    LateralMovement,
    DataExfiltration,
    PrivilegeEscalation,
    CommandAndControl,
    InitialAccess,
    Persistence,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    Execution,
    Impact,
    Custom(String),
}
```

---

## Exponential Decay Model

Pheromones are not permanent. They evaporate over time following an exponential decay curve, modeling the decreasing relevance of a threat signal as time passes. An anomaly observed five minutes ago is far more actionable than one observed five hours ago.

### Formula

```
strength(t) = confidence * 0.5^((t - timestamp) / half_life)
```

Where:
- `confidence` is the initial deposit strength (the agent's confidence in the signal)
- `t` is the current time (unix seconds)
- `timestamp` is the deposit time
- `half_life` is the configured decay half-life in seconds

This is standard radioactive decay applied to threat signals. The confidence value is the initial amplitude; the half-life controls how quickly the signal fades.

### Implementation

From `PheromoneDeposit::strength_at`:

```rust
pub fn strength_at(&self, now: i64) -> f64 {
    if now <= self.timestamp {
        return self.confidence;
    }
    let elapsed = (now - self.timestamp) as f64;
    self.confidence * (0.5_f64).powf(elapsed / self.decay_half_life)
}
```

If the query time is at or before the deposit time (clock skew or same-instant query), the full confidence value is returned without decay.

### Worked Examples

**Example 1: High-confidence signal, default half-life**

A Whisker deposits a lateral movement indicator with `confidence = 0.95` and `decay_half_life = 3600.0` (1 hour).

| Time elapsed | Effective strength | Computation |
|---|---|---|
| 0 minutes | 0.950 | `0.95 * 0.5^(0/3600) = 0.95` |
| 30 minutes | 0.672 | `0.95 * 0.5^(1800/3600) = 0.95 * 0.707` |
| 1 hour | 0.475 | `0.95 * 0.5^(3600/3600) = 0.95 * 0.5` |
| 2 hours | 0.238 | `0.95 * 0.5^(7200/3600) = 0.95 * 0.25` |
| 4 hours | 0.059 | `0.95 * 0.5^(14400/3600) = 0.95 * 0.0625` |
| ~6.6 hours | 0.010 | Reaches default evaporation threshold |

**Example 2: Low-confidence signal, short half-life**

A Whisker deposits an ambiguous discovery indicator with `confidence = 0.4` and `decay_half_life = 600.0` (10 minutes).

| Time elapsed | Effective strength | Computation |
|---|---|---|
| 0 minutes | 0.400 | `0.4 * 0.5^(0/600)` |
| 10 minutes | 0.200 | `0.4 * 0.5^(600/600) = 0.4 * 0.5` |
| 20 minutes | 0.100 | `0.4 * 0.5^(1200/600) = 0.4 * 0.25` |
| ~52 minutes | 0.010 | Reaches evaporation threshold |

The short half-life means low-confidence signals evaporate quickly. This is intentional: weak signals should not accumulate noise in the substrate indefinitely.

### Design Rationale

Exponential decay was chosen over linear decay or fixed TTL for three reasons:

1. **Smooth degradation.** Pheromone concentration decreases continuously, not in discrete steps. This produces smoother mode transitions in quorum sensing.
2. **Configurable urgency.** High-severity threats can use shorter half-lives to force rapid escalation if corroborated, or longer half-lives for threats that develop slowly (e.g., data exfiltration over days).
3. **Self-cleaning.** The asymptotic approach to zero, combined with a garbage collection threshold, means the substrate automatically purges stale data without explicit cleanup logic.

---

## Concentration Computation

Individual pheromone deposits are aggregated into `PheromoneConcentration` values per threat class. This is the metric that drives swarm behavior.

```rust
pub struct PheromoneConcentration {
    pub threat_class: ThreatClass,
    pub total_strength: f64,
    pub distinct_sources: usize,
    pub peak_confidence: f64,
}
```

| Field | Description |
|---|---|
| `total_strength` | Sum of `strength_at(now)` for all non-evaporated deposits of this threat class. |
| `distinct_sources` | Count of unique `agent_id` values contributing to the sum. |
| `peak_confidence` | The highest individual `confidence` value among contributing deposits (before decay). |

### Aggregation Algorithm

To compute concentration for a given `ThreatClass` at time `now`:

1. Retrieve all `PheromoneDeposit` records matching the threat class from the NATS JetStream-backed store.
2. For each deposit, compute `strength_at(now)`.
3. Discard deposits where `strength_at(now) < evaporation_threshold`.
4. Sum the remaining strengths into `total_strength`.
5. Count distinct `agent_id` values into `distinct_sources`.
6. Track the maximum `confidence` value into `peak_confidence`.

This is a time-windowed aggregation. No explicit time window parameter is needed because the decay function itself handles temporal relevance -- old deposits contribute negligible strength.

---

## Source Diversity Enforcement

A single compromised or malfunctioning agent could flood the substrate with high-confidence deposits to artificially inflate concentration. Source diversity enforcement prevents this.

The `PheromoneConcentration::exceeds_threshold` method requires **both** a minimum total strength **and** a minimum number of distinct contributing agents:

```rust
pub fn exceeds_threshold(&self, strength_threshold: f64, min_sources: usize) -> bool {
    self.total_strength >= strength_threshold && self.distinct_sources >= min_sources
}
```

With the default configuration (`min_sources_for_escalation: 2`), a single agent can never trigger a mode transition regardless of how many deposits it makes or how high its confidence is. At least two independent agents must corroborate a threat class for escalation to occur.

This is a direct countermeasure against Byzantine agents. Even if one agent in the swarm is compromised and deposits fabricated signals, it cannot single-handedly drive the swarm into incident mode.

### Example

Suppose three Whiskers independently detect lateral movement:

| Agent | Confidence | Time elapsed | Effective strength |
|---|---|---|---|
| Whisker-7a3f | 0.92 | 5 min | 0.911 |
| Whisker-2b1c | 0.88 | 2 min | 0.876 |
| Whisker-9d4e | 0.75 | 10 min | 0.741 |

Concentration: `total_strength = 2.528`, `distinct_sources = 3`, `peak_confidence = 0.92`.

With `alert_threshold = 2.0` and `min_sources_for_escalation = 2`:
- `2.528 >= 2.0` -- strength threshold met
- `3 >= 2` -- source diversity met
- Result: alert mode transition triggered

If only Whisker-7a3f had deposited all three signals (total_strength still 2.528), the distinct_sources would be 1, and the threshold check would fail.

---

## NATS Subject Hierarchy

Pheromone deposits are published and subscribed via a structured NATS subject hierarchy. The prefix is configurable (default: `swarm`).

```
swarm.pheromone.{threat_class}.{severity}
```

### Subject Examples

| Subject | Meaning |
|---|---|
| `swarm.pheromone.lateral_movement.HIGH` | High-severity lateral movement indicator |
| `swarm.pheromone.data_exfiltration.CRITICAL` | Critical data exfiltration indicator |
| `swarm.pheromone.command_and_control.MEDIUM` | Medium-severity C2 indicator |
| `swarm.pheromone.custom.apt_group_x.LOW` | Custom threat class, low severity |

### Subscription Patterns

NATS wildcard subscriptions allow agents to scope their awareness:

| Pattern | Who Uses It | Purpose |
|---|---|---|
| `swarm.pheromone.>` | Tom (governance) | Monitor all pheromone activity for posture decisions |
| `swarm.pheromone.*.CRITICAL` | Pouncer (response) | React to any critical-severity signal |
| `swarm.pheromone.lateral_movement.*` | Stalker (investigation) | Investigate all lateral movement regardless of severity |
| `swarm.pheromone.data_exfiltration.>` | Weaver (correlation) | Correlate exfiltration signals across severities |

### JetStream Persistence

The pheromone stream (`swarm-pheromones` by default) is a NATS JetStream stream providing:

- **Persistence.** Deposits survive agent restarts and network partitions.
- **Replay.** New agents joining the swarm can replay recent deposits to build an initial concentration picture.
- **Ordering.** JetStream provides per-subject ordering guarantees, so deposits are processed in causal order within a threat class.
- **Retention.** The stream uses a time-based retention policy aligned with the maximum practical deposit lifetime (several multiples of the configured half-life).

---

## Evaporation and Garbage Collection

Pheromones naturally approach zero strength via exponential decay, but they never mathematically reach zero. The `evaporation_threshold` configuration parameter defines the floor below which a pheromone is considered fully evaporated.

```rust
pub fn is_evaporated(&self, now: i64, threshold: f64) -> bool {
    self.strength_at(now) < threshold
}
```

### Garbage Collection

The substrate periodically runs a garbage collection pass that removes deposits with `strength_at(now) < evaporation_threshold`. The planned substrate API:

```
gc_evaporated(threshold: f64) -> usize  // returns count of deposits removed
```

With the default configuration (`evaporation_threshold = 0.01`, `default_half_life_secs = 3600`):

- A deposit with `confidence = 1.0` evaporates after approximately 6.64 hours (`log2(1.0/0.01) * 3600 = 6.64 * 3600 = 23,900 seconds`).
- A deposit with `confidence = 0.5` evaporates after approximately 5.64 hours.
- A deposit with `confidence = 0.1` evaporates after approximately 3.32 hours.

Lower-confidence deposits evaporate faster, which naturally biases the substrate toward high-confidence, corroborated signals.

### GC Frequency

Garbage collection does not need to be frequent. Because concentration computation already filters by effective strength, evaporated deposits contribute nothing to aggregation -- they are just inert storage. GC is a storage optimization, not a correctness requirement. Running it every few minutes is sufficient.

---

## Quorum Sensing and Mode Transitions

The swarm operates in one of three modes, defined in `crates/swarm-core/src/agent.rs`:

```rust
pub enum SwarmMode {
    Normal,    // Routine patrol
    Alert,     // Elevated threat signals
    Incident,  // Active threat confirmed
}
```

Mode transitions are driven by **quorum sensing** -- the aggregate pheromone concentration across the substrate. This is analogous to bacterial quorum sensing, where individual bacteria release autoinducer molecules and the collective concentration triggers gene expression changes when a threshold is reached.

### Transition Thresholds

From `PheromoneConfig`:

| Transition | Strength Threshold | Source Diversity Required |
|---|---|---|
| Normal -> Alert | `alert_threshold` (default: 2.0) | `min_sources_for_escalation` (default: 2) |
| Alert -> Incident | `incident_threshold` (default: 5.0) | `min_sources_for_escalation` (default: 2) |

Both conditions (strength AND source diversity) must be satisfied for a transition. See [Source Diversity Enforcement](#source-diversity-enforcement).

### What Changes in Each Mode

| Mode | Whisker Behavior | Stalker Behavior | Pouncer Behavior | Tom Behavior |
|---|---|---|---|---|
| **Normal** | Standard sampling rate. Broad threat class coverage. | Idle or investigating cold leads. | Locked (no response actions). | Routine policy enforcement. |
| **Alert** | Increased sampling rate. Focused on elevated threat classes. | Activated on high-concentration leads. | Standby (can pre-stage responses). | Evaluates whether to authorize escalation. |
| **Incident** | Maximum sampling. All resources on active threat classes. | All hands investigating. | Unlocked. Executes consensus-approved response actions. | Convenes BFT consensus for response decisions. |

### Transition Hysteresis

The transition from a higher mode back to a lower mode requires the concentration to drop below the lower threshold, not merely below the upper threshold. This prevents oscillation when concentration hovers near a boundary.

Example: Once in Incident mode (triggered at 5.0), the swarm does not drop back to Alert until concentration falls below 2.0 (the alert threshold). If concentration is between 2.0 and 5.0, the swarm remains in whichever mode it was already in.

### Scenario Walkthrough

1. **T+0 min**: Swarm in Normal mode. No significant pheromone concentration.
2. **T+2 min**: Whisker-7a3f detects unusual SSH tunneling to an external IP. Deposits a `CommandAndControl` pheromone with `confidence = 0.85`. Concentration: 0.85, sources: 1. No transition (source diversity not met).
3. **T+4 min**: Whisker-2b1c independently detects DNS beaconing to the same IP range. Deposits a `CommandAndControl` pheromone with `confidence = 0.90`. Concentration: ~1.74, sources: 2. Source diversity met, but strength below `alert_threshold` (2.0). No transition.
4. **T+6 min**: Whisker-9d4e detects a new SSH tunnel variant. Deposits `CommandAndControl` with `confidence = 0.80`. Concentration: ~2.50, sources: 3. Both thresholds exceeded. **Transition: Normal -> Alert.**
5. **T+8 min**: Alert mode. Stalkers activate and begin investigating the C2 indicators.
6. **T+15 min**: Stalker-2e1b confirms C2 channel and discovers lateral movement. Deposits `LateralMovement` with `confidence = 0.95`. Whiskers increase sampling. Additional C2 and lateral movement pheromones accumulate. Combined concentration across threat classes exceeds 5.0 with 4+ sources.
7. **T+18 min**: **Transition: Alert -> Incident.** Pouncers are unlocked. Tom convenes BFT consensus for response actions.

---

## Security Model

The pheromone substrate is a shared communication medium. In a threat hunting context, the substrate itself can become an attack target. The security model addresses three threats: fabricated deposits, deposit flooding, and replay attacks.

### Signed Deposits

Every `PheromoneDeposit` carries an Ed25519 signature (`signature` field) and the depositing agent's public key (`agent_key` field). The signature covers the canonical JSON (RFC 8785 JCS) serialization of all fields except `signature` itself.

Before a deposit is incorporated into concentration computation, the substrate verifies:

1. The signature is valid for the given public key and payload.
2. The public key belongs to an agent currently admitted to the swarm (checked against the Tom-managed agent registry).

Unsigned or improperly signed deposits are rejected. This is fail-closed: if signature verification fails for any reason (malformed key, corrupted payload, clock skew causing timestamp issues), the deposit is discarded.

### Source Diversity (Anti-Sybil)

As described in [Source Diversity Enforcement](#source-diversity-enforcement), mode transitions require deposits from multiple distinct agents. Combined with cryptographic identity verification, this prevents a single compromised agent from manipulating the swarm's behavior.

The `min_sources_for_escalation` parameter (default: 2) is the minimum source diversity for any threshold crossing. Deployments in higher-threat environments may increase this to 3 or more.

### Anti-Flooding

A single agent depositing many pheromones in rapid succession contributes repeated strength from the same `agent_id`. Because `distinct_sources` counts unique agent IDs (not deposit count), flooding from one agent does not increase source diversity.

Additionally, when computing `total_strength`, the substrate can cap the contribution of any single agent to a configurable maximum per time window. This prevents a compromised agent from inflating `total_strength` even without affecting `distinct_sources`.

### Replay Protection

The `timestamp` field in each deposit, combined with the JetStream sequence number, provides replay protection. Deposits with timestamps outside a configurable tolerance window (accounting for clock skew) are rejected. The JetStream deduplication window provides an additional layer of protection against exact-duplicate replays.

### Summary of Security Properties

| Threat | Mitigation | Mechanism |
|---|---|---|
| Fabricated deposits | Ed25519 signature verification | `signature` + `agent_key` fields |
| Single-agent flooding | Source diversity requirement | `distinct_sources >= min_sources_for_escalation` |
| Sybil attack (fake agents) | Agent registry verification | Tom-managed admission, key-to-agent binding |
| Replay attacks | Timestamp validation + JetStream dedup | `timestamp` window + stream sequence numbers |
| Clock manipulation | Byzantine tolerance | 2f+1 agents must independently corroborate |

---

## Configuration Reference

The pheromone substrate is configured via the `pheromone` block in the mission YAML. The complete default configuration from `rulesets/default.yaml`:

```yaml
pheromone:
  default_half_life_secs: 3600
  evaporation_threshold: 0.01
  min_sources_for_escalation: 2
  alert_threshold: 2.0
  incident_threshold: 5.0
```

### Parameter Reference

| Parameter | Type | Default | Description |
|---|---|---|---|
| `default_half_life_secs` | `f64` | `3600` (1 hour) | Default half-life for pheromone decay. Individual deposits can override this, but this value is used when no override is specified. |
| `evaporation_threshold` | `f64` | `0.01` | Minimum effective strength. Pheromones below this value are considered fully evaporated and eligible for garbage collection. Lower values retain signals longer but increase storage. |
| `min_sources_for_escalation` | `usize` | `2` | Minimum number of distinct agents whose deposits must contribute to a concentration before it can trigger a mode transition. This is the anti-flooding / anti-sybil parameter. |
| `alert_threshold` | `f64` | `2.0` | Total pheromone concentration (sum of effective strengths) required to transition from Normal to Alert mode. |
| `incident_threshold` | `f64` | `5.0` | Total pheromone concentration required to transition from Alert to Incident mode. |

### Tuning Guidance

**Aggressive posture** (faster escalation, more false positives):
```yaml
pheromone:
  default_half_life_secs: 7200    # 2 hours -- signals persist longer
  evaporation_threshold: 0.005    # Lower floor retains weak signals
  min_sources_for_escalation: 2   # Keep at 2 minimum
  alert_threshold: 1.5            # Lower bar for alert
  incident_threshold: 3.0         # Lower bar for incident
```

**Conservative posture** (slower escalation, fewer false positives):
```yaml
pheromone:
  default_half_life_secs: 1800    # 30 minutes -- signals decay faster
  evaporation_threshold: 0.05     # Higher floor cleans up faster
  min_sources_for_escalation: 3   # Require 3 independent sources
  alert_threshold: 4.0            # Higher bar for alert
  incident_threshold: 8.0         # Higher bar for incident
```

### Rust Type

The configuration is deserialized into `PheromoneConfig` (`crates/swarm-core/src/config.rs`):

```rust
pub struct PheromoneConfig {
    pub default_half_life_secs: f64,
    pub evaporation_threshold: f64,
    pub min_sources_for_escalation: usize,
    pub alert_threshold: f64,
    pub incident_threshold: f64,
}
```

The `Default` implementation matches the YAML defaults shown above.
