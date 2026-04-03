# Swarm Team Six: Integration Guide

> Historical note: this document reflects the earlier mixed Rust/Python integration plan. The active direction is a Rust-first runtime with copied upstream references.

> How the three foundational systems are wired together.  
> Last updated: 2026-04-02

Swarm Team Six is not a greenfield project. It is an orchestration layer that wires together three existing internal systems, each owning a distinct concern:

| System | Concern | Language | What STS Uses |
|--------|---------|----------|---------------|
| **ClawdStrike** | Security enforcement, crypto, transport | Rust | Guard pipeline, Spine envelopes, Ed25519 crypto |
| **Cyntra** | Scheduling, dispatching, verification, memory | Python | Scheduler, Dispatcher, Memory patterns |
| **Hellcat** | Red teaming, adversarial pressure | Python | Attack operators, OPSEC, co-evolutionary engine |

The STS-specific code is thin glue: pheromone substrate, archetype routing, co-evolutionary fitness, and the blue swarm agent implementations.

---

## ClawdStrike Integration

ClawdStrike (`../clawdstrike/`) provides the security enforcement, cryptographic identity, and transport layers. Three STS crates are vendored and adapted from ClawdStrike source:

### Crate Mapping

| STS Crate | Upstream ClawdStrike Crate | What Is Vendored |
|-----------|---------------------------|------------------|
| `swarm-guard` | `clawdstrike` (main library) | Guard trait, GuardResult, GuardAction, Spider Sense detector, policy loading |
| `swarm-spine` | `spine` | Signed envelopes, Merkle checkpoint statements, NATS JetStream helpers |
| `swarm-crypto` | `hush-core` | Ed25519 signing/verification, SHA-256, canonical JSON (RFC 8785), Merkle trees |

### Why Vendor Instead of Depend

ClawdStrike's crates are designed for a different deployment model (single-agent enforcement). STS needs:

- **Swarm-specific guard middleware.** The guard pipeline in STS wraps the `SwarmAgent.tick()` output, not individual tool calls. The evaluation context includes pheromone state, swarm mode, and autonomy tier -- none of which exist in upstream ClawdStrike.
- **Pheromone-aware Spine subjects.** Upstream Spine uses a flat subject hierarchy (`hush.spine.*`). STS extends this with `swarm.pheromone.{threat_class}.{severity}` and `swarm.consensus.{round_id}`.
- **Multi-agent key management.** Upstream hush-core manages a single keypair. STS manages a keypair-per-agent with delegation tokens for swarm membership.

The vendoring strategy: copy the core types and logic, adapt the integration surfaces, keep the cryptographic primitives identical for cross-system receipt verification.

### swarm-guard

Vendored from `clawdstrike/crates/libs/clawdstrike/src/`.

**What is taken directly:**
- `Guard` trait (sync evaluation of an action against policy)
- `AsyncGuard` trait (for guards that need network access)
- `GuardResult` and `GuardAction` enums
- Spider Sense detector: `SpiderSenseDetector`, `SpiderSenseDetectorConfig`, `PatternDb`, `PatternEntry`
- Cosine similarity computation over threat embeddings
- Built-in pattern database loading (`builtin:s2bench-v1`)

**What is adapted:**
- Policy loading. Upstream parses schema v1.5.0 YAML with `extends` inheritance. STS parses hunt mission YAML (`rulesets/*.yaml`) which has a different top-level structure (population, pheromone, consensus sections) but embeds compatible guard configurations.
- Guard pipeline middleware. Upstream evaluates guards in a linear pipeline per tool call. STS wraps this in the 9-stage middleware pipeline where the `GuardPipeline` is stage 5, and the evaluation context includes swarm-specific fields (current mode, autonomy tier, pheromone concentration).
- Spider Sense as Whisker fast path. Upstream Spider Sense is a guard that can deny actions. In STS, Spider Sense is the Whisker's primary detection mechanism -- it produces pheromone deposits rather than deny/allow verdicts.

### swarm-spine

Vendored from `clawdstrike/crates/libs/spine/src/`.

**What is taken directly:**
- Signed envelope construction: `build_envelope(payload, signing_key) -> SignedEnvelope`
- Signed envelope verification: `verify_envelope(envelope, verifying_key) -> Result<Payload>`
- Merkle tree construction from a sequence of envelopes
- Merkle inclusion proof generation and verification
- NATS JetStream helpers: `ensure_stream()`, `ensure_kv()`

**What is adapted:**
- Subject hierarchy. Upstream uses `hush.spine.*`. STS adds:
  ```
  swarm.pheromone.{threat_class}.{severity}    # Pheromone deposits
  swarm.action.{agent_role}.{action_type}      # Agent actions
  swarm.consensus.{round_id}.{phase}           # BFT consensus messages
  swarm.gossip.{agent_id}                      # SWIM membership gossip
  swarm.health.{agent_id}                      # Health heartbeats
  swarm.evolution.{generation}                 # Strategy mutations
  ```
- Checkpoint statements. Upstream checkpoints attest to a sequence of tool-call receipts. STS checkpoints attest to pheromone deposits, consensus rounds, and response actions. The checkpoint structure is the same (Merkle root + witness co-signatures), but the payload schema differs.

### swarm-crypto

Vendored from `clawdstrike/crates/libs/hush-core/src/`.

**What is taken directly (unchanged):**
- Ed25519 key generation (`generate_keypair()`)
- Ed25519 signing (`sign(message, signing_key)`)
- Ed25519 verification (`verify(message, signature, verifying_key)`)
- SHA-256 hashing
- RFC 8785 canonical JSON serialization (JCS)
- Merkle tree construction and inclusion proof verification

**What is adapted:**
- Key management. Upstream manages one keypair per HushEngine instance. STS manages N keypairs (one per swarm agent) with a `KeyStore` that maps `AgentId -> SigningKey`. Delegation tokens allow Toms to authorize new agent identities.

### Receipt Interoperability

STS receipts are wire-compatible with ClawdStrike receipts. A receipt signed by a Whisker agent can be verified by any ClawdStrike installation that has the Whisker's public key. This is by design -- the swarm's audit trail must be verifiable by external systems.

The canonical JSON (JCS) serialization ensures that Rust-produced receipts can be verified by the TypeScript and Python ClawdStrike SDKs, and vice versa.

---

## Cyntra Integration

Cyntra is the orchestration kernel from the Backbay platform (`../../platform/kernel/`). STS ports its scheduling, dispatching, and memory patterns into the `kernel/` Python package.

### Pattern Mapping

| Cyntra Pattern | STS Adaptation | Location |
|---------------|----------------|----------|
| Ready-Set computation | Hunt task readiness (dependency satisfaction) | `kernel/scheduler/` |
| Critical path analysis | Longest threat chain weighted by severity | `kernel/scheduler/` |
| Lane packing | Parallel investigations within resource budget | `kernel/scheduler/` |
| Memory-informed priority | Boost threat types with prior detection success | `kernel/scheduler/` |
| Dispatcher (spawn/monitor/collect) | Agent lifecycle management per archetype | `kernel/dispatcher/` |
| Workcell isolation | Per-investigation isolation context for Stalkers | `kernel/dispatcher/` |
| Verifier (speculate+vote) | Multi-agent investigation consensus | `kernel/archetypes/tom/` |
| KernelMemoryBridge | Threat memory with semantic/temporal/causal graphs | `kernel/memory/` |
| BaseSentinel | Background housekeeping (prune, consolidate, rebalance) | `kernel/scheduler/` |
| Ralph (loop control) | Arms race cadence control | `kernel/evolution/` |
| Event system | Pheromone deposit/subscription routing | `kernel/harness/` |

### Scheduler (`kernel/scheduler`)

The Cyntra scheduler computes which tasks are ready (dependencies satisfied), finds the critical path (longest chain weighted by effort), and packs tasks into parallel lanes within resource budgets.

STS adapts this for hunt prioritization:
- **Tasks** become hunt investigations (triggered by pheromone concentration exceeding thresholds).
- **Dependencies** become investigation prerequisites (e.g., a Stalker investigation depends on a Whisker detection).
- **Effort weights** become threat severity (Critical > High > Medium > Low).
- **Resource budgets** become agent population limits (max_count per archetype).
- **Memory-informed priority** boosts threat types where prior hunts succeeded and deprioritizes known false-positive patterns.

The scheduler runs in the Python control plane and dispatches work to Rust agents via the PyO3 bridge.

### Dispatcher (`kernel/dispatcher`)

The Cyntra dispatcher manages task lifecycle: spawn an execution context, route the task, monitor for timeouts, and collect results.

STS adapts this for agent lifecycle:
- **Spawn** creates a new agent instance with a fresh Ed25519 keypair, registered in the KeyStore.
- **Route** maps task types to appropriate archetypes (anomaly -> Whisker, lead -> Stalker, correlation -> Weaver).
- **Monitor** tracks agent health via signed heartbeats. Unhealthy agents are replaced.
- **Collect** gathers findings and signed receipts from completed investigations.
- **Workcell isolation** gives each Stalker investigation its own execution context, preventing cross-contamination between concurrent investigations.

### Memory (`kernel/memory`)

Cyntra's memory system provides semantic search, learning from outcomes, and context retrieval. STS extends this with MAGMA-style multi-graph architecture:

- **Temporal graph:** Attack timeline ordering (when events occurred relative to each other).
- **Causal graph:** Kill chain dependencies (this exploit enabled that lateral movement).
- **Entity graph:** Adversary infrastructure mapping (IPs, domains, tools, credentials, their relationships).
- **Semantic graph:** TTP pattern similarity via embedding-based comparison.

The memory system is pluggable: in-memory for development, SQLite for testing, Neo4j or KuzuDB for production deployments. The Sphinx archetype is the primary memory custodian, but all agents can read from the knowledge graph.

Cyntra's memory types map to STS threat memory types:

| Cyntra Memory Type | STS Equivalent | Purpose |
|-------------------|----------------|---------|
| Pattern memory | TTP pattern library | Known attack technique signatures |
| Failure memory | False positive registry | Investigations that turned out benign |
| Dynamic memory | Active threat state | Currently tracked threats and their status |
| Context memory | Investigation context | Per-hunt accumulated evidence and reasoning |
| Playbook memory | Response playbook library | Proven response procedures |
| Frontier memory | Threat landscape | Emerging threats not yet seen in this environment |

---

## Hellcat Integration

Hellcat is the autonomous red teaming kernel. In STS, it serves as the adversarial pressure engine -- the red swarm that the blue swarm co-evolves against.

### Adaptation Strategy

Hellcat currently runs as a single-process kernel. STS adapts its operators into NATS-connected agents that participate in the co-evolutionary arms race.

**What is ported directly from Hellcat:**
- `TargetGraph` -- attack surface model with typed nodes (targets, vulnerabilities, credentials, defenses) and weighted edges
- `AttackScorer` -- scoring function: CVSS + EPSS + chain multiplier - stealth cost
- `AttackPlanner` -- selects optimal attack path through the TargetGraph
- Proof validation gates (L1 informational -> L2 confirmed -> L3 exploited -> L4 exploited with reproducibility)
- `NoiseMonitor` -- OPSEC weighted ensemble (analyzer 35%, circuit 20%, trap 15%, rate 15%, session 15%)
- `StealthBudget` -- constrains red swarm to avoid detection (mirrors real attacker trade-offs)
- `AttackPatternDB` -- cross-engagement technique outcome tracking
- Prompt genome evolution with Pareto selection and curriculum-based scheduling

**What is adapted:**
- Hellcat's operators become independent red swarm agents:

  | Hellcat Operator | Red Swarm Agent | Adaptation |
  |-----------------|-----------------|------------|
  | Recon pipeline (9-phase) | `ReconOp` | Feeds TargetGraph via NATS, operates on `swarm.red.recon.*` subjects |
  | SQLi/cmd injection | `InjectionOp` | Probes targets, reports results to AttackPatternDB |
  | Auth bypass | `AuthOp` | Tests authentication weaknesses, respects StealthBudget |
  | Evasion classifier + strategy | `EvasionOp` | Monitors blue detection patterns via pheromone observation, adapts TTPs |
  | ChainAnalyzer | `ChainOp` | Finds multi-step exploit chains through TargetGraph |
  | NoiseMonitor + StealthBudget | `OpsecOp` | Detects when blue swarm is watching, throttles red activity |

- **Communication.** Hellcat operators communicate via internal function calls. Red swarm agents communicate via NATS subjects under `swarm.red.*`, isolated from blue swarm subjects.

- **Execution sandboxing.** Red swarm operators execute in a sandboxed environment. They never touch production infrastructure. Their "targets" are simulated attack surfaces or designated test environments.

### The Co-Evolutionary Bridge (`kernel/evolution`)

The evolution engine manages the arms race between blue and red swarms:

```
Red swarm executes attacks
    |
    v
Blue Whiskers attempt detection
    |
    v
Fitness evaluation
    |-- Blue fitness: detection_rate * (1 - FP_rate) * speed
    |-- Red fitness: evasion_rate * exploit_success * stealth
    |
    v
Kittens mutate blue detection strategies
    |
    v
Z3 verification gate (safety invariants)
    |
    v
Staged rollout: shadow -> canary -> production
    |
    v
Red EvasionOp adapts to new blue strategies
    |
    v
(cycle repeats)
```

**Fitness coupling:** Each side's fitness degrades the other's. A blue strategy that catches more attacks reduces red evasion_rate. A red evasion technique that bypasses detection reduces blue detection_rate. This creates genuine evolutionary pressure.

**Z3 gate:** Every evolved blue strategy must pass Z3 verification before deployment. The Z3 gate checks:
- The strategy does not weaken any existing proven guard invariant
- The strategy's detection predicates are satisfiable (not vacuously true/false)
- Resource consumption bounds are maintained

**MemRL Q-value scoring:** Strategy selection uses utility-based scoring (learned effectiveness), not just semantic similarity. Strategies that performed well in prior generations are preferred, with exploration bonuses for untested mutations.

**Staged rollout:**
1. **Shadow:** New strategy runs in parallel with production, results logged but not acted on.
2. **Canary:** Strategy handles a small percentage of real traffic alongside production.
3. **Production:** Strategy fully deployed after canary validation.

---

## PyO3 Bridge

The `swarm-bridge` crate (`crates/swarm-bridge/`) is the seam between the Rust data plane and the Python control plane. It is built with PyO3 and distributed as a native Python extension module via maturin.

### What Crosses the Boundary

The bridge exposes Rust functionality to Python. The design principle: **hot path in Rust, warm path in Python.**

| Direction | What | Why |
|-----------|------|-----|
| Python -> Rust | Pheromone deposit | Signing + serialization must be fast and deterministic |
| Python -> Rust | Pheromone query | Concentration computation with decay is math-heavy |
| Python -> Rust | Detection strategy evaluation | Spider Sense cosine similarity is the Whisker hot path |
| Python -> Rust | Receipt signing | Ed25519 signing must use the same implementation as verification |
| Python -> Rust | Receipt verification | Cryptographic verification of any receipt |
| Python -> Rust | Guard pipeline check | Policy evaluation must be fail-closed and deterministic |
| Python -> Rust | Consensus vote tallying | BFT math must be deterministic |
| Python -> Rust | Canonical JSON serialization | RFC 8785 determinism required for cross-language receipt compatibility |
| Rust -> Python | (none currently) | Rust agents (Whiskers) do not call into Python. LLM calls happen in Python-native agents. |

### Module Structure

The bridge is exposed as `swarm_team_six._bridge` (configured in `pyproject.toml` under `[tool.maturin]`):

```python
from swarm_team_six._bridge import (
    # Pheromone operations
    PheromoneSubstrate,    # deposit, query, subscribe

    # Detection
    DetectionStrategy,     # evaluate (Spider Sense fast path)

    # Crypto
    CryptoOps,             # sign, verify, hash, canonical_json

    # Guard pipeline
    GuardPipeline,         # check (returns allow/deny + receipt)

    # Consensus
    ConsensusRound,        # propose, vote, tally
)
```

### Build and Development

```bash
# Build the bridge (development mode, links into virtualenv)
maturin develop

# Build release wheel
maturin build --release

# The bridge is automatically available after `uv sync && maturin develop`
```

### Data Serialization Across the Boundary

All data crossing the PyO3 boundary is serialized as JSON (using canonical JSON / RFC 8785 on the Rust side). This ensures:
- Deterministic serialization regardless of which side produces the data
- Receipt signatures are valid whether created in Rust or verified in Python
- No PyO3-specific type coupling -- the bridge could be replaced with a different FFI mechanism without changing the data format

Python-side types use Pydantic models that mirror the Rust serde structs. The `swarm-core` Rust types (`PheromoneDeposit`, `SwarmAction`, `ConsensusResult`, etc.) have corresponding Pydantic models in `kernel/`.

---

## NATS

NATS (with JetStream) is the external communication backbone. All inter-agent communication, pheromone persistence, and audit logging flows through NATS.

### Why NATS

- **JetStream persistence:** Pheromone deposits are persisted and replayable. New agents can catch up on the current threat landscape by replaying the pheromone stream.
- **Subject-based routing:** The hierarchical subject namespace maps naturally to threat classes, agent roles, and consensus rounds.
- **At-least-once delivery:** Combined with idempotent receipt processing, ensures no signals are lost.
- **Horizontal scaling:** NATS clusters support the deployed swarm topology without application-level sharding.

### Subject Hierarchy

All STS subjects are prefixed with the configured `subject_prefix` (default: `swarm`).

```
swarm.                                  # Root prefix
  pheromone.                            # Pheromone substrate
    {threat_class}.{severity}           # e.g., swarm.pheromone.lateral_movement.HIGH
  action.                               # Agent actions (post-guard-pipeline)
    {agent_role}.{action_type}          # e.g., swarm.action.stalker.claim_investigation
  consensus.                            # BFT consensus protocol
    {round_id}.propose                  # Proposal
    {round_id}.prevote                  # Prevote
    {round_id}.precommit               # Precommit
    {round_id}.commit                  # Committed decision
  gossip.                               # SWIM membership
    {agent_id}                          # Health and membership announcements
  health.                               # Agent health heartbeats
    {agent_id}                          # Signed heartbeat with status
  evolution.                            # Strategy evolution
    {generation}.propose               # New strategy proposal
    {generation}.test                  # Test results
    {generation}.promote               # Promotion to canary/production
  red.                                  # Red swarm (isolated namespace)
    recon.{target_id}                  # Reconnaissance results
    attack.{operator}.{target_id}      # Attack execution
    opsec.{metric}                     # OPSEC monitoring
  hunt.                                 # Hunt lifecycle
    {hunt_id}.created                  # Investigation created
    {hunt_id}.findings                 # Published findings
    {hunt_id}.verdict                  # Final verdict
    {hunt_id}.response                 # Authorized response
  audit.                                # Audit trail (append-only)
    receipt.{agent_id}                 # Signed receipts
    checkpoint.{sequence}              # Merkle checkpoint statements
```

### JetStream Streams

| Stream Name | Subjects | Retention | Purpose |
|-------------|----------|-----------|---------|
| `swarm-pheromones` | `swarm.pheromone.>` | Limits (time-based, matches decay) | Pheromone deposit persistence and replay |
| `swarm-audit` | `swarm.audit.>` | Limits (size-based, archival) | Immutable audit trail of all signed receipts |
| `swarm-consensus` | `swarm.consensus.>` | WorkQueue | Consensus message delivery with ack |
| `swarm-hunts` | `swarm.hunt.>` | Limits (time-based) | Hunt lifecycle events |

### Deployed Swarm Topology

A production STS deployment consists of:

```
+-------------------------------------------+
|  Control Plane (Python)                   |
|  - Scheduler                              |
|  - Dispatcher                             |
|  - Stalker/Weaver/Tom/Kitten/Sphinx/      |
|    Calico/Pouncer agent processes         |
|  - Evolution engine                       |
|  - PyO3 bridge to Rust                    |
+-------------------+-----------------------+
                    |
              NATS Cluster
              (JetStream)
                    |
+-------------------+-----------------------+
|  Data Plane (Rust)                        |
|  - Whisker stream processors (N instances)|
|  - Pheromone substrate                    |
|  - Guard pipeline                         |
|  - Consensus vote tallying                |
|  - Receipt signing                        |
+-------------------+-----------------------+
                    |
        +-----------+-----------+
        |                       |
+-------+-------+   +-----------+---------+
| Tetragon      |   | Hubble              |
| Bridge        |   | Bridge              |
| (eBPF events) |   | (network flows)     |
+---------------+   +---------------------+
```

Whisker instances scale horizontally. Each Whisker subscribes to a partition of the telemetry stream (NATS queue groups provide load balancing). The Python control plane runs the warm-path agents that require LLM access. The PyO3 bridge allows Python agents to call into Rust for cryptographic operations and pheromone queries without crossing a network boundary.

The red swarm (when active) runs in a separate process group with its own NATS subjects (`swarm.red.*`), isolated from the blue swarm's operational subjects. The evolution engine bridges the two by reading fitness metrics from both sides.
