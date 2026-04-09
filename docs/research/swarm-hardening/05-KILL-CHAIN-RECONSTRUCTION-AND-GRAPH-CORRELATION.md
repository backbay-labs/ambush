---
title: "05 -- Kill Chain Reconstruction and Graph-Based Correlation"
series: Swarm Hardening (5 of 8)
version: "0.2"
date: 2026-04-08
status: Draft
authors: Swarm Team Six Research
---

# Kill Chain Reconstruction and Graph-Based Correlation

## Extending Weaver Correlation from Time-Window Clustering to Attack-Graph DAGs

> Research document for a proposed `swarm-graph` module within the STS critical
> lane. Sources: `crates/swarm-runtime/src/correlation.rs`,
> `crates/swarm-runtime/src/weaver_agent.rs`,
> `crates/swarm-runtime/src/stalker_agent.rs`,
> `crates/swarm-spine/src/incident.rs`,
> `crates/swarm-spine/src/investigation.rs`.

---

## Table of Contents

1. [Abstract](#1-abstract)
2. [Current State: Time-Window Correlation](#2-current-state-time-window-correlation)
3. [Kill Chain Models](#3-kill-chain-models)
4. [Attack Graph Theory](#4-attack-graph-theory)
5. [Temporal-Causal Correlation](#5-temporal-causal-correlation)
6. [Graph Construction from Detections](#6-graph-construction-from-detections)
7. [Graph Storage Approaches](#7-graph-storage-approaches)
8. [Scoring and Prioritization](#8-scoring-and-prioritization)
9. [Provenance Graph Visualization](#9-provenance-graph-visualization)
10. [Integration Design](#10-integration-design)
11. [Proposed Architecture](#11-proposed-architecture)
12. [Open Questions and Future Work](#12-open-questions-and-future-work)
- [Cross-References](#cross-references)
- [References](#references)

---

## 1. Abstract

Swarm Team Six currently correlates detection findings using time-window
clustering with shared correlation keys. The `CorrelationEngine` in
`crates/swarm-runtime/src/correlation.rs` assembles `CorrelatedIncident`
records by comparing an investigation seed against recent candidates, checking
whether they share non-strategy correlation keys (e.g., `host:host-1`,
`user:alice`) within a configurable `time_window_ms`. This approach succeeds at
grouping temporally proximate events touching the same host or user, but it
cannot reconstruct the causal structure of a multi-stage intrusion. Two
investigations that share a host but represent unrelated activity will be
grouped; two investigations that represent consecutive kill chain stages on
different hosts (lateral movement from host-1 to host-2) will be missed.

This document proposes extending the correlation architecture with directed
acyclic graph (DAG) representations of attack progression. We survey kill chain
models (Lockheed Martin Cyber Kill Chain, MITRE ATT&CK, Diamond Model),
formalize attack graph theory for STS, design temporal-causal correlation
algorithms, evaluate graph storage options, define graph-based severity
scoring, and propose an integration path that feeds graph intelligence back
into the pheromone substrate and PounceAgent response decisions.

The goal is not to replace time-window correlation but to layer graph-based
reasoning on top of it, enabling STS to answer questions that flat clustering
cannot: "What is the attacker trying to achieve?" and "What will they do next?"

---

## 2. Current State: Time-Window Correlation

### 2.1 CorrelationEngine Architecture

The `CorrelationEngine` (`crates/swarm-runtime/src/correlation.rs`) operates as
a deterministic, rule-based correlator. Its `correlate_hunt` method takes a seed
hunt ID, loads the corresponding `InvestigationBundle` from the investigation
store, retrieves up to `candidate_limit` recent investigation records, and
evaluates each candidate for inclusion in a `CorrelatedIncident`.

The inclusion criteria form a three-gate filter:

1. **Completion gate**: The candidate must have `InvestigationStatus::Completed`.
   Running, queued, failed, or timed-out investigations are rejected.

2. **Key overlap gate**: The candidate must share at least one non-strategy
   correlation key with the seed. Strategy-only overlap (e.g., both produced by
   `summary_investigator`) is explicitly rejected. This prevents unrelated
   investigations that happen to use the same detection strategy from being
   grouped.

3. **Time window gate**: The absolute time delta between the seed's
   `last_updated_ms` and the candidate's `last_updated_ms` must be within
   `time_window_ms`.

A weighted scoring system adds nuance: the `weighted_score` equals the count of
shared non-strategy keys plus a cross-strategy bonus (1 point if the seed and
candidate used different detection strategies). This means two investigations
sharing `host:host-1` from different strategies (e.g., `suspicious_process_tree`
and `dns_exfiltration`) score higher than two from the same strategy, reflecting
the intuition that independent detection methods corroborating the same entity
provide stronger evidence of real threat activity.

### 2.2 Correlation Key Taxonomy

The `SummaryInvestigator` in `crates/swarm-runtime/src/investigation.rs`
generates correlation keys during investigation:

- `host:<host_id>` -- from the telemetry event's `host_id` field
- `user:<username>` -- from the detection evidence's `user` field
- `threat:<threat_class>` -- from the detection finding's `ThreatClass`
- `strategy:<strategy_id>` -- from the detection finding's `strategy_id`

The key namespace is flat. There is no semantic hierarchy or typed relationship
between keys. `host:host-1` and `user:alice` are treated as independent tokens;
the correlation engine has no concept of "alice logged into host-1" as a
structured relationship.

### 2.3 WeaverAgent Role

The `WeaverAgent` (`crates/swarm-runtime/src/weaver_agent.rs`) is the swarm
agent responsible for triggering correlation. On each tick, it scans pheromone
deposits from stalker agents, extracts hunt IDs, and invokes
`CorrelationEngine::correlate_hunt` for any hunt it has not previously
correlated. Results are published as `SwarmAction::PublishFindings` containing
the incident ID, summary, and included hunt IDs.

The Weaver operates reactively: it processes one hunt at a time, in the order
stalker deposits appear. It does not maintain a global view of ongoing
incidents, does not merge incidents that share members, and does not track
incident evolution over time.

### 2.4 StalkerAgent Role

The `StalkerAgent` (`crates/swarm-runtime/src/stalker_agent.rs`) bridges
detection and investigation. On each tick, it scans pheromone deposits from
whisker agents, loads corresponding replay bundles, submits them to the
`InvestigationCoordinator` for async enrichment, and -- once investigation
completes -- publishes findings to the pheromone substrate with Ed25519
signatures.

The Stalker produces the correlation keys and investigation bundles that the
Weaver subsequently correlates. Its output is the primary input to the
correlation pipeline.

### 2.5 Limitations of Time-Window Clustering

Five structural limitations constrain the current approach:

**L1: No causal ordering.** Time-window clustering treats all correlated events
as peers. There is no concept of "event A caused event B" or "event A preceded
and enabled event B." An incident containing initial access + lateral movement +
credential access presents all three as a flat set of `IncidentMemberDecision`
entries.

**L2: No cross-host linking.** Correlation keys are entity-based, and lateral
movement by definition changes the entity. An attacker compromising `host-1`,
stealing credentials, and moving to `host-2` produces two investigations with
different `host:` keys. Unless the same `user:` key appears in both (the
attacker uses the same account), the investigations will not correlate.

**L3: No kill chain awareness.** The correlation engine cannot distinguish
between an incident containing two independent credential access events on the
same host (coincidental overlap) and an incident containing initial access
followed by privilege escalation (multi-stage attack). Both score the same way.

**L4: No incident evolution.** The `CorrelatedIncident` struct is immutable once
assembled. New investigations arriving after the initial correlation cannot be
appended to an existing incident. Each correlation run produces a new, separate
incident.

**L5: No campaign detection.** Multiple incidents that share technique patterns,
infrastructure indicators, or timing patterns cannot be linked into a campaign.
The correlation engine operates at the investigation-to-incident level only.

---

## 3. Kill Chain Models

### 3.1 Lockheed Martin Cyber Kill Chain

The Lockheed Martin Cyber Kill Chain [1] defines seven sequential stages:
Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, and
Actions on Objectives. The model assumes linear progression -- each stage
completes before the next begins. This linearity is both its strength (easy
to reason about) and its weakness (real attacks skip stages, revisit earlier
stages, or run multiple chains in parallel).

**Relevance to STS**: The `ThreatClass` enum already maps loosely to kill
chain stages (`InitialAccess`, `Persistence`, `CommandAndControl`,
`DataExfiltration`), but the mapping is not formalized and the correlation
engine does not use `ThreatClass` ordering to infer progression.

### 3.2 MITRE ATT&CK Framework

MITRE ATT&CK [2] organizes adversary behavior into 14 tactics (the *why*),
each containing multiple techniques (the *how*). Unlike the Lockheed Martin
model, ATT&CK does not impose strict linear ordering -- adversaries may use
multiple techniques within a tactic and revisit tactics non-linearly.

**Relevance to STS**: The `ThreatClass` enum maps to a subset of ATT&CK
tactics:

| STS ThreatClass        | ATT&CK Tactic         |
|------------------------|------------------------|
| InitialAccess          | Initial Access (TA0001) |
| Execution              | Execution (TA0002)     |
| Persistence            | Persistence (TA0003)   |
| PrivilegeEscalation    | Privilege Escalation (TA0004) |
| DefenseEvasion         | Defense Evasion (TA0005) |
| CredentialAccess       | Credential Access (TA0006) |
| Discovery              | Discovery (TA0007)     |
| LateralMovement        | Lateral Movement (TA0008) |
| DataExfiltration       | Exfiltration (TA0010)  |
| CommandAndControl      | Command and Control (TA0011) |
| Impact                 | Impact (TA0040)        |
| SupplyChain            | Resource Development / Initial Access |

Missing coverage: Reconnaissance (TA0043), Resource Development (TA0042),
and Collection (TA0009) have no direct `ThreatClass` representation. The
`Custom(String)` variant provides an escape hatch but lacks type safety.

### 3.3 Diamond Model of Intrusion Analysis

The Diamond Model [3] structures each intrusion event around four core
features: adversary, capability, infrastructure, and victim. Relationships
between events are captured through activity threads (temporal sequences of
events by the same adversary) and activity-attack graphs (directed graphs
connecting events through shared features).

**Relevance to STS**: The Diamond Model's emphasis on entity relationships
(adversary-uses-infrastructure, adversary-targets-victim) maps naturally to
graph-based correlation. The current flat correlation key scheme captures two
of the four Diamond features (infrastructure via `host:` keys, victim via
`user:` keys) but lacks adversary and capability dimensions.

### 3.4 Model Selection for STS

We recommend adopting **ATT&CK tactics as the primary kill chain model** for
graph-based correlation, for three reasons:

1. **Existing alignment**: `ThreatClass` already maps to ATT&CK tactics. No
   new ontology is needed.

2. **Non-linearity**: ATT&CK's tactic independence matches real attack
   patterns better than the Lockheed Martin model's strict linearity.

3. **Community compatibility**: ATT&CK technique IDs provide a universal
   language for threat intelligence feeds (see 03-Threat Intel).

The Diamond Model's entity schema should be adopted as the **node type
taxonomy** for attack graphs, enriching the flat correlation key namespace
with structured relationships. The Lockheed Martin model remains useful as
a simplified operator-facing visualization for the review workbench.

---

## 4. Attack Graph Theory

### 4.1 Formal Definition

An attack graph is a directed acyclic graph (DAG) G = (V, E) where:

- V is a set of typed nodes representing observable entities and events
- E is a set of typed directed edges representing relationships between entities

The "acyclic" constraint is a simplification. Real attacks may contain cycles
(e.g., C2 beaconing is periodic; lateral movement may revisit hosts). We
enforce acyclicity by treating each *observation* of an entity as a distinct
temporal instance: `host-1 at T1` and `host-1 at T2` are different nodes even
if they represent the same physical host. Logical entity identity is maintained
through node attributes, not graph topology.

### 4.2 Node Types

We define five primary node types, each corresponding to extractable entities
from STS telemetry:

**TechniqueNode**: Represents an observed ATT&CK technique instance. Attributes
include `threat_class: ThreatClass`, `strategy_id: String`, `confidence: f64`,
`timestamp: i64`, and a reference to the source `finding_id`.

**AssetNode**: Represents a host or endpoint. Attributes include
`host_id: String`, `asset_criticality: AssetCriticality` (a new enum to be
defined), and optional metadata (OS, role, network zone).

**IdentityNode**: Represents a user account or service principal. Attributes
include `user: String`, `privilege_level: Option<PrivilegeLevel>`, and
authentication context.

**ProcessNode**: Represents a process instance. Attributes include
`process_name: String`, `parent_process: Option<String>`,
`command_line: Option<String>`, and `executable_path: Option<String>`. This
maps directly to the `ProcessStartEvent` telemetry payload.

**NetworkNode**: Represents a network endpoint or connection. Attributes
include `address: String`, `port: Option<u16>`, `protocol: Option<String>`.
This maps to `NetworkConnectEvent` and `DnsQueryEvent` payloads.

### 4.3 Edge Types

We define four primary edge types:

**CausalEdge**: Represents a direct causal relationship. "Process P1 spawned
process P2" or "technique T1 produced the credentials used in technique T2."
Causal edges are the strongest evidence of attack progression.

**TemporalEdge**: Represents temporal ordering without proven causation. "Event
A happened before event B on the same host." Temporal edges are weaker than
causal edges but essential for reconstructing timelines.

**LateralEdge**: Represents movement between assets. "Activity on host-1
preceded activity on host-2 using credentials observed on host-1." Lateral
edges link different `AssetNode` instances and are the key to solving limitation
L2 from Section 2.5.

**AssociationEdge**: Represents non-causal entity relationships. "User alice
authenticated to host-1" or "process powershell connected to IP 203.0.113.5."
Association edges provide context without implying attack progression.

### 4.4 Edge Confidence

Each edge carries a `confidence: f64` in [0.0, 1.0] reflecting how certain the
causal or temporal relationship is. Confidence sources:

- **Direct observation**: Process parent-child relationships from telemetry have
  confidence 1.0 (the OS reports the relationship).
- **Temporal inference**: Events on the same host within a short window have
  confidence derived from time proximity: `confidence = e^(-delta_t / tau)`
  where `tau` is a configurable decay constant.
- **Key overlap inference**: Events sharing correlation keys but lacking direct
  telemetry linkage have confidence proportional to the weighted score from the
  existing `CorrelationEngine`.
- **Analyst assertion**: Edges added through the review workbench by human
  operators have confidence 1.0 with an `analyst_confirmed` flag.

### 4.5 Graph Properties

An attack graph should maintain these invariants:

1. **Temporal consistency**: For every directed edge (u, v), timestamp(u) <=
   timestamp(v). No effect precedes its cause.

2. **Entity grounding**: Every `TechniqueNode` must be connected to at least one
   `AssetNode` and optionally to `IdentityNode` and `ProcessNode` instances.
   Ungrounded technique observations provide no correlation value.

3. **Provenance**: Every node and edge must reference the source data that
   created it (finding ID, investigation ID, or analyst action). This enables
   the audit trail required by STS's "fail closed on malformed requests"
   convention.

---

## 5. Temporal-Causal Correlation

### 5.1 Problem Statement

Given a stream of `InvestigationBundle` records, each containing a
`threat_class`, `correlation_keys`, `host_id`, `user`, `process_name`, and
timestamps, construct and maintain an attack graph that captures the causal
structure of ongoing intrusions.

The challenge is that causal relationships are rarely directly observed. STS
telemetry provides:

- Process start events with parent-child relationships (direct causation)
- Network connections with process context (association)
- Registry and file persistence events with process context (association)
- Authentication events with user and host context (association)
- DNS queries with process context (association)

From these raw associations, we must infer higher-level causal patterns:
"initial access on host-1 led to credential access which enabled lateral
movement to host-2."

### 5.2 Sliding Window vs Event-Driven Approaches

**Sliding window**: Rebuild the graph from all bundles within a rolling time
window on each new investigation. Simple and deterministic but expensive for
large windows and unable to capture cross-window relationships.

**Event-driven incremental**: Maintain a persistent graph; on each new bundle,
extract entities, create nodes, evaluate edges to existing nodes. O(1)
amortized cost, supports arbitrary time spans and incident evolution
(limitation L4), but requires careful growth management.

**Recommendation**: Adopt the event-driven incremental approach with periodic
graph compaction. The existing `time_window_ms` serves as the default
retention period, with a longer `graph_retention_ms` for slow-moving
intrusions.

### 5.3 Causal Link Detection Algorithms

#### 5.3.1 Process Tree Chaining

When a `ProcessStartEvent` arrives, its `parent_process` field provides a
direct causal link. If the parent process was involved in a prior detection
(identified by matching `process_name` and `host_id` within the graph), a
`CausalEdge` with confidence 1.0 connects the parent's `TechniqueNode` to the
child's `TechniqueNode`.

```
TechniqueNode(Execution, winword, host-1)
    |
    | CausalEdge(confidence=1.0, reason="parent_process match")
    v
TechniqueNode(Execution, powershell, host-1)
```

#### 5.3.2 Credential Pivot Detection

When a credential access event produces a username, and a subsequent event on
a different host authenticates with that username, a `LateralEdge` connects
the two:

```
TechniqueNode(CredentialAccess, mimikatz, host-1)
    |
    | LateralEdge(confidence=0.85, reason="credential pivot: user=admin")
    v
TechniqueNode(LateralMovement, psexec, host-2)
```

The confidence is less than 1.0 because the credential may have been used
legitimately. Confidence increases if the time proximity is tight and the
user account is not a service account.

#### 5.3.3 Network-Based Lateral Movement

When a network connection from host-1 to host-2 is followed by detection
activity on host-2, a `LateralEdge` connects them:

```
TechniqueNode(LateralMovement, host-1)
    |
    | LateralEdge(confidence=0.7, reason="network connection to host-2:445")
    v
TechniqueNode(Execution, host-2)
```

Lower confidence because network connections are common and may be benign.

#### 5.3.4 Temporal Proximity Linking

When no direct causal mechanism is observable but two technique nodes on the
same asset occur within a configurable `causal_proximity_ms` window, a
`TemporalEdge` connects them:

```
TechniqueNode(DefenseEvasion, host-1, T1)
    |
    | TemporalEdge(confidence=0.5, reason="same host within 30s")
    v
TechniqueNode(CredentialAccess, host-1, T2)
```

The confidence formula is: `confidence = base_confidence * e^(-delta_t / tau)`.
With `base_confidence = 0.6` and `tau = 60000` (60 seconds), events 5 seconds
apart score 0.55, events 30 seconds apart score 0.37, and events 5 minutes
apart score 0.004.

### 5.4 Kill Chain Stage Ordering

ATT&CK tactics have a conventional ordering that provides a prior for causal
direction. When two technique nodes have similar timestamps, the kill chain
ordering provides a tiebreaker for edge direction:

```rust
fn tactic_order(threat_class: &ThreatClass) -> u8 {
    match threat_class {
        ThreatClass::InitialAccess => 1,
        ThreatClass::Execution => 2,
        ThreatClass::Persistence => 3,
        ThreatClass::PrivilegeEscalation => 4,
        ThreatClass::DefenseEvasion => 5,
        ThreatClass::CredentialAccess => 6,
        ThreatClass::Discovery => 7,
        ThreatClass::LateralMovement => 8,
        ThreatClass::CommandAndControl => 9,
        ThreatClass::DataExfiltration => 10,
        ThreatClass::Impact => 11,
        ThreatClass::SupplyChain => 0,
        ThreatClass::Custom(_) => 12,
    }
}
```

When `tactic_order(A) < tactic_order(B)` and the timestamp difference is
within `causal_proximity_ms`, the edge direction is A -> B. When
`tactic_order(A) > tactic_order(B)`, either the attacker is revisiting an
earlier stage (allowed) or the ordering is coincidental. In the revisit case,
the edge still follows temporal order (earlier -> later) but is annotated with
a `revisit: true` flag.

---

## 6. Graph Construction from Detections

### 6.1 Entity Extraction Pipeline

Each `InvestigationBundle` arriving at the graph correlation module undergoes
entity extraction to produce graph nodes. The extraction draws on existing
fields in the `InvestigationBundle` struct:

```rust
struct ExtractedEntities {
    technique: TechniqueNode,
    asset: Option<AssetNode>,      // from bundle.host_id
    identity: Option<IdentityNode>, // from bundle.user
    process: Option<ProcessNode>,   // from bundle.process_name
    network: Vec<NetworkNode>,      // from evidence JSON
}
```

The extraction logic mirrors what the `SummaryInvestigator` already does when
building `evidence_points` and `correlation_keys`, but produces structured
graph nodes instead of flat strings.

### 6.2 Evidence JSON Mining

The `InvestigationBundle`'s `evidence_points` field contains structured strings
like `host_id=host-1`, `user=alice`, `process_name=powershell`,
`command_line=powershell.exe -enc AAA=`. The detection finding's `evidence`
JSON field contains richer data:

```json
{
    "source": "synthetic",
    "parent_process": "winword",
    "process_name": "powershell",
    "command_line": "powershell.exe -enc AAA=",
    "user": "alice",
    "host_id": "host-1"
}
```

The graph construction module must parse the evidence JSON to extract:

- **Parent-child process relationships**: `parent_process` + `process_name`
  yields a `CausalEdge` between process nodes.
- **Network connections**: Fields like `remote_address`, `remote_port`, and
  `destination_host` (when present in `NetworkConnectEvent` or `DnsQueryEvent`
  payloads) yield `NetworkNode` instances and `AssociationEdge` entries.
- **File and registry paths**: Persistence-related evidence yields indicators
  of attacker infrastructure.

### 6.3 Incremental Graph Update Protocol

When a new `InvestigationBundle` arrives:

1. **Extract entities** from the bundle (Section 6.1).
2. **Deduplicate** against existing graph nodes. If an `AssetNode` for
   `host-1` already exists, reuse it rather than creating a duplicate.
   `TechniqueNode` instances are never deduplicated (each detection is a
   distinct observation).
3. **Create association edges** between the new `TechniqueNode` and its
   extracted entity nodes (asset, identity, process, network).
4. **Evaluate causal edges** against existing `TechniqueNode` instances
   that share at least one entity node with the new technique. Use the
   `entity_index` to find connected technique nodes in O(degree) rather
   than scanning all technique nodes in O(|V|):
   - Check process tree chaining (Section 5.3.1)
   - Check credential pivot (Section 5.3.2)
   - Check network lateral movement (Section 5.3.3)
   - Check temporal proximity (Section 5.3.4)
5. **Update graph metrics**: Recompute severity scores, depth, and breadth
   (Section 8).
6. **Emit graph events** to the pheromone substrate if the graph structure
   changed meaningfully (new causal edge discovered, new kill chain stage
   reached).

### 6.4 Mapping STS Telemetry Types to Graph Entities

The `TelemetryPayload` enum in `swarm-core::telemetry` (re-exported by
swarm-whisker) defines seven event types. Each maps to a specific entity
extraction pattern:

| Telemetry Type | Asset | Identity | Process | Network | Causal Link |
|---|---|---|---|---|---|
| ProcessStart | host_id | user | process_name + parent_process | -- | parent_process |
| NetworkConnect | host_id | (evidence) | process_name | remote_address:port | -- |
| DnsQuery | host_id | (evidence) | process_name | queried domain | -- |
| RegistryAccess | host_id | (evidence) | process_name | -- | -- |
| RegistryPersistence | host_id | (evidence) | process_name | -- | -- |
| FilePersistence | host_id | (evidence) | process_name | -- | -- |
| AuthenticationEvent | host_id | user | process_name | -- | credential pivot |

The `ProcessStart` type is the richest for graph construction because it
provides a direct `parent_process` causal link. `AuthenticationEvent` is the
most important for lateral movement detection because it reveals credential
usage across hosts.

---

## 7. Graph Storage Approaches

### 7.1 Requirements

The attack graph storage must satisfy:

1. **Low-latency reads**: The review workbench and PounceAgent need
   sub-millisecond graph traversals for scoring and visualization.
2. **Concurrent access**: Multiple agents (Weaver, Stalker, PounceAgent,
   workbench HTTP handlers) may read the graph concurrently.
3. **Incremental writes**: New nodes and edges arrive one investigation at a
   time, not in bulk.
4. **Bounded memory**: The graph must not grow unboundedly. A retention policy
   must prune old subgraphs.
5. **Serializable state**: The graph must be persistable for restart recovery,
   matching the `FileIncidentStore` and `FileInvestigationBundleStore` patterns
   in swarm-spine.
6. **No external dependencies**: STS is a self-contained Rust binary. External
   graph databases (Neo4j, JanusGraph) violate the single-binary constraint.

### 7.2 Option A: In-Memory petgraph

The `petgraph` crate [4] provides a mature, well-tested graph data structure
library for Rust. It supports directed graphs, topological sorting, shortest
paths, and cycle detection.

```rust
use petgraph::stable_graph::StableDiGraph;

type AttackGraph = StableDiGraph<GraphNode, GraphEdge>;
```

**Advantages**: Zero external dependencies. Sub-microsecond node/edge access.
Rich algorithm library (DFS, BFS, Dijkstra, topological sort). Stable node
indices survive removal.

**Disadvantages**: Entire graph must fit in memory. No built-in persistence.
No query language (traversals are imperative Rust code). No built-in
concurrency control.

**Concurrency**: Wrap in `Arc<RwLock<AttackGraph>>`, matching the pattern
used by `MemoryIncidentStore` and `MemoryInvestigationBundleStore` in
swarm-spine (both use `Arc<RwLock<Vec<...>>>`). Note that
`InvestigationCoordinator` uses `Arc<Mutex<>>` for its queue state, so the
codebase has precedent for both synchronization primitives. `RwLock` is
preferred here because graph reads (scoring, visualization, agent queries)
are expected to dominate over writes (investigation ingestion).

**Persistence**: petgraph supports serde serialization behind the `serde-1`
feature flag, enabling direct `serde_json::to_string` / `from_str` on the
graph. Serialize to JSON on a periodic timer and on shutdown; load on
startup. Matches the file-backed store pattern throughout swarm-spine.

**Memory bound**: At 1,000 investigations/hour with 24-hour retention, the
graph holds approximately 120,000 nodes and 360,000 edges -- roughly 60 MB,
well within single-process constraints.

### 7.3 Option B: Embedded Graph Database (indradb / cozo)

Rust-native embedded graph databases (indradb with RocksDB, cozo with Datalog)
offer built-in persistence and query languages but add significant dependency
weight (RocksDB alone adds 20+ MB to binary size), less mature algorithm
support than petgraph, and unfamiliar query paradigms.

### 7.4 Option C: Adjacency List with swarm-spine Storage

A minimal graph abstraction built on top of swarm-spine's file storage pattern
(JSON files per node/edge, in-memory adjacency list) reuses proven patterns
but reimplements graph algorithms from scratch and offers no benefit over
petgraph for in-memory operations.

### 7.5 Recommendation

**petgraph with file-backed persistence** (Option A) is the clear choice for
the STS context:

1. It matches the project's "Rust-first, minimal dependencies" philosophy.
2. The memory requirements are well within bounds for realistic workloads.
3. The `Arc<RwLock<>>` concurrency pattern is already proven in swarm-spine's
   memory-backed stores (with `Arc<Mutex<>>` as a fallback for write-heavy
   paths).
4. petgraph's algorithm library provides topological sort, connected components,
   and DFS/BFS needed for kill chain reconstruction and scoring.
5. petgraph's `serde-1` feature flag provides native serialization, reducing
   the persistence implementation to `serde_json::to_writer` / `from_reader`
   against a single JSON file -- matching the existing `FileIncidentStore`
   recovery pattern with minimal custom code.

Add `petgraph` as a dependency of `swarm-runtime` (or the new `swarm-graph`
module if split into its own crate). Use `StableDiGraph` to ensure node indices
remain valid after deletions during graph compaction.

---

## 8. Scoring and Prioritization

### 8.1 Graph-Based Severity Scoring

Time-window clustering produces a flat severity score: the seed investigation's
severity. Graph-based correlation enables a richer scoring model that considers
the *structure* of the attack.

We propose a composite severity score with four components:

#### 8.1.1 Kill Chain Depth Score

Depth measures how far along the kill chain the attacker has progressed. Count
the number of distinct `ThreatClass` values along the longest path in the
attack subgraph (using `tactic_order` from Section 5.4):

```
depth_score = distinct_tactics_on_longest_path / total_tactic_count
```

An attack that has only reached `Execution` (depth 1/11) scores 0.09. An
attack that has reached `DataExfiltration` through five intermediate tactics
(depth 6/11) scores 0.55. This directly measures how close the attacker is
to achieving objectives.

#### 8.1.2 Kill Chain Breadth Score

Breadth measures how many parallel attack paths exist. Count the number of
connected subgraphs within the incident's attack graph:

```
breadth_score = min(connected_subgraph_count / breadth_normalizer, 1.0)
```

A single linear attack chain scores low breadth. An attacker operating on
multiple hosts simultaneously through different techniques scores high breadth,
indicating a more sophisticated and harder-to-contain intrusion.

#### 8.1.3 Asset Criticality Score

Not all compromised assets are equal. A database server is more critical than
a developer workstation. The asset criticality score weights graph nodes by
their importance:

```
asset_score = max(criticality(asset) for asset in compromised_assets)
```

Where `criticality` returns a value from an `AssetCriticality` enum:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AssetCriticality {
    Low,       // 0.25
    Medium,    // 0.50
    High,      // 0.75
    Critical,  // 1.00
}
```

Initially, asset criticality can default to `Medium` for all assets. As the
asset inventory matures (see 06-Behavioral Baselines), criticality can be
configured per host or derived from behavioral patterns.

#### 8.1.4 Confidence Aggregation

The overall graph confidence is the geometric mean of edge confidences along
the longest causal path:

```
confidence = (product of edge confidences on longest path) ^ (1/path_length)
```

This penalizes long chains of low-confidence links while rewarding chains
where each link is well-supported.

#### 8.1.5 Composite Score

The composite severity score combines all four components:

```
severity = w_depth * depth_score
         + w_breadth * breadth_score
         + w_asset * asset_score
         + w_confidence * confidence

where w_depth=0.35, w_breadth=0.15, w_asset=0.30, w_confidence=0.20
```

The weights reflect the principle that kill chain depth and asset criticality
are the strongest indicators of real damage potential.

### 8.2 Campaign Detection

A campaign is a set of correlated kill chains that share adversary
infrastructure, techniques, or timing patterns. Graph-based correlation
enables campaign detection through cross-incident graph analysis:

**Technique fingerprinting**: If two incidents in different network zones use
the same rare technique sequence (e.g., `T1566.001` -> `T1059.001` ->
`T1003.001`), they may represent the same campaign.

**Infrastructure overlap**: If two incidents involve the same C2 IP addresses
or domains (extracted from `NetworkNode` instances), they likely share an
adversary.

**Temporal clustering**: If multiple incidents begin within a narrow time
window across different assets, they may represent a coordinated attack.

Campaign detection operates at a higher level than incident correlation. It
takes `CorrelatedIncident` records as input (from the existing correlation
engine) and produces `Campaign` records that link multiple incidents.

```rust
pub struct Campaign {
    pub campaign_id: String,
    pub name: Option<String>,
    pub incident_ids: Vec<String>,
    pub shared_infrastructure: Vec<String>,
    pub shared_techniques: Vec<ThreatClass>,
    pub confidence: f64,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}
```

### 8.3 Priority Queue Integration

The review workbench currently lists incidents in reverse chronological order.
Graph-based scoring enables a priority queue that surfaces the most dangerous
incidents first:

```rust
fn incident_priority(incident: &GraphCorrelatedIncident) -> f64 {
    let base = incident.composite_severity_score;
    let recency_bonus = recency_decay(incident.last_activity_ms, now_ms());
    let campaign_bonus = if incident.campaign_id.is_some() { 0.1 } else { 0.0 };
    base + recency_bonus + campaign_bonus
}
```

---

## 9. Provenance Graph Visualization

### 9.1 Operator Requirements

The review workbench exposes incident data to human operators through an HTTP
surface. Graph-based correlation requires visualization capabilities beyond
flat investigation lists.

Operators need to answer these questions:

1. **What happened?** -- Full attack timeline from initial access to current
   state.
2. **What is affected?** -- Which hosts, users, and processes are compromised.
3. **How confident are we?** -- Which links in the chain are well-supported
   and which are inferred.
4. **What comes next?** -- Predicted next kill chain stage based on current
   graph structure.
5. **What should we do?** -- Recommended response actions based on graph
   structure and PounceAgent playbook matching.

### 9.2 Information Density

Graph visualizations fail when they show too much or too little. The STS
operator graph must balance:

- **Node count**: Collapse redundant entity nodes. Show one `AssetNode` per
  host, not one per event. Show `TechniqueNode` instances individually (they
  are the primary analysis unit).
- **Edge rendering**: Show `CausalEdge` and `LateralEdge` instances prominently
  (thick lines, directed arrows). Show `TemporalEdge` instances as dashed
  lines. Suppress `AssociationEdge` instances unless the operator expands a
  node.
- **Temporal layout**: Arrange nodes left-to-right by timestamp, with vertical
  lanes per host. This produces a "swim lane" view that naturally shows lateral
  movement.

### 9.3 Serialization Format

The graph must be serialized to JSON consumable by the operator HTTP surface,
compatible with graph visualization libraries (d3-force, cytoscape.js,
vis-network). The wire format contains `nodes` (typed with id, label, and
type-specific attributes), `edges` (source, target, type, confidence, reason),
and summary metadata (`kill_chain_stages`, `composite_score`, `campaign_id`).

### 9.4 Integration with Review Workbench

The existing review workbench module at
`crates/swarm-runtime/src/workbench/` provides HTTP endpoints for operator
review. Graph visualization adds two new endpoints:

- `GET /api/incidents/:id/graph` -- Returns the attack graph for a specific
  incident in the JSON format above.
- `GET /api/campaigns/:id/graph` -- Returns the cross-incident campaign graph.

The workbench render module (`crates/swarm-runtime/src/workbench/render.rs`)
currently delegates to generated code in `core.inc`. Graph serialization
functions that convert the in-memory `petgraph::StableDiGraph` representation
to the JSON wire format should be added alongside the existing render
pipeline, following the same module structure.

---

## 10. Integration Design

### 10.1 Pheromone Substrate Feedback

Graph-based correlation produces intelligence that should feed back into the
pheromone substrate. When a graph analysis identifies a multi-stage attack,
the resulting pheromone deposit should carry richer metadata than single-event
deposits:

```rust
let indicator = serde_json::json!({
    "graph_incident_id": incident.incident_id,
    "kill_chain_depth": incident.depth_score,
    "kill_chain_stages": incident.observed_tactics,
    "compromised_assets": incident.asset_ids,
    "composite_severity": incident.composite_score,
    "predicted_next_stage": incident.predicted_next_tactic,
});
```

This enriched deposit allows other agents to react to the *structure* of the
attack, not just individual events. A PounceAgent seeing a deposit with
`kill_chain_depth > 0.5` and `predicted_next_stage: "data_exfiltration"` can
preemptively deploy egress blocking before exfiltration is observed.

### 10.2 PounceAgent Response Enhancement

The `PounceAgent` (`crates/swarm-runtime/src/pounce_agent.rs`) currently
selects response actions by matching pheromone deposits against a static
playbook of `ResponsePlaybookRule` entries. Each rule matches on
`threat_class`, `severity`, and `confidence` thresholds.

Graph-based correlation enables context-aware response selection:

**Kill chain depth escalation**: A single `Execution` event might warrant
`DeployDecoy`; the same event in a chain reaching `CredentialAccess` warrants
`RevokeCredential` or `IsolateHost`.

**Lateral movement containment**: When a `LateralEdge` is detected, the
PounceAgent should consider isolating the destination host. The playbook
gains graph-aware rules with `min_kill_chain_depth`, `requires_lateral_movement`,
and `min_compromised_assets` fields.

**Predictive response**: If the graph suggests impending exfiltration (kill
chain progressed through discovery and credential access), the PounceAgent
preemptively tightens egress controls.

### 10.3 Tom Governance Integration

The `TomAgent` governs response authorization through a `GovernancePolicy`.
Graph context informs governance: composite severity below a threshold raises
approval requirements, while kill chain depth above a threshold triggers
automatic escalation from `SwarmMode::Alert` to `SwarmMode::Incident`.

### 10.4 Investigation Feedback Loop

Graph analysis may reveal investigation gaps -- technique nodes with low
confidence or missing connections. The graph module can publish
`GraphInvestigationRequest` pheromone deposits (reinvestigate a finding with
graph context, or probe a hypothesized connection between two technique nodes)
that `StalkerAgent` instances consume, creating a feedback loop where graph
analysis drives further investigation which improves the graph.

---

## 11. Proposed Architecture

### 11.1 Module Placement

We propose a new `GraphCorrelator` component within `swarm-runtime` (not a
separate crate), alongside the existing `CorrelationEngine`:

```
crates/swarm-runtime/src/
    correlation.rs          -- existing time-window correlator (unchanged)
    graph_correlation.rs    -- new: attack graph construction and analysis
    graph_types.rs          -- new: node, edge, and graph type definitions
    weaver_agent.rs         -- extended: invokes graph correlator after
                               time-window correlation
```

The rationale for keeping it in `swarm-runtime` rather than creating a separate
`swarm-graph` crate is that graph correlation is tightly coupled to the agent
lifecycle (it runs inside the Weaver's tick loop) and depends on swarm-spine
types already imported by swarm-runtime.

### 11.2 GraphCorrelator Struct

```rust
use petgraph::stable_graph::StableDiGraph;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct GraphCorrelator {
    config: GraphCorrelationConfig,
    /// Graph, entity index, and finding index share a single lock to ensure
    /// consistency. Separating them behind independent locks would allow a
    /// reader to observe an index entry pointing to a node that has been
    /// removed during compaction.
    state: Arc<RwLock<GraphState>>,
}

struct GraphState {
    graph: StableDiGraph<GraphNode, GraphEdge>,
    /// Index from entity key to node index for deduplication.
    entity_index: HashMap<String, petgraph::graph::NodeIndex>,
    /// Index from finding_id to technique node index.
    finding_index: HashMap<String, petgraph::graph::NodeIndex>,
}
```

### 11.3 Configuration

```rust
pub struct GraphCorrelationConfig {
    pub enabled: bool,
    /// Maximum age of nodes before compaction removes them.
    pub retention_ms: i64,
    /// Maximum time gap for temporal proximity edges.
    pub causal_proximity_ms: i64,
    /// Base confidence for temporal proximity edges.
    pub temporal_base_confidence: f64,
    /// Decay constant for temporal confidence (milliseconds).
    pub temporal_decay_tau_ms: f64,
    /// Minimum edge confidence to retain.
    pub min_edge_confidence: f64,
    /// File path for graph persistence (None = in-memory only).
    pub persistence_path: Option<String>,
    /// Interval between periodic graph persistence writes.
    pub persistence_interval_ms: u64,
    /// Compaction frequency (run every N ingestions).
    pub compaction_interval: usize,
    /// Maximum node count before forced compaction and ingestion rejection.
    pub max_node_count: usize,
}
```

### 11.4 Weaver Agent Extension

The `WeaverAgent` gains an optional `graph_correlator: Option<GraphCorrelator>`
field. In the `tick` loop, after the existing `CorrelationEngine::correlate_hunt`
call succeeds and returns a `CorrelationOutcome`, the Weaver invokes
`graph_correlator.ingest_investigation()` for each investigation bundle
included in the outcome's `CorrelatedIncident`. If the graph update discovers
new causal edges, the Weaver publishes enriched findings containing graph
context (kill chain depth, composite score, predicted next stage) as
`SwarmAction::PublishFindings`.

The current `tick` implementation iterates `investigation_hunts()` from
pheromone deposits, skipping hunts already in `correlated_hunts`. Graph
ingestion must also use `correlated_hunts` as its dedup set to avoid
re-ingesting the same investigation on subsequent ticks. Because `tick`
is `async`, the `RwLock` on the graph must not be held across `.await`
points -- acquire the write lock, perform graph mutations, release, then
read back scores in a separate read lock acquisition.

### 11.5 Data Flow

```
Telemetry
    |
    v
WhiskerAgent (detection) -> PheromoneDeposit
    |
    v
StalkerAgent (investigation) -> InvestigationBundle -> PheromoneDeposit
    |
    v
WeaverAgent
    |
    +---> CorrelationEngine (time-window) -> CorrelatedIncident
    |
    +---> GraphCorrelator (attack graph) -> GraphUpdate
    |         |
    |         +---> entity extraction
    |         +---> edge evaluation
    |         +---> severity scoring
    |         +---> kill chain stage identification
    |
    +---> Enriched PheromoneDeposit (graph context)
              |
              v
         PounceAgent (graph-aware response selection)
              |
              v
         TomAgent (graph-aware governance)
```

### 11.6 Graph Compaction

To prevent unbounded graph growth, the `GraphCorrelator` runs compaction on
a configurable schedule:

1. **Age-based pruning**: Remove all nodes with `timestamp < now - retention_ms`
   and their incident edges. Use `StableDiGraph::retain_nodes` which preserves
   indices of remaining nodes.

2. **Orphan cleanup**: Remove entity nodes (Asset, Identity, Process, Network)
   that no longer have any connected `TechniqueNode` after age-based pruning.

3. **Index rebuild**: Remove stale entries from `entity_index` and
   `finding_index`.

4. **Persistence flush**: Write the compacted graph to disk if
   `persistence_path` is configured.

### 11.7 Error Handling

Following STS conventions, graph correlation errors are non-fatal: if graph
ingestion or analysis fails, the Weaver continues with time-window correlation
alone. Errors are logged and exposed through metrics, not propagated to the
agent tick loop. This ensures that an experimental graph feature cannot
destabilize the proven correlation pipeline.

```rust
pub enum GraphCorrelationError {
    /// Graph lock poisoned (concurrent panic in another thread).
    PoisonedLock,
    /// Entity extraction failed for a specific investigation.
    ExtractionFailed { investigation_id: String, reason: String },
    /// Graph persistence write failed.
    PersistenceFailed { path: String, reason: String },
    /// Graph exceeds configured memory limit.
    MemoryLimitExceeded { current_nodes: usize, limit: usize },
}
```

---

## 12. Open Questions and Future Work

### 12.1 Open Questions

**Q1: Graph vs. flat correlation for operator UX.** The review workbench is
currently built around flat incident lists. Should graph visualization be the
primary view, or should it be a drill-down from the existing list view? The
answer depends on operator skill levels and workload volume.

**Q2: Real-time vs. batch graph analysis.** Section 5.2 recommends event-driven
incremental updates. However, some graph algorithms (connected components,
longest path) are expensive to maintain incrementally. Should these be computed
on-demand when an operator views an incident, or maintained continuously?

**Q3: Cross-tenant graph isolation.** If STS is deployed in a multi-tenant
context, attack graphs from different tenants must not leak. How should tenant
isolation be enforced -- separate graph instances, or tenant-tagged nodes with
access control on queries?

**Q4: Machine learning integration.** Graph neural networks (GNNs) have shown
promise in attack detection [9, 10]. Should STS reserve extension points for
GNN-based analysis, or is deterministic rule-based graph analysis sufficient
for the current milestone?

**Q5: Historical graph replay.** Can completed attack graphs be replayed for
training or post-incident analysis? This requires full serializable provenance
and a replay mode that ingests investigations in chronological order.

**Q6: petgraph serialization stability.** petgraph's `serde-1` feature
provides derive-based serialization that tracks internal representation.
For persistence across petgraph version upgrades, a custom node-list +
edge-list JSON format (as used by the `FileIncidentStore` index pattern)
provides version-decoupled recovery. Start with petgraph's native serde
for simplicity; migrate to a custom format only if a petgraph upgrade
breaks deserialization.

### 12.2 Future Work

**F1: Automated technique classification.** Currently, `ThreatClass` is
assigned by detection strategies. Graph context could refine classification
-- e.g., reclassifying an `Execution` finding as `LateralMovement` when it
occurs immediately after a credential pivot from another host.

**F2: Graph-based anomaly detection.** Establish baseline attack graph
patterns for the monitored environment. Flag deviations from baseline as
anomalous -- e.g., a new lateral movement path that has never been observed.
This connects to 06-Behavioral Baselines.

**F3: Threat intelligence graph enrichment.** Overlay external threat
intelligence (IOCs, adversary profiles, known campaign patterns) onto the
attack graph. A C2 IP address matching a known APT group's infrastructure
immediately elevates the campaign's priority. This connects to 03-Threat
Intel.

**F4: Federated graph correlation.** In multi-node deployments, share graph
summaries across nodes to detect distributed attacks. Connects to distributed
consensus research (sentinel-convergence/01).

**F5: Graph-based evasion resistance.** Adaptive retention windows that extend
when partial kill chains are detected counter adversary fragmentation. Connects
to 01-Evasion.

**F6: Operator annotation persistence.** Allow operators to confirm/reject
edges and add context notes that survive graph compaction.

---

## Cross-References

- **01-Evasion Resistance and Adversarial Robustness**: Section 12.2/F5
  discusses graph-based evasion resistance. Adversaries that deliberately
  fragment kill chains across time windows present a challenge that adaptive
  graph retention can address.

- **02-ATT&CK Coverage and Detection Engineering**: Section 3.2 maps
  `ThreatClass` to ATT&CK tactics and identifies coverage gaps
  (Reconnaissance, Resource Development, Collection). Graph-based
  correlation depends on comprehensive tactic coverage to reconstruct
  complete kill chains.

- **03-Threat Intelligence Integration**: Section 12.2/F3 proposes overlaying
  external threat intelligence onto attack graphs. Campaign detection
  (Section 8.2) benefits directly from IOC matching against `NetworkNode`
  and infrastructure indicators.

- **04-Performance Characterization Under Load**: Graph compaction (Section
  11.6) and memory-bound analysis (Section 7.2) should be validated against
  the throughput benchmarks from the performance characterization work. The
  O(n) edge evaluation in Section 6.3 deserves load-testing under sustained
  ingestion rates.

- **06-Behavioral Baseline and Anomaly Detection**: Section 8.1.3 introduces
  asset criticality scoring that should be informed by behavioral baselines.
  Section 12.2/F2 proposes graph-based anomaly detection using baseline
  attack graph patterns.

- **07-Secure Update and Self-Protection**: Graph persistence files
  (Section 7.2) represent high-value artifacts that an attacker could
  corrupt to blind the correlator. Integrity verification of persisted
  graph state on load should follow the secure update patterns.

---

## References

[1] Hutchins, E. M., Cloppert, M. J., & Amin, R. M. (2011). Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains. *Lockheed Martin Corporation.*

[2] MITRE Corporation. (2024). MITRE ATT&CK Framework. https://attack.mitre.org/

[3] Caltagirone, S., Pendergast, A., & Betz, C. (2013). The Diamond Model of Intrusion Analysis. *Center for Cyber Intelligence Analysis and Threat Research, Hanover, MD.*

[4] Bluss, U., et al. (2024). petgraph: Graph data structure library for Rust. https://github.com/petgraph/petgraph

[5] Noel, S., & Jajodia, S. (2004). Managing Attack Graph Complexity through Visual Hierarchical Aggregation. *Proceedings of the 2004 ACM Workshop on Visualization and Data Mining for Computer Security (VizSEC),* 109--118.

[6] Sheyner, O., Haines, J., Jha, S., Lippmann, R., & Wing, J. M. (2002). Automated Generation and Analysis of Attack Graphs. *IEEE Symposium on Security and Privacy,* 273--284.

[7] Ou, X., Boyer, W. F., & McQueen, M. A. (2006). A Scalable Approach to Attack Graph Generation. *ACM CCS,* 336--345.

[8] Milajerdi, S. M., Gjomemo, R., Eshete, B., Sekar, R., & Venkatakrishnan, V. N. (2019). HOLMES: Real-Time APT Detection through Correlation of Suspicious Information Flows. *IEEE S&P,* 1137--1152.

[9] Han, X., Pasquier, T., Bates, A., Mickens, J., & Seltzer, M. (2020). UNICORN: Runtime Provenance-Based Detector for Advanced Persistent Threats. *NDSS.*

[10] Wang, Q., Hassan, W. U., Li, D., Jee, K., Yu, X., Zou, K., ... & Bates, A. (2020). You Are What You Do: Hunting Stealthy Malware via Data Provenance Analysis. *NDSS.*

[11] King, S. T., & Chen, P. M. (2003). Backtracking Intrusions. *ACM SOSP,* 223--236.

[12] Liu, Y., Zhang, M., Li, D., Jee, K., Li, Z., Wu, Z., ... & Bates, A. (2018). Towards a Timely Causality Analysis for Enterprise Security. *NDSS.*

[13] Alsaheel, A., Nan, Y., Ma, S., Yu, L., Walkup, G., Celik, Z. B., ... & Zhang, X. (2021). ATLAS: A Sequence-Based Learning Approach for Attack Investigation. *USENIX Security,* 3005--3022.

[14] Hossain, M. N., Milajerdi, S. M., Wang, J., Eshete, B., Gjomemo, R., Sekar, R., ... & Venkatakrishnan, V. N. (2017). SLEUTH: Real-time Attack Scenario Reconstruction from COTS Audit Data. *USENIX Security,* 487--504.

[15] Haas, S., & Fischer, M. (2018). GAC: Graph-Based Alert Correlation for the Detection of Distributed Multi-Step Attacks. *ACM SAC,* 979--988.

[16] Navarro, J., Deruyver, A., & Parrend, P. (2018). A Systematic Survey on Multi-Step Attack Detection. *Computers & Security,* 76, 214--249.

[17] Ning, P., Cui, Y., & Reeves, D. S. (2002). Constructing Attack Scenarios through Correlation of Intrusion Alerts. *ACM CCS,* 245--254.
