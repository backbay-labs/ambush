# Gap Analysis: Doc 05 (Kill Chain Reconstruction) and Doc 06 (Behavioral Baselines)

**Date**: 2026-04-08
**Analyst**: Detection Engineering
**Scope**: Cross-document gap analysis covering graph scalability, adversarial resistance, integration complexity, entity resolution, baseline persistence, real-world validation, correlation-baseline interaction, and computational overlap.

---

## Executive Summary

1. **Graph scalability has a sketch but no hard failure mode analysis.** Doc 05 proposes `max_node_count` and age-based compaction but does not define what happens when ingestion rate exceeds compaction rate, nor does it model memory behavior under sustained attack floods where compaction cannot keep pace.

2. **Baseline adversarial resistance is acknowledged but deferred.** Doc 06 Section 14.2 identifies slow poisoning, noise injection, and baseline reset attacks, then explicitly defers formal analysis to "future work" and a cross-reference to Doc 01. The dual-baseline architecture provides partial mitigation for weeks-long poisoning but no mitigation is proposed for multi-week campaigns or reset attacks beyond snapshot recovery.

3. **The two documents propose conflicting ownership of the Weaver tick loop.** Doc 05 extends `WeaverAgent::tick` with graph correlation after time-window correlation. Doc 06 extends the Whisker detection pipeline (pre-Weaver). They do not conflict at an architectural level, but neither document accounts for the other's computational cost in its performance budget.

4. **Entity resolution across telemetry sources is unaddressed in both documents.** Doc 05 proposes five node types (Technique, Asset, Identity, Process, Network) but assumes `host_id` and `user` are globally unique identifiers. No discussion of hostname aliasing, DHCP churn, NAT, or multi-domain user identity federation.

5. **Baseline persistence has a recommendation but no durability contract.** Doc 06 recommends periodic snapshots to a sidecar file but does not specify recovery semantics, data format versioning, or behavior when the snapshot is corrupted or stale.

6. **Neither document validates proposed algorithms against real attack datasets.** Both reference academic work but evaluation plans rely on synthetic corpora and internal replay tests. No DARPA TC, LANL, or MITRE Engenuity evaluation is planned.

7. **The integration path from baseline anomalies to kill chain graphs is implicit, not designed.** Doc 06 baseline findings enter the pheromone substrate as low-confidence deposits. Doc 05 graph construction consumes InvestigationBundles. The bridge (how a baseline finding becomes an investigation bundle that feeds graph construction) relies on the existing Stalker pipeline but neither doc confirms this path handles low-confidence anomaly-sourced events.

8. **Combined per-event overhead is unquantified.** Doc 06 targets <50us p99 per-event for baseline evaluation. Doc 05 does not state a per-event budget for graph ingestion. The combined overhead of baseline evaluation + graph entity extraction + graph edge evaluation on a single event is not modeled.

9. **Count-Min Sketch decay semantics create a silent detection gap.** Doc 06 proposes halving all sketch counters at window boundaries. Immediately after decay, even established patterns appear "rare," creating a burst of false positives at each window rotation. No dampening strategy is proposed.

10. **Graph persistence format is coupled to petgraph internals.** Doc 05 acknowledges this risk (Section 12.1 Q6) but defers it. Since baseline state and graph state both need persistence, a unified serialization strategy would reduce operational risk.

---

## Detailed Findings

### 1. Graph Scalability (Doc 05)

**What is covered**: Section 7.2 estimates ~120K nodes and ~360K edges at 1,000 investigations/hour with 24-hour retention (~60 MB). Section 11.3 defines `max_node_count` and `compaction_interval`. Section 11.6 describes age-based pruning, orphan cleanup, and index rebuild.

**Gaps identified**:

- **Sustained burst behavior**: During an active incident, investigation rate may spike 10-100x above the steady-state 1,000/hour estimate. At 100K investigations/hour, the graph could reach 2.4M nodes within 24 hours -- 1.2 GB without compaction. The document does not model compaction throughput or define backpressure behavior when `max_node_count` is reached.
- **Compaction cost under load**: The `retain_nodes` operation on `StableDiGraph` is O(|V|+|E|). During a burst, compaction may take tens of milliseconds while holding the write lock, blocking all graph reads (scoring, visualization, agent queries). No lock contention analysis is provided.
- **Archival strategy**: Compaction permanently deletes nodes. There is no archival tier for post-incident forensic review. If a kill chain is pruned because it fell outside `retention_ms`, the graph evidence is lost.
- **Subgraph isolation**: The document proposes one monolithic graph per runtime instance. In environments with many unrelated incidents, the graph becomes a disconnected forest where most edge evaluations are wasted. Partitioned subgraphs per incident would be more efficient.

**Priority**: High

**Recommended additions**:
- Model graph size under burst conditions (10x, 50x, 100x steady state).
- Define backpressure semantics: drop, queue, or degrade when `max_node_count` is exceeded.
- Propose a compaction lock-contention strategy (e.g., copy-on-write snapshot for reads, write to shadow graph, swap).
- Add a cold-storage archival path for completed incident subgraphs.
- Evaluate incident-partitioned subgraphs vs. monolithic graph.

---

### 2. Baseline Adversarial Resistance (Doc 06)

**What is covered**: Section 8.1 identifies three types of behavioral change (legitimate drift, adversary-induced, adversary poisoning). Section 8.2 proposes dual-baseline architecture with short-term (alpha=0.10) and long-term (alpha=0.02) EWMA. Section 14.2 lists three attack vectors (slow poisoning, noise injection, baseline reset).

**Gaps identified**:

- **Quantified poisoning resistance**: The document does not calculate how many observations an attacker needs to shift the long-term baseline by 1 sigma. With alpha=0.02, the effective memory is ~50 observations. At one observation per hour, the attacker needs roughly 2-3 days of sustained low-level poisoning to begin shifting the long-term mean. This number should be stated explicitly so operators can assess risk.
- **No integrity verification for baseline state**: If an attacker can write to the baseline snapshot file (Section 14.1), they can directly poison the baseline without gradual shifting. Doc 07 (Secure Update) is cross-referenced but no specific integrity mechanism is proposed for baseline snapshots.
- **Baseline reset attack mitigation**: Doc 06 acknowledges that crashing the agent forces cold-start with reduced confidence. The snapshot-based persistence partially mitigates this, but the document does not specify how quickly a snapshot can be loaded, or what happens if the snapshot is hours stale (drift between snapshot state and current reality).
- **No cross-reference to Doc 01 evasion catalog**: Section 14.2 says "see Doc 01 for fuller treatment" but does not identify which specific evasion techniques from Doc 01 are relevant to baselines. This cross-reference is too vague to be actionable.
- **Noise injection defense is weak**: The defense against noise injection (graduated confidence + pheromone concentration requirements) assumes the attacker generates benign-looking noise. A more sophisticated attack generates noise that mimics real anomaly patterns, saturating the operator's attention with high-fidelity false positives. No defense is proposed for this scenario.

**Priority**: Critical

**Recommended additions**:
- Quantify the poisoning window: how many observations at what rate shift each baseline tier by 1, 2, 3 sigma.
- Propose HMAC or signature verification for baseline snapshot files, reusing the Ed25519 signing infrastructure already present in swarm-spine.
- Define snapshot staleness policy: max acceptable snapshot age, behavior when snapshot is too old (partial cold-start with graduated confidence starting from snapshot observation count, not zero).
- Map specific Doc 01 evasion techniques to baseline attack vectors with concrete mitigations.
- Research "anomaly budget" or operator fatigue models for noise injection defense.

---

### 3. Integration Complexity and Architectural Conflicts (Docs 05 + 06)

**What is covered**: Doc 05 Section 11 places graph correlation inside `WeaverAgent::tick` as a post-correlation step. Doc 06 Section 10 places baseline detectors inside the `CompositeDetector` framework at the Whisker layer, upstream of Stalker and Weaver.

**Gaps identified**:

- **No combined data-flow diagram**: Each document provides its own data-flow diagram (Doc 05 Section 11.5, Doc 06 Section 10.4). Neither shows the other's components. An implementer has no single reference for the combined pipeline: Telemetry -> CompositeDetector (rule + baseline) -> PheromoneDeposit -> StalkerAgent -> InvestigationBundle -> WeaverAgent -> CorrelationEngine + GraphCorrelator.
- **Baseline findings increase Stalker workload**: Every baseline `DetectionFinding` that produces a pheromone deposit creates a hunt ID that the Stalker will attempt to investigate. If baseline detectors produce 10x more findings than rule detectors (plausible given their lower thresholds), Stalker investigation queues will grow proportionally. Neither document analyzes this amplification effect on the `InvestigationCoordinator`'s `max_pending_jobs` (currently 8).
- **Graph ingestion assumes InvestigationBundle fields**: Doc 05's entity extraction (Section 6.1) relies on `host_id`, `user`, `process_name`, `correlation_keys`, and `evidence` fields from `InvestigationBundle`. Baseline-sourced investigations will have different evidence structure (z-scores, rarity metrics) than rule-sourced investigations. The graph entity extraction must handle both evidence schemas, which is not discussed.
- **Lock ordering risk**: Doc 05 uses `Arc<RwLock<GraphState>>` in the Weaver. Doc 06 uses `Arc<RwLock<HashMap>>` in each baseline detector at the Whisker layer. If any code path holds both locks (e.g., a future optimization that feeds graph context back to baseline scoring, as mentioned in Doc 05 F2), a lock ordering violation could cause deadlock. Neither document establishes a lock ordering convention.

**Priority**: High

**Recommended additions**:
- Produce a combined data-flow diagram showing both baseline and graph components in a single pipeline view.
- Model the investigation amplification factor and propose throttling: baseline-sourced findings might use a separate, lower-priority investigation queue with its own `max_pending_jobs`.
- Define a schema contract for evidence JSON that graph entity extraction can rely on, covering both rule-sourced and baseline-sourced evidence.
- Establish a project-wide lock ordering convention for the runtime process.

---

### 4. Entity Resolution (Doc 05)

**What is covered**: Doc 05 Section 4.2 defines five node types (Technique, Asset, Identity, Process, Network). Section 6.3 describes deduplication: reuse existing `AssetNode` when `host_id` matches. Entity index maps entity key strings to node indices.

**Gaps identified**:

- **Hostname instability**: `host_id` comes from the telemetry source. In DHCP environments, the same physical host may report different identifiers after lease renewal. In cloud environments, ephemeral instances generate new host IDs on each deployment. The graph treats these as different assets, fracturing kill chains that span host identity changes.
- **NAT and proxy collapse**: Multiple internal hosts behind a NAT gateway appear as a single `NetworkNode` (the NAT IP). Conversely, the same host may appear as multiple network nodes if it has multiple NICs. No disambiguation strategy is discussed.
- **User identity federation**: `user:alice` on host-1 may be a local account; `user:alice@CORP.LOCAL` on host-2 may be a domain account for the same person. The correlation key namespace treats these as distinct identities. No normalization or federation layer is proposed.
- **Process identity ambiguity**: `process_name: powershell` is not globally unique. Multiple unrelated PowerShell instances on the same host produce identical `ProcessNode` attributes. The graph needs a per-execution unique identifier (e.g., PID + start time) that the current `ProcessStartEvent` struct does not include (`executable_path` and `signer` are optional and often null).

**Priority**: Critical

**Recommended additions**:
- Define an entity resolution strategy: canonical identifiers for hosts (e.g., machine SID or hardware fingerprint), users (UPN normalization), and processes (PID + host + timestamp tuple).
- Propose a host identity table that maps observed `host_id` values to canonical asset identifiers, updated by the entity extraction pipeline.
- Address NAT/proxy collapse with a heuristic: internal network nodes use `host_id + process_name + destination` as the key, not just the destination IP.
- Add `pid` and `start_time` fields to `ProcessStartEvent` telemetry (coordinate with Doc 06 Section 14.5 telemetry schema extensions).

---

### 5. Baseline Persistence and Durability (Doc 06)

**What is covered**: Section 14.1 identifies the restart problem and recommends periodic snapshots to a sidecar file. Population baselines (Section 7.3.1) provide a fallback for cold-start after restart.

**Gaps identified**:

- **No serialization format specification**: The document proposes `Serialize`/`Deserialize` for all baseline structures but does not define a versioned wire format. If the `ProcessBaselineDetector` gains a new field in a future release, old snapshots become unreadable without migration logic.
- **No corruption recovery**: If a snapshot write is interrupted (power failure, OOM kill), the file may be truncated or invalid. No write-ahead pattern (write to temp file, atomic rename) is specified.
- **Snapshot frequency vs. data loss window**: The recommendation is "every 5 minutes." In a burst scenario where the agent processes thousands of events per minute, 5 minutes of baseline learning represents significant state. The snapshot interval should be adaptive (more frequent under high event rates).
- **HyperLogLog persistence complexity**: HLL registers are bit-packed (Section 9.3.3). Serializing and deserializing bit-packed registers requires exact format agreement. The document does not specify whether to serialize the packed representation or unpack to a portable format.
- **Count-Min Sketch window alignment**: After restoring from snapshot, the sketch's decay schedule must align with the wall clock. If the snapshot was taken 3 minutes into a 10-minute window, and the agent restarts 2 minutes later, should the next decay happen in 5 minutes or 10 minutes? This edge case is not addressed.

**Priority**: High

**Recommended additions**:
- Define a versioned snapshot format with a magic number and schema version field.
- Specify atomic write semantics (temp file + rename pattern, matching `FileIncidentStore` conventions).
- Propose adaptive snapshot intervals keyed to event throughput.
- Specify HLL and CMS serialization format (recommend unpacked/portable representation for cross-version compatibility).
- Define window alignment behavior on snapshot restore.

---

### 6. Real-World Validation (Docs 05 + 06)

**What is covered**: Doc 05 references 17 academic papers. Doc 06 Section 13 proposes synthetic corpora, MITRE ATT&CK technique mapping, and replay tests.

**Gaps identified**:

- **No public dataset evaluation**: Neither document plans validation against public attack datasets. The DARPA Transparent Computing (TC) datasets (CADETS, THEIA, TRACE, ClearScope, FiveDirections) provide labeled provenance graphs directly relevant to Doc 05's kill chain reconstruction. The LANL Unified Host and Network Dataset provides authentication and network flow data relevant to Doc 06's baseline detectors.
- **No red team validation plan**: Synthetic corpora test mathematical correctness but not operational effectiveness. A red team exercise where an adversary attempts to evade both rule and baseline detectors, then fragment their kill chain to evade graph correlation, would stress-test the combined system in ways synthetic data cannot.
- **Evaluation metrics for graph correlation are missing**: Doc 05 proposes scoring algorithms (depth, breadth, confidence) but defines no evaluation metrics (precision of kill chain reconstruction, recall of lateral movement edges, false positive rate for campaign detection). Doc 06 provides target AUC-ROC and precision/recall; Doc 05 provides none.
- **No comparison to existing systems**: The academic references include HOLMES, UNICORN, SLEUTH, and ATLAS -- all of which have published evaluation results on public datasets. Doc 05 should compare its proposed approach against these published baselines to establish whether the STS graph correlator will be competitive.

**Priority**: High

**Recommended additions**:
- Add DARPA TC dataset evaluation to Doc 05's validation plan (at minimum, CADETS and THEIA for provenance graph reconstruction).
- Add LANL dataset evaluation to Doc 06's validation plan (authentication logs for AuthBaselineDetector, network flows for NetworkBaselineDetector).
- Define evaluation metrics for Doc 05: kill chain reconstruction precision/recall, lateral movement edge accuracy, campaign detection F1.
- Plan a purple team exercise after initial implementation: red team attempts evasion, blue team operates with the combined baseline + graph system.
- Benchmark against published results from HOLMES and UNICORN on the same datasets.

---

### 7. Correlation-Baseline Interaction Path (Docs 05 + 06)

**What is covered**: Doc 06 Section 10.4 describes compound detection through pheromone concentration (baseline + rule findings producing escalations). Doc 05 Section 10.1 describes graph-enriched pheromone deposits. Doc 06 Section 15 cross-references Doc 05 for "compound detection via graph overlay."

**Gaps identified**:

- **No explicit bridge from baseline finding to graph node**: A baseline `DetectionFinding` enters the standard pipeline: pheromone deposit -> Stalker investigation -> Weaver correlation -> graph ingestion. But the `SummaryInvestigator` (current implementation) extracts correlation keys from the evidence JSON. Baseline evidence uses different field names (`z_arg_count`, `pair_rarity`, `mode`) than rule evidence (`command_line`, `parent_process`, `user`). If the investigator does not extract the same entity fields from baseline evidence, the resulting `InvestigationBundle` will have sparse `correlation_keys`, and the graph entity extraction will produce impoverished nodes.
- **Baseline anomalies as graph context vs. graph nodes**: Should a baseline anomaly ("unusual login time for alice") become a `TechniqueNode` in the attack graph? Or should it be an annotation on an existing `IdentityNode`? Doc 05 treats all detections as `TechniqueNode` instances. But baseline findings are fundamentally different -- they say "this is unusual" rather than "this matches a known attack technique." Making them technique nodes may dilute the graph's signal-to-noise ratio.
- **Feedback from graph to baseline**: Doc 05 Section 12.2/F2 proposes "graph-based anomaly detection using baseline attack graph patterns." Doc 06 Section 14.4 proposes "feedback from investigations to adjust baseline parameters." Neither specifies a concrete mechanism, and the two feedback loops could interact in unpredictable ways (graph analysis changes baseline thresholds, which changes which findings reach the graph, which changes graph analysis).
- **Temporal alignment**: Baseline detectors operate per-event at the Whisker layer (microsecond latency). Graph correlation operates per-investigation at the Weaver layer (millisecond latency, after async Stalker investigation). A baseline anomaly detected at T=0 may not appear in the graph until T=0+investigation_latency. If a rule-based detection at T=0.5 is already in the graph, the temporal ordering of graph nodes may not reflect the true detection sequence.

**Priority**: High

**Recommended additions**:
- Define a standardized evidence schema that both rule and baseline detectors populate, ensuring the `SummaryInvestigator` can extract consistent entity fields for correlation keys and graph nodes.
- Decide whether baseline anomalies become TechniqueNodes (full graph participation) or AnomalyAnnotations (metadata on entity nodes). Document the tradeoffs.
- Defer feedback loops until both systems are independently validated. Feedback introduces coupling that makes each system harder to debug.
- Document the expected temporal skew between baseline detection and graph ingestion, and confirm that the graph's temporal consistency invariant (Section 4.5) uses the original event timestamp, not the ingestion timestamp.

---

### 8. Combined Computational Overhead (Docs 05 + 06)

**What is covered**: Doc 06 Section 13.3 specifies per-event targets: <5us p50, <50us p99 for baseline evaluation. Doc 05 does not specify per-event latency targets but estimates the graph at ~60 MB for realistic workloads.

**Gaps identified**:

- **No combined budget**: The existing rule-based detectors have a per-event budget (Doc 04 cross-reference). Adding baseline evaluation (<50us p99) and graph entity extraction + edge evaluation (unspecified) on the same event produces an additive overhead that is nowhere totaled. If the rule pipeline takes 10us, baselines take 50us, and graph ingestion takes 100us, the combined per-event cost is 160us -- potentially material at high throughput.
- **Graph ingestion is not per-event**: Graph ingestion operates on `InvestigationBundle`, not raw telemetry events. But entity extraction parses the evidence JSON, which may itself embed a serialized `TelemetryEvent`. The cost of JSON parsing during entity extraction is not benchmarked.
- **Lock contention compounds**: Both systems use `RwLock`. During high-throughput periods, baseline detectors and graph correlator readers may contend for CPU time at the OS scheduler level even though they hold different locks. No end-to-end contention analysis spans both subsystems.
- **Memory budgets are independent**: Doc 06 targets 1 MiB per host for baseline state. Doc 05 estimates 60 MB for the graph. These are separate allocations but share the same process heap. Neither document defines a combined memory ceiling or proposes monitoring/alerting when the combined footprint exceeds expectations.

**Priority**: Medium

**Recommended additions**:
- Define a combined per-event latency budget that accounts for rule evaluation + baseline evaluation + (amortized) graph ingestion.
- Benchmark graph entity extraction cost separately from edge evaluation; the former runs per-ingestion and the latter per-edge-candidate.
- Propose a unified memory monitoring strategy that tracks baseline state + graph state + pheromone substrate as a single watermark.
- Run end-to-end load tests with both subsystems active, measuring p50/p99 latency and memory at sustained ingestion rates.

---

### 9. Count-Min Sketch Decay Edge Effects (Doc 06)

**What is covered**: Section 9.4 proposes halving all CMS counters at window boundaries.

**Gaps identified**:

- **Post-decay false positive burst**: Immediately after halving, all counters are half their previous values. The `rarity()` function computes `1 - (count / max_count)`. If max_count was 100 and an item had count 80, its pre-decay rarity is 0.20 (not rare). After decay, max_count=50 and count=40, rarity is still 0.20. However, for items that were recently incremented (count near max), the decay is fine. For items with count near 0, the halving may push them below the integer floor, effectively losing them. Items that had count=1 become count=0 after decay, making them appear completely novel on next observation.
- **Window boundary synchronization across detectors**: If `ProcessBaselineDetector` and `NetworkBaselineDetector` both use CMS with different window sizes, their decay schedules are unsynchronized. A finding from one detector may have high rarity (just after decay) while the other has low rarity (just before decay), producing inconsistent anomaly signals.
- **No smooth decay alternative**: A smooth decay (multiply by a factor on every observation rather than halving at boundaries) would avoid the step-function artifact. The document does not evaluate this alternative.

**Priority**: Medium

**Recommended additions**:
- Analyze the false-positive profile around window boundary decay events.
- Propose per-observation exponential decay as an alternative to periodic halving (multiply each counter by a decay factor on every query, keyed to elapsed time).
- If periodic decay is retained, implement a post-decay dampening period where the rarity threshold is temporarily relaxed.
- Synchronize decay schedules across detectors or use per-observation decay to eliminate boundary effects.

---

### 10. Unified Persistence Strategy (Docs 05 + 06)

**What is covered**: Doc 05 proposes petgraph serde serialization to a JSON file (Section 7.2, 11.6). Doc 06 proposes periodic snapshots to a sidecar file (Section 14.1). The existing codebase uses `FileIncidentStore` and `FileInvestigationBundleStore` with JSON files and index files in swarm-spine.

**Gaps identified**:

- **Four independent persistence mechanisms**: swarm-spine file stores (existing), graph persistence (Doc 05), baseline snapshots (Doc 06), and pheromone substrate journal (existing). Each has its own write schedule, format, and recovery logic. No unified persistence layer is proposed.
- **Consistency across stores**: On restart, graph state, baseline state, investigation state, and incident state must be mutually consistent. If the graph references an investigation that was not persisted (different write schedules), the graph contains dangling references. Neither document addresses cross-store consistency.
- **Disk I/O contention**: Four persistence mechanisms writing to the same filesystem introduce I/O contention during flush operations. On edge deployments with slow storage (SD cards, NFS mounts), this could be material.

**Priority**: Medium

**Recommended additions**:
- Propose a coordinated persistence flush: all stores write in a single coordinated checkpoint, using a monotonic sequence number for cross-store consistency.
- Evaluate whether a single embedded key-value store (e.g., sled, redb) would simplify persistence while maintaining the single-binary constraint.
- Define recovery semantics when stores are inconsistent: which store is authoritative, and how to detect/repair cross-store drift.

---

## Priority Summary

| # | Finding | Priority |
|---|---------|----------|
| 2 | Baseline adversarial resistance -- quantified poisoning, integrity, reset defense | Critical |
| 4 | Entity resolution -- host/user/process identity across telemetry sources | Critical |
| 1 | Graph scalability -- burst behavior, compaction cost, archival | High |
| 3 | Integration complexity -- combined data flow, investigation amplification, lock ordering | High |
| 5 | Baseline persistence -- format versioning, corruption recovery, window alignment | High |
| 6 | Real-world validation -- public datasets, red team, evaluation metrics for graph | High |
| 7 | Correlation-baseline interaction -- evidence schema, node type decision, temporal skew | High |
| 8 | Combined computational overhead -- unified latency/memory budget | Medium |
| 9 | CMS decay edge effects -- post-decay false positives, smooth decay alternative | Medium |
| 10 | Unified persistence strategy -- coordinated checkpoints, cross-store consistency | Medium |
