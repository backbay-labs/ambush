<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

## Objective

Deliver the first vertical slice of collective cyber reasoning. A suspicious seed signal must produce a shared, versioned causal theory that agents can contest, refine, and eventually hand to containment planning. The product is collective epistemology, not concurrent detector execution.

## Required shape

- A typed, serializable graph contains actor, asset, credential, process, and event nodes plus typed causal edges. Every edge carries confidence, provenance, source evidence IDs, producer role, observation time, and schema version.
- Ambiguous evidence creates competing attack hypotheses. Each hypothesis retains confidence distribution, uncertainty, contradiction set, and decision history; a new classification cannot erase live alternatives without an adjudicated transition.
- Hunter, challenger, and falsifier roles claim unresolved graph edges through a durable stigmergic task ledger. Claims use leases, idempotency keys, evidence scope, and explicit complete/fail/expired state so duplicate investigation work is measurable.
- Process, identity, Kubernetes audit, CloudTrail, network, and threat-intelligence telemetry enter one evidence envelope with source lineage and clock/ordering metadata. Conflicting signals remain visible rather than being silently averaged away.
- A converged incident reconstructs a kill chain. Every node, edge, stage assignment, and narration claim links to evidence or explicitly reports missing evidence.
- Containment options are simulations only. Ranking includes predicted blast radius, reversibility, evidence support, and required approval; any live action remains behind the existing policy, receipt, and operator-approval path.
- Completed investigations emit persistent strategy memory containing hypothesis deltas, evidence utility, falsified alternatives, outcomes, and provenance. Retrieval can prioritize work but cannot authorize action.

## Measurement contract

Compare the swarm with a single-agent control on an adjudicated corpus. Report median time to correct causal hypothesis, attack-chain recall, false causal-edge rate, duplicate investigation work, and evidence coverage. Pass thresholds are at least 20% lower median hypothesis time, +10 percentage points chain recall, false edges at or below 10%, duplicate work at or below 5%, and evidence coverage at or above 90%.

The evidence model must not overclaim ordering. A post-action receipt does not by itself prove receipt-before-action; crash and restart cases should report at-most-once or unknown outcomes unless a protocol-level proof establishes a stronger guarantee.

### Claude's Discretion

No `## Claude's Discretion` section is present in `286-CONTEXT.md`; implementation choices remain researcher/planner discretion within the required shape.

### Deferred Ideas (OUT OF SCOPE)

## Non-goals

No direct response execution, irreversible classification, raw-telemetry memory export, or external GitHub App enforcement belongs in this phase.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| COG-01 | Versioned serializable actor/asset/credential/process/event graph with typed causal edges and confidence/provenance/evidence/role/time/schema validation. | `swarm-core` typed records, immutable canonical IDs, bounded validation, and `swarm-crypto` signatures; see Architecture Patterns 1 and 2. |
| COG-02 | Ambiguous seeds retain at least two competing hypotheses with confidence distributions, uncertainty, contradiction sets, and decision history. | Append-only hypothesis/decision model and non-destructive adjudication rules; see Architecture Pattern 3. |
| COG-03 | Durable hunter/challenger/falsifier task claims with lease, idempotency, evidence scope, terminal state, and <=5% duplicate work on 100 tasks. | Fenced CAS ledger design based on governance persistence; duplicate/restart/fencing tests in Validation Architecture. |
| COG-04 | Process, identity, Kubernetes audit, CloudTrail, network, and threat-intelligence events share one lineage/clock-aware evidence envelope; conflicts remain visible. | Existing bridge mapping seams plus a new typed envelope and explicit ordering claims; see Architecture Pattern 4. |
| COG-05 | Kill-chain reconstruction preserves stage order and requires evidence IDs for nodes, edges, stages, and narration, reporting missing evidence. | Typed `KillChainClaim`/`MissingEvidence` records and withheld multi-stage fixture; see Architecture Pattern 5. |
| COG-06 | Containment options are ranked simulations only, scored by blast radius/reversibility/evidence/approval, with no response execution. | Separate planner module consuming existing rehearsal previews but not response executors or leases; see Architecture Pattern 6. |
| COG-07 | Completed investigations persist typed strategy memory without raw telemetry and deterministically reprioritize applicable work on replay. | Signed immutable memory records, redacted retrieval, and replay priority test; see Architecture Pattern 7. |
| COG-08 | Checked-in benchmark reports five metrics and enforces the stated collective-vs-control thresholds. | Deterministic logical-time metrics, checked-in manifest, exact test execution wrapper, and non-gating wall-clock observations; see Validation Architecture. |
</phase_requirements>

# Phase 286: Collective Hypothesis Graph - Research

**Researched:** 2026-08-21
**Domain:** Rust typed causal graph, signed evidence provenance, durable fenced task coordination, deterministic replay benchmarking
**Confidence:** HIGH for repository seams and dependency versions; MEDIUM for the proposed new public type names

## Summary

Phase 286 is not a graph visualization or a larger version of the current Sphinx graph. The current code has useful adjacent pieces—normalized `TelemetryEvent` variants, a signed Sphinx snapshot, `InvestigationBundle` interpretations, `CorrelatedIncident` dimensions, and a signed pheromone substrate—but none of those records has the complete COG contract. In particular, existing graph edges have no evidence lineage or bounded admission, interpretations are mutable-looking `Vec<String>` summaries, Stalker/Weaver duplicate suppression is process-local, and the existing local file stores do not provide compare-and-swap semantics.

The plan should introduce a dependency-safe vertical slice: typed immutable graph/evidence/hypothesis records in `swarm-core`; durable graph, task-ledger, and strategy-memory stores in `swarm-spine`; deterministic normalization, adjudication, kill-chain, containment-planning, and benchmark orchestration in `swarm-runtime`; and thin hunter/challenger/falsifier integration in `swarm-agents`. Existing ingest bridges remain source parsers. Existing response policy, receipt, executor, and containment-lease paths remain the only live-action authority and must not be imported by graph planning.

Every durable claim must be identified by canonical bytes and independently witnessed by the cryptographic base identity derived from its Ed25519 public key. A scoped role/agent label is not an independent source. Task claiming must use a durable generation/digest CAS plus lease fencing, and the same logical operation sequence must yield the same result on memory and file backends. Benchmark verdicts must use fixture event times, logical task steps, and adjudicated truth; `Instant`/wall-clock values may be recorded as observations but must never decide COG-08.

**Primary recommendation:** Build one append-only, bounded `HypothesisGraph`/`EvidenceEnvelope` model with a fenced `HypothesisTaskLedger`, and make all graph-derived outputs evidence-linked advisory artifacts that cannot construct or execute a `ResponseAction`.

## Current Repository Reality

| Existing seam | What it provides | Why it is insufficient for COG |
|---|---|---|
| `crates/swarm-core/src/telemetry.rs::TelemetryEvent` and `TelemetryPayload` | Typed process, network, DNS, CloudTrail, Kubernetes audit, authentication, registry, persistence, and infrastructure payloads. | It has only `source`, `event_id`, second-resolution timestamp, optional host, and payload. It has no immutable evidence ID, source lineage, clock precision/order claim, producer witness, or conflict record. Several payloads still contain unbounded `serde_json::Value`. |
| `crates/swarm-runtime/src/sphinx_agent.rs` | Durable Sphinx `KnowledgeGraphSnapshot`, typed nodes/edges, signed snapshot load, observation dedupe, and memory query/answer pheromones. | Node taxonomy is ThreatPattern/AttackTechnique/Entity/Engagement/DeceptionAsset, not actor/asset/credential/process/event. Edges lack confidence/evidence IDs/producer role/schema metadata; upsert/prune is mutable and unbounded; local file persistence has no cross-process CAS/fencing. It is an enrichment component, not the COG authority. |
| `crates/swarm-spine/src/investigation.rs` | Durable `InvestigationBundle`, interpretations, votes, final decision, memory/local-file stores. | `supporting_evidence` and rationale are strings; one decision can hide alternatives; no contradiction history, evidence envelope, immutable versions, or task leases. Use it as an integration seam only, or add typed references without treating it as the graph model. |
| `crates/swarm-runtime/src/correlation.rs` and `swarm-spine/src/incident.rs` | Deterministic correlation when an explicit timestamp is supplied, typed temporal/causal/entity/semantic dimensions, durable incidents. | Correlation links are not evidence IDs and the incident has no ordered kill-chain claims or missing-evidence semantics. Extend through typed references, not stringifying a graph into `graph_dimensions`. |
| `crates/swarm-agents/src/stalker_agent.rs` and `weaver_agent.rs` | Async investigation and correlation flow, signed pheromone deposits, local `HashSet` dedupe. | `HashSet`s disappear on restart and cannot coordinate concurrent workers. They cannot prove duplicate work <=5%. Route roles through the durable ledger. |
| `crates/swarm-pheromone/src/substrate.rs` | Ed25519 deposit validation, admission, `agent_identity`, scoped `agent_id`, and `independent_source_identity` that re-verifies persisted reads. | This is the correct identity precedent, not a complete graph store. Reuse its base-identity rule and signature checks. Do not count scoped IDs or role names as independent witnesses. |
| `crates/swarm-response/src/containment.rs` and `swarm-runtime/src/service/preview.rs` | Dry-run `ResponseRehearsalPreview`, blast-radius/rollback previews, and existing policy/receipt/lease boundary. | The graph must not call an executor, mint a capability/containment lease, or turn a preview into authority. |
| `crates/swarm-governance/src/lib.rs` | Signed state, OS lock binding, sequence + digest CAS, atomic temp-write/rename/directory sync, stale-snapshot tests, fence-like sequence advancement. | It is the durability pattern to copy into a graph/task store; do not depend on private governance types or pretend the existing Sphinx/replay file stores are CAS-safe. |

## Standard Stack

No new third-party dependency is required. The workspace lock was inspected on 2026-08-21 (`cargo tree --workspace --locked`); the relevant resolved versions are listed below. Workspace crates are all currently `0.1.0`. Do not add a graph database or a second canonicalization/signing implementation in this phase.

### Core

| Library/crate | Verified version | Purpose | Why standard here |
|---|---:|---|---|
| `swarm-core` | 0.1.0 | Public serializable graph, evidence, hypothesis, task, kill-chain, simulation, memory, config, and validation types. | Lowest shared layer; runtime, spine, agents, and tests already depend on it. |
| `swarm-crypto` | 0.1.0 | RFC 8785 canonical JSON (`canonical_json_bytes`), SHA-256 IDs, Ed25519 key/signature wrappers. | Repository TCB explicitly owns the byte representation used for signatures and hashes. |
| `swarm-spine` | 0.1.0 | Durable graph snapshot, task-ledger, strategy-memory stores and incident references. | Spine owns durable records and explicitly does not authorize, correlate, or execute. |
| `swarm-runtime` | 0.1.0 | Normalization, graph admission/adjudication, role task planning, kill-chain reconstruction, containment simulation, benchmark orchestration. | Existing correlation, investigation, replay, containment, and bridge composition live here. |
| `swarm-agents` | 0.1.0 | Hunter/challenger/falsifier role adapters around the ledger. | Existing Stalker/Weaver agent implementations are here; keep role execution thin and state in the ledger. |

### Supporting

| Library/crate | Verified version | Purpose | When to use |
|---|---:|---|---|
| `serde` | 1.0.228 (locked) | Derive typed wire records; `deny_unknown_fields` on persisted/admission types. | Every graph/evidence/task/memory payload. Avoid `serde_json::Value` in the COG schema. |
| `serde_json` | 1.0.149 (locked) | Intermediate canonicalization and existing bridge payload decoding. | Convert typed records to canonical bytes through `swarm-crypto`; retain raw vendor JSON only at the ingest boundary, never in strategy memory. |
| `serde_yaml` | 0.9.34+deprecated (locked) | Checked-in benchmark fixture/manifest files, matching existing replay manifests. | Parse a dedicated COG benchmark manifest with strict validation. |
| `ed25519-dalek` | 2.2.0 (locked) | Ed25519 verification where the existing core/pheromone APIs require the raw key. | Verify a producer/witness before graph admission; derive `AgentId` from the public key. |
| `sha2` / `hex` | 0.10.9 / 0.4.3 (locked) | Available through workspace; use `swarm-crypto::sha256_hex` for stable IDs. | Only direct use is justified for a lower-layer implementation that cannot depend on the wrapper. |
| `tokio` / `async-trait` | 1.52.3 / 0.1.89 (locked) | Async agent/store boundaries and notification; deterministic clock stays injected. | Use for worker integration, not for lease expiry timing or benchmark verdicts. |
| `chrono` | 0.4.44 (locked) | Existing source timestamp parsing. | Parse CloudTrail/Kubernetes RFC3339 input before converting to the evidence clock model. |
| `prometheus-client` | 0.23.1 (locked) | Operational counters/gauges and wall-clock observations. | Export task/edge/evidence observations; keep COG pass/fail report as typed deterministic data. |
| `proptest` | 1.x workspace dev dependency (resolved through lock) | Bounds, canonical-ID, serialization, malformed-edge, and replay properties. | Add property tests for finite confidence, resource limits, and idempotent operations. |
| `uuid` | 1.23.1 (locked) | Existing runtime identifiers only. | Do not use random UUIDs for graph/evidence/task identity; IDs must be content-derived or manifest-derived. |

**Installation:** None. Use the current workspace dependencies; do not introduce a graph DB, async lease library, or new metrics library.

**Version verification:** `cargo tree --workspace --locked` on 2026-08-21 resolved `serde 1.0.228`, `serde_json 1.0.149`, `serde_yaml 0.9.34+deprecated`, `ed25519-dalek 2.2.0`, `sha2 0.10.9`, `hex 0.4.3`, `tokio 1.52.3`, `async-trait 0.1.89`, `chrono 0.4.44`, `prometheus-client 0.23.1`, `uuid 1.23.1`, and `thiserror 2.0.18`. Cargo metadata does not expose registry publication dates; the lockfile is the reproducibility authority, so upgrade dates are outside this phase.

## Architecture Patterns

### Recommended Project Structure

```text
crates/swarm-core/src/
├── hypothesis_graph.rs       # bounded typed nodes/edges, evidence, hypotheses, roles
├── telemetry.rs              # existing source-normalized payloads (keep source adapters)
├── signed_state.rs           # existing signed-state verification seam
└── config/                  # HypothesisGraphConfig and strict limits/store settings

crates/swarm-spine/src/
├── hypothesis_graph_store.rs # graph snapshots, immutable evidence, CAS task ledger
├── strategy_memory.rs       # append-only signed/redacted memory records and retrieval
├── incident.rs              # typed incident references and persistence integration
└── store.rs                 # existing replay store; do not treat plain writes as CAS

crates/swarm-runtime/src/
├── hypothesis_graph/
│   ├── mod.rs               # admission/coordinator public API
│   ├── normalize.rs         # TelemetryEvent/ThreatIntel -> EvidenceEnvelope
│   ├── hypotheses.rs        # seed, confidence, contradiction, adjudication
│   ├── tasks.rs             # role-specific task generation and deterministic ordering
│   ├── kill_chain.rs        # evidence-linked ordered reconstruction
│   ├── containment_plan.rs  # simulation-only options/ranking
│   └── benchmark.rs         # manifest runner and deterministic COG-08 report
├── correlation.rs           # existing correlation; consume typed graph references
└── service/preview.rs       # existing dry-run preview builder, never an authority

crates/swarm-agents/src/
├── stalker_agent.rs         # hunter/challenger/falsifier role adapter changes
└── weaver_agent.rs          # graph/kill-chain handoff, no live response capability

scenarios/collective-hypothesis-graph/
├── *.yaml                   # six source families, ambiguity, conflicts, withheld stages
└── manifest.yaml            # adjudicated truth, controls, limits, metric thresholds

docs/benchmarks/
├── collective-hypothesis-graph.md
└── collective-hypothesis-graph-baseline.json

tools/check-collective-hypothesis-graph.sh
```

Keep the graph data model in `swarm-core`, persistence in `swarm-spine`, and orchestration in `swarm-runtime`; this avoids a `swarm-core -> spine` cycle and prevents agents from owning durable state. If the implementation instead leaves all records in the 3,000-line `sphinx_agent.rs`, the planner must explicitly account for public-type extraction, module layering, and tests; a local patch to Sphinx’s existing node enums is not enough.

### Pattern 1: Typed, bounded, immutable graph records

**What:** Define strict structs/enums for `ActorNode`, `AssetNode`, `CredentialNode`, `ProcessNode`, `EventNode`, `CausalEdge`, and `HypothesisGraph`. Use `#[serde(deny_unknown_fields)]` on each persisted struct and a `schema_version` on every top-level record and edge. Make IDs content-derived (`GraphNodeId`, `EvidenceId`, `EdgeId`) from canonical typed bytes. Store edges and hypothesis decisions append-only; a later record supersedes/rejects an earlier one rather than mutating or deleting it.

**Required edge shape:**

```rust
pub struct CausalEdge {
    pub schema_version: u32,
    pub edge_id: EdgeId,
    pub from: GraphNodeId,
    pub to: GraphNodeId,
    pub relation: CausalRelation,
    pub confidence_basis_points: u16, // 0..=10_000; no NaN f64
    pub source_evidence_ids: BTreeSet<EvidenceId>,
    pub producer_role: GraphProducerRole, // hunter/challenger/falsifier/etc.
    pub producer_identity: AgentId,        // base swarm:ed25519 identity
    pub observed_at_ms: i64,
    pub state: EdgeState,                  // unresolved/proposed/validated/rejected
    pub supersedes: Option<EdgeId>,
}
```

`admit_edge` must reject unknown node IDs, unsupported schema versions, empty evidence for a proposed/validated edge, out-of-range confidence, invalid producer identity/signature, observation timestamps that violate the declared clock contract, and resource-limit overflows. `BTreeMap`/`BTreeSet` and stable tie-breaks are required for canonical serialization and replay parity.

**When to use:** Every graph mutation, snapshot, kill-chain claim, and memory reference. Do not expose public setters that can bypass validation.

**Resource limits:** Put explicit caps in `GraphResourceLimits`: max nodes, edges, evidence IDs per edge, hypotheses, contradiction/decision entries, serialized bytes, task count, and memory records. Validate before cloning/allocating large collections and return a named `ResourceLimitExceeded` error. Persist limits with the manifest/config and include them in the deterministic report.

### Pattern 2: Base cryptographic identity is an independent witness

**What:** Verify the detached Ed25519 signature over canonical bytes, derive `AgentId::from_verifying_key`, and compare that exact base identity with the admitted registry identity before accepting evidence or an edge. Keep a separate `producer_role` field for Hunter/Challenger/Falsifier. Never count `agent_id` values with scope suffixes, role labels, or claimed public-key strings as independent sources.

The repository already establishes this in `swarm-pheromone`: `validate_deposit_signature` checks the signature, derives the base ID, allows a scoped `agent_id` only as a scope, and requires `agent_identity` to equal the key-derived ID. `independent_source_identity` re-verifies persisted records at read time and deliberately ignores scoped IDs. COG graph admission should use the same invariant, preferably through a shared core validation helper rather than copying a weaker string check.

For snapshots or memories, use `SignedStateEnvelope` only when its stream/signer/sequence semantics match the artifact. For evidence/edge IDs and cross-backend replay, compute `swarm_crypto::canonical_json_bytes(&record)` and `swarm_crypto::sha256_hex(&bytes)` first. If signing that record directly, sign those canonical bytes with `swarm_crypto::Keypair` and persist the public key/signature; do not rely on `serde_json::to_vec` field order as a new signature protocol.

**When to use:** At ingress and again on persisted read/replay. A valid signature from an unadmitted key is not an admitted witness; a matching role string without a key is not a witness.

### Pattern 3: Competing hypotheses are append-only epistemic state

**What:** A seed creates at least two `Hypothesis` records when ambiguity exists (for example, malicious execution and authorized automation). Each has a `ConfidenceDistribution` over fixed integer buckets whose sum is 10,000 basis points, explicit `UncertaintyReason` values, a `BTreeSet<ContradictionId>`, and an append-only `DecisionRecord` history. A detector classification is an observation/claim, not an irreversible replacement.

```rust
pub struct Hypothesis {
    pub schema_version: u32,
    pub hypothesis_id: HypothesisId,
    pub graph_version: u64,
    pub claims: BTreeSet<EdgeId>,
    pub confidence: BTreeMap<ConfidenceBucket, u16>,
    pub uncertainty: BTreeSet<UncertaintyReason>,
    pub contradiction_ids: BTreeSet<ContradictionId>,
    pub decision_history: Vec<DecisionRecord>,
    pub status: HypothesisStatus,
}
```

Only an explicit adjudication record may retire an alternative, and it must reference the evidence/contradiction resolution and the adjudicating base identity. Retired hypotheses remain queryable for metrics and falsified-alternative memory. Never implement “classification update” as `Vec::retain` over live alternatives.

**When to use:** Seed admission, evidence updates, challenger/falsifier results, incident convergence, and replay. Deterministic ordering is by hypothesis ID then decision sequence, never arrival order from an async worker.

### Pattern 4: One immutable evidence envelope, source-specific adapters

**What:** Keep the current source parsers and map their typed outputs into a common `EvidenceEnvelope` in `swarm-runtime::hypothesis_graph::normalize`. The envelope should contain:

```rust
pub struct EvidenceEnvelope {
    pub schema_version: u32,
    pub evidence_id: EvidenceId,          // hash of canonical envelope
    pub source_family: EvidenceSourceFamily,
    pub source_id: String,
    pub source_record_id: String,
    pub lineage: SourceLineage,            // adapter, upstream IDs, parent refs
    pub clock: EvidenceClock,              // observed time, precision, source/ingest
    pub ordering: OrderingClaim,           // source sequence/partial/unknown
    pub payload: TypedEvidencePayload,     // no raw telemetry Value
    pub witness: EvidenceWitness,         // signed, admitted base identity
}
```

`EvidenceClock` must distinguish source-observed time from ingestion time and include precision/uncertainty. `OrderingClaim` must support `SourceSequence`, explicit declared-before links, same-time/partial order, and `Unknown`; absence of an order is not proof of concurrency or causality. Preserve each conflicting envelope and add a typed `ConflictRecord` referencing both evidence IDs and the comparison basis instead of averaging values.

Map existing seams as follows:

- Tetragon `map_process_exec` -> `Process` evidence, preserving `exec_id`, node, parent, process, UID, and source timestamp/fallback marker.
- `AuthenticationEventData`, CloudTrail principals/MFA/source IP, and Kubernetes `user`/impersonation -> `Identity` evidence. Do not silently equate a CloudTrail principal with a local OS user; retain the lineage and confidence of the join.
- Kubernetes `KubernetesAuditBridge` -> `KubernetesAudit` evidence, retaining audit ID, stage, source IPs, verb, resource, request/response data as typed bounded projections.
- `CloudTrailBridge` -> `CloudTrail` evidence, retaining event ID/name/source, principal, account, source IP, request/response hashes or bounded typed fields, and error state.
- Existing `NetworkConnectEvent`/`DnsQueryEvent` -> `Network` evidence; process-to-destination links require an explicit edge claim and evidence IDs.
- `TaxiiPoller::parse_taxii_bundle`/`ThreatIntelEntry` -> `ThreatIntel` evidence with feed/indicator ID, indicator type/value digest, expiry, and confidence. Treat feed confidence as evidence metadata, not proof of causality.

The phase’s six source-family fixture must contain at least one corroborating and one conflicting signal for each family. `Sentinel` infrastructure events can remain supplemental; do not silently count them as one of the six COG-04 families unless the manifest explicitly says so.

**When to use:** All evidence entering a graph, including synthetic replay and agent-produced evidence. Store immutable envelopes by evidence ID and make duplicate exact envelopes idempotent; a same-ID/different-content collision is a hard error.

### Pattern 5: Kill-chain claims are evidence-linked projections

**What:** Build `KillChainReconstruction` from graph nodes/edges and an explicit ordered list of `KillChainClaim` records. A claim references one or more evidence IDs, the graph object IDs it assigns, a fixed stage enum, declared predecessor/order information, and a narration claim whose support is also evidence-linked. Missing support is represented by `MissingEvidence {claim_id, expected_scope, reason}`, never by an invented link or inferred timestamp.

Use the existing `CorrelatedIncident` as the durable incident shell, adding typed graph/kill-chain references rather than stuffing opaque JSON into `graph_dimensions`. The withheld multi-stage fixture should remove one source or edge and assert that all available stage order is retained while the report names the missing evidence. A post-action receipt must not be used to assert that an action preceded a later event unless the protocol has a signed sequence/chain proof; report `AtMostOnce` or `Unknown` where crash/restart leaves ordering unresolved.

**When to use:** Only after graph convergence/adjudication. A single detector result can seed a hypothesis but cannot produce a converged kill chain by itself.

### Pattern 6: Containment planning is a pure simulation boundary

**What:** Add a pure `ContainmentPlanner`/`ContainmentSimulation` in runtime. It consumes a typed incident/kill-chain projection and emits `ContainmentOption` values with `predicted_blast_radius`, `reversibility`, `evidence_support`, `required_approval`, deterministic rank/tie-break, and the existing `ResponseRehearsalPreview` where applicable. It may call `build_rehearsal_preview` because that path is explicitly simulation-only.

The planner module must not depend on `swarm-response` executors, `CapabilityLease`, `ContainmentLeaseStore`, `Dispatcher`, or governance receipt minting. A live handoff, if later selected, must be a separate typed request routed through the existing policy -> governance/approval -> receipt -> dispatcher path. Graph confidence, correlation, Sphinx memory, or a strategy-memory score must never be accepted as a response authority token.

**When to use:** COG-06 ranking and operator review only. Add a negative compile/dependency test or source-boundary check proving the graph planner cannot construct/execute a response.

### Pattern 7: Typed strategy memory, retrieval as prioritization only

**What:** Persist an immutable, signed `StrategyMemory` with `memory_id`, schema/version, graph/hypothesis identity, hypothesis delta (added/retracted/superseded edge IDs), evidence utility observations, falsified alternative IDs, outcome, provenance/evidence references, and producer base identity. Exclude raw `TelemetryEvent`, command lines, request objects, and arbitrary `serde_json::Value` from this type. If a redacted feature is needed for retrieval, use bounded enums/digests or stable indicator IDs.

Retrieval should return `StrategyMemoryMatch` (relevance, bounded features, provenance refs) and feed a deterministic task priority function only when the current graph/source-family context matches. A replay must produce the same priority/order with or without an irrelevant memory. Sphinx can expose this through its existing enrichment path, but it cannot authorize or execute; do not treat `SphinxMemoryAnswer` as the new authority or export raw graph telemetry through it.

**When to use:** On completed investigation/adjudication, restart/replay, and benchmark memory-enabled control. Memory writes should be append-only and deduplicated by canonical memory ID; tampered/replayed signatures fail closed.

### Pattern 8: Fenced durable task ledger, backend-independent semantics

**What:** Introduce typed `TaskId`, `TaskKind` (`AcquireEvidence`, `ChallengeEdge`, `FalsifyHypothesis`), `EvidenceScope`, `TaskClaimRequest`, `TaskLease`, `TaskState`, `FencingToken`, and `TaskCompletion`. Derive `idempotency_key = sha256(canonical(task target + role + evidence scope + operation))`. A claim either returns the existing same-key claim (idempotent) or atomically wins a lease; a different live holder receives `AlreadyClaimed`.

The durable store must retain a monotonically increasing generation and predecessor digest. Every mutation reads and verifies the current signed/hashed state, compares `(generation, digest)`, writes the next record atomically, and returns `StalePredecessor` on mismatch. Lease expiry is driven by an injected `now_ms`, advances the fencing token, and does not let a stale holder complete/fail a task. Completion/failure/expiry are terminal records; preserve history for duplicate metrics. A restart must rehydrate the ledger and enforce the same fencing rule.

Implement memory and local-file backends behind one trait and run the same deterministic operation log against both. The local backend needs an OS lock for the lifetime of the store, `create_new` temporary files, file `sync_all`, rename, parent-directory sync, lock identity/generation binding, and startup signature/digest verification. Existing `FileKnowledgeGraphStore`, `FileReplayBundleStore`, and `FileContainmentLeaseStore` use plain writes or in-process locks and are not sufficient by themselves.

**When to use:** Every hunter/challenger/falsifier claim and terminal transition. Async worker queues may notify workers, but queue memory is not the source of truth.

## Plan-Sized Work Decomposition

The planner should keep the following dependency order. Each item is a bounded implementation slice with a testable contract; do not create one giant “collective graph” task or hide the CAS/authority boundary inside an agent integration task.

### Wave 0: Contracts, limits, fixtures, and test seams

1. Add strict `HypothesisGraphConfig`, `GraphResourceLimits`, schema-version constants, injected `GraphClock`, and typed ID/error scaffolding in `swarm-core`.
2. Add the COG fixture manifest and truth model under `scenarios/collective-hypothesis-graph/`: ambiguous seed, six source families, corroborating/conflicting pairs, withheld stage, expected edge/stage/evidence IDs, and fixed logical timestamps.
3. Create unit/integration test targets and the benchmark wrapper before implementation. Pin exact test execution and fail-closed manifest validation, including the 100-task duplicate fixture shape.

**Exit:** strict records can be constructed only through validated helpers; malformed manifests and over-limit inputs fail; all future tests compile against stable type seams.

### Wave 1: Immutable evidence and cryptographic witness admission

1. Implement typed `EvidenceEnvelope`, `EvidenceSourceFamily`, `SourceLineage`, `EvidenceClock`, `OrderingClaim`, `EvidenceWitness`, and `ConflictRecord` in `swarm-core`/runtime normalization.
2. Adapt existing CloudTrail, Kubernetes audit, Tetragon/process, authentication/identity, network/DNS, and TAXII/threat-intel bridges without duplicating source parsers. Add bounded projections for currently raw JSON fields.
3. Reuse canonical bytes, Ed25519 verification, `AgentId::from_verifying_key`, and admission registry checks. Add tamper, wrong-key, unadmitted-key, scoped-ID, duplicate, and same-ID/different-content tests.

**Exit:** every COG fixture event becomes one immutable envelope with lineage/clock/order metadata; conflicts remain two records plus a typed conflict; no role label is accepted as an independent witness.

### Wave 2: Graph schema, edge validation, competing hypotheses, and adjudication

1. Implement typed actor/asset/credential/process/event nodes, causal relations, immutable `CausalEdge`, `HypothesisGraph` versioning, and bounded admission.
2. Implement seed-to-two-hypothesis creation, integer confidence distributions, uncertainty/contradiction records, append-only decision history, and evidence-required adjudication.
3. Add serialization/property tests, graph reload validation, canonical ID/replay parity, and negative tests proving classification cannot erase an unresolved alternative.

**Exit:** COG-01 and COG-02 are independently green against malformed, conflicting, over-limit, and ambiguous fixtures.

### Wave 3: Durable task ledger and role adapters

1. Implement `HypothesisTaskLedger`/`TaskStore` traits, idempotency-key derivation, evidence scopes, task state machine, lease/fencing records, injected-time expiry, and deterministic priority/tie-breaks.
2. Implement memory and local-file stores with signed/hashed generation+digest CAS, OS lock binding, atomic sync/rename, restart revalidation, and explicit stale-predecessor errors. Copy governance persistence patterns rather than existing plain-write stores.
3. Route Stalker/Weaver (and the hunter/challenger/falsifier role adapters) through the ledger. Preserve terminal claim history and count actual redundant evidence work for the duplicate metric.
4. Add two-writer, stale completion, expiry/reclaim, restart, same-sequence-different-digest, and 100-task duplicate tests on both backends.

**Exit:** COG-03 proves <=5% duplicate work and no stale holder can commit after fencing; a backend-independent logical operation log yields identical canonical state.

### Wave 4: Kill-chain reconstruction and simulation-only containment

1. Implement ordered `KillChainStage`, `KillChainClaim`, `MissingEvidence`, narration-support records, and reconstruction from converged graph state. Extend `CorrelatedIncident` with typed references rather than opaque graph dimensions.
2. Implement withheld-evidence behavior and explicit unknown/at-most-once ordering outcomes; add lineage tests for every node, edge, stage, and narration claim.
3. Implement pure `ContainmentPlanner`/`ContainmentSimulation` ranking by predicted blast radius, reversibility, evidence support, and required approval. Reuse response preview data only; add compile/source boundary tests showing no executor, capability lease, or receipt construction is reachable.

**Exit:** COG-05 and COG-06 are green; the planner can produce an operator-facing dry-run option but cannot execute or authorize a live action.

### Wave 5: Typed strategy memory and deterministic retrieval

1. Implement append-only signed/redacted `StrategyMemory`, evidence-utility records, hypothesis delta/falsified-alternative/outcome types, memory store, and bounded retrieval matches.
2. Emit memory on completed investigation/adjudication, verify signatures/admission on load, and ensure raw telemetry cannot be represented or returned.
3. Feed only applicable retrieval matches into deterministic task prioritization; add replay/restart/privacy tests for applicable, irrelevant, tampered, and replayed memories.

**Exit:** COG-07 proves memory changes priority deterministically only for matching context and never supplies response authority.

### Wave 6: Benchmark/report gate and combined-tree assurance

1. Implement the single-agent control and collective lane over the same fixture manifest, logical clock, source evidence, adjudicated truth, and resource limits.
2. Calculate the five COG-08 metrics with explicit denominators, compare all values to the checked-in baseline/threshold manifest, and retain wall-clock measurements as non-gating observations.
3. Wire `tools/check-collective-hypothesis-graph.sh` with exact test-run assertions, metric extraction, missing/extra-field failures, and mutation controls for truth, thresholds, source families, and test names.
4. Run package/unit/property/negative tests and the full workspace suite on the combined tree; verify `git diff --check`, format, clippy, fixture cleanliness, and no response-authority imports.

**Exit:** COG-08 passes the stated 20%/10pp/10%/5%/90% thresholds on the checked-in corpus, with deterministic report values and separate truthful wall-clock observations.

## Don't Hand-Roll

| Problem | Don’t build | Use instead | Why |
|---|---|---|---|
| Canonical IDs/signature bytes | `serde_json::to_vec` as a new signing protocol, ad-hoc key IDs, or role strings as identity | `swarm_crypto::canonical_json_bytes`, `sha256_hex`, `Keypair`/`PublicKey`, and `AgentId::from_verifying_key` | Field/map ordering and key binding must be stable across backends and independent readers. |
| Independent-source counting | `HashSet<agent_id>` or `HashSet<role>` | `validate_deposit_signature` + base `agent_identity`, following `independent_source_identity` | Scoped IDs are intentionally not independent witnesses; persisted reads must be reverified. |
| Telemetry parsing | A second CloudTrail/Kubernetes/Tetragon/TAXII parser inside graph code | Existing `CloudTrailBridge`, `KubernetesAuditBridge`, Tetragon mapper, `TaxiiPoller`, and typed `TelemetryPayload` adapters | Existing tests already pin source mapping and fail-closed malformed records. |
| Durable task claims | A `HashSet`, in-memory queue, plain `fs::write`, or “last writer wins” JSON index | A graph-specific CAS/fenced ledger modeled on `swarm-governance`’s signed sequence/digest persistence | Restart, two writers, stale completion, and crash-after-rename cases otherwise create duplicate or lost work. |
| Response simulation | A graph-owned executor, capability/containment lease, or fake receipt | Existing `build_rehearsal_preview`/`ResponseRehearsalPreview`, then existing policy/receipt/operator path for any future live handoff | COG-06 explicitly forbids execution and graph-derived authority. |
| Kill-chain truth | A causal edge inferred from timestamps alone or a free-form incident narrative | Evidence-linked `KillChainClaim`, explicit `OrderingClaim`, and `MissingEvidence` | Timestamp equality/ingest order do not prove causal order; withheld evidence must remain visible. |
| Strategy memory | Persisting `TelemetryEvent`, raw command lines, request objects, or whole graph JSON | Typed signed `StrategyMemory` with bounded feature/digest references | COG-07 forbids raw-telemetry memory export and later herd-memory phases need a clean abstraction. |
| COG benchmark gate | A wall-clock latency threshold, a bare `cargo test` name filter, or hand-edited numbers | Replay-style checked-in manifest, exact test-run assertion, canonical deterministic report, and separate operational observations | Existing project evidence shows a filter can match zero tests while exiting 0 and a wall-clock stall can flip a verdict on identical fixtures. |

**Key insight:** The hard part is not traversing nodes; it is making every mutation independently attributable, bounded, replayable, and unable to silently become authority. The type boundaries and durable CAS protocol are the feature.

## Common Pitfalls

### Pitfall 1: Counting scoped role IDs as independent witnesses

**What goes wrong:** `swarm:ed25519:<key>:hunter-a` and `swarm:ed25519:<key>:challenger-b` are counted as two sources even though one key produced both.

**Why it happens:** Existing Stalker deposits intentionally use scoped `agent_id` while preserving base `agent_identity`.

**How to avoid:** Verify the signature, derive the base `AgentId` from the public key, require admission of that exact base identity, and use only it for source diversity/edge witness checks. Keep role/scope as metadata.

**Warning signs:** Duplicate metric looks good only when role names change; a forged `agent_identity` string passes without signature verification.

### Pitfall 2: “Classification update” deletes live alternatives

**What goes wrong:** A detector writes `malicious=true`, drops authorized-automation hypothesis, and later cannot explain contradictory evidence or false causal edges.

**Why it happens:** Existing investigation bundles contain a selected interpretation and a boolean `ambiguous` decision rather than an append-only decision history.

**How to avoid:** Seed two hypotheses for ambiguous input, append claims/votes/contradictions, and retire an alternative only through an evidence-linked adjudication record. Preserve falsified alternatives for COG-07.

**Warning signs:** A replay’s hypothesis count decreases after new evidence without a decision record; contradiction sets are empty despite conflicting fixture signals.

### Pitfall 3: Unproven or malformed edges enter the graph

**What goes wrong:** An edge with an unknown node, unsupported schema, empty evidence list, NaN/out-of-range confidence, or unadmitted producer is persisted and later appears as causal truth.

**Why it happens:** Public structs and `serde_json::Value` make construction easy, while current Sphinx `upsert_edge` merges without COG validation.

**How to avoid:** Make admission the only constructor path, use integer basis points, strict serde schemas, explicit evidence/state rules, and validate persisted records again on load.

**Warning signs:** `serde_json::from_value` accepts unknown fields; graph load does not revalidate signatures/limits; report contains an edge with no evidence ID.

### Pitfall 4: Graph resource bounds are checked after allocation

**What goes wrong:** A large evidence list or nested raw payload consumes memory before a limit check, or a snapshot grows indefinitely through decision history.

**Why it happens:** Limits are often treated as config for query results, not as admission invariants.

**How to avoid:** Bound serialized input and collection lengths before cloning, cap all nested lists/history, reject over-limit records, and expose limit failures in health/metrics. Test every cap with generated inputs.

**Warning signs:** `Vec::extend`/`serde_json::Value` occurs before `GraphResourceLimits::check`; no maximum for contradiction history or memory payload bytes.

### Pitfall 5: Memory and local backends disagree

**What goes wrong:** Memory dedupes/replaces by ID while file replay or restart produces a second task, different ordering, or a different hash.

**Why it happens:** Existing memory/local stores have similar APIs but different persistence and sorting behavior; plain file indices are not transactions.

**How to avoid:** Define operation semantics above the backend, drive both backends with the same fixed logical clock and canonical operation log, compare canonical snapshots/reports, and test restart before/after every terminal state.

**Warning signs:** Tests cover only `Memory`; IDs include wall-clock/UUID; output order depends on `HashMap` or async completion order.

### Pitfall 6: Lease expiry does not fence stale workers

**What goes wrong:** Worker A’s lease expires; worker B claims the task; A later completes and overwrites B’s result.

**Why it happens:** Lease ID/expiry is checked but no durable generation/fencing token is required on completion.

**How to avoid:** Store `(generation, digest, lease_id, fencing_token)`; advance the token on expiry/reclaim; require exact token and predecessor CAS for complete/fail. Add a barrier-controlled stale completion test.

**Warning signs:** `complete(task_id)` accepts no lease/fence token; a stale store instance can write after a fresh instance commits; same generation with different bytes is accepted.

### Pitfall 7: Graph planning becomes a response authority

**What goes wrong:** A high-confidence edge or Sphinx answer directly constructs `ResponseAction`, a capability lease, or a receipt.

**Why it happens:** Existing runtime functions can build previews and execute through adjacent services, making an import shortcut tempting.

**How to avoid:** Keep `containment_plan.rs` pure and dependency-separated; output only simulation options. Require a distinct existing policy/approval/receipt path for live actions and add a negative boundary test.

**Warning signs:** Graph module imports `swarm-response` executor/lease types; `StrategyMemoryMatch` appears in a policy decision; tests assert only a simulated receipt but call an executor.

### Pitfall 8: Ingest order is mistaken for event order

**What goes wrong:** A CloudTrail receipt or file write observed after an action is narrated as proof that the action occurred before a later event, including after crash/restart.

**Why it happens:** Bridges expose timestamps and `BridgeHealth` lag but no source sequence/clock uncertainty; current correlation uses temporal windows.

**How to avoid:** Preserve source timestamp, ingest timestamp, precision, source sequence where present, and `Unknown` ordering. Require explicit protocol chain evidence for stronger claims and report `AtMostOnce`/`Unknown` otherwise.

**Warning signs:** `sort_by(timestamp)` is the only ordering logic; `created_at_ms` is wall-clock from the current process; narration says “before” with no source evidence ID.

### Pitfall 9: Wall-clock observations decide deterministic metrics

**What goes wrong:** Scheduler load changes median hypothesis time or a latency threshold flips the COG verdict on identical fixtures.

**Why it happens:** Existing runtime captures `Instant` stage latency and had to demote it to a non-gating observation.

**How to avoid:** Define hypothesis time from fixture event/seed time and logical task steps; run fixed seeds and deterministic ordering. Record `Instant` latency in a separate observation field only.

**Warning signs:** `SystemTime::now()`/`Instant::now()` occurs in metric scoring, benchmark pass/fail, or task ordering; report timestamps differ between identical replays.

### Pitfall 10: A test filter or baseline hides missing coverage

**What goes wrong:** A renamed/deleted graph benchmark still exits 0, or a checked-in baseline is never read.

**Why it happens:** Bare Cargo filters report success with zero tests; prior benchmark tooling had this exact gap.

**How to avoid:** Use `--exact`, assert the named `test ... ok` line and exactly one pass, parse every printed metric, compare against the checked-in JSON, and fail on missing/extra fields.

### Pitfall 11: Raw telemetry leaks through memory or reports

**What goes wrong:** A strategy memory stores the entire replay bundle or command line and later exports it through Sphinx/strategy retrieval.

**Why it happens:** Existing `DetectionFinding`, pheromone indicator, and Sphinx contribution models use `serde_json::Value` for flexibility.

**How to avoid:** Make COG memory types unable to contain raw telemetry by construction; store bounded enums, hashes, evidence IDs, and provenance. Add a serialization test that rejects raw payload fields and a restart/retrieval test that returns no raw event.

## Code Examples

Verified repository patterns to reuse (adapt names, do not bypass validation):

### Canonical ID and signed witness

```rust
use swarm_core::types::AgentId;
use swarm_crypto::{canonical_json_bytes, sha256_hex, Keypair, Signer};

let bytes = canonical_json_bytes(&typed_evidence)?;
let evidence_id = EvidenceId(format!("evidence:{}", sha256_hex(&bytes)));
let signature = signer.sign(&bytes);
let base_identity = AgentId::from_public_key_hex(&signer.public_key().to_hex());
// Admission must compare this derived identity with the registry and verify
// the signature over `bytes`; a scoped role ID is only metadata.
```

The concrete repository APIs are `swarm_crypto::canonical_json_bytes`, `swarm_crypto::sha256_hex`, `Keypair::sign`/`PublicKey::verify`, and `AgentId::from_verifying_key`. `swarm-pheromone::validate_deposit_signature` is the reference for checking signature, base identity, and scoped IDs together.

### Signed state stream verification

```rust
let verified = envelope.verify(SignedStateExpectation {
    state_kind: GRAPH_STATE_KIND,
    stream_id: graph_id.as_str(),
    expected_signer_agent_id: Some(&admitted_base_identity),
    accepted_sequence: Some(previous_sequence),
})?;
```

This is the exact `swarm_core::signed_state::SignedStateEnvelope`/`SignedStateExpectation` pattern used by Sphinx and governance for signer, stream, and replay checks. For new evidence/edge signatures, still canonicalize the record explicitly before signing; the signed-state wrapper’s statement encoding is its existing protocol and should not be silently reinterpreted.

### Deterministic logical clock and task expiry

```rust
pub trait GraphClock: Send + Sync {
    fn now_ms(&self) -> i64;
}

fn expire_claims(ledger: &mut LedgerState, now_ms: i64) {
    for task in ledger.tasks.values_mut() {
        if task.state == TaskState::Claimed
            && task.lease.as_ref().is_some_and(|lease| lease.expires_at_ms <= now_ms)
        {
            task.expire_and_advance_fence();
        }
    }
}
```

The runtime’s containment and replay code already injects `now_ms` for expiry/replay. Use the same pattern; do not call `SystemTime` from the graph coordinator.

### CAS commit boundary

```rust
let current = store.load_version_and_digest()?;
if current.sequence != expected.sequence || current.digest != expected.digest {
    return Err(GraphStoreError::StalePredecessor {
        expected_sequence: expected.sequence,
        observed_sequence: current.sequence,
        ..
    });
}
let next = state.next_sequence()?;
store.write_atomic_synced(next, &canonical_bytes(next_state)?)?;
```

The implementation must add the lease/fencing token to this CAS, not just copy a sequence counter. `swarm-governance` tests `sequence_cas_refuses_the_exact_stale_double_consume_snapshot` and `cas_rejects_a_different_trusted_statement_at_the_expected_sequence` are the required adversarial shape: reject stale snapshots even when sequence numbers match but predecessor bytes differ, and do not mutate the stale caller’s in-memory state.

### Deterministic benchmark report

```rust
let logical_hypothesis_time_ms = first_correct_hypothesis_at_ms
    .saturating_sub(manifest.seed_time_ms);
let report = CollectiveMetrics {
    median_hypothesis_time_ms: median(logical_times),
    attack_chain_recall: ratio(recovered_truth_edges, truth_edges),
    false_causal_edge_rate: ratio(false_edges, admitted_edges),
    duplicate_work_rate: ratio(redundant_claim_executions, total_claim_executions),
    evidence_coverage: ratio(covered_adjudicated_evidence, adjudicated_evidence),
    wall_clock_observations: observations_from_runtime_metrics,
};
```

The report’s pass/fail uses only the five fixture-derived values and the manifest thresholds. Existing `replay::metrics::observe_experiment_detect_latency_delta` and `helpers::latency_observation` show the correct posture for wall-clock values: retain and print them as explicitly non-gating observations.

## State of the Art

| Existing approach | Current Phase 286 approach | Impact |
|---|---|---|
| Sphinx `KnowledgeGraphSnapshot` with mutable upsert/prune | Append-only bounded `HypothesisGraph` with typed COG node taxonomy and versioned edge records | Supports contestability, resource ceilings, and reproducible replay. |
| `InvestigationInterpretation` strings + one `InvestigationDecision` | Confidence distributions, uncertainty, contradictions, and decision history | Alternatives remain live until evidence-linked adjudication. |
| Stalker/Weaver process-local `HashSet` dedupe | Durable idempotency-keyed claims with leases and fencing | Duplicate work and stale workers become measurable and safe across restart. |
| `TelemetryEvent` source/payload/timestamp | Immutable `EvidenceEnvelope` with source lineage, clock precision, ordering claims, and witness | Conflicting/cross-source evidence is preserved without causal overclaim. |
| Correlation dimensions/summary | Evidence-linked ordered kill-chain claims + explicit missing evidence | Narration can be audited and withheld stages cannot be invented. |
| Rehearsal preview adjacent to response | Pure ranked `ContainmentSimulation` | Graph reasoning can recommend without inheriting response authority. |
| Sphinx memory pheromone contributions | Typed redacted `StrategyMemory` with deterministic retrieval priority | Memory informs task order only and cannot export raw telemetry/authorize action. |
| Wall-clock benchmark latency as a gate | Logical fixture-time metrics; wall-clock as observation | Identical inputs produce identical verdicts on different machines. |

**Deprecated/outdated for this phase:**

- Treating Sphinx’s existing graph as the COG schema: it lacks required node/edge provenance and bounds.
- Treating `InvestigationBundle` `Vec<String>` evidence as typed provenance.
- Treating a local JSON/index write or process-local `HashSet` as a durable CAS ledger.
- Treating a response rehearsal/receipt as proof of live action or causal order.
- Reopening the deferred external GitHub App enforcement or retired DST/FUZZ/LOOM/Red Swarm gates; Phase 286 consumes the Phase 285 boundary.

## Open Questions

1. **Where should registry admission for graph producer keys live?**
   - What we know: `swarm-pheromone::AdmissionControl` enforces admitted base identities but is crate-private; `docs/AGENTS.md` requires persisted Ed25519 identity/registry admission.
   - What is unclear: whether Phase 286 should expose a shared core registry trait or have runtime configure the existing substrate admission.
   - Recommendation: define a small `GraphWitnessRegistry` trait in `swarm-core`/graph types and adapt the substrate registry; never bypass admission or duplicate a string-only allow-list. Keep role labels separate from key identity.

2. **How much distributed transport is required by the durable ledger?**
   - What we know: current repository scope explicitly avoids uncontrolled multi-node/gossip, and the task requirement is backend-independent replay/idempotence plus durable CAS/fencing.
   - What is unclear: whether a JetStream task adapter is needed in this phase or whether memory + local files are the accepted vertical slice.
   - Recommendation: implement and parity-test memory and local-file stores first; expose a transport-neutral trait. Add JetStream only if the phase plan has a concrete existing substrate integration and can prove identical idempotency/fencing semantics; do not claim distributed failover from an isolated test.

3. **Which exact kill-chain taxonomy is the adjudicated truth?**
   - What we know: existing Sphinx has `SemanticRelation::KillChainStage`; scenario manifests carry technique metadata; COG requires declared order, not a particular vendor taxonomy.
   - What is unclear: whether the fixture should use ATT&CK tactic IDs, a local stage enum, or both.
   - Recommendation: choose one checked-in `KillChainStage` enum with stable order indices and optional ATT&CK IDs as typed metadata. Put expected stages/evidence IDs in the manifest so recall is measurable rather than inferred from labels.

4. **How should response previews map predicted blast radius to existing action variants?**
   - What we know: `build_rehearsal_preview` already provides deterministic simulated action previews and rollback data; the response layer owns action execution and leases.
   - What is unclear: the exact policy table for predicted scope/capability impact for every simulated option.
   - Recommendation: define a runtime-owned deterministic table for the COG fixture, reuse `ResponseBlastRadiusPreview`/`ResponseRollbackPreview` as data only, and require evidence support plus approval class. Keep conversion to a live request outside the graph planner.

5. **How should raw source fields be retained for audit without entering memory?**
   - What we know: CloudTrail/Kubernetes payloads currently contain `serde_json::Value`; COG-07 forbids raw-telemetry memory export, while evidence lineage may need audit pointers.
   - What is unclear: whether the phase can persist a bounded raw evidence blob or only a hash/reference.
   - Recommendation: keep raw vendor records at the ingest/replay fixture boundary, persist only typed projections plus content hash and source-record pointer in `EvidenceEnvelope`, and make the strategy-memory type unable to hold raw blobs. If raw retention is required later, add a separate access-controlled evidence archive rather than widening memory.

## Validation Architecture

Validation is enabled because `.planning/config.json` has `workflow.nyquist_validation: true`. The implementation plan must create tests before or alongside each behavior; an isolated green worktree is not phase evidence. Run final checks on the combined tree.

### Test Framework

| Property | Value |
|---|---|
| Framework | Rust `cargo test`/libtest; `proptest 1.x` for properties; `trybuild 1.0` for compile-boundary tests; Criterion 0.5 exists for benchmarks but COG pass/fail must be fixture-deterministic. |
| Config files | No COG-specific config yet. Existing package manifests are `crates/swarm-core/Cargo.toml`, `crates/swarm-spine/Cargo.toml`, `crates/swarm-runtime/Cargo.toml`, and `crates/swarm-agents/Cargo.toml`; replay manifests use strict YAML types in `swarm-runtime/src/replay/types.rs`. |
| Quick unit command | `cargo test -p swarm-core hypothesis_graph --lib` (then equivalent `swarm-spine hypothesis_graph_store` and `swarm-runtime hypothesis_graph`). |
| Quick integration command | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact <test_name> --nocapture` once the target exists. Assert that the exact test ran; Cargo exits 0 for zero matches. |
| Full suite command | `cargo test --workspace --all-targets --locked`; pair with `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features -- -D warnings`. |
| Benchmark gate | Future `bash tools/check-collective-hypothesis-graph.sh`; it must read `docs/benchmarks/collective-hypothesis-graph-baseline.json`, assert exact tests executed, parse all metrics, and reject missing/extra fields. |

### Metric Definitions (must be fixed before implementation)

| Metric | Deterministic definition | Not allowed |
|---|---|---|
| Median time to correct causal hypothesis | Median of `first_correct_hypothesis_event_time - manifest.seed_time_ms` over adjudicated cases, using fixture/source logical time; define no-correct-hypothesis as a documented miss/censoring value before calculating. | `Instant::elapsed`, worker wall time, or async completion order. |
| Attack-chain recall | `truth-linked node/edge/stage claims recovered / adjudicated truth claims`, with truth and withheld evidence named in manifest. | A detector label or narrative that has no evidence IDs. |
| False causal-edge rate | `admitted causal edges not in adjudicated truth / all admitted causal edges`, including edges later rejected; report denominator. | Counting only final selected hypothesis, hiding rejected edges. |
| Duplicate investigation work | `redundant claim executions for the same idempotency key / total claim executions` across the 100-task fixture and restarts. Same-key idempotent retries that do no work are not duplicate work; a second worker doing evidence work is. | Number of distinct IDs or process-local HashSet size. |
| Evidence coverage | `adjudicated evidence IDs linked by at least one accepted graph/kill-chain claim / all adjudicated evidence IDs`, including conflict/withheld metadata as specified by manifest. | Treating an unlinked source record or a wall-clock receipt as coverage. |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test type | Automated command | File exists? |
|---|---|---|---|---|
| COG-01 | All five node kinds and causal relations round-trip through strict serialization; malformed/unknown/unproven edges, invalid witness, unsupported schema, and resource overages reject; canonical IDs are stable. | Unit + property | `cargo test -p swarm-core hypothesis_graph --lib -- --exact graph_` and `cargo test -p swarm-core hypothesis_graph_proptest --lib` | ❌ Wave 0 |
| COG-02 | Ambiguous seed creates >=2 hypotheses; distributions sum to 10,000; contradictions and decisions append; classification cannot erase a live alternative; adjudication requires evidence. | Unit/state machine | `cargo test -p swarm-runtime --lib -- hypothesis_competing` | ❌ Wave 0 |
| COG-03 | 100 identical logical tasks across hunter/challenger/falsifier claims are idempotent, duplicate work <=5%; lease expiry/reclaim advances fence; stale completion/failure and stale snapshot fail; restart preserves terminal state. | Integration + concurrency/barrier + property | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact duplicate_claim_fixture_100 --nocapture` | ❌ Wave 0 |
| COG-04 | Each process/identity/Kubernetes/CloudTrail/network/threat-intel adapter maps to one strict envelope; fixture has corroborating and conflicting signal per family; source lineage and unknown/partial order survive round-trip. | Adapter unit + integration | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact cross_telemetry_fixture_preserves_conflicts` | ❌ Wave 0 |
| COG-05 | Kill-chain node/edge/stage/narration claims all have evidence IDs; withheld multi-stage input preserves declared order and emits `MissingEvidence`, never an invented edge. | Integration + negative fixture | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact withheld_kill_chain_reports_missing_evidence` | ❌ Wave 0 |
| COG-06 | Ranking is deterministic and simulation-only; graph planner cannot execute, mint leases, or bypass policy; live conversion remains existing approval/receipt path. | Unit + compile/source boundary + integration | `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact containment_plan_is_simulation_only` and `cargo test -p swarm-runtime --test negative_graph_response_boundary` | ❌ Wave 0 |
| COG-07 | Completed memory persists signed typed delta/utility/falsified alternatives/outcome/provenance; raw telemetry is absent; replay retrieves applicable memory and deterministically changes task priority only when context matches. | Store restart + privacy + replay integration | `cargo test -p swarm-spine strategy_memory --lib` and `cargo test -p swarm-runtime --test collective_hypothesis_graph -- --exact memory_replay_changes_priority_deterministically` | ❌ Wave 0 |
| COG-08 | Collective and single-agent control run identical checked-in manifests; report all five metrics and exact thresholds; repeated runs/backend parity have identical deterministic values; wall-clock load changes only observations. | Benchmark integration + mutation/negative controls | `bash tools/check-collective-hypothesis-graph.sh` | ❌ Wave 0 |

### Cross-backend and adversarial controls

The planner should require these tests in addition to happy paths:

- Run a fixed `Vec<LogicalOperation>` through `MemoryHypothesisStore` and `LocalFilesHypothesisStore`, reopen the file store, and compare canonical graph/ledger/memory reports byte-for-byte.
- Start two store handles from the same signed predecessor, synchronize them before write, let one commit, and require the other to receive `StalePredecessor` without changing its in-memory state.
- Replace the durable statement at the same sequence with different signed bytes and require digest CAS rejection; sequence equality alone must not pass.
- Let a lease expire at an injected timestamp, reclaim it, and prove the old holder cannot complete after the new holder commits.
- Tamper with an evidence payload, producer key, signature, lineage, edge confidence, or task state on disk and require read-time rejection.
- Replay the same evidence/task/memory record twice and require exactly one logical effect; replay an older sequence and require explicit `ReplayDetected`/stale failure.
- Mutate the benchmark manifest to remove a source family, truth edge, threshold, or named test and require the wrapper/report to fail rather than silently produce a passing zero.
- Inject scheduler delay or CPU load while keeping fixture inputs identical; deterministic metric verdict must remain unchanged, while a separately labeled observation may change.
- Compile a probe that tries to import the graph planner’s response executor/lease type; the boundary check must fail. Conversely, prove the existing approved live path still has to mint policy/receipt artifacts.

### Sampling Rate

- **Per task commit:** Targeted package tests for the changed module, `cargo fmt --all -- --check`, and `git diff --check`.
- **Per wave merge:** `cargo test -p swarm-core --lib`, `cargo test -p swarm-spine --lib`, `cargo test -p swarm-runtime --lib`, relevant `swarm-agents` tests, and the exact COG integration target.
- **Phase gate:** `bash tools/check-collective-hypothesis-graph.sh`, all COG integration/negative tests, `cargo test --workspace --all-targets --locked`, clippy/format, and combined-tree review before `/gsd:verify-work`.

### Wave 0 Gaps

- [ ] `crates/swarm-core/src/hypothesis_graph.rs` and strict config/limit types — COG-01/02/04/06/07.
- [ ] `crates/swarm-spine/src/hypothesis_graph_store.rs` — memory/local durable stores, signed snapshots, generation/digest CAS, lease fencing — COG-03/07.
- [ ] `crates/swarm-spine/src/strategy_memory.rs` — typed redacted memory and retrieval records — COG-07.
- [ ] `crates/swarm-runtime/src/hypothesis_graph/{mod,normalize,hypotheses,tasks,kill_chain,containment_plan,benchmark}.rs` — orchestration and deterministic report — COG-01..08.
- [ ] `crates/swarm-runtime/tests/collective_hypothesis_graph.rs` plus `tests/negative_graph_response_boundary.rs` — integration/authority boundaries — COG-01..08.
- [ ] `crates/swarm-spine` store tests for restart, tamper, same-sequence digest, stale lease completion, and backend parity — COG-03/07.
- [ ] `scenarios/collective-hypothesis-graph/` fixtures: six source families, corroborating/conflicting pairs, ambiguous seed, withheld multi-stage chain, and adjudicated truth manifest — COG-02/04/05/08.
- [ ] `docs/benchmarks/collective-hypothesis-graph.md` and `collective-hypothesis-graph-baseline.json` — checked-in metric definitions and expected values — COG-08.
- [ ] `tools/check-collective-hypothesis-graph.sh` — exact-test execution assertion, full metric extraction, baseline comparison, and negative mutation controls — COG-08.
- [ ] Injected `GraphClock`/logical scheduler seam and deterministic role tie-break rules; existing `InvestigationCoordinator` calls `SystemTime` directly and is not sufficient for COG benchmark truth — COG-03/08.
- [ ] No framework install is required; all listed dependencies already exist in the locked workspace. If a plan adds one, document why and verify it in `Cargo.lock` before implementation.

## Sources

### Primary (HIGH confidence)

- `.planning/phases/286-collective-hypothesis-graph/286-CONTEXT.md` — locked objective, required shape, measurement contract, ordering caveat, and non-goals.
- `.planning/REQUIREMENTS.md` (`COG-01` through `COG-08`) — exact acceptance behaviors and thresholds.
- `.planning/ROADMAP.md` and `.planning/STATE.md` — phase dependencies, success criteria, Phase 285 evidence boundary, and explicit deferred scope.
- `CLAUDE.md` — Rust-first crate layering, canonical production paths, fail-closed and auditable conventions.
- `docs/AGENTS.md` — persisted Ed25519 role identities, registry admission, Pouncer-only response authority, Sphinx enrichment-only boundary.
- `crates/swarm-core/src/types.rs` — `AgentId`, `ResponseAction`, rehearsal previews, and existing action/identity types.
- `crates/swarm-core/src/telemetry.rs` — normalized telemetry payloads and bridge contract.
- `crates/swarm-core/src/signed_state.rs` — signed state envelope, signer binding, stream/sequence/replay verification.
- `crates/swarm-crypto/src/{canonical.rs,hashing.rs,signing.rs,lib.rs}` — canonical JSON, SHA-256, Ed25519, and detached signature APIs.
- `crates/swarm-pheromone/src/substrate.rs` — signature/admission validation and `independent_source_identity` base-witness rule.
- `crates/swarm-spine/src/{investigation.rs,incident.rs,store.rs}` — existing durable record/store seams and their non-CAS file behavior.
- `crates/swarm-runtime/src/{sphinx_agent.rs,correlation.rs,investigation.rs,containment.rs,service/preview.rs}` — current graph, correlation, clock, and simulation behavior.
- `crates/swarm-agents/src/{stalker_agent.rs,weaver_agent.rs}` — current async investigation/correlation agents and process-local dedupe.
- `crates/swarm-governance/src/lib.rs` — durable lock binding, atomic persistence, sequence/digest CAS, and stale-snapshot tests.
- `crates/swarm-runtime/src/replay/{harness.rs,helpers.rs,metrics.rs,types.rs}` and `crates/swarm-runtime/src/detection/metrics.rs` — deterministic seed-time replay and explicit non-gating wall-clock observation pattern.
- `crates/swarm-ingest-json/src/{cloudtrail.rs,kubernetes_audit.rs}`, `crates/swarm-ingest-tetragon/src/mapper.rs`, `crates/swarm-ingest-taxii/src/lib.rs`, and `crates/swarm-ingest-sentinel/src/lib.rs` — source-specific normalization seams and tests.
- `Cargo.toml`, package manifests, and `Cargo.lock` — workspace dependency declarations and locked versions checked 2026-08-21.

### Secondary (MEDIUM confidence)

- `docs/research/swarm-hardening/05-KILL-CHAIN-RECONSTRUCTION-AND-GRAPH-CORRELATION.md` — earlier graph/correlation research; useful context only, subordinate to current COG requirements and live code.
- `docs/RESEARCH.md` — earlier HOLMES/MAGMA and stigmergic architecture rationale; not an acceptance source for Phase 286.
- `docs/benchmarks/stigmergic-feedback.md` and `tools/check-stigmergic-feedback-benchmark.sh` — repository precedent for checked-in baselines, exact test-run assertions, and full metric comparisons.

### Tertiary (LOW confidence)

- No external ecosystem claim is required for this phase. Any future claim about a graph database, distributed queue, or ATT&CK taxonomy should be verified against current official documentation before adding a dependency or changing the locked scope.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — all recommended crates and versions are present in the workspace/Cargo.lock; no new library is needed.
- Architecture: HIGH for layering and existing seam constraints; MEDIUM for proposed new module/type names, which the planner may refine without changing boundaries.
- Pitfalls: HIGH — identity, CAS, response-authority, and wall-clock issues are directly demonstrated by current source/tests and phase context.
- Validation: HIGH — test commands and baseline discipline follow existing replay/benchmark infrastructure; exact COG target names/files are Wave 0 work.

**Research date:** 2026-08-21
**Valid until:** 2026-09-20 for stable repository architecture; 2026-08-28 for dependency/version assumptions if the workspace lock changes.
