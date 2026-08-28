# Roadmap: Swarm Team Six

## Milestones

<details>
<summary>Shipped milestones (v1.0 through v1.37) -- see MILESTONES.md and .planning/milestones/</summary>

Phases 1-115 shipped across milestones v1.0 through v1.37. Full history is in `.planning/MILESTONES.md`, and per-milestone roadmap snapshots live in `.planning/milestones/`.

</details>

<details>
<summary>Shipped: v1.37.1 Runtime Hardening And Audit Debt (Phases 116-119)</summary>

- [x] **Phase 116: Agent Safety Hardening** - Signed pheromone deposits, configurable tick timeout, and explicit action-handling warnings close the three agent-safety audit findings (completed 2026-04-07)
- [x] **Phase 117: Substrate Durability And Bridge Resilience** - Threat-intel GC on all three backends, journal rewrite on GC, gRPC stream timeout, and empty-parent schema fix close the four substrate and bridge audit findings (completed 2026-04-07)
- [x] **Phase 118: Operational Hardening** - Independent secret-dir file-watch for hot rotation and size-based dead-letter rotation close the two operational-gap audit findings (completed 2026-04-07)
- [x] **Phase 119: Pheromone Test Suite** - A focused `swarm-pheromone` test suite with 15+ tests covering the substrate trait contract closes the test-coverage audit finding (completed 2026-04-08)

</details>

<details>
<summary>Shipped: v1.38 Multi-Detector Composition And Network Detection (Phases 120-123)</summary>

- [x] **Phase 120: Composite Detector And Config Migration** - CompositeDetector replaces single-variant SupportedDetector dispatch; config gains multi-strategy selection with per-strategy profile overrides (completed 2026-04-08)
- [x] **Phase 121: Network Connect Detector** - NetworkConnectDetector detects C2 beaconing and anomalous ports, while the runtime pipeline applies threat-intel IP enrichment to NetworkConnect findings (completed 2026-04-08)
- [x] **Phase 122: Cross-Strategy Pheromone Signals And Rollout Scoping** - Deposits carry strategy-specific identity for distinct-source escalation, WeaverAgent weights cross-strategy correlation higher, and canary/promotion scope to individual strategies (completed 2026-04-08)
- [x] **Phase 123: Multi-Strategy Integration Proof** - NetworkConnect findings produce CommandAndControl deposits, and a 3+ strategy composite triggers escalation via distinct_sources (completed 2026-04-08)

</details>

<details>
<summary>Shipped: v1.40 Killer Demo And Providence Integration (Phases 128-131)</summary>

- [x] **Phase 128: Demo Replay Injector And Event Stream Backbone** - Repo-owned replay injection now drives the live telemetry lane, and typed SSE events expose the running swarm to downstream demo surfaces. (completed 2026-04-08)
- [x] **Phase 129: Live Demo Dashboard And Runtime Timeline** - The operator review workbench now boots from runtime snapshot plus SSE and shows live mode, agent health, pheromone pressure, and timeline state. (completed 2026-04-08)
- [x] **Phase 130: Approval-In-The-Loop Demo And Signed Proof Export** - Human-gated demo runs now pause, resume through signed approval votes, and export one signed proof package for the full decision chain. (completed 2026-04-08)
- [x] **Phase 131: Providence Webhook Delivery And Drilldown Context** - Providence notifications now include Swarm drilldown URLs, runtime context, and bridge-health summary through the existing router. (completed 2026-04-08)

</details>

<details>
<summary>Shipped: v1.39 PounceAgent And Policy Gate Hardening (Phases 124-127)</summary>

- [x] **Phase 124: PounceAgent Core And De-escalation** - PounceAgent implements SwarmAgent with guard-gated autonomous response, dry-run mode, and de-escalation closes the response loop; lease expiration enforcement fails closed before any adapter call (completed 2026-04-08)
- [x] **Phase 125: Configurable Policy Rules And Audit Trail** - ConfigurableApprovalGate loads YAML rules with per-threat-class and per-severity allow/deny logic, rate limiting, and verdict reason in every structured log and receipt (completed 2026-04-08)
- [x] **Phase 126: TomAgent Governance** - TomAgent monitors agent health and provides synchronous pre-execution veto over destructive PounceAgent actions via shared GovernancePolicy with auditable veto receipts (completed 2026-04-08)
- [x] **Phase 127: Integration Hardening** - End-to-end integration tests prove all seven correctness pitfalls are guarded: no double-trigger, synchronous veto, fail-closed policy, TOCTOU-safe lease check, flap-resistant de-escalation, dry-run parity, and audit lineage (completed 2026-04-08)

</details>

<details>
<summary>Shipped: v1.41 Deployment And Hardening (Phases 132-136)</summary>

- [x] **Phase 132: Platform API Envelope And Auth Surface** - Versioned `/v2/api/` routes with cursor pagination and scoped API keys on the detect server. (completed 2026-04-08)
- [x] **Phase 133: Asset Posture And Findings Stream Surface** - Host posture endpoint and live findings SSE stream on the platform API. (completed 2026-04-08)
- [x] **Phase 134: Helm Deployment And Config CLI Experience** - Repo-owned Helm chart with NATS subchart, `swarmctl validate`, and `swarmctl init`. (completed 2026-04-08)
- [x] **Phase 135: Serve-Surface Security And Panic Elimination** - Panic-free detector defaults, bearer+TLS auth on serve surfaces. (completed 2026-04-08)
- [x] **Phase 136: Crate Extraction And Trace Instrumentation** - `swarm-evolution` and `swarm-cli` crate extraction, `#[instrument]` spans with `trace_id`. (completed 2026-04-09)

</details>

<details>
<summary>Shipped: v1.42 Evolution Engine Core (Phases 137-140)</summary>

- [x] **Phase 137: Kitten Mutation And Drift Orchestration** - KittenAgent multi-tick state machine with concept-drift activation. (completed 2026-04-09)
- [x] **Phase 138: Fitness Evaluation And Population Persistence** - Replay-backed Pareto fitness, durable population, proposal throttling. (completed 2026-04-09)
- [x] **Phase 139: Formal Safety Gate And Canary Admission** - Two-tier safety verification with canary handoff. (completed 2026-04-09)
- [x] **Phase 140: Evolution Observability And Operator Status** - SSE evolution_status events and `swarmctl evolution status`. (completed 2026-04-09)

</details>

<details>
<summary>Shipped: v1.43 Swarm Memory And Adversarial Pressure (Phases 141-144)</summary>

- [x] **Phase 141: Sphinx Knowledge Graph Foundations** - SphinxAgent with durable typed knowledge graph. (completed 2026-04-09)
- [x] **Phase 142: Stigmergic Memory Queries And Fitness Retrieval** - Pheromone query/answer with Q-value fitness integration. (completed 2026-04-09)
- [x] **Phase 143: Knowledge Retention And Adversarial Corpus Adapter** - Graph retention GC and Rust-native RedSwarmAdapter. (completed 2026-04-09)
- [x] **Phase 144: Red-Blue Pressure And Episode Logging** - Generation-scoped adversarial pressure and durable episode history. (completed 2026-04-09)

</details>
<details>
<summary>Shipped: v1.44 Agent Identity And Infrastructure Signals (Phases 145-148)</summary>

- [x] **Phase 145: Agent Key Persistence And Identity Derivation** - Durable Ed25519 keypair persistence and `swarm:ed25519:<hex>` identity derivation. (completed 2026-04-09)
- [x] **Phase 146: Identity Registry And Key Rotation** - Registry-backed identity admission and continuity-proof key rotation. (completed 2026-04-09)
- [x] **Phase 147: Sentinel Infrastructure Telemetry Bridge** - `swarm-ingest-sentinel` crate with health, thermal, and resource exhaustion payloads. (completed 2026-04-09)
- [x] **Phase 148: Infrastructure Anomaly Detection And Cross-Signal Correlation** - `InfrastructureAnomalyDetector` with cross-signal escalation. (completed 2026-04-09)

</details>

<details>
<summary>Shipped: v1.45 Providence Native (Phases 149-152)</summary>

- [x] **Phase 149: Providence Contract And Service Auth** - Shared webhook contract, HMAC signing, bearer service auth. (completed 2026-04-09)
- [x] **Phase 150: Incident Lifecycle Adapter** - Outbound create/update/resolve with retry, dead-letter, health reporting. (completed 2026-04-09)
- [x] **Phase 151: Analyst Feedback Loop** - Feedback endpoint, KittenAgent fitness signals, audit trail. (completed 2026-04-09)
- [x] **Phase 152: Embeddable Dashboard Widget And Context Tokens** - Widget embedding, scoped SSE, signed context tokens. (completed 2026-04-09)

</details>

<details>
<summary>Shipped: v1.46 Distributed Governance (Phases 153-156)</summary>

- [x] **Phase 153: Consensus Protocol Core** - Tendermint-style propose-prevote-precommit state machine with deterministic committee rotation over JetStream. (completed 2026-04-09)
- [x] **Phase 154: Byzantine Safety And Multi-Instance Governance** - Signed message validation, equivocation detection, agent exclusion receipts, receipt-backed Tom governance, and registry-backed deposit validation. (completed 2026-04-09)
- [x] **Phase 155: Partition Authority And Contingency Leases** - Quorum-loss partition detection, staged contingency leases, fail-closed destructive response during partition, and healing reconciliation. (completed 2026-04-09)
- [x] **Phase 156: Chaos And Resilience Testing** - Byzantine injection, partition-expiry fail-closed proof, and deterministic recovery persistence verification. (completed 2026-04-09)

</details>

<details>
<summary>Shipped: v1.47 Calico And Detection Breadth (Phases 157-160)</summary>

- [x] **Phase 157: Calico Agent Core And Deception Playbook** - Repo-owned deception playbooks now drive baseline decoy deployment and high-confidence tripwire findings. (completed 2026-04-09)
- [x] **Phase 158: Calico Lifecycle And Evolution Integration** - Calico lifecycle state persists across restart, Sphinx registers deception assets, and Kitten consumes deception pressure in durable fitness artifacts. (completed 2026-04-09)
- [x] **Phase 159: Fileless Execution Detection** - `FilelessExecutionDetector` now turns typed `ProcessMemoryAccess` telemetry into deterministic fileless execution findings. (completed 2026-04-09)
- [x] **Phase 160: Behavioral Anomaly Baselines** - Restart-safe per-host behavioral baselines now persist through the durable substrate and hydrate back into the runtime detection lane. (completed 2026-04-09)

</details>

<details>
<summary>Shipped: v1.49 Canonical Runtime Contract And Governance Modes (Phases 164-167)</summary>

- [x] **Phase 164: Canonical Capability Matrix And Source-Of-Truth Reset** - Re-established one active-vs-historical contract set for runtime, agent, config, and deployment surfaces so the planning and docs layer now describes the same system. (completed 2026-04-10)
- [x] **Phase 165: Governance Modes And Identity Admission Contracts** - Canonicalized local guarded response, human gates, identity admission, and receipt-backed quorum behavior into one operator-readable governance contract. (completed 2026-04-10)
- [x] **Phase 166: Degraded Governance And Partition Recovery Spec** - Defined fail-closed degraded-governance, contingency lease, partition, and reconciliation behavior against the shipped runtime and serve-mode surfaces. (completed 2026-04-10)
- [x] **Phase 167: Evolution, Rollout, And Operator Contract Consolidation** - Aligned queue, canary, promotion, proof, and operator-review semantics with the current runtime-owned evolution and approval lanes. (completed 2026-04-10)

</details>

<details>
<summary>Shipped: v1.50 Async Enrichment And Correlation Depth (Phases 168-171)</summary>

- [x] **Phase 168: Weaver Multi-Graph Correlation Foundations** - Weaver now traverses temporal, causal, entity, and semantic graph dimensions and persists explainable incident evidence with bounded confidence. (completed 2026-04-10)
- [x] **Phase 169: Investigation Scheduling And Confidence Voting** - The async investigation lane now uses bounded priority scheduling, queue budgets, starvation protection, and durable ambiguity-vote lineage. (completed 2026-04-10)
- [x] **Phase 170: Identity And Peer-Group Behavioral Baselines** - Behavioral learning now persists and evaluates host, identity, and peer-group scope independently with readable scope attribution. (completed 2026-04-10)
- [x] **Phase 171: Async Enrichment Surface And Integration Proof** - Async backlog, pressure, and correlation outcomes now surface through shared runtime status, and the end-to-end detect -> investigate -> correlate path is integration-proven. (completed 2026-04-10)

</details>

<details>
<summary>Shipped: v1.51 Assurance-Gated Evolution And Counterexample Loop (Phases 172-175)</summary>

- [x] **Phase 172: Assurance Policy And Gate Inputs** - Define assurance policy from coverage floors, solver outcomes, and fail-closed gate thresholds. (ASSURE-01, ASSURE-02) (completed 2026-04-11)
- [x] **Phase 173: Counterexample Harvest And Replay Regeneration** - Convert evasion misses and solver counterexamples into replayable regression and mutation inputs with lineage. (COUNTER-01, COUNTER-02) (completed 2026-04-11)
- [x] **Phase 174: Assurance-Gated Queue, Canary, And Promotion** - Apply assurance policy to the queue, canary, and promotion state machines with fail-closed enforcement. (ASSURE-03) (completed 2026-04-11)
- [x] **Phase 175: Waivers, Review Surface, And Assurance Lineage** - Add signed waivers, bounded operator overrides, and surfaced assurance lineage to review and proof artifacts. (ASSURE-04, ASSURE-05) (completed 2026-04-11)

</details>

<details>
<summary>Shipped: v1.52 Providence Reconciliation And Response Rehearsal (Phases 176-179)</summary>

- [x] **Phase 176: Providence Callback And Incident Reconciliation** - Accept authenticated Providence callbacks and reconcile incident lifecycle state with correlated incidents. (PROVREC-01, PROVREC-02) (completed 2026-04-11)
- [x] **Phase 177: Analyst Disposition Sync And Memory Feedback** - Persist analyst dispositions and notes as signed audit evidence and feed them back into Sphinx and Kitten memory. (PROVREC-03) (completed 2026-04-11)
- [x] **Phase 178: Response Rehearsal Harness And Blast-Radius Modeling** - Reuse the existing response and approval path in non-destructive rehearsal mode with bounded blast-radius and rollback evidence. (REHEARSE-01, REHEARSE-02) (completed 2026-04-11)
- [x] **Phase 179: Rehearsal Review Surface And Providence Handoff** - Surface reconciliation and rehearsal context through the local review path and Providence-facing handoff surfaces. (REHEARSE-03, REHEARSE-04) (completed 2026-04-11)

</details>

<details>
<summary>Shipped: v1.53 Production Packaging, Recovery, And Operator Access (Phases 180-183)</summary>

- [x] **Phase 180: Secure Production Packaging Profile** - Ship secure-by-default packaging for runtime, state, and dependency surfaces with an explicit supported deployment profile. (PROD-01) (completed 2026-04-11)
- [x] **Phase 181: Recovery Drills And Durability Validation** - Prove backup, restore, upgrade, rollback, and durability behavior across the supported state roots. (PROD-02, PROD-03) (completed 2026-04-11)
- [x] **Phase 182: SLO, Capacity Envelope, And Alert Baselines** - Publish end-to-end load, capacity, SLO, and alert guidance based on measured runtime behavior. (PROD-04) (completed 2026-04-11)
- [x] **Phase 183: Operator Access Model And Multi-Operator Audit** - Add scoped multi-operator access, attributable approvals, and a supported reference architecture for adoption. (ACCESS-01, ACCESS-02, ACCESS-03) (completed 2026-04-11)

</details>

<details>
<summary>Shipped: v1.54 Panic Eradication And Error Contracts (Phases 184-187)</summary>

- [x] **Phase 184: Runtime Unwrap Audit And Error Types** - `swarm-runtime` now has a repo-owned audit of live non-test panic sites plus explicit typed runtime boundary enums. (completed 2026-04-12)
- [x] **Phase 185: Ingest And Service Panic-Free Conversion** - Ingest, service, and operator-facing request paths now fail closed through typed errors instead of panic or string-only propagation. (completed 2026-04-12)
- [x] **Phase 186: Agent Tick And Evolution Error Boundaries** - Agent ticks and Kitten proposal routing now preserve typed runtime-owned failure context across replay, store, and evolution seams. (completed 2026-04-12)
- [x] **Phase 187: Error Contract CI Enforcement** - CI now runs a repo-owned `#[cfg(test)]`-aware panic-contract checker and integration proof for malformed ingest and Kitten proposal inputs. (completed 2026-04-12)

</details>

<details>
<summary>Shipped: v1.55 JetStream Integration Tests And Load Baselines (Phases 188-191)</summary>

- [x] **Phase 188: Containerized NATS Test Harness** - The repo now ships a compose-backed JetStream harness with deterministic lifecycle, exported `NATS_URL`, and CI-backed smoke verification. (JTEST-01) (completed 2026-04-12)
- [x] **Phase 189: JetStream Substrate Test Migration** - The repo now runs the full pheromone substrate contract against JetStream through the shared harness, including policy-aware GC parity under threat-class overrides, and CI executes that broader suite automatically. (JTEST-02) (completed 2026-04-12)
- [x] **Phase 190: Hot Path Criterion Benchmarks** - `swarm-runtime` now ships a Criterion-owned hot-path benchmark with checked-in `in_memory` and `local_journal` percentile baselines. (JTEST-03) (completed 2026-04-12)
- [x] **Phase 191: Sustained Throughput Load Test** - The operator-facing ingest benchmark now captures the highest stable accepted-event rate before `/readyz` sheds, with documented host-profile and heap-budget assumptions. (JTEST-04) (completed 2026-04-12)

</details>

<details>
<summary>Shipped: v1.56 Binary Attestation And Configuration Integrity (Phases 192-195)</summary>

- [x] **Phase 192: Startup Binary And Ruleset Attestation** - Runtime startup now verifies a signed repo ruleset manifest and adjacent binary sidecar, surfaces `startup_attestation` on health routes, and refuses `live_response` mode on failure. (ATTEST-01) (completed 2026-04-12)
- [x] **Phase 193: Configuration Signature Verification** - File-backed runtime config now requires an Ed25519-signed `.sig.json` sidecar on startup and full reload, with fail-closed rejection on tamper. (ATTEST-02) (completed 2026-04-12)
- [x] **Phase 194: Runtime Anti-Tamper Monitoring** - The runtime now detects Linux debugger attachment and unexpected library loads, emits structured tamper alerts, and surfaces anti-tamper state on health and platform status routes. (ATTEST-03) (completed 2026-04-12)
- [x] **Phase 195: Supply Chain Hardening And SBOM** - CI now enforces the shared dependency-policy gate, release automation publishes per-crate CycloneDX SBOM artifacts, and the repo documents the operator workflow. (ATTEST-04) (completed 2026-04-12)

</details>

<details>
<summary>Shipped detail sections for v1.60-v1.63</summary>

## Recently Completed Milestone

### v1.60 Agent Lifecycle Isolation And Graceful Degradation

**Goal:** Contain agent failures to their own boundary and define explicit runtime degradation levels.
**Executable phases:** 208-211

- [x] **Phase 208: Per-Agent Panic Boundaries** - The dispatcher now catches panics per agent tick, degrades only the crashing agent, and keeps the shared run loop alive for healthy peers. (ISOLATE-01) (completed 2026-04-12)
- [x] **Phase 209: Agent Health-Driven Restart** - Persistent agent failures now trigger individual agent restart through dispatcher-owned factories without affecting the rest of the swarm. (ISOLATE-02) (completed 2026-04-12)
- [x] **Phase 210: Degradation Mode State Machine** - The runtime now derives and surfaces explicit full/detect-only/read-only/emergency-drain states with bounded capabilities, triggers, and ingest gating. (ISOLATE-03) (completed 2026-04-12)
- [x] **Phase 211: Degradation Transition Tests** - Repo-owned runtime tests now prove NATS-down to detect-only, replay-store write-path failure to read-only, and heap-pressure to emergency-drain transitions. (ISOLATE-04) (completed 2026-04-12)

### Phase 208: Per-Agent Panic Boundaries

**Goal:** Ensure each registered agent tick runs inside a panic boundary so one crashing agent does not terminate the dispatcher task or runtime process.
**Requirements:** ISOLATE-01
**Depends on:** v1.59 milestone complete
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. Every registered runtime agent tick executes inside a runtime-owned panic boundary instead of allowing panic unwind through the shared dispatcher task.
2. A panic marks only the crashing agent degraded while the dispatcher continues ticking healthy agents.
3. Panic attribution is preserved well enough for later health-driven restart and degradation work to reason about the failing agent.

### Phase 209: Agent Health-Driven Restart

**Goal:** Restart only the failing agent when its health repeatedly crosses the configured failure boundary.
**Requirements:** ISOLATE-02
**Depends on:** Phase 208
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. Repeated boundary failures can trigger restart of the affected agent without restarting the full dispatcher or runtime process.
2. Healthy agents remain registered and continue ticking while the failing agent is restarted.
3. Restart activity is surfaced through the existing runtime health reporting and logs.

### Phase 210: Degradation Mode State Machine

**Goal:** Define explicit runtime degradation levels and health-driven transitions between them.
**Requirements:** ISOLATE-03
**Depends on:** Phase 209
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. The runtime exposes explicit full, detect-only, read-only, and emergency-drain modes with documented behavior.
2. Health signals can drive bounded automatic transitions between those modes.
3. Operators can observe the current degradation level through repo-owned status or health surfaces.

### Phase 211: Degradation Transition Tests

**Goal:** Prove the degradation state machine behaves correctly under bounded failure scenarios.
**Requirements:** ISOLATE-04
**Depends on:** Phase 210
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. End-to-end tests prove an unavailable NATS path forces the expected detect-only behavior.
2. End-to-end tests prove disk exhaustion or write failure forces the expected read-only behavior.
3. End-to-end tests prove heap-pressure or equivalent drain triggers the expected emergency-drain behavior without unsafe action execution.

## Recently Completed Milestone

### v1.63 Evolution Crate Decomposition And Schema Migration

**Goal:** Pay down velocity debt by decomposing the evolution crate and establishing versioned wire formats.
**Executable phases:** 220-223

- [x] **Phase 220: Evolution Module Extraction** - Decompose `evolution.rs` into focused sub-modules with no file exceeding 2000 lines. (DECOMP-01) (completed 2026-04-12)
- [x] **Phase 221: Mutation Module Extraction** - Decompose `mutation.rs` into focused sub-modules with documented API boundaries. (DECOMP-02) (completed 2026-04-12)
- [x] **Phase 222: Pheromone Wire Format Versioning** - Add explicit schema version to deposits with current+previous version migration. (DECOMP-03) (completed 2026-04-12)
- [x] **Phase 223: API Response Schema Migration** - Version API envelopes with version negotiation for breaking changes. (DECOMP-04) (completed 2026-04-12)

## Active Milestone

No active milestone. `v1.63 Evolution Crate Decomposition And Schema Migration`
completed on 2026-04-12, and the next milestone has not been activated yet.

### Phase 212: Response Action Adapter Expansion

**Goal:** Expand the response adapter library to add more concrete actions without changing the existing guarded execution contract.
**Requirements:** RESPONSE-01
**Depends on:** v1.60 milestone complete
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. The response library grows beyond the current limited adapter set with concrete operator-meaningful actions such as network isolation, DNS sinkhole, session termination, EDR scan, and firewall rule injection.
2. New actions stay inside the existing approval, audit, and executor seams instead of adding a parallel response path.
3. The expanded action set is repo-owned, testable, and documented well enough for later playbook composition work.

### Phase 213: Blast-Radius Models And Rollback Procedures

**Goal:** Add typed blast-radius and rollback contracts for each supported response action.
**Requirements:** RESPONSE-02
**Depends on:** Phase 212
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. Each concrete response action declares a typed blast-radius model covering affected hosts, services, users, or equivalent scope.
2. Each action has a bounded rollback procedure or an explicit non-reversible declaration.
3. Blast-radius and rollback metadata are available to later rehearsal and preview surfaces without re-deriving them ad hoc.

### Phase 214: Composable Playbook YAML Schema

**Goal:** Let operators define multi-step response playbooks in repo-owned YAML with conditional composition.
**Requirements:** RESPONSE-03
**Depends on:** Phase 213
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. Operators can express multi-step playbooks in YAML instead of hard-coding sequences in Rust.
2. Playbooks support bounded conditional branching over threat class, severity, or equivalent runtime context.
3. Composed playbooks still flow through the existing approval-aware runtime response path.

### Phase 215: Playbook Dry-Run And Preview

**Goal:** Preview projected blast radius and approval requirements for playbooks before any live execution.
**Requirements:** RESPONSE-04
**Depends on:** Phase 214
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. Operators can run a dry-run preview for a playbook without performing live actions.
2. The preview shows projected blast radius, rollback expectations, and approval requirements.
3. Preview output is grounded in the same typed action metadata used by live execution and rehearsal, not a separate heuristic-only path.

### Phase 216: Online Distribution Learning

**Goal:** Replace fixed behavioral-anomaly confidence arithmetic with learned per-entity online distributions.
**Requirements:** ANOMALY-01
**Depends on:** v1.61 milestone complete
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. `BehavioralAnomalyDetector` no longer relies on the current fixed signal-count confidence formula.
2. Learned distribution state survives restart through the existing behavioral baseline snapshot seam.
3. The phase stays bounded to the existing behavioral process-start detector rather than widening into multi-telemetry anomaly scoring early.

### Phase 217: Statistical Deviation Scoring

**Goal:** Derive anomaly scores from explicit statistical deviation measures instead of fixed threshold arithmetic.
**Requirements:** ANOMALY-02
**Depends on:** Phase 216
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. Behavioral anomaly confidence is derived from one explicit statistical deviation model such as z-score, percentile rank, or information-theoretic surprise.
2. The detector surfaces enough structured evidence for operators to understand why one event scored as anomalous.
3. Statistical scoring remains bounded and restart-safe on the existing repo-owned detector path.

### Phase 218: Multi-Telemetry Behavioral Extension

**Goal:** Extend learned behavioral baselines beyond process starts to the other shipped telemetry families.
**Requirements:** ANOMALY-03
**Depends on:** Phase 217
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. Learned baselines extend to network, DNS, authentication, file-access, and memory-oriented telemetry instead of process starts alone.
2. Each added telemetry family uses repo-owned bounded per-entity learning rather than detector-local heuristics.
3. The shared operator and evidence surfaces preserve clear strategy attribution across the widened behavioral detector family.

### Phase 219: Anomaly Quality Benchmark

**Goal:** Measure the quality impact of learned behavioral scoring against labeled telemetry.
**Requirements:** ANOMALY-04
**Depends on:** Phase 218
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. The repo ships a repeatable labeled-telemetry benchmark for behavioral anomaly quality.
2. Measured false-positive rate improves by at least 30% while catch rate remains bounded relative to the shipped baseline.
3. The resulting benchmark artifact is checked in so later milestone work can compare against the same reference run.

### Phase 220: Evolution Module Extraction

**Goal:** Decompose the oversized `swarm-evolution` evolution module into focused internal submodules without changing the crate contract.
**Requirements:** DECOMP-01
**Depends on:** v1.62 milestone complete
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. `crates/swarm-evolution/src/evolution.rs` is decomposed into focused internal modules rather than remaining one monolithic file.
2. No extracted file in the new evolution module tree exceeds 2000 lines.
3. Existing runtime callers keep working through the same `swarm-evolution` crate surface after the refactor.

### Phase 221: Mutation Module Extraction

**Goal:** Decompose the oversized mutation implementation into focused modules with explicit API boundaries.
**Requirements:** DECOMP-02
**Depends on:** Phase 220
**Status:** Complete
**Plans:** 1
**Success Criteria**:
1. `crates/swarm-evolution/src/mutation.rs` is decomposed into coherent submodules instead of one monolithic file.
2. Internal boundaries are documented with module-level responsibilities and `pub(crate)` visibility where practical.
3. The public `swarm-evolution` API remains stable for existing crate consumers after the extraction.

### Phase 222: Pheromone Wire Format Versioning

**Goal:** Add explicit versioning and migration support to pheromone deposits without breaking the current substrate contract.
**Requirements:** DECOMP-03
**Depends on:** Phase 221
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. Deposits carry an explicit schema version instead of relying on implicit field shape.
2. The substrate accepts the current and previous wire versions with bounded automatic migration.
3. Version mismatch or unsupported deposits fail closed with explicit error reporting instead of silent coercion.

### Phase 223: API Response Schema Migration

**Goal:** Version operator-facing API envelopes so future breaking changes negotiate explicitly instead of landing as silent shape drift.
**Requirements:** DECOMP-04
**Depends on:** Phase 222
**Status:** Completed 2026-04-12
**Plans:** 1
**Success Criteria**:
1. API response envelopes carry explicit schema version metadata.
2. Breaking response changes route through version negotiation instead of unannounced field changes.
3. Existing operator and CLI clients keep one bounded compatibility path while newer schema versions roll out.

</details>

## Active Milestone

<details>
<summary>Shipped: v1.68 Multi-Detector Evolution Genomes (Phases 240-243)</summary>

- [x] **Phase 240: Behavioral Anomaly Genome And Mutation Operators** - Added typed behavioral-anomaly genomes and bounded autonomous recipes without regressing the existing suspicious-process-tree flow. (GENOME-01) (completed 2026-04-13)
- [x] **Phase 241: Fileless And DNS Detector Genomes** - Extended the typed-genome mutation lane to fileless execution and DNS exfiltration detectors with bounded perturbation and crossover support. (GENOME-02) (completed 2026-04-13)
- [x] **Phase 242: Multi-Detector Evolution Benchmark** - Generalized the bounded measured benchmark harness across process-tree, behavioral anomaly, fileless execution, and DNS exfiltration detector families. (GENOME-03) (completed 2026-04-13)
- [x] **Phase 243: Cross-Detector Fitness Improvement Proof** - Proved measured autonomous improvement above baseline for the fileless-execution detector through the shared benchmark surface. (GENOME-04) (completed 2026-04-13)

</details>

<details>
<summary>Shipped: v1.69 Command-Line Deobfuscation Pipeline (Phases 244-247)</summary>

- [x] **Phase 244: Caret And Environment Variable Normalization** - Added one shared `swarm-whisker` command-line normalization seam for caret stripping and bounded env-var expansion with raw-to-normalized evidence lineage. (completed 2026-04-13)
- [x] **Phase 245: Unicode Homoglyph And Encoding Normalization** - Extended the shared seam with bounded homoglyph folding and encoded-command / `FromBase64String(...)` decode support across the command-line detector family. (completed 2026-04-13)
- [x] **Phase 246: Evasion Catch-Rate Improvement Measurement** - Added a repo-owned command-line deobfuscation corpus and baseline-vs-normalized benchmark helpers proving 15%+ gain on the targeted execution and defense-evasion lanes. (completed 2026-04-13)
- [x] **Phase 247: Normalization False-Positive Regression Test** - Added benign normalization controls and a repo-owned regression proof showing zero false-positive increase across the command-line detector family. (completed 2026-04-13)

</details>

<details>
<summary>Shipped: v1.67 Secret Zeroization And API Token Lifecycle (Phases 236-239)</summary>

- [x] **Phase 236: Secret Zeroization With zeroize Crate** - Zeroized resolved secrets from heap-backed config and auth state through a shared `SecretString` wrapper plus scrubbed resolver buffers. (completed 2026-04-13)
- [x] **Phase 237: Release Build Hardening** - Made release hardening explicit with `panic = "abort"`, `overflow-checks = true`, and a repo-owned proof script for the shipped binaries. (completed 2026-04-13)
- [x] **Phase 238: Rotatable Token Lifecycle** - Added expiry metadata and per-request bearer-token reload so operator and platform auth can rotate without restart. (completed 2026-04-13)
- [x] **Phase 239: HTTP Rate Limiting** - Added shared per-source burst and sustained rate limiting with `429` responses, `Retry-After`, and recent-violation status context. (completed 2026-04-13)

</details>

<details>
<summary>Shipped: v1.66 Learned-State Integrity Signing (Phases 232-235)</summary>

- [x] **Phase 232: Behavioral Baseline Signing And Verification** - Signed behavioral baseline snapshots before persistence and verified them on restore with fail-closed semantics. (completed 2026-04-13)
- [x] **Phase 233: Sphinx Graph State Signing** - Signed knowledge-graph state files with verification on restore. (completed 2026-04-13)
- [x] **Phase 234: Evolution Population Signing** - Signed population and episode artifacts with verification on restore. (completed 2026-04-13)
- [x] **Phase 235: Monotonic Sequence And Replay Prevention** - Added monotonic sequence numbers and replay rejection to all signed learned-state artifacts. (completed 2026-04-13)

</details>

<details>
<summary>Shipped: v1.65 Config Crate Extraction And service.rs Decomposition (Phases 228-231)</summary>

- [x] **Phase 228: Config Module Decomposition** - Split `config.rs` into focused sub-modules with no file exceeding 2000 lines while preserving the `swarm_core::config` surface. (completed 2026-04-13)
- [x] **Phase 229: Config Compilation Boundary Verification** - Proved a config-only touch rebuilds exactly the `swarm-core` dependent set instead of the whole workspace. (completed 2026-04-13)
- [x] **Phase 230: Service Module Decomposition** - Split `service.rs` into lifecycle, orchestration, and request handling modules while preserving the shipped import surface. (completed 2026-04-13)
- [x] **Phase 231: RuntimeService Arc Reduction** - Narrowed request-facing execution to a separately swapped shared runtime handle instead of cloning the full configured stack. (completed 2026-04-13)

</details>

<details>
<summary>Shipped: v1.64 Cross-Crate Path Hack Elimination (Phases 224-227)</summary>

- [x] **Phase 224: Audit Path Hack Dependencies And Migration Plan** - Cataloged the ten runtime path hacks and defined the bounded migration order. (completed 2026-04-13)
- [x] **Phase 225: Extract Runtime-Evolution Bridge Types** - Moved the formerly path-hacked source tree under `swarm-runtime` and kept `swarm-evolution` as a compatibility facade. (completed 2026-04-13)
- [x] **Phase 226: Remove Remaining Path Directives And Fix Imports** - Removed the remaining `#[path]` directives and normalized runtime/evolution imports to ordinary crate/module paths. (completed 2026-04-13)
- [x] **Phase 227: Path Hack Removal Integration Proof** - Proved build, library-test, and production-target clippy health after the full path-hack removal. (completed 2026-04-13)

</details>

<details>
<summary>Shipped: v1.71 CI Hardening And Versioned Releases (Phases 252-255)</summary>

### v1.71 CI Hardening And Versioned Releases

**Goal:** Parallel CI, JetStream tests in CI, benchmark regression gate, versioned container images.
**Executable phases:** 252-255

- [x] **Phase 252: CI Job Parallelization** - Split CI into parallel fmt/clippy/build/test jobs with shared cargo cache reuse and a stable serialized workspace test proof. (completed 2026-04-13)
- [x] **Phase 253: JetStream Integration Tests In CI** - Added containerized NATS JetStream proof to CI through the repo-owned harness with actionable failure output. (completed 2026-04-13)
- [x] **Phase 254: Benchmark Regression Gate** - Added the hot-path Criterion p99 gate, refreshed the tracked baseline, and documented repo-owned baseline refresh workflow. (completed 2026-04-13)
- [x] **Phase 255: Release Pipeline And Container Publishing** - Added tagged multi-arch releases with changelog generation, SBOM, signing, provenance attestation, and GitHub release publication. (completed 2026-04-13)

### Phase 252: CI Job Parallelization

**Goal:** Split the repo CI pipeline into bounded parallel jobs with artifact reuse instead of one monolithic serial run.
**Requirements:** CIHARD-01
**Depends on:** v1.70 milestone complete
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. CI runs separate fmt, clippy, build, and test jobs with explicit dependency edges instead of one serialized mega-job.
2. Shared artifacts or caches avoid redundant rebuild work across the new job graph.
3. The repo retains one clear green/red CI signal while the job breakdown becomes operator-readable.

### Phase 253: JetStream Integration Tests In CI

**Goal:** Run the JetStream-backed integration surface in CI against a containerized NATS instance.
**Requirements:** CIHARD-02
**Depends on:** Phase 252
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. CI provisions a containerized NATS instance with JetStream enabled for the relevant integration jobs.
2. The repo-owned JetStream integration tests now execute in CI instead of remaining local-only proof.
3. Failure output stays actionable enough to distinguish harness, service, and test regressions quickly.

### Phase 254: Benchmark Regression Gate

**Goal:** Add a CI regression gate for the Criterion hot-path benchmark.
**Requirements:** CIHARD-03
**Depends on:** Phase 253
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. CI runs the repo-owned hot-path benchmark in a dedicated regression job.
2. The job fails when p99 latency regresses beyond the configured threshold relative to the tracked baseline.
3. The repo documents how to refresh or review the benchmark baseline when intentional performance tradeoffs land.

### Phase 255: Release Pipeline And Container Publishing

**Goal:** Automate versioned releases with publishable multi-arch images, attestation, and changelog generation.
**Requirements:** RELEASE-01, RELEASE-02
**Depends on:** Phase 254
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. Tagged releases build and publish versioned multi-arch container images with SBOM and signature attestation.
2. Release automation produces a human-readable CHANGELOG from conventional commit history.
3. The release path is repo-owned and repeatable instead of relying on manual out-of-band steps.

</details>

<details>
<summary>Shipped: v1.72 OpenAPI Spec And SOAR Bidirectional Sync (Phases 256-259)</summary>

- [x] **Phase 256: OpenAPI 3.1 Spec Generation** - The repo now emits and validates one checked-in OpenAPI 3.1 contract for the authenticated `/v2/api/` platform surface. (completed 2026-04-13)
- [x] **Phase 257: Generated Python Client** - The repo now generates a Python client from the checked-in OpenAPI contract and proves it against a live runtime router. (completed 2026-04-13)
- [x] **Phase 258: Inbound SOAR Verdict Sync** - The detect router now accepts bounded Splunk SOAR, Sentinel SOAR, and Chronicle SOAR verdicts on one signed ingress surface and routes them into the existing feedback lane. (completed 2026-04-13)
- [x] **Phase 259: SOAR Audit Lineage** - Incident audit entries and normalized false-positive measurements now persist durable SOAR source-system lineage and fail closed on duplicate or incomplete verdicts. (completed 2026-04-13)

### Phase 256: OpenAPI 3.1 Spec Generation

**Goal:** Publish a machine-readable OpenAPI 3.1 description for the shipped `/v2/api/` platform surface from one repo-owned source of truth.
**Requirements:** APISPEC-01
**Depends on:** v1.71 milestone complete
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. The repo can generate or derive one OpenAPI 3.1 spec for the authenticated `/v2/api/` platform surface without maintaining a second divergent contract by hand.
2. The published spec covers the shipped request and response shapes, auth expectations, and error envelopes for the supported `/v2/api/` routes.
3. The spec is checked in or emitted to a stable repo-owned path and validated as a real OpenAPI 3.1 document.

### Phase 257: Generated Python Client

**Goal:** Ship a generated Python client from the checked-in OpenAPI spec and prove it against the live platform API contract.
**Requirements:** APISPEC-02
**Depends on:** Phase 256
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. The repo generates a Python client from the same OpenAPI spec published in Phase 256 instead of introducing a handwritten parallel client surface.
2. The generated client exposes the shipped `/v2/api/` auth and endpoint contracts in a usable package form.
3. Repo-owned tests prove the generated client can talk to the live or test platform API surface without contract drift.

### Phase 258: Inbound SOAR Verdict Sync

**Goal:** Accept inbound analyst verdicts from supported SOAR systems and route them into Swarm's existing false-positive and evolution feedback paths.
**Requirements:** SOARSYNC-01
**Depends on:** Phase 257
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. Swarm accepts a bounded inbound verdict contract for Splunk SOAR, Sentinel SOAR, and Chronicle SOAR sources on one authenticated runtime-owned surface.
2. Accepted verdicts update the existing false-positive tracking and evolution-fitness inputs instead of creating a disconnected side channel.
3. Source system, verdict type, and referenced finding or incident identifiers are normalized well enough for later audit and replay use.

### Phase 259: SOAR Audit Lineage

**Goal:** Preserve durable audit lineage for each inbound SOAR verdict from the external analyst identity to the affected Swarm evidence.
**Requirements:** SOARSYNC-02
**Depends on:** Phase 258
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. Every synced verdict persists the external analyst identity, source system, verdict timestamp, and affected Swarm finding or incident identifiers.
2. The stored lineage is attached to the same durable evidence or review surfaces that already carry operator and evolution audit context.
3. Invalid, duplicate, or incomplete verdict sync inputs fail closed with explicit audit-visible rejection instead of silently mutating fitness or false-positive state.

</details>

<details>
<summary>Shipped: v1.73 Stigmergic Feedback Loops And Baseline Resistance (Phases 260-263)</summary>

### v1.73 Stigmergic Feedback Loops And Baseline Resistance

**Goal:** Implement real pheromone recruitment and quantify baseline poisoning resistance.
**Executable phases:** 260-263

- [x] **Phase 260: Positive-Feedback Pheromone Recruitment** - High-concentration signed command-and-control deposits now lower the bounded network beacon threshold for the matching detector lane only. (STIGM-01, BASERES-01) (completed 2026-04-13)
- [x] **Phase 261: Inhibitory Escalation Resolution Signaling** - Cooldown-driven de-escalation now persists one durable inhibitory `Normal` record that restores the recruited threshold back toward baseline across restart. (STIGM-02) (completed 2026-04-13)
- [x] **Phase 262: Recruitment Kill-Chain Benchmark** - The repo now ships replay proof for 33.3% faster alerting plus checked-in sigma-shift poisoning bounds at `3σ=2`, `2σ=4`, and `1σ=13`. (STIGM-03, BASERES-02) (completed 2026-04-13)
- [x] **Phase 263: Baseline Poisoning Resistance And Staleness Policy** - Aged signed behavioral baselines now trigger graduated confidence reduction with restart-proof evidence on the live runtime path. (BASERES-03) (completed 2026-04-13)

### Phase 260: Positive-Feedback Pheromone Recruitment

**Goal:** Lower matching detector thresholds when trusted pheromone concentration proves a threat class is already recruiting corroboration.
**Requirements:** STIGM-01, BASERES-01
**Depends on:** v1.72 milestone complete
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. Matching high-concentration pheromone state can lower the relevant detector threshold for one threat class without globally broadening the runtime.
2. The recruitment effect is derived from trusted signed state instead of unsourced mutable counters.
3. The recruited threshold state is observable enough to explain why a faster alert fired.

### Phase 261: Inhibitory Escalation Resolution Signaling

**Goal:** Restore recruited thresholds back toward baseline once escalation resolves so the runtime does not stay permanently over-sensitized.
**Requirements:** STIGM-02
**Depends on:** Phase 260
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. Escalation resolution emits one inhibitory signal that reduces or clears prior recruitment pressure for the affected threat class.
2. Detector thresholds return toward baseline on the same bounded runtime-owned path that lowered them.
3. The reset path is durable enough to survive restart without leaving a stale recruited state behind.

### Phase 262: Recruitment Kill-Chain Benchmark

**Goal:** Measure whether recruitment materially improves time-to-alert and quantify how resistant the learned baseline is to sigma-scale poisoning pressure.
**Requirements:** STIGM-03, BASERES-02
**Depends on:** Phase 261
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. The repo ships a benchmark or replay proof showing at least 20% faster alerting on the targeted kill-chain scenarios with recruitment enabled.
2. The same proof surface quantifies the observation count needed to shift the baseline by 1, 2, and 3 sigma.
3. The measured results are checked into the repo as repeatable evidence instead of remaining ad hoc local proof.

### Phase 263: Baseline Poisoning Resistance And Staleness Policy

**Goal:** Reduce trust in aged learned state instead of silently treating stale baselines as fresh truth.
**Requirements:** BASERES-03
**Depends on:** Phase 262
**Status:** Complete
**Plans:** 1/1 planned
**Success Criteria**:
1. Baseline snapshots older than a configurable staleness threshold trigger graduated confidence reduction.
2. The stale-state policy composes cleanly with the signed baseline persistence path from the earlier learned-state integrity work.
3. Repo-owned tests prove the stale-baseline confidence reduction path instead of relying on documentation-only expectations.

</details>

<details>
<summary>Deferred: v1.74 Structural Integrity (Phases 264-267)</summary>

### v1.74 Structural Integrity

**Goal:** Stabilize the codebase by fixing failing tests, removing dead code, decomposing the worst oversized source files, and extracting agent implementations into a dedicated crate.
**Executable phases:** 264-267

- [ ] **Phase 264: Test Fixes And Dead Code Removal** - The 2 failing pheromone journal recovery tests pass, the 7 ignored tests are resolved, and the swarm-evolution facade crate is deleted from the workspace. (TESTFIX-01, TESTFIX-02, DEADCODE-01)
- [ ] **Phase 265: kitten_agent.rs Decomposition** - kitten_agent.rs (4,479 lines) is replaced by a focused module tree with each submodule under 1,500 lines, preserving the existing public API. (DECOMP-01)
- [ ] **Phase 266: drafting.rs And ingest/tests.rs Decomposition** - drafting.rs (3,763 lines) and ingest/tests.rs (5,751 lines) are each decomposed into focused submodule trees with unsafe env-var mutations replaced by config injection. (DECOMP-02, DECOMP-03)
- [ ] **Phase 267: Agent Crate Extraction** - All eight agent implementations are moved into a dedicated swarm-agents crate; the workspace builds cleanly, all tests pass, and clippy is warning-free. (EXTRACT-01, EXTRACT-02, EXTRACT-03)

### Phase 264: Test Fixes And Dead Code Removal

**Goal:** Restore test-suite integrity and remove the swarm-evolution dead-code facade before structural work begins.
**Requirements:** TESTFIX-01, TESTFIX-02, DEADCODE-01
**Depends on:** v1.73 milestone complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `cargo test -p swarm-pheromone` passes with correct deposit and escalation counts after journal reopen for both previously-failing recovery tests.
2. Every previously-ignored test in swarm-pheromone is either enabled with passing assertions or carries an explicit inline `#[ignore = "reason"]` skip comment.
3. `cargo build --workspace` and `cargo test --workspace` complete without any reference to the swarm-evolution crate.
4. No downstream crate imports swarm-evolution; all such imports have been redirected to swarm-runtime directly.

### Phase 265: kitten_agent.rs Decomposition

**Goal:** Replace the 4,479-line kitten_agent.rs monolith with a focused module tree that is navigable and maintainable without changing the public API.
**Requirements:** DECOMP-01
**Depends on:** Phase 264
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `swarm-runtime/src/kitten_agent.rs` no longer exists as a single flat file; it is replaced by `kitten_agent/mod.rs` plus focused submodules.
2. No extracted submodule exceeds 1,500 lines.
3. The existing `swarm-runtime` public API is preserved: all previously-public types and functions remain accessible at the same paths.
4. `cargo test --workspace` continues to pass with no behavior change.

### Phase 266: drafting.rs And ingest/tests.rs Decomposition

**Goal:** Decompose the two remaining oversized files and eliminate unsafe global environment mutation from the test surface.
**Requirements:** DECOMP-02, DECOMP-03
**Depends on:** Phase 265
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `swarm-runtime/src/drafting.rs` is replaced by a focused module tree with each submodule under 1,500 lines and documented module responsibilities.
2. `swarm-runtime/src/ingest/tests.rs` is decomposed into focused test submodules grouped by tested subsystem.
3. The 7 `unsafe` blocks that mutate environment variables in ingest/tests.rs are replaced by config injection or test-scoped configuration patterns.
4. `cargo test --workspace` passes with no test regressions after both decompositions.

### Phase 267: Agent Crate Extraction

**Goal:** Move all agent implementations out of swarm-runtime and into a dedicated swarm-agents crate so each can be reasoned about and tested in isolation.
**Requirements:** EXTRACT-01, EXTRACT-02, EXTRACT-03
**Depends on:** Phase 266
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. A new `swarm-agents` crate exists in the workspace containing all eight agent implementations: kitten_agent, sphinx_agent, tom_agent, calico_agent, pounce_agent, stalker_agent, weaver_agent, whisker_agent.
2. `cargo build -p swarm-agents` succeeds independently without pulling in the full swarm-runtime surface.
3. `swarm-agents` carries its own focused unit test suite and `swarm-runtime` integration tests continue to exercise the full agent pipeline through the swarm-agents dependency.
4. `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace -- -D warnings` all complete cleanly after extraction.

</details>

<details>
<summary>Shipped: v1.75 Operator Packaging (Phases 268-271)</summary>

### v1.75 Operator Packaging

**Goal:** Package the runtime for first external operator use with curated defaults, deployment docs, quickstart workflow, and validation against a public adversary emulation corpus.
**Executable phases:** 268-271

- [x] **Phase 268: Curated Defaults And Operator UX** - A curated detect-only bootstrap bundle now validates without hand edits, `swarmctl status` leads with an operator-readable one-screen summary, and config or bridge failures emit remediation-grade guidance. (DEFAULTS-01, DEFAULTS-02, OPEXP-01, OPEXP-02)
- [x] **Phase 269: Deployment Documentation** - `docs/QUICKSTART.md` and `docs/DEPLOYMENT.md` now cover Docker Compose first-run, Docker single-container, Compose with NATS, Helm, and bare-metal packaging with verification steps. (DEPLOY-01, DEPLOY-02)
- [x] **Phase 270: Adversary Emulation Corpus** - The repo now ships a mapped adversary-emulation corpus, integration suite, JSON report generator, CI wrapper, and a documented per-technique coverage report with a passing coverage floor. (EMULATION-01, EMULATION-02, EMULATION-03)
- [x] **Phase 271: Quickstart Command And End-To-End Validation** - `swarmctl quickstart` now validates config, runs the built-in first-run scenario, reports elapsed time plus finding proof in one command, and is verified against the packaged Docker image path. (DEPLOY-03)

</details>

### v1.77 Integration Proof

**Goal:** Prove end-to-end integration with one real EDR platform and one real SIEM, replacing generic HTTP wrappers with tested adapters and validating the full detect-to-respond loop with real telemetry.
**Executable phases:** 276-279

- [x] **Phase 276: CrowdStrike RTR Adapter** - A CrowdStrikeRtrAdapter implements ResponseExecutor with OAuth2 service-to-service authentication, session management, host isolation, process kill, and file quarantine actions; it inherits ResilientExecutor retry and circuit-breaker behavior and is validated by a repo-owned mock RTR API integration test suite. (EDRINT-01, EDRINT-02, EDRINT-03)
- [x] **Phase 277: Splunk HEC Adapter** - A SplunkHecAdapter implements ResponseExecutor delivering DetectionFinding payloads to Splunk HEC with CIM-compliant field mapping, configurable batching, secret-resolved HEC token auth, and delivery metrics; it inherits ResilientExecutor retry and circuit-breaker behavior and is validated by a repo-owned mock HEC integration test suite. (SIEMINT-01, SIEMINT-02, SIEMINT-03)
- [x] **Phase 278: E2E Deployment Proof Compose Stack** - A repo-owned Docker Compose stack provisions the runtime with mocked CrowdStrike RTR and Splunk HEC adapters plus one telemetry source bridge; a scripted scenario injects attack telemetry and proves the full detect -> respond -> deliver loop with observable finding delivery, response receipts, and correct CIM field mapping. (E2EPROOF-01, E2EPROOF-02)
- [x] **Phase 279: Integration Architecture Validation** - The deployment proof is completed with a repo-owned integration architecture diagram documenting the telemetry-to-finding-to-response-to-SIEM flow, and all adapter metrics, health endpoints, and audit receipts are validated as correctly populated in the running Compose stack. (E2EPROOF-03)

<details>
<summary>Completed milestone summary: v1.76 External Signal Ingestion (Phases 272-275)</summary>

- [x] **Phase 272: STIX/TAXII Consumer And Threat Intel Enrichment** - A swarm-ingest-taxii crate polls STIX/TAXII 2.1 collection feeds on a bounded interval, maps indicator objects into ThreatIntelEntry records with confidence scores and TTL, deduplicates on re-observation, and enriches behavioral detection findings with IOC context including feed source, STIX indicator ID, and confidence boost. (THREATINTEL-01, THREATINTEL-02, THREATINTEL-03)
- [x] **Phase 273: Cloud Telemetry Bridges** - swarm-ingest-json gains a cloudtrail bridge variant parsing AWS CloudTrail JSON into TelemetryPayload::CloudTrailEvent and a kubernetes_audit bridge variant parsing Kubernetes audit webhook JSON into TelemetryPayload::KubernetesAuditEvent; both bridges register in SwarmConfig, expose health metrics on the existing bridge surface, and are validated by integration tests. (CLOUDBR-01, CLOUDBR-02, CLOUDBR-03)
- [x] **Phase 274: CloudTrail Detector** - A CloudTrailDetector implements DetectionStrategy and detects IAM abuse, resource hijacking, and credential compromise patterns from CloudTrailEvent telemetry, maps findings to existing ThreatClass variants and MITRE ATT&CK cloud technique IDs, produces signed pheromone deposits through the standard pipeline, and carries cloud-specific evidence in finding payloads. (CLOUDDET-01)
- [x] **Phase 275: Kubernetes Audit Detector And Cross-Cloud Integration Proof** - A KubernetesAuditDetector implements DetectionStrategy and detects privilege escalation, RBAC abuse, and container escape indicators from KubernetesAuditEvent telemetry; the milestone closes with an end-to-end integration proof that both cloud detectors produce signed findings with cloud-specific evidence through the full detection pipeline. (CLOUDDET-02, CLOUDDET-03)

</details>


<details>
<summary>Shipped detail sections: v1.75 Operator Packaging (Phases 268-271)</summary>

### Phase 268: Curated Defaults And Operator UX

**Goal:** Operators can reach a working detect_only runtime on first run using curated defaults, and the operator status surface and error messages are clear enough to self-serve.
**Requirements:** DEFAULTS-01, DEFAULTS-02, OPEXP-01, OPEXP-02
**Depends on:** v1.73 milestone complete; v1.74 deferred by operator request
**Status:** Complete
**Plans:** 268-01-PLAN.md
**Success Criteria**:
1. `rulesets/default.yaml` ships with documented detection profiles for all 12 shipped detector strategies; an operator can run `swarmctl init` and `swarmctl validate` without modification.
2. The runtime boots to a ready state on first run using the generated config without manual config editing.
3. `swarmctl status` outputs a single-screen summary of runtime mode, active detectors, bridge health, recent findings count, and escalation state.
4. Error messages from config validation, startup failures, and bridge connection issues include a specific remediation step, not just an error code.

### Phase 269: Deployment Documentation

**Goal:** An operator who has never run Swarm can follow a getting-started guide and reach first detection in under 15 minutes, and the deployment reference covers all supported paths.
**Requirements:** DEPLOY-01, DEPLOY-02
**Depends on:** Phase 268
**Status:** Complete
**Plans:** 269-01-PLAN.md
**Success Criteria**:
1. `docs/QUICKSTART.md` walks an operator from zero to first detection using Docker Compose including telemetry injection, detection observation, and finding inspection via `swarmctl`.
2. A hands-on path through the guide from a clean state produces a visible detection finding within the 15-minute time target.
3. Deployment documentation covers Docker single-container, Docker Compose with NATS, Helm chart, and bare-metal binary paths, each with prerequisites, config snippets, and a verification step.

### Phase 270: Adversary Emulation Corpus

**Goal:** Operators and CI can verify detection coverage against public adversary emulation scenarios and read a per-technique coverage report.
**Requirements:** EMULATION-01, EMULATION-02, EMULATION-03
**Depends on:** Phase 269
**Status:** Complete
**Plans:** 270-01-PLAN.md
**Success Criteria**:
1. The repo includes at least 20 Atomic Red Team techniques adapted as replay scenarios spanning execution, persistence, credential access, lateral movement, and defense evasion tactics.
2. `cargo test` runs an adversary emulation integration suite that replays the corpus through the full detection pipeline and passes with a documented technique-to-detector mapping.
3. A coverage report is generated showing per-MITRE-technique detection status (detected, partial, not covered) and overall technique coverage percentage, meeting the 60%+ coverage target against the mapped corpus.

### Phase 271: Quickstart Command And End-To-End Validation

**Goal:** A new operator can run one command and get to first detection with a measured time-to-detect proof, validating the full operator packaging end-to-end.
**Requirements:** DEPLOY-03
**Depends on:** Phase 270
**Status:** Complete
**Plans:** 271-01-PLAN.md
**Success Criteria**:
1. `swarmctl quickstart` validates the config, starts the runtime, injects a built-in synthetic attack scenario, waits for detection, and prints the finding with elapsed time in one command.
2. The quickstart command completes successfully on a clean install without requiring manual runtime management steps.
3. The end-to-end flow from `swarmctl quickstart` through reported finding serves as the integration-level proof that curated defaults, deployment docs, and corpus validation are all coherent.

</details>

<details>
<summary>Archived detail sections: v1.76 External Signal Ingestion (Phases 272-275)</summary>

### Phase 272: STIX/TAXII Consumer And Threat Intel Enrichment

**Goal:** The runtime can consume external STIX/TAXII 2.1 threat intelligence feeds and enrich behavioral detection findings with matched IOC context.
**Requirements:** THREATINTEL-01, THREATINTEL-02, THREATINTEL-03
**Depends on:** v1.75 milestone complete
**Status:** Complete
**Plans:** 272-01-PLAN.md
**Success Criteria**:
1. `swarm-ingest-taxii` polls a configured STIX/TAXII 2.1 collection URL on a bounded interval and writes IPv4, domain, file hash, and URL indicator objects into the existing pheromone substrate as ThreatIntelEntry records with confidence scores, TTL derived from STIX `valid_until`, and source attribution.
2. Re-observed indicators update confidence and TTL in place rather than creating duplicate entries; the deduplication key is type+value.
3. Feed health (last poll time, indicators ingested, error count) is visible on the existing `/healthz` surface without requiring a separate status command.
4. A behavioral detection finding that matches a threat-intel indicator carries enriched evidence including the IOC value, feed source, STIX indicator ID, and the confidence boost applied, visible in `swarmctl` finding inspection and signed finding envelopes.

### Phase 273: Cloud Telemetry Bridges

**Goal:** The runtime can ingest AWS CloudTrail and Kubernetes audit log telemetry through two new bridge variants that participate in the existing bridge health and metrics surface.
**Requirements:** CLOUDBR-01, CLOUDBR-02, CLOUDBR-03
**Depends on:** Phase 272
**Status:** Complete
**Plans:** 273-01-PLAN.md
**Success Criteria**:
1. `swarm-ingest-json` ships a `cloudtrail` bridge variant that parses AWS CloudTrail JSON records into `TelemetryPayload::CloudTrailEvent` with field mapping for `eventName`, `userIdentity`, `sourceIPAddress`, `requestParameters`, and `responseElements`.
2. `swarm-ingest-json` ships a `kubernetes_audit` bridge variant that parses Kubernetes audit log JSON (webhook backend format) into `TelemetryPayload::KubernetesAuditEvent` with field mapping for `verb`, `user`, `objectRef`, `responseStatus`, and `annotations`.
3. Both cloud bridges register as named entries under `SwarmConfig.runtime.telemetry_sources` and appear in `swarmctl status` bridge health output alongside the existing host-log bridges.
4. Integration tests prove end-to-end delivery from raw cloud JSON through the bridge into `TelemetryPayload` variants without data loss on mapped fields.

### Phase 274: CloudTrail Detector

**Goal:** The runtime can detect IAM abuse, resource hijacking, and credential compromise patterns from AWS CloudTrail telemetry and produce signed findings with cloud-specific evidence.
**Requirements:** CLOUDDET-01
**Depends on:** Phase 273
**Status:** Complete
**Plans:** 274-01-PLAN.md
**Success Criteria**:
1. `CloudTrailDetector` implements `DetectionStrategy` and fires on at least three IAM abuse patterns (CreateAccessKey from unusual principal, ConsoleLogin without MFA from new geography, AssumeRole to privilege-escalation-capable roles), two resource hijacking patterns (RunInstances with crypto-mining AMI patterns, large instance type from unusual principal), and two credential compromise patterns (GetSecretValue/GetParameter from unusual callers).
2. Detected findings include cloud-specific evidence fields: AWS account ID, principal ARN, and the triggering event name.
3. Findings map to existing `ThreatClass` variants and carry MITRE ATT&CK cloud technique IDs in finding metadata.
4. `CloudTrailDetector` produces signed pheromone deposits through the standard pipeline and findings appear in `swarmctl` finding inspection with full evidence payloads.

### Phase 275: Kubernetes Audit Detector And Cross-Cloud Integration Proof

**Goal:** The runtime can detect privilege escalation, RBAC abuse, and container escape from Kubernetes audit telemetry, and both cloud detectors are proven end-to-end through the full detection pipeline.
**Requirements:** CLOUDDET-02, CLOUDDET-03
**Depends on:** Phase 274
**Status:** Complete
**Plans:** 275-01-PLAN.md
**Success Criteria**:
1. `KubernetesAuditDetector` implements `DetectionStrategy` and fires on at least two privilege escalation patterns (create/update ClusterRoleBinding, exec into privileged pod), two RBAC abuse patterns (impersonation, wildcard permissions), and two container escape indicators (privileged container creation, hostPID or hostNetwork).
2. Detected findings include cloud-specific evidence fields: Kubernetes namespace, requesting user or ServiceAccount, and the triggering audit verb plus object reference.
3. Both `CloudTrailDetector` and `KubernetesAuditDetector` findings map to existing `ThreatClass` variants, carry MITRE ATT&CK cloud technique IDs, and produce signed pheromone deposits through the standard pipeline.
4. An integration test proves the full path: cloud bridge JSON ingestion -> `TelemetryPayload` normalization -> detector evaluation -> signed finding with cloud-specific evidence -> `swarmctl` finding inspection for both cloud detectors.

</details>

### Phase 276: CrowdStrike RTR Adapter

**Goal:** The runtime can execute host isolation, process kill, and file quarantine against CrowdStrike-managed hosts through a tested, resilient RTR adapter backed by a repo-owned mock server.
**Requirements:** EDRINT-01, EDRINT-02, EDRINT-03
**Depends on:** Phase 275
**Status:** Complete
**Plans:** 276-01-PLAN.md
**Success Criteria**:
1. `CrowdStrikeRtrAdapter` implements `ResponseExecutor` and translates `ResponseAction::IsolateHost`, `ResponseAction::KillProcess`, and `ResponseAction::QuarantineFile` into CrowdStrike RTR API calls with OAuth2 service-to-service authentication, session creation, command dispatch, and result retrieval.
2. The adapter uses the existing `ResilientExecutor` retry loop and `CircuitBreakerState` circuit-breaker without duplicating resilience logic, and failed actions land in the dead-letter journal.
3. An integration test suite runs against a repo-owned mock RTR API server and covers session creation, each command variant, successful result retrieval, timeout handling, and error status propagation — all without requiring live CrowdStrike credentials.
4. Adapter behavior on auth failure, session expiry, and network timeout is deterministic and observable through structured audit receipts.

### Phase 277: Splunk HEC Adapter

**Goal:** The runtime can deliver detection findings to Splunk HTTP Event Collector with CIM-compliant field mapping, configurable batching, and a tested resilience contract backed by a repo-owned mock endpoint.
**Requirements:** SIEMINT-01, SIEMINT-02, SIEMINT-03
**Depends on:** Phase 276
**Status:** Complete
**Plans:** 277-01-PLAN.md
**Success Criteria**:
1. `SplunkHecAdapter` implements `ResponseExecutor` and delivers `DetectionFinding` payloads to Splunk HEC with configurable index, source, and sourcetype, CIM-compliant field mapping (src, dest, severity, action, signature), and HEC token authentication resolved via `@secret:` references.
2. The adapter batches findings within a configurable flush interval and max batch size; it inherits the existing `ResilientExecutor` retry and `CircuitBreakerState` circuit-breaker without duplicating resilience logic.
3. Delivery metrics — events sent, bytes delivered, error count, and p99 delivery latency — appear on the existing `/metrics` surface without requiring a separate endpoint.
4. An integration test suite runs against a repo-owned mock HEC endpoint and covers batch delivery, CIM field mapping correctness, authentication, backpressure (HTTP 429), and error status propagation without requiring live Splunk credentials.

### Phase 278: E2E Deployment Proof Compose Stack

**Goal:** A repo-owned Docker Compose stack proves the full detect-to-respond-to-deliver loop with mocked EDR and SIEM endpoints and a scripted attack scenario, observable without live vendor credentials.
**Requirements:** E2EPROOF-01, E2EPROOF-02
**Depends on:** Phase 277
**Status:** Complete
**Plans:** 278-01-PLAN.md
**Success Criteria**:
1. A repo-owned `docker-compose.yml` starts the runtime with the CrowdStrike RTR adapter pointed at a mocked RTR server, the Splunk HEC adapter pointed at a mocked HEC endpoint, and at least one telemetry source bridge active — all from a single `docker compose up` without manual config editing.
2. A scripted scenario injects attack telemetry into the running stack, and an operator can observe a detection finding generated, a policy-gated response action dispatched through the CrowdStrike adapter (with a receipt), and the finding delivered to the Splunk adapter with correct CIM field mapping.
3. The Compose stack's health surface (`/healthz`, `/metrics`) reports all adapter and bridge components as healthy after scenario completion.

### Phase 279: Integration Architecture Validation

**Goal:** The detect-to-respond-to-SIEM flow is documented in a repo-owned integration architecture diagram, and the Compose stack proves all adapter metrics, health endpoints, and audit receipts are correctly populated.
**Requirements:** E2EPROOF-03
**Depends on:** Phase 278
**Status:** Complete
**Plans:** 279-01-PLAN.md
**Success Criteria**:
1. A repo-owned integration architecture diagram (Mermaid or equivalent, checked into `docs/`) depicts the telemetry source bridge -> detection -> policy gate -> CrowdStrike RTR adapter -> Splunk HEC adapter flow with named crate boundaries, data types crossing each boundary, and health/metrics surfaces.
2. After running the scripted Compose scenario, all adapter metrics (events sent, errors, circuit-breaker state), all health endpoint fields for both adapters, and all audit receipts for the dispatched response action are confirmed populated with non-zero/non-null values.
3. The integration proof as a whole is executable as a single scripted validation step (`make integration-proof` or equivalent) that passes in CI without live vendor credentials.


### v1.78 Runtime Decomposition And TCB Boundary

**Goal:** Green the verification gates, eliminate the `core.inc` include pattern, split the 97,709-LOC `swarm-runtime` crate along its existing module seams, and name and enforce a trusted computing base, so every later milestone builds on real crate boundaries instead of a monolith.
**Executable phases:** 280-283

- [x] **Phase 280: Verification Gate Repair** - Replace crate-wide clippy opt-outs with reviewed per-call-site allows, widen the panic contract beyond swarm-runtime, and stop the supply-chain check suppressing its own findings. (GATEFIX-02, GATEFIX-03, GATEFIX-04)
- [x] **Phase 281: core.inc Elimination** - Replace the four 22,762-line `.inc` include files with ordinary modules and decompose the CLI into one module per command domain. (INCFIX-01, INCFIX-02, INCFIX-03)
- [x] **Phase 282: Crate Extraction From swarm-runtime** - Break three known dependency cycles, then extract HTTP, workbench, agents, ingest, and part of the evolution lane into real crates. Complete-as-scoped and merged 2026-08-13 (0a09358); SPLIT-02's replay half, ~~5 of 8 agents~~ and 7 of 10 evolution modules do NOT move, each blocked by a trait inversion rather than by ordering, recorded in ADRs 0002-0008. (SPLIT-01, SPLIT-03, SPLIT-05)
  CORRECTED 2026-08-13 (task #14): it is **3 of 8 agents** that did not move, not 5 — the count was inverted while being restated from ADR 0004's era, and ADR 0007 has since moved `tom`. `ls crates/swarm-runtime/src/*_agent.rs | wc -l` prints 3 (`calico`, `kitten`, `sphinx`); `ls crates/swarm-agents/src/*_agent.rs | wc -l` prints 5. Also corrected: "each blocked by a trait inversion" is true of the evolution lane and FALSE of replay — the replay half is blocked by the composition root NAMING `crate::replay` (3 pins at `cc5b169`), not by `harness.rs` constructing `SwarmRuntime`; inverting that executor is an architecture improvement off the critical path. Full re-derivation with commands in `.planning/PHASE-282-REMAINDER.md`.
- [x] **Phase 283: TCB Boundary And Layering Enforcement** - Name `swarm-policy` + `swarm-crypto` + `swarm-spine` as the trusted base and enforce the boundary in CI. (TCBOUND-01, TCBOUND-02, TCBOUND-03, TCBOUND-04)

### Phase 280: Verification Gate Repair

**Goal:** NOTE (2026-08-11): GitHub Actions has never validated this work - every run on the branch failed in 2-4s with zero steps executed, and the test, clippy, jetstream, and benchmark jobs were skipped. `.github/workflows/ci.yml` does wire in every gate this phase repaired, so the phase's value is only realized once CI itself is fixed; no requirement owns that. Ambush's supply-chain gate suppresses its own findings and its panic contract covers a narrower surface than it appears to. Refactoring on top of gates that do not enforce is unsafe, so this phase runs before any structural change.
**Requirements:** GATEFIX-01, GATEFIX-02, GATEFIX-03, GATEFIX-04
**Depends on:** v1.77 milestone complete
**Status:** Complete 2026-08-11
**Plans:** TBD
**Success Criteria**:
1. `cargo clippy --workspace --all-targets -- -D warnings` is verified exit-0 on the branch tip in an isolated worktree with an empty target directory, and the result is recorded; the "~41 violations against `main`" figure is WRONG and was corrected on completion: `main` is already clippy-clean because the opt-outs suppress the lints; stripping all 8 yields at least 85 errors across two crates before cargo aborts, so 85 is a lower bound. The substance (clean where the unsuppressed baseline is not) is verified.
2. The crate-wide `#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]` opt-outs in 8 files (not the 3 originally named: also `swarm-whisker`, `swarm-response`, `swarm-ingest-json`, `swarm-ingest-sentinel`, `swarm-ingest-tetragon`) are replaced by MODULE-level `#[allow(clippy::unwrap_used, clippy::expect_used)]` on `#[cfg(test)] mod tests` declarations (101 -> 110 sites), so the granularity moves from crate-wide to module. RESTATED ON COMPLETION: the original wording said "per-call-site"; that was not delivered and was judged not worth 110 call-site annotations. Accepted limitation: a new unwrap inside an already-allowed test module is still permitted. Production code uses a genuine per-call-site allow paired with a `// SAFETY: runtime panic contract exception` marker, documented in Cargo.toml.
3. `bash tools/check-runtime-panic-contract.sh` scans every workspace crate's production code, and its in-file documentation states exactly which surfaces it does and does not cover.
4. `cargo deny check advisories licenses bans sources` passes with no `-A duplicate` suppression (present at `tools/check-supply-chain.sh:8` on both main and the branch), and `deny.toml` raises `[bans] multiple-versions`, `[sources] unknown-registry`, and `[sources] unknown-git` from `warn` to `deny`.
5. The suite passes with zero failures on a clean checkout, measured with the commands CI actually runs (`cargo test --workspace` is not a supported invocation here; it conflates the known `SWARM_*_TEST_TOKEN` env-var race into false failures):
   - `cargo test --workspace --exclude swarm-runtime`
   - `cargo test -p swarm-runtime -- --test-threads=1`
   - `bash tools/with-nats-jetstream.sh cargo test -p swarm-pheromone --test jetstream --test multi_instance -- --ignored`
   Baseline measured 2026-08-10 on a pristine clone at b637a11: command 1 exit 0 (476 passed, 0 failed); command 2 exit 101. CORRECTED ON COMPLETION: the real baseline is 9 failures, not 7 - the original 7 came from a fail-fast run. The two extra (`concurrent_bridge_registry_feeds_shared_whisker_pipeline`, `host_log_bridge_registry_feeds_detectors_and_reports_metrics`) were stale bridge-registry fixtures, not parallelism artifacts. All 9 are fixed. The failures are genuine - they survive both a pristine clone and serial execution - and this criterion owns fixing them:
   - `control::tests::first_run_completes_detection_approval_and_proof`
   - `http::core::tests::approval_vote_endpoint_resumes_demo_runtime_and_proof_export` (0 vs 1)
   - `ingest::tests::providence_feedback::dismiss_feedback_reaches_kitten_or_pending_fallback` (500 vs 200)
   - `ingest::tests::readyz_reports_jetstream_unreachable_detect_only_transition` (503 vs 200)
   - `replay::core::tests::evaluation_report_passes_expected_scenario_and_flags_regressions` (`passed == false`)
   - `replay::core::tests::named_suite_manifest_runs_with_metadata_and_technique_groups` (`suite.passed == false`)
   - `service::tests::runtime::process_event_forwards_enriched_findings_to_siem` (auth `None` vs `Some("Splunk splunk-secret")`)

### Phase 281: core.inc Elimination

**Goal:** Four `#[path = "core.inc"]` files hold 22,762 lines that `cargo fmt`, clippy, rust-analyzer, and every LOC tool skip. Removing the pattern is a prerequisite for splitting the crate, since the includes cross crate boundaries.
**Requirements:** INCFIX-01, INCFIX-02, INCFIX-03
**Depends on:** Phase 280
**Status:** Complete 2026-08-11 (INCFIX-01 for the 3 single-owner files, INCFIX-03; INCFIX-02 deferred to 282 with the two-owner CLI file)
**Plans:** TBD
**Success Criteria**:
1. SCOPED 2026-08-11: the three single-owner `.inc` files are replaced by ordinary `.rs` modules -- `swarm-runtime/src/{http,replay,workbench}/core.inc` (8,153 + 5,425 + 3,902 = 17,480 lines). `crates/swarm-cli/src/core.inc` (5,394) is DEFERRED to phase 282: it is included by TWO crates (`swarm-cli/src/lib.rs:79` and `swarm-runtime/src/cli/mod.rs:1` via `../../../`), so eliminating it decides which crate owns the CLI, which is SPLIT-01..06 territory -- and 282 criterion 1 requires cycles be broken before any crate is cut. `find crates -name '*.inc'` therefore returns 1, not 0, at the end of 281.
   NOTE FOR 282's PLANNER: eliminating it may not require deciding ownership at all. Splitting it into `swarm-cli/src/cli/` modules and repointing the cross-crate include at `#[path = "../../../swarm-cli/src/cli/mod.rs"]` keeps the include working while removing the `.inc`, since nested `mod` declarations resolve relative to the included file. INCFIX-03 forbids new `#[path = "*.inc"]`, not `#[path]` itself.
2. SCOPED 2026-08-11: the 800-line limit applies to the CLI decomposition's resulting files, per INCFIX-02's actual wording ("with no resulting file exceeding 800 lines"), NOT workspace-wide. Taken literally the original wording covered 66 files and 129,032 LOC -- milestone scale, and already assigned elsewhere: deferred v1.74 phases 265 and 266 name `kitten_agent.rs` (4,516), `drafting.rs` (3,812), and `ingest/tests.rs` (5,991) explicitly, and phase 282 splits the remainder by crate. Because the CLI surface IS `swarm-cli/src/core.inc`, INCFIX-02 defers to 282 with it; phase 281 delivers INCFIX-01 (3 of 4 files) and INCFIX-03.
3. SUPERSEDED 2026-08-11: this criterion's premise is FALSE and cannot be satisfied as written. rustfmt DOES follow `#[path]` into `.inc` files, disproved two-sided: a formatting violation appended to a still-`.inc` file makes `cargo fmt --all -- --check` exit 1, and `rustfmt --check` on the pristine `core.inc` files exits 0 (they were already formatted). clippy reads them too. Only rust-analyzer and `*.rs`-globbing LOC/complexity tools skip a `.inc` -- two tools of the four INCFIX-01 names. The conversion is still worth having on those grounds; the fmt-coverage claim is not. Do not inherit it in 282/283.
4. A CI check fails the build if a new `#[path = "*.inc"]` directive or non-`.rs` Rust source file is added.

### Phase 282: Crate Extraction From swarm-runtime

**Goal:** Turn one 115,156-LOC crate (97,709 excluding `.inc`) into several. The seams exist as modules but three of them are cyclically coupled, so this phase breaks the cycles before cutting the crates.
**Requirements:** SPLIT-01, SPLIT-02, SPLIT-03, SPLIT-04, SPLIT-05, SPLIT-06
**Depends on:** Phase 281
**Status:** Complete as scoped 2026-08-13, merged as 0a09358. MEASURED per criterion 4: swarm-runtime/src 120,431 -> 77,868; swarm-ingest-runtime 17,956; ~~swarm-runtime-http 10,381~~; swarm-evolution 7,066 (real source, replacing the facade); swarm-runtime-workbench 4,064; swarm-agents 3,366. SPLIT-02's replay half, ~~5 of 8 agents~~ and 7 of 10 evolution modules did NOT move: each needs a trait inversion, not code motion, and neither inversion can ride inside an extraction diff. SPLIT-06's LOC targets are arithmetically unreachable with the extractions SPLIT-01..05 name AND self-contradictory (landing SPLIT-04's seven modules in swarm-evolution breaches the same requirement's own 20,000 ceiling); re-derive them from coupling, not from a budget. Tracked as task #14.

RE-DERIVED 2026-08-13 against the merged tree (task #14). Full analysis with every command in `.planning/PHASE-282-REMAINDER.md`. Four corrections to the line above:
- **swarm-runtime-http was 10,391 at 0a09358, not 10,381** — a digit transposition. `git archive 0a09358 crates/swarm-runtime-http/src | tar -xO -f - '*.rs' | wc -l` prints 10391. Every other figure in the list reproduces exactly.
- **3 of 8 agents did not move, not 5.** `ls crates/swarm-runtime/src/*_agent.rs | wc -l` prints 3. ADR 0007 moved `tom` after ADR 0004 was written.
- **"each needs a trait inversion" holds for the evolution lane and not for replay.** Replay is pinned by three sites in the root naming `crate::replay` (`lib.rs:240/243/246`, `detector_factory.rs:8`, `evasion_coverage.rs:7`), and the first of those three is the SAME enum that pins the evolution lane. Once the root stops naming replay, `swarm-runtime-replay -> swarm-runtime` is a legal forward edge and `harness.rs` may keep constructing `SwarmRuntime` verbatim. ADR 0003's executor inversion is worth doing, separately and later, to make the replay crate a leaf.
- **There is a THIRD pin the ADRs recorded only as "corroborating".** `runtime_events.rs:4` and `service/mod.rs:46` name `crate::evolution_status::EvolutionStatusReport` in production code, and `evolution_status.rs` names `canary`, `evolution`, `mutation` and `selection` in production code. It is now the LARGEST term in ADR 0005's own progress measure (19 of 39, vs `lib.rs`'s 7), so landing the `StrategyProposalRouteError` inversion ALONE moves zero lines.

MEASURED at cc5b169: swarm-runtime/src 80,615 (up 2,747 since the merge, phase 320's containment work). Unlanded extractions would remove: replay/ 8,142; the three agents 8,932; the seven evolution modules 31,860 — 48,934 total, leaving swarm-runtime at 31,681, which is the measured floor and is 6,681 over SPLIT-06's 25,000. The seven evolution modules condense into a three-node DAG (canary+evolution+promotion+strategy 15,304; drafting+mutation 14,627; selection 1,929), which is what a coupling-driven SPLIT-06 should be built on.
**Plans:** TBD
**Success Criteria**:
1. ORDERING CORRECTED 2026-08-12. The roadmap sequenced the self-contained extractions (http, replay, workbench) before the deeply-coupled ones (agents, evolution, ingest); the dependencies run the OTHER WAY and that order cannot work. Proven in part A by making Cargo say it: extracting replay while the evolution lane is still inside swarm-runtime yields `error: cyclic package dependency: package swarm-runtime depends on itself. Cycle: swarm-runtime -> swarm-runtime-replay -> swarm-runtime -> swarm-cli`, because replay imports `crate::service` which this criterion requires to STAY. 52 non-test references reach back into `crate::replay` from 24 files, overwhelmingly the evolution lane. A compile probe commenting out `pub mod replay;` produces 36 errors across 20 files.
   After SPLIT-04 and SPLIT-05 the coupling collapses to FOUR references in TWO files -- `lib.rs:118,121,124` (`#[from]` error variants) and `detector_factory.rs:8` (`DetectorCandidateManifest`) -- which are type and error definitions, not logic.
   CORRECTED SEQUENCE: cycles -> http -> agents -> evolution -> ingest -> decouple those four references -> replay -> workbench -> CLI. `swarm-runtime-workbench` has no such coupling and was delivered in part A. SPLIT-02 IS NOT DELIVERED until replay lands.
   A SECOND consequence of the same inversion: `axum` cannot leave `swarm-runtime`'s manifest until SPLIT-05, because `ingest/` (8 files), `providence.rs`, `threat_intel_runtime.rs` and `http/rate_limit.rs` still use it -- and SPLIT-05 itself names `crate::http::rate_limit::HttpRateLimiter` as ingest's dependency. Five of the six transport dependencies did leave with SPLIT-01.
1b. The three known cycles are broken before any crate is cut: `service/` stays in the remainder rather than moving into the HTTP crate, `OperatorSurfacePaths` is relocated out of `http`, and a `swarm_core::agent` trait boundary replaces `dispatcher.rs`/`lib.rs` imports of concrete `crate::*_agent` types.
2. `swarm-runtime-http`, `swarm-runtime-replay`, `swarm-runtime-workbench`, `swarm-agents`, and `swarm-ingest-runtime` exist as workspace crates, and `swarm-evolution` contains real source rather than an 8-line facade.
3. `crates/swarm-runtime/Cargo.toml` no longer depends on `axum`, `hyper`, `hyper-util`, `tokio-rustls`, `rustls-pemfile`, or `x509-parser`.
4. RESTATED 2026-08-12, because the original target is arithmetically unreachable with the extractions SPLIT-01..05 name, and SPLIT-06 itself admits the gap ("the five originally-planned extractions remove roughly 66,000, leaving about 48,800 before `service/` and ingest placement are decided"). Measured on main @0018e6a: `swarm-runtime/src` is 120,431 LOC counting `.inc`. Extracting ALL SIX named groups removes 83,093 and leaves 37,338 -- above the 25,000 target -- because the remainder IS the composition root (config 2,692, dispatcher 2,633, control 2,627, approval 2,450, plus `service/`, which SPLIT-01 explicitly requires to STAY). `swarm-evolution` lands at 36,700, above the 20,000 cap. The criterion is therefore: every extraction in SPLIT-01..05 lands, the three cycles are broken first, and the resulting per-crate LOC is MEASURED AND RECORDED rather than asserted against a number chosen before the code was counted. Further splitting to reach <25,000 belongs to a follow-on phase, and should be driven by coupling rather than by a LOC budget.
   Projected after extraction: swarm-runtime 37,338 | swarm-evolution 36,700 | swarm-ingest-runtime 13,479 | swarm-agents 12,137 | swarm-runtime-http 8,632 | swarm-runtime-replay 8,118 | swarm-runtime-workbench 4,027.
4b. RE-DERIVED 2026-08-13 (task #14) against the merged tree at cc5b169; the projection in 4 was made on `.inc`-inclusive LOC at 0018e6a and no longer describes this tree. `.planning/PHASE-282-REMAINDER.md` carries the commands. The conclusion in 4 is unchanged and the numbers are:
   - MEASURED FLOOR for swarm-runtime if every extraction SPLIT-01..05 names lands in full: **31,681** (80,615 now, minus replay/ 8,142 + three agents 8,932 + seven evolution modules 31,860 = 48,934). Still 6,681 over 25,000, and the residue is `service/` 5,663, `config.rs` 2,692, `dispatcher.rs` 2,616, `approval.rs` 2,450, `evolution_status.rs` 2,251, `lib.rs` 2,211, `detection/` 2,165 and sixteen smaller root modules — the composition root itself.
   - SELF-CONTRADICTION, measured: landing SPLIT-04's seven in `swarm-evolution` gives 7,067 + 31,860 = **38,927**, nearly double the same requirement's 20,000 ceiling.
   - COUPLING-DRIVEN ALTERNATIVE: the seven condense into a three-node DAG — A `{canary, evolution, promotion, strategy}` 15,304; B `{drafting, mutation}` 14,627 (depends on A); C `{selection}` 1,929 (depends on A and B). A and B are genuine SCCs and cannot be subdivided without a design change. The DAG holds for test code too, so no dev-dependency edge is needed in either direction. Two crates (A with the existing swarm-evolution = 22,371; B+C = 16,556) breach the ceiling by one crate; three crates (7,067 / 15,304 / 16,556) do not.
   - THE PLAN NOTE'S TWO CLAIMS, checked: `mutation/` 10,631 and `evolution/` 6,862 are correct AT 0a09358 and are directory-only — they exclude the module roots `mutation.rs` (74) and `evolution.rs` (78) where the `#[path]` declarations and the `crate::replay`/`crate::strategy` imports live. At cc5b169 the movable units are 10,814 and 7,707. "Each stands alone" is FALSE: `mutation` and `drafting` are a two-module SCC, and `evolution` is in a four-module SCC with `canary`, `promotion` and `strategy`. `service/` is 5,663 (5,643 at the merge, so the size is right) but "can follow replay out" is BACKWARDS — outside `service/` and `replay/` only `lib.rs:848` names it, while `service/` itself names ten root modules including phase 320's `containment.rs`. It is the composition root's service layer, and moving it needs the executor inversion plus a decision on those ten edges.
   - THE MEASURE ITSELF IS BLIND to 5,413 lines. `crates/swarm-cli/src/core.inc` is `#[path]`-included by two crates and counted in neither: swarm-cli is 177 `.rs` / 5,590 compiled, swarm-runtime-http is 10,450 `.rs` / 15,863 compiled. Neither breaches 20,000 today, but a LOC ceiling checked by an instrument that cannot see two crates' real size is this project's catalogued failure mode applied to a gate. Amend the clause to say `*.rs` under `src/` PLUS `#[path]`-included non-`.rs` source, or land INCFIX-02 first.
5. INCFIX-02 and `crates/swarm-cli/src/core.inc` are in scope here, inherited from phase 281: two crates include that file (`swarm-cli/src/lib.rs:79` and `swarm-runtime/src/cli/mod.rs:1` via `../../../`), which makes it an ownership question. Note from 281: splitting it into `swarm-cli/src/cli/` and repointing the include at `#[path = "../../../swarm-cli/src/cli/mod.rs"]` may remove the `.inc` without deciding ownership at all, since nested `mod` declarations resolve relative to the included file.
5. `cargo build --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` all pass at each phase boundary, not only at the end.

### Phase 283: TCB Boundary And Layering Enforcement

**Goal:** `swarm-policy` is already dependency-clean and nothing enforces that it stays that way. Name the trusted base and make the boundary a build-time guarantee before six later milestones add code around it.
**Requirements:** TCBOUND-01, TCBOUND-02, TCBOUND-03, TCBOUND-04
**Depends on:** Phase 282
**Status:** Complete 2026-08-13. All four criteria met; two requirement PATHS were stale and were corrected rather than created (`docs/adr/` -> `docs/decisions/`, `scripts/` -> `tools/`), and criterion 3's transport clause is met with one measured, baselined deviation the shipped tree already carried. Details on each criterion below.
**Plans:** TBD
**Success Criteria**:
1. `docs/adr/ADR-0001-trusted-computing-base.md` names `swarm-policy` + `swarm-crypto` + `swarm-spine` as the TCB and states in negative-space form what they must never depend on.
   MET at `docs/decisions/0009-trusted-computing-base-boundary.md`. PATH CORRECTED: `docs/adr/` does not exist and never has; ADRs live in `docs/decisions/` numbered 0001-0008, so the requirement's path would have created a second ADR tree whose first entry collided in number with `0001-rust-first-runtime.md`. Four negative-space prohibitions: never a transport or command line (in ANY dependency kind), never anything above the TCB, never the advisory lane, never a `pub` widening (already owned by `check-visibility-baseline.sh`).
2. Each of the six trust-sensitive crates carries an "Owns / does not own" section in its crate-level doc comment.
   MET. The six were identified by measurement, not assumption: TCBOUND-02 names `swarm-policy`, `swarm-pheromone`, `swarm-response`, `swarm-guard`, `swarm-crypto`, `swarm-spine`, and all six are workspace members under `crates/`. The sections are ENFORCED by RULE 5 of the gate, so this criterion cannot rot into prose. Two crates were considered and excluded with stated reasons: `swarm-consensus` (trust-sensitive and already manifest-clean, but phase 321 is rewriting it) and `swarm-core` (inside the TCB closure and enforced as such, but it is the shared vocabulary every crate depends on).
3. `scripts/check-workspace-layering.sh` runs as a required CI step and fails when a TCB crate gains a product or transport dependency, proven by a deliberately-broken fixture.
   MET at `tools/check-workspace-layering.sh`. PATH CORRECTED: there is no `scripts/` directory, gates live in `tools/`, and `tools/check-gates-wired.sh` only enumerates `tools/check-*.sh` — landing it at the requirement's path would have made it invisible to the gate that exists to catch unrun gates. Wired unconditionally into the `panic-contract` job; disabling that step was OBSERVED to fail `check-gates-wired.sh`.
   THE PRODUCT LIST IS DERIVED, NOT TYPED. TCBOUND-03's three names predate phase 282's split into seven crates. The gate derives "above the TCB" from `cargo metadata` (workspace crates reaching the TCB but outside its closure — 14 today) and raises a vacuity failure if any of the requirement's three names stops being in that set.
   ONE MEASURED DEVIATION, baselined rather than narrowed away. The transport rule is stated over DECLARED edges in all three kinds, because on the RESOLVED normal graph the TCB is not transport-free today: `cargo tree -p swarm-spine -i reqwest -e normal` prints `reqwest <- swarm-response <- swarm-spine`, and `hyper` follows from `reqwest`. Rule 3 enforces the resolved graph against exactly those two edges; a third fails the build and a baseline entry that stops holding also fails the build. What deletes them is a trait inversion of `swarm-spine -> swarm-response`, which belongs to a phase that owns crate shape.
4. The same script fails if `swarm-policy` or `swarm-response` gains a dependency on the memory or correlation modules, making v1.82's advisory-lane boundary a build-time guarantee.
   MET, with the modules LOCATED rather than assumed: `crates/swarm-runtime/src/sphinx_agent.rs` (memory, `memory.enabled`) and `crates/swarm-runtime/src/correlation.rs` (correlation, `correlation.enabled`), both hosted by `swarm-runtime`. Stated over the hosting crate, which is strictly stronger while the modules live there, and aimed by a registry that fails the build loudly if a registered path stops existing — so the lane cannot move out from under the rule.
   THE FIXTURE RUNS ON EVERY INVOCATION and is a real cargo workspace, not a mock: real crate names, stub path crates literally named `axum`/`clap`/`hyper`/`reqwest` so nothing is fetched, real `cargo metadata`, and the SAME rule engine with the SAME policy and baseline. One control case that must exit 0 (without it the nine broken variants prove nothing) plus nine deliberately-broken variants, four of which are inversions cargo itself accepts. Additionally observed against the REAL tree: `clap` in `swarm-policy`'s `[dependencies]` plus `swarm-runtime` in its `[dev-dependencies]` produced five diagnostics; tree restored.

### v1.78.1 Critical Defect Repair

**Goal:** Repair three defects reachable in the running system today before thirty-five phases of capability are built on top of them: containment with no undo, a Byzantine threshold that can deadlock governance, and a promotion gate that ignores its own solver results.
**Executable phases:** 320-322

- [x] **Phase 320: Reversible Quarantine Execution** - Promote the preview-only blast-radius and rollback model into a real executor with TTL auto-revert and a receipt-chained undo path. (QRT-01, QRT-02, QRT-03, QRT-04)
- [~] **Phase 321: BFT Correctness Repair** - Fix the `(n-1)/2` sizing bug, make the single-governor-key property structural, and measure what a seeded loss/delay corpus actually shows about the commit bound. (BFT-01, BFT-02, BFT-03, BFT-04, BFT-05)
- [x] **Phase 322: Promotion Solver Gate** - Make the production promotion path read the solver results the Z3 lane already produces. (ZGATE-01, ZGATE-02, ZGATE-03, ZGATE-04, ZGATE-05)

### Phase 320: Reversible Quarantine Execution

**Goal:** `QuarantineFile` dispatches to real EDR adapters while nothing can reverse it. The system can contain a host and cannot un-contain it. This is the highest-blast-radius gap in the codebase.
RESTATED 2026-08-13 to measured reality, the way 742206d restated phase 282 criterion 4: the original "no rollback executor exists anywhere in `swarm-response`" was true before 4d03543 and is false now. What is true today is that rollback TYPES exist and are constructed only in tests — zero production constructors of `ContainmentLease`, and `SandboxRollbackExecutor::rollback` never branches on `ResponseRollbackStepKind`, so it performs no inverse action.
**Requirements:** QRT-01, QRT-02, QRT-03, QRT-04
**Depends on:** v1.78 milestone complete
**Status:** IN PROGRESS. Wave 1 landed 2026-08-13: QRT-01, QRT-02 and QRT-03 are done, QRT-04 is deliberately deferred. Criteria 1, 2 and 4 are met with two stated limits; criterion 3 is not started. Earlier note kept for the record: 4d03543 shipped types only — zero production code constructed a ContainmentLease, and SandboxRollbackExecutor::rollback performed no side effect, so the phase was 0/4 and not 2/4. See task #19.
**Plans:** TBD
**Success Criteria**:
1. Execute-and-rollback coverage exists for quarantine, suspend, isolate, and session-terminate, persisting a lease carrying blast radius, rollback plan, governance receipt, and expiry.
   MET 2026-08-13 with two stated limits. All four actions now open a lease on execution via `SwarmRuntime::record_containment_lease`, carrying blast radius, rollback plan, governance receipt id, the typed action, and a mandatory expiry. Three of the four have executable rollback (`resolve_inverse` -> `HttpEdrRollbackExecutor`), proven against a stateful fake EDR by asserting the fake's set of contained targets, not the receipt. LIMIT 1: `TerminateUserSession` resolves to `Irreversible` by design, and `fully_reversed()` is false for it — a receipt claiming otherwise would be a false audit record. LIMIT 2: CrowdStrike and webhook deployments get the sandbox rollback executor, whose receipts report `Simulated`/`Irreversible` rather than `Reversed`; a real CrowdStrike inverse is open follow-up.
   BASELINE MEASURED 2026-08-13 (before the above), criterion was 0/4 not 4/4: all four actions EXECUTE (SandboxExecutor adapters.rs:19-35; HttpEdrAdapter http_edr.rs:68/89/128/140; WebhookAdapter webhook.rs:72-99) and all four have a DERIVED inverse plan (service/preview.rs:157, :268, :383, :462), but zero have executable rollback and zero persist a lease. Two known limits to state rather than paper over: CrowdStrike can reverse only 2 of the 4 (crowdstrike_rtr.rs:453-481), and `TerminateUserSession` has no true inverse — preview.rs:295-305 says the terminated session cannot be resumed.
2. A lease past its TTL is auto-rolled-back by the background sweep within one sweep interval with no operator action.
   MET 2026-08-13, and stated as a deterministic property rather than a wall-clock one: `sweep(now_ms)` takes the instant as a parameter, so "one sweep at or after expiry releases, one before does not" is pinned by two integer literals. The loop bound `expiry + interval_ms` follows by construction from `run_until_shutdown` ticking on `interval_ms`; no test asserts on elapsed time. `swarm_detect --serve` spawns the sweep and awaits its handle on both shutdown arms.
3. `swarmctl quarantine release <lease_id>` performs manual early rollback through the same governance signing path, and a tampered rollback receipt fails verification.
   NOT MET, deferred with reasons 2026-08-13. Manual release exists and is literally the same function the TTL sweep calls (`release_lease`); the CLI surface and the receipt SIGNATURE do not. Blockers, both measured: split-brain governance state between `swarmctl` and a running daemon over an unlocked `data/governance-partition-state.json`, and `swarm-cli` not depending on swarm-agents/swarm-response/swarm-policy. See QRT-04 in REQUIREMENTS.md.
4. An end-to-end test executes containment then both manual and TTL rollback and asserts the target resource is fully restored to its pre-containment state.
   MET at the response layer, restated to what is actually asserted. `http_edr::rollback_tests` contains a host through `HttpEdrAdapter`, asserts the fake EDR's contained set holds the target, rolls back through `HttpEdrRollbackExecutor`, and asserts the set no longer holds it — restoration verified as an effect. `containment::tests::a_manual_release_and_an_expiry_sweep_run_the_same_function` covers both triggers over one store and asserts each reached the executor. What is NOT covered: a single test driving `SwarmRuntime` -> lease -> sweep -> real inverse end to end in one process; that wants QRT-04's wiring to be worth writing once.

### Phase 321: BFT Correctness Repair

**Goal:** RESTATED 2026-08-13 to measured reality; the original text is kept in the criteria below where it still applies. The sizing half is closed: f55c3bd fixed `recommended_max_faulty`, now at `crates/swarm-consensus/src/lib.rs:74` returning `(committee_size - 1) / 3`, and threshold survival after exclusion is asserted directly. What was still open at that point is the SHAPE of the round: `GovernancePolicy` held `governors: BTreeMap<AgentId, SigningKey>` and reached its decision by building one in-process `ConsensusNode` per key, so the type permitted one process to cast every committee member's vote.
**Requirements:** BFT-01, BFT-02, BFT-03, BFT-04, BFT-05
**Depends on:** Phase 320
**Status:** 4 of 5 criteria met. BFT-01/BFT-02 shipped in f55c3bd; `can_act`'s fail-open with no governor key was closed in b4bf119 (task #18). BFT-03 and BFT-05 are met as stated below; BFT-04 is PARTIAL and criterion 5 records exactly which half. SEVERITY STATED ACCURATELY, and this correction matters: the shipped binary registers exactly ONE governor (`crates/swarm-runtime-http/src/bin/swarm_detect.rs` is the only `AgentRole::Tom` registration), and MEASURED 2026-08-13, every one of the 13 `register_governor` call sites in the tree -- production and test -- registers exactly one key per policy. So `governors.len() == 1` everywhere and the multi-node loop inside `simulate_governance_commit` had ZERO coverage at n>1 before it was deleted. BFT-03 was worth doing as "make the one-key property structural", not as "stop a live multi-key leak".
**Plans:** `.planning/plans/bft-plan.md` (written pre-282-merge; re-verified and corrected against the tree, see Requirement corrections in STATE.md)
**Success Criteria**:
1. `recommended_max_faulty` computes `(n-1)/3`, with a regression table asserting 4->1, 7->2, 10->3, 13->4.
   MET in f55c3bd (`recommended_max_faulty_follows_three_f_plus_one`).
2. A correctly sized committee still reaches its threshold after excluding the maximum tolerable number of Byzantine members, asserted directly rather than in prose.
   MET in f55c3bd (`threshold_survives_excluding_the_maximum_tolerable_faulty_members`).
3. `simulate_governance_commit`'s co-located-key path is removed from production; no production path holds more than one governor signing key in memory.
   MET, and the second clause is CHECKABLE rather than asserted -- by three mechanisms whose coverage boundaries are all written down. `simulate_governance_commit` and `collect_signed_progress` are DELETED, not moved to `#[cfg(test)]`: nothing in the tree ever called them with more than one key, so a test-only multi-key simulator would have been dead code, and `swarm-consensus`'s own multi-node tests plus the new loss/delay harness cover multi-node rounds properly. (1) TYPE: `GovernanceState.local_governor: Option<LocalGovernorKey>`, a type with no `SigningKey` accessor -- catches a second key inside that struct, at compile time, and nothing outside it. (2) TEST: `register_governor` returns `Err(GovernanceKeyError::SecondSigningKey)`, propagated through `TomAgent::new_with_signing_key` to the composition root -- catches a runtime attempt through the public API. (3) GATE: `tools/check-single-governor-key.sh`, wired at `.github/workflows/ci.yml` in the `panic-contract` job, scans the three governance-signing source paths for a collection-of-`SigningKey` outside `#[cfg(test)]` and inventories the shipped opaque authority across its exact eight-crate normal reverse-dependency closure. Its 94-case fixture (76 adversarial, eighteen controls) includes compiler proof that the exact safe generic/default-alias field-shorthand and type-erased recovery exploits are valid Rust; compiler proof that inferred `transmute_copy` is accepted without and rejected under `forbid(unsafe_code)`; locked Cargo-metadata package-ID closure derivation, exact manifests, normal lib/bin roots, public method/impl identities, and raw, recursively derived Rust privacy closures rooted at every private-authority field owner; hidden-header trait impls, trait-default and extern leaks, renamed private aliases/imports, raw-policy accessors, trait conversions, and type-inferred raw-memory construction. The gate requires the compiler unsafe prohibition on every shipped normal lib/bin target in that closure, rejects custom build targets, inventories every regular file in each closure package regardless of extension, pins the exact sanctioned non-Rust `core.inc` input and `#[path]` graph, and compares Cargo/rustc dep-info for all thirteen normal lib/bin targets against the exact compiler-input inventory. Compiler-backed fixtures exercise literal, `#[path]`, macro-hidden, arbitrary-cfg, release/non-debug, untracked, outside-workspace, and safe included sources under consumer-style `--cap-lints allow`. The protected negative-registry contract binds the exact gate, root workspace manifest and lock, all eight closure manifests, every regular closure-package file, all compiler target/input identities, and the private-field privacy closure, and independently mutates arbitrary constructors, trait-transmute forgery, safe alias forgery, inferred downstream transmute, safe Any recovery, descendant split-helper Any recovery, renamed workspace-inherited dependency escape, trait-default and extern leakage, a real git-dependency cap-linted included-source escape, checker weakening, source redirection, and build-script injection. It still cannot prove the absence of two `GovernancePolicy` instances in an arbitrary downstream process; the shipped builder's same-Arc identity test covers dispatcher, ingest, containment, and human resume.
4. A seeded message-loss and delay harness proves commit completes within the documented bound, and the phase states which fault classes it did not exercise.
   MET with the bound EXPLICITLY NOT CLAIMED, which is the honest reading. `crates/swarm-consensus/tests/loss_delay_bound.rs` runs 192 virtual-clock episodes (sizes 4/7/10 x 64 seeds) with seeded loss and delay and no wall-clock anywhere. MEASURED, loss+delay: 192/192 commit, 169/192 inside `round_timeout_ms * (max_faulty + 1)`, 5 episodes have EVERY proposer in rounds 0..=f silent. MEASURED, delay-only: 187/192 inside the bound and the 5 that miss it are exactly those 5 leader-schedule episodes -- delay alone never costs a round. The bound is not a theorem here because `ConsensusCommittee::proposer_for` is an independent per-round argmax rather than a rotating permutation, so f+1 consecutive faulty proposers are reachable; VRF-02 (phase 301) is what removes that precondition. What IS asserted unconditionally is the conditional version: a live round-0 proposer plus zero round-0 loss forces a round-0 commit (161 of 192 episodes qualify on the delay-only corpus, 13 of 192 under loss), and an all-silent leader schedule provably cannot commit inside the bound. Two negative controls prove the oracle can report failure: all-n silent, and f+1 silent with live traffic still flowing. Fault classes NOT exercised are enumerated in the test file header: Byzantine equivocation under loss, split proposals, invalid signatures under loss, per-node clock skew, partition/heal, governor crash-restart mid-round, cross-height replay, and real transport faults.
5. (ADDED 2026-08-13; BFT-04 had no matching criterion, recorded as missing at STATE.md.) `GovernancePolicy::can_act` reaches its decision through a `ConsensusNode` the policy owns and envelopes published to a `ConsensusTransport`, never through a locally held peer key; `GovernanceDecision::{Allow, Veto}` and the serialized `ConsensusGovernanceReceipt` field set are unchanged; `crates/swarm-runtime/src/dispatcher.rs` carries no governance-logic diff; and a round that cannot reach `committee.threshold()` within `round_timeout_ms * (max_faulty + 1)` returns Veto naming the cause, not Allow.
   PARTIAL, and the missing half is named rather than implied. MET: the round is driven by `swarm_consensus::drive_round` over a `ConsensusTransport`; the policy owns exactly one node built from its own key; `GovernanceDecision` is untouched; the receipt JSON is pinned by `the_governance_receipt_wire_shape_is_unchanged`, which also asserts `prevote_tally >= threshold`, `precommit_tally >= threshold` and `committee_members.len() == threshold` so a round that silently degenerated to one node would fail it; `dispatcher.rs`'s only change is the `.expect` on a now-fallible `TomAgent` constructor in its own `#[cfg(test)]` fixture; a non-committing round returns Veto carrying the consensus error verbatim. NOT MET: the round is not NETWORKED. The only transport that ships is `SoloGovernorTransport`, which serves a committee of one and REFUSES anything larger, so a peer-governor deployment fails closed instead of running a real multi-member round. `ConsensusTransport` is synchronous by design (a mailbox), and a transport that must wait for peers forces `can_act` to become `async`; that change, and BFT-03's "over the pheromone substrate" clause, are deferred. Contingency-lease issuance was deliberately left on the same synchronous path: `ensure_contingency_leases_locked` runs a round for each of twelve destructive action kinds from the SYNCHRONOUS `observe_health` on every tick, and networking that is a different change of a different size (DISTGOV-02, phase 303).

### Phase 322: Promotion Solver Gate

**Goal:** `crates/swarm-runtime/src/promotion.rs` never references `solver_summary` (verified: zero occurrences), so an evolved detector can reach production with no recorded solver result while the Z3 lane runs and is ignored.
PATH CORRECTED and BLOCKER WITHDRAWN 2026-08-13: this phase is executable now and always was. `crates/swarm-evolution/src/promotion.rs` does not exist; the real file is `crates/swarm-runtime/src/promotion.rs`, 2,901 lines, and its 0-occurrence measurement holds. STATE.md's claim that phase 282 had to "restore real source first" was wrong on all three counts.
DEFECT FOUND 2026-08-13 that changes this phase's shape (task #17): the bypass is not merely a missing gate. `selection.rs:1045` mints a proposal with `assurance: None, review_state: AcceptedForCanary` without calling `evaluate_proposal_assurance`, and `crates/swarm-ingest-runtime/src/ingest/mod.rs:436-463` then FABRICATES `EvolutionProposalAssuranceSummary { decision: Passed, solver: { required: false, status: None } }` and persists it. So the automated route reaches promotion having never run the solver gate AND leaves an audit record affirming that it passed. Closing that fabrication is the part that closes the hole; ZGATE-01/02 alone would protect a route that is already protected.
**Requirements:** ZGATE-01, ZGATE-02, ZGATE-03, ZGATE-04, ZGATE-05
**Depends on:** Phase 321
**Status:** COMPLETE 2026-08-13. ZGATE-01/02/04 plus the fabricated-attestation fix and the `solver-z3` CI lane landed in 99733a0; ZGATE-03/05 and the posture decision (task #23) closed after it.
POSTURE DECISION RECORDED, and it is the half of this phase that needed a human answer: enabling the gate made promotion refuse in EVERY shipped configuration, and that is ACCEPTED as the intended posture rather than treated as a regression. Automated promotion of evolved detectors is OFF by default; an evolved detector does not reach production without a recorded solver proof. The posture is now legible where an operator hits it — `docs/DEPLOYMENT.md` Notes and a `Default Promotion Posture` section in `docs/EVOLUTION.md` carrying the enable recipe — rather than discoverable only by reading a test.
ZGATE-03's shape changed on contact with the code, and the change is recorded here because the requirement text still reads as if a distinction were missing. It is not: the feature-off arm and `enable_z3: false` both already produce `EvolutionSolverProofStatus::Disabled`, and `promotion_solver_block` already maps it onto the same `Missing` variant as an absent status. The real gap was `rulesets/default.yaml:236-238` listing `disabled` in `evolution.assurance.allowed_solver_statuses` — unfixable in this repository, because that file's sha256 is inside the ed25519-signed `rulesets/attestation.json` and the signing key is deliberately absent. So the fix went into the CONSUMING code: the promotion gate reads the assurance allow-list nowhere, and that is now enforced by a test rather than left as a convention.
**Plans:** TBD
**Success Criteria**:
1. `require_solver_result_for_promotion` exists, defaults true in the curated ruleset, and is read by `promotion.rs`. MET 99733a0 — "defaults true in the curated ruleset" resolves to "a ruleset omitting the key resolves to true", since the curated file cannot carry the key.
2. A promotion whose solver summary is absent is rejected with a named, matchable variant when the gate is enabled. MET — `ProductionPromotionError::SolverResultMissing { recorded_status: None }`.
3. A build without the `z3` feature carrying a custom-Z3 bundle is rejected identically, so a disabled-solver stub never counts as a passed proof. MET, end to end: `promotion_is_denied_when_the_solver_lane_was_disabled` runs the real formal-safety gate over a `custom_z3` bundle, takes the status that build actually records, and requires `SolverResultMissing { recorded_status: Some(Disabled) }`. The same test covers the config-disabled case under `--features z3`.
4. The promotion report prints the solver proof id and attestation hash, or an explicit no-solver-result line, for every run. MET 99733a0 by the second branch of the "or": every report carries `Solver result: <status> | required_for_promotion=<bool>` or the exact literal `Solver result: NO SOLVER RESULT RECORDED`. The proof id and attestation hash are NOT on the promotion report; they are on the proof artifact the lineage references.
5. (Added with the posture decision.) The default posture is documented where an operator meets it, with a followable enable recipe, and the recipe is executed rather than described: `the_documented_recipe_produces_a_proof_that_promotes` reads the `custom_z3` query out of `docs/EVOLUTION.md` and runs it through a real z3, and the default-feature lane reads the same block. Editing the doc's query so it no longer proves fails the test (measured).

### v1.79 Collective Cyber Reasoning

**Goal:** Make Ambush a collective reasoning system: construct competing typed causal theories from cross-telemetry, have agents acquire and falsify evidence through stigmergic task allocation, simulate containment, and turn measured outcomes into reusable strategy and herd memory. Phase 285 must first close its reopened governance/detector integration gate under a truthful local+hosted evidence boundary; external GitHub App enforcement remains explicitly deferred.
**Executable phases:** 284-289

- [x] **Phase 284: Fixture Determinism And Suite Health** - Keep the evidence substrate deterministic and isolated. (FIXTURE-01..04; historical prerequisite)
- [ ] **Phase 285: Assurance Foundation Closure** - Preserve local and hosted assurance evidence, negative controls, locked supply-chain evidence, and truthful status reporting; close the reopened governance/detector integration gate; defer provenance-distinct external GitHub App enforcement. (ASSURE-01..06)
- [ ] **Phase 286: Collective Hypothesis Graph** - Build a typed causal graph with competing hypotheses, role-based evidence claims, stigmergic task allocation, contradiction tracking, kill-chain reconstruction, ranked containment simulation, and strategy memory. (COG-01..08)
- [ ] **Phase 287: Adversarial Co-evolution Arena** - Run bounded red campaigns and blue investigations through the real Ambush runtime, mutate evasions, synthesize candidates, and retain only measured improvements. (ARENA-01..08)
- [ ] **Phase 288: Autonomous Detector And Response Synthesis** - Generate typed detector and response candidates, evaluate them against attacks and controls, and promote only fail-closed, operator-reviewed candidates. (SYNTH-01..06)
- [ ] **Phase 289: Herd Memory** - Transfer signed, abstract attack strategy between swarms without raw telemetry, with corroboration, expiry, poisoning resistance, and withheld-campaign evaluation. (HERDMEM-01..06)

### Phase 284: Fixture Determinism And Suite Health

**Goal:** Preserve the deterministic, isolated evidence substrate that the collective-reasoning phases consume.
**Requirements:** FIXTURE-01, FIXTURE-02, FIXTURE-03, FIXTURE-04 (historical prerequisite)
**Depends on:** v1.78 milestone complete
**Status:** Complete 2026-08-11
**Plans:** Existing completed phase plans
**Success Criteria**:
1. The fixture generator and freshness gate are deterministic and detect checked-in drift.
2. Supported suite runs do not mutate the checkout.
3. The clean baseline remains reproducible.

### Phase 285: Assurance Foundation Closure

**Goal:** Close the assurance foundation on a truthful local-plus-hosted evidence boundary while explicitly deferring provenance-distinct external GitHub App/repository protected-check enforcement.
**Requirements:** ASSURE-01, ASSURE-02, ASSURE-03, ASSURE-04, ASSURE-05, ASSURE-06
**Depends on:** Phase 284
**Status:** Reopened 2026-08-24; in progress with 4 of 13 plans accepted. The 2026-08-21 pass claim did not include the subsequently reopened governance/detector integration gate.
**Plans:** Accepted clean checkpoints: approval/voters `f2eb791d`, persistence architecture `5be011a0`, production protocol slice `27b64174`, reviewed witness-adapter contract `eacadf6b`, session fence `3a584882`, witness-envelope model `296bb983`, witness-service wire `a9837f21`, Plan 01 response/candidate-verifier slice `f29f2832`, Plan 02 revision-CAS store/reference/proxy slice `ff762236`, Plan 03A transport/dependency boundary `cf0ad8b`, and Plan 03B pinned JetStream CAS/restart slice `8abe28d`. Plan 04 is accepted through A2b2 `30eb13c`; A2b3 `ed77183` is banked but unaccepted. R83's selective 9/3 per-leg omission and isolated source/target provenance correction passed independent P0/P1/P2/P3=`0/0/0/0` review at `4de9c2d`. The resulting R1a candidate `1decdd7` completed four physical positives and 23/23 controls but is rejected under `refs/rejected/phase285/plan04-task03a2b3r1a-1decdd7`: canonical transport passed and canonical deadline failed on stale first-private/fifth-public queue-expiry trace expectations. The next attempt must be a fresh direct child of A2b3 with only those two oracle traces corrected before full evidence regeneration in a new canonical target. Fixed-lane and recovery completion, detector integration, the frozen combined-tree gate, hosted CI, and closure evidence remain open.
**Success Criteria**:
1. Local combined-tree mapping, negative-registry, fixture, and locked-SBOM evidence are reproducible.
2. Fresh hosted Linux evidence is commit-bound and credential-free.
3. Status distinguishes wired, executed, passed, and protected-required; no protected GitHub App or release claim is made.
4. No unresolved P0/P1/P2 finding remains in the scoped review.
5. The reviewed external witness contract is implemented fail-closed, including the bounded session fence and pinned persistence semantics, and one immutable combined Phase 285 tree passes the full local, mutation, independent-review, hosted, and closure gates.

### Phase 286: Collective Hypothesis Graph

**Goal:** Turn a seed signal into a shared, contestable causal incident model rather than a single irreversible classification.
**Requirements:** COG-01, COG-02, COG-03, COG-04, COG-05, COG-06, COG-07, COG-08
**Depends on:** Phase 285
**Status:** Blocked behind Phase 285. Plan 04 is independently accepted as a frozen checkpoint, but Phase 286 is not publishable or advanceable.
**Plans:** Plan 04 checkpoint `1408620e`; remaining Phase 286 execution resumes only after Phase 285 closure.
**Success Criteria**:
1. A typed graph represents actors, assets, credentials, processes, and events plus confidence/provenance causal edges; competing hypotheses retain uncertainty and contradictions.
2. Hunter, challenger, and falsifier agents claim leased unresolved edges without duplicate work, and process, identity, Kubernetes, CloudTrail, network, and threat-intelligence evidence normalize into the graph.
3. Every kill-chain claim links to evidence; ranked containment simulations report predicted blast radius and reversibility without executing; strategy memory persists.
4. The benchmark measures median time to correct causal hypothesis (>=20% gain over single-agent), attack-chain recall (+10 percentage points), false causal edges (<=10%), duplicate work (<=5%), and evidence coverage (>=90%).

### Phase 287: Adversarial Co-evolution Arena

**Goal:** Measure collective intelligence against bounded red campaigns and benign controls through the real Ambush runtime.
**Requirements:** ARENA-01, ARENA-02, ARENA-03, ARENA-04, ARENA-05, ARENA-06, ARENA-07, ARENA-08
**Depends on:** Phase 286
**Status:** Plan set independently reviewed and parked; execution stopped until Phases 285 and 286 close in sequence.
**Plans:** Parked planning checkpoint `e88204e7`.
**Success Criteria**:
1. Red agents compose reusable multi-stage tactics in a deterministic sandbox; blue agents investigate and contain through real runtime boundaries; red cannot reach response authority.
2. Red mutates evasions from observed blue behavior and blue generates detector/response candidates from escapes.
3. Candidates compete on historical attacks, benign controls, counterexamples, and withheld campaigns.
4. The benchmark measures time to containment (>=15% median improvement), containment blast radius (no median increase), at least one previously unseen evasion in three seeded runs, >=10% improvement over the single-agent baseline, and withheld-campaign performance no worse than 5%.

### Phase 288: Autonomous Detector And Response Synthesis

**Goal:** Generate and evaluate new defensive strategies from graph gaps and adversarial escapes, promoting only candidates that pass safety and evidence gates.
**Requirements:** SYNTH-01, SYNTH-02, SYNTH-03, SYNTH-04, SYNTH-05, SYNTH-06
**Depends on:** Phase 287
**Status:** Plan set independently reviewed and parked; execution stopped until Phase 287 closes.
**Plans:** Parked planning checkpoint `e88204e7`.
**Success Criteria**:
1. Detector candidates use the typed graph vocabulary and response candidates use a bounded policy library.
2. Candidates are evaluated against historical attacks, benign controls, counterexamples, and withheld campaigns with differential, mutation, and metamorphic controls.
3. Solver/approval lineage and operator review are required for promotion; fail-closed behavior rejects missing, stale, or contradictory evidence.
4. At least one target metric improves by >=10% with no safety regression.

### Phase 289: Herd Memory

**Goal:** Transfer reusable attack abstractions between swarms without sharing raw telemetry, while resisting poisoning and preserving local epistemic control.
**Requirements:** HERDMEM-01, HERDMEM-02, HERDMEM-03, HERDMEM-04, HERDMEM-05, HERDMEM-06
**Depends on:** Phase 288
**Status:** Plan set independently reviewed and parked; execution stopped until Phase 288 closes.
**Plans:** Parked planning checkpoint `e88204e7`.
**Success Criteria**:
1. Memory records contain typed attack abstractions only, never raw telemetry, secrets, or host identifiers; signatures, provenance, expiry, and transformations are explicit.
2. Local corroboration, revocation, retention, and deletion are enforced; retrieval may change task ordering but cannot directly authorize action.
3. Poisoning and stale-memory controls are tested.
4. Transfer improves time to correct hypothesis by >=20% or recall by >=10 percentage points without exceeding false-edge/duplicate ceilings, discovers a previously unseen evasion, and stays within 5% of baseline on withheld campaigns.

### Historical v1.79 Assurance Foundation (retired 2026-08-21; not an acceptance set)

The original DST/FUZZ/LOOM/SUPPLY sequence and its MAPPING/FALSIFY protected-check claim remain below as historical planning notes. They are not active or queued acceptance criteria; their useful assurance work is represented by ASSURE-01..06 above, and the deferred external GitHub App boundary is not silently counted as passed.

### Historical Phase 284: Fixture Determinism And Suite Health

**Goal:** NOTE (2026-08-11): the "7 tests fail against 161 checked-in fixtures" premise did NOT reproduce - e93d521 had already removed 137 of them and the grep returned 0 before this phase began. The real work was isolation, the generator, and the freshness gate. Test runs write into the repository. Every later assurance signal is unreadable until the baseline is green and isolated.
**Requirements:** FIXTURE-01, FIXTURE-02, FIXTURE-03, FIXTURE-04
**Depends on:** v1.78 milestone complete
**Status**: Complete 2026-08-11 (executed out of order, ahead of v1.78, as a prerequisite for parallel work)
**Plans:** TBD
**Success Criteria**:
1. `cargo test -p swarm-runtime kitten_agent` passes with zero failures and zero schema-drift skips.
2. `grep -rl command_line_normalization experiments/` returns empty. ALREADY SATISFIED as of 2026-08-10 (returns 0); e93d521 removed 137 such fixtures. Verify rather than re-do.
3. `tools/check-fixture-freshness.sh` regenerates into a scratch directory, diffs against checked-in copies, fails on drift, and runs as a required CI step.
4. A full suite run across all three supported commands (see phase 280 criterion 5) leaves `git status --porcelain` empty. Today each run mutates 10 tracked files; 24 of them live under `crates/swarm-cli/data/approval-*/`, which is already gitignored, so they must be untracked rather than ignored.

### Historical Phase 285: Assumption Registry And Invariant Mapping

**Goal:** Convert fail-closed from a README assertion into an auditable table linking each invariant to the exact function enforcing it and the assumption beneath it, with broken variants proving each check actually fires.
**Requirements:** MAPPING-01, MAPPING-02, MAPPING-03, MAPPING-04, MAPPING-05, FALSIFY-01, FALSIFY-02, FALSIFY-03, FALSIFY-04
**Depends on:** Phase 284
**Status:** 7/9 requirements delivered. MAPPING-05 and FALSIFY-04 remain externally blocked on a provenance-distinct protected check: the Free organization cannot pin an organization-owned required workflow, and the existing Actions App/check name is spoofable, so the Free-plan path is a dedicated external GitHub App check with a separate integration ID. The mapping decision is ADR 0012, avoiding the trust ADR 0011 collision; the current integration branch includes the combined trust/security re-derivation.
**Plans:** TBD
**Success Criteria**:
1. `docs/assurance/assumptions.toml` parses and enumerates at least 8 named assumptions, each with an owner and dependent invariants.
   MET with 13, parsed by `tomllib`. `ASSUME-STATEFUL-GATE-DETERMINISM` models only local policy rate-window transitions; external adapter outcomes use `ASSUME-EXTERNAL-ADAPTER-BEHAVIOR`, and release-signer membership uses `ASSUME-GOVERNANCE-TRUST-ANCHOR`. Rows name multiple assumptions where appropriate, and the gate requires exact many-to-many set equality.
2. `docs/assurance/MAPPING.md` carries at least 12 invariant rows spanning `swarm-policy`, `swarm-response`, `swarm-runtime`, and `swarm-spine`, each naming an existing `crate::module::function` path.
   MET with 59 executable rows across the four named crates, plus five enforced omissions. `docs/assurance/universe.toml` records exact IDs/counts, mapped/omitted disjointness, and exact one-surface assignment. The checker strips comments/literals, resolves only modules reachable from each crate root (including inline and `#[path]` modules), and requires each marker to precede an executable decision in the exact function. This local ratchet detects drift unless the checker is coherently changed too; it is not described as externally immutable.
   THE HONEST CAVEAT IS IN THE TABLE. Ten of the seventeen swarm-spine rows are on `verify_chain_link`, which has NO production caller: searching outside its own file and negative test returns only the `pub use` re-export. They are mapped ahead of the caller deliberately. That measurement surfaced a real gap: `swarm_runtime::approval::build_vote_envelope_hash` BUILDS an envelope chain and nothing ever verifies it. Reported, not fixed.
3. `scripts/check-mapping.sh` is a required CI step and demonstrably fails against a deliberately unmapped `// INVARIANT:` marker.
   CODE AND WORKFLOW MET at `tools/check-mapping.sh`, including adversarial comment/string and marker-adjacency fixtures. The workflow invokes it unconditionally. That does not authenticate the workflow: protected enforcement remains open on the dedicated external GitHub App check described in the phase status.
   DEMONSTRATED by one clean control, five module-resolution controls, and fourteen adversarial fixtures, including an unmapped marker, coordinated row/marker/assumption deletion, deletion of all omissions, comment/string spoofing, wrong-function adjacency, a nested compiled-module marker, and an orphan `ghost.rs` module. The real-tree inventory comes from Cargo's rustc dep-info rather than a source-directory walk.
4. Every MAPPING.md row has a `negative_*.rs` test asserting a broken variant permits what the real function denies; `scripts/check-negative-registry.sh` fails on any missing entry.
   CODE AND WORKFLOW MET at `tools/check-negative-registry.sh`: 59 built-in `#[test]` wrappers across four files plus a separate five-test compiled protocol contract. The gate reports 179 self-tests (3 clean controls, 176 adversarial), including fourteen protected governance-assurance mutations. They cover source/protocol/production-binding evasions plus fake proc macros, compiler and cfg substitution, executable build dependencies, Cargo runner/target redirection, all registered-crate manifest drift, external Cargo-home build.rustc/wrapper/workspace-wrapper/rustflags/linker/runner attacks, ancestor configuration, toolchain redirection, cwd/PYTHONPATH module shadowing, pre-entry BASH_ENV/ENV and loader injection, hostile SHELLOPTS/BASHOPTS/exported functions, PATH-shadowed Bash, exact fresh-runner job topology, complete descendant LD_/DYLD_ stripping, and the opaque-governance authority gate's root-workspace, eight-manifest, target-root, complete regular-file package snapshot, Cargo/rustc dep-info target/input inventory, and recursively derived private-field privacy identity. It pins toolchain, manifests, lock resolution, metadata targets, and package/source artifact identity. The thirteenth governance mutation compiles the exact macro-hidden, non-`.rs`, release-only unsafe escape against a self-contained, local-only git dependency under `--cap-lints allow`, then proves both the direct and protected contracts reject the corresponding real source mutation. The fourteenth proves an empty, unhydrated Cargo cache fails closed. Before any proof compile, the gate validates the exact tracked manifest, lock, source/checksum policy, and execution-input snapshot, fetches only that locked/checksummed resolution into an empty config-free cache, proves the lock and snapshot remained unchanged, and returns every proof compile to `--locked --offline`. Every Cargo command uses the pinned Cargo/rustc and sanitized process settings; a gate-owned isolated-Python wrapper forces and audits one exact test-mode compilation per target, and emitted test binaries run directly under a sanitized environment for exact inventory and passed/ignored counts. Dedicated `mapping-contract` and `negative-registry-contract` jobs use separate fresh Ubuntu runners with only a pinned credential-free checkout before their absolute `/usr/bin/env -i` custom-shell launchers. That fresh hosted runner is the explicit bootstrap trust root; local workflow/checker edits remain co-editable, and protected external check provenance remains open.
   Each registry row records its neutralization observation and binds the shared macro-owned call to an exact fully-qualified public production entry. The local checker digests each complete registered source file and the shared protocol AST, so imports, helper/wrapper bodies, setup, call arguments, normalization, mirror operations, and predicates are all within the checked source contract. Mapped markers and real adapters share that public entry; only two Serde conversions are explicitly reviewed boundaries. The protocol executes one real, mirror(None), and mirror(BrokenVariant) operation on one typed probe and asserts the real/control denial and broken permission differential. The co-located checker and digests are tamper-evident, not externally authenticated.
   WHAT IT CANNOT CHECK, STATED: a handwritten mirror is not mechanically proven faithful beyond the registered probe. The compiled differential, source mutations, exact production-expression binding, and review stand in for that broader proof.

### Historical Phase 286: Deterministic Simulation Testing

**Goal:** Prove receipt-before-action ordering and no-double-dispatch hold under adversarial scheduling and mid-operation crashes, not only on the happy path.
**Requirements:** DST-01, DST-02, DST-03, DST-04, DST-05, DST-06
**Depends on:** Phase 285
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. The harness drives the real `SwarmRuntime::authorize_and_execute`, a real approval gate, and the real substrate, with no mocks.
2. At least three fault classes are injected: future-drop before dispatch, future-drop after dispatch but before receipt persistence, and substrate close/reopen between policy-allow and receipt-persist.
3. A 64-seed corpus runs on every PR and a 5,000-seed corpus nightly, naming the failing seed on any oracle violation.
4. `SWARM_DST_SEED=<n>` reproduces one episode's exact fault plan, and MAPPING.md states the evidence boundary as single-process and single-substrate-instance.

### Historical Phase 287: Fuzz, Loom, And Supply-Chain Hardening

**Goal:** Give the untrusted telemetry-parse boundary and the concurrent write paths executable adversarial coverage, and bring dependency policy to a dated, justified, deny-by-default shape.
**Requirements:** FUZZ-01, FUZZ-02, FUZZ-03, FUZZ-04, LOOM-01, LOOM-02, LOOM-03, LOOM-04, SUPPLY-01, SUPPLY-02
**Depends on:** Phase 286
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Four cargo-fuzz targets call real parse entry points, seeded from existing fixtures, with a 30s smoke pass on every PR and a 600s nightly run that uploads any crashing input.
2. Loom harnesses over the pheromone and policy concurrent paths pass nightly with a documented preemption budget, labeled `bounded_abstract_model` in MAPPING.md.
3. Every `deny.toml` ignore entry carries a date, blast-radius note, and clearing condition, enforced by `tools/check-supply-chain.sh`.
4. The `cargo audit --ignore` list is deduplicated against `deny.toml` so the two cannot drift apart.
### Historical v1.80 Red Swarm (retired 2026-08-21; superseded by v1.79 arena)

**Goal:** Land an adversary as a first-class, deterministic, catalog-bounded in-tree lane so detectors are scored against something that adapts generation over generation, with fitness measured on the existing evasion-coverage infrastructure and a bounded arms race running in CI.
**Executable phases:** 288-291

- [ ] **Phase 288: Red Operator Genome And Target Graph** - Six operator roles recombine already-catalogued techniques into deterministic sequences, replacing verbatim suite replay. (OPFOR-01, OPFOR-04)
- [ ] **Phase 289: Attack Scoring, Stealth Budget And Pattern Memory** - Score plans against the real catch-rate surface, cap noise, and remember per-technique outcomes. (ATKSCORE-01, ATKSCORE-03)
- [ ] **Phase 290: Bidirectional Co-Evolution And Convergence** - Close the loop against real detector outcomes with a bounded stopping rule. (COEVOLVE-01, COEVOLVE-02)
- [ ] **Phase 291: CI Arms Race Gate And Structural Isolation** - Wire a real executed gate and enforce that the red lane can never reach response authority. (ARMSCI-01, ARMSCI-02)

### Historical Phase 288: Red Operator Genome And Target Graph

**Goal:** `red_swarm.rs` today replays static suites verbatim. Give the red lane a bounded mutation engine that recombines catalogued techniques rather than inventing payload shapes, keeping the arms race classical and maintainable.
**Requirements:** OPFOR-01, OPFOR-02, OPFOR-03, OPFOR-04
**Depends on:** v1.79 milestone complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Six operator roles implement a shared trait, and the target graph's technique-node set equals the union of the catalog's declared techniques and every suite scenario's declared techniques.
2. `RedGenome::plan` is proven pure: identical arguments produce byte-identical output, and a 20-seed sweep produces at least one differing step per seed.
3. A test fails if any generated step names a technique absent from the target graph.
4. `swarmctl red-swarm plan` prints a `determinism` object with `rng_seed`, `virtual_clock_start_ms`, and `scheduler`, and no code path reads wall-clock for output bytes.

### Historical Phase 289: Attack Scoring, Stealth Budget And Pattern Memory

**Goal:** Turn plans into scored, resource-bounded telemetry so red cannot win by volume, and give each generation real memory of what the previous one survived.
**Requirements:** ATKSCORE-01, ATKSCORE-02, ATKSCORE-03, ATKSCORE-04
**Depends on:** Phase 288
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. A fully caught plan scores `red_fitness == 0.0`; a plan built only from declared-uncovered techniques scores above 0.5.
2. A manifest capping events per generation bounds emitted events accordingly, with identical truncation order across runs at the same seed.
3. The pattern store round-trips: an unrecorded technique returns success rate 1.0, an always-detected technique returns 0.0.
4. `swarmctl red-swarm score --json` prints `red_fitness`, `evasion_rate`, `stealth`, and `events_emitted` as top-level fields.

### Historical Phase 290: Bidirectional Co-Evolution And Convergence

**Goal:** Make both sides actually move, measured against real detector runs rather than self-play estimates, and guarantee every campaign terminates.
**Requirements:** COEVOLVE-01, COEVOLVE-02, COEVOLVE-03, COEVOLVE-04
**Depends on:** Phase 289
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. A campaign configured for 6 generations never executes a 7th, for a fixed seed.
2. A campaign whose fitness plateaus stops early with `stop_reason == "plateau"`.
3. Over at least 4 generations, blue catch rate is non-decreasing on average and red technique weights measurably shift away from generation-zero favourites once recorded as caught.
4. Two invocations at the same seed produce byte-identical campaign reports except for a generated-at timestamp.

### Historical Phase 291: CI Arms Race Gate And Structural Isolation

**Goal:** Ship an executed gate rather than an attested one, and enforce structurally that the red lane generates telemetry and scores detectors without ever reaching response authority.
**Requirements:** ARMSCI-01, ARMSCI-02, ARMSCI-03, ARMSCI-04, ARMSCI-05
**Depends on:** Phase 290
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. CI runs the bounded campaign and fails if final blue catch rate regresses below the checked-in threshold, reading the file the executor actually writes.
2. The isolation script exits 0 on the real tree and exits 1 against a fixture with an injected response-execution call, proving it is not vacuous.
3. A Rust-side companion test performs the same check at test time, with a documented counterexample.
4. `swarmctl evolution status --json` reports the campaign object, and reports null rather than a stale value when the report file is absent; a wall-clock guard fails a runaway campaign loudly.

### v1.81 Machine-Checked Decision Core

**Goal:** Extract an IO-free decision core from the policy gate and the governance predicates, bind it to Kani bounded model checking and named safety properties, model the partition-contingency-lease state machine in TLA+, and make the existing Z3 lane actually gate promotion.
**Executable phases:** 292-294

- [ ] **Phase 292: Pure Decision Core Extraction** - Carve out total, clock-injected, lock-free decision functions, enforced by a dependency-boundary script. (DCORE-01, DCORE-02)
- [ ] **Phase 293: Kani Bounded Model Checking** - Bounded-check fail-closed evaluation, severity gating, rate-limit bounds, and lease integrity. (KANI-01, KANI-03)
- [ ] **Phase 294: Named Safety Properties And Partition-Lease Model** - Name P1-P6, map them, and model-check the highest-risk concurrent protocol with negative falsifiability. (SAFEP-01, SAFEP-04)

### Phase 292: Pure Decision Core Extraction

**Goal:** Chio's proof apparatus exists only because an IO-free decision surface exists. `can_act` currently reads the OS clock internally and the gates hold state in a mutex. This phase is the prerequisite for everything after it.
**Requirements:** DCORE-01, DCORE-02, DCORE-03, DCORE-04, DCORE-05
**Depends on:** v1.79 milestone complete and v1.78.1 complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `crates/swarm-policy/src/formal_core.rs` holds the approval, severity, rate-limit, and lease predicates as pure functions with no mutex, filesystem, clock, or network call in their bodies.
2. `GovernancePolicy::can_act` no longer calls `now_ms()` internally; the clock is caller-supplied at every entry into `formal_core`.
3. `cargo tree -p swarm-policy` contains no transport, telemetry, or CLI crate, enforced by `scripts/check-decision-core-boundary.sh` in CI.
4. Every pre-existing gate and governance test passes unchanged against the new call paths.

### Phase 293: Kani Bounded Model Checking

**Goal:** Catch regressions in fail-closed behavior, blast-radius conservation, and lease-forgery rejection in CI rather than in an incident.
**Requirements:** KANI-01, KANI-02, KANI-03, KANI-04, KANI-05
**Depends on:** Phase 292
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. At least 8 `#[kani::proof]` harnesses call the real public functions from `formal_core.rs`.
2. Every harness that models an abstraction rather than the literal production symbol is labeled `MODEL-ONLY`, naming the runtime test that provides complementary coverage.
3. A manifest lists every harness, and a unit test fails the build when a harness is missing from it.
4. The PR-lane runner completes within configured timeouts and is wired into CI.

### Phase 294: Named Safety Properties And Partition-Lease Model

**Goal:** State the decision core's guarantees as named, mapped, falsifiable properties, and model-check the partition-contingency-lease protocol, the highest-risk concurrent logic in the system.
**Requirements:** SAFEP-01, SAFEP-02, SAFEP-03, SAFEP-04, SAFEP-05
**Depends on:** Phase 293
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. P1-P6 are each defined with exact symbols and the harnesses that check them, and appear as rows in `docs/assurance/MAPPING.md` with valid existing Rust paths.
2. `ASSUME-INJECTED-CLOCK` and `ASSUME-GOVERNOR-KEY-CUSTODY` are registered with owners and dependent properties.
3. Apalache model-checks the lease state machine clean in CI for its named invariants.
4. At least 3 negative-falsifiability entries produce the expected violation, each naming the runtime regression test pinning the same defect.

### v1.82 Provenance Memory And Correlation

**Goal:** Deepen the existing four-graph knowledge substrate into real OS-level provenance, reconstruct kill chains across hunts, migrate correlation off pairwise heuristics onto graph traversal, and cut false positives with dependency-aware scoring, without either lane ever gating the critical path.
**Executable phases:** 296-299

- [ ] **Phase 296: Provenance Graph Substrate** - Add real causal nodes and edges, bounded-hop path queries with a hub-degree cap, and proven retention bounds. (GRAPH-01, GRAPH-04)
- [ ] **Phase 297: Kill-Chain Reconstruction** - Reconstruct multi-stage chains mapped to declared kill-chain stages, with narration. (CHAIN-01, CHAIN-03)
- [ ] **Phase 298: Cross-Hunt Correlation** - Migrate correlation onto graph traversal and make incidents restart-durable. (XHUNT-01, XHUNT-03)
- [ ] **Phase 299: Dependency-Aware Triage** - Path-rarity scoring hitting a measured false-positive reduction target. (TRIAGE-01, TRIAGE-03)

### Phase 296: Provenance Graph Substrate

**Goal:** The four-graph model already exists but `CausalRelation` has only two variants, so the causal graph cannot express file writes, execution, DNS, or credential access. Deepen it, and bound its growth before anything traverses it.
**Requirements:** GRAPH-01, GRAPH-02, GRAPH-03, GRAPH-04, GRAPH-05, GRAPH-06
**Depends on:** v1.81 milestone complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Node and causal-relation variants are added with at least 7 new unit tests, and serialization round-trips for the extended enums.
2. Bounded-hop path queries return correct paths on a 10k-node fixture within a fixed wall-clock ceiling, with a hub-degree cap preventing high-degree nodes from linking unrelated hunts.
3. A property test over 200+ randomized prune sequences proves no orphaned edges, no premature deletion, and idempotence.
4. A 100k-event soak keeps post-GC node and edge count under a fixed ceiling, and config validation rejects a zero retention window while memory is enabled.

### Phase 297: Kill-Chain Reconstruction

**Goal:** Turn ephemeral sequence detections into durable graph evidence and reconstruct chains that span hunts, producing operator-auditable narratives.
**Requirements:** CHAIN-01, CHAIN-02, CHAIN-03, CHAIN-04
**Depends on:** Phase 296
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. All sequence-detector matches are written as semantic kill-chain-stage edges in a new integration test.
2. At least two existing multi-stage fixtures reconstruct with stage order exactly matching each fixture's declared chain.
3. Narration produces a non-empty stage-by-stage string for every reconstructed chain.
4. Two investigations from different hunts sharing a causal path reconstruct into one chain, not two disjoint incidents.

### Phase 298: Cross-Hunt Correlation

**Goal:** Retire pairwise heuristics in favour of graph-native traversal, make incidents durable across restarts, and prove the optional lanes never gate detection or response.
**Requirements:** XHUNT-01, XHUNT-02, XHUNT-03, XHUNT-04
**Depends on:** Phase 297
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Candidate selection uses graph traversal rather than recent-investigation scanning, and all pre-existing correlation tests still pass.
2. Evidence links carry a graph path for every newly created link, and pre-existing JSON still deserializes.
3. Disabling correlation and memory together yields policy decisions identical to the enabled case.
4. Incidents assembled before a simulated restart reload with identical dimensions and evidence.

### Phase 299: Dependency-Aware Triage

**Goal:** Implement NODOZE's actual contribution, dependency-aware suppression of common causal paths, and prove it cuts false positives against the project's own benign corpus.
**Requirements:** TRIAGE-01, TRIAGE-02, TRIAGE-03, TRIAGE-04, TRIAGE-05
**Depends on:** Phase 298
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Path-rarity scoring has at least 5 unit-tested scenarios where common chains score low and rare chains score high.
2. Measured false-positive rate across the three benign scenarios drops at least 50% relative to the post-phase-298 baseline, with before and after numbers in the assertion.
3. No benign scenario crosses the incident-escalation threshold after scoring.
4. The false-positive measurement report carries a dependency-score summary, and mean true-positive score exceeds mean false-positive score.
### v1.83 Distributed Governance

**Goal:** Repair the shipped BFT sizing defect, then stop anchoring destructive authority to a fixed, publicly predictable set of long-lived keys: VRF-selected epoch committees, real networked rounds with per-instance keys, and quorum-authorized revocation, with every documented fail-closed guarantee re-verified against the new model.
**Executable phases:** 301-303

- [ ] **Phase 301: VRF Committee Selection** - Replace the publicly precomputable proposer schedule with RFC 9381 VRF epoch rotation. (VRF-01, VRF-02)
- [ ] **Phase 302: Governance Key Rotation And Revocation** - Add quorum-authorized ejection that does not need the compromised key's cooperation. (REVOKE-01, REVOKE-04)
- [ ] **Phase 303: Fail-Closed Contract Preservation** - Re-verify every partition and recovery guarantee against the new committee model. (DISTGOV-01, DISTGOV-02)

### Phase 301: VRF Committee Selection

**Goal:** `proposer_for` derives the leader from public data alone, so anyone can precompute the entire future schedule. Make membership unpredictable and untargetable in advance.
**Requirements:** VRF-01, VRF-02, VRF-03, VRF-04, VRF-05
**Depends on:** v1.82 milestone complete and v1.78.1 complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. RFC 9381 ECVRF prove and verify are implemented over the existing Ed25519 keys, with tests rejecting forged proofs and wrong-seed proofs.
2. Committees are VRF-selected from the eligible pool and sized to exactly `3f+1`, replacing permanent seating of every registered governor.
3. A test proves next-epoch membership cannot be derived from public data alone without candidate private keys.
4. Single-governor bootstrap degenerates to a no-op selection and existing single-instance governance tests pass unmodified.

### Phase 302: Governance Key Rotation And Revocation

**Goal:** `rotate_identity` requires the retiring key to co-sign its own handoff, so there is no way to eject a key that will not cooperate. Add quorum-authorized revocation.
**Requirements:** REVOKE-01, REVOKE-02, REVOKE-03, REVOKE-04, REVOKE-05
**Depends on:** Phase 301
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Revocation succeeds using only a quorum-signed receipt, proven by a test where the revoked key is never consulted.
2. Admission returns false immediately after revocation while historical signature verification against the retired key still succeeds.
3. `swarmctl identity revoke` fails closed with no partial registry mutation when quorum cannot be obtained.
4. An in-protocol exclusion updates the registry mid-epoch, and the excluded member cannot be VRF-selected into the next epoch.

### Phase 303: Fail-Closed Contract Preservation

**Goal:** Prove the new committee model weakened nothing operators were already promised, and extend leases and reconciliation to remain verifiable across rotations.
**Requirements:** DISTGOV-01, DISTGOV-02, DISTGOV-03, DISTGOV-04
**Depends on:** Phase 302
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Every documented partition and recovery rule has a passing integration test against the VRF-rotated networked committee, with single-operator boundary language preserved.
2. A lease issued by one epoch remains redeemable after rotation replaces its signers, without weakening blast-radius or TTL checks.
3. Quorum loss mid-transition falls back to the last-confirmed committee rather than seating a half-formed one, handed to the v1.81 model as an extension rather than modeled twice.
4. Governance status and health endpoints report epoch, committee size, time to rotation, and eligible-pool exhaustion below `3f+1`.

### v1.84 Herd Immunity

**Goal:** Give containment a real undo before deepening it, then compose taint-aware information-flow control, no-single-publisher cross-instance immunity, and adaptive deception into a fleet response where one instance's confirmed threat makes peers resistant without any instance trusting another blindly.
**Executable phases:** 305-307

- [ ] **Phase 305: Information-Flow Control** - Taint propagation sharpening detection and gating containment, never authorizing it alone. (IFC-02, IFC-04)
- [ ] **Phase 306: Cross-Instance Immunity Sharing** - Immunity records requiring independent local corroboration and canary-staged adoption. (HERD-01, HERD-02)
- [ ] **Phase 307: Adaptive Deception And Integration Proof** - Higher-fidelity taint-informed decoys and the full-loop executable proof. (DECOY-01, DECOY-04)

### Phase 305: Information-Flow Control

**Goal:** Trace how attacker-influenced data propagates and use it to sharpen detection and raise containment scrutiny, while guaranteeing taint alone never authorizes a destructive action.
**Requirements:** IFC-01, IFC-02, IFC-03, IFC-04
**Depends on:** v1.83 milestone complete and v1.78.1 complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Taint labels and data-flow edges extend the existing knowledge graph and reuse its GC rather than adding a second retention path.
2. Detector confidence is boosted by a decayed taint score capped at 1.0, with the propagation chain recorded on the finding.
3. The policy gate denies a taint-only containment proposal and approves a taint-plus-corroboration proposal, proven by integration test.
4. The taint model, its half-life, and the never-authorizes-alone invariant are documented in the agent and configuration docs.

### Phase 306: Cross-Instance Immunity Sharing

**Goal:** Let one instance's confirmed threat make the fleet resistant in real time without any instance blindly trusting a peer, which is the direct answer to the single-publisher failure mode.
**Requirements:** HERD-01, HERD-02, HERD-03, HERD-04
**Depends on:** Phase 305
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Immunity records replicate across three in-process instances over one shared substrate.
2. No record is adopted without independent local corroboration, including a fabricated record injected directly at a subscriber.
3. A forced false-positive spike during canary soak reverts that instance only, leaving publisher and peers unaffected.
4. The module documentation names the no-single-publisher invariant, and the configuration surface documents soak window, corroboration requirement, and canary scope.

### Phase 307: Adaptive Deception And Integration Proof

**Goal:** Deepen decoy fidelity and taint-informed placement, then prove the whole loop end to end as the single executable artifact backing this milestone's claims.
**Requirements:** DECOY-01, DECOY-02, DECOY-03, DECOY-04
**Depends on:** Phase 306
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Interactive and stateful decoys return distinct non-empty payloads across repeated interactions.
2. Placement biases toward taint-adjacent zones versus a no-taint control run, never leaving operator-approved zones.
3. Higher-fidelity engagement seeds measurably stronger taint than static decoys.
4. The full-loop test runs in CI: decoy interaction, taint propagation, receipt-backed quarantine, automatic rollback, immunity publication, corroborated peer adoption.

### v1.85 The Detection Commons

**Goal:** Publish a normative spec for the deposit format, receipt chain, and wire surface with JSON Schema; package the existing scenario corpus into an externally verifiable conformance suite; ship a dependency-light detector-authoring SDK; and generate the coverage claim from the catalog so it cannot drift from the detectors.
**Executable phases:** 308-311

- [ ] **Phase 308: Normative Spec** - Role-indexed spec with schemas validated against real runtime output. (SPEC-01, SPEC-03)
- [ ] **Phase 309: External Conformance Suite** - A checksummed package and verifier an outside implementer can run without the monorepo. (CONFORM-01, CONFORM-02)
- [ ] **Phase 310: Detector-Authoring SDK** - The smallest unit needed to extend rather than run, plus a hello-detector example. (SDK-01, SDK-02)
- [ ] **Phase 311: Generated Coverage And Adopter IA** - Coverage generated from the catalog, role-indexed docs, and an epistemic fence. (COVDOC-01, COVDOC-03)

### Phase 308: Normative Spec

**Goal:** Give Federation and any external implementer one normative artifact instead of reverse-engineering the crates. This ships before Federation because Federation consumes it.
**Requirements:** SPEC-01, SPEC-02, SPEC-03
**Depends on:** v1.84 milestone complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `spec/README.md` gives three named reading orders each citing the four normative docs by path.
2. The deposit spec documents every field including the schema-version compatibility window; the receipt spec covers envelope through Merkle proof; the wire spec covers only the stable external subset.
3. At least four JSON Schema files exist and are independently valid under a draft 2020-12 validator.
4. A CI test serializes real runtime-produced values, validates them against the checked-in schemas, and fails on an intentionally malformed fixture.

### Phase 309: External Conformance Suite

**Goal:** The raw material already exists as 19 scenarios, 3 suites, and replay and evidence tooling. The gap is packaging it for someone without repo access.
**Requirements:** CONFORM-01, CONFORM-02, CONFORM-03
**Depends on:** Phase 308
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. The package command produces a versioned archive containing all 19 scenarios, all 3 suites, the default ruleset, and a checksum manifest.
2. The verify command exits non-zero on any verdict mismatch against the pinned expectations inside the package.
3. Evidence mode additionally verifies every exported receipt and fails closed on any that does not verify.
4. A CI job builds the package, unpacks it into a scratch directory, verifies against that fresh build, and fails if any scenario is silently absent from the manifest.

### Phase 310: Detector-Authoring SDK

**Goal:** Let a third party write a detector without inheriting the runtime's dependency graph.
**Requirements:** SDK-01, SDK-02, SDK-03
**Depends on:** Phase 309
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `crates/swarm-detector-sdk` depends only on `swarm-core`; a CI check proves no runtime, transport, or telemetry crate appears in its dependency tree.
2. `examples/hello-detector/` implements a detector purely against the SDK with a ruleset entry and a README following the read, write, deny, allow, receipt, smoke shape.
3. The example's smoke script runs `swarmctl first-run`, prints an emitted deposit and a verified receipt id, and exits 0.
4. `tools/run-hello-smokes.sh` is the CI entry point for the hello family, and the SDK doc states version-to-schema compatibility.

### Phase 311: Generated Coverage And Adopter IA

**Goal:** Make the coverage claim generated rather than asserted, and give adopters one role-indexed door, with narrative explicitly fenced off from load-bearing claims.
**Requirements:** COVDOC-01, COVDOC-02, COVDOC-03
**Depends on:** Phase 310
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. The generator reproduces the coverage doc byte-for-byte identically on repeated runs, stamped as generated and naming its source YAML.
2. Running with `--check` against a stale doc exits non-zero, and the mode is wired into the documented contributor gate.
3. The generated doc enumerates every catalogued detector with its uncovered techniques and rationale reproduced verbatim.
4. `docs/README.md` provides four role-indexed reading orders, and both `README.md` and `spec/README.md` point at `docs/REFERENCE-STATUS.md` as the qualified-claims gate.

### v1.86 Federation

**Goal:** Let operators exchange verifiable threat evidence across operator boundaries with no shared server and no auto-authorization of local action, so trust spreads without creating a single point of centralized failure.
**Executable phases:** 312-315

- [ ] **Phase 312: Cross-Operator Evidence Exchange** - Offline-verifiable evidence packages built on the receipt chain and the v1.85 spec. (FEDX-01, FEDX-02)
- [ ] **Phase 313: Local Activation Boundary** - Guarantee a peer signal can never by itself authorize local destructive response. (LOCACT-02, LOCACT-03)
- [ ] **Phase 314: Reputation And Anti-Equivocation** - Locally computed peer standing and detectable equivocation with no central registry. (FEDREP-01, EQUIV-01)
- [ ] **Phase 315: Privacy-Preserving Sharing** - Share detection evidence without leaking topology, hostnames, or identities. (FEDPRIV-01, FEDPRIV-04)

### Phase 312: Cross-Operator Evidence Exchange

**Goal:** Establish the exchange envelope and offline verification path, conforming to the spec published in v1.85 rather than inventing a competing format.
**Requirements:** FEDX-01, FEDX-02, FEDX-03, FEDX-04
**Depends on:** v1.85 milestone complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `crates/swarm-federation` builds and is registered in the workspace.
2. Verification completes with zero outbound network calls, confirmed by a test asserting the crate carries no network client dependency.
3. Export and import round-trip a real signed envelope and checkpoint through one integration test, using the v1.85 normative format.
4. Federation config defaults to disabled and a test asserts no federation surface starts when disabled.

### Phase 313: Local Activation Boundary

**Goal:** Ship the anti-single-publisher property as code and as a named CI-enforced regression test, not a design claim.
**Requirements:** LOCACT-01, LOCACT-02, LOCACT-03, LOCACT-04
**Depends on:** Phase 312
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Federated-peer provenance exists on deposits with a distinct lower weight, and all existing pheromone tests pass unmodified.
2. A maximal-severity zero-corroboration import produces no dispatch and no signed governance receipt.
3. A named policy test guards the property against regression.
4. The architecture and consensus docs state the precise new boundary, and the governance-mode table gains no new row.

### Phase 314: Reputation And Anti-Equivocation

**Goal:** Let operators weight peers without a central registry, and make it possible to prove offline that a peer told two operators different things.
**Requirements:** FEDREP-01, FEDREP-02, EQUIV-01, EQUIV-02
**Depends on:** Phase 313
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Peer reputation is influenced only by that peer's own history, proven by a test asserting no cross-peer read.
2. Admission requires the local operator's signature, and an unadmitted peer's evidence is rejected at import.
3. A peer driven below the configured minimum is demoted to advisory-only weight zero with retained history and a signed audit event.
4. Two conflicting checkpoint statements produce equivocation evidence independently re-verifiable by a third party holding only the artifact.

### Phase 315: Privacy-Preserving Sharing

**Goal:** Make cross-operator sharing safe to adopt by construction, proven with a byte-level test rather than a policy statement.
**Requirements:** FEDPRIV-01, FEDPRIV-02, FEDPRIV-03, FEDPRIV-04
**Depends on:** Phase 314
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. A fixture containing literal hostnames, usernames, and internal CIDRs produces zero byte-string matches in the exported package, enforced in CI.
2. Export of a payload carrying an out-of-allowlist field fails closed with nothing written.
3. Dry-run output matches the actual written package byte for byte.
4. Pseudonyms are stable within one export relationship, and a documented rotation path bounds long-term linkability.

### v1.87 Fleet Scale

**Goal:** Scale from a single-node runtime to a multi-instance fleet within one operator, where horizontal capacity, cross-instance blast-radius authorization, tenant isolation, and release provenance all stay fail-closed and are backed by rerun measurements rather than assumed numbers.
**Executable phases:** 316-319

- [ ] **Phase 316: Sharded Substrate And Horizontal Scale** - Partition telemetry across shards owned by disjoint instances with measured capacity at N=1, 3, 10. (SHARD-01, SHARD-03)
- [ ] **Phase 317: Fleet Blast Radius And Tenant Isolation** - A fleet-level cap enforced across instances, and per-tenant policy, identity, and receipt chains. (FCAP-02, TENANT-02)
- [ ] **Phase 318: Fleet Operational Maturity** - Fleet SLOs, drills, and a capacity model sourced from reruns, not assumption. (FLEETOPS-01, FLEETOPS-03)
- [ ] **Phase 319: Signed Release Supply Chain** - Signed, attested releases that a live-response fleet must verify before deploying. (RELSIGN-02, RELSIGN-04)

### Phase 316: Sharded Substrate And Horizontal Scale

**Goal:** Move from one runtime process to a horizontally scaled fleet over shared JetStream, with a real partitioning scheme and measured capacity rather than an assumed multiple.
**Requirements:** SHARD-01, SHARD-02, SHARD-03
**Depends on:** v1.86 milestone complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. A deterministic shard function replaces the single-bucket design, with stable assignment across restarts.
2. The chart supports N pods each claiming a disjoint shard set via a startup lease, with the shard count documented in production values.
3. An integration test with at least 3 concurrent instances proves disjoint ownership and zero duplicate or lost deposits.
4. A fleet benchmark reruns the fixed and ramp-to-shed profiles at N=1, 3, and 10, recording measured throughput and first shed point per N.

### Phase 317: Fleet Blast Radius And Tenant Isolation

**Goal:** Apply the single-publisher lesson to our own autonomy: containment spanning many hosts needs a fleet-level cap, and one operator serving several tenants must not leak across them.
**Requirements:** FCAP-01, FCAP-02, TENANT-01, TENANT-02
**Depends on:** Phase 316
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. The fleet cap exists, is distinct from the per-instance cap, and fails config validation at zero.
2. A durable ledger denies further destructive action once the fleet cap is reached, proven with 3 concurrent instances whose combined volume no single instance would have crossed.
3. Ledger unavailability fails closed for destructive response while health endpoints remain reachable.
4. A replay or query scoped to one tenant never returns another tenant's records on the shared substrate.

### Phase 318: Fleet Operational Maturity

**Goal:** Give operators the same SLO, alerting, upgrade, and capacity discipline for a fleet that already exists for one instance, sourced from measurement.
**Requirements:** FLEETOPS-01, FLEETOPS-02, FLEETOPS-03, FLEETOPS-04
**Depends on:** Phase 317
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. Every fleet alert threshold is traceable to a specific measured row in the fleet benchmark.
2. The DR runbook carries a fleet upgrade and rollback drill preserving shard assignment and ledger state, verified by a recorded runthrough.
3. The capacity-model doc requires a benchmark rerun on the target host before any capacity number is treated as valid.
4. Metrics carry instance and shard labels, verified by a scrape test.

### Phase 319: Signed Release Supply Chain

**Goal:** A binary that can execute destructive containment across a fleet needs enforced release provenance, and verification must block deployment mechanically rather than by runbook instruction.
**Requirements:** RELSIGN-01, RELSIGN-02, RELSIGN-03, RELSIGN-04
**Depends on:** Phase 318
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. The release workflow publishes multi-arch images on tag push, and its coverage is reconciled against the `RELEASE-01` requirement currently marked Complete.
2. Published images are signed, and a required check verifies the signature before the release is marked complete.
3. SBOM and provenance attach to the release artifact and are required fields in the recovery evidence packet for live-response deployments.
4. Signature verification blocks deployment mechanically for live-response fleets, extending the existing startup attestation to the container supply chain.

## Progress

**v1.38 execution order:** 120 -> 121 || 122 -> 123

**v1.39 execution order:** 124 -> 125 -> 126 -> 127

**v1.40 execution order:** 128 -> 129 -> 130 -> 131

**v1.41 execution order:** 132 -> 133 || 134 -> 135 -> 136

**v1.42 execution order:** 137 -> 138 -> 139 -> 140

**v1.43 execution order:** 141 -> 142 || 143 -> 144

**v1.44 execution order:** 145 -> 146 -> 147 -> 148

**v1.45 execution order:** 149 -> 150 -> 151 -> 152

**v1.46 execution order:** 153 -> 154 -> 155 -> 156

**v1.47 execution order:** 157 -> 158 -> 159 -> 160

**v1.48 execution order:** 161 -> 162 -> 163

**v1.49 execution order:** 164 -> 165 -> 166 -> 167

**v1.50 execution order:** 168 -> 169 -> 170 -> 171

**v1.51 execution order:** 172 -> 173 -> 174 -> 175

**v1.52 execution order:** 176 -> 177 -> 178 -> 179

**v1.53 execution order:** 180 -> 181 -> 182 -> 183

**v1.54 execution order:** 184 -> 185 -> 186 -> 187

**v1.55 execution order:** 188 -> 189 -> 190 -> 191

**v1.56 execution order:** 192 -> 193 -> 194 -> 195

**v1.57 execution order:** 196 -> 197 -> 198 -> 199

**v1.58 execution order:** 200 -> 201 -> 202 -> 203

**v1.59 execution order:** 204 -> 205 -> 206 -> 207

**v1.60 execution order:** 208 -> 209 -> 210 -> 211

**v1.61 execution order:** 212 -> 213 -> 214 -> 215

**v1.62 execution order:** 216 -> 217 -> 218 -> 219

**v1.63 execution order:** 220 -> 221 -> 222 -> 223

**v1.64 execution order:** 224 -> 225 -> 226 -> 227

**v1.65 execution order:** 228 -> 229 -> 230 -> 231

**v1.66 execution order:** 232 -> 233 -> 234 -> 235

**v1.67 execution order:** 236 -> 237 -> 238 -> 239

**v1.68 execution order:** 240 -> 241 -> 242 -> 243

**v1.69 execution order:** 244 -> 245 -> 246 -> 247

**v1.70 execution order:** 248 -> 249 -> 250 -> 251

**v1.71 execution order:** 252 -> 253 -> 254 -> 255

**v1.72 execution order:** 256 -> 257 -> 258 -> 259

**v1.73 execution order:** 260 -> 261 -> 262 -> 263

**v1.75 execution order:** 268 -> 269 -> 270 -> 271

**v1.76 execution order:** 272 -> 273 -> 274 -> 275

**v1.77 execution order:** 276 -> 277 -> 278 -> 279
**v1.78 execution order:** 280 -> 281 -> 282 -> 283
**v1.78.1 execution order:** 320 -> 321 -> 322
**v1.79 execution order:** 284 -> 285 -> 286 -> 287 -> 288 -> 289
**v1.80 historical execution order:** 288 -> 289 -> 290 -> 291 (superseded; not an acceptance queue)
**v1.81 execution order:** 292 -> 293 -> 294
**v1.82 execution order:** 296 -> 297 -> 298 -> 299
**v1.83 execution order:** 300 -> 301 -> 302 -> 303
**v1.84 execution order:** 304 -> 305 -> 306 -> 307
**v1.85 execution order:** 308 -> 309 -> 310 -> 311
**v1.86 execution order:** 312 -> 313 -> 314 -> 315
**v1.87 execution order:** 316 -> 317 -> 318 -> 319

| Phase | Milestone | Plans | Status | Completed |
|-------|-----------|-------|--------|-----------|
| 112. Telemetry Persistence Payloads And Detector Contracts | v1.37 | 2/2 | Complete | 2026-04-07 |
| 113. Persistence Detector And Profile Support | v1.37 | 2/2 | Complete | 2026-04-07 |
| 114. Supply Chain Detector And Profile Support | v1.37 | 2/2 | Complete | 2026-04-07 |
| 115. Persistence And Supply Chain Integration Proof | v1.37 | 2/2 | Complete | 2026-04-07 |
| 116. Agent Safety Hardening | v1.37.1 | 2/2 | Complete | 2026-04-07 |
| 117. Substrate Durability And Bridge Resilience | v1.37.1 | 2/2 | Complete | 2026-04-08 |
| 118. Operational Hardening | v1.37.1 | 3/3 | Complete | 2026-04-07 |
| 119. Pheromone Test Suite | v1.37.1 | 1/1 | Complete | 2026-04-08 |
| 120. Composite Detector And Config Migration | v1.38 | 2/2 | Complete | 2026-04-08 |
| 121. Network Connect Detector | v1.38 | 2/2 | Complete | 2026-04-08 |
| 122. Cross-Strategy Pheromone Signals And Rollout Scoping | v1.38 | 2/2 | Complete | 2026-04-08 |
| 123. Multi-Strategy Integration Proof | v1.38 | 1/1 | Complete | 2026-04-08 |
| 124. PounceAgent Core And De-escalation | v1.39 | 5/5 | Complete | 2026-04-08 |
| 125. Configurable Policy Rules And Audit Trail | v1.39 | 4/4 | Complete | 2026-04-08 |
| 126. TomAgent Governance | v1.39 | 4/4 | Complete | 2026-04-08 |
| 127. Integration Hardening | v1.39 | 2/2 | Complete | 2026-04-08 |
| 128. Demo Replay Injector And Event Stream Backbone | v1.40 | 1/1 | Complete | 2026-04-08 |
| 129. Live Demo Dashboard And Runtime Timeline | v1.40 | 1/1 | Complete | 2026-04-08 |
| 130. Approval-In-The-Loop Demo And Signed Proof Export | v1.40 | 1/1 | Complete | 2026-04-08 |
| 131. Providence Webhook Delivery And Drilldown Context | v1.40 | 1/1 | Complete | 2026-04-08 |
| 132. Platform API Envelope And Auth Surface | v1.41 | 1/1 | Complete | 2026-04-08 |
| 133. Asset Posture And Findings Stream Surface | v1.41 | 1/1 | Complete | 2026-04-08 |
| 134. Helm Deployment And Config CLI Experience | v1.41 | 1/1 | Complete | 2026-04-08 |
| 135. Serve-Surface Security And Panic Elimination | v1.41 | 1/1 | Complete | 2026-04-08 |
| 136. Crate Extraction And Trace Instrumentation | v1.41 | 1/1 | Completed | 2026-04-09 |
| 137. Kitten Mutation And Drift Orchestration | v1.42 | 1/1 | Complete | 2026-04-09 |
| 138. Fitness Evaluation And Population Persistence | v1.42 | 1/1 | Complete | 2026-04-09 |
| 139. Formal Safety Gate And Canary Admission | v1.42 | 1/1 | Complete | 2026-04-09 |
| 140. Evolution Observability And Operator Status | v1.42 | 1/1 | Complete | 2026-04-09 |
| 141. Sphinx Knowledge Graph Foundations | v1.43 | 1/1 | Complete | 2026-04-09 |
| 142. Stigmergic Memory Queries And Fitness Retrieval | v1.43 | 1/1 | Complete | 2026-04-09 |
| 143. Knowledge Retention And Adversarial Corpus Adapter | v1.43 | 1/1 | Complete | 2026-04-09 |
| 144. Red-Blue Pressure And Episode Logging | v1.43 | 1/1 | Complete | 2026-04-09 |
| 145. Agent Key Persistence And Identity Derivation | v1.44 | 1/1 | Complete | 2026-04-09 |
| 146. Identity Registry And Key Rotation | v1.44 | 1/1 | Complete | 2026-04-09 |
| 147. Sentinel Infrastructure Telemetry Bridge | v1.44 | 1/1 | Complete | 2026-04-09 |
| 148. Infrastructure Anomaly Detection And Cross-Signal Correlation | v1.44 | 1/1 | Complete | 2026-04-09 |
| 149. Providence Contract And Service Auth | v1.45 | 1/1 | Complete | 2026-04-09 |
| 150. Incident Lifecycle Adapter | v1.45 | 1/1 | Complete | 2026-04-09 |
| 151. Analyst Feedback Loop | v1.45 | 1/1 | Complete | 2026-04-09 |
| 152. Embeddable Dashboard Widget And Context Tokens | v1.45 | 1/1 | Complete | 2026-04-09 |
| 153. Consensus Protocol Core | v1.46 | 1/1 | Complete | 2026-04-09 |
| 154. Byzantine Safety And Multi-Instance Governance | v1.46 | 1/1 | Complete | 2026-04-09 |
| 155. Partition Authority And Contingency Leases | v1.46 | 1/1 | Complete | 2026-04-09 |
| 156. Chaos And Resilience Testing | v1.46 | 1/1 | Complete | 2026-04-09 |
| 157. Calico Agent Core And Deception Playbook | v1.47 | 1/1 | Complete | 2026-04-09 |
| 158. Calico Lifecycle And Evolution Integration | v1.47 | 1/1 | Complete | 2026-04-09 |
| 159. Fileless Execution Detection | v1.47 | 1/1 | Complete | 2026-04-09 |
| 160. Behavioral Anomaly Baselines | v1.47 | 1/1 | Complete | 2026-04-09 |
| 161. Evasion Test Corpus And Coverage Metrics | v1.48 | 1/1 | Complete | 2026-04-10 |
| 162. KittenAgent Evasion Mutation Cycle | v1.48 | 1/1 | Complete | 2026-04-10 |
| 163. Z3 Formal Verification | v1.48 | 1/1 | Complete | 2026-04-10 |
| 164. Canonical Capability Matrix And Source-Of-Truth Reset | v1.49 | 1/1 | Complete | 2026-04-10 |
| 165. Governance Modes And Identity Admission Contracts | v1.49 | 1/1 | Complete | 2026-04-10 |
| 166. Degraded Governance And Partition Recovery Spec | v1.49 | 1/1 | Complete | 2026-04-10 |
| 167. Evolution, Rollout, And Operator Contract Consolidation | v1.49 | 1/1 | Complete | 2026-04-10 |
| 168. Weaver Multi-Graph Correlation Foundations | v1.50 | 1/1 | Complete | 2026-04-10 |
| 169. Investigation Scheduling And Confidence Voting | v1.50 | 1/1 | Complete | 2026-04-10 |
| 170. Identity And Peer-Group Behavioral Baselines | v1.50 | 1/1 | Complete | 2026-04-10 |
| 171. Async Enrichment Surface And Integration Proof | v1.50 | 1/1 | Complete | 2026-04-10 |
| 172. Assurance Policy And Gate Inputs | v1.51 | 1/1 | Complete | 2026-04-11 |
| 173. Counterexample Harvest And Replay Regeneration | v1.51 | 1/1 | Complete | 2026-04-11 |
| 174. Assurance-Gated Queue, Canary, And Promotion | v1.51 | 1/1 | Complete | 2026-04-11 |
| 175. Waivers, Review Surface, And Assurance Lineage | v1.51 | 1/1 | Complete | 2026-04-11 |
| 176. Providence Callback And Incident Reconciliation | v1.52 | 1/1 | Complete | 2026-04-11 |
| 177. Analyst Disposition Sync And Memory Feedback | v1.52 | 1/1 | Complete | 2026-04-11 |
| 178. Response Rehearsal Harness And Blast-Radius Modeling | v1.52 | 1/1 | Complete | 2026-04-11 |
| 179. Rehearsal Review Surface And Providence Handoff | v1.52 | 1/1 | Complete | 2026-04-11 |
| 180. Secure Production Packaging Profile | v1.53 | 1/1 | Complete | 2026-04-11 |
| 181. Recovery Drills And Durability Validation | v1.53 | 1/1 | Complete | 2026-04-11 |
| 182. SLO, Capacity Envelope, And Alert Baselines | v1.53 | 1/1 | Complete | 2026-04-11 |
| 183. Operator Access Model And Multi-Operator Audit | v1.53 | 1/1 | Complete | 2026-04-11 |
| 184. Runtime Unwrap Audit And Error Types | v1.54 | 1/1 | Complete | 2026-04-11 |
| 185. Ingest And Service Panic-Free Conversion | v1.54 | 1/1 | Complete | 2026-04-11 |
| 186. Agent Tick And Evolution Error Boundaries | v1.54 | 1/1 | Complete | 2026-04-12 |
| 187. Error Contract CI Enforcement | v1.54 | 1/1 | Complete | 2026-04-12 |
| 188. Containerized NATS Test Harness | v1.55 | 1/1 | Complete | 2026-04-12 |
| 189. JetStream Substrate Test Migration | v1.55 | 1/1 | Complete | 2026-04-12 |
| 190. Hot Path Criterion Benchmarks | v1.55 | 1/1 | Complete | 2026-04-12 |
| 191. Sustained Throughput Load Test | v1.55 | 1/1 | Complete | 2026-04-12 |
| 192. Startup Binary And Ruleset Attestation | v1.56 | 1/1 | Complete | 2026-04-12 |
| 193. Configuration Signature Verification | v1.56 | 1/1 | Complete | 2026-04-12 |
| 194. Runtime Anti-Tamper Monitoring | v1.56 | 1/1 | Complete | 2026-04-12 |
| 195. Supply Chain Hardening And SBOM | v1.56 | 1/1 | Complete | 2026-04-12 |
| 196. Algorithmic Parameter Variant Generation | v1.57 | 1/1 | Complete | 2026-04-12 |
| 197. Autonomous Fitness Evaluation Loop | v1.57 | 1/1 | Complete | 2026-04-12 |
| 198. Measured Evolution Benchmark | v1.57 | 1/1 | Complete | 2026-04-12 |
| 199. Evolution Results And Reporting | v1.57 | 1/1 | Complete | 2026-04-12 |
| 200. Temporal Event Window Infrastructure | v1.58 | 1/1 | Complete | 2026-04-12 |
| 201. Kill Chain Sequence Detector | v1.58 | 1/1 | Complete | 2026-04-12 |
| 202. ATT&CK Chain Scenario Suite | v1.58 | 1/1 | Complete | 2026-04-12 |
| 203. Sequence Detection Integration | v1.58 | 1/1 | Complete | 2026-04-12 |
| 204. Readiness Diagnostic And Guided Setup | v1.59 | 1/1 | Complete | 2026-04-12 |
| 205. Time-To-First-Detection Wizard | v1.59 | 1/1 | Complete | 2026-04-12 |
| 206. Per-Detector False Positive Tracking | v1.59 | 1/1 | Complete | 2026-04-12 |
| 207. Alert Tuning Recommendations | v1.59 | 1/1 | Complete | 2026-04-12 |
| 208. Per-Agent Panic Boundaries | v1.60 | 1/1 | Complete | 2026-04-12 |
| 209. Agent Health-Driven Restart | v1.60 | 1/1 | Complete | 2026-04-12 |
| 210. Degradation Mode State Machine | v1.60 | 1/1 | Complete | 2026-04-12 |
| 211. Degradation Transition Tests | v1.60 | 1/1 | Complete | 2026-04-12 |
| 212. Response Action Adapter Expansion | v1.61 | 1/1 | Complete | 2026-04-12 |
| 213. Blast-Radius Models And Rollback Procedures | v1.61 | 1/1 | Complete | 2026-04-12 |
| 214. Composable Playbook YAML Schema | v1.61 | 1/1 | Complete | 2026-04-12 |
| 215. Playbook Dry-Run And Preview | v1.61 | 1/1 | Complete | 2026-04-12 |
| 216. Online Distribution Learning | v1.62 | 1/1 | Complete | 2026-04-12 |
| 217. Statistical Deviation Scoring | v1.62 | 1/1 | Complete | 2026-04-12 |
| 218. Multi-Telemetry Behavioral Extension | v1.62 | 1/1 | Complete | 2026-04-12 |
| 219. Anomaly Quality Benchmark | v1.62 | 1/1 | Complete | 2026-04-12 |
| 220. Evolution Module Extraction | v1.63 | 1/1 | Complete | 2026-04-12 |
| 221. Mutation Module Extraction | v1.63 | 1/1 | Complete | 2026-04-12 |
| 222. Pheromone Wire Format Versioning | v1.63 | 1/1 | Complete | 2026-04-12 |
| 223. API Response Schema Migration | v1.63 | 1/1 | Complete | 2026-04-12 |
| 224. Audit Path Hack Dependencies And Migration Plan | v1.64 | 1/1 | Complete | 2026-04-13 |
| 225. Extract Runtime-Evolution Bridge Types | v1.64 | 1/1 | Complete | 2026-04-13 |
| 226. Remove Remaining Path Directives And Fix Imports | v1.64 | 1/1 | Complete | 2026-04-13 |
| 227. Path Hack Removal Integration Proof | v1.64 | 1/1 | Complete | 2026-04-13 |
| 228. Config Module Decomposition | v1.65 | 1/1 | Complete | 2026-04-13 |
| 229. Config Compilation Boundary Verification | v1.65 | 1/1 | Complete | 2026-04-13 |
| 230. Service Module Decomposition | v1.65 | 1/1 | Complete | 2026-04-13 |
| 231. RuntimeService Arc Reduction | v1.65 | 1/1 | Complete | 2026-04-13 |
| 232. Behavioral Baseline Signing And Verification | v1.66 | 1/1 | Complete | 2026-04-13 |
| 233. Sphinx Graph State Signing | v1.66 | 1/1 | Complete | 2026-04-13 |
| 234. Evolution Population Signing | v1.66 | 1/1 | Complete | 2026-04-13 |
| 235. Monotonic Sequence And Replay Prevention | v1.66 | 1/1 | Complete | 2026-04-13 |
| 236. Secret Zeroization With zeroize Crate | v1.67 | 1/1 | Complete | 2026-04-13 |
| 237. Release Build Hardening | v1.67 | 1/1 | Complete | 2026-04-13 |
| 238. Rotatable Token Lifecycle | v1.67 | 1/1 | Complete | 2026-04-13 |
| 239. HTTP Rate Limiting | v1.67 | 1/1 | Complete | 2026-04-13 |
| 240. Behavioral Anomaly Genome And Mutation Operators | v1.68 | 1/1 | Complete | 2026-04-13 |
| 241. Fileless And DNS Detector Genomes | v1.68 | 1/1 | Complete | 2026-04-13 |
| 242. Multi-Detector Evolution Benchmark | v1.68 | 1/1 | Complete | 2026-04-13 |
| 243. Cross-Detector Fitness Improvement Proof | v1.68 | 1/1 | Complete | 2026-04-13 |
| 244. Caret And Environment Variable Normalization | v1.69 | 1/1 | Complete | 2026-04-13 |
| 245. Unicode Homoglyph And Encoding Normalization | v1.69 | 1/1 | Complete | 2026-04-13 |
| 246. Evasion Catch-Rate Improvement Measurement | v1.69 | 1/1 | Complete | 2026-04-13 |
| 247. Normalization False-Positive Regression Test | v1.69 | 1/1 | Complete | 2026-04-13 |
| 248. Windows Event Log Bridge | v1.70 | 1/1 | Complete | 2026-04-13 |
| 249. Sysmon Bridge | v1.70 | 1/1 | Complete | 2026-04-13 |
| 250. Auditd Bridge | v1.70 | 1/1 | Complete | 2026-04-13 |
| 251. Bridge Health And Metrics Integration | v1.70 | 1/1 | Complete | 2026-04-13 |
| 252. CI Job Parallelization | v1.71 | 1/1 | Complete | 2026-04-13 |
| 253. JetStream Integration Tests In CI | v1.71 | 1/1 | Complete | 2026-04-13 |
| 254. Benchmark Regression Gate | v1.71 | 1/1 | Complete | 2026-04-13 |
| 255. Release Pipeline And Container Publishing | v1.71 | 1/1 | Complete | 2026-04-13 |
| 256. OpenAPI 3.1 Spec Generation | v1.72 | 1/1 | Complete | 2026-04-13 |
| 257. Generated Python Client | v1.72 | 1/1 | Complete | 2026-04-13 |
| 258. Inbound SOAR Verdict Sync | v1.72 | 1/1 | Complete | 2026-04-13 |
| 259. SOAR Audit Lineage | v1.72 | 1/1 | Complete | 2026-04-13 |
| 260. Positive-Feedback Pheromone Recruitment | v1.73 | 1/1 | Complete | 2026-04-13 |
| 261. Inhibitory Escalation Resolution Signaling | v1.73 | 1/1 | Complete | 2026-04-13 |
| 262. Recruitment Kill-Chain Benchmark | v1.73 | 1/1 | Complete | 2026-04-13 |
| 263. Baseline Poisoning Resistance And Staleness Policy | v1.73 | 1/1 | Complete | 2026-04-13 |
| 264. Test Fixes And Dead Code Removal | v1.74 | 0/TBD | Not started | - |
| 265. kitten_agent.rs Decomposition | v1.74 | 0/TBD | Not started | - |
| 266. drafting.rs And ingest/tests.rs Decomposition | v1.74 | 0/TBD | Not started | - |
| 267. Agent Crate Extraction | v1.74 | 0/TBD | Not started | - |
| 268. Curated Defaults And Operator UX | v1.75 | 1/1 | Complete | 2026-04-13 |
| 269. Deployment Documentation | v1.75 | 1/1 | Complete | 2026-04-13 |
| 270. Adversary Emulation Corpus | v1.75 | 1/1 | Complete | 2026-04-13 |
| 271. Quickstart Command And End-To-End Validation | v1.75 | 1/1 | Complete | 2026-04-13 |
| 272. STIX/TAXII Consumer And Threat Intel Enrichment | v1.76 | 1/1 | Complete | 2026-04-13 |
| 273. Cloud Telemetry Bridges | v1.76 | 1/1 | Complete | 2026-04-13 |
| 274. CloudTrail Detector | v1.76 | 1/1 | Complete | 2026-04-13 |
| 275. Kubernetes Audit Detector And Cross-Cloud Integration Proof | v1.76 | 1/1 | Complete | 2026-04-13 |
| 276. CrowdStrike RTR Adapter | v1.77 | 1/1 | Complete | 2026-04-13 |
| 277. Splunk HEC Adapter | v1.77 | 1/1 | Complete | 2026-04-13 |
| 278. E2E Deployment Proof Compose Stack | v1.77 | 1/1 | Complete | 2026-04-13 |
| 279. Integration Architecture Validation | v1.77 | 1/1 | Complete | 2026-04-13 |
| 280. Verification Gate Repair | v1.78 | 4/4 | Complete | 2026-08-11 |
| 281. core.inc Elimination | v1.78 | 2/3 | Complete | 2026-08-11 |
| 282. Crate Extraction From swarm-runtime | v1.78 | 0/6 closed | Code merged 2026-08-13 (0a09358), complete as scoped; all six SPLIT checkboxes still open, remainder re-derived 2026-08-13 (task #14, `.planning/PHASE-282-REMAINDER.md`) | 2026-08-13 |
| 283. TCB Boundary And Layering Enforcement | v1.78 | 4/4 requirements | Complete | 2026-08-13 |
| 284. Fixture Determinism And Suite Health | v1.79 | 4/4 | Complete | 2026-08-11 |
| 285. Assurance Foundation Closure | v1.79 | 6/6 requirements; closure gate open | Reopened for governance/detector integration; external GitHub App enforcement deferred | - |
| 286. Collective Hypothesis Graph | v1.79 | Plan 04 checkpointed | Blocked behind Phase 285 | - |
| 287. Adversarial Co-evolution Arena | v1.79 | Plans reviewed | Parked; execution blocked by sequencing | - |
| 288. Autonomous Detector And Response Synthesis | v1.79 | Plans reviewed | Parked; execution blocked by sequencing | - |
| 289. Herd Memory | v1.79 | Plans reviewed | Parked; execution blocked by sequencing | - |
| 290. Bidirectional Co-Evolution And Convergence | v1.80 historical | 0/TBD | Superseded; historical only | - |
| 291. CI Arms Race Gate And Structural Isolation | v1.80 historical | 0/TBD | Superseded; historical only | - |
| 292. Pure Decision Core Extraction | v1.81 | 0/TBD | Not started | - |
| 293. Kani Bounded Model Checking | v1.81 | 0/TBD | Not started | - |
| 294. Named Safety Properties And Partition-Lease Model | v1.81 | 0/TBD | Not started | - |
| 295. Z3-Backed Promotion Gate | v1.81 historical | - | Superseded by 322 | - |
| 296. Provenance Graph Substrate | v1.82 | 0/TBD | Not started | - |
| 297. Kill-Chain Reconstruction | v1.82 | 0/TBD | Not started | - |
| 298. Cross-Hunt Correlation | v1.82 | 0/TBD | Not started | - |
| 299. Dependency-Aware Triage | v1.82 | 0/TBD | Not started | - |
| 300. BFT Correctness Repair | v1.83 historical | - | Superseded by 321 | - |
| 301. VRF Committee Selection | v1.83 | 0/TBD | Not started | - |
| 302. Governance Key Rotation And Revocation | v1.83 | 0/TBD | Not started | - |
| 303. Fail-Closed Contract Preservation | v1.83 | 0/TBD | Not started | - |
| 304. Reversible Quarantine Execution | v1.84 historical | - | Superseded by 320 | - |
| 305. Information-Flow Control | v1.84 | 0/TBD | Not started | - |
| 306. Cross-Instance Immunity Sharing | v1.84 | 0/TBD | Not started | - |
| 307. Adaptive Deception And Integration Proof | v1.84 | 0/TBD | Not started | - |
| 308. Normative Spec | v1.85 | 0/TBD | Not started | - |
| 309. External Conformance Suite | v1.85 | 0/TBD | Not started | - |
| 310. Detector-Authoring SDK | v1.85 | 0/TBD | Not started | - |
| 311. Generated Coverage And Adopter IA | v1.85 | 0/TBD | Not started | - |
| 312. Cross-Operator Evidence Exchange | v1.86 | 0/TBD | Not started | - |
| 313. Local Activation Boundary | v1.86 | 0/TBD | Not started | - |
| 314. Reputation And Anti-Equivocation | v1.86 | 0/TBD | Not started | - |
| 315. Privacy-Preserving Sharing | v1.86 | 0/TBD | Not started | - |
| 316. Sharded Substrate And Horizontal Scale | v1.87 | 0/TBD | Not started | - |
| 317. Fleet Blast Radius And Tenant Isolation | v1.87 | 0/TBD | Not started | - |
| 318. Fleet Operational Maturity | v1.87 | 0/TBD | Not started | - |
| 319. Signed Release Supply Chain | v1.87 | 0/TBD | Not started | - |
| 320. Reversible Quarantine Execution | v1.78.1 | 4/4 requirements | Complete | 2026-08-14 |
| 321. BFT Correctness Repair | v1.78.1 | Partial by scope | BFT-01/02/05 complete; substrate exchange and networked round deferred to v1.83 | 2026-08-14 |
| 322. Promotion Solver Gate | v1.78.1 | 5/5 requirements | Complete | 2026-08-13 |

---
*Active milestone: v1.79 Collective Cyber Reasoning.*
*v1.79 status (updated 2026-08-28): Phase 284 is complete. Phase 285 remains reopened for governance/detector integration with Plans 01-03B accepted (4/13), Plan 04 accepted through A2b2, and A2b3 banked but unaccepted. R1a `1decdd7` is canonically rejected after transport PASS and deadline-oracle FAIL; a fresh direct-child trace-only correction is next. External GitHub App enforcement remains deferred. Phase 286 Plan 04 is checkpointed but sequenced behind Phase 285. Phase 287-289 plans are reviewed and parked; none is executing.*
*v1.77 and v1.78 complete: phases 276-279 shipped 2026-04-13; phases 280-283 completed as scoped by 2026-08-13.*
*v1.78.1 closed locally with a deliberate partial: phases 320 and 322 complete; phase 321's substrate exchange and networked round are deferred to v1.83.*
*v1.80 Red Swarm is historical/superseded; v1.81-v1.87 retain their original queued phase numbering (292-319).*
*v1.74 deferred: Run `/gsd:plan-phase 264` when structural-integrity work is reactivated.*
