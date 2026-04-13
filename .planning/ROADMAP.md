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

### v1.75 Operator Packaging

**Goal:** Package the runtime for first external operator use with curated defaults, deployment docs, quickstart workflow, and validation against a public adversary emulation corpus.
**Executable phases:** 268-271

- [ ] **Phase 268: Curated Defaults And Operator UX** - A curated rulesets/default.yaml ships for detect_only mode, swarmctl init generates a working config, swarmctl status outputs an operator-readable runtime summary, and config/bridge error messages include actionable remediation guidance. (DEFAULTS-01, DEFAULTS-02, OPEXP-01, OPEXP-02)
- [ ] **Phase 269: Deployment Documentation** - A getting-started guide walks operators from zero to first detection in under 15 minutes using Docker Compose; deployment documentation covers Docker single-container, Docker Compose with NATS, Helm, and bare-metal paths with prerequisites, config, and verification steps. (DEPLOY-01, DEPLOY-02)
- [ ] **Phase 270: Adversary Emulation Corpus** - A mapped Atomic Red Team corpus of 20+ techniques ships as replay scenarios; cargo test includes an adversary emulation integration suite with a technique-to-detector mapping; a coverage report summarizes per-MITRE-technique detection status with a 60%+ coverage target. (EMULATION-01, EMULATION-02, EMULATION-03)
- [ ] **Phase 271: Quickstart Command And End-To-End Validation** - swarmctl quickstart orchestrates first-run end-to-end: validates config, starts runtime, injects a synthetic attack, waits for detection, and reports the finding with an elapsed-time measurement. (DEPLOY-03)

### Phase 268: Curated Defaults And Operator UX

**Goal:** Operators can reach a working detect_only runtime on first run using curated defaults, and the operator status surface and error messages are clear enough to self-serve.
**Requirements:** DEFAULTS-01, DEFAULTS-02, OPEXP-01, OPEXP-02
**Depends on:** v1.74 milestone complete
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `rulesets/default.yaml` ships with documented detection profiles for all 12 shipped detector strategies; an operator can run `swarmctl init` and `swarmctl validate` without modification.
2. The runtime boots to a ready state on first run using the generated config without manual config editing.
3. `swarmctl status` outputs a single-screen summary of runtime mode, active detectors, bridge health, recent findings count, and escalation state.
4. Error messages from config validation, startup failures, and bridge connection issues include a specific remediation step, not just an error code.

### Phase 269: Deployment Documentation

**Goal:** An operator who has never run Swarm can follow a getting-started guide and reach first detection in under 15 minutes, and the deployment reference covers all supported paths.
**Requirements:** DEPLOY-01, DEPLOY-02
**Depends on:** Phase 268
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `docs/QUICKSTART.md` walks an operator from zero to first detection using Docker Compose including telemetry injection, detection observation, and finding inspection via `swarmctl`.
2. A hands-on path through the guide from a clean state produces a visible detection finding within the 15-minute time target.
3. Deployment documentation covers Docker single-container, Docker Compose with NATS, Helm chart, and bare-metal binary paths, each with prerequisites, config snippets, and a verification step.

### Phase 270: Adversary Emulation Corpus

**Goal:** Operators and CI can verify detection coverage against public adversary emulation scenarios and read a per-technique coverage report.
**Requirements:** EMULATION-01, EMULATION-02, EMULATION-03
**Depends on:** Phase 269
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. The repo includes at least 20 Atomic Red Team techniques adapted as replay scenarios spanning execution, persistence, credential access, lateral movement, and defense evasion tactics.
2. `cargo test` runs an adversary emulation integration suite that replays the corpus through the full detection pipeline and passes with a documented technique-to-detector mapping.
3. A coverage report is generated showing per-MITRE-technique detection status (detected, partial, not covered) and overall technique coverage percentage, meeting the 60%+ coverage target against the mapped corpus.

### Phase 271: Quickstart Command And End-To-End Validation

**Goal:** A new operator can run one command and get to first detection with a measured time-to-detect proof, validating the full operator packaging end-to-end.
**Requirements:** DEPLOY-03
**Depends on:** Phase 270
**Status:** Not started
**Plans:** TBD
**Success Criteria**:
1. `swarmctl quickstart` validates the config, starts the runtime, injects a built-in synthetic attack scenario, waits for detection, and prints the finding with elapsed time in one command.
2. The quickstart command completes successfully on a clean install without requiring manual runtime management steps.
3. The end-to-end flow from `swarmctl quickstart` through reported finding serves as the integration-level proof that curated defaults, deployment docs, and corpus validation are all coherent.


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

**v1.74 execution order:** 264 -> 265 -> 266 -> 267

**v1.75 execution order:** 268 -> 269 -> 270 -> 271

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
| 268. Curated Defaults And Operator UX | v1.75 | 0/TBD | Not started | - |
| 269. Deployment Documentation | v1.75 | 0/TBD | Not started | - |
| 270. Adversary Emulation Corpus | v1.75 | 0/TBD | Not started | - |
| 271. Quickstart Command And End-To-End Validation | v1.75 | 0/TBD | Not started | - |

---
*Active milestone: v1.74 Structural Integrity*
*v1.75 queued: Run `/gsd:plan-phase 268` after v1.74 completes.*
