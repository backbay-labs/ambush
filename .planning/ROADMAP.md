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

## Recently Completed Milestone

### v1.43 Swarm Memory And Adversarial Pressure

**Goal:** Give the swarm persistent memory and adversarial fitness pressure through SphinxAgent’s knowledge graph, stigmergic query loops, and Rust-native red-blue scenario generation.
**Executable phases:** 141-144

- [x] **Phase 141: Sphinx Knowledge Graph Foundations** - Built SphinxAgent’s persistent graph store and typed threat-memory model. (completed 2026-04-09)
- [x] **Phase 142: Stigmergic Memory Queries And Fitness Retrieval** - Routed knowledge lookups through pheromone queries and fed Sphinx-backed Q-values into Kitten fitness. (completed 2026-04-09)
- [x] **Phase 143: Knowledge Retention And Adversarial Corpus Adapter** - Added graph retention controls and the Rust-native adversarial scenario adapter. (completed 2026-04-09)
- [x] **Phase 144: Red-Blue Pressure And Episode Logging** - Folded generation-scoped adversarial pressure into Kitten fitness and persisted durable red-blue episode history plus status reporting. (completed 2026-04-09)

### Phase 132: Platform API Envelope And Auth Surface

**Goal:** Expose a versioned, read-only platform API on the detect server with stable pagination envelopes and scoped API key authentication.
**Requirements:** API-01, API-04
**Depends on:** Phase 131
**Status:** Completed 2026-04-08
**Plans:** 1
**Success Criteria**:
1. A `/v2/api/` route group on the detect server serves findings, incidents, and runtime status through a `{ data: [...], cursor: Option<String> }` envelope with cursor pagination and filter support.
2. The platform API enforces default `page_size=50`, `max=200`, and keeps `/v1/operator/*`, `/v1/ingest/events`, and health probes outside the new API key gate.
3. Platform API key middleware validates configured SHA-256 key hashes, resolves `read` scope, and attaches authenticated identity to the request context for downstream logging.

### Phase 133: Asset Posture And Findings Stream Surface

**Goal:** Make the new platform API useful for operator and downstream consumers by exposing host posture and live findings streams.
**Requirements:** API-02, API-03
**Depends on:** Phase 132
**Status:** Completed 2026-04-08
**Plans:** 1
**Success Criteria**:
1. `GET /v2/api/assets/{host_id}/posture` returns per-`ThreatClass` pheromone concentrations, active investigations, escalation level, and recent findings for a host using substrate-backed host filtering.
2. `GET /v2/api/stream/findings` reuses the existing `RuntimeEventBroadcaster` with a `finding` event filter and emits `SwarmFindingEnvelope` payloads as Server-Sent Events.
3. The posture and findings-stream surfaces preserve the versioned platform API auth and response contract introduced in Phase 132.

### Phase 134: Helm Deployment And Config CLI Experience

**Goal:** Turn the runtime into a repeatable deployment target with a repo-owned Helm chart and operator-friendly config bootstrapping commands.
**Requirements:** HELM-01a, HELM-01b, HELM-02, CLI-01, CLI-02
**Depends on:** Phase 132
**Status:** Completed 2026-04-08
**Plans:** 1
**Success Criteria**:
1. A base Helm chart deploys `swarm_detect --serve` with ConfigMap-mounted config, Secret-backed `@secret:` references, configurable resources, and an optional NATS subchart for JetStream mode.
2. The Helm chart parameterizes runtime mode, strategies, substrate backend, response adapter, SIEM target, and notification channels through `values.yaml`, and wires the existing startup, readiness, liveness, and PreStop probe behavior plus a `PodDisruptionBudget`.
3. `swarmctl validate --config <path>` performs full config validation, supports optional endpoint reachability checks, and emits structured JSON when `--json` is passed.
4. `swarmctl init --mode detect_only|live_response` generates a complete `rulesets/custom.yaml` with documented defaults and inline comments for the selected mode.

### Phase 135: Serve-Surface Security And Panic Elimination

**Goal:** Harden the production-facing runtime by eliminating known panic paths and securing the versioned platform API with bearer auth and TLS.
**Requirements:** HARD-01, HARD-03a, HARD-03b
**Depends on:** Phase 133, Phase 134
**Status:** Completed 2026-04-08
**Plans:** 1
**Success Criteria**:
1. Panic-prone `Default::default()` detector profiles in `swarm-whisker` and the remaining `.expect()` demo-proof path in `swarm-runtime` are replaced with safe defaults or fallible `Result`-based construction.
2. `/v2/api/*` routes enforce bearer token validation consistent with the operator surface middleware pattern, and authenticated identity is recorded in structured tracing context.
3. Both HTTP servers can run with optional TLS via configured cert and key paths, and optionally require client certificates when a client CA cert is configured.

### Phase 136: Crate Extraction And Trace Instrumentation

**Goal:** Reduce runtime monolith pressure and improve observability by extracting the evolution and CLI code into dedicated crates and instrumenting the critical path.
**Requirements:** HARD-02, HARD-04
**Depends on:** Phase 135
**Status:** Completed 2026-04-09
**Plans:** 1
**Success Criteria**:
1. The evolution subsystem is extracted into a `swarm-evolution` crate and the CLI is extracted into a `swarm-cli` crate, while `swarm-runtime` retains agents, HTTP, ingest, and dispatcher ownership.
2. `IngestState::process_event()`, `ConfiguredRuntimeStack::process_event()`, `CompositeDetector::evaluate()`, `ConfigurableApprovalGate::check()`, and `DispatchingExecutor::execute()` are instrumented with structured tracing spans that carry the existing correlation ID as `trace_id`.
3. OTLP export remains optional behind an `--otlp-endpoint` flag, and the extracted workspace still builds and runs the existing runtime and CLI entrypoints.

## Latest Milestone Details

### v1.42 Evolution Engine Core

**Goal:** Add KittenAgent’s mutation loop, drift detection, formal safety verification, canary admission, and observability so strategy evolution becomes a first-class runtime subsystem.
**Executable phases:** 137-140
**Status:** Complete 2026-04-09

- [x] **Phase 137: Kitten Mutation And Drift Orchestration** - Add KittenAgent’s multi-tick mutation loop and concept-drift activation logic.
- [x] **Phase 138: Fitness Evaluation And Population Persistence** - Score candidate genomes on replay corpora and persist the evolving population across restarts.
- [x] **Phase 139: Formal Safety Gate And Canary Admission** - Verify evolved candidates against repo-owned safety invariants before the canary handoff.
- [x] **Phase 140: Evolution Observability And Operator Status** - Surface evolution metrics over SSE and `swarmctl evolution status`.

### Phase 137: Kitten Mutation And Drift Orchestration

**Goal:** Introduce KittenAgent as a timeout-safe multi-tick mutation worker that wakes up only when concept drift indicates the current detector set is degrading.
**Requirements:** KITTEN-01, KITTEN-03
**Depends on:** Phase 136
**Status:** Complete 2026-04-09
**Plans:** 1
**Success Criteria**:
1. `KittenAgent` implements `SwarmAgent` with a multi-tick state machine (`AwaitingDrift -> Mutating -> Evaluating -> Verifying -> Proposing`) and repo-owned mutation operators over detector profile genomes.
2. A `ConceptDriftDetector` activates Kitten based on configured detection-rate and false-positive-rate drift thresholds, minimum observation counts, and cooldown windows.
3. Kitten’s tick path stays within the existing agent timeout budget by breaking long-running mutation work into resumable state-machine steps.

### Phase 138: Fitness Evaluation And Population Persistence

**Goal:** Make evolved candidates measurable and durable by scoring them on replay corpora and persisting the population across restarts.
**Requirements:** KITTEN-02, KITTEN-05
**Depends on:** Phase 137
**Status:** Complete 2026-04-09
**Plans:** 1
**Success Criteria**:
1. Candidate strategies are evaluated on the repo-owned replay corpus using configurable multi-objective fitness weights and Pareto-based tournament selection.
2. The Kitten population and generation state are serialized to durable storage and restored on restart without losing progress.
3. A configurable `max_proposals_per_hour` throttle prevents the evolution loop from flooding the downstream canary pipeline.

### Phase 139: Formal Safety Gate And Canary Admission

**Goal:** Gate evolved strategies through deterministic safety proofs before they are allowed to enter the existing rollout lane.
**Requirements:** KITTEN-04, SAFETY-01, SAFETY-02, SAFETY-03
**Depends on:** Phase 138
**Status:** Complete 2026-04-09
**Plans:** 1
**Success Criteria**:
1. A `FormalSafetyGate` verifies evolved candidates with deterministic invariant checks and optional Z3-backed proofs driven by repo-owned YAML invariant files in `rulesets/safety/`.
2. Safety verification runs asynchronously, persists signed proof artifacts and counterexamples on failure, and does not block the Kitten tick loop.
3. Candidates that pass safety are submitted through the existing `SwarmAction::ProposeStrategy` and canary handoff path with failure records preserved when canary admission rejects them.

### Phase 140: Evolution Observability And Operator Status

**Goal:** Make the evolution subsystem inspectable to operators through the same runtime streaming and CLI surfaces used elsewhere in the product.
**Requirements:** EVOLVE-OBS-01, EVOLVE-OBS-02
**Depends on:** Phase 139
**Status:** Complete 2026-04-09
**Plans:** 1
**Success Criteria**:
1. Evolution metrics for generation count, diversity, best and mean fitness, verification pass rate, and canary admission rate are emitted as runtime events on the existing SSE broadcaster.
2. `swarmctl evolution status` reports current generation, population size, drift-detector state, latest fitness scores, and pending or completed verification results.
3. The new observability surfaces stay aligned with the evolution state owned by Phases 137-139 rather than duplicating logic in a side channel.

### v1.43 Swarm Memory And Adversarial Pressure

**Goal:** Give the swarm persistent memory and adversarial fitness pressure through SphinxAgent’s knowledge graph, stigmergic query loops, and Rust-native red-blue scenario generation.
**Executable phases:** 141-144
**Status:** Complete 2026-04-09

- [x] **Phase 141: Sphinx Knowledge Graph Foundations** - Build SphinxAgent’s persistent graph store and typed threat-memory model.
- [x] **Phase 142: Stigmergic Memory Queries And Fitness Retrieval** - Route knowledge lookups through pheromone queries and feed Sphinx-backed Q-values into Kitten fitness.
- [x] **Phase 143: Knowledge Retention And Adversarial Corpus Adapter** - Add graph retention controls and the Rust-native adversarial scenario adapter.
- [x] **Phase 144: Red-Blue Pressure And Episode Logging** - Fold adversarial pressure into evolution fitness and persist full red-blue episode history.

### Phase 141: Sphinx Knowledge Graph Foundations

**Goal:** Establish SphinxAgent and a durable knowledge graph store as the persistent memory substrate for the swarm.
**Requirements:** SPHINX-01, SPHINX-02
**Depends on:** Phase 140
**Status:** Complete 2026-04-09
**Plans:** 1
**Success Criteria**:
1. `SphinxAgent` implements `SwarmAgent` with `AgentRole::Sphinx` and persists knowledge through a `FileKnowledgeGraphStore` rather than the time-decaying pheromone substrate.
2. The knowledge graph supports the typed node and edge model defined in requirements, covering threat patterns, ATT&CK techniques, entities, engagements, and temporal, causal, entity, and semantic relationships.
3. The Sphinx lifecycle loads durable graph state on startup and preserves cross-engagement context across restarts.

### Phase 142: Stigmergic Memory Queries And Fitness Retrieval

**Goal:** Make swarm memory usable without breaking the indirect pheromone-based communication model.
**Requirements:** SPHINX-03, SPHINX-04
**Depends on:** Phase 141
**Status:** Complete 2026-04-09
**Plans:** 1
**Success Criteria**:
1. Other agents query Sphinx by depositing `QueryPheromone` entries, and Sphinx replies with `AnswerPheromone` deposits rather than direct RPC or shared mutable state.
2. Kitten fitness can incorporate Sphinx-backed Q-value retrieval using relevance, outcome reward, and recency decay, with a clean fallback to replay-only fitness when memory is unavailable.
3. Query and answer semantics remain auditable and compatible with the existing substrate-driven swarm interaction model.

### Phase 143: Knowledge Retention And Adversarial Corpus Adapter

**Goal:** Keep memory bounded and add a Rust-native adversarial-sequence generator that can feed the evolution loop without reviving Python dependencies.
**Requirements:** SPHINX-05, HELLCAT-01
**Depends on:** Phase 141
**Status:** Complete 2026-04-09
**Plans:** 1
**Success Criteria**:
1. The knowledge graph applies TTL-based garbage collection for stale entries using configurable `knowledge_retention_days`.
2. A `RedSwarmAdapter` can generate adversarial telemetry sequences from repo-owned scenario suites, and a `MockRedSwarm` exists for deterministic tests.
3. The adversarial corpus adapter remains Rust-native and does not require the historical Hellcat Python runtime to function.

### Phase 144: Red-Blue Pressure And Episode Logging

**Goal:** Close the loop between swarm memory and evolution by scoring candidate strategies under adversarial pressure and preserving full episode history.
**Requirements:** HELLCAT-02, HELLCAT-03
**Depends on:** Phase 142, Phase 143
**Status:** Completed 2026-04-09
**Plans:** 1
**Success Criteria**:
1. Kitten fitness evaluates candidates against the latest adversarial corpus snapshot, freezing the corpus version per generation and regenerating between generations.
2. A `FileEvolutionEpisodeStore` persists episode IDs, generation numbers, corpus versions, genome hashes, per-threat-class coverage, and red/blue fitness vectors.
3. Red-blue episode logging integrates with the evolution loop introduced in v1.42 without bypassing the existing safety and canary controls.

## Active Milestone

### v1.44 Agent Identity And Infrastructure Signals

**Goal:** Ship durable agent identity lifecycle (prerequisite for all future governance work) plus Sentinel-derived infrastructure telemetry bridge for a new detection dimension.
**Executable phases:** 145-148

- [ ] **Phase 145: Agent Key Persistence And Identity Derivation** - Persist Ed25519 keypairs to configurable directory, derive stable identity strings, load on restart. (IDENTITY-01)
- [ ] **Phase 146: Identity Registry And Key Rotation** - Maintain known-agent registry with admission verification, implement key rotation with continuity proofs and old-key retention. (IDENTITY-02, IDENTITY-03)
- [ ] **Phase 147: Sentinel Infrastructure Telemetry Bridge** - Implement `swarm-ingest-sentinel` crate with `TelemetryBridge` trait for infrastructure health, thermal anomaly, and resource exhaustion payloads. (INFRA-01, INFRA-04)
- [ ] **Phase 148: Infrastructure Anomaly Detection And Cross-Signal Correlation** - Add `InfrastructureAnomalyDetector` for cryptomining, resource exhaustion, and thermal threats; wire cross-signal correlation with behavioral detectors. (INFRA-02, INFRA-03)

### Phase 145: Agent Key Persistence And Identity Derivation

**Goal:** Give every agent a durable Ed25519 identity that survives restarts and can be verified across the swarm.
**Requirements:** IDENTITY-01
**Depends on:** Phase 144
**Status:** Queued
**Plans:** 0
**Success Criteria**:
1. Agent keypairs are generated at first startup and persisted to `agent_key_dir` as PEM or raw-bytes files.
2. On subsequent starts, the agent loads existing keys instead of generating new ones.
3. Agent identity is derived as `swarm:ed25519:<hex-encoded-public-key>` and used consistently in deposits, receipts, and audit entries.

### Phase 146: Identity Registry And Key Rotation

**Goal:** Track which agent identities are legitimate and support safe key rotation without breaking historical verification.
**Requirements:** IDENTITY-02, IDENTITY-03
**Depends on:** Phase 145
**Status:** Queued
**Plans:** 0
**Success Criteria**:
1. An `AgentIdentityRegistry` admits agents after identity verification on startup; unknown identities are logged and rejected from governance participation.
2. Key rotation generates a new keypair, the old key signs a handoff message containing the new public key, and the continuity proof is persisted.
3. Old keys are retained with `active_until` timestamps for verification of historical signed artifacts.

### Phase 147: Sentinel Infrastructure Telemetry Bridge

**Goal:** Add a new telemetry source that ingests infrastructure-level signals from Sentinel for threat detection.
**Requirements:** INFRA-01, INFRA-04
**Depends on:** Phase 144
**Status:** Queued
**Plans:** 0
**Success Criteria**:
1. A `swarm-ingest-sentinel` crate implements `TelemetryBridge` and maps `InfrastructureHealth`, `ThermalAnomaly`, and `ResourceExhaustion` payloads into new `TelemetryPayload` variants.
2. `SwarmConfig.runtime.telemetry_sources` accepts `"sentinel"` as a named bridge with event-count, error-count, and lag-seconds metrics on `/healthz` and `/metrics`.
3. The bridge follows the same health reporting and lifecycle patterns as existing Tetragon and JSON bridges.

### Phase 148: Infrastructure Anomaly Detection And Cross-Signal Correlation

**Goal:** Detect infrastructure-signal threats and boost escalation confidence when infrastructure and behavioral signals converge.
**Requirements:** INFRA-02, INFRA-03
**Depends on:** Phase 147
**Status:** Queued
**Plans:** 0
**Success Criteria**:
1. `InfrastructureAnomalyDetector` detects cryptominer activity (sustained CPU/thermal), resource exhaustion (fork bomb, disk wiper), and memory pressure correlated with fileless malware.
2. Infrastructure findings flow through the existing pheromone deposit, escalation, and notification pipelines.
3. Cross-signal correlation between infrastructure anomalies and behavioral detections boosts escalation confidence via `distinct_sources` diversity.

## Queued Milestones With Defined Phases

### v1.45 Providence Native

**Goal:** Complete the Providence ecosystem integration with bidirectional incident lifecycle, analyst feedback, and embeddable dashboard widget.
**Executable phases:** 149-152

- [ ] **Phase 149: Providence Contract And Service Auth** - Define shared webhook schema, implement HMAC signature verification, and configure service-to-service bearer token. (PROVAUTH-01, PROVAUTH-02)
- [ ] **Phase 150: Incident Lifecycle Adapter** - Build outbound incident create/update/resolve adapter with retry, dead-letter, idempotent create-by-key, and health reporting. (PROVBI-01, PROVBI-02, PROVBI-03)
- [ ] **Phase 151: Analyst Feedback Loop** - Expose feedback endpoint for confirm/dismiss/investigate actions, forward dismissals to KittenAgent fitness, persist audit trail. (PROVFB-01, PROVFB-02, PROVFB-03)
- [ ] **Phase 152: Embeddable Dashboard Widget And Context Tokens** - Serve minimal embeddable widget with CSP headers, context-scoped display, and short-lived Ed25519-signed access tokens. (PROVDASH-01, PROVDASH-02, PROVDASH-03)

### v1.46 Distributed Governance

**Goal:** Implement multi-instance BFT consensus, extend TomAgent to distributed agreement, add partition authority with contingency leases, and validate with chaos testing.
**Executable phases:** 153-156

- [ ] **Phase 153: Consensus Protocol Core** - Implement Tendermint-style propose-prevote-precommit state machine with deterministic committee rotation over JetStream. (CONSENSUS-01, CONSENSUS-02)
- [ ] **Phase 154: Byzantine Safety And Multi-Instance Governance** - Add signed message validation, equivocation detection, agent exclusion receipts; extend TomAgent to BFT agreement with 1-of-1 fallback; wire registry-backed deposit validation and governance receipts. (CONSENSUS-03, GOVERN-01, GOVERN-02, GOVERN-03)
- [ ] **Phase 155: Partition Authority And Contingency Leases** - Build partition detector with heartbeat/quorum signals, contingency lease pre-staging and redemption, fail-open detection / fail-closed response, and partition reconciliation on healing. (PARTITION-01, PARTITION-02, PARTITION-03, PARTITION-04)
- [ ] **Phase 156: Chaos And Resilience Testing** - Inject Byzantine agent behavior, simulate network partitions, and run cascading failure scenarios with deterministic replay. (CHAOS-01, CHAOS-02, CHAOS-03)

### v1.47 Calico And Detection Breadth

**Goal:** Complete the 8th agent archetype (deception) and expand detection coverage to fileless execution and behavioral anomalies.
**Executable phases:** 157-160

- [ ] **Phase 157: Calico Agent Core And Deception Playbook** - Implement CalicoAgent with honeypot service deployment and canary token placement driven by repo-owned YAML playbooks. (CALICO-01, CALICO-02)
- [ ] **Phase 158: Calico Lifecycle And Evolution Integration** - Manage decoy deploy/monitor/rotate/cleanup lifecycle, register decoys in Sphinx knowledge graph, and feed deception interactions into KittenAgent fitness. (CALICO-03, CALICO-04)
- [ ] **Phase 159: Fileless Execution Detection** - Add `FilelessExecutionDetector` for reflective DLL injection, encoded PowerShell, and syscall gadget patterns via new `ProcessMemoryAccess` telemetry payload. (FILELESS-01, FILELESS-03, FILELESS-05)
- [ ] **Phase 160: Behavioral Anomaly Baselines** - Add `BehavioralAnomalyDetector` with per-host process ancestry baselines, configurable decay, and substrate-backed persistence. (FILELESS-02, FILELESS-04, FILELESS-06)

### v1.48 Adversarial Robustness

**Goal:** Validate detection coverage against curated evasion techniques and add optional Z3 formal verification for evolved strategies.
**Executable phases:** 161-163

- [ ] **Phase 161: Evasion Test Corpus And Coverage Metrics** - Build curated evasion corpus (10+ payloads per ThreatClass), coverage metrics module, and evasion technique catalog. (EVASION-01, EVASION-02, EVASION-04)
- [ ] **Phase 162: KittenAgent Evasion Mutation Cycle** - Wire evasion corpus gaps into KittenAgent mutation loop and run end-to-end evasion-to-canary integration tests. (EVASION-03, EVASION-05)
- [ ] **Phase 163: Z3 Formal Verification** - Implement Z3 SMT verification tier behind `z3` feature flag with strategy-to-assertion compilation, counterexample generation, configurable timeout, and signed proof artifacts. (Z3-01, Z3-02)

## Progress

**v1.38 execution order:** 120 -> 121 || 122 -> 123

**v1.39 execution order:** 124 -> 125 -> 126 -> 127

**v1.40 execution order:** 128 -> 129 -> 130 -> 131

**v1.41 execution order:** 132 -> 133 || 134 -> 135 -> 136

**v1.42 execution order:** 137 -> 138 -> 139 -> 140

**v1.43 execution order:** 141 -> 142 || 143 -> 144

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

---
*Last shipped milestone: v1.43 Swarm Memory And Adversarial Pressure on 2026-04-09*
*Next step: `$gsd-new-milestone` to activate v1.44 Agent Identity And Infrastructure Signals*
*Last updated: 2026-04-09 — milestones restructured after post-v1.43 review (hybrid sequence: identity+infra → Providence → governance → Calico → evasion)*
