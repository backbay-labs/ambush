# Roadmap: Swarm Team Six

## Milestones

<details>
<summary>Shipped milestones (v1.0 through v1.37) -- see MILESTONES.md and .planning/milestones/</summary>

Phases 1-115 shipped across milestones v1.0 through v1.37. Full history is in `.planning/MILESTONES.md`, and per-milestone roadmap snapshots live in `.planning/milestones/`.

</details>

## Active Milestone

`v1.37.1 Runtime Hardening And Audit Debt` — Fix critical infrastructure bugs and test coverage gaps identified during the v1.31-v1.37 audit before adding more features. Phases 116-119.

## Phases

- [x] **Phase 112: Telemetry Persistence Payloads And Detector Contracts** - `TelemetryPayload` grows `registry_persistence` and `file_persistence`, `ThreatClass` gains `SupplyChain`, and runtime/profile plumbing learns the new detector families
- [x] **Phase 113: Persistence Detector And Profile Support** - A `PersistenceDetector` identifies scheduled tasks, cron changes, systemd timers, and run-key writes using a validated `PersistenceProfile`
- [x] **Phase 114: Supply Chain Detector And Profile Support** - A `SupplyChainDetector` identifies unsigned trusted-path binaries, DLL side-loading, and signed-binary abuse with ATT&CK-tagged evidence
- [x] **Phase 115: Persistence And Supply Chain Integration Proof** - Integration coverage, replay/canary/promotion support, docs, and milestone verification prove the new detectors through deposits and threat-class tagging
- [x] **Phase 116: Agent Safety Hardening** - Signed pheromone deposits, configurable tick timeout, and explicit action-handling warnings close the three agent-safety audit findings (completed 2026-04-07)
- [x] **Phase 117: Substrate Durability And Bridge Resilience** - Threat-intel GC on all three backends, journal rewrite on GC, gRPC stream timeout, and empty-parent schema fix close the four substrate and bridge audit findings (completed 2026-04-07)
- [x] **Phase 118: Operational Hardening** - Independent secret-dir file-watch for hot rotation and size-based dead-letter rotation close the two operational-gap audit findings (completed 2026-04-07)
- [x] **Phase 119: Pheromone Test Suite** - A focused `swarm-pheromone` test suite with 15+ tests covering the substrate trait contract closes the test-coverage audit finding (completed 2026-04-08)

## Phase Details

### Phase 112: Telemetry Persistence Payloads And Detector Contracts
**Goal**: Extend the shared telemetry and detector contracts so persistence and supply-chain signals can move through ingest, replay, canary, and promotion flows without ad hoc special cases
**Depends on**: Phase 111 (v1.36 complete)
**Requirements**: PERSIST-03, PERSIST-04
**Success Criteria** (what must be TRUE):
  1. `TelemetryPayload` includes `RegistryPersistence` and `FilePersistence` variants with stable serde support
  2. `ThreatClass` includes `SupplyChain`, and threat-class label helpers recognize it everywhere they surface user-facing strings or metrics
  3. `DetectorProfilesConfig` and profile-resolution helpers understand `persistence` and `supply_chain`
  4. Control, replay, canary, and promotion code paths can construct the new detector families from repo-owned config
  5. Focused tests prove the shared contracts accept the new telemetry and detector shapes
**Plans**: 2/2 plans complete

Plans:
- [x] 112-01-PLAN.md -- Add shared telemetry payloads, `SupplyChain` threat class, and detector profile contracts
- [x] 112-02-PLAN.md -- Wire the new detector families through runtime config, replay, canary, and promotion surfaces

### Phase 113: Persistence Detector And Profile Support
**Goal**: Ship a first-class `PersistenceDetector` that recognizes suspicious scheduled-task, cron, systemd-timer, and registry-run persistence activity
**Depends on**: Phase 112
**Requirements**: PERSIST-01, PERSIST-04
**Success Criteria** (what must be TRUE):
  1. `PersistenceDetector` implements `DetectionStrategy` and evaluates `RegistryPersistence` and `FilePersistence` events
  2. Suspicious run-key writes, cron modifications, systemd timer installs, and scheduled-task artifacts generate `ThreatClass::Persistence` findings
  3. Every persistence finding includes `mitre_technique_id` in the evidence payload
  4. `PersistenceProfile` validates consistently with existing detector profiles
  5. Focused tests prove benign persistence-adjacent events stay silent while suspicious patterns trigger deposits
**Plans**: 2/2 plans complete

Plans:
- [x] 113-01-PLAN.md -- Implement `PersistenceProfile` plus heuristics for run keys, cron, systemd timers, and scheduled-task persistence
- [x] 113-02-PLAN.md -- Add focused persistence detector tests and runtime-facing coverage for the new strategy

### Phase 114: Supply Chain Detector And Profile Support
**Goal**: Ship a `SupplyChainDetector` that recognizes unsigned trusted-path execution, DLL side-loading, and signed-binary abuse
**Depends on**: Phase 112
**Requirements**: PERSIST-02, PERSIST-03, PERSIST-04
**Success Criteria** (what must be TRUE):
  1. `SupplyChainDetector` implements `DetectionStrategy` for `ProcessStart` and `FilePersistence` signals
  2. Unsigned trusted-path binaries, DLL side-loading, and certutil/rundll32 abuse produce `ThreatClass::SupplyChain` findings
  3. Every supply-chain finding includes `mitre_technique_id` in the evidence payload
  4. `SupplyChainProfile` validates consistently with the existing detector profile contract
  5. Focused tests prove each heuristic and preserve stable strategy IDs across runtime surfaces
**Plans**: 2/2 plans complete

Plans:
- [x] 114-01-PLAN.md -- Implement `SupplyChainProfile` plus heuristics for unsigned trusted-path execution and DLL side-loading
- [x] 114-02-PLAN.md -- Add signed-binary abuse coverage and runtime/replay support for the `supply_chain` strategy

### Phase 115: Persistence And Supply Chain Integration Proof
**Goal**: Prove the new detectors end to end, update operator docs, and close the milestone with replayable verification evidence
**Depends on**: Phases 113 and 114
**Requirements**: PERSIST-05
**Success Criteria** (what must be TRUE):
  1. Integration tests drive synthetic `RegistryPersistence`, `FilePersistence`, and `ProcessStart` events through both detectors
  2. Findings from both detectors preserve the correct `ThreatClass`, `mitre_technique_id`, and non-zero pheromone deposits via `findings_to_deposits`
  3. Runtime-facing tests prove the new strategies can be selected from config without breaking existing detector families
  4. Config and operator docs describe the new payload variants and profile surfaces
  5. Milestone verification closes `v1.37` only after the new detectors, tags, and deposits are proven
**Plans**: 2/2 plans complete

Plans:
- [x] 115-01-PLAN.md -- Add integration scenarios and deposit proofs for persistence and supply-chain findings
- [x] 115-02-PLAN.md -- Update docs, verify the milestone, and close out `v1.37`

### Phase 116: Agent Safety Hardening
**Goal**: Agents sign every deposit before submitting, the dispatcher enforces a tick timeout, and unhandled action variants produce structured warnings instead of silent drops
**Depends on**: Phase 115 (v1.37 complete)
**Requirements**: HARDEN-01, HARDEN-02, HARDEN-03
**Success Criteria** (what must be TRUE):
  1. A `PheromoneDeposit` with an empty `signature` or `agent_key` field is rejected by `PheromoneSubstrate::deposit()` with a structured error; unsigned deposits cannot reach the substrate in serve mode
  2. `WhiskerAgent` and `StalkerAgent` each sign deposits with their agent key before calling `deposit()`, and the substrate accepts those signed records
  3. Every `SwarmAgent::tick()` call is wrapped in `tokio::time::timeout()` using `agent_tick_timeout_ms` from `RuntimeSettings`; an agent that times out is marked `AgentHealth::Degraded` and its tick is skipped for that cycle
  4. Any `SwarmAction` variant not explicitly handled by `AgentDispatcher::apply_actions()` emits a structured warning log with the variant name; `ClaimInvestigation` and `PublishFindings` are no longer silently dropped
**Plans**: 2 plans

Plans:
- [ ] 116-01-PLAN.md -- Enforce signed pheromone deposits across substrate and agents
- [ ] 116-02-PLAN.md -- Add tick timeout enforcement and structured warnings for unhandled actions

### Phase 117: Substrate Durability And Bridge Resilience
**Goal**: Threat-intel GC runs on all three backends and rewrites the local-journal file, and the TetragonBridge detects and recovers from silent stream hangs and accepts init-spawned processes
**Depends on**: Phase 116
**Requirements**: HARDEN-04, HARDEN-05, HARDEN-06, HARDEN-07
**Success Criteria** (what must be TRUE):
  1. `gc_expired_threat_intel()` exists on `PheromoneSubstrate` and removes entries whose `expires_at` has passed across in-memory, local-journal, and JetStream backends; purge counts appear in structured logs
  2. `LocalJournalPheromoneSubstrate` rewrites the threat-intel journal file during GC, removing expired entries so the file does not grow without bound across multiple GC cycles
  3. `TetragonBridge::poll()` wraps `stream.next().await` in `tokio::time::timeout()` with a configurable `event_timeout_secs`; a stream that goes silent increments `swarm_bridge_error_count` and enters reconnect-backoff instead of hanging
  4. `TetragonBridge` schema validation accepts `ProcessStartEvent` with an empty `parent_process` field and stores `"<none>"` as the sentinel instead of rejecting the event
**Plans**: 2 plans

Plans:
- [ ] 117-01-PLAN.md -- Add gc_expired_threat_intel() to PheromoneSubstrate across all three backends with journal rewrite
- [ ] 117-02-PLAN.md -- Add stream timeout to TetragonBridge::poll() and fix empty-parent schema validation

### Phase 118: Operational Hardening
**Goal**: Secret-dir changes are detected and applied independently of config reload, and dead-letter journals rotate by size instead of growing without bound
**Depends on**: Phase 116
**Requirements**: HARDEN-08, HARDEN-09
**Success Criteria** (what must be TRUE):
  1. The `SwarmSecretProvider` file-watch thread monitors `secret_dir` independently; when a secret file changes, only the affected `@secret:` references are re-resolved and injected into active adapter configs without triggering a full config reload
  2. Response and notification dead-letter journals rotate when the file exceeds `max_dead_letter_bytes` from `RuntimeSettings`; the rotated file receives a timestamp suffix and the active journal is truncated to an empty state
  3. The runtime can cycle through at least one secret rotation and one dead-letter rotation in integration conditions without losing in-flight deposits or notification records
**Plans**: 3 plans

Plans:
- [x] 118-01-PLAN.md -- Independent secret-dir file-watch for hot rotation
- [x] 118-02-PLAN.md -- Size-based dead-letter journal rotation
- [x] 118-03-PLAN.md -- Thread max_dead_letter_bytes to production paths and add rotation integration test (gap closure)

### Phase 119: Pheromone Test Suite
**Goal**: `swarm-pheromone` has a focused, self-contained test suite that exercises the substrate trait contract independently of the runtime
**Depends on**: Phase 117
**Requirements**: HARDEN-10
**Success Criteria** (what must be TRUE):
  1. `swarm-pheromone` contains at least 15 tests covering deposit, query, evaporation GC, escalation record persistence, threat-intel CRUD with TTL expiry, and `ThreatClassConfig` store/query
  2. Every test runs against `InMemoryPheromoneSubstrate` without importing `swarm-runtime` or requiring a running server
  3. Tests for threat-intel TTL expiry call `gc_expired_threat_intel()` and assert the expired entry is absent while unexpired entries remain present
  4. `cargo test -p swarm-pheromone` passes with `cargo clippy -p swarm-pheromone -- -D warnings` clean
**Plans**: 1 plan

Plans:
- [ ] 119-01-PLAN.md -- Add 16 focused substrate trait contract tests for deposit, query, GC, escalation, threat-intel, and ThreatClassConfig

## Queued Milestones

### Tier 1: Core Value Delivery

- `v1.38 Multi-Detector Composition And Network Detection` — Run all strategies simultaneously, add C2/network detection, cross-strategy pheromone escalation (10 requirements: COMPOSE-01–05, NETWORK-01–05)
- `v1.39 PounceAgent And Policy Gate Hardening` — Autonomous response agent, lease expiration fix, mode de-escalation, configurable policy, TomAgent governance (10 requirements: POUNCE-01–04, POLICY-01–03, DEESC-01–02, TOM-01)

### Tier 2: Product Visibility

- `v1.40 Killer Demo And Providence Integration` — Scenario replay injector, SSE event stream, Providence live feed, approval-in-the-loop demo, signed proof export (8 requirements: DEMO-01–05, PROV-01–03)
- `v1.41 Platform APIs And Deployment Experience` — Versioned platform API, Helm chart, config validation CLI, guided setup wizard (8 requirements: API-01–04, HELM-01–02, CLI-01–02)

### Tier 3: Detection Breadth (v1.42+)

- `v1.42 Fileless Execution And Behavioral Baselines` — Memory-based detection, behavioral anomaly baselines (6 requirements: FILELESS-01–06)
- `v1.43 Adversarial Robustness And Evasion Bench` — Evasion test corpus, coverage metrics, strategy mutation (5 requirements: EVASION-01–05)

## Progress

**v1.37 execution order:** 112 -> 113 -> 114 -> 115

**v1.37.1 execution order:** 116 -> 117 || 118 -> 119

| Phase | Complete    | 2026-04-08 | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 112. Telemetry Persistence Payloads And Detector Contracts | v1.37 | 2/2 | Complete | 2026-04-07 |
| 113. Persistence Detector And Profile Support | v1.37 | 2/2 | Complete | 2026-04-07 |
| 114. Supply Chain Detector And Profile Support | v1.37 | 2/2 | Complete | 2026-04-07 |
| 115. Persistence And Supply Chain Integration Proof | v1.37 | 2/2 | Complete | 2026-04-07 |
| 116. Agent Safety Hardening | 2/2 | Complete    | 2026-04-07 | - |
| 117. Substrate Durability And Bridge Resilience | 2/2 | Complete    | 2026-04-08 | - |
| 118. Operational Hardening | v1.37.1 | 3/3 | Complete | 2026-04-07 |
| 119. Pheromone Test Suite | 1/1 | Complete    | 2026-04-08 | - |

---
*Last shipped milestone: v1.37 Persistence And Supply Chain Detection on 2026-04-07*
*Active milestone: v1.37.1 Runtime Hardening And Audit Debt*
*Last updated: 2026-04-07 after completing 118-03 gap closure*
