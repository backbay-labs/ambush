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

## Active Milestone

`v1.38 Multi-Detector Composition And Network Detection` -- Run all detector strategies simultaneously per event via CompositeDetector, add NetworkConnectDetector for C2 beaconing and threat-intel IP matching, and enable cross-strategy pheromone escalation so the swarm metaphor actually works. Phases 120-123.

## Phases

- [ ] **Phase 120: Composite Detector And Config Migration** - CompositeDetector replaces single-variant SupportedDetector dispatch; config gains multi-strategy selection with per-strategy profile overrides
- [ ] **Phase 121: Network Connect Detector** - NetworkConnectDetector detects C2 beaconing, anomalous ports, and threat-intel IP matches from NetworkConnect telemetry
- [ ] **Phase 122: Cross-Strategy Pheromone Signals And Rollout Scoping** - Deposits carry strategy-specific identity for distinct-source escalation, WeaverAgent weights cross-strategy correlation higher, and canary/promotion scope to individual strategies
- [ ] **Phase 123: Multi-Strategy Integration Proof** - NetworkConnect findings produce CommandAndControl deposits, and a 3+ strategy composite triggers escalation via distinct_sources

## Phase Details

### Phase 120: Composite Detector And Config Migration
**Goal**: Every configured detection strategy evaluates every telemetry event through a single CompositeDetector, and operators select active strategies via config instead of a single-strategy scalar
**Depends on**: Phase 119 (v1.37.1 complete)
**Requirements**: COMPOSE-01, COMPOSE-02
**Success Criteria** (what must be TRUE):
  1. `CompositeDetector` holds multiple `DetectionStrategy` implementations and returns merged findings from all contained strategies for a single `TelemetryEvent`
  2. `DetectionConfig.strategies` (a `Vec<String>`) takes precedence over the legacy `strategy` scalar when present; both parse paths remain valid
  3. Per-strategy profile overrides in `DetectorProfilesConfig` are resolved correctly when multiple strategies are active simultaneously
  4. Existing single-strategy configs continue to work without modification (backward compatibility)
**Plans:** 2 plans
Plans:
- [ ] 120-01-PLAN.md -- CompositeDetector type, DetectionConfig migration, and detector factory
- [ ] 120-02-PLAN.md -- Runtime integration (IngestState, WhiskerAgent), SupportedDetector removal, and integration tests

### Phase 121: Network Connect Detector
**Goal**: NetworkConnect telemetry events are evaluated for C2 beaconing patterns, anomalous port usage, and threat-intel IP matches through a dedicated detector with a validated profile
**Depends on**: Phase 120
**Requirements**: NETWORK-01, NETWORK-02, NETWORK-03
**Success Criteria** (what must be TRUE):
  1. `NetworkConnectDetector` implements `DetectionStrategy` and evaluates `TelemetryPayload::NetworkConnect` events for periodic same-destination connections with low inter-arrival jitter (C2 beaconing)
  2. `NetworkConnectDetector::evaluate()` queries the substrate threat-intel cache for destination IP matches and boosts finding confidence when matches are found
  3. `NetworkConnectProfile` defines `suspicious_ports` and `process_port_allowlist` and validates consistently with existing detector profiles
  4. Anomalous port usage and process-to-port mismatches produce medium-confidence findings even without threat-intel matches
**Plans**: TBD

### Phase 122: Cross-Strategy Pheromone Signals And Rollout Scoping
**Goal**: Deposits from different strategies count as independent signals for escalation, correlation weights cross-strategy evidence higher, and canary/promotion runs can target a single strategy within the composite
**Depends on**: Phase 120
**Requirements**: COMPOSE-03, COMPOSE-04, COMPOSE-05
**Success Criteria** (what must be TRUE):
  1. Pheromone deposits from different strategies on the same event carry distinct `agent_id` values that incorporate the `strategy_id`, so `PheromoneConcentration.distinct_sources` reflects independent strategy signals
  2. `CorrelationEngine::assemble_incident_at()` applies higher weight to `IncidentMemberDecision` pairs with different `strategy_id` values than same-strategy pairs
  3. `CanaryConfig` and `PromotionConfig` accept an optional `strategy_id` field that scopes observation to a single strategy within the `CompositeDetector`
  4. A multi-strategy deposit burst from distinct strategies satisfies `min_sources_for_escalation` where the same number of same-strategy deposits would not
**Plans**: TBD

### Phase 123: Multi-Strategy Integration Proof
**Goal**: End-to-end integration tests prove NetworkConnect detection through to CommandAndControl deposits, and a multi-stage attack across 3+ strategies triggers escalation via cross-strategy distinct sources
**Depends on**: Phases 121, 122
**Requirements**: NETWORK-04, NETWORK-05
**Success Criteria** (what must be TRUE):
  1. `NetworkConnectDetector` sets all findings to `ThreatClass::CommandAndControl`; an integration test proves NetworkConnect telemetry through detection to signed pheromone deposit
  2. A cross-strategy integration test configures `CompositeDetector` with 3+ strategies, feeds a multi-stage attack sequence, and asserts `PheromoneConcentration.distinct_sources >= 3`
  3. The multi-strategy escalation test proves `min_sources_for_escalation` triggers an `Alert` or `Incident` transition in the substrate
  4. `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` remain green after all v1.38 changes land
**Plans**: TBD

## Queued Milestones

### Tier 1: Core Value Delivery

- `v1.39 PounceAgent And Policy Gate Hardening` -- Autonomous response agent, lease expiration fix, mode de-escalation, configurable policy, TomAgent governance (10 requirements: POUNCE-01-04, POLICY-01-03, DEESC-01-02, TOM-01)

### Tier 2: Product Visibility

- `v1.40 Killer Demo And Providence Integration` -- Scenario replay injector, SSE event stream, Providence live feed, approval-in-the-loop demo, signed proof export (8 requirements: DEMO-01-05, PROV-01-03)
- `v1.41 Platform APIs And Deployment Experience` -- Versioned platform API, Helm chart, config validation CLI, guided setup wizard (8 requirements: API-01-04, HELM-01-02, CLI-01-02)

### Tier 3: Detection Breadth (v1.42+)

- `v1.42 Fileless Execution And Behavioral Baselines` -- Memory-based detection, behavioral anomaly baselines (6 requirements: FILELESS-01-06)
- `v1.43 Adversarial Robustness And Evasion Bench` -- Evasion test corpus, coverage metrics, strategy mutation (5 requirements: EVASION-01-05)

## Progress

**v1.37 execution order:** 112 -> 113 -> 114 -> 115

**v1.37.1 execution order:** 116 -> 117 || 118 -> 119

**v1.38 execution order:** 120 -> 121 || 122 -> 123

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
| 120. Composite Detector And Config Migration | v1.38 | 0/2 | Not started | - |
| 121. Network Connect Detector | v1.38 | 0/? | Not started | - |
| 122. Cross-Strategy Pheromone Signals And Rollout Scoping | v1.38 | 0/? | Not started | - |
| 123. Multi-Strategy Integration Proof | v1.38 | 0/? | Not started | - |

---
*Last shipped milestone: v1.37.1 Runtime Hardening And Audit Debt on 2026-04-08*
*Active milestone: v1.38 Multi-Detector Composition And Network Detection*
*Last updated: 2026-04-08 after v1.38 roadmap creation*
