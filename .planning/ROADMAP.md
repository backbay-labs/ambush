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

## Active Milestone

No active milestone. `v1.39 PounceAgent And Policy Gate Hardening` shipped on 2026-04-08 and is archived in `.planning/milestones/v1.39-ROADMAP.md`.
Start `v1.40 Killer Demo And Providence Integration` with `$gsd-new-milestone`.

<details>
<summary>Shipped: v1.39 PounceAgent And Policy Gate Hardening (Phases 124-127)</summary>

- [x] **Phase 124: PounceAgent Core And De-escalation** - PounceAgent implements SwarmAgent with guard-gated autonomous response, dry-run mode, and de-escalation closes the response loop; lease expiration enforcement fails closed before any adapter call (completed 2026-04-08)
- [x] **Phase 125: Configurable Policy Rules And Audit Trail** - ConfigurableApprovalGate loads YAML rules with per-threat-class and per-severity allow/deny logic, rate limiting, and verdict reason in every structured log and receipt (completed 2026-04-08)
- [x] **Phase 126: TomAgent Governance** - TomAgent monitors agent health and provides synchronous pre-execution veto over destructive PounceAgent actions via shared GovernancePolicy with auditable veto receipts (completed 2026-04-08)
- [x] **Phase 127: Integration Hardening** - End-to-end integration tests prove all seven correctness pitfalls are guarded: no double-trigger, synchronous veto, fail-closed policy, TOCTOU-safe lease check, flap-resistant de-escalation, dry-run parity, and audit lineage (completed 2026-04-08)

</details>

## Queued Milestones

### Tier 1: Core Value Delivery

(none remaining after v1.39)

### Tier 2: Product Visibility

- `v1.40 Killer Demo And Providence Integration` -- Scenario replay injector, SSE event stream, Providence live feed, approval-in-the-loop demo, signed proof export (8 requirements: DEMO-01-05, PROV-01-03)
- `v1.41 Platform APIs And Deployment Experience` -- Versioned platform API, Helm chart, config validation CLI, guided setup wizard (8 requirements: API-01-04, HELM-01-02, CLI-01-02)

### Tier 3: Detection Breadth (v1.42+)

- `v1.42 Fileless Execution And Behavioral Baselines` -- Memory-based detection, behavioral anomaly baselines (6 requirements: FILELESS-01-06)
- `v1.43 Adversarial Robustness And Evasion Bench` -- Evasion test corpus, coverage metrics, strategy mutation (5 requirements: EVASION-01-05)

## Progress

**v1.38 execution order:** 120 -> 121 || 122 -> 123

**v1.39 execution order:** 124 -> 125 -> 126 -> 127

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

---
*Last shipped milestone: v1.39 PounceAgent And Policy Gate Hardening on 2026-04-08*
*Active milestone: none*
*Last updated: 2026-04-08 after v1.39 archival*
