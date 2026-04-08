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

### v1.40 Killer Demo And Providence Integration

**Goal:** Turn the shipped runtime into a compelling live demo surface with replay injection, streamed swarm visibility, approval-in-the-loop response, signed proof export, and Providence delivery.
**Executable phases:** 128-131

- [ ] **Phase 128: Demo Replay Injector And Event Stream Backbone** - Add the demo replay entrypoint and typed SSE stream so the running swarm can be driven and observed from one operator-facing lane.
- [ ] **Phase 129: Live Demo Dashboard And Runtime Timeline** - Build the real-time workbench view for mode, agent health, pheromone pressure, and escalation timeline updates.
- [ ] **Phase 130: Approval-In-The-Loop Demo And Signed Proof Export** - Turn `RequireHuman` response flow and signed proof packaging into a coherent demo path.
- [ ] **Phase 131: Providence Webhook Delivery And Drilldown Context** - Deliver enriched Swarm findings to Providence with runtime context and stable drilldown links.

### Phase 128: Demo Replay Injector And Event Stream Backbone

**Goal:** Add the operator-facing replay injector and streamed event backbone needed to drive a live demo against the real runtime.
**Requirements:** DEMO-01, DEMO-02
**Depends on:** None
**Status:** Planned
**Plans:** 0
**Success Criteria**:
1. `POST /v1/demo/replay` is gated behind `demo_mode`, accepts a scenario YAML path plus replay pacing, and injects events into the running telemetry lane instead of a mock side channel.
2. Replay injection produces real swarm activity across detection, investigation, correlation, escalation, and response surfaces.
3. `GET /v1/events/stream` emits typed Server-Sent Events for agent actions with event-type filtering so downstream demo surfaces can subscribe selectively.

### Phase 129: Live Demo Dashboard And Runtime Timeline

**Goal:** Expose the live runtime state as a purpose-built demo dashboard on top of the streamed event backbone.
**Requirements:** DEMO-03
**Depends on:** Phase 128
**Status:** Planned
**Plans:** 0
**Success Criteria**:
1. The review workbench renders a live dashboard backed by the event stream rather than polling raw storage or logs.
2. The dashboard shows current `SwarmMode`, per-agent health, and per-`ThreatClass` pheromone concentrations in one operator-facing view.
3. The dashboard maintains a scrolling escalation timeline derived from streamed runtime events.

### Phase 130: Approval-In-The-Loop Demo And Signed Proof Export

**Goal:** Make the human-gated response path demoable end to end and exportable as one signed evidence package.
**Requirements:** DEMO-04, DEMO-05
**Depends on:** Phase 128
**Status:** Planned
**Plans:** 0
**Success Criteria**:
1. Demo execution pauses cleanly on `RequireHuman` policy verdicts and persists a resumable approval target instead of executing immediately.
2. The operator approval-set vote endpoint can approve the paused action and resume execution with signed receipt evidence for the approval chain.
3. `GET /v1/demo/proof` exports a JSON proof package containing signed receipts, Merkle proofs, the final `CorrelatedIncident`, and the full decision timeline for the demo run.

### Phase 131: Providence Webhook Delivery And Drilldown Context

**Goal:** Push Swarm findings into Providence with enough runtime and drilldown context to support an external live-demo story.
**Requirements:** PROV-01, PROV-02, PROV-03
**Depends on:** Phase 128
**Status:** Planned
**Plans:** 0
**Success Criteria**:
1. A `providence_webhook` notification channel delivers `SwarmFindingEnvelope` payloads to Providence with threat class and severity mapped into Providence incident fields.
2. Providence payloads include stable links back to Swarm finding drilldown, replay-bundle access, and audit-trail inspection surfaces.
3. Providence payloads include current `SwarmMode`, active agent count, and bridge health summary for runtime status display.

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

- `v1.41 Platform APIs And Deployment Experience` -- Versioned platform API, Helm chart, config validation CLI, guided setup wizard (8 requirements: API-01-04, HELM-01-02, CLI-01-02)

### Tier 3: Detection Breadth (v1.42+)

- `v1.42 Fileless Execution And Behavioral Baselines` -- Memory-based detection, behavioral anomaly baselines (6 requirements: FILELESS-01-06)
- `v1.43 Adversarial Robustness And Evasion Bench` -- Evasion test corpus, coverage metrics, strategy mutation (5 requirements: EVASION-01-05)

## Progress

**v1.38 execution order:** 120 -> 121 || 122 -> 123

**v1.39 execution order:** 124 -> 125 -> 126 -> 127

**v1.40 execution order:** 128 -> 129 -> 130 -> 131

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
| 128. Demo Replay Injector And Event Stream Backbone | v1.40 | 0/0 | Planned | — |
| 129. Live Demo Dashboard And Runtime Timeline | v1.40 | 0/0 | Planned | — |
| 130. Approval-In-The-Loop Demo And Signed Proof Export | v1.40 | 0/0 | Planned | — |
| 131. Providence Webhook Delivery And Drilldown Context | v1.40 | 0/0 | Planned | — |

---
*Last shipped milestone: v1.39 PounceAgent And Policy Gate Hardening on 2026-04-08*
*Active milestone: v1.40 Killer Demo And Providence Integration*
*Last updated: 2026-04-08 after activating v1.40*
