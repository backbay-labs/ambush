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

`v1.39 PounceAgent And Policy Gate Hardening` -- Close the detect-to-respond loop with an autonomous PounceAgent that consumes escalation pheromones and executes safe response actions through the guard-gated adapter pipeline, while hardening policy leases, adding mode de-escalation, and introducing TomAgent for governance oversight. Phases 124-127.

## Phases

- [ ] **Phase 124: PounceAgent Core And De-escalation** - PounceAgent implements SwarmAgent with guard-gated autonomous response, dry-run mode, and de-escalation closes the response loop; lease expiration enforcement fails closed before any adapter call
- [ ] **Phase 125: Configurable Policy Rules And Audit Trail** - ConfigurableApprovalGate loads YAML rules with per-threat-class and per-severity allow/deny logic, rate limiting, and verdict reason in every structured log and receipt
- [ ] **Phase 126: TomAgent Governance** - TomAgent monitors agent health and provides synchronous pre-execution veto over destructive PounceAgent actions via shared GovernancePolicy with auditable veto receipts
- [ ] **Phase 127: Integration Hardening** - End-to-end integration tests prove all seven correctness pitfalls are guarded: no double-trigger, synchronous veto, fail-closed policy, TOCTOU-safe lease check, flap-resistant de-escalation, dry-run parity, and audit lineage

## Phase Details

### Phase 124: PounceAgent Core And De-escalation
**Goal**: Operators can observe PounceAgent autonomously consuming escalation pheromones, routing through the policy gate and guard pipeline, and emitting signed receipts with detection lineage; mode de-escalation returns the runtime to Normal when threat pressure drops
**Depends on**: Phase 123 (v1.38 complete)
**Requirements**: POUNCE-01, POUNCE-02, POUNCE-03, POUNCE-04, POUNCE-05, DEESC-01, DEESC-02, POLICY-01
**Success Criteria** (what must be TRUE):
  1. PounceAgent emits `SwarmAction::RequestResponse` when mode is Alert or Incident, and the dispatcher routes it through `authorize_and_execute()` so PounceAgent actions flow through the policy gate and guard pipeline
  2. PounceAgent dry-run mode produces `ResponseReceipt` records with `status: Simulated`, routing through the identical code path as live mode so the policy gate and guard pipeline are both exercised
  3. `SwarmRuntime::authorize_and_execute()` returns `ApprovalError::Denied("capability lease expired")` for any request where `CapabilityLease.expires_at_ms <= now_ms`, failing closed before any adapter is called
  4. PounceAgent skips emitting responses whose target scope already matches an `AgentFinding` in `peer_findings` for the same tick cycle, preventing double-trigger on the same escalation signal
  5. `ConcentrationMonitor::evaluate_all()` calls `transition_down()` when all threat-class concentrations remain below alert threshold for `deescalation_cooldown_secs`, and `SwarmModeState::transition_down()` updates `last_transition_at` and clears `triggering_threat_class`
**Plans**: TBD

### Phase 125: Configurable Policy Rules And Audit Trail
**Goal**: Operators can tune response authorization per deployment by writing YAML rules without code changes; every policy verdict carries the matched rule name and reason in structured logs and receipt audit records
**Depends on**: Phase 124
**Requirements**: POLICY-02, POLICY-03, POLICY-04
**Success Criteria** (what must be TRUE):
  1. `StaticApprovalGate` tracks recent actions per scope and denies requests that exceed `max_actions_per_scope_per_minute`, with the rate-limit denial reason appearing in structured logs
  2. `ConfigurableApprovalGate` loads YAML rules specifying action allow/deny by threat class, severity thresholds, time-of-day restrictions, and per-agent rate limits; an empty or parse-error ruleset defaults to deny, not allow
  3. Every policy verdict (allow or deny) records the matched rule name and verdict reason in structured logs and in the `ResponseReceipt` audit field
  4. `ConfigurableApprovalGate` falls through to `StaticApprovalGate` when no YAML rule matches, preserving invariant enforcement as the last line of defense
**Plans**: TBD

### Phase 126: TomAgent Governance
**Goal**: TomAgent monitors the health of all registered agents and provides synchronous pre-execution veto authority over destructive PounceAgent actions, with every vetoed action producing an auditable veto receipt
**Depends on**: Phase 125
**Requirements**: TOM-01, TOM-02
**Success Criteria** (what must be TRUE):
  1. TomAgent implements `SwarmAgent` with `AgentRole::Tom`, monitors agent health summaries each tick, emits `RoleShift` for degraded agents, and emits `HealthReport { status: Failed }` for agents that remain degraded beyond a configurable tick threshold
  2. TomAgent's `GovernancePolicy::can_act()` is evaluated synchronously inside PounceAgent's tick, before `authorize_and_execute()` is called, so a veto always prevents execution rather than annotating it after the fact
  3. Vetoed actions produce durable veto receipts carrying the rejected action type, the veto reason, and the governing agent ID, queryable from the operator surface
**Plans**: TBD

### Phase 127: Integration Hardening
**Goal**: The full autonomous response pipeline from escalation through governance to execution is proven correct against all seven identified pitfalls via deterministic integration tests that cover the complete Phases 124-126 pipeline
**Depends on**: Phase 126
**Requirements**: POUNCE-01, POUNCE-02, POUNCE-03, POUNCE-04, POUNCE-05, DEESC-01, DEESC-02, POLICY-01, POLICY-02, POLICY-03, POLICY-04, TOM-01, TOM-02
**Note**: This phase does not own exclusive requirements — it adds integration-level test coverage proving the correctness properties of all 13 v1.39 requirements working together. Individual requirements are assigned to their delivery phases above; this phase verifies their integration.
**Success Criteria** (what must be TRUE):
  1. A test injects the same escalation pheromone twice into a running PounceAgent and asserts `authorize_and_execute()` is called exactly once (no double-trigger)
  2. A test advances the clock past `lease_ttl_ms` and asserts the executor returns an error receipt, not a successful response (TOCTOU-safe lease check)
  3. A test configures an empty YAML ruleset and asserts `ConfigurableApprovalGate` returns `Deny`, not `Allow` (fail-closed policy)
  4. A test wires a TomAgent veto and asserts `execute()` is never called for the vetoed action (synchronous veto gate)
  5. A test runs a burst-decay-burst pheromone sequence and asserts no second response fires within the cooldown window (flap-resistant de-escalation)
  6. `cargo test --workspace` and `cargo clippy --workspace -- -D warnings` remain green after all v1.39 changes land
**Plans**: TBD

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
| 124. PounceAgent Core And De-escalation | v1.39 | 0/TBD | Not started | - |
| 125. Configurable Policy Rules And Audit Trail | v1.39 | 0/TBD | Not started | - |
| 126. TomAgent Governance | v1.39 | 0/TBD | Not started | - |
| 127. Integration Hardening | v1.39 | 0/TBD | Not started | - |

---
*Last shipped milestone: v1.38 Multi-Detector Composition And Network Detection on 2026-04-08*
*Active milestone: v1.39 PounceAgent And Policy Gate Hardening*
*Last updated: 2026-04-08 after v1.39 roadmap creation*
