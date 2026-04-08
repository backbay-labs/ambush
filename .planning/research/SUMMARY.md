# Project Research Summary

**Project:** Swarm Team Six — ClawdStrike Ambush
**Domain:** Autonomous EDR/XDR response agent with configurable policy gate, mode de-escalation, and governance oversight
**Researched:** 2026-04-08
**Confidence:** HIGH

## Executive Summary

Swarm Team Six v1.39 closes the detect-to-respond loop by adding autonomous response capability to a runtime that already handles telemetry ingestion, multi-agent detection, pheromone-based signal accumulation, and policy-gated execution. The four features — PounceAgent, configurable policy rules, mode de-escalation, and TomAgent governance — are deeply interdependent: PounceAgent requires de-escalation (so it is not permanently stuck in elevated mode), requires configurable policy rules (so operators can tune behavior without code changes), and requires TomAgent (so destructive actions have a pre-execution governance gate). All four features can be built entirely from crates already in the workspace, with no new Cargo dependencies.

The recommended approach follows the existing agent model precisely: PounceAgent and TomAgent each implement `SwarmAgent` in their own files under `swarm-runtime/src/`, registered in `AgentRegistry` alongside Whisker, Stalker, and Weaver. Policy becomes a composed gate — `ConfigurableApprovalGate` evaluates YAML rules in order, falling through to `StaticApprovalGate` for invariant enforcement, guaranteeing the system fails closed if rules are absent or malformed. Mode de-escalation is a symmetric downward extension of the existing upward-only `ConcentrationMonitor` path, gated by a configurable cooldown to prevent oscillation.

The dominant risk category is correctness-of-ordering: seven distinct pitfalls were identified and all but one cluster in Phase 1 (PounceAgent core). The highest-severity pitfalls are TomAgent veto arriving after execution (making governance meaningless for destructive actions), policy failing open on an empty or parse-error ruleset, and PounceAgent double-triggering on the same escalation signal. All three are preventable with explicit design choices — synchronous veto gate, default-deny with no implicit allow, and a per-session handled-escalation seen-set — and each has a deterministic integration test that proves the guard is in place.

## Key Findings

### Recommended Stack

All v1.39 features are internal-crate changes reusing existing workspace dependencies. The locked dependency surface is stable: `tokio` 1.51.0 for async agent ticks and governance channel handshake (`oneshot` + `mpsc` already available via `features = ["full"]`), `arc-swap` 1.0.102 for lock-free mode state and live policy reload, `serde_yaml` 0.9.x for YAML policy rule config (already used by `SwarmConfig`), `ed25519-dalek` 2.2.3 for agent signing keys, and `uuid`/`chrono` for stable record IDs and cooldown math. The only Cargo.toml change required is verifying that `swarm-guard` is listed in `crates/swarm-runtime/Cargo.toml` before PounceAgent calls `GuardPipeline::evaluate`.

**Core technologies:**
- `tokio` 1.51.0: Async agent tick loop, `oneshot`/`mpsc` for TomAgent veto handshake — already workspace dependency
- `arc-swap` 1.0.102: Lock-free shared mode state, live policy rule reload — established pattern in existing dispatcher
- `serde_yaml` 0.9.x: YAML-driven configurable policy rules — already used for `SwarmConfig` deserialization
- `swarm-policy` (workspace crate): `ConfigurableApprovalGate` lives here alongside `StaticApprovalGate`
- `swarm-runtime` (workspace crate): PounceAgent, TomAgent, and `ConcentrationMonitor` de-escalation all land here
- `swarm-core` (workspace crate): `SwarmModeState::transition_down()`, `PolicyRuleConfig`, `GovernanceConfig` config extensions

### Expected Features

All nine v1.39 features are P1 — operators cannot safely run autonomous response without any of them. There are no optional features in this milestone.

**Must have (table stakes):**
- PounceAgent core: mode-triggered, guard-gated, policy-evaluated autonomous response — the loop is not closed without it
- PounceAgent dry-run mode: operators must preview autonomous behavior before enabling live response
- Lease expiration enforcement: fail-closed on expired `CapabilityLease` before any adapter call
- Configurable policy rules: YAML-backed rule overrides replacing hardcoded `StaticApprovalGate` thresholds
- Policy audit trail: verdict reason and matched rule in every structured log and receipt
- Mode de-escalation: ConcentrationMonitor downward path from Incident/Alert to Normal
- De-escalation cooldown: configurable minimum dwell time preventing mode oscillation
- TomAgent governance: pre-execution veto authority over destructive PounceAgent actions
- TomAgent veto receipts: auditable veto record with rejected action and reason

**Should have (competitive differentiators — v1.x):**
- Per-threat-class policy overrides: different thresholds for DataExfiltration vs. Discovery
- Operator-initiated de-escalation override: manual mode clear via swarmctl without waiting for cooldown
- PounceAgent action prioritization: execute by severity/threat-class priority when multiple events queue

**Defer (v2+):**
- Multi-agent TomAgent quorum: requires independent trust boundaries and distributed node architecture
- PounceAgent adaptive response selection: requires strategy memory integration
- Policy rule hot-reload via file-watch: depends on file-watch infrastructure not yet in place

### Architecture Approach

The architecture is a linear pipeline from telemetry through detection, pheromone accumulation, escalation, autonomous response, and audit — with governance inserted as a synchronous gate before execution. No new crate boundaries are needed. PounceAgent never holds a `SwarmRuntime` reference; it returns `SwarmAction::RequestResponse`, and the dispatcher routes that through a new `ResponseRouter` trait object. This keeps `<P, E>` generics out of agent implementations and makes every agent independently testable. The build order within the milestone is strict: core domain changes first (`SwarmModeState::transition_down()`, config extensions), then policy crate extensions, then runtime agent additions, then dispatcher wiring, then integration tests.

**Major components:**
1. `PounceAgent` (`swarm-runtime/src/pounce_agent.rs`) — reads pheromone/mode state, emits `RequestResponse`, tracks handled escalation IDs to prevent double-trigger
2. `TomAgent` (`swarm-runtime/src/tom_agent.rs`) — reads shared health snapshot, applies `GovernancePolicy` synchronously via `Arc<GovernancePolicy>` shared with PounceAgent, emits role shifts and veto records
3. `ConfigurableApprovalGate` (`swarm-policy/src/configurable_gate.rs`) — evaluates YAML rules in order, delegates to `StaticApprovalGate` on no match, fails closed by default
4. `ConcentrationMonitor` extension (`swarm-runtime/src/escalation.rs`) — adds `transition_down()` path with `last_below_threshold_at` tracking and `deescalation_cooldown_secs` enforcement
5. `ResponseRouter` trait (`swarm-runtime/src/dispatcher.rs`) — decouples `AgentDispatcher` from `SwarmRuntime<P, E>` generics; response executions spawn as bounded Tokio tasks

### Critical Pitfalls

1. **TomAgent veto arrives after execution** — TomAgent must call `GovernancePolicy::can_act()` synchronously inside PounceAgent's tick, before the `execute()` call. A veto via pheromone deposit or separate async task is meaningless for destructive actions. Test: assert `execute()` is never called when veto returns `Err`.

2. **Policy fails open on empty or parse-error ruleset** — `ConfigurableApprovalGate` must default to `PolicyDecision::deny("no matching rule; failing closed")` when no rule matches. Config parse errors must fail startup, not skip silently. Test: empty ruleset yields `Deny`, not `Allow`.

3. **PounceAgent double-triggers on the same escalation signal** — PounceAgent must maintain a per-mode-session seen-set of handled escalation IDs and react to mode-transition events, not raw pheromone concentrations. Test: inject same escalation twice, assert `execute()` called exactly once.

4. **TOCTOU on lease expiry between evaluation and execution** — `ResponseExecutor::execute()` must check `lease.expires_at_ms > now_ms` immediately before calling any adapter, using the same `now_ms` snapshot as policy evaluation. Test: advance clock past `lease_ttl_ms`, assert executor returns `Err` not a receipt.

5. **Mode de-escalation flapping amplifies false-positive response actions** — de-escalation must require all active threat classes to stay below threshold continuously for `deescalation_cooldown_secs`. Test: burst-decay-burst pattern, assert second response does not fire within cooldown window.

6. **Dry-run bypasses the full pipeline** — PounceAgent dry-run must route through the identical code path as live mode, passing `ExecutionMode::DryRun` to the executor. An early-return before the policy gate tests a different path than production. Test: dry-run path asserts policy evaluated, receipt persisted with `status: Simulated`.

7. **Audit lineage broken between PounceAgent and detection** — `ActionRequest.hunt_id` must trace to the escalation record that triggered the response. A synthetic `"pounce-{uuid}"` breaks the audit chain. Test: PounceAgent receipt resolves via `replay_lookup` to the originating finding.

## Implications for Roadmap

Based on combined research, four phases are recommended, matching the feature dependency graph exactly.

### Phase 1: PounceAgent Core and Foundation
**Rationale:** Everything else depends on PounceAgent existing. Five of seven pitfalls are in this phase — getting the core right before building governance and policy on top prevents cascading correctness problems. De-escalation must also land here or PounceAgent is permanently stuck in elevated mode.
**Delivers:** Working end-to-end autonomous response loop: escalation pheromone triggers PounceAgent, policy gate evaluates, guard pipeline checks, executor fires (or simulates), signed receipt with lineage emitted. Mode de-escalation with cooldown allows the runtime to return to Normal.
**Addresses:** PounceAgent core (POUNCE-01..04), dry-run mode, lease expiration enforcement, mode de-escalation (DEESC-01..02), policy audit trail foundation
**Avoids:** Pitfalls 1 (TOCTOU), 2 (double-trigger), 5 (mode flapping), 6 (dry-run path divergence), 7 (audit lineage)

### Phase 2: Configurable Policy Rules
**Rationale:** Phase 1 can ship with `StaticApprovalGate` as the policy backend; Phase 2 replaces it with the configurable gate. This separation means PounceAgent is testable with a known policy before introducing the complexity of YAML rule evaluation. Policy is on the critical safety path — correctness here gates TomAgent introduction in Phase 3.
**Delivers:** YAML-driven `ConfigurableApprovalGate` composed with `StaticApprovalGate` as invariant fallback. Policy verdicts carry matched-rule attribution in audit records. Operators can tune response behavior per deployment without code changes.
**Addresses:** POLICY-01 (configurable rules), POLICY-02 (policy audit trail), POLICY-03 (lease expiration in gate)
**Avoids:** Pitfall 4 (fail-open on empty/parse-error ruleset)

### Phase 3: TomAgent Governance
**Rationale:** TomAgent governs PounceAgent, so PounceAgent must be stable before TomAgent is meaningful. The synchronous veto handshake requires the configurable policy gate to be in place so governance config and policy config are consistent types.
**Delivers:** TomAgent implementing `SwarmAgent`, pre-execution synchronous veto for destructive actions via `Arc<GovernancePolicy>` shared with PounceAgent, auditable veto receipts, agent health monitoring with role-shift emission.
**Addresses:** TOM-01 (governance oversight), TomAgent veto records
**Avoids:** Pitfall 3 (veto race — veto is synchronous gate, not post-hoc annotation)

### Phase 4: Integration Hardening and Test Coverage
**Rationale:** Seven specific pitfalls each have a deterministic integration test that proves the guard is in place. These tests cannot be written in isolation — they require the full pipeline from Phases 1-3. This phase closes the verification gap and produces the "looks done but isn't" checklist from PITFALLS.md.
**Delivers:** Complete integration test suite covering all seven pitfall scenarios, added to `crates/swarm-runtime/tests/`.
**Addresses:** All seven pitfall verification tests
**Avoids:** Shipping with untested safety properties

### Phase Ordering Rationale

- Phases 1 and 2 before Phase 3: TomAgent governs PounceAgent; PounceAgent must exist and have a stable policy backend before governance is meaningful.
- De-escalation in Phase 1, not Phase 3: PounceAgent operating permanently in elevated mode is an operational problem from day one, not a governance problem.
- Policy in Phase 2, not Phase 1: Phase 1 can run with `StaticApprovalGate` as a shim; configurable rules deserve independent validation before being composed with governance.
- Integration hardening as a final phase: The seven pitfall tests all require the full pipeline to be wired; writing them earlier creates test stubs that cannot execute.

### Research Flags

Phases with standard patterns (research not needed during planning):
- **Phase 1:** Agent implementation pattern is well-established in the codebase (Whisker, Stalker, Weaver are direct templates). De-escalation is a symmetric extension of the existing upward path.
- **Phase 2:** YAML deserialization and `arc-swap` hot-reload are already used in `SwarmConfig`; `ConfigurableApprovalGate` follows the same pattern.
- **Phase 4:** Integration test structure matches `crates/swarm-runtime/tests/`; no new infrastructure needed.

Phases that may need targeted research during planning:
- **Phase 3 (TomAgent):** The `Arc<GovernancePolicy>` synchronous veto design resolves the race condition but the ownership wiring through `AgentDispatcher` construction needs careful design review. The boundary between TomAgent-as-health-monitor (async, dispatcher tick) and TomAgent-as-veto-gate (synchronous, inside PounceAgent tick) must be clearly specified in the phase plan before implementation begins.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All findings verified against live `Cargo.toml`, `Cargo.lock`, and crate source; no new dependencies needed |
| Features | HIGH (codebase) / MEDIUM (domain) | Must-have feature set is grounded in codebase gaps; domain patterns from SentinelOne/CrowdStrike/Defender are secondary sources |
| Architecture | HIGH | Primary sources are the live crates; build order is derived from actual import dependencies |
| Pitfalls | HIGH | Seven pitfalls are code-grounded; three are supported by real-world EDR CVE and security research |

**Overall confidence:** HIGH

### Gaps to Address

- **TomAgent ownership boundary:** The exact construction-time wiring of `Arc<GovernancePolicy>` between `TomAgent` and `PounceAgent` inside `AgentDispatcher` needs explicit resolution in the Phase 3 plan before implementation begins. This is a design decision, not a research gap.
- **`ResponsePlaybookConfig` scope:** The architecture research introduces a `ResponsePlaybookConfig` type mapping `(ThreatClass, Severity, confidence_range)` tuples to ordered `ResponseAction` sequences. This is not in REQUIREMENTS.md yet. Confirm whether Phase 1 PounceAgent selects actions from this config or from a simpler default before planning begins.
- **Rate limiter GC memory bound:** The architecture research calls for GC of rate-tracking entries in `StaticApprovalGate` older than 60s. Memory bound under sustained high-volume telemetry is unquantified. Note in Phase 2 plan.

## Sources

### Primary (HIGH confidence)
- `crates/swarm-core/src/agent.rs` — `SwarmAgent`, `SwarmModeState`, `AgentRole::Pouncer`, `AgentRole::Tom`
- `crates/swarm-core/src/config.rs` — `PolicyConfig`, `PheromoneConfig`, `SwarmConfig` current state
- `crates/swarm-policy/src/lib.rs` + `static_gate.rs` — `ApprovalGate` trait, `StaticApprovalGate`, lease semantics
- `crates/swarm-guard/src/lib.rs` — `GuardPipeline`, `GuardAction::ResponseAction`
- `crates/swarm-response/src/dispatch.rs` — `DispatchingExecutor`, `ExecutionMode::DryRun`, `ResponseReceipt`
- `crates/swarm-runtime/src/escalation.rs` — `ConcentrationMonitor` upward-only path confirmed
- `crates/swarm-runtime/src/dispatcher.rs` — `AgentDispatcher`, `RequestResponse` no-op confirmed
- `crates/swarm-runtime/src/whisker_agent.rs` + `stalker_agent.rs` — agent implementation reference patterns
- `Cargo.toml` + `Cargo.lock` — locked dependency versions (tokio 1.51.0, arc-swap 1.0.102, uuid 1.23.0, chrono 0.4.44)

### Secondary (MEDIUM confidence)
- [Autonomous SOC Explained — Security Boulevard, 2026](https://securityboulevard.com/2026/04/autonomous-soc-explained-how-agentic-investigation-solves-what-playbooks-couldnt/) — industry patterns for agentic response triggering
- [Configure automated investigation — Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/m365d-configure-auto-investigation-response) — governance oversight patterns
- [AI Guardrail Design — QueryPie](https://www.querypie.com/features/documentation/white-paper/28/ai-agent-guardrails-governance-2026) — pre-execution veto design patterns
- [Understanding Fail Open and Fail Closed — AuthZed](https://authzed.com/blog/fail-open) — security gate default posture
- [Agentic Governance Architecture — arXiv](https://arxiv.org/html/2603.07191v2) — governance pre-execution vs. post-hoc analysis
- [Idempotency in Event-Driven Systems — DZone](https://dzone.com/articles/idempotency-and-reliability-in-event-driven-systems) — at-least-once delivery and idempotent consumer patterns
- CVE-2025-59497 (TOCTOU in Microsoft Defender for Endpoint on Linux) — real-world TOCTOU in production EDR code

---
*Research completed: 2026-04-08*
*Ready for roadmap: yes*
