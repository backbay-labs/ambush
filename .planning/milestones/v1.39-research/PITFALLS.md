# Pitfalls Research

**Domain:** Autonomous response agent, configurable policy gate, mode de-escalation, governance oversight in a single-node Rust EDR runtime
**Researched:** 2026-04-08
**Confidence:** HIGH (code-grounded; verified against existing crates)

---

## Critical Pitfalls

### Pitfall 1: PounceAgent Triggers On Stale Pheromone Pressure (TOCTOU on Lease and Mode)

**What goes wrong:**
PounceAgent reads the escalation pheromone, evaluates the policy gate, mints a `CapabilityLease`, then executes the adapter — all as separate async steps. If the lease check and the adapter execution are not atomic with respect to lease expiration, the agent can execute an action under a lease that expired between `issue_lease()` and `execute()`. Conversely, if pheromone concentration has already decayed below the alert threshold by the time the policy gate runs, the agent acts on a condition that no longer exists.

**Why it happens:**
The current `StaticApprovalGate::issue_lease()` mints a lease with `expires_at_ms = context.now_ms + lease_ttl_ms`, but the `CapabilityLease` struct has no enforcement path after minting — the executor receives the lease as a plain struct and never checks `expires_at_ms` before calling the adapter. Adding PounceAgent creates the first real consumer of the lease expiration field, which has been semantically present but never enforced.

**How to avoid:**
- The adapter execution path in `swarm-response` must check `lease.expires_at_ms > now_ms()` immediately before calling into the adapter, and must return `ResponseError` (not skip silently) when the lease is expired.
- PounceAgent must re-check current pheromone concentration and current `SwarmMode` from the shared `ArcSwap<SwarmModeState>` immediately before forming the `ActionRequest`, using a single consistent `now_ms` snapshot for both the concentration check and the lease timestamp.
- The policy evaluation and lease issuance must share the same `now_ms` value so the lease does not expire before the executor even receives it.

**Warning signs:**
- `CapabilityLease.expires_at_ms` field is present in existing code but no test exercises the expired-lease path.
- `StaticApprovalGate::issue_lease` and `ResponseExecutor::execute` are called with different `now_ms` values anywhere in the calling code.
- Integration tests for PounceAgent do not include a scenario where wall clock advances past `lease_ttl_ms` between evaluation and execution.

**Phase to address:** PounceAgent core (Phase 1 of v1.39)

---

### Pitfall 2: PounceAgent Double-Triggers On The Same Escalation Signal

**What goes wrong:**
PounceAgent polls or subscribes to escalation pheromones. If the pheromone substrate delivers the same escalation event twice (at-least-once semantics common in async channels and JetStream), or if the `ConcentrationMonitor` emits multiple `EscalationOutcome` events for the same threshold crossing during mode stabilization, PounceAgent executes the same response action multiple times. On a live EDR adapter this produces duplicate `block_egress` calls, duplicate `isolate_host` calls, or duplicate audit receipts for the same incident, all of which damage operator trust.

**Why it happens:**
The existing `ConcentrationMonitor::evaluate_all()` correctly gates upward mode transitions with `if target_mode > self.mode_state.current`, preventing duplicate escalation *records*, but pheromone polling is separate from the mode state machine. PounceAgent, if it reacts to pheromone deposits rather than mode transitions, sees the same deposit multiple times on each tick. Even if PounceAgent reacts to mode transitions, if it is registered in the `AgentRegistry` and ticked on every dispatcher cycle, it will see `SwarmMode::Incident` on every tick after the first escalation and re-trigger unless it tracks which escalation events it has already acted on.

**How to avoid:**
- PounceAgent must maintain an internal set of `hunt_id` or `escalation_record_id` values it has already acted on within the current mode session, and skip re-execution for already-handled events.
- The triggering contract should be mode-transition events (a `mode_changed: true` outcome with a new escalation record ID), not raw pheromone deposits. React to the transition, not the concentration.
- Receipts from `ResponseExecutor::execute` already carry a stable `capability_id` derived from `hunt_id + action + now_ms`. PounceAgent can use this as an idempotency key against a local in-memory or substrate-backed seen-set.
- Integration tests must inject the same escalation signal twice and assert that the adapter is called exactly once.

**Warning signs:**
- PounceAgent tick loop does not carry any `last_handled_escalation` state between ticks.
- The pheromone substrate's `query_concentration` is called on every tick without a per-escalation deduplication check.
- Tests inject a single escalation and verify execution count is `>= 1` rather than `== 1`.

**Phase to address:** PounceAgent core (Phase 1 of v1.39)

---

### Pitfall 3: TomAgent Veto Races PounceAgent Execution

**What goes wrong:**
TomAgent is introduced to provide governance oversight with veto authority over PounceAgent actions. If TomAgent's veto check is implemented as a separate async task that runs after PounceAgent has already dispatched the `ActionRequest` to the adapter, the veto arrives too late — the response action has already executed. This is the classic check-then-act ordering failure in concurrent agent systems.

**Why it happens:**
The natural implementation of veto is a post-hoc audit: PounceAgent executes, TomAgent sees the receipt and marks it as approved or vetoed. But a vetoed receipt after execution is meaningless for destructive actions — the host is already isolated. The temptation is to add a "veto flag" that PounceAgent checks after execution, which is only useful for undoing actions, not preventing them. Implementing true pre-execution veto requires a synchronous or blocking handshake, which conflicts with the single-node tick-based agent model.

**How to avoid:**
- TomAgent's veto authority must be enforced as a synchronous gate *within* the PounceAgent tick, before the `execute()` call, not in a separate concurrent task.
- The veto mechanism is simplest as a `fn can_act(request: &ActionRequest, context: &GovernanceContext) -> Result<(), VetoReason>` call on a `TomAgent`-owned `GovernancePolicy` struct, called synchronously by PounceAgent before dispatching to the executor.
- TomAgent does not need to run on its own dispatcher tick to provide veto. The governance policy evaluation is a pure function over the request and context, not an async coordination problem.
- If TomAgent is registered in the agent registry and runs on its own tick (for observability and audit), its veto authority must be the *same policy struct* as the one PounceAgent calls inline, enforced by shared ownership (`Arc<GovernancePolicy>`).
- Do not implement veto as a flag that PounceAgent polls or a channel it reads — those approaches introduce the race window.

**Warning signs:**
- TomAgent and PounceAgent are both in the `AgentRegistry` and interact only through pheromone deposits.
- "Veto" is described as TomAgent depositing a `deny_response` pheromone that PounceAgent checks on the next tick.
- Tests for veto do not assert that the adapter's `execute()` method was never called when TomAgent vetoes.

**Phase to address:** TomAgent governance (Phase 3 or 4 of v1.39)

---

### Pitfall 4: Configurable Policy Rules Bypass Fail-Closed Semantics

**What goes wrong:**
Moving from `StaticApprovalGate` (hardcoded verdicts) to a configurable rule system means that a misconfigured or empty ruleset produces an `Allow` verdict by default — the system fails open. If operator-defined policy rules are YAML-loaded and the parsing or rule-matching path has an error, the gate falls through to an implicit allow instead of an explicit deny. Any gap in the rule coverage silently authorizes actions that should have been denied.

**Why it happens:**
Rule engine implementations default to "no matching rule = allow" to reduce friction during initial rollout. This is the wrong default for a security gate. The transition from `StaticApprovalGate` to configurable rules feels incremental but actually inverts the security posture: the existing static gate has an explicit `Deny` path for low-severity destructive actions and an explicit `RequireHuman` path for high-severity ones — there is no implicit allow. A configurable rule engine introduces implicit allow as soon as the match fails.

**How to avoid:**
- The configurable policy gate must have an explicit default verdict in its config: `default_verdict: deny`. Absence of a matching rule must yield `PolicyDecision::deny("no matching rule; failing closed")`.
- Rule parsing errors must fail startup (or operator upsert) rather than silently skip the malformed rule and leave a gap.
- The policy audit trail required by the milestone must record which rule matched (or "no rule matched, default applied") so operators can see gaps.
- Tests must include a scenario with an empty ruleset and assert the verdict is `Deny`, not `Allow`.

**Warning signs:**
- Policy rule matching returns `None` or `Option<PolicyDecision>` and the caller uses `.unwrap_or(PolicyDecision::allow(...))`.
- Config validation for the new policy rule format does not reject unknown action types or missing required fields at load time.
- The policy audit trail records `reason: "authorized"` without identifying which rule produced the verdict.

**Phase to address:** Configurable policy rules (Phase 2 of v1.39)

---

### Pitfall 5: Mode De-escalation Flapping Amplifies False Positive Response Actions

**What goes wrong:**
Adding de-escalation (transitioning from `Incident` or `Alert` back to `Normal`) without a cooldown allows the runtime to oscillate rapidly: pheromone pressure rises above the incident threshold, mode escalates to `Incident`, PounceAgent responds, pheromone pressure decays below the threshold, mode de-escalates to `Normal`, new activity drives pressure above threshold again, PounceAgent responds again. In a high-noise environment this produces repeated response actions for the same underlying activity within minutes, which is operationally worse than staying in `Incident` mode and waiting for explicit operator clearance.

**Why it happens:**
`ConcentrationMonitor::evaluate_all()` currently only escalates upward (`if target_mode > self.mode_state.current`). De-escalation requires adding a downward path. The natural implementation — check if all threat classes are below their thresholds, then return to `Normal` — has no memory of how long the system has been at elevated mode or when the last response action fired. Pheromone half-life decay can oscillate across a threshold within a single monitor interval.

**How to avoid:**
- De-escalation must require that pheromone concentration has been below the threshold continuously for at least one configurable cooldown window (e.g., `deescalation_cooldown_ms: 300_000` for 5 minutes).
- `SwarmModeState` must track `last_escalation_at_ms` and de-escalation must only trigger if `now_ms - last_escalation_at_ms >= cooldown_ms`.
- De-escalation must produce a durable `EscalationRecord` with `mode: Normal` and timestamp so operators can see the transition in audit logs.
- The cooldown should be separate from the pheromone half-life configuration so operators can tune them independently.
- Integration tests must inject a burst-decay-burst pattern and assert that the second burst does not produce a second response action within the cooldown window.

**Warning signs:**
- De-escalation logic is added to `evaluate_all()` without adding `deescalation_cooldown_ms` to `PheromoneConfig`.
- `SwarmModeState` does not record `last_escalation_at_ms` or `last_deescalation_at_ms`.
- Tests for de-escalation only verify the final mode, not the number of response actions that fired during the oscillation.

**Phase to address:** Mode de-escalation (Phase 2 or 3 of v1.39)

---

### Pitfall 6: PounceAgent Dry-Run Mode Is Not Structurally Identical To Live Mode

**What goes wrong:**
Dry-run mode for PounceAgent is implemented as a flag that skips the executor call entirely rather than passing `ExecutionMode::DryRun` through the full adapter pipeline. This means operators previewing dry-run behavior see a truncated path that never exercises the policy gate, the lease check, or the receipt generation. The dry-run preview is not a faithful simulation of what live mode will do, and bugs in those paths are invisible until live mode is activated.

**Why it happens:**
The `SandboxExecutor` already implements the correct pattern: it processes the full `execute(request, lease, DryRun)` path and returns `ResponseStatus::Simulated`. But the shortcut of "if dry-run, just log and return" is tempting because it is simpler and produces clean output without any infrastructure setup. The problem is that it tests a different code path than live mode.

**How to avoid:**
- PounceAgent dry-run mode must route through the identical code path as live mode, up to and including the executor's `execute()` call.
- The executor receives `ExecutionMode::DryRun` and returns `ResponseStatus::Simulated`; the response receipt is generated and persisted identically to the live path.
- Dry-run receipts must be distinguishable in the audit trail by status (`Simulated`) not by absence.
- Tests for dry-run must assert that the policy gate was evaluated, the lease was checked, and a receipt was persisted — not just that no network call was made.

**Warning signs:**
- PounceAgent has a `if self.dry_run { return Ok(()) }` early-return before the policy gate evaluation.
- Dry-run integration tests only check that no HTTP call was made, not that a receipt was written.
- The operator status surface shows zero decisions in dry-run mode instead of decisions with `Simulated` status.

**Phase to address:** PounceAgent core (Phase 1 of v1.39)

---

### Pitfall 7: Audit Trail Lineage Broken Between PounceAgent And Detection

**What goes wrong:**
PounceAgent produces response receipts, but the receipts are not linked back to the escalation pheromone, the detection finding, or the replay bundle that caused the response. An operator reviewing the audit trail sees that a `block_egress` action was executed, but cannot trace it back to the `NetworkConnectDetector` finding that triggered the escalation. The audit trail is auditable in isolation but not explainable in context.

**Why it happens:**
The existing `ReplayBundle` and `ResponseReceipt` schema carry a `hunt_id` that links detection to response. But PounceAgent is a new layer between detection and response — it consumes escalation pheromones, not individual findings. The escalation record carries a `threat_class` and `timestamp` but not a direct `hunt_id`. Linking PounceAgent's response receipts back through the escalation record to the originating findings requires the receipt to carry an `escalation_record_id` or the PounceAgent to embed the relevant `hunt_id` values from the substrate query.

**How to avoid:**
- PounceAgent must populate `ActionRequest.hunt_id` with a value traceable to the escalation event that triggered it — either the most recent escalation record ID or the highest-confidence finding's hunt ID from the substrate.
- Response receipts must carry `escalation_record_id` or an equivalent stable identifier linking them to the substrate escalation history.
- The `ControlEnvelope` status surface must show PounceAgent-originated receipts as distinct from investigation-pipeline receipts, so operators can see the full chain.
- Integration tests must assert that a PounceAgent-generated receipt's `hunt_id` can be resolved via `replay_lookup` to the originating detection event.

**Warning signs:**
- `ActionRequest.hunt_id` in PounceAgent is set to a synthetic value like `"pounce-{uuid}"` that does not trace to any detection artifact.
- The status surface shows PounceAgent receipts but `replay_lookup` by receipt ID returns `NotFound`.
- The governance audit trail does not record which escalation event a vetoed or allowed action corresponds to.

**Phase to address:** PounceAgent core (Phase 1 of v1.39)

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| TomAgent veto as post-hoc audit only | Simpler implementation, no sync handshake | Veto cannot prevent destructive actions, only flag them after the fact | Never for destructive actions; acceptable for informational receipt audit |
| Policy rules default-allow on no match | Easier operator onboarding, fewer startup rejections | Any gap in rule coverage silently authorizes actions; one misconfigured rule opens a hole | Never in a security gate; use default-deny always |
| De-escalation without cooldown | Simpler state machine, faster return to Normal | Mode oscillation triggers repeated response actions on the same incident | Never when PounceAgent is active; only acceptable in observe-only modes |
| Dry-run as early-exit skip | Cleaner logs, simpler implementation | Dry-run tests a different path than live mode; bugs invisible until live activation | Never; dry-run must exercise the full pipeline |
| Lease expiration as advisory (not enforced) | Lease TTL field already present, no new enforcement code needed | Expired leases authorize actions after the response window closes | Never; lease expiration is a security boundary |
| Generic `hunt_id: "pounce-{uuid}"` | Avoids substrate query in PounceAgent hot path | Breaks audit trail; operators cannot trace response actions to detections | Never; link to real escalation record |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| PounceAgent + `AgentRegistry` tick loop | PounceAgent ticked on every interval and re-triggers on persistent elevated mode | Track handled escalation IDs in PounceAgent state; only act on new transitions |
| TomAgent + `ApprovalGate` | TomAgent implemented as a pheromone-depositing agent that influences future PounceAgent ticks | TomAgent governs PounceAgent via a shared `Arc<GovernancePolicy>` called synchronously before execute |
| Configurable policy + `StaticApprovalGate` | New configurable gate is added alongside the static gate as a second parallel check | Replace `StaticApprovalGate` with the configurable gate; static rules become the starting config |
| De-escalation + `EscalationRecord` persistence | De-escalation transitions are not written to the substrate escalation history | Write a downward `EscalationRecord` with `mode: Normal` so the substrate history is complete |
| PounceAgent dry-run + `DispatchingExecutor` | Dry-run mode bypasses `DispatchingExecutor` entirely | Pass `ExecutionMode::DryRun` into `DispatchingExecutor::execute`; let the adapter handle it |
| Lease expiration + `ResponseExecutor` | `expires_at_ms` check lives only in `issue_lease`, not in `execute` | Add `if lease.expires_at_ms <= now_ms { return Err(expired) }` in `execute` before adapter dispatch |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| PounceAgent blocks on substrate query in tick hot path | Dispatcher tick intervals slip; agent marked `Degraded` under tick timeout (500ms default) | Use the shared `ArcSwap<SwarmModeState>` for mode reads; limit substrate queries to post-escalation not every tick | When substrate is `LocalJournal` or `JetStream` under I/O pressure |
| TomAgent governance policy evaluated on every PounceAgent action for every pheromone | Policy evaluation slows down the tick; governance overhead visible in metrics | Policy evaluation is a pure in-memory function; the substrate query is the expensive part — separate them | When configurable policy rules require substrate lookups (threat-class configs) |
| De-escalation check scans all threat classes on every monitor interval | Adds 12 substrate queries per interval (one per `ThreatClass`) even when no de-escalation is possible | Short-circuit: de-escalation only runs if `now_ms - last_escalation_at_ms >= cooldown_ms` | Under high tick frequency with journal backend |
| PounceAgent seen-set grows unbounded over long uptime | Memory grows with every new escalation record ID; never pruned | Bound the seen-set to the current mode session; clear it on de-escalation to `Normal` | After weeks of continuous high-mode operation |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Policy gate fails open on rule parse error | Malformed YAML policy config silently allows all actions through the gate | Validate all rules at config load; reject startup if any rule is malformed |
| Lease expiration not enforced at execution time | Expired leases authorize destructive actions after the response window closes | `ResponseExecutor` must check `expires_at_ms` before calling any adapter |
| TomAgent veto is advisory only (post-execution) | Destructive actions (isolate_host, revoke_credential) execute before governance can stop them | TomAgent veto must be a pre-execution synchronous gate, not a post-receipt annotation |
| PounceAgent ignores `live_mode: false` in `ApprovalContext` | Actions execute in `LiveResponse` mode even when operator intends dry-run | PounceAgent must check runtime mode from `SwarmModeState` and map `DetectOnly` to `ExecutionMode::DryRun` |
| Response receipts from PounceAgent not linked to escalation record | Audit trail cannot prove which detections justified each response action | PounceAgent populates `ActionRequest.evidence` with escalation record ID and relevant finding references |
| Configurable policy rule with wildcard action scope | A single misconfigured rule authorizes all action types for all severities | Policy rule validation must require explicit action type and severity range; reject wildcards that expand scope |

---

## "Looks Done But Isn't" Checklist

- [ ] **PounceAgent dry-run:** Dry-run receipts appear in operator status with `status: Simulated` — not just absent from live receipts
- [ ] **Lease expiration enforcement:** A test advances `now_ms` past `expires_at_ms` and asserts the executor returns an error, not a receipt
- [ ] **TomAgent veto before execute:** A vetoed action test asserts `ResponseExecutor::execute` was never called, not just that a veto record was written
- [ ] **De-escalation cooldown:** A burst-decay-burst test asserts the second burst does not produce a second response action within `deescalation_cooldown_ms`
- [ ] **Policy default-deny:** An empty ruleset test asserts verdict is `Deny`, not `Allow`
- [ ] **Audit trail linkage:** A PounceAgent receipt can be resolved via `replay_lookup` to the detection finding that originated the escalation
- [ ] **Mode de-escalation persisted:** The substrate `EscalationRecord` history includes downward transitions to `Normal`, not just upward escalations
- [ ] **PounceAgent idempotency:** Injecting the same escalation event twice produces exactly one receipt, not two

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| PounceAgent double-triggered live response | HIGH | Audit receipt history for duplicate `capability_id` prefixes; file incident review; add seen-set deduplication before re-enabling |
| Policy gate failed open on parse error | HIGH | Immediately switch to `StaticApprovalGate` fallback; fix rule YAML; verify all rules parse before re-enabling configurable gate |
| TomAgent veto arrived after destructive action | HIGH | Review audit receipts for unauthorized scope; add pre-execution governance gate; consider operator-initiated rollback for reversible actions |
| Mode oscillation produced repeated response actions | MEDIUM | Increase `deescalation_cooldown_ms`; review response receipts for duplicate actions within cooldown window; add cooldown enforcement before next deploy |
| Dry-run mode exercised different path than live | LOW | Refactor dry-run to pass through full pipeline with `ExecutionMode::DryRun`; re-run integration tests; compare receipt counts before re-enabling live mode |
| Audit trail lineage broken (receipts not linked) | LOW | Backfill receipt metadata from substrate escalation history; add linkage assertion to CI gate |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| TOCTOU on lease and mode (Pitfall 1) | Phase 1 — PounceAgent core | Test: advance clock past `lease_ttl_ms`; assert executor returns `Err` not receipt |
| Double-trigger idempotency (Pitfall 2) | Phase 1 — PounceAgent core | Test: inject same escalation twice; assert `execute()` called exactly once |
| TomAgent veto race (Pitfall 3) | Phase 3/4 — TomAgent governance | Test: veto active; assert `execute()` never called when veto returns `Err` |
| Policy fail-open on empty/parse-error ruleset (Pitfall 4) | Phase 2 — Configurable policy | Test: empty ruleset; assert verdict is `Deny` |
| Mode flapping without cooldown (Pitfall 5) | Phase 2/3 — De-escalation | Test: burst-decay-burst pattern; assert second response not fired within cooldown |
| Dry-run not structurally identical (Pitfall 6) | Phase 1 — PounceAgent core | Test: dry-run path; assert policy gate evaluated and receipt persisted with `Simulated` status |
| Audit lineage broken (Pitfall 7) | Phase 1 — PounceAgent core | Test: PounceAgent receipt; assert `replay_lookup` resolves to originating finding |

---

## Sources

- Code-grounded analysis of `crates/swarm-policy/src/static_gate.rs` — current lease semantics and gate logic
- Code-grounded analysis of `crates/swarm-runtime/src/escalation.rs` — current upward-only mode transition logic
- Code-grounded analysis of `crates/swarm-runtime/src/dispatcher.rs` — agent tick and registry model
- Code-grounded analysis of `crates/swarm-response/src/dispatch.rs` — executor dispatch and `ExecutionMode` handling
- [CVE-2025-59497: TOCTOU in Microsoft Defender for Endpoint on Linux](https://windowsforum.com/threads/cve-2025-59497-toctou-in-defender-for-endpoint-linux-patch-and-mitigate.384773/) — real-world TOCTOU in production EDR code
- [Idempotency and Reliability in Event-Driven Systems](https://dzone.com/articles/idempotency-and-reliability-in-event-driven-systems) — at-least-once delivery and idempotent consumer patterns
- [Understanding Fail Open and Fail Closed](https://authzed.com/blog/fail-open) — security gate default posture
- [Agentic Governance Architecture](https://arxiv.org/html/2603.07191v2) — governance pre-execution vs. post-hoc patterns
- [Async Rust TOCTOU and concurrency pitfalls 2025](https://rustsec.org/advisories/) — RustSec advisory context for async race conditions

---
*Pitfalls research for: v1.39 PounceAgent, Policy Gate Hardening, Mode De-escalation, TomAgent Governance*
*Researched: 2026-04-08*
