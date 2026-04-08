# Stack Research

**Domain:** Autonomous response agent, configurable policy gates, mode de-escalation, governance oversight
**Researched:** 2026-04-08
**Milestone:** v1.39 PounceAgent And Policy Gate Hardening
**Confidence:** HIGH — all findings are grounded in the existing codebase, workspace Cargo.toml, and Cargo.lock

---

## Scope

This research is scoped to **new or changed stack elements** for four features:

1. **PounceAgent** — autonomous response agent that consumes escalation pheromones and drives the guard-gated adapter pipeline
2. **Configurable policy rules** — YAML-driven verdict rules beyond the current hardcoded `StaticApprovalGate`
3. **Mode de-escalation** — downward `SwarmMode` transitions with cooldown enforcement
4. **TomAgent governance** — veto authority agent over PounceAgent actions

Existing capabilities (detection pipeline, pheromone substrate, guard pipeline, SIEM/webhook adapters, dispatcher, signing infrastructure) are already in the workspace and require no new crates.

---

## Recommended Stack

### Core Technologies — No New Crates Required

All four features can be built from crates already in the workspace. The analysis below confirms this by tracing each feature to its integration surface.

| Technology | Locked Version | Role in New Features |
|------------|---------------|----------------------|
| `tokio` | 1.51.0 | Async agent tick loop, timeout guards on PounceAgent tick, shutdown channel |
| `async-trait` | 0.47.0 | `SwarmAgent` impl for `PounceAgent` and `TomAgent` |
| `ed25519-dalek` | 2.2.3 | Agent signing keys for PounceAgent/TomAgent identity, receipt signing |
| `rand_core` | 0.6.x (workspace) | Signing key generation (`SigningKey::generate(&mut OsRng)`) |
| `serde` + `serde_json` | 1.0.228 / 1.0.149 | Policy rule config, veto records, de-escalation records |
| `serde_yaml` | 0.9.x (workspace) | YAML-driven policy rule config (already used for `SwarmConfig`) |
| `arc-swap` | 1.0.102 | Live policy rule reload without restart (mirrors existing config hot-reload pattern) |
| `thiserror` | 2.0.18 | Error types for new `PolicyRuleError`, `TomVetoError`, `DeescalationError` |
| `tracing` | 0.1.x (workspace) | Structured audit log for every veto, de-escalation, and policy verdict |
| `uuid` | 1.23.0 | Stable IDs for veto records, de-escalation records, response receipts |
| `chrono` | 0.4.44 | Timestamps on policy verdicts, de-escalation cooldown math |

### Supporting Libraries — Already in Workspace

| Library | Purpose in New Features | When It Is Needed |
|---------|------------------------|-------------------|
| `swarm-policy` | Extend `PolicyConfig`, add configurable rule evaluation, lease expiration enforcement | Phase 1 — configurable rules |
| `swarm-guard` | Pass `GuardAction::ResponseAction` through pipeline before PounceAgent executes | Phase 1 — PounceAgent's safety gate |
| `swarm-pheromone` | `PheromoneSubstrate::query_concentration` drives de-escalation checks; `EscalationRecord` storage | Phase 1 and 2 |
| `swarm-response` | `DispatchingExecutor::execute` is PounceAgent's final execution target; dry-run mode via `ExecutionMode::DryRun` | Phase 1 — PounceAgent |
| `swarm-core` | `SwarmAgent`, `SwarmEnvironment`, `SwarmMode`, `SwarmModeState`, `ResponseAction`, `AgentRole::Pouncer`, `AgentRole::Tom` | All phases — already typed |
| `swarm-runtime` | `AgentRegistry`, `AgentDispatcher`, `ConcentrationMonitor` — PounceAgent and TomAgent register here | All phases |
| `swarm-spine` | `ResponseReceipt`-linked `IncidentRecord` for audit trail linking detection lineage to response outcome | Phase 1 |

### Development Tools — No Changes

| Tool | Notes |
|------|-------|
| `cargo clippy -D warnings` | Existing lint gate, no change |
| `cargo test --workspace` | Integration tests follow existing pattern in `crates/swarm-runtime/tests/` |
| `cargo fmt --all` | Existing format gate |

---

## Feature-to-Stack Mapping

### PounceAgent

**What is needed:** A `struct PounceAgent` in `crates/swarm-runtime/src/pounce_agent.rs` implementing `SwarmAgent`. On each tick it:

1. Reads escalation pheromones from `SwarmEnvironment::pheromones`
2. Checks `SwarmEnvironment::current_mode()` — only acts in `Alert` or `Incident`
3. Calls `ApprovalGate::evaluate` (the configurable gate, see below) to get a `PolicyDecision`
4. If `Allow`, checks lease expiration via `CapabilityLease::expires_at_ms`
5. Passes `GuardAction::ResponseAction` through `GuardPipeline::evaluate`
6. Dispatches via `DispatchingExecutor::execute` — uses `ExecutionMode::DryRun` when dry-run mode is set
7. Emits a `ResponseReceipt` linked to the originating `hunt_id` for audit trail

**Integration points:**
- Registers in `AgentRegistry` alongside `WhiskerAgent`, `StalkerAgent`, `WeaverAgent` — no registry changes needed
- Dispatcher already handles `AgentRole::Pouncer` in `agent_role_label` — no dispatcher changes needed
- `SwarmAction::RequestResponse` exists on `SwarmAction` — PounceAgent can also emit this for TomAgent interception

**No new crates needed.** All required types (`ResponseAction`, `CapabilityLease`, `GuardPipeline`, `DispatchingExecutor`, `ResponseReceipt`) are already in the workspace.

### Configurable Policy Rules

**What is needed:** Replace the hardcoded `StaticApprovalGate` logic with a rule-based evaluator that reads from YAML config.

**Implementation approach:**
- Add `PolicyRuleConfig` to `swarm-core/src/config.rs` — a `Vec<PolicyRule>` inside `PolicyConfig`
- Each `PolicyRule` has: `action_kind: String`, `min_severity: Severity`, `verdict: PolicyVerdict`, `require_human_above: Option<Severity>`
- Add `ConfigurableApprovalGate` to `swarm-policy/src/` that implements `ApprovalGate` by evaluating rules in order, with fail-closed defaults matching the existing `StaticApprovalGate` behavior
- `arc-swap` wraps the loaded gate so live config reload works without locking the tick path

**No new crates needed.** `serde_yaml` already handles YAML deserialization in `SwarmConfig`. The `arc-swap` pattern for hot-reload is already established in the dispatcher.

### Policy Audit Trail

**What is needed:** Every `PolicyDecision` verdict (Allow, Deny, RequireHuman) must produce a durable audit record.

**Implementation approach:**
- Add `PolicyAuditRecord` struct to `swarm-policy` with: `decision_id: String`, `action: String`, `severity: String`, `verdict: PolicyVerdict`, `reason: String`, `rule_matched: Option<String>`, `timestamp_ms: i64`
- Append records to a newline-JSON journal (same pattern as `DeadLetterJournal`) — no new persistence mechanism needed
- `uuid` and `chrono` (already workspace dependencies) handle IDs and timestamps

**No new crates needed.**

### Lease Expiration Enforcement

**What is needed:** `CapabilityLease::expires_at_ms` must be checked before dispatch, and expired leases must fail closed.

**Implementation approach:**
- `PounceAgent::tick` checks `now_ms > lease.expires_at_ms` before calling `DispatchingExecutor::execute`
- Expired lease emits `SwarmAction::HealthReport { status: AgentHealth::Degraded }` and skips execution
- All wall-clock reads use `SystemTime::now()` (already used throughout the runtime)

**No new crates needed.**

### Mode De-escalation

**What is needed:** `ConcentrationMonitor` currently only escalates upward (`transition_to` returns false if `mode <= self.current`). De-escalation adds a downward path.

**What must change:**
- `SwarmModeState` gains two new fields: `deescalation_cooldown_secs: u64` (from config) and `last_deescalation_at: Option<i64>`
- `PolicyConfig` (in `swarm-core/src/config.rs`) gains `deescalation_cooldown_secs: u64` (default: 300)
- `ConcentrationMonitor::evaluate_all` checks whether ALL active threat classes have concentration below their alert threshold — if so and cooldown has elapsed, it calls a new `try_deescalate` method
- De-escalation records are persisted as `EscalationRecord` variants (extend the existing enum or add a `DeescalationRecord` parallel type)

**No new crates needed.** The entire de-escalation mechanism is a logic extension to existing types in `swarm-core` and `swarm-runtime`.

### TomAgent Governance

**What is needed:** A `struct TomAgent` in `crates/swarm-runtime/src/tom_agent.rs` implementing `SwarmAgent`. TomAgent exercises veto authority over PounceAgent actions.

**Implementation approach — veto channel:**
- Add `tokio::sync::mpsc` channel pair (already used in `WhiskerAgent` for telemetry events) between PounceAgent's action emission and dispatch
- PounceAgent places a proposed `ActionRequest` on a `pending_actions: mpsc::Sender<PendingAction>` channel instead of dispatching directly for high-severity actions
- TomAgent holds the `mpsc::Receiver<PendingAction>` and evaluates each pending action in its tick
- TomAgent emits a `TomVerdict::Approve` or `TomVerdict::Veto` back via a `oneshot::Sender` embedded in `PendingAction`
- PounceAgent awaits the `oneshot::Receiver` within its tick timeout budget, then proceeds or aborts

**TomAgent policy:**
- TomAgent reads a separate `GovernanceConfig` section in `SwarmConfig` — same YAML deserialization
- Configurable thresholds: `veto_on_severity: Severity` (default: `High`), `veto_destructive_in_normal_mode: bool`, `max_pending_actions: usize`
- TomAgent vetoes emit `TomVetoRecord` with stable ID, agent ID, action kind, reason, timestamp — persisted to audit journal

**Async channel type:** `tokio::sync::oneshot` (already available via `tokio = { version = "1", features = ["full"] }` workspace dependency)

**No new crates needed.** `tokio::sync::mpsc` and `tokio::sync::oneshot` are available via the existing workspace tokio dependency.

---

## Installation

No new dependencies are required. All stack additions for v1.39 are internal-crate changes and reuse of existing workspace dependencies.

```toml
# crates/swarm-runtime/Cargo.toml — verify swarm-guard is listed
swarm-guard.workspace = true

# No other Cargo.toml changes required
```

Verify `swarm-guard` is in `crates/swarm-runtime/Cargo.toml` before PounceAgent calls `GuardPipeline::evaluate`. All other required crates (`swarm-policy`, `swarm-response`, `swarm-pheromone`, `swarm-core`, `swarm-spine`) are already listed in the runtime's Cargo.toml.

---

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Extend `swarm-policy` with `ConfigurableApprovalGate` | New `swarm-policy-rules` crate | Only if rule evaluation logic grows beyond ~500 lines and demands independent testing. Not warranted at v1.39 scale. |
| `tokio::sync::mpsc` + `oneshot` for veto channel | Shared `Mutex<Vec<PendingAction>>` | Mutex is simpler if tick timing is not critical. Prefer channel because it avoids holding a lock across `.await` and matches existing WhiskerAgent pattern. |
| Extend `EscalationRecord` for de-escalation | Separate `DeescalationRecord` type | Separate type is cleaner if de-escalation records need different fields (e.g., `previous_mode`, `cooldown_elapsed`). Either works; prefer extending to avoid changing substrate method signatures. |
| Append-only JSONL audit journal for policy verdicts | Full SQLite or database | Database adds a dependency and operational complexity. JSONL is the proven pattern in `DeadLetterJournal` and is adequate for single-node audit use. |

---

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| New async runtime or executor | Mixing executors (e.g., adding `smol` or `async-std`) causes subtle deadlocks with existing `tokio`-based code | `tokio` (already workspace) |
| `std::sync::Mutex` across `.await` points | Holding a blocking mutex across an async yield point deadlocks the tokio executor | `tokio::sync::Mutex` where async hold is required; prefer field ownership and message passing |
| External rule engine (Rego/CEL) | Requires external process or unsafe FFI; policy rules in this domain are narrow enough for hand-rolled struct evaluation | `ConfigurableApprovalGate` with ordered `Vec<PolicyRule>` |
| Distributed consensus for TomAgent veto | Explicitly out of scope per PROJECT.md; single-node constraint is permanent until independent trust boundaries exist | In-process `oneshot` channel with configurable severity threshold |
| Python runtime expansion or PyO3 | Explicitly out of scope per CLAUDE.md and PROJECT.md | Pure Rust throughout |
| `parking_lot` | Absent from workspace; provides no benefit over `tokio::sync` or `std::sync` for this use case | `tokio::sync::RwLock` or `std::sync::RwLock` |

---

## Integration Points for Each New Component

```
PounceAgent tick:
  SwarmEnvironment.pheromones
    -> filter escalation pheromones (mode >= Alert)
    -> ConfigurableApprovalGate.evaluate(ActionRequest, ApprovalContext)
       -> PolicyAuditRecord (appended to journal)
    -> CapabilityLease expiry check (chrono/now_ms)
    -> [conditional] TomAgent veto channel (tokio::sync::oneshot)
    -> GuardPipeline.evaluate(GuardAction::ResponseAction)
    -> DispatchingExecutor.execute (DryRun or Enforced)
    -> ResponseReceipt (linked to hunt_id)

TomAgent tick:
  mpsc::Receiver<PendingAction>
    -> GovernanceConfig evaluation
    -> TomVetoRecord (appended to audit journal) on veto
    -> oneshot reply (Approve or Veto) to PounceAgent

ConcentrationMonitor.evaluate_all:
  (existing escalation path, unchanged)
  + try_deescalate:
    -> check all threat classes below alert threshold
    -> check deescalation_cooldown_secs elapsed since last_transition_at
    -> SwarmModeState.transition_down (new method, symmetric to transition_to)
    -> EscalationRecord or DeescalationRecord persisted to substrate

ConfigurableApprovalGate (swarm-policy):
  arc-swap<PolicyRuleSet>
    -> evaluate rules in order
    -> first matching rule wins
    -> fail-closed default: Deny if no rule matches and action is destructive
```

---

## Crate Responsibility After v1.39

| Crate | Changes for v1.39 |
|-------|------------------|
| `swarm-core` | Add `PolicyRuleConfig`, `deescalation_cooldown_secs` to `PolicyConfig`; add `GovernanceConfig` to `SwarmConfig`; extend `SwarmModeState` with de-escalation fields |
| `swarm-policy` | Add `ConfigurableApprovalGate`, `PolicyAuditRecord`, `PolicyRuleSet`; keep `StaticApprovalGate` as fallback/reference |
| `swarm-runtime` | Add `pounce_agent.rs`, `tom_agent.rs`; extend `ConcentrationMonitor` with `try_deescalate`; register Pouncer and Tom in `AgentRegistry` wiring |
| `swarm-pheromone` | No changes needed unless `DeescalationRecord` requires a new substrate query method |
| `swarm-response` | No changes needed — `DispatchingExecutor` and `ExecutionMode` already support dry-run |
| `swarm-guard` | No changes needed — `GuardPipeline` and `GuardAction::ResponseAction` already exist |
| `swarm-spine` | No changes needed — existing `ReplayBundle` and `IncidentRecord` can carry response receipts |

---

## Sources

- `crates/swarm-core/src/agent.rs` — `SwarmAgent`, `SwarmMode`, `AgentRole::Pouncer`, `AgentRole::Tom` already defined (HIGH confidence)
- `crates/swarm-core/src/config.rs` — `PolicyConfig` has only `human_gate_severity` and `lease_ttl_ms`; no rule list yet (HIGH confidence)
- `crates/swarm-policy/src/lib.rs` + `static_gate.rs` — `ApprovalGate` trait and hardcoded `StaticApprovalGate`; configurable variant is absent (HIGH confidence)
- `crates/swarm-guard/src/lib.rs` — `GuardPipeline`, `GuardAction::ResponseAction` confirmed present (HIGH confidence)
- `crates/swarm-response/src/lib.rs` + `dispatch.rs` — `DispatchingExecutor`, `ExecutionMode::DryRun`, `ResponseReceipt` confirmed present (HIGH confidence)
- `crates/swarm-runtime/src/escalation.rs` — `ConcentrationMonitor` escalation-only path confirmed; de-escalation gap confirmed (HIGH confidence)
- `crates/swarm-runtime/src/dispatcher.rs` — role labels include `Pouncer` and `Tom` already; no agent structs for those roles yet (HIGH confidence)
- `crates/swarm-runtime/src/whisker_agent.rs` + `weaver_agent.rs` — reference patterns for new agent structs (HIGH confidence)
- `Cargo.toml` (workspace) — authoritative version bounds for all dependencies (HIGH confidence)
- `Cargo.lock` — locked versions: tokio 1.51.0, ed25519-dalek 2.2.3, arc-swap 1.0.102, uuid 1.23.0, chrono 0.4.44, serde 1.0.228, serde_json 1.0.149, thiserror 2.0.18 (HIGH confidence)

---
*Stack research for: v1.39 PounceAgent And Policy Gate Hardening*
*Researched: 2026-04-08*
