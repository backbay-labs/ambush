# Architecture Research

**Domain:** Rust autonomous threat detection and response runtime — v1.39 PounceAgent and policy gate hardening
**Researched:** 2026-04-08
**Confidence:** HIGH (primary sources are the live codebase)

## Standard Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Telemetry Ingest Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │
│  │TetragonBridge│  │CloudTrailBridge│ │GenericJsonBridge│               │
│  └──────┬───────┘  └──────┬───────┘  └──────┬────────┘                 │
│         └─────────────────┴─────────────────┘                           │
│                     BridgeRuntimeRegistry                                │
│                       mpsc::Sender<TelemetryEvent>                       │
├─────────────────────────────────────────────────────────────────────────┤
│                        Agent Dispatcher Layer                             │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                       AgentDispatcher                               │ │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ ┌──────┐ │ │
│  │  │ Whisker  │  │ Stalker  │  │ Weaver   │  │ Pounce   │ │ Tom  │ │ │
│  │  │ Agent    │  │ Agent    │  │ Agent    │  │ Agent    │ │ Agent│ │ │
│  │  │ (exists) │  │ (exists) │  │ (exists) │  │ [NEW]    │ │[NEW] │ │ │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘ └──┬───┘ │ │
│  │       └─────────────┴─────────────┴──────────────┘          │     │ │
│  │                 SwarmAction → apply_actions() [MODIFIED]     │     │ │
│  └──────────────────────────┬──────────────────────────────────┘     │ │
│               RequestResponse routed to ResponseRouter [NEW]           │ │
├──────────────────────────────┼──────────────────────────────────────────┤
│                              ▼                                           │
│                 SwarmRuntime::authorize_and_execute()                    │
│  ┌───────────────────────────────┐  ┌────────────────────────────────┐  │
│  │ ApprovalGate                  │  │ GuardPipeline                  │  │
│  │  StaticApprovalGate (exists)  │  │  rate-limit guard [NEW]        │  │
│  │  ConfigurableApprovalGate [NEW]│  └────────────────────────────────┘  │
│  │  lease expiry check [NEW]     │                                       │
│  └───────────────────────────────┘                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                        Escalation and Mode Layer                          │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │ ConcentrationMonitor                                               │  │
│  │  evaluate_all() → EscalationOutcome (upward transitions, exists)  │  │
│  │  transition_down() when pressure drops + cooldown elapsed [NEW]   │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│  Arc<ArcSwap<SwarmModeState>> ──── shared with AgentDispatcher          │
├─────────────────────────────────────────────────────────────────────────┤
│                        Substrate Layer (exists, unchanged)               │
│  ┌──────────────────┐  ┌───────────────────┐  ┌───────────────────────┐ │
│  │ InMemory         │  │ LocalJournal       │  │ JetStream             │ │
│  │ PheromoneSubstrate│ │ PheromoneSubstrate │  │ PheromoneSubstrate    │ │
│  └──────────────────┘  └───────────────────┘  └───────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities (Current State)

| Component | Crate | Responsibility | v1.39 Status |
|-----------|-------|----------------|--------------|
| `WhiskerAgent` | swarm-runtime | Drain telemetry channel, run CompositeDetector, deposit signed pheromones | Unchanged |
| `StalkerAgent` | swarm-runtime | Claim Whisker pheromones, run investigation coordinator, publish investigation pheromones | Unchanged |
| `WeaverAgent` | swarm-runtime | Consume investigation pheromones, assemble CorrelatedIncident | Unchanged |
| `AgentDispatcher` | swarm-runtime | Tick all agents, collect actions, apply role shifts and health reports | Modified: route `RequestResponse` actions to `ResponseRouter` |
| `ConcentrationMonitor` | swarm-runtime | Query substrate concentrations, drive upward mode transitions | Modified: add downward transition + cooldown |
| `SwarmRuntime` | swarm-runtime | Evaluate policy, guard pipeline, execute response adapter, produce audit trail | Modified: add lease expiry check |
| `StaticApprovalGate` | swarm-policy | Hardcoded severity/action rules, human gate, lease issuance | Modified: add rate limiter per scope |
| `GuardPipeline` | swarm-guard | Pre-execution guard chain evaluation | Existing; used as-is |
| `SwarmModeState` | swarm-core | Current mode, last transition timestamp, triggering threat class | Modified: add `transition_down()` |
| `PheromoneSubstrate` | swarm-pheromone | Deposits, concentration queries, GC, escalation records | Unchanged |

### New Components for v1.39

| Component | Crate | File | Responsibility |
|-----------|-------|------|----------------|
| `PounceAgent` | swarm-runtime | `src/pounce_agent.rs` | Implements `SwarmAgent` with `AgentRole::Pouncer`; reads `SwarmEnvironment.mode` and `pheromones`; emits `SwarmAction::RequestResponse` for Alert/Incident modes; skips when peer findings show same target scope |
| `TomAgent` | swarm-runtime | `src/tom_agent.rs` | Implements `SwarmAgent` with `AgentRole::Tom`; monitors agent health via shared health snapshot; emits `RoleShift` for degraded agents; emits `HealthReport { status: Failed }` for agents degraded beyond configurable tick threshold |
| `ResponsePlaybookConfig` | swarm-core | `src/config.rs` (new field in `SwarmConfig`) | Maps `(ThreatClass, Severity, confidence_range)` tuples to ordered `ResponseAction` sequences with per-step `escalation_timeout_secs` |
| `ConfigurableApprovalGate` | swarm-policy | `src/configurable_gate.rs` | Implements `ApprovalGate`; loads YAML rules for allow/deny by threat class, severity, time-of-day, per-agent rate limits; chains to `StaticApprovalGate` for invariant enforcement |
| `ResponseRouter` trait | swarm-runtime | `src/dispatcher.rs` | Decouples `AgentDispatcher` from `SwarmRuntime<P, E>` generic params; allows async routing of `RequestResponse` actions |

## Recommended Project Structure

```
crates/
├── swarm-core/
│   └── src/
│       ├── agent.rs           # SwarmModeState: add transition_down()
│       └── config.rs          # SwarmConfig: add response_playbook field
│                              # PheromoneConfig: add deescalation_cooldown_secs
├── swarm-policy/
│   └── src/
│       ├── lib.rs             # ApprovalGate trait: unchanged
│       ├── static_gate.rs     # StaticApprovalGate: add per-scope rate limiter
│       └── configurable_gate.rs  # NEW: ConfigurableApprovalGate from YAML rules
├── swarm-runtime/
│   └── src/
│       ├── pounce_agent.rs    # NEW: PounceAgent
│       ├── tom_agent.rs       # NEW: TomAgent
│       ├── escalation.rs      # ConcentrationMonitor: add transition_down + cooldown
│       ├── dispatcher.rs      # apply_actions: route RequestResponse; add ResponseRouter
│       └── lib.rs             # SwarmRuntime: validate lease expiry before execution
└── rulesets/
    └── default.yaml           # Add response_playbook and configurable_policy sections
```

### Structure Rationale

- **`pounce_agent.rs` / `tom_agent.rs` alongside `stalker_agent.rs`:** Every agent role has its own file under swarm-runtime/src. Consistent with established convention.
- **`configurable_gate.rs` in swarm-policy:** The `ApprovalGate` trait and `StaticApprovalGate` already live there. The configurable implementation is the same abstraction, same crate, no new dependency edge.
- **`transition_down()` on `SwarmModeState` in swarm-core:** Mode state is a core domain type. De-escalation is the symmetric operation to `transition_to()` and belongs beside it, not in the runtime escalation module.
- **`ResponsePlaybookConfig` in swarm-core config:** Consistent with `PheromoneConfig`, `PolicyConfig`, etc. Config is a core contract, not a runtime implementation detail.

## Architectural Patterns

### Pattern 1: Agent-Direct vs Dispatcher-Routed Actions

**What:** `SwarmAction` variants split into two behavioral categories. Agent-direct actions (`DepositPheromone`, `ClaimInvestigation`) are executed by the agent inside its own `tick()` call against resources the agent already holds. Dispatcher-routed actions (`RoleShift`, `HealthReport`) are collected after all ticks complete and processed by the dispatcher against shared dispatcher state.

**The current gap:** `SwarmAction::RequestResponse` is currently marked with a comment "agent-direct: the response executor pipeline handles these" but is a no-op in `apply_actions()`. In practice, it cannot be truly agent-direct because `PounceAgent` needs `SwarmRuntime<P, E>` to call `authorize_and_execute()`, but agents only hold substrate and store references. The dispatcher must own a routing handle.

**Resolution:** Make `AgentDispatcher` hold a `ResponseRouter` trait object. Route `RequestResponse` through it in `apply_actions()`. `tick_agents()` and `apply_actions()` become async. `PounceAgent` never imports `SwarmRuntime`.

**Trade-offs:** Async `apply_actions()` means the dispatcher tick loop awaits response routing. Mitigate by spawning response executions as Tokio tasks bounded by the existing `max_in_flight_actions` semaphore in `DispatchingExecutor`, rather than awaiting them inline.

### Pattern 2: Shared Mode State via Arc<ArcSwap>

**What:** `ConcentrationMonitor` owns `SwarmModeState` and writes it to an `Arc<ArcSwap<SwarmModeState>>`. `AgentDispatcher` loads from the same cell each tick without locking.

**Current behavior:** `transition_to()` is monotonic — it ignores calls where the target mode is `<=` current. Correct for escalation. De-escalation requires a separate `transition_down()` method with different semantics (downward movement, different timestamp meaning, clearing `triggering_threat_class`).

**De-escalation design:** `ConcentrationMonitor::evaluate_all()` tracks a `last_below_threshold_at: HashMap<ThreatClass, i64>` for all threat classes currently at or above alert level. De-escalation fires only when `(now - last_below_threshold_at[class]) >= deescalation_cooldown_secs` across all active classes. This prevents flapping under borderline concentrations.

### Pattern 3: Policy Gate Composition

**What:** `SwarmRuntime::authorize_and_execute()` chains three concerns: `ApprovalGate::evaluate()`, `GuardPipeline::evaluate()`, `ResponseExecutor::execute()`. Each is a distinct trait boundary.

**Lease expiry gap (POLICY-01):** `CapabilityLease.expires_at_ms` exists but `authorize_and_execute()` never checks it against `ApprovalContext::now_ms`. The check belongs at the start of `authorize_and_execute()` after `issue_lease()` returns, before handing the lease to the executor.

**ConfigurableApprovalGate composition:** Chain, do not replace. `ConfigurableApprovalGate` evaluates its YAML rules. If no rule matches the request, it delegates to `StaticApprovalGate` for invariant enforcement (null evidence, empty targets). The static invariants are not configurable.

### Pattern 4: TomAgent as Read-Only Health Observer

**What:** `TomAgent` implements `SwarmAgent` with `AgentRole::Tom`. It needs access to the health of other agents, which is maintained by the dispatcher as `Arc<ArcSwap<Vec<AgentHealthEntry>>>`. Give `TomAgent` a clone of this handle at construction.

**Tick behavior:** Each tick, `TomAgent` loads the health snapshot, tracks consecutive-degraded counts in `HashMap<AgentId, u32>` in its own state, and emits appropriate `SwarmAction`s. The dispatcher processes those actions in the same `apply_actions()` pass as any other agent.

**Ownership boundary:** TomAgent observes health from the previous tick (the snapshot is refreshed before agents tick via `refresh_health_snapshot()`). This one-tick lag is acceptable for governance oversight — governance does not need sub-tick latency.

## Data Flow

### v1.39 Response Loop (new path)

```
TelemetryEvent
    → WhiskerAgent::tick()
        → detect_and_deposit() → PheromoneSubstrate::deposit() [exists]
        → SwarmAction::DepositPheromone (AgentFinding for peer visibility)
    ↓
ConcentrationMonitor::evaluate_all() [runs in parallel task]
    → substrate.query_concentration()
    → if threshold crossed: SwarmModeState::transition_to() → Arc<ArcSwap>.store()
    ↓
PounceAgent::tick() [receives SwarmEnvironment with mode=Alert|Incident]
    → reads env.pheromones → select ResponseAction from ResponsePlaybookConfig
    → check env.peer_findings for same target scope → skip if duplicate
    → return SwarmAction::RequestResponse { hunt_id, action, evidence }
    ↓
AgentDispatcher::apply_actions() [MODIFIED]
    → ResponseRouter::route(agent_id, RequestResponse action)
    ↓
SwarmRuntime::authorize_and_execute()
    → ApprovalGate::evaluate() → PolicyDecision
    → validate lease.expires_at_ms > context.now_ms [NEW]
    → GuardPipeline::evaluate()
    → ApprovalGate::issue_lease()
    → ResponseExecutor::execute() → ResponseReceipt
    → AuditTrail persisted [exists]
```

### De-escalation Flow (new)

```
ConcentrationMonitor::evaluate_all() [every interval]
    → query_concentration() for each ThreatClass
    → for each class below alert_threshold:
        last_below_threshold_at[class] = now
    → if all active threat classes have been below threshold
      for >= deescalation_cooldown_secs:
        SwarmModeState::transition_down(Normal, now)
        Arc<ArcSwap<SwarmModeState>>.store()
    → agents see new mode on next tick
```

### TomAgent Governance Flow (new)

```
TomAgent::tick()
    → load Arc<ArcSwap<Vec<AgentHealthEntry>>>.load()
    → for each AgentHealthEntry:
        if health == Degraded:
            degraded_ticks[agent_id] += 1
            if degraded_ticks[agent_id] < failed_threshold:
                emit SwarmAction::RoleShift { new_role }
            else:
                emit SwarmAction::HealthReport { status: Failed }
        else:
            degraded_ticks.remove(agent_id)
    → actions collected by dispatcher and applied in apply_actions()
```

## Integration Points

### New vs Modified — Explicit Breakdown

| Component | Status | Touch Points |
|-----------|--------|--------------|
| `PounceAgent` | New: `swarm-runtime/src/pounce_agent.rs` | Registered in `AgentDispatcher` at serve-mode startup; reads `ResponsePlaybookConfig` at construction; emits `RequestResponse` |
| `TomAgent` | New: `swarm-runtime/src/tom_agent.rs` | Registered in `AgentDispatcher`; receives `Arc<ArcSwap<Vec<AgentHealthEntry>>>` at construction |
| `ResponsePlaybookConfig` | New field in `SwarmConfig` in `swarm-core/src/config.rs` | `serde(default)`; passed to `PounceAgent` at construction; new YAML section in `rulesets/default.yaml` |
| `ConfigurableApprovalGate` | New: `swarm-policy/src/configurable_gate.rs` | Implements `ApprovalGate`; composed with `StaticApprovalGate` as fallback; new `configurable_policy` section in `SwarmConfig` |
| `SwarmModeState::transition_down()` | Modified: `swarm-core/src/agent.rs` | Symmetric to `transition_to()`; updates `current`, `last_transition_at`, clears `triggering_threat_class`; only descends when target < current |
| `PheromoneConfig` | Modified: `swarm-core/src/config.rs` | Add `deescalation_cooldown_secs: f64` with `serde(default = "default_deescalation_cooldown_secs")`; default 300.0 |
| `ConcentrationMonitor::evaluate_all()` | Modified: `swarm-runtime/src/escalation.rs` | Add `last_below_threshold_at: HashMap<ThreatClass, i64>` field; add downward transition check |
| `AgentDispatcher::apply_actions()` | Modified: `swarm-runtime/src/dispatcher.rs` | Route `RequestResponse` to `ResponseRouter`; `apply_actions` and `tick_agents` become async |
| `AgentDispatcher` struct | Modified: `swarm-runtime/src/dispatcher.rs` | Add `response_router: Option<Arc<dyn ResponseRouter>>` field; add `with_response_router()` builder method |
| `SwarmRuntime::authorize_and_execute()` | Modified: `swarm-runtime/src/lib.rs` | Add lease expiry validation: `if lease.expires_at_ms <= context.now_ms { return Err(ApprovalError::Denied("capability lease expired")) }` |
| `StaticApprovalGate` | Modified: `swarm-policy/src/static_gate.rs` | Add `max_actions_per_scope_per_minute` field; add `HashMap<String, VecDeque<i64>>` rate tracker; validate in `evaluate()` |
| serve-mode startup | Modified: `swarm-runtime/src/ingest.rs` | Register `PounceAgent` and `TomAgent` in `AgentDispatcher`; wire `ResponseRouter` to `SwarmRuntime` |

### Crate Dependency Graph (no new crates needed)

```
swarm-core  (SwarmModeState, SwarmConfig, ResponsePlaybookConfig, PheromoneConfig)
    ↑
swarm-policy  (ApprovalGate, StaticApprovalGate, ConfigurableApprovalGate)
    ↑
swarm-pheromone  (substrate backends, unchanged)
    ↑
swarm-guard  (GuardPipeline, unchanged)
    ↑
swarm-response  (ResponseExecutor, adapters, unchanged)
    ↑
swarm-runtime  (PounceAgent, TomAgent, ConcentrationMonitor, AgentDispatcher, SwarmRuntime)
```

All new components live in existing crates. No new crate boundary is needed for v1.39.

### Internal Boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| `PounceAgent` → `AgentDispatcher` | `SwarmAction::RequestResponse` return value | No direct runtime reference in agent |
| `AgentDispatcher` → `SwarmRuntime` | `ResponseRouter` trait object (`Arc<dyn ResponseRouter>`) | Avoids exposing `SwarmRuntime<P, E>` generics in dispatcher signature |
| `ConcentrationMonitor` → `AgentDispatcher` | `Arc<ArcSwap<SwarmModeState>>` | Already exists; no new channel needed |
| `TomAgent` ← `AgentDispatcher` | `Arc<ArcSwap<Vec<AgentHealthEntry>>>` | Dispatcher already maintains this; clone the Arc at construction |
| `ConfigurableApprovalGate` → `StaticApprovalGate` | Direct delegation call (composition) | Configurable gate holds an instance of static gate as fallback |

## Build Order

Based on component dependencies, the correct build sequence within v1.39 is:

1. **`SwarmModeState::transition_down()`** (swarm-core) — No deps on any new component. Unblocks escalation changes.

2. **`PheromoneConfig::deescalation_cooldown_secs`** (swarm-core) — Config field addition. Can land with step 1.

3. **`ResponsePlaybookConfig`** (swarm-core) — New config type. Independent of runtime changes. `serde(default)` so existing configs remain valid.

4. **`ConcentrationMonitor` de-escalation** (swarm-runtime/escalation.rs) — Requires step 1 and 2. Add cooldown tracking, call `transition_down()`.

5. **`StaticApprovalGate` rate limiter** (swarm-policy) — Independent of all above. Add in-memory rate tracking, enforce in `evaluate()`.

6. **`ConfigurableApprovalGate`** (swarm-policy) — Requires `ApprovalGate` trait and `StaticApprovalGate` (step 5). New file in swarm-policy.

7. **`SwarmRuntime` lease expiry** (swarm-runtime/lib.rs) — Independent addition. One comparison in `authorize_and_execute()`.

8. **`ResponseRouter` trait + `AgentDispatcher` routing** (swarm-runtime/dispatcher.rs) — Requires step 7. Make `apply_actions` async, add trait, add optional router field.

9. **`PounceAgent`** (swarm-runtime/pounce_agent.rs) — Requires steps 3, 8. Reads playbook config, emits `RequestResponse`.

10. **`TomAgent`** (swarm-runtime/tom_agent.rs) — Requires step 8 (async dispatcher). Reads health snapshot, emits governance actions.

11. **Serve-mode wiring** (swarm-runtime/ingest.rs) — Requires steps 6, 9, 10. Register both new agents, wire `ResponseRouter`.

12. **Integration tests** — Require all above. Prove full response loop from escalation pheromone to executed response receipt; prove de-escalation cooldown; prove TomAgent emitting role shifts.

## Scaling Considerations

This is a single-node runtime. Scaling concerns are throughput and safety, not distribution.

| Concern | After v1.39 |
|---------|-------------|
| Async `apply_actions()` | Spawns response tasks rather than awaiting inline; bounded by `max_in_flight_actions` semaphore already in `DispatchingExecutor` |
| Rate limiting memory | `StaticApprovalGate` rate tracker grows with unique target scopes; GC old entries older than 60s on each `evaluate()` call |
| De-escalation stability | `deescalation_cooldown_secs` prevents flapping; default 300s is conservative |
| TomAgent overhead | Loads `Arc::load()` clone each tick — O(n_agents), negligible |

## Anti-Patterns

### Anti-Pattern 1: PounceAgent Holding a SwarmRuntime Reference

**What people do:** Give `PounceAgent` a `Arc<SwarmRuntime<P, E>>` and call `authorize_and_execute()` inside `tick()`.

**Why it's wrong:** `SwarmAgent::tick()` is `&mut self` async. Giving each agent a typed handle to `SwarmRuntime` leaks the `<P, E>` generic parameters into every agent. The `AgentDispatcher` already has a composition role; duplicating it in agents creates double-ownership and makes testing significantly harder (every agent test needs a full runtime stub).

**Do this instead:** `PounceAgent::tick()` returns `SwarmAction::RequestResponse`. The dispatcher owns the `ResponseRouter` and calls it after all ticks complete. `PounceAgent` has zero knowledge of the policy or executor types.

### Anti-Pattern 2: De-escalation Without Cooldown

**What people do:** Call `transition_down()` in `evaluate_all()` immediately when concentrations are below threshold.

**Why it's wrong:** Pheromone concentrations fluctuate around thresholds under noisy traffic. Without cooldown, the runtime oscillates between Alert and Normal on consecutive ticks, generating meaningless escalation audit records and confusing operators watching the mode timeline.

**Do this instead:** Track `last_below_threshold_at` per threat class. De-escalate only after all relevant threat classes have stayed below threshold continuously for `deescalation_cooldown_secs`.

### Anti-Pattern 3: ConfigurableApprovalGate Replacing StaticApprovalGate Entirely

**What people do:** Swap out `StaticApprovalGate` for `ConfigurableApprovalGate` to enable YAML-driven policy.

**Why it's wrong:** `StaticApprovalGate` contains hardened invariants (null evidence rejection, empty target rejection) that must never be defeatable by config. If the YAML file is misconfigured or missing, the runtime must not fall into an open state.

**Do this instead:** Compose them. `ConfigurableApprovalGate` evaluates its YAML rules first. If no rule matches, it delegates to `StaticApprovalGate`. The static gate's invariants remain load-bearing regardless of what the YAML says.

### Anti-Pattern 4: Blocking the Dispatcher Tick on Response Execution

**What people do:** Await each `ResponseRouter::route()` call inline inside `apply_actions()` before proceeding to the next action.

**Why it's wrong:** HTTP EDR and webhook adapters are network-bound. Blocking the dispatcher loop on each response execution stalls all agents, breaks the bounded-tick guarantee, and risks cascading into `agent_tick_timeout_ms` violations on the next cycle.

**Do this instead:** Spawn response executions as background Tokio tasks from `apply_actions()`. Bound concurrency using the `max_in_flight_actions` semaphore that `DispatchingExecutor` already manages. The dispatcher does not await receipts inline; audit trails are written by the spawned task.

## Sources

- `crates/swarm-core/src/agent.rs` — `SwarmAgent`, `SwarmModeState`, `SwarmEnvironment`, `AgentRole`
- `crates/swarm-core/src/types.rs` — `SwarmAction`, `ResponseAction`
- `crates/swarm-core/src/config.rs` — `SwarmConfig`, `PheromoneConfig`, `PolicyConfig`
- `crates/swarm-policy/src/lib.rs` — `ApprovalGate`, `ActionRequest`, `CapabilityLease`
- `crates/swarm-policy/src/static_gate.rs` — `StaticApprovalGate` implementation
- `crates/swarm-runtime/src/lib.rs` — `SwarmRuntime::authorize_and_execute()`
- `crates/swarm-runtime/src/dispatcher.rs` — `AgentDispatcher`, `apply_actions()`, current `RequestResponse` no-op
- `crates/swarm-runtime/src/escalation.rs` — `ConcentrationMonitor`, current escalation-only logic
- `crates/swarm-runtime/src/whisker_agent.rs` — Reference agent implementation pattern
- `crates/swarm-runtime/src/stalker_agent.rs` — Reference agent implementation pattern
- `.planning/REQUIREMENTS.md` — v1.39 requirements: POUNCE-01..04, POLICY-01..03, DEESC-01..02, TOM-01

---
*Architecture research for: v1.39 PounceAgent, policy gate hardening, mode de-escalation, TomAgent governance*
*Researched: 2026-04-08*
