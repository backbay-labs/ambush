# Phase 124: PounceAgent Core And De-escalation - Research

**Researched:** 2026-04-08
**Domain:** `swarm-runtime` autonomous response routing, lease enforcement, and mode de-escalation
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
### Triggering And Idempotency
- `PounceAgent` reacts to new elevated-mode sessions and escalation context, not raw repeated pheromone scans alone; the design must prevent repeated execution while the runtime remains in the same alert or incident posture.
- Duplicate suppression is mandatory and phase-owned: `PounceAgent` keeps a bounded handled-escalation seen-set for the current elevated-mode session and clears it when the runtime de-escalates back to `Normal`.
- `SwarmEnvironment.peer_findings` is the in-tick dedupe signal for requirement `POUNCE-02`; if a matching target scope already appears in peer findings for the same cycle, `PounceAgent` skips emitting a second response.
- Scope matching should reuse the same action-to-scope semantics already implied by `StaticApprovalGate` and `CapabilityLease.scope`, rather than inventing a second scope model in the agent.

### Response Selection And Execution Path
- Phase 124 uses a repo-owned `ResponsePlaybookConfig` to map `(ThreatClass, Severity, confidence range)` to ordered `ResponseAction` sequences; this phase should not hardcode ad hoc action selection when the requirement already defines the config seam.
- `PounceAgent` remains a normal `SwarmAgent`: it emits `SwarmAction::RequestResponse` and never owns a direct `SwarmRuntime<P, E>` reference.
- Dispatcher routing is phase-owned: `AgentDispatcher` is responsible for turning `RequestResponse` actions into calls through `authorize_and_execute()` so the policy gate and guard pipeline stay centralized.
- Dry-run must use the identical runtime path as live mode, with the execution mode changed to `DryRun`; there should be no early-return shortcut that bypasses policy, lease, guard, or receipt generation.

### Audit Lineage And Evidence
- `PounceAgent` receipts must stay traceable to real detection lineage; do not mint synthetic `hunt_id` values like `pounce-{uuid}`.
- The emitted `ActionRequest.evidence` should carry enough lineage to explain why the action fired, including the escalation context and the underlying hunt or finding references used for the decision.
- Phase 124 should reuse existing `ResponseReceipt` and audit-trail primitives instead of inventing a second receipt type just for autonomous response.
- Policy lease expiry is a hard safety boundary in this phase: expired leases fail closed before any adapter call, and that denial must remain visible as structured audit output rather than being silently skipped.

### De-escalation Behavior
- `SwarmModeState` gets an explicit `transition_down()` path instead of weakening the existing upward-only `transition_to()` semantics.
- De-escalation returns the runtime to `Normal` only after all active threat classes have stayed below alert threshold for `deescalation_cooldown_secs`; no immediate oscillation-based downgrade is acceptable.
- The cooldown belongs with pheromone and concentration behavior, so the config seam should live with pheromone/runtime concentration settings rather than in TomAgent or policy-specific config.
- De-escalation is owned by Phase 124, not deferred to governance; PounceAgent must not operate indefinitely in an elevated mode by default.

### Claude's Discretion
- Exact internal representation of the handled-escalation seen-set, as long as it is bounded to the current elevated-mode session.
- Whether the dispatcher routes autonomous responses through a dedicated `ResponseRouter` trait or an equivalent seam that keeps `SwarmRuntime` generics out of agent implementations.
- The concrete lineage payload shape inside `ActionRequest.evidence`, as long as receipts remain traceable to the originating escalation and hunt context.

### Deferred Ideas (OUT OF SCOPE)
- Configurable YAML policy rules, matched rule names, and rate-limit verdict reasons belong to Phase 125.
- TomAgent health monitoring, synchronous veto authority, and veto receipts belong to Phase 126.
- Priority ordering across multiple queued autonomous actions, adaptive action selection, and distributed governance remain out of scope for this milestone phase.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| POUNCE-01 | `PounceAgent` emits `SwarmAction::RequestResponse` in `Alert`/`Incident` | Add new agent under `crates/swarm-runtime/src/pounce_agent.rs`; build on `SwarmAgent` pattern used by `whisker_agent.rs`; trigger from `env.mode` plus escalation session state |
| POUNCE-02 | Skip duplicate responses when matching scope already exists in `peer_findings` | Reuse `StaticApprovalGate`/`CapabilityLease.scope` semantics as the single scope model; compare against same-tick `peer_findings` before emitting |
| POUNCE-03 | `ResponsePlaybookConfig` maps threat/severity/confidence to ordered actions | Add config contract in `swarm-core/src/config.rs` and defaults in `rulesets/default.yaml`; keep selection deterministic and repo-owned |
| POUNCE-04 | Dispatcher routes `RequestResponse` through `authorize_and_execute()` | Replace current no-op arm in `AgentDispatcher::apply_actions()` with routed execution through a dispatcher-owned seam |
| POUNCE-05 | Dry-run uses identical path and yields `ResponseReceipt { status: Simulated }` | Reuse existing `SwarmRuntime::authorize_and_execute()` and `ExecutionMode::DryRun`; do not add a shortcut path |
| POLICY-01 | Expired capability leases fail closed before adapter call | Add explicit `lease.expires_at_ms <= context.now_ms` denial in `SwarmRuntime::authorize_and_execute()` immediately after lease issuance and before `response.execute()` |
| DEESC-01 | `SwarmModeState::transition_down()` updates timestamp and clears trigger | Add symmetric downward transition in `crates/swarm-core/src/agent.rs` with dedicated tests |
| DEESC-02 | `ConcentrationMonitor::evaluate_all()` de-escalates after cooldown | Extend `PheromoneConfig` with `deescalation_cooldown_secs`; teach `evaluate_all()` to call `transition_down()` only after all classes remain below threshold long enough |
</phase_requirements>

## Summary

Phase 124 is primarily a runtime-wiring phase, not a greenfield design phase. The core seams already exist: `SwarmAction::RequestResponse` is defined in `crates/swarm-core/src/types.rs`, `SwarmRuntime::authorize_and_execute()` already centralizes policy, guard, and executor flow in `crates/swarm-runtime/src/lib.rs`, `ResponseStatus::Simulated` already exists in `crates/swarm-response/src/lib.rs`, and the dispatcher already provides `mode`, `mode_transition_at`, and `peer_findings` to agents. The missing pieces are the new `PounceAgent`, routing that action through the dispatcher, fail-closed lease enforcement, and a downward mode path.

The highest-risk implementation errors are all ordering bugs: triggering PounceAgent repeatedly while mode stays elevated, bypassing the runtime path in dry-run, or checking lease expiry too late. The repo already has the right boundaries to avoid these. Keep PounceAgent as a normal `SwarmAgent`, keep execution centralized in `authorize_and_execute()`, keep scope semantics aligned with `StaticApprovalGate`, and make de-escalation part of `ConcentrationMonitor`, not a separate governance concern.

**Primary recommendation:** Plan this phase in four slices: core config/types, `PounceAgent` emission + dedupe, dispatcher/runtime routing with lease fail-closed behavior, then de-escalation plus integration tests.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `swarm-core` | workspace `0.1.0` | `SwarmAgent`, `SwarmModeState`, `SwarmAction`, config contracts | This is where mode state and playbook config belong today |
| `swarm-runtime` | workspace `0.1.0` | `AgentDispatcher`, `ConcentrationMonitor`, `SwarmRuntime` | Phase 124 is mostly wiring inside this crate |
| `swarm-policy` | workspace `0.1.0` | `ActionRequest`, `ApprovalGate`, `CapabilityLease` | Existing scope and lease semantics already live here |
| `swarm-response` | workspace `0.1.0` | `ExecutionMode`, `ResponseReceipt`, executor path | Dry-run and receipt behavior already exist here |
| `swarm-spine` | workspace `0.1.0` | Audit trail records | Reuse existing audit primitives instead of inventing a second receipt system |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `tokio` | workspace `1.x` | async dispatcher tick loop and runtime flow | Reuse existing async execution model; no new runtime |
| `arc-swap` | workspace `1.x` | shared `SwarmModeState` snapshots | Already used for mode sharing between monitor and dispatcher |
| `serde_yaml` | workspace `0.9.x` | config defaults and playbook serialization | Needed when adding `ResponsePlaybookConfig` to repo-owned YAML |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Dispatcher-routed execution | Direct runtime handle inside `PounceAgent` | Violates the existing agent boundary and leaks runtime generics into agent code |
| Existing `ResponseReceipt`/`AuditTrail` | New autonomous-response receipt type | Adds duplicate audit surfaces and breaks consistency |
| `CapabilityLease.scope` semantics | New PounceAgent-only scope matcher | Creates two conflicting definitions of “same target scope” |

**Installation:**
```bash
# No new crates required for Phase 124.
cargo test -p swarm-runtime
```

**Version verification:** Workspace dependencies are authoritative in [Cargo.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/Cargo.toml) and crate membership is confirmed in [crates/swarm-runtime/Cargo.toml](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/Cargo.toml). No project-local `.claude/skills/` or `.agents/skills/` directories exist.

## Architecture Patterns

### Recommended Project Structure
```text
crates/swarm-core/src/
├── agent.rs              # add transition_down()
├── config.rs             # add ResponsePlaybookConfig + deescalation_cooldown_secs
└── types.rs              # reuse existing SwarmAction::RequestResponse

crates/swarm-runtime/src/
├── pounce_agent.rs       # new agent
├── dispatcher.rs         # route RequestResponse
├── escalation.rs         # transition_down cooldown logic
└── lib.rs                # lease expiry enforcement in authorize_and_execute()

crates/swarm-runtime/tests/
├── dispatch_integration.rs    # extend runtime-path assertions
├── escalation_integration.rs  # extend de-escalation coverage
└── pounceagent_integration.rs # new end-to-end phase file
```

### Pattern 1: Agent Emits, Dispatcher Routes
**What:** `PounceAgent` should only decide and emit `SwarmAction::RequestResponse`. The dispatcher owns runtime routing.

**When to use:** Always. This is the locked boundary from context and matches existing agent structure.

**Example:**
```rust
// Source: crates/swarm-runtime/src/dispatcher.rs + phase requirement POUNCE-04
match action {
    SwarmAction::RequestResponse { hunt_id, action, evidence } => {
        response_router.route(&completed.agent_id, hunt_id, action, evidence, now).await?;
    }
    // existing arms unchanged
}
```

### Pattern 2: One Scope Model For Dedupe
**What:** Derive the target scope for duplicate suppression from the same action-to-scope semantics used by policy leases.

**When to use:** For `POUNCE-02` and when constructing evidence/receipts.

**Example:**
```rust
// Source: crates/swarm-policy/src/static_gate.rs
fn scope_for_action(action: &ResponseAction) -> Option<String> {
    match action {
        ResponseAction::BlockEgress { target } => Some(target.clone()),
        ResponseAction::IsolateHost { host_id } => Some(host_id.clone()),
        ResponseAction::RevokeCredential { credential_id } => Some(credential_id.clone()),
        ResponseAction::DeployDecoy { target_zone, .. } => Some(target_zone.clone()),
        ResponseAction::Escalate { .. } => None,
    }
}
```

### Pattern 3: Fail Closed Inside `authorize_and_execute()`
**What:** Lease expiry belongs in the canonical runtime path, after `issue_lease()` and before any adapter call.

**When to use:** For every request, including dry-run.

**Example:**
```rust
// Source: crates/swarm-runtime/src/lib.rs + POLICY-01
let lease = self.policy.issue_lease(request, context)?;
if lease.expires_at_ms <= context.now_ms {
    return Err(ApprovalError::Denied("capability lease expired".to_string()).into());
}
let receipt = self.response.execute(request, &lease, execution_mode).await?;
```

### Pattern 4: Downward Mode Transition Is Explicit
**What:** Keep `transition_to()` upward-only and add a separate `transition_down()` for de-escalation semantics.

**When to use:** `DEESC-01` and `DEESC-02`.

**Example:**
```rust
// Source: crates/swarm-core/src/agent.rs + phase requirement DEESC-01
pub fn transition_down(&mut self, mode: SwarmMode, now: i64) -> bool {
    if mode >= self.current {
        return false;
    }
    self.current = mode;
    self.last_transition_at = Some(now);
    self.triggering_threat_class = None;
    true
}
```

### Anti-Patterns to Avoid
- **Direct runtime in agent:** Do not inject `SwarmRuntime<P, E>` into `PounceAgent`; it breaks the current `SwarmAgent` model.
- **Dry-run short circuit:** Do not return a synthetic result from PounceAgent before policy/guard/executor.
- **Synthetic hunt IDs:** Do not generate `pounce-{uuid}` lineage.
- **Global unbounded seen-set:** Bound dedupe to the current elevated-mode session and clear it on return to `Normal`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Autonomous response receipts | A second receipt type | `ResponseReceipt` + `AuditTrail` | The runtime and tests already understand these shapes |
| Target-scope matching | A Pounce-only matcher | `StaticApprovalGate`/`CapabilityLease.scope` semantics | Prevents drift between dedupe and policy scope |
| Live vs dry-run branching | Separate Pounce dry-run code path | `ExecutionMode::DryRun` through `authorize_and_execute()` | Keeps safety checks identical |
| Response execution boundary | Direct executor calls from agent | Dispatcher route to `SwarmRuntime::authorize_and_execute()` | Preserves centralized guard and policy flow |

**Key insight:** The repo already has the hard parts. Phase 124 should connect them, not replace them.

## Common Pitfalls

### Pitfall 1: Dispatcher Wiring Stops At `RequestResponse`
**What goes wrong:** `SwarmAction::RequestResponse` is emitted but never executed.
**Why it happens:** `AgentDispatcher::apply_actions()` currently treats it as agent-direct and does nothing.
**How to avoid:** Add a dispatcher-owned routing seam and make `apply_actions()` async if needed.
**Warning signs:** Tests only inspect emitted actions, not runtime receipts.

### Pitfall 2: Duplicate Response On Stable Elevated Mode
**What goes wrong:** PounceAgent re-emits the same action every tick while mode stays `Alert`/`Incident`.
**Why it happens:** Triggering is based on current mode alone with no session dedupe.
**How to avoid:** Maintain a bounded handled-escalation seen-set keyed to the current elevated-mode session and also consult `peer_findings`.
**Warning signs:** Same `hunt_id` and scope produce multiple receipts across consecutive ticks.

### Pitfall 3: Lease Expiry Is Checked Too Late Or Not At All
**What goes wrong:** Adapter executes with an expired `CapabilityLease`.
**Why it happens:** `CapabilityLease.expires_at_ms` exists but `authorize_and_execute()` currently never checks it.
**How to avoid:** Deny immediately after `issue_lease()` and before `response.execute()`.
**Warning signs:** No regression test asserts `ApprovalError::Denied("capability lease expired")`.

### Pitfall 4: De-escalation Flaps
**What goes wrong:** Runtime bounces between elevated mode and `Normal`, letting PounceAgent fire repeatedly.
**Why it happens:** `ConcentrationMonitor::evaluate_all()` only handles upward transitions today; a naive downward check will oscillate.
**How to avoid:** Track below-threshold dwell time per active threat class and require `deescalation_cooldown_secs`.
**Warning signs:** Tests assert only final mode, not number of transitions or actions.

## Code Examples

Verified repo patterns to extend:

### Existing Upward-Only Mode Logic
```rust
// Source: crates/swarm-core/src/agent.rs
pub fn transition_to(&mut self, mode: SwarmMode, threat_class: ThreatClass, now: i64) -> bool {
    if mode <= self.current {
        return false;
    }
    self.current = mode;
    self.last_transition_at = Some(now);
    self.triggering_threat_class = Some(threat_class);
    true
}
```

### Existing Runtime Dry-Run Mapping
```rust
// Source: crates/swarm-runtime/src/lib.rs
let execution_mode = match self.mode {
    RuntimeMode::DetectOnly => ExecutionMode::DryRun,
    RuntimeMode::LiveResponse => ExecutionMode::Enforced,
};
```

### Existing Integration Proof For Simulated Receipts
```rust
// Source: crates/swarm-runtime/tests/dispatch_integration.rs
assert_eq!(receipt.mode, ExecutionMode::DryRun);
assert_eq!(receipt.status, ResponseStatus::Simulated);
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Agents deposit or publish only | Agents can also emit `RequestResponse` | Already defined pre-Phase 124 | Routing is the missing seam, not the action type |
| Upward-only mode transitions | Explicit upward + downward paths | Phase 124 | Prevents permanent elevated posture |
| Lease TTL as metadata only | Lease TTL as enforced safety boundary | Phase 124 | Required for fail-closed execution |

**Deprecated/outdated:**
- Treating `RequestResponse` as “agent-direct” in the dispatcher is no longer valid once PounceAgent exists.
- Treating `last_transition_at` as “upward only” is no longer sufficient once de-escalation lands.

## Open Questions

1. **What should the elevated-mode session key be for the handled-escalation seen-set?**
   - What we know: dedupe must clear on return to `Normal`.
   - What's unclear: whether to key by `mode_transition_at`, escalation record tuple, or a dedicated session ID.
   - Recommendation: use `mode_transition_at` plus current mode as the session boundary unless implementation finds a stronger stable key in substrate escalation records.

2. **How much lineage should live in `ActionRequest.evidence` for autonomous response?**
   - What we know: synthetic `hunt_id` values are forbidden.
   - What's unclear: exact payload shape for escalation context and contributing findings.
   - Recommendation: include the selected escalation tuple, the originating `hunt_id`, and any matched finding references in JSON, but defer schema polish to later policy/audit phases.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust `cargo test` |
| Config file | none |
| Quick run command | `cargo test -p swarm-runtime --test dispatch_integration --test escalation_integration` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| POUNCE-01 | PounceAgent emits `RequestResponse` in elevated mode only | integration | `cargo test -p swarm-runtime --test pounceagent_integration pounceagent_emits_request_response_for_alert_and_incident -- --exact` | ❌ Wave 0 |
| POUNCE-02 | PounceAgent suppresses same-scope duplicates from `peer_findings` | integration | `cargo test -p swarm-runtime --test pounceagent_integration pounceagent_skips_scope_present_in_peer_findings -- --exact` | ❌ Wave 0 |
| POUNCE-03 | Playbook mapping selects ordered actions deterministically | unit/integration | `cargo test -p swarm-runtime --test pounceagent_integration response_playbook_selects_actions_by_threat_severity_and_confidence -- --exact` | ❌ Wave 0 |
| POUNCE-04 | Dispatcher routes `RequestResponse` through runtime policy and guard path | integration | `cargo test -p swarm-runtime --test dispatch_integration request_response_routes_through_authorize_and_execute -- --exact` | ✅ extend |
| POUNCE-05 | Dry-run uses identical path and yields `Simulated` receipt | integration | `cargo test -p swarm-runtime --test dispatch_integration pounceagent_dry_run_routes_through_runtime_path -- --exact` | ✅ extend |
| POLICY-01 | Expired lease returns denied before adapter call | integration | `cargo test -p swarm-runtime --test dispatch_integration expired_capability_lease_fails_closed_before_execution -- --exact` | ✅ extend |
| DEESC-01 | `transition_down()` updates timestamp and clears trigger | unit | `cargo test -p swarm-core mode_state_transition_down_clears_triggering_threat_class -- --exact` | ✅ extend |
| DEESC-02 | Monitor de-escalates after cooldown once all classes stay below threshold | integration | `cargo test -p swarm-runtime --test escalation_integration concentration_monitor_deescalates_after_cooldown -- --exact` | ✅ extend |

### Sampling Rate
- **Per task commit:** `cargo test -p swarm-runtime --test dispatch_integration --test escalation_integration`
- **Per wave merge:** `cargo test -p swarm-runtime`
- **Phase gate:** `cargo test --workspace`

### Wave 0 Gaps
- [ ] `crates/swarm-runtime/tests/pounceagent_integration.rs` — core PounceAgent emission, playbook selection, peer-finding dedupe, dry-run proof
- [ ] Extend `crates/swarm-runtime/tests/dispatch_integration.rs` — routed `RequestResponse` and expired-lease fail-closed coverage
- [ ] Extend `crates/swarm-runtime/tests/escalation_integration.rs` — cooldown-based de-escalation proof
- [ ] Extend `crates/swarm-core/src/agent.rs` tests — `transition_down()` semantics

## Sources

### Primary (HIGH confidence)
- `crates/swarm-core/src/agent.rs` - current `SwarmModeState`, `SwarmEnvironment`, and missing downward transition
- `crates/swarm-core/src/types.rs` - existing `SwarmAction::RequestResponse` and `ResponseAction` variants
- `crates/swarm-core/src/config.rs` - current `PheromoneConfig` and `PolicyConfig`; both missing Phase 124 fields
- `crates/swarm-policy/src/lib.rs` - authoritative `ActionRequest`, `ApprovalContext`, `CapabilityLease`, `ApprovalError`
- `crates/swarm-policy/src/static_gate.rs` - existing action-to-scope semantics to reuse for dedupe
- `crates/swarm-runtime/src/dispatcher.rs` - current `RequestResponse` no-op and existing `peer_findings` environment wiring
- `crates/swarm-runtime/src/escalation.rs` - current upward-only `evaluate_all()` implementation
- `crates/swarm-runtime/src/lib.rs` - canonical policy -> guard -> executor path in `authorize_and_execute()`
- `crates/swarm-runtime/src/whisker_agent.rs` - reference `SwarmAgent` implementation pattern
- `crates/swarm-runtime/tests/dispatch_integration.rs` - existing dry-run and guard/policy integration pattern
- `crates/swarm-runtime/tests/escalation_integration.rs` - existing escalation integration test surface
- `rulesets/default.yaml` - current config defaults and missing response playbook/de-escalation fields
- `Cargo.toml` - workspace dependency surface

### Secondary (MEDIUM confidence)
- `.planning/research/ARCHITECTURE.md` - recommended dispatcher/router seam and file touch points
- `.planning/research/PITFALLS.md` - risk ordering and verification checklist aligned to this phase
- `.planning/research/STACK.md` - confirms no new crate dependencies are required

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - entirely repo-grounded; no new dependencies needed
- Architecture: HIGH - current runtime seams are explicit and phase-local
- Pitfalls: HIGH - each major risk is directly observable in current code gaps

**Research date:** 2026-04-08
**Valid until:** 2026-05-08
