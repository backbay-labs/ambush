# Phase 126: TomAgent Governance - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 126 adds a governance lane on top of the Phase 124-125 autonomous response path. TomAgent must observe agent-health summaries during dispatcher ticks, emit lifecycle actions for degraded agents, and feed a shared `GovernancePolicy` that PounceAgent consults synchronously before it emits destructive `RequestResponse` actions. When governance blocks an action, the runtime must still produce a durable veto receipt that preserves hunt lineage and is queryable through the existing operator/audit surfaces. Distributed quorum governance remains out of scope.

</domain>

<decisions>
## Implementation Decisions

### Governance Inputs
- TomAgent needs the dispatcher’s current agent-health summary inside `SwarmEnvironment`; reading `health_state` indirectly from elsewhere would break the single-tick agent model.
- The configurable failure threshold belongs in runtime config, not policy config. It governs agent lifecycle escalation, not response authorization semantics.
- `AgentHealthEntry` should live in `swarm-core::agent`, not `swarm-runtime::dispatcher`, because it becomes part of the cross-agent environment contract.

### Lifecycle Actions
- Existing `SwarmAction::RoleShift` and `SwarmAction::HealthReport` only affect the emitting agent today. TomAgent needs targeted variants or targeted fields so it can act on another agent’s lifecycle state.
- The dispatcher should remain the only component that applies role and health overrides. TomAgent emits intent; the dispatcher resolves those intents against the registered roster.
- A missing target agent should fail soft with structured warning logs instead of panicking or silently mutating the wrong agent.

### Governance Policy
- The shared `Arc<GovernancePolicy>` is the authoritative state TomAgent updates and PounceAgent reads.
- `GovernancePolicy::can_act()` must run inside `PounceAgent::tick()` before `SwarmAction::RequestResponse` is emitted. A runtime-side re-check would be too late for the phase goal.
- Governance veto only needs to cover destructive actions in this phase. Non-destructive actions such as `Escalate` should still pass through when governance is otherwise healthy.

### Audit And Receipts
- A governance veto still needs a receipt id so the existing replay/operator lookup paths can find it by receipt.
- The cleanest path is a synthetic veto receipt recorded through the dispatcher router seam, not a side-channel file or direct agent write.
- Receipt audit metadata should gain a governance section parallel to the Phase 125 policy audit so governance provenance stays explicit.

### Claude's Discretion
- The exact runtime config field name for the degraded-to-failed threshold, as long as it is validated and repository-owned.
- The exact destructive-action set for governance veto, as long as it covers clearly destructive response actions and is tested explicitly.
- Whether vetoed actions are represented as a distinct `ResponseStatus::Vetoed` or a failure-shaped synthetic receipt, as long as they remain queryable by receipt id and carry governing-agent provenance.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `AgentDispatcher` already computes a health snapshot and stores it in shared `ArcSwap` state for the operator surface.
- `PounceAgent` already owns the synchronous decision point where autonomous `RequestResponse` actions are chosen from escalation pheromones.
- `RequestResponseRouter` already routes autonomous responses back into the canonical runtime path from the dispatcher.
- `ResponseReceipt.audit.policy` and `AuditTrail.policy` now provide an established pattern for layered audit provenance.

### Established Patterns
- Agent role changes propagate through dispatcher-owned `SwarmEvent::RoleShift` broadcasts rather than direct mutation by peers.
- Runtime config and validation live in `swarm-core/src/config.rs`, with repository load proved through `crates/swarm-runtime/src/config.rs`.
- Durable operator queryability today comes from persisted replay/audit bundles keyed by `response_receipt_id`; Phase 126 should piggyback on that path rather than inventing a parallel store.

### Integration Points
- `crates/swarm-core/src/agent.rs` and `crates/swarm-core/src/types.rs` define the agent/runtime contracts that TomAgent needs.
- `crates/swarm-runtime/src/dispatcher.rs` owns targeted action application, environment construction, and autonomous routing.
- `crates/swarm-runtime/src/pounce_agent.rs` is the synchronous veto insertion point.
- `crates/swarm-runtime/src/ingest.rs` and `crates/swarm-runtime/tests/dispatch_integration.rs` own the runtime-backed routing seam that should record veto receipts.

</code_context>

<specifics>
## Specific Ideas

- Keep TomAgent narrow: it does not execute responses, it updates governance state and emits lifecycle actions.
- Use targeted lifecycle actions with explicit `AgentId`s so the dispatcher remains deterministic and auditable.
- Record governance veto receipts with the rejected action kind, veto reason, and governing agent id in receipt audit metadata so the existing receipt-id lookup paths keep working.

</specifics>

<deferred>
## Deferred Ideas

- Multi-node committee governance and quorum voting remain outside Phase 126.
- Recovery or automatic role restoration for degraded agents can wait; this phase only needs detection, quarantine-style role shift, and failed escalation.
- Full seven-pitfall end-to-end coverage belongs to Phase 127 after TomAgent lands.

</deferred>
