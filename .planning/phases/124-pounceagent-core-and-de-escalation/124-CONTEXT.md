# Phase 124: PounceAgent Core And De-escalation - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 124 delivers the first autonomous response loop: a new `PounceAgent` reacts to elevated swarm mode, emits response requests that the dispatcher routes through the existing runtime authorization and guard pipeline, and supports dry-run plus fail-closed lease expiry. This phase also adds downward mode transitions with cooldown so the runtime can return to `Normal` after pressure subsides. Configurable YAML policy rules and TomAgent governance are explicitly out of scope for this phase.

</domain>

<decisions>
## Implementation Decisions

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

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-runtime/src/whisker_agent.rs`, `crates/swarm-runtime/src/stalker_agent.rs`, and `crates/swarm-runtime/src/weaver_agent.rs` already define the repo pattern for `SwarmAgent` implementations, role-shift handling, and bounded per-tick work.
- `crates/swarm-runtime/src/dispatcher.rs` already builds `SwarmEnvironment` with `mode`, `mode_transition_at`, and `peer_findings`, and it already recognizes `SwarmAction::RequestResponse` even though routing is currently a no-op.
- `crates/swarm-runtime/src/lib.rs` owns `SwarmRuntime::authorize_and_execute()` and the full policy -> guard -> executor path; this is the canonical place to enforce lease expiry before adapter execution.
- `crates/swarm-policy/src/static_gate.rs` already defines action scope semantics and lease issuance behavior that PounceAgent should align with instead of duplicating.
- `.planning/research/ARCHITECTURE.md`, `.planning/research/STACK.md`, and `.planning/research/PITFALLS.md` already capture the v1.39 architectural recommendation, dependency boundaries, and failure modes for PounceAgent and de-escalation.

### Established Patterns
- Agent roles live in `swarm-runtime/src/*_agent.rs`, keep their own small internal state, and emit `SwarmAction` values rather than reaching into runtime generics directly.
- Shared runtime state is exposed through `Arc<ArcSwap<...>>` snapshots and lightweight environment views, not mutable cross-agent references.
- Config contracts belong in `swarm-core` and runtime wiring belongs in `swarm-runtime`; Phase 124 should follow that split for `ResponsePlaybookConfig` and de-escalation settings.
- Integration proofs live under `crates/swarm-runtime/tests/` and use deterministic in-memory runtime stacks rather than bespoke test-only infrastructure.

### Integration Points
- New phase-owned files likely include `crates/swarm-runtime/src/pounce_agent.rs` and changes in `crates/swarm-runtime/src/dispatcher.rs`, `crates/swarm-runtime/src/escalation.rs`, `crates/swarm-runtime/src/ingest.rs` and/or `crates/swarm-runtime/src/service.rs`.
- Core type changes likely touch `crates/swarm-core/src/agent.rs`, `crates/swarm-core/src/config.rs`, and `crates/swarm-core/src/types.rs`.
- Lease-expiry enforcement and autonomous-response audit flow likely touch `crates/swarm-runtime/src/lib.rs`, `crates/swarm-response/src/dispatch.rs`, and related runtime integration tests.
- Default config examples and milestone verification will likely need updates in `rulesets/default.yaml` and `crates/swarm-runtime/tests/`.

</code_context>

<specifics>
## Specific Ideas

- Prefer mode-session-triggered response logic over raw persistent-pressure polling; the pitfall research explicitly calls out duplicate execution on stable elevated mode as a phase-one failure mode.
- Keep the action selection logic deterministic and repo-owned from day one by introducing `ResponsePlaybookConfig` now instead of backfilling it later.
- Preserve the audit chain by choosing a real escalation-backed or finding-backed `hunt_id`, not a synthetic autonomous-response identifier.
- Defer TomAgent veto and configurable YAML rule evaluation to their own phases, but do not defer the seams that those phases need: centralized dispatcher routing and traceable evidence payloads should land here.

</specifics>

<deferred>
## Deferred Ideas

- Configurable YAML policy rules, matched rule names, and rate-limit verdict reasons belong to Phase 125.
- TomAgent health monitoring, synchronous veto authority, and veto receipts belong to Phase 126.
- Priority ordering across multiple queued autonomous actions, adaptive action selection, and distributed governance remain out of scope for this milestone phase.

</deferred>
