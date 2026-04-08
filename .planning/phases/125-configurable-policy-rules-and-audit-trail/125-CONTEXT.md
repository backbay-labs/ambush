# Phase 125: Configurable Policy Rules And Audit Trail - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 125 delivers the configurable response-policy layer that sits behind the already-routed autonomous execution path. Operators should be able to express ordered YAML authorization rules in the repository ruleset, with `ConfigurableApprovalGate` evaluating those rules before falling back to `StaticApprovalGate` when no rule matches. This phase also extends policy audit output so the decisive rule name and reason persist in structured runtime logs, audit trails, and successful response receipts. TomAgent governance and end-to-end multi-phase pitfall coverage remain out of scope.

</domain>

<decisions>
## Implementation Decisions

### Policy Config Surface
- The YAML contract belongs in `swarm-core` config, not in `swarm-policy`; repository-owned rules should deserialize as part of `SwarmConfig` so parse errors fail startup instead of being silently ignored at runtime.
- `PolicyConfig` should grow two explicit knobs in this phase: a static per-scope burst limit for `StaticApprovalGate` and an ordered list of configurable policy rules for `ConfigurableApprovalGate`.
- Policy rules should be deterministic and ordered: the first rule whose action/threat/severity selectors match decides the YAML outcome for that request.
- Time-of-day limits and per-agent rate limits are rule-local constraints, not global runtime toggles.

### Gate Composition
- `ConfigurableApprovalGate` composes with `StaticApprovalGate`; it does not replace request-shape validation or the existing fallback policy path.
- Empty configurable rules are a fail-closed condition in this phase; an operator who enables the configurable gate but ships no rules should get a deny verdict, not an implicit allow.
- When no YAML rule matches, the request must fall through to `StaticApprovalGate` so existing invariant behavior still applies.
- Rule-local allow/deny behavior should come from YAML, but the audit output must clearly identify whether the decisive verdict came from a named YAML rule or a static fallback rule.

### Audit And Observability
- `PolicyDecision` should become the canonical carrier for rule attribution by holding the decisive rule name and reason beside the verdict.
- `AuditTrail.policy` should persist the decisive rule name so deny, require-human, and allow outcomes remain auditable even when no response receipt exists.
- Successful `ResponseReceipt` values should gain an explicit audit payload for policy metadata instead of overloading adapter-specific `details`.
- Runtime structured logs should emit the decisive rule name and reason as first-class fields on policy evaluation events.

### Rate Limiting
- `StaticApprovalGate` owns the per-scope one-minute window required by `POLICY-02`; the data structure can be in-memory and window-pruned on access.
- Scope tracking should reuse `scope_for_response_action()` so policy, leases, and dispatcher dedupe continue sharing the same target identity semantics.
- Unscoped actions should still produce a deterministic rate-limit bucket so the gate never needs a special no-scope bypass path.
- `ConfigurableApprovalGate` should maintain its own per-agent one-minute counters keyed by `(rule_name, requested_by)` so one rule’s rate limit does not bleed into another’s.

### Claude's Discretion
- The exact YAML field names for action selectors and UTC hour restrictions, as long as they are validated and readable in `rulesets/default.yaml`.
- Whether successful receipt audit metadata uses a typed `audit.policy` structure or a JSON object, as long as it is explicit and separate from adapter implementation details.
- The exact names of the static fallback rules (`static.default_allow`, `static.scope_rate_limit`, etc.), as long as they are stable and auditable.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `crates/swarm-policy/src/static_gate.rs` already owns request validation, severity gating, and lease issuance; it is the natural home for the new per-scope rate limiter and static fallback rule names.
- `crates/swarm-runtime/src/lib.rs` already centralizes policy evaluation, structured logging, audit-trail construction, and receipt return paths, so policy attribution should be injected there rather than at the adapter layer.
- `crates/swarm-runtime/src/service.rs`, `crates/swarm-runtime/src/ingest.rs`, and `crates/swarm-runtime/src/replay/core.inc` are the current configured-runtime construction seams and still hardcode `StaticApprovalGate`.
- `crates/swarm-response/src/lib.rs` defines `ResponseReceipt`; it currently has no dedicated audit field, so Phase 125 must add that seam before policy metadata can land on receipts.

### Established Patterns
- Config contracts and validation rules live in `swarm-core/src/config.rs`, with repository ruleset loading validated through `crates/swarm-runtime/src/config.rs` tests.
- Runtime composition uses explicit generic gate types; replacing the configured runtime’s policy backend means updating the configured stack wiring, not hiding behavior behind global state.
- Audit record types live in `swarm-spine`, while adapter-facing receipt types live in `swarm-response`; Phase 125 should preserve that separation instead of collapsing policy and adapter metadata together.
- Deterministic rate-limiter state elsewhere in the repo uses bounded timestamp queues pruned against `now_ms`; that pattern is sufficient for the new policy counters.

### Integration Points
- `crates/swarm-core/src/config.rs` and `rulesets/default.yaml` define the repo-facing policy contract.
- `crates/swarm-policy/src/lib.rs`, `crates/swarm-policy/src/static_gate.rs`, and new `crates/swarm-policy/src/configurable_gate.rs` own the evaluation logic.
- `crates/swarm-runtime/src/service.rs`, `crates/swarm-runtime/src/ingest.rs`, and `crates/swarm-runtime/src/replay/core.inc` must instantiate the new configurable gate from loaded config.
- `crates/swarm-runtime/tests/dispatch_integration.rs` is already the strongest proof point for canonical runtime-path behavior and should extend to cover policy attribution on audit trails and receipts.

</code_context>

<specifics>
## Specific Ideas

- Keep the ruleset readable and deployment-owned by putting the first real policy examples into `rulesets/default.yaml` instead of introducing a second file format.
- Use named static fallback rules so audit output remains consistent even when YAML does not match.
- Make the receipt policy audit payload explicit enough that later phases can attach TomAgent veto provenance without changing the adapter contract again.

</specifics>

<deferred>
## Deferred Ideas

- TomAgent veto authority and veto receipts belong to Phase 126.
- Full pipeline pitfall-proof integration coverage belongs to Phase 127.
- Hot-reload of policy files or file-watch driven rule updates is outside this phase; startup-time config loading is sufficient.

</deferred>
