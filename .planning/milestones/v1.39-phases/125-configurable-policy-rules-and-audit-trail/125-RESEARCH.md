# Phase 125: Configurable Policy Rules And Audit Trail - Research

**Date:** 2026-04-08
**Status:** Complete

## Key Findings

- `ConfigurableApprovalGate` should live in `crates/swarm-policy/src/configurable_gate.rs` and compose with `StaticApprovalGate`, not replace it.
- The repository already loads YAML into `SwarmConfig`, so configurable policy rules should deserialize through `swarm-core` config. This makes malformed rules a startup error instead of a silent runtime branch.
- `ActionRequest.evidence` already carries `escalation.threat_class` for PounceAgent-originated requests, which is enough for rule matching without changing the request wire shape.
- `PolicyDecision` currently loses rule attribution. Phase 125 needs a decisive rule-name field there so runtime logs, audit trails, and receipts can all share the same source of truth.
- `ResponseReceipt` currently has only `details` for adapter metadata. A separate audit payload is the cleanest place to attach policy provenance without coupling adapters to runtime policy internals.

## Implementation Direction

1. Extend `PolicyConfig` with:
   - `max_actions_per_scope_per_minute`
   - ordered `rules`
2. Add validated config types for:
   - rule decision (`allow` / `deny`)
   - action selectors
   - optional UTC hour windows
   - optional per-agent one-minute limits
3. Refactor `StaticApprovalGate` so request validation stays reusable and its decisions carry stable static rule names.
4. Introduce `ConfigurableApprovalGate` with:
   - fail-closed empty-rules behavior
   - ordered selector matching
   - rule-local time-window checks
   - rule-local per-agent rate limiting
   - static fallback when no rule matches
5. Extend runtime audit plumbing so:
   - structured logs include `rule_name` and `reason`
   - `PolicyRecord` stores `rule_name`
   - successful `ResponseReceipt` values store `audit.policy`

## Risks To Control

- Do not let YAML allow rules silently bypass request-shape validation; empty targets and null evidence must still fail as invalid requests.
- Avoid double-counting rate-limit windows when a request flows through the configurable gate and then into static fallback.
- Keep receipt audit metadata additive so existing adapter logic and failure shaping remain intact.
