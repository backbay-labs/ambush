---
phase: 125-configurable-policy-rules-and-audit-trail
plan: 04
subsystem: runtime-audit
tags: [runtime, audit, receipts, dispatch]
provides:
  - policy rule attribution in runtime logs, audit trails, and successful receipts
  - dedicated `ResponseReceipt.audit.policy` payload for verdict provenance
  - dispatch integration proof for audit-trail and receipt policy attribution
affects:
  - 125 verification
  - 126 governance receipt and audit baseline
key-files:
  created:
    - .planning/phases/125-configurable-policy-rules-and-audit-trail/125-04-SUMMARY.md
  modified:
    - crates/swarm-response/src/lib.rs
    - crates/swarm-spine/src/lib.rs
    - crates/swarm-runtime/src/lib.rs
    - crates/swarm-runtime/tests/dispatch_integration.rs
requirements-completed: [POLICY-04]
completed: 2026-04-08
---

# Phase 125 Plan 04 Summary

**Every policy verdict now carries the decisive rule name and reason through runtime logs, persisted audit trails, and successful `ResponseReceipt` values**

## Accomplishments

- Added a typed `ResponseReceipt.audit.policy` payload so policy provenance is explicit and separate from adapter-specific receipt details.
- Extended `PolicyRecord` and runtime audit construction to persist `rule_name` and `reason` for allow, deny, and require-human verdicts.
- Updated runtime structured logging so policy evaluation and response execution emit `rule_name` and `reason` as first-class fields.
- Preserved attribution across both successful and failure-shaped receipts by attaching policy audit data before `into_failure()`.
- Extended `dispatch_integration` with exact tests proving rule attribution reaches `AuditTrail.policy` and successful receipts.

## Task Commits

No task commit was created for this plan.

## Decisions Made

- Kept receipt audit metadata typed and additive instead of stuffing policy provenance into `details`, which keeps adapters decoupled from policy internals.
- Used the canonical runtime path as the single injection point for policy audit data so live and dry-run execution stay aligned.
- Reused the new `PolicyDecision` rule attribution instead of deriving log or receipt provenance independently downstream.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Broad verification surfaced drafting harnesses that still loaded repository config without explicit test policy rules**
- **Found during:** `cargo test -p swarm-core -p swarm-policy -p swarm-runtime`
- **Issue:** drafting scorecard and materialization tests now ran under the Phase 125 fail-closed configurable gate and their local sample config never overrode the empty configured rules, causing verification-driven draft promotion coverage to fail
- **Fix:** aligned `crates/swarm-runtime/src/drafting.rs` with the other synthetic harnesses by loading the repository config and injecting permissive named allow rules for the test-only path
- **Files modified:** `crates/swarm-runtime/src/drafting.rs`
- **Verification:** `cargo test -p swarm-runtime drafting::tests::`

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** No scope change. The deviation only repaired an owned test fixture so phase-wide verification stayed green without weakening production fail-closed behavior.

## Verification Notes

- `cargo test -p swarm-runtime --test dispatch_integration audit_trail_records_rule_name_and_reason -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration successful_receipts_embed_policy_audit -- --exact` passed
- `cargo test -p swarm-runtime --test dispatch_integration` passed
- `cargo test -p swarm-runtime drafting::tests::` passed
- `cargo test -p swarm-core -p swarm-policy -p swarm-runtime` passed

## Next Phase Readiness

Phase 126 can now assume:

- the decisive policy rule is durable and queryable after execution
- successful receipts already expose an audit payload suitable for later governance provenance
- runtime logs and audit trails share a single source of truth for policy attribution
