---
phase: 77-human-gate-and-promotion-integration
type: context
created: "2026-04-04"
---

# Phase 77: Human Gate And Promotion Integration

## Decisions

- Critical-severity promotion candidates MUST enter `HumanApprovalPending` state instead of proceeding directly to `Active`
- The gate follows fail-closed: missing approval = blocked, not allowed
- Lower severities (Low, Medium, High) pass through to `Active` without the human gate
- The quorum gate is structural (present in code path) but advisory until distributed trust boundaries arrive
- Approval reference types (signed votes, consensus receipts) are added as `Option<T>` fields on promotion records since Phase 75/76 artifacts may not be populated yet
- Promotion records carry approval references (vote refs + consensus receipt) alongside existing canary and rollout lineage
- The pending state persists a review packet and audit history inspectable through both `swarmctl` and the authenticated HTTP surface
- An operator-explicit `approve` command clears the pending state and transitions to `Active`

## Deferred Ideas

- Distributed quorum voting across independent nodes (no trust boundaries yet)
- Automatic approval from verdicts (approval remains explicit operator action)
- Multi-user approval workflows or RBAC
- Configurable severity thresholds for the gate (hardcoded to Critical for now)

## Claude's Discretion

- Naming of the approval reference types (e.g., `PromotionApprovalRef`, `PromotionConsensusReceipt`)
- Whether to add a separate `PromotionApprovalGate` trait or inline the check in the harness
- Structure of the review packet that accompanies the pending state
- Rendering format for approval references in `swarmctl` output
