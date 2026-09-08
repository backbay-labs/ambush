# Named safety properties (P1–P6)

Phase 292 extracted the policy gate's decision logic into `swarm_policy::formal_core`
— pure, total functions with no `Mutex`, no `std::fs`, no clock read and no
`panic!` (see that module's header doc). Phase 293 proved six classes of
guarantee about that decision core with Kani bounded model checking
(`crates/swarm-policy/src/kani_public_harnesses.rs`, manifested in
`formal/kani/swarm-policy-harnesses.toml`). This document does not add new
behaviour or new proof: it **names** those already-proved guarantees as six
falsifiable safety properties, P1–P6, so the rest of the assurance ledger
(`docs/assurance/MAPPING.md`, `docs/assurance/assumptions.toml`, and the
Phase 294 Task 2 TLA+ model) can cite them by a stable identifier instead of
re-deriving "what does the 293 harness set actually guarantee" from scratch
each time.

Each property below states, in plain language, what must always hold; names
the exact Rust symbol(s) it constrains; names the Kani harness(es) that check
it; and, where a Phase 294 Task 2 TLA+ invariant will check the same property
at the state-machine level (P3–P5), names that invariant. Every symbol and
harness name in this document was verified to resolve against the source
tree at HEAD (`grep` each one — see the Task 1 report for the exact
commands) before this document was written.

`docs/assurance/MAPPING.md`'s "Named safety properties" section cross-links
each property to the table's own registered invariant `Name`s where one
already exists; see that section for why P1–P6 are documented there as a
separate, non-gate-parsed section rather than as new rows in the gate-checked
invariant table.

---

## P1 — Fail-closed evaluation

**Statement.** Every action request the static approval gate evaluates
reaches a decision (`Allow`, `RequireHuman`, or `Deny`) through a total,
deterministic path: a structurally malformed request is rejected before any
decision logic runs, and every well-formed request is decided by the pure
severity-floor and human-gate functions before any default-allow branch can
apply. No input causes a panic, an unhandled case, or an implicit allow.

**Rust symbol(s).**
- `swarm_policy::static_gate::StaticApprovalGate::validate_request` (`crates/swarm-policy/src/static_gate.rs:39`) —
  the malformed-request check that runs first, unconditionally.
- `swarm_policy::static_gate::StaticApprovalGate::evaluate` (`crates/swarm-policy/src/static_gate.rs:252`, the
  `impl ApprovalGate for StaticApprovalGate` block) — the orchestration:
  `validate_request`, then `severity_floor_denial`, then the rate limit, then
  `human_gate_decision`, then (only if none of those returned) the default
  allow.
- `swarm_policy::formal_core::severity_floor_denial` (`crates/swarm-policy/src/formal_core.rs:323`).
- `swarm_policy::formal_core::human_gate_decision` (`crates/swarm-policy/src/formal_core.rs:351`).

**Kani harness(es).**
- `kani_severity_floor_low_is_sound_for_every_action` — exhaustive over all
  15 `ResponseAction` variants at `Severity::Low`.
- `kani_human_gate_holds_destructive_at_or_above_gate` — a destructive action
  at or above the configured gate severity is always held.

**Existing MAPPING.md invariant(s).** `PolicyMalformedRequestRejected`
(the `validate_request` half) and `PolicyHumanGateOnDestructiveAction` (the
`human_gate_decision` half), each with its own negative-registry entry.

---

## P2 — Severity-gate soundness

**Statement.** The decision core's severity classification is internally
consistent: `destructive_action` classifies exactly the twelve
destructive/containment-class `ResponseAction` variants (never misses one of
the twelve, never spuriously includes one of the other three); a destructive
action, or `DeployDecoy`, at `Severity::Low` is always denied by
`severity_floor_denial`; and a destructive action at or above the configured
human-gate severity is always held by `human_gate_decision`. Every gate that
reasons about "is this action dangerous enough to deny/hold" reasons from the
same classification.

**Rust symbol(s).**
- `swarm_policy::formal_core::destructive_action` (`crates/swarm-policy/src/formal_core.rs:297`).
- `swarm_policy::formal_core::severity_floor_denial` (`crates/swarm-policy/src/formal_core.rs:323`).
- `swarm_policy::formal_core::human_gate_decision` (`crates/swarm-policy/src/formal_core.rs:351`).

**Kani harness(es).**
- `kani_destructive_action_classifies_every_variant` — exhaustive over all
  15 variants.
- `kani_severity_floor_low_is_sound_for_every_action`.
- `kani_human_gate_holds_destructive_at_or_above_gate`.

**Existing MAPPING.md invariant(s).** `PolicyHumanGateOnDestructiveAction`
covers the human-gate half. The severity-floor-at-`Low` half and the
`destructive_action` classification itself have no MAPPING.md row of their
own today (they are Kani-only, not gate-checked at a source call site) —
named here rather than left implicit.

---

## P3 — Partition-override receipt integrity

**Statement.** A contingency lease issued during a network partition is
honored only when its embedded governance receipt actually verifies: the
signature verifies against the claimed governor key, the receipt's decision
is `Approve` (never any other decision), and the receipt's hash matches the
lease's own proposal hash exactly. An invalid signature, a non-`Approve`
decision, or a hash mismatch each independently fails the lease closed
(denies it), regardless of what the other two checks would have said.

**Rust symbol(s).**
- `swarm_agents::tom_agent::ContingencyLease::verify` (`crates/swarm-agents/src/tom_agent.rs:52`) —
  the receipt-bound check; it sits above `swarm-policy` in the dependency
  graph (the receipt type and its crypto live in `swarm-agents`/`swarm-consensus`),
  so it is not itself a `formal_core` function, but it is the enforcement
  point this property names.
- `swarm_policy::formal_core::validate_lease_terms` (`crates/swarm-policy/src/formal_core.rs:261`) —
  the structural, clock-free half of the same verification (schema version,
  positive cap/duration, expiry strictly after issuance) that stays in
  `swarm-policy`.

**Kani harness(es) (model-only — see `formal/kani/swarm-policy-harnesses.toml`
for why: receipt crypto lives above this crate, so these harnesses prove a
scalar/boolean MODEL of the decision, not the real `ContingencyLease::verify`
symbol; the named runtime test is what covers the real symbol).**
- `kani_model_only_invalid_signature_always_denies` — runtime test
  `keyless_policy_reloaded_into_a_partition_refuses_persisted_leases`.
- `kani_model_only_non_approve_decision_always_denies` — runtime test
  `governance_policy_approves_destructive_actions_with_signed_receipt_when_healthy`.
- `kani_model_only_hash_mismatch_always_denies` — runtime test
  `governance_policy_approves_destructive_actions_with_signed_receipt_when_healthy`.
- `kani_model_only_validate_lease_terms_rejects_malformed` — the structural
  half; runtime tests are the `formal_core validate_lease_terms_*` unit tests
  plus `keyless_policy_reloaded_into_a_partition_refuses_persisted_leases`.

**TLA+ invariant (Phase 294 Task 2, not yet written).** `OverrideRequiresReceipt`
in `formal/tla/PartitionContingency.tla` — a lease exists in the model only
by way of an approved receipt.

---

## P4 — Blast-radius conservation

**Statement.** Redeeming a contingency lease against an action never grows
the lease's recorded scope count past its `blast_radius_cap`: a new scope is
recorded only when the count of already-redeemed scopes is strictly less
than the cap; redeeming an already-redeemed scope is a no-op
(`AlreadyRedeemed`) that changes nothing; and every denial (expired lease,
non-matching action, or cap already reached) leaves the lease's recorded
state exactly as it was — no partial mutation on the failure path.

**Rust symbol(s).**
- `swarm_policy::formal_core::lease_redeem` (`crates/swarm-policy/src/formal_core.rs:219`).
- `swarm_policy::formal_core::lease_can_redeem` (`crates/swarm-policy/src/formal_core.rs:199`) —
  the boolean predicate `lease_redeem`'s cap/expiry/match logic mirrors.

**Kani harness(es).**
- `kani_model_only_blast_radius_conservation` — model of `lease_redeem`: a
  new scope is recorded only while `count < cap`; runtime test
  `governance_policy_stages_and_redeems_contingency_leases_during_partition`.
- `kani_model_only_expired_lease_always_denies` — model of `lease_can_redeem`:
  `expires_at_ms <= now_ms` denies regardless of match or budget; runtime
  test `governance_policy_stages_and_redeems_contingency_leases_during_partition`.

**Unit tests (real symbol, not model-only).**
`lease_redeem_records_a_new_scope_within_budget`,
`lease_redeem_fails_closed_on_mismatch_expiry_and_cap`
(`crates/swarm-policy/src/formal_core.rs`, `#[cfg(test)]` module).

**TLA+ invariant (Phase 294 Task 2, not yet written).** `BlastRadiusNeverExceeded`
in `formal/tla/PartitionContingency.tla` — redeemed scopes per lease ≤ its
`blast_radius_cap`, checked over the full issuance/redemption/reconciliation
state machine (`lease_redeem` itself is already Kani-proved at the function
level; the TLA+ invariant checks the property holds across sequences of
partition-state transitions, concurrent leases, and heal/reconciliation,
which is outside what a single-function Kani harness bounds).

---

## P5 — Quorum-transition soundness

**Statement.** The governance quorum threshold is always Byzantine-safe: for
an empty committee the threshold is `0` (nothing to quorum over); for any
non-empty committee of `max_faulty`-tolerant size the threshold is exactly
`2 * max_faulty + 1`; the threshold is monotonically non-decreasing as
`max_faulty` grows; and the arithmetic never overflows (saturates instead) —
so no committee size or fault-tolerance parameter can produce a threshold
that a coalition smaller than `2f + 1` could satisfy.

**Rust symbol(s).**
- `swarm_policy::formal_core::governance_quorum_threshold` (`crates/swarm-policy/src/formal_core.rs:132`).

**Kani harness(es).**
- `kani_governance_quorum_threshold_is_2f_plus_1`.
- `kani_governance_quorum_threshold_is_monotonic_and_saturating`.

**TLA+ invariant (Phase 294 Task 2, not yet written).** The quorum/transition
invariant in `formal/tla/PartitionContingency.tla` (exact name set by Task 2's
design of record) — checks that a modeled governance-quorum state transition
(e.g. healing back from `Partitioned` to `Healthy`, or approving an override)
can only complete once at least `governance_quorum_threshold` votes are
present, over the bounded state machine, not just as a function-level
arithmetic fact.

---

## P6 — Rate-limit boundedness

**Statement.** The per-scope (or per-agent) action rate limiter enforces a
hard ceiling: an action is allowed only when the trailing-60-second window,
pruned of stale entries first, has recorded strictly fewer than
`max_actions_per_scope_per_minute` timestamps; a denied action never records
a new timestamp (denial cannot be worked around by retrying into the same
window); and every timestamp retained after pruning lies within 60,000ms of
`now_ms` — no stale entry can ever count toward the budget.

**Rust symbol(s).**
- `swarm_policy::formal_core::evaluate_rate_limit` (`crates/swarm-policy/src/formal_core.rs:103`).

**Kani harness(es).**
- `kani_rate_limit_allowed_stays_within_limit`.
- `kani_rate_limit_denied_means_budget_full`.
- `kani_rate_limit_retains_only_fresh_timestamps`.

**Existing MAPPING.md invariant.** `PolicyScopeRateLimitDeniesBurst`, with
negative-registry entry `negative_policy_scope_rate_limit_denies_burst`.

---

## Summary table

| Property | One-line guarantee | Rust symbol(s) | Kani harness(es) |
|---|---|---|---|
| P1 | Fail-closed evaluation: malformed input rejected first; every well-formed request reaches a total decision. | `static_gate::StaticApprovalGate::{validate_request,evaluate}`, `formal_core::{severity_floor_denial,human_gate_decision}` | `kani_severity_floor_low_is_sound_for_every_action`, `kani_human_gate_holds_destructive_at_or_above_gate` |
| P2 | Severity-gate soundness: destructive classification and the floor/gate deny/hold decisions agree. | `formal_core::{destructive_action,severity_floor_denial,human_gate_decision}` | `kani_destructive_action_classifies_every_variant`, `kani_severity_floor_low_is_sound_for_every_action`, `kani_human_gate_holds_destructive_at_or_above_gate` |
| P3 | Partition-override receipt integrity: invalid signature, non-Approve, or hash mismatch each independently deny. | `tom_agent::ContingencyLease::verify`, `formal_core::validate_lease_terms` | `kani_model_only_{invalid_signature,non_approve_decision,hash_mismatch}_always_denies`, `kani_model_only_validate_lease_terms_rejects_malformed` |
| P4 | Blast-radius conservation: redeemed scopes never exceed the lease's cap; denial mutates nothing. | `formal_core::{lease_redeem,lease_can_redeem}` | `kani_model_only_blast_radius_conservation`, `kani_model_only_expired_lease_always_denies` |
| P5 | Quorum-transition soundness: threshold is always `2f+1` (0 if empty), monotonic, saturating. | `formal_core::governance_quorum_threshold` | `kani_governance_quorum_threshold_is_2f_plus_1`, `kani_governance_quorum_threshold_is_monotonic_and_saturating` |
| P6 | Rate-limit boundedness: pruned-then-checked-then-recorded budget, denial never records. | `formal_core::evaluate_rate_limit` | `kani_rate_limit_allowed_stays_within_limit`, `kani_rate_limit_denied_means_budget_full`, `kani_rate_limit_retains_only_fresh_timestamps` |

## Trust assumptions this document leans on

Two assumptions (registered in `docs/assurance/assumptions.toml`, Phase 294
Task 1, SAFEP-03) are load-bearing for the properties above:

- **`ASSUME-INJECTED-CLOCK`** — every `formal_core` entry point receives
  `now_ms` as a plain caller-supplied parameter and never reads the OS clock
  itself (the Phase 292 functional-core/imperative-shell result, restated in
  `formal_core`'s own module doc). P1, P2, P4 and P6 all reason about
  `now_ms`-parameterized decisions (`human_gate_decision`'s hold, `lease_redeem`'s
  expiry check, `evaluate_rate_limit`'s window pruning); if the clock feeding
  those functions were adversarially controlled rather than the trusted
  caller's own read, the Kani proofs about "as of `now_ms`" would no longer
  say anything about the wall clock the caller actually intended.
- **`ASSUME-GOVERNOR-KEY-CUSTODY`** — exactly one governor key is registered
  and its custody is not adversarially shared. P3 and P5 both reason about a
  receipt/quorum authority that presumes a single, non-compromised governor
  key set; if custody were shared or the key set larger than registered, the
  signature/quorum checks those properties name would still evaluate
  correctly against the (wrong) input, but the input itself would no longer
  reflect the intended authority.
