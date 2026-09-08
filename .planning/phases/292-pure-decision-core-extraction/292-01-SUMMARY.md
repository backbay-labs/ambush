# Phase 292 Plan 01 Summary

Pure Decision Core Extraction (v1.81 Machine-Checked Decision Core). The FIRST v1.81 phase — the
prerequisite for Kani bounded model checking (293) and named safety properties (294): a proof
apparatus needs an IO-free decision surface. Executed 2026-09-08 with subagent-driven-development
as a sequential 4-task pipeline (T1 -> T2 -> T3 -> T4, not parallel — the extraction is
interdependent). Every task was independently reviewed before the next began; all three
implementation-task reviews came back clean (0 Critical / 0 Important).

## Delivered

- **Pure rate-limit core (DCORE-01; `eb64f7c85`):** `crates/swarm-policy/src/formal_core.rs`
  (new) lifts the prune-then-check-then-record rate-limit decision that
  `StaticApprovalGate::scope_rate_limit_decision` and
  `ConfigurableApprovalGate::agent_limit_exceeded` each implemented separately into one pure,
  total function, `evaluate_rate_limit(window, now_ms, limit) -> (RateLimitOutcome, window)`.
  It takes the window and the clock as plain values and returns the decision plus the window
  exactly as the caller should store it back — no `Mutex`, `fs`, clock read, network, `panic!`,
  or unbounded recursion in its body. Both gates keep their
  `Arc<Mutex<HashMap<String, VecDeque<i64>>>>` at the edge: under the lock they take the window
  out with `mem::take`, hand it to the pure core, and write the returned window back before
  releasing the lock. No verdict changes for any input — all 20 pre-existing `static_gate` and
  `configurable_gate` tests plus the three 285 negative-registry tests pass unchanged.
- **Governance predicates ported down the dep graph (DCORE-02; `f5cb3d8df`):** the governance
  authorization predicates that used to live in `swarm-agents/src/tom_agent.rs` — the partition
  branch of `GovernancePolicy::can_act`, `ContingencyLease::{verify,can_redeem,redeem}`,
  `governance_quorum_threshold` — are ported into `swarm-policy::formal_core` as pure, total,
  clock-injected functions (`governance_quorum_threshold(total_governors, max_faulty)` with
  `max_faulty` now caller-supplied so the 3f+1 model / `swarm-consensus` never enters this crate;
  a receipt-free `LeaseTerms<'a>` view plus `lease_matches_action`, `action_scope_key`,
  `lease_can_redeem`, `lease_redeem` (-> `LeaseRedeemOutcome`), `validate_lease_terms`). The move
  is cycle-free: `swarm-policy` depends only on `swarm-core`, and `swarm-agents` already depends
  on `swarm-policy`, so lifting predicate logic DOWN into `swarm-policy::formal_core` adds no
  edge. `ContingencyLease` itself did not move — it still embeds a `ConsensusGovernanceReceipt`,
  and that cryptographic half of `verify()` (signature check, `Approve`-decision check,
  proposal-hash rebuild) deliberately stays in `swarm-agents`, calling the new pure functions
  with the clock supplied explicitly. Every verdict is identical to before for every input.
- **The decision-core dependency boundary — ADR + gate (DCORE-03/04; `49121d577`):**
  `tools/check-decision-core-boundary.sh` reads `swarm-policy`'s resolved NORMAL dependency
  graph via `cargo metadata` (fast, resolves without compiling) and fails if `axum`, `hyper`,
  `tokio-rustls`, `reqwest`, any `opentelemetry*` crate, `clap`, or `x509-parser` is reachable —
  catching a forbidden crate smuggled in transitively through `swarm-core`, which a manifest
  grep cannot see (the ADR 0008/0009 lesson). Every invocation self-tests the same
  `scan_forbidden()` function against synthetic in-memory graphs (a clean control, a direct
  plant, a two-hop "smuggled behind swarm-core" plant, and an `opentelemetry*`-prefix plant)
  before trusting it to judge the real graph, and touches no real `Cargo.toml`/`Cargo.lock`.
  `docs/decisions/0012-decision-core-boundary.md` records the boundary, the forbidden list and
  why each entry belongs, and that the gate enforces it in CI. Wired into the `panic-contract`
  job of `.github/workflows/ci.yml`, right after the TCB layering check, so
  `check-gates-wired.sh` stays green. DCORE-03 was ENFORCE-only: `swarm-policy`'s dependency
  graph was already clean of all seven forbidden crates before this task; no removal was
  needed.
- **Ledger close (this task; DCORE-05 final verification):** `.planning/REQUIREMENTS.md`,
  `.planning/ROADMAP.md`, and `.planning/STATE.md` updated to record Phase 292 complete and the
  DCORE-01..05 satisfaction, with STATE.md's frontmatter and body reconciled so neither
  contradicts the other or REQUIREMENTS/ROADMAP.
- **Severity predicates extracted, completing SC1 (`0f3fa0207`):** a whole-branch
  review found Success Criterion 1 enumerates a `severity` predicate the pure core should hold,
  but the severity gating still lived inline in `static_gate::evaluate`. The three severity
  decisions — the `static.minimum_severity` and `static.deploy_decoy_min_severity` floors and
  the `static.human_gate` hold — were lifted into `formal_core` as `severity_floor_denial`
  (both floors, in their exact original order and with identical rule names + reason strings)
  and `human_gate_decision`, together with the `destructive_action` classifier they both read
  (moved out of `StaticApprovalGate`, leaving no duplicate body behind — `evaluate` now
  delegates to the pure functions in the identical order: floor denials → scope rate limit →
  human-gate hold → default allow). The `PolicyHumanGateOnDestructiveAction` invariant marker
  and its `docs/assurance/MAPPING.md` row moved with the human gate to
  `formal_core::human_gate_decision`; `check-mapping.sh` and `check-negative-registry.sh` stay
  green (the negative test still asserts `RequireHuman`). No verdict changes for any input — all
  pre-existing `static_gate` tests (incl. `low_severity_isolation_is_denied`, the human-gate and
  deploy_decoy tests) pass UNCHANGED, plus new `formal_core` unit tests for each predicate. This
  makes SC1 literally true and gives phase 293's Kani severity-gate harness a pure surface.

## The functional-core / imperative-shell deviation, and why it is correct

`GovernancePolicy::can_act`'s public signature — `fn can_act(&self, action: &ResponseAction) ->
GovernanceDecision` — is depended on by many call sites across `swarm-agents` and `swarm-runtime`,
and DCORE-05 pins the governance tests that exercise it UNCHANGED. Rewriting `can_act` itself to
take `now_ms` as a parameter would break that signature everywhere. Instead, Task 2 split it in
two: `can_act` is kept as a one-line clock-reading wrapper —

```rust
pub fn can_act(&self, action: &ResponseAction) -> GovernanceDecision {
    self.can_act_at(action, now_ms())
}
```

— and the entire decision body that used to live directly in `can_act` (the destructive-action
short-circuit, the governor-key veto, the partition/lease branch, the health-based approve/veto,
receipt issuance) moved verbatim into a new private `can_act_at(&self, action, now_ms: i64)`,
which reads no clock itself and calls `formal_core::lease_can_redeem` with `now_ms` supplied
explicitly. This satisfies DCORE-02's actual text — "the clock is caller-supplied at every entry
into `formal_core`" — because every `formal_core` call `can_act_at` makes receives `now_ms` as a
plain argument; the one remaining OS-clock read is confined to the single line inside `can_act`,
exactly the same "Mutex-at-the-edge" shape DCORE-01 uses for the rate-limit gates. `can_act_at` is
the real, clock-free proof surface phase 293's Kani harnesses and phase 294's named properties
will target; `can_act` is an unavoidably impure thin shell over it, preserved only because its
signature is load-bearing. Task 2's independent review confirmed the split is behaviourally
equivalent for every input (the only observable delta is that the clock is now read at `can_act`'s
entry rather than lazily inside the old partition branch — a microsecond-scale shift the
governance tests, which use >=1000ms margins, cannot see) and endorsed it as the correct resolution
of the SC2/DCORE-05 tension.

## DCORE-04 path-slip

The requirement text (REQUIREMENTS.md:912) names `docs/adr/ADR-0002-decision-core-boundary.md`
plus `scripts/check-decision-core-boundary.sh`. Per the controller's Design-of-record ruling —
the same ruling as phases 283, 285, and 291 — the real artifacts are
`docs/decisions/0012-decision-core-boundary.md` (repo convention: ADRs live in
`docs/decisions/NNNN-…`, numbered 0001-0011 before this one) and
`tools/check-decision-core-boundary.sh` (repo convention: gates live in `tools/check-*.sh` so
`check-gates-wired.sh` — which only scans `tools/` — can see them; a gate at the requirement's
`scripts/` path would have been invisible to it). DCORE-04 is marked Satisfied citing the real
paths, with the slip recorded in REQUIREMENTS.md, ROADMAP.md, and ADR 0012 itself, per the
audit-trail convention: the requirement's original wording is preserved, not overwritten.

## DCORE-05 final verification (this task, on the closing tree)

- `cargo test -p swarm-policy` — 31 passed, 0 failed (unit tests; `loom_concurrent_decision` and
  the three negative-registry tests also pass, 0 in each when not run under `--cfg loom`).
- `cargo test -p swarm-agents` — 17 lib tests + 7 `governance_single_key.rs` tests, 0 failed.
- `tools/check-decision-core-boundary.sh` — exit 0 (self-test: 4 cases, 1 control + 3 planted, all
  correct; real tree clean).
- `tools/check-mapping.sh` — exit 0 (17 rows, 17 markers).
- `tools/check-negative-registry.sh` — exit 0.
- `tools/check-gates-wired.sh` — exit 0 (30 gate scripts, all wired; `check-decision-core-boundary.sh`
  confirmed wired into `ci.yml`'s `panic-contract` job).
- `tools/check-workspace-layering.sh` — exit 0 (11 fixture cases: 1 control + 10 deliberately
  broken, all correct; real tree holds).

Every pre-existing `static_gate`, `configurable_gate`, and `tom_agent` governance test passes
UNCHANGED against the new call paths, and every fail-closed invariant this phase's extraction
touched (`PolicyScopeRateLimitDeniesBurst`, now mapped to `formal_core::evaluate_rate_limit` in
`docs/assurance/MAPPING.md`) still resolves.

## Notes

- This is TCB-adjacent work — `swarm-policy` is in the trusted computing base per ADR 0009 — and
  was reviewed as a security change at every task, per the plan's global constraints.
- `formal_core.rs` is now 500 lines and is the intended target for phase 293's `#[kani::proof]`
  harnesses (`evaluate_rate_limit`, `governance_quorum_threshold`, `lease_can_redeem`,
  `lease_redeem`, `validate_lease_terms`, plus `swarm-agents::tom_agent::can_act_at` as the
  clock-injected governance entry point) and phase 294's named safety properties (P1-P6).
- Whole-branch review across all four tasks is recorded in
  `.superpowers/sdd/292-01-PLAN/task-{1,2,3}-review.md`; merge to `main` follows this close.
