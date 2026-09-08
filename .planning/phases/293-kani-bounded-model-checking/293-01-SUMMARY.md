# Phase 293 Plan 01 Summary

Kani Bounded Model Checking (v1.81 Machine-Checked Decision Core). The SECOND v1.81 phase — binds
Kani bounded model checking to the pure, clock-injected decision core phase 292 extracted into
`crates/swarm-policy/src/formal_core.rs`. Executed 2026-09-08 as a 5-task pipeline (T1 scaffolding
+ rate-limit/severity harnesses -> T2 lease integrity + quorum harnesses -> T3 manifest +
completeness gate -> T4 CI runner -> T5 this close). T1 and T2 were independently reviewed before
the next task began; T3 and T4 were controller-authored and fully self-verified (manifest
non-vacuity demonstrated by removing/restoring a row; the CI runner proved end-to-end, 14/14
harnesses verified).

## Delivered

- **Kani scaffolding + rate-limit/severity harnesses (KANI-01, KANI-02; `f0e2067b0`):** an optional,
  dependency-free `kani` feature (`[features] kani = []`) gates a new
  `#[cfg(any(kani, feature = "kani"))] mod kani_public_harnesses;` in `swarm-policy`'s `lib.rs`.
  `crates/swarm-policy/src/kani_public_harnesses.rs` holds the first 5 `#[kani::proof]` functions,
  each calling a real `formal_core` `pub fn` with bounded symbolic inputs: 3 prove
  `evaluate_rate_limit` (allowed stays within limit; denied means the pruned window was already
  full; every retained timestamp lies within the 60,000ms trailing window), 2 prove
  `severity_floor_denial`/`human_gate_decision` (the low-severity floor is sound over all 15
  `ResponseAction` variants; the human-gate holds a destructive action at/above its severity and
  not below). The rate-limit proofs needed `MAX_WINDOW = 3` and a small symbolic timestamp range
  straddling the prune threshold to terminate CBMC's ring-buffer cost within the CI budget. A
  compile-time exhaustiveness guard was added so a 16th `ResponseAction` variant cannot silently
  drop out of the severity harness's coverage. Reviewed clean: 0 Critical, 0 Important, 2 Minor
  (a stale report figure and the exhaustiveness gap, both fixed).
- **Lease integrity + governance quorum harnesses (KANI-03; `86cd1cc41`, review fixes `71fbd08e9`):**
  9 more `#[kani::proof]` functions bring the total to 14. **3 REAL**: `governance_quorum_threshold`
  is `2*max_faulty+1` (always ≥1, monotonic and saturating in `max_faulty`) and
  `destructive_action` classifies every `ResponseAction` variant. **6 MODEL-ONLY**: lease-terms
  rejection, blast-radius conservation across redemption, and expiry-always-denies (the three lease
  predicates originally planned as REAL — see the deviation below), plus the three receipt-crypto
  predicates that were MODEL-ONLY as planned (invalid signature, non-`Approve` decision, and
  proposal-hash mismatch each always deny — the crypto half of `ContingencyLease::verify` lives
  above `swarm-policy`, out of this crate's proof surface). Every MODEL-ONLY harness is labeled and
  names the `formal_core`/`tom_agent` unit test that exercises the real symbol it mirrors. All 14
  harnesses prove `VERIFICATION SUCCESSFUL`. Task 2's review came back **approved-with-nits**: two
  Important findings (the REAL/MODEL-ONLY split diverging from the plan's original assignment
  without a recorded ruling, and two MODEL-ONLY doc comments citing a runtime test that didn't
  actually exercise the modeled property) plus three Minor findings were all addressed in
  `71fbd08e9` — see the deviation note below.
- **Harness manifest + completeness gate (KANI-04; `de0628490`):** `formal/kani/swarm-policy-harnesses.toml`
  lists all 14 harnesses (`name`, `lane`, `model_only`, `runtime_test`, `property`) and
  `crates/swarm-policy/tests/kani_harness_manifest.rs` is a small NORMAL-lane text scanner (no
  Kani install required) that reads the harness source and the manifest as plain text via
  `include_str!` and fails the build if the `#[kani::proof]` function-name set and the manifest's
  `name = "…"` set differ in either direction — a harness added without a manifest row, or a row
  whose harness was renamed or removed. Non-vacuity was demonstrated directly: removing a manifest
  row fails the test naming the offending harness; restoring it passes again.
- **PR-lane CI runner (KANI-05; `df364bc94`):** `scripts/run-kani-swarm-policy.sh` parses the
  manifest for `lane = "pr"` harnesses (all 14 today) and proves each one at a time via
  `cargo kani -p swarm-policy --harness <name>`, scoped to `swarm-policy` (so CBMC never
  code-generates the rest of the workspace) and serial (CBMC is memory-heavy; a parallel run risks
  an OOM kill in CI). A new `kani` job in `.github/workflows/ci.yml` installs
  `kani-verifier 0.67.0`, runs `cargo kani setup`, then runs the script — gated behind the same
  `needs.changes.outputs.engine == 'true'` path filter the other engine-lane jobs use. Verified
  end-to-end: the script itself reports "all 14 pr-lane harness(es) verified", exit 0.
- **Ledger close (this task):** `.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md`, and
  `.planning/STATE.md` updated to record Phase 293 complete and KANI-01..05 satisfaction, with
  STATE.md's frontmatter and body reconciled so neither contradicts the other or
  REQUIREMENTS/ROADMAP.

## The REAL/MODEL-ONLY split deviation, and why it is correct

The plan's Design-of-record originally assigned the lease predicates — blast-radius conservation
across redemption, expiry-always-denies, and `validate_lease_terms` rejection — to the REAL set,
proved directly over the literal `formal_core::{lease_redeem, lease_can_redeem,
validate_lease_terms}` symbols. That did not survive contact with Kani. `lease_redeem`/
`lease_can_redeem` match scopes by `String`, and `validate_lease_terms` builds its reject-path
error messages with `format!`. Kani instruments every heap `String`/`format!` access with
allocation and `memchr` safety checks, and CBMC symbolically executes **all** branches — including
the infeasible `format!` error arms — so those three harnesses did not terminate under any CI
budget: `core::slice::memchr` was observed unwinding past 2800 iterations, with timeouts exceeding
240 seconds even with a fully-concrete redeemed slice and only the cap left symbolic.

**Ruling (recorded in `293-01-PLAN.md`'s Design-of-record and re-confirmed here):** blast-radius
conservation, expiry denial, and `validate_lease_terms` rejection are proved **MODEL-ONLY** instead
— scalar models mirroring the real decision arithmetic exactly, each naming the `formal_core` unit
test that exercises the real symbol (`lease_redeem_records_a_new_scope_within_budget`,
`lease_redeem_fails_closed_on_mismatch_expiry_and_cap`, `lease_can_redeem_denies_an_expired_lease`,
and the `validate_lease_terms_*` tests). ROADMAP Phase 293 Success Criterion 1's ≥8-REAL floor is
still met — with the `format!`-free real functions substituted in: `governance_quorum_threshold`×2
and `destructive_action`×1, alongside the 5 rate-limit/severity harnesses from KANI-02, for 8 REAL
total. The MODEL-ONLY set grows from the originally-planned 3 (receipt crypto) to 6 (receipt crypto
+ the three displaced lease predicates), still within KANI-03's own MODEL-ONLY provision. This is
not a downgrade in what got verified — every one of the 14 harnesses proves `VERIFICATION
SUCCESSFUL` — it is a change in *which* symbols carry a literal Kani proof versus a scalar model
plus a named runtime-test cross-check. Do NOT read this phase as having Kani-proved the real
`lease_redeem`/`validate_lease_terms`; it has not. A reviewer who wants the literal lease-redemption
symbols proved would need Kani function-stubbing of the `String`/`format!` machinery — flagged as a
293 follow-on, not attempted here.

## No path-slip for KANI (unlike DCORE-04)

KANI-04 names `formal/kani/swarm-policy-harnesses.toml` and KANI-05 names
`scripts/run-kani-swarm-policy.sh` — both were used **verbatim**. `scripts/` already exists in this
repo (unlike phase 292's `docs/adr/`/`scripts/` collisions); `formal/` was newly created for this
phase. No path-slip is recorded for Phase 293.

## Task reviews

- **Task 1 review** (KANI-01/KANI-02, `1633ec425..f0e2067b0`): Spec compliance ✅. Code quality
  Approved. 0 Critical, 0 Important, 2 Minor (a stale `MAX_LIMIT` figure in the task report, and a
  `ResponseAction` coverage gap closed with a compile-time exhaustiveness guard). Two spot-run
  harnesses confirmed `VERIFICATION SUCCESSFUL`; non-vacuity confirmed by inspection of every
  `kani::assume`/bound/assertion.
- **Task 2 review** (KANI-03, `9df2ca910..86cd1cc41`): Spec compliance ✅ with one material,
  disclosed deviation (the REAL/MODEL-ONLY split — see above). Code quality Approved-with-nits.
  0 Critical, 2 Important + 3 Minor, **all addressed** in the fix commit `71fbd08e9`: Important #1
  (the split diverged from the plan's original text without a recorded ruling) fixed by adding the
  AS-BUILT DEVIATION to `293-01-PLAN.md`'s Design-of-record; Important #2 (two MODEL-ONLY doc
  comments named a runtime test that didn't actually exercise the modeled property) fixed by
  re-pointing those comments at the `formal_core` unit tests that do. Hard constraints all green
  both before and after the fixes: `cargo build -p swarm-policy` clean, `cargo test -p swarm-policy
  --lib` 39 passed, no dependency leak (`cargo tree` clean of kani/tonic/hyper/reqwest),
  `check-decision-core-boundary.sh`/`check-workspace-layering.sh` exit 0, `cargo fmt --all --check`
  and `cargo clippy -p swarm-policy --all-targets -- -D warnings` both clean. Two spot-run harnesses
  (`kani_governance_quorum_threshold_is_monotonic_and_saturating`,
  `kani_destructive_action_classifies_every_variant`) both `VERIFICATION:- SUCCESSFUL`.

## KANI-04 final verification (this task, on the closing tree)

- `cargo test -p swarm-policy --test kani_harness_manifest` — 1 passed, 0 failed (the completeness
  gate).
- `cargo test -p swarm-policy` — 7 `test result: ok` blocks: 39 lib tests, 1 manifest-completeness
  test, 3 negative-registry tests, and 2 zero-test blocks (loom under non-`--cfg loom`, doc-tests).
  0 failed anywhere.
- `tools/check-gates-wired.sh` — exit 0 (30 gate scripts, all wired).
- `tools/check-decision-core-boundary.sh` — exit 0 (self-test: 4 cases, 1 control + 3 planted, all
  correct; real tree clean).
- `tools/check-workspace-layering.sh` — exit 0 (11 fixture cases: 1 control + 10 deliberately
  broken, all correct; real tree holds).
- One spot Kani run: `cargo kani -p swarm-policy --harness
  kani_governance_quorum_threshold_is_2f_plus_1` — `VERIFICATION:- SUCCESSFUL`.

## Notes

- This is TCB-adjacent work — `swarm-policy` is in the trusted computing base per ADR 0009 — and
  the `kani` feature is dependency-free by construction, so it cannot smuggle a transport or
  telemetry crate into the shipped build; `cargo tree -p swarm-policy` stays clean with the feature
  off (the default) and every task's hard constraints re-confirmed it.
- All 14 harnesses are classified `lane = "pr"` in the manifest; none are `nightly` today. A future
  harness proving a looser or slower bound is the intended use of the `nightly` lane.
- Whole-branch scrutiny of T3 (manifest) and T4 (CI runner) was folded into their own
  self-verification (manifest non-vacuity demonstrated directly; the runner proved end-to-end,
  14/14) rather than a separate reviewer pass, since both are mechanical/deterministic scripts over
  already-reviewed harness content.
- Full session ledger: `.superpowers/sdd/293-01-PLAN/progress.md`,
  `task-1-review.md`, `task-2-review.md`.
