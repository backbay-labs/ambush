---
phase: 288
slug: autonomous-detector-response-synthesis
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-08-21
---

# Phase 288 — Validation Strategy

> This is the executable validation contract for bounded detector and advisory response synthesis. It is intentionally independent of candidate output: the corpus, truth manifest, expected relations, and negative controls are authored before implementation and must reject omissions, mutations, and zero-test passes.

## Test Infrastructure

| Property | Value |
|----------|-------|
| Framework | Rust built-in tests through `cargo test`; `proptest` for bounded/digest properties; `trybuild` and source/dependency probes for authority isolation |
| Config/corpus | `scenarios/autonomous-detector-response-synthesis/manifest.yaml` plus four digest-addressed lane fixtures |
| Quick run | `cargo test -p swarm-runtime synthesis --lib` |
| Dedicated gate | `bash tools/check-autonomous-detector-response-synthesis.sh` |
| Full suite | `cargo test --workspace --all-targets --locked && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check` |
| Diff check | `git diff --check` |
| Expected feedback | Focused checks under 90 seconds after warm compilation; the full combined-tree suite is a phase gate |

## Sampling Rate

- After every task commit: run that task's exact automated command, `cargo fmt --all -- --check`, and `git diff --check`.
- After every wave: run `cargo test -p swarm-runtime synthesis --lib`, all completed exact integration tests, and the authority-boundary negative fixture.
- Before phase verification: run the dedicated gate twice, compare deterministic report/packet bytes, then run the full workspace/clippy/format/diff suite.
- No watch-mode flags are allowed. Wall-clock measurements may be retained as observations, never as a candidate verdict, threshold, ranking, or rollback input.

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirements | Test type | Automated command | File exists | Status |
|---------|------|------|--------------|-----------|-------------------|-------------|--------|
| 288-00-01 | 00 | 1 | SYNTH-01..06 | strict contracts/schema | `cargo test -p swarm-runtime --test synthesis_contract strict_contract_rejects_unknown_fields -- --exact` | ❌ W0 | ⬜ pending |
| 288-00-02 | 00 | 1 | SYNTH-01..06 | independent four-lane oracle and withheld capability isolation | `cargo test -p swarm-runtime --test synthesis_contract four_lane_manifest_is_disjoint_and_digest_bound -- --exact && cargo test -p swarm-runtime --test synthesis_contract synthesizer_cannot_dereference_withheld_handle -- --exact` | ❌ W0 | ⬜ pending |
| 288-00-03 | 00 | 1 | SYNTH-01..06 | boundary/gate self-test | `bash tools/check-autonomous-detector-response-synthesis.sh --self-test && cargo test -p swarm-runtime --test negative_synthesis_authority_boundary boundary_checker_rejects_broken_fixture -- --exact` | ❌ W0 | ⬜ pending |
| 288-01-01 | 01 | 2 | SYNTH-01 | typed genome conversion | `cargo test -p swarm-runtime typed_genome_round_trips_all_ten --lib` | ❌ W1 | ⬜ pending |
| 288-01-02 | 01 | 2 | SYNTH-01 | bounded family recipes | `cargo test -p swarm-runtime autonomous_generation_covers_all_ten_families --lib` | ❌ W1 | ⬜ pending |
| 288-01-03 | 01 | 2 | SYNTH-01 | typed materialization/factory | `cargo test -p swarm-runtime typed_genome_materialization_builds_all_ten --lib` | ❌ W1 | ⬜ pending |
| 288-02-01 | 02 | 3 | SYNTH-01 | typed graph/arena input adapter | `cargo test -p swarm-runtime synthesis_detector_input_validation --lib` | ❌ W2 | ⬜ pending |
| 288-02-02 | 02 | 3 | SYNTH-01 | evidence-addressed candidate synthesis | `cargo test -p swarm-runtime synthesis_detector_candidates_preserve_typed_lineage --lib` | ❌ W2 | ⬜ pending |
| 288-02-03 | 02 | 3 | SYNTH-01 | all-family integration | `cargo test -p swarm-runtime --test synthesis_integration detector_candidates_materialize_all_ten_families -- --exact` | ❌ W2 | ⬜ pending |
| 288-03-01 | 03 | 4 | SYNTH-02 | configured vocabulary references | `cargo test -p swarm-runtime synthesis_response_plan_uses_configured_playbook --lib` | ❌ W3 | ⬜ pending |
| 288-03-02 | 03 | 4 | SYNTH-02 | simulated preview/policy/rollback | `cargo test -p swarm-runtime --test synthesis_response response_preview_is_simulated_and_policy_bound -- --exact` | ❌ W3 | ⬜ pending |
| 288-03-03 | 03 | 4 | SYNTH-02 | adapter/authority negative control | `cargo test -p swarm-runtime --test negative_synthesis_authority_boundary response_synthesis_cannot_invoke_adapter -- --exact` | ❌ W3 | ⬜ pending |
| 288-04-01 | 04 | 5 | SYNTH-03 | real replay seam parity | `cargo test -p swarm-runtime replay::tests::synthesis_suite_seam_matches_default_replay --lib` | ❌ W4 | ⬜ pending |
| 288-04-02 | 04 | 5 | SYNTH-03 | four-lane real evaluation | `cargo test -p swarm-runtime --test synthesis_evaluation four_lanes_execute_through_real_replay -- --exact` | ❌ W4 | ⬜ pending |
| 288-04-03 | 04 | 5 | SYNTH-03, SYNTH-06 | metric separation/thresholds | `cargo test -p swarm-runtime --test synthesis_evaluation detector_and_response_metrics_are_separate -- --exact` | ❌ W4 | ⬜ pending |
| 288-05-01 | 05 | 6 | SYNTH-04 | mutation digest controls | `cargo test -p swarm-runtime synthesis_controls_mutations_change_input_digest --lib` | ❌ W5 | ⬜ pending |
| 288-05-02 | 05 | 6 | SYNTH-04 | differential/metamorphic regressions | `cargo test -p swarm-runtime --test synthesis_controls differential_and_metamorphic_controls_fail_closed -- --exact` | ❌ W5 | ⬜ pending |
| 288-05-03 | 05 | 6 | SYNTH-04 | no-op/tamper rejection | `cargo test -p swarm-runtime --test synthesis_controls no_op_or_tampered_control_blocks -- --exact` | ❌ W5 | ⬜ pending |
| 288-06-01 | 06 | 7 | SYNTH-05 | signed immutable packet | `cargo test -p swarm-runtime synthesis_packet_is_signed_and_immutable --lib` | ❌ W6 | ⬜ pending |
| 288-06-02 | 06 | 7 | SYNTH-05, SYNTH-06 | real assurance/solver/canary/quorum handoff | `cargo test -p swarm-runtime --test synthesis_handoff requires_proved_solver_canary_and_operator_quorum -- --exact` | ❌ W6 | ⬜ pending |
| 288-06-03 | 06 | 7 | SYNTH-05 | tamper/baseline negative handoff | `cargo test -p swarm-runtime --test synthesis_handoff rejects_tampered_lineage_and_retains_baseline -- --exact` | ❌ W6 | ⬜ pending |
| 288-07-01 | 07 | 8 | SYNTH-01..06 | exact non-vacuous phase gate | `bash tools/check-autonomous-detector-response-synthesis.sh` | ❌ W7 | ⬜ pending |
| 288-07-02 | 07 | 8 | SYNTH-01..06 | combined-tree repeat/full gate | `bash tools/check-autonomous-detector-response-synthesis.sh && bash tools/check-autonomous-detector-response-synthesis.sh && cargo test --workspace --all-targets --locked && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check && bash tools/check-workspace-layering.sh && bash tools/check-gates-wired.sh && git diff --check` | ❌ W7 | ⬜ pending |
| 288-07-03 | 07 | 8 | SYNTH-01..06 | independent P0/P1/P2 and goal-backward closure | `bash tools/check-autonomous-detector-response-synthesis.sh && python3 -c 'import pathlib,re; text="\n".join(pathlib.Path(p).read_text() for p in [".planning/phases/288-autonomous-detector-response-synthesis/288-P0-P2-REVIEW.md", ".planning/phases/288-autonomous-detector-response-synthesis/288-VERIFICATION.md"]); assert all(re.search(rf"{key}:\s*0\b", text) for key in ("open_p0", "open_p1", "open_p2"))'` | ❌ W7 | ⬜ pending |

## Wave 0 Requirements

- [ ] Strict typed synthesis contracts, schema/version checks, resource budgets, deterministic work-model version, and graph/arena source-reference adapters exist in `crates/swarm-runtime/src/synthesis/`.
- [ ] Independent historical, benign, executable counterexample, and withheld fixtures exist under `scenarios/autonomous-detector-response-synthesis/`; the manifest records lane ownership, class, denominator, digest, and disjointness rules.
- [ ] `crates/swarm-runtime/tests/synthesis_contract.rs` rejects unknown fields, missing/duplicate IDs, missing classes, mixed/default class bypasses, empty evidence, digest drift, overlapping partitions, absent executable counterexamples, and unbounded budgets.
- [ ] `crates/swarm-runtime/tests/negative_synthesis_authority_boundary.rs` proves both clean acceptance and deliberate response/policy/adapter leakage rejection; an absent implementation directory cannot make the checker pass.
- [ ] `tools/check-autonomous-detector-response-synthesis.sh --self-test` proves zero-test/count, renamed-test, missing/extra report field, threshold removal, oracle mutation, authority mutation, and wall-clock-gating failure modes before later behavior exists.
- [ ] `wave_0_complete` remains `false` until the phase executor has actually run and recorded the Wave 0 exact tests; later plans must not flip it merely because files exist.

## Manual-Only Verifications

None are acceptance-only. An operator may inspect the final signed packet for readability, but visual inspection cannot replace signature, digest, lineage, solver, quorum, replay, or full-suite checks.

## Validation Sign-Off

- [x] Every planned task has an automated verification command.
- [x] Sampling continuity has no three consecutive implementation tasks without an automated check.
- [x] Wave 0 owns every missing fixture, test, authority probe, and gate reference.
- [x] Exact test execution counts are asserted so zero-match passes are impossible.
- [x] Detector and response metrics are separate, with deterministic work/resource gates and observational wall-clock latency.
- [x] The acceptance gate requires all four lanes, every control, signed packet revalidation, Proved solver evidence, canary readiness, operator/quorum approval, and retained baseline.
- [x] Final closure requires independent P0/P1/P2 dispositions, zero open severity counters, and a requirement-linked verification artifact.
- [ ] Phase execution evidence is present; `wave_0_complete` intentionally remains false in this planning artifact.

**Approval:** approved for execution 2026-08-21; Wave 0 execution pending.
