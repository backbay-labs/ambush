---
phase: 288
slug: autonomous-detector-response-synthesis
status: approved
nyquist_compliant: true
wave_0_complete: false
created: 2026-08-21
---

# Phase 288 — Validation Strategy

This is the executable planning contract for bounded detector and advisory
response synthesis. The Phase 288 lane files are an independent oracle; runtime
results must come from the concrete Phase 287 Arena bridge and evidence types.
No missing-file, zero-test, aggregate-score, generic replay, or workflow-banner
shortcut is evidence.

## Test Infrastructure

| Property | Value |
|----------|-------|
| Framework | Rust built-in tests through `cargo test`; typed fixed-point/digest tests; independent Python parser probes |
| Oracle | `scenarios/autonomous-detector-response-synthesis/manifest.yaml` bound to Phase 287 partition/campaign digests |
| Arena bridge | `BlueRuntimeAdapter::run` with candidate and `SignedBlueLearnedState::empty_frozen()` through the six-argument Phase 286 stack |
| Solver invariant | Every signed packet/report contains one present nonempty `EvolutionSolverInvariantArtifact` from `evolution/types.rs`, canonical bytes/digest, existing `attestation_sha256`, and `EvolutionSolverProofStatus::Proved`; absent/disabled/malformed/digest-mismatched/non-Proved mutations fail on revalidation |
| Phase 287 gates | `check-arena-corpus-truth.py --self-test/--check`, `check-arena-config-inventory.sh`, `check-arena-oracles.sh --self-test`, `check-arena-isolation.sh`, `check-adversarial-coevolution-arena.sh`, `parse-arena-report.py`, `check-phase287-review.py` |
| Phase 287 retained-evidence parser | `FINAL_GATE_DIGEST=$(python3 -c 'import json; print(json.load(open("artifacts/phase287/final-gate/final-gate-evidence.json"))["final_gate_evidence_digest"])') && python3 tools/check-phase287-review.py --review-file .planning/phases/287-adversarial-co-evolution-arena/287-P0-P2-REVIEW.md --verification-file .planning/phases/287-adversarial-co-evolution-arena/287-VERIFICATION.md --validation-file .planning/phases/287-adversarial-co-evolution-arena/287-VALIDATION.md --plans-dir .planning/phases/287-adversarial-co-evolution-arena --final-report artifacts/phase287/final-gate/arena-report.json --final-lineage artifacts/phase287/final-gate/arena-lineage.json --final-evidence-manifest artifacts/phase287/final-gate/final-gate-evidence.json --final-gate-evidence-digest "$FINAL_GATE_DIGEST"` |
| Exact Arena suites | `arena_corpus_oracles`, `blue_runtime`, `blue_safety`, `candidate_lineage`, `evaluation_partitions`, `signed_artifacts`, `adversarial_coevolution_arena`, `arena_teardown`; plus exact Red `arena_red_isolation::red_capability_boundary_is_nonvacuous` |
| Phase 288 gate | `bash tools/check-autonomous-detector-response-synthesis.sh` |
| Exact run invocation | `bash tools/check-autonomous-detector-response-synthesis.sh --run-id run-1 --artifact-dir artifacts/synthesis/run-1 --output-manifest artifacts/synthesis/run-1/manifest.json --tree-scope . --require-current-head --require-frozen-tree` (repeat with `run-2`) |
| Signed report truth | `python3 tools/parse-arena-report.py artifacts/synthesis/run-1/arena-report.signed.json` (repeat for `run-2`; signed report is a required positional argument) |
| Red isolation truth | `CARGO_NET_OFFLINE=true bash tools/check-arena-isolation.sh --self-test && CARGO_NET_OFFLINE=true bash tools/check-arena-isolation.sh && cargo test -p swarm-arena-red --test arena_red_isolation --locked --offline -- --exact red_capability_boundary_is_nonvacuous` (the exact test must execute nonzero and report `ignored == 0`; absent/non-running fails) |
| Corpus truth | `python3 tools/check-arena-corpus-truth.py --self-test && python3 tools/check-arena-corpus-truth.py --check` plus `cargo test -p swarm-arena --test arena_corpus_oracles --locked --offline -- --test-threads=1` and `python3 tools/check-phase288-validation-map.py --plans-dir .planning/phases/288-autonomous-detector-response-synthesis --validation .planning/phases/288-autonomous-detector-response-synthesis/288-VALIDATION.md --require-wave-0-pending --require-exact-task-rows` |
| Full combined tree | `cargo test --workspace --all-targets --locked --offline`, all-features clippy `-D warnings`, format, layering, negative registry, fixture freshness, panic contract, gate wiring, and diff check |
| Feedback | Focused tests target exact names; no watch mode; wall-clock latency is observation-only |

## Sampling Rate

- After every task: run its exact automated command, `cargo fmt --all -- --check`, and `git diff --check`.
- After every wave: run all completed exact task commands plus the Phase 287 arena/config/parser gates and the authority-boundary negative fixture.
- Before closure: run Phase 287 gates and all exact Arena suites on the same combined tree, run the Phase 288 gate twice, mechanically compare canonical artifacts, then run the full combined-tree suite and independent review parser.
- No command may use watch mode, `--ignored`, `|| true`, file-exists-only success, or an unlocked Cargo invocation.

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirements | Test type | Automated command | File exists | Status |
|---------|------|------|--------------|-----------|-------------------|-------------|--------|
| 288-00-01 | 00 | 1 | SYNTH-01..06 | strict contract schema | `cargo test -p swarm-runtime --test synthesis_contract strict_contract_rejects_unknown_fields --locked --offline -- --exact` | ❌ W0 | ⬜ pending |
| 288-00-02 | 00 | 1 | SYNTH-01..06 | full signed-source envelope | `cargo test -p swarm-runtime --test synthesis_contract signed_state_envelope_validation_is_complete --locked --offline -- --exact` | ❌ W0 | ⬜ pending |
| 288-00-03 | 00 | 1 | SYNTH-01..06 | authority/gate mutation | `bash tools/check-autonomous-detector-response-synthesis.sh --self-test && cargo test -p swarm-runtime --test negative_synthesis_authority_boundary boundary_checker_rejects_broken_fixture --locked --offline -- --exact` | ❌ W0 | ⬜ pending |
| 288-00A-01 | 00A | 2 | SYNTH-01..06 | four-lane oracle | `cargo test -p swarm-runtime --test synthesis_contract four_lane_manifest_is_disjoint_and_digest_bound --locked --offline -- --exact` | ❌ W0 | ⬜ pending |
| 288-00A-02 | 00A | 2 | SYNTH-01..06 | oracle/withheld mutation | `cargo test -p swarm-runtime --test synthesis_contract synthesizer_cannot_dereference_withheld_handle --locked --offline -- --exact && cargo test -p swarm-runtime --test synthesis_contract oracle_mutations_fail_closed --locked --offline -- --exact` | ❌ W0 | ⬜ pending |
| 288-00A-03 | 00A | 2 | SYNTH-01..06 | validation-map exact rows | `python3 tools/check-phase288-validation-map.py --plans-dir .planning/phases/288-autonomous-detector-response-synthesis --validation .planning/phases/288-autonomous-detector-response-synthesis/288-VALIDATION.md --require-wave-0-pending --require-exact-task-rows` | ❌ W0 | ⬜ pending |
| 288-01-01 | 01 | 3 | SYNTH-01 | exact ten-family genome | `cargo test -p swarm-runtime --lib --locked --offline -- --exact typed_genome_round_trips_all_ten` | ❌ W1 | ⬜ pending |
| 288-01-02 | 01 | 3 | SYNTH-01 | exact ten-family recipes | `cargo test -p swarm-runtime --lib --locked --offline -- --exact autonomous_generation_covers_all_ten_families` | ❌ W1 | ⬜ pending |
| 288-01-03 | 01 | 3 | SYNTH-01 | exact ten-family factory | `cargo test -p swarm-runtime --lib --locked --offline -- --exact typed_genome_materialization_builds_all_ten` | ❌ W1 | ⬜ pending |
| 288-02-01 | 02 | 4 | SYNTH-01 | concrete Arena adapter | `cargo test -p swarm-arena --test synthesis_adapter real_blue_runtime_adapter_preserves_phase286_capture_and_signed_sources --locked --offline -- --exact` | ❌ W2 | ⬜ pending |
| 288-02-02 | 02 | 4 | SYNTH-01 | typed evidence lineage | `cargo test -p swarm-runtime --test synthesis_integration synthesis_detector_candidates_preserve_typed_lineage --locked --offline -- --exact` | ❌ W2 | ⬜ pending |
| 288-02-03 | 02 | 4 | SYNTH-01 | four-family real Blue admission plus six-family factory-only materialization | `cargo test -p swarm-runtime --test synthesis_integration detector_candidates_materialize_all_ten_families --locked --offline -- --exact && cargo test -p swarm-arena --test synthesis_adapter learned_state_change_requires_direct_blue_outcome_change --locked --offline -- --exact` | ❌ W2 | ⬜ pending |
| 288-03-01 | 03 | 5 | SYNTH-02 | configured response vocabulary | `cargo test -p swarm-runtime --test synthesis_response synthesis_response_plan_uses_configured_playbook --locked --offline -- --exact` | ❌ W3 | ⬜ pending |
| 288-03-02 | 03 | 5 | SYNTH-02 | pure policy/rehearsal preview | `cargo test -p swarm-runtime --test synthesis_response response_preview_is_simulated_and_policy_bound --locked --offline -- --exact` | ❌ W3 | ⬜ pending |
| 288-03-03 | 03 | 5 | SYNTH-02 | authority and stable plan ID | `cargo test -p swarm-runtime --test negative_synthesis_authority_boundary response_synthesis_cannot_invoke_adapter --locked --offline -- --exact && cargo test -p swarm-runtime --test synthesis_response response_plan_digest_ignores_display_time_but_binds_lineage --locked --offline -- --exact` | ❌ W3 | ⬜ pending |
| 288-04-01 | 04 | 6 | SYNTH-03 | real candidate/control Arena lanes | `cargo test -p swarm-arena --test synthesis_evaluation_bridge four_lanes_use_real_blue_bridge_for_candidate_and_empty_frozen_control --locked --offline -- --exact` | ❌ W4 | ⬜ pending |
| 288-04-02 | 04 | 6 | SYNTH-03 | lane denominators/pairs | `cargo test -p swarm-runtime --test synthesis_evaluation four_lanes_preserve_independent_denominators_and_pair_digests --locked --offline -- --exact` | ❌ W4 | ⬜ pending |
| 288-04-03 | 04 | 6 | SYNTH-03,SYNTH-06 | separated metric thresholds | `cargo test -p swarm-runtime --test synthesis_evaluation detector_and_response_metrics_are_separate --locked --offline -- --exact` | ❌ W4 | ⬜ pending |
| 288-05-01 | 05 | 7 | SYNTH-04 | real mutation inputs | `cargo test -p swarm-runtime --test synthesis_controls synthesis_controls_mutations_change_input_digest --locked --offline -- --exact && cargo test -p swarm-arena --test synthesis_controls_bridge controls_use_real_arena_bridge --locked --offline -- --exact` | ❌ W5 | ⬜ pending |
| 288-05-02 | 05 | 7 | SYNTH-04 | differential/metamorphic | `cargo test -p swarm-runtime --test synthesis_controls differential_and_metamorphic_controls_fail_closed --locked --offline -- --exact` | ❌ W5 | ⬜ pending |
| 288-05-03 | 05 | 7 | SYNTH-04 | tamper/repeat controls | `cargo test -p swarm-runtime --test synthesis_controls no_op_or_tampered_control_blocks --locked --offline -- --exact && cargo test -p swarm-arena --test synthesis_controls_bridge repeated_controls_have_identical_canonical_bytes --locked --offline -- --exact` | ❌ W5 | ⬜ pending |
| 288-06-01 | 06 | 8 | SYNTH-05 | signed immutable packet | `cargo test -p swarm-runtime --test synthesis_handoff synthesis_packet_is_signed_and_immutable --locked --offline -- --exact` | ❌ W6 | ⬜ pending |
| 288-06-02 | 06 | 8 | SYNTH-05,SYNTH-06 | present nonempty solver-invariant Proved/absence-disabled-malformed-non-Proved mutation and approval handoff | `cargo test -p swarm-runtime --test synthesis_handoff requires_proved_solver_canary_and_operator_quorum --locked --offline -- --exact` | ❌ W6 | ⬜ pending |
| 288-06-03 | 06 | 8 | SYNTH-05 | independent review parser | `python3 tools/parse-synthesis-review.py --self-test && python3 tools/compare-synthesis-artifacts.py --self-test && python3 tools/compute-synthesis-tree-digest.py --self-test && cargo test -p swarm-runtime --test synthesis_handoff review_parser_rejects_duplicate_or_nonzero_rows --locked --offline -- --exact` | ❌ W6 | ⬜ pending |
| 288-07-01 | 07 | 9 | SYNTH-01..06 | exact Phase 287/288 gate | `bash tools/check-autonomous-detector-response-synthesis.sh --self-test && cargo test -p swarm-runtime --test synthesis_phase_gate --locked --offline -- --exact phase_gate_requires_real_arena_evidence` | ❌ W7 | ⬜ pending |
| 288-07-02 | 07 | 9 | SYNTH-01..06 | exact repeat/canonical/full frozen tree | `bash tools/check-autonomous-detector-response-synthesis.sh --run-id run-1 --artifact-dir artifacts/synthesis/run-1 --output-manifest artifacts/synthesis/run-1/manifest.json --tree-scope . --require-current-head --require-frozen-tree && bash tools/check-autonomous-detector-response-synthesis.sh --run-id run-2 --artifact-dir artifacts/synthesis/run-2 --output-manifest artifacts/synthesis/run-2/manifest.json --tree-scope . --require-current-head --require-frozen-tree && python3 tools/parse-arena-report.py artifacts/synthesis/run-1/arena-report.signed.json && python3 tools/parse-arena-report.py artifacts/synthesis/run-2/arena-report.signed.json && python3 tools/compare-synthesis-artifacts.py --first artifacts/synthesis/run-1 --second artifacts/synthesis/run-2 --allow-observation-fields && cargo test --workspace --all-targets --locked --offline && cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings && cargo fmt --all -- --check && bash tools/check-workspace-layering.sh && bash tools/check-negative-registry.sh && bash tools/check-fixture-freshness.sh && bash tools/check-runtime-panic-contract.sh && bash tools/check-gates-wired.sh && git diff --check` | ❌ W7 | ⬜ pending |
| 288-07-03 | 07 | 9 | SYNTH-01..06 | independent closure | `python3 tools/parse-synthesis-review.py --self-test && python3 tools/parse-synthesis-review.py --review-file .planning/phases/288-autonomous-detector-response-synthesis/288-P0-P2-REVIEW.md --verification-file .planning/phases/288-autonomous-detector-response-synthesis/288-VERIFICATION.md --require-current-head --require-combined-tree --require-independent-review --require-exact-rows && python3 tools/compare-synthesis-artifacts.py --first artifacts/synthesis/run-1 --second artifacts/synthesis/run-2 --allow-observation-fields && git diff --check` | ❌ W7 | ⬜ pending |

## Wave 0 Requirements

- [ ] Strict `ArenaSynthesisInput`/source-role/schema/canonical-ID/content-digest contracts and full signed envelope validation exist before candidate code.
- [ ] Independent four-lane manifest/fixtures, nonzero denominators, executable counterexamples, Phase 287 partition digests, and opaque withheld handles exist before evaluation.
- [ ] Authority-boundary and gate self-tests reject response/dispatch/policy/live/withheld/generic-replay leakage and zero-test/missing-field/threshold/oracle mutations.
- [ ] `wave_0_complete` remains `false` until the executor records the exact Wave 0 commands as green; file existence is not evidence.

## Combined-tree Phase 287 gate inventory

The final gate must invoke, in the same combined tree, `python3 tools/check-arena-corpus-truth.py --self-test`
and `python3 tools/check-arena-corpus-truth.py --check`, then
`check-arena-config-inventory.sh`
(including its two config-literal halves), `check-arena-oracles.sh --self-test`,
`CARGO_NET_OFFLINE=true bash tools/check-arena-isolation.sh --self-test` and the
same normal command, `check-adversarial-coevolution-arena.sh --self-test` and
normal mode, `python3 tools/parse-arena-report.py artifacts/synthesis/run-1/arena-report.signed.json`
(and the run-2 positional signed report), and `check-phase287-review.py` with
current review/verification/validation artifacts and the exact retained final
evidence arguments:
`FINAL_GATE_DIGEST=$(python3 -c 'import json; print(json.load(open("artifacts/phase287/final-gate/final-gate-evidence.json"))["final_gate_evidence_digest"])') && python3 tools/check-phase287-review.py --review-file .planning/phases/287-adversarial-co-evolution-arena/287-P0-P2-REVIEW.md --verification-file .planning/phases/287-adversarial-co-evolution-arena/287-VERIFICATION.md --validation-file .planning/phases/287-adversarial-co-evolution-arena/287-VALIDATION.md --plans-dir .planning/phases/287-adversarial-co-evolution-arena --final-report artifacts/phase287/final-gate/arena-report.json --final-lineage artifacts/phase287/final-gate/arena-lineage.json --final-evidence-manifest artifacts/phase287/final-gate/final-gate-evidence.json --final-gate-evidence-digest "$FINAL_GATE_DIGEST"`.
The gate recomputes `phase287_evidence_digest` as
`SHA256(canonical_json_bytes(arena-report.json) || "\n" ||
canonical_json_bytes(arena-lineage.json) || "\n" ||
canonical_json_bytes(final-gate-evidence.json))` and binds it into each run
manifest, signed packet/report, and both review artifacts; any missing,
altered, replaced, or noncanonical retained byte fails. It must also run the exact
corpus truth suite and validation-map command listed above. The gate manifest
must expose run ownership, all canonical output paths, `head_oid`, the frozen
allowlist tree digest, and immutable `phase287_evidence_digest`.
It must run the exact Arena suites `arena_corpus_oracles`, `blue_runtime`,
`blue_safety`, `candidate_lineage`, `evaluation_partitions`, `signed_artifacts`,
`adversarial_coevolution_arena`, and `arena_teardown`, plus
`cargo test -p swarm-arena-red --test arena_red_isolation --locked --offline -- --exact red_capability_boundary_is_nonvacuous`; every named suite and this exact
Red test require nonzero execution/passed counts and `ignored == 0`, and
absence/non-running/zero-match fails. It also runs workspace layering, negative-registry,
fixture-freshness, runtime-panic, gate-wiring, full locked/offline tests/clippy,
format, and `git diff --check`.

## Manual-Only Verifications

None are acceptance-only. An operator may read the final signed packet and review
rows, but visual inspection cannot replace exact parser, signature, digest,
lineage, solver, quorum, lane, control, or combined-tree evidence.

## Validation Sign-Off

- [x] Every planned task has an automated verification command.
- [x] Every Cargo command is locked/offline and every test filter is exact or targets a named suite.
- [x] Sampling continuity has no three consecutive implementation tasks without an automated check.
- [x] Wave 0 owns contracts, corpus, withheld boundary, authority probe, and gate references while remaining pending.
- [x] Candidate/control evaluation requires actual Phase 287 Arena bridge evidence and concrete Arena `PairReport`/empty-frozen pairing converted once to Runtime-owned views.
- [x] Mutation/differential/metamorphic controls require changed canonical bytes and fail closed on no-op/tamper.
- [x] Review parser requires exactly one `review_row` for every fixed task/requirement/artifact key, current HEAD/tree, disjoint owner/reviewer, immutable Phase 287 evidence digest, and zero-open counters.
- [x] Review cardinality is exact: each review artifact has 35 structured rows (27 task + 6 requirement + 2 artifact keys) and exactly one anchored zero counter for each P0/P1/P2 severity.
- [x] Phase execution evidence is not present; `wave_0_complete` intentionally remains false.

**Approval:** repaired for execution 2026-08-23; Phase 287 bridge and Phase 288 Wave 0 execution evidence pending.
