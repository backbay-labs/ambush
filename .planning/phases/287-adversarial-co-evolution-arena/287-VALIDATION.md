---
phase: 287
slug: adversarial-co-evolution-arena
status: approved
nyquist_compliant: true
preflight_complete: false
wave_0_complete: false
preflight_execution_waves: "1-5"
execution_waves: "6-13"
created: 2026-08-21
---

# Phase 287 — Validation Strategy

> This validation contract is written before arena behavior. `wave_0_complete`
> has one unambiguous meaning here: the Phase 287 preflight bundle (Plans 00,
> 00A, 00B, 00C, 00D, 00E, 00F, 00G, and 00H) has passed its independent
> contract, corpus, registry, compile-fail, exact-count, config-inventory, and
> mutation self-tests on the combined tree. It is a logical preflight marker,
> not a GSD execution-wave number. Plan 00 runs in wave 1, 00A in wave 2,
> 00C/00D/00F in wave 3, 00B/00G/00H in wave 4, and 00E in wave 5; each
> dependent plan is assigned `max(dependency waves) + 1` (ignoring only the
> completed cross-phase prerequisite 286-07B);
> `preflight_complete` and `wave_0_complete` stay `false` until all nine are
> green. Plan 00E is the final scanner after both migration halves. Implementation execution waves are 6–13.

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust 2024 `cargo test`, `proptest`, `trybuild`, and credential-free shell/Python gates |
| **Config** | Workspace `Cargo.toml`; `SwarmConfig::arena.run_root`; immutable `scenarios/adversarial-coevolution-arena/` catalog, oracle registry, baseline, fingerprint set, and four partition manifests |
| **Quick Red** | `cargo test -p swarm-arena-red --lib --locked --offline -- --test-threads=1` |
| **Quick arena** | `cargo test -p swarm-arena --lib --locked --offline -- --test-threads=1` |
| **Runtime integration** | `cargo test -p swarm-arena --test adversarial_coevolution_arena --locked --offline -- --test-threads=1` |
| **Independent report parser** | `python3 tools/parse-arena-report.py <signed-report>` |
| **Final config inventory** | `bash tools/check-arena-config-inventory.sh` (invokes both migration helpers and the AST-aware 24-site/23-path oracle) |
| **Isolation gate** | `CARGO_NET_OFFLINE=true bash tools/check-arena-isolation.sh` |
| **Phase gate** | `CARGO_NET_OFFLINE=true bash tools/check-adversarial-coevolution-arena.sh` |
| **Full combined-tree gate** | `cargo test --workspace --all-targets --locked --offline && cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings && cargo fmt --all -- --check` |
| **Determinism rule** | Virtual campaign time, deterministic work units, canonical bytes, BTree ordering, fixed signer/sequence, and frozen common-input digests; wall-clock is guard/observation only |
| **TDD rule** | Every implementation task owns a failing behavior/negative test before production code; no skipped/ignored test, placeholder, `todo!`, `unimplemented!`, or no-op success path |

## Canonical measurement arithmetic

All verdict arithmetic is checked integer arithmetic. Virtual time is integer
milliseconds; blast radius is integer asset-impact units; scores are basis
points. Improvement uses floor division and loss uses ceiling division:

```text
time_improvement_bp = (control_median_virtual_ms - learned_median_virtual_ms)
                      * 10_000 / control_median_virtual_ms
require control_median_virtual_ms > 0 and time_improvement_bp >= 1_500

blast_radius_delta_units = learned_median_asset_impact_units
                           - control_median_asset_impact_units
require blast_radius_delta_units <= 0

learning_improvement_bp = (learned_score_bp - control_score_bp)
                          * 10_000 / control_score_bp
require control_score_bp > 0 and learning_improvement_bp >= 1_000

withheld_loss_bp = (in_sample_score_bp - withheld_score_bp)
                   * 10_000 / in_sample_score_bp
require in_sample_score_bp > 0 and withheld_loss_bp <= 500
```

Unseen evasion is a measured Blue escape/falsification whose normalized
fingerprint is absent from the frozen known set. The exact fingerprint is
`tactic_id|technique_id|fixture_primitive|order_relation|timing_bucket`; event
IDs, generation IDs, worker counts, and agent counts are not fingerprints.

## Sampling Rate

- **After every task:** Run its named automated check, `cargo fmt --all -- --check`, and `git diff --check` with all Cargo commands locked/offline.
- **After every execution wave:** Run Quick Red/arena checks plus all exact integration tests completed in that wave; run the independent parser when a report exists.
- **Before phase closure:** Run the phase gate twice, compare deterministic report/lineage bytes, run the full combined-tree gate and all authority/cleanup checks, then obtain independent P0/P1/P2 review.
- **Max targeted feedback latency:** 90 seconds after warm compilation; full workspace is an explicit final-wave check.
- **No watch mode:** Every command is bounded, non-interactive, credential-free, and uses `--locked --offline` for dependency resolution.

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 287-00-01 | 00 | 1 | ARENA-01, ARENA-03, ARENA-04, ARENA-06, ARENA-08 | contract/dependency boundary TDD | `cargo metadata --format-version 1 --locked --offline && cargo check -p swarm-arena-red -p swarm-arena --locked --offline && cargo test -p swarm-arena-red --lib --locked --offline -- --test-threads=1 && cargo test -p swarm-arena --lib --locked --offline -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-00-02 | 00 | 1 | ARENA-02, ARENA-06, ARENA-08 | Arena-owned six-file ArenaConfig package-boundary compile contract | `cargo check -p swarm-arena-red -p swarm-arena --locked --offline && cargo test -p swarm-arena --lib --locked --offline -- --exact arena_config_package_boundary_is_canonical && git diff --check` | ❌ W0 | ⬜ pending |
| 287-00A-01 | 00A | 2 | ARENA-02, ARENA-06, ARENA-08 | ArenaConfig default/validation/admission-order TDD | `cargo test -p swarm-core config --lib --locked --offline && cargo fmt --all -- --check && git diff --check` | ❌ W0 | ⬜ pending |
| 287-00B-01 | 00B | 4 | ARENA-01, ARENA-05, ARENA-07, ARENA-08 | immutable corpus/registry/fingerprint parser/verifier TDD | `cargo test -p swarm-arena --test arena_corpus_oracles --locked --offline -- --exact corpus_manifest_is_strict && cargo test -p swarm-arena --test arena_corpus_oracles --locked --offline -- --exact corpus_oracle_rejects_mutation` | ❌ W0 | ⬜ pending |
| 287-00B-02 | 00B | 4 | ARENA-01, ARENA-06, ARENA-08 | exact-count/ignored-zero/compile-fail isolation TDD | `bash tools/check-arena-oracles.sh --self-test && cargo test -p swarm-arena-red --test arena_red_isolation --locked --offline -- --exact red_capability_boundary_is_nonvacuous` | ❌ W0 | ⬜ pending |
| 287-00C-01 | 00C | 3 | ARENA-02, ARENA-06, ARENA-08 | first-half SwarmConfig literal inventory/default migration TDD | `bash tools/check-arena-config-literals.sh --self-test && bash tools/check-arena-config-literals.sh && git diff --check` | ❌ W0 | ⬜ pending |
| 287-00D-01 | 00D | 3 | ARENA-02, ARENA-06, ARENA-08 | second-half SwarmConfig literal inventory/default migration TDD | `bash tools/check-arena-config-literals-second-half.sh --self-test && bash tools/check-arena-config-literals-second-half.sh && cargo test -p swarm-core config --lib --locked --offline && git diff --check` | ❌ W0 | ⬜ pending |
| 287-00E-01 | 00E | 5 | ARENA-02, ARENA-06, ARENA-08 | final AST-aware direct-literal config inventory TDD | `bash tools/check-arena-config-inventory.sh --self-test && bash tools/check-arena-config-inventory.sh && python3 tools/check-arena-config-inventory.py --root . --golden tools/arena-config-site-golden.json && git diff --check` | ❌ W0 | ⬜ pending |
| 287-00F-01 | 00F | 3 | ARENA-01, ARENA-05, ARENA-07, ARENA-08 | independently sealed catalog/partitions/baseline/registry | `python3 -c 'import pathlib; assert all(pathlib.Path(p).exists() for p in ["scenarios/adversarial-coevolution-arena/catalog.yaml","scenarios/adversarial-coevolution-arena/oracle-registry.json"])' && git diff --check` | ❌ W0 | ⬜ pending |
| 287-00G-01 | 00G | 4 | ARENA-02, ARENA-06, ARENA-08 | first-half supplementary migration/scanner ownership | `bash tools/check-arena-config-literals.sh --self-test && git diff --check` | ❌ W0 | ⬜ pending |
| 287-00H-01 | 00H | 4 | ARENA-02, ARENA-06, ARENA-08 | second-half supplementary migration ownership | `bash tools/check-arena-config-literals-second-half.sh --self-test && git diff --check` | ❌ W0 | ⬜ pending |
| 287-01-01 | 01 | 6 | ARENA-01 | strict grammar/materialization TDD | `cargo test -p swarm-arena-red --lib --locked --offline grammar::tests::catalogued_campaign_rejects_unbounded_primitive -- --exact && cargo test -p swarm-arena-red --test red_grammar --locked --offline -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-01-02 | 01 | 6 | ARENA-01, ARENA-03, ARENA-08 | deterministic scheduler/budget TDD | `cargo test -p swarm-arena-red --lib --locked --offline scheduler::tests::virtual_queue_order_is_canonical -- --exact && cargo test -p swarm-arena-red --test scheduler_bounds --locked --offline -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-01B-01 | 01B | 7 | ARENA-03, ARENA-08 | projection-causal mutation TDD | `cargo test -p swarm-arena-red --test mutation_causality --locked --offline -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-02-01 | 02 | 8 | ARENA-02, ARENA-08 | injected-clock/FixtureTarget/no-action handoff implementation TDD | `cargo test -p swarm-ingest-runtime --lib --locked --offline arena_clock -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-02B-01 | 02B | 9 | ARENA-02, ARENA-03, ARENA-08 | real virtual-clock ingest/injection/disabled-first proof | `cargo test -p swarm-ingest-runtime --test arena_virtual_clock --locked --offline -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-02-02 | 02 | 8 | ARENA-02, ARENA-03, ARENA-06 | exact real Blue traversal plus Phase 286 one-shot handoff TDD | `cargo test -p swarm-arena --test blue_runtime --locked --offline -- --exact blue_runtime_learned_state_changes_outcome --test-threads=1 && cargo test -p swarm-arena --test blue_runtime --locked --offline -- --test-threads=1 && cargo test -p swarm-runtime --test collective_hypothesis_graph_contract --locked --offline -- --test-threads=1 && cargo test -p swarm-runtime --test phase286_bridge_handoff --locked --offline -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-02-03 | 02 | 8 | ARENA-02, ARENA-06 | policy/receipt/target safety TDD | `cargo test -p swarm-arena --test blue_safety --locked --offline -- --test-threads=1 && bash tools/check-arena-oracles.sh --self-test` | ❌ W0 | ⬜ pending |
| 287-03-01 | 03 | 10 | ARENA-04 | candidate lineage/learned-state mapping TDD | `cargo test -p swarm-arena --test candidate_lineage --locked --offline -- --exact learned_state_materially_applies_detector_profile --nocapture && cargo test -p swarm-arena --test candidate_lineage --locked --offline -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-03-02 | 03 | 10 | ARENA-05, ARENA-07 | immutable partition/identical-control TDD | `cargo test -p swarm-arena --test evaluation_partitions --locked --offline -- --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-03-03 | 03 | 10 | ARENA-04, ARENA-08 | ArenaArtifactStore CAS/fence TDD | `cargo test -p swarm-arena --test signed_artifacts --locked --offline -- --test-threads=1 && cargo clippy -p swarm-arena --all-targets --locked --offline -- -D warnings` | ❌ W0 | ⬜ pending |
| 287-04-01 | 04 | 11 | ARENA-02, ARENA-03, ARENA-04, ARENA-05, ARENA-07 | bounded adaptive runner/config gate and single-capture handoff TDD | `cargo test -p swarm-arena --test arena_ingest_capture_handoff --locked --offline -- --exact arena_ingest_capture_is_single_source --test-threads=1 && cargo test -p swarm-arena --test adversarial_coevolution_arena --locked --offline -- --exact arena_disabled_refuses_before_ingest --test-threads=1 && cargo test -p swarm-arena --test adversarial_coevolution_arena --locked --offline -- --exact adaptive_mutation_is_causal --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-04-02 | 04 | 11 | ARENA-02, ARENA-05, ARENA-07, ARENA-08 | real-runtime/three-run/identical-control TDD | `cargo test -p swarm-arena --test adversarial_coevolution_arena --locked --offline -- --exact blue_uses_real_runtime --test-threads=1 && cargo test -p swarm-arena --test adversarial_coevolution_arena --locked --offline -- --exact acceptance_metrics_meet_arena_07 --test-threads=1 && cargo test -p swarm-arena --test adversarial_coevolution_arena --locked --offline -- --exact single_agent_control_is_identical_stream --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-04-03 | 04 | 11 | ARENA-03, ARENA-07, ARENA-08 | bounds/determinism/teardown TDD | `cargo test -p swarm-arena --test arena_teardown --locked --offline -- --test-threads=1 && cargo test -p swarm-arena --test arena_teardown --locked --offline -- --exact reproducible_artifacts --test-threads=1 && cargo test -p swarm-arena --test arena_teardown --locked --offline -- --exact bounded_teardown --test-threads=1` | ❌ W0 | ⬜ pending |
| 287-05-01 | 05 | 12 | ARENA-01, ARENA-02, ARENA-03, ARENA-04, ARENA-05, ARENA-06, ARENA-07, ARENA-08 | independent final gate/parser/mutations | `bash tools/check-adversarial-coevolution-arena.sh --self-test && bash tools/check-arena-config-inventory.sh && python3 -c 'import pathlib,py_compile,shutil,tempfile; repo=pathlib.Path("."); tmp=pathlib.Path(tempfile.mkdtemp(prefix="arena-validation-")); exec("try:\n py_compile.compile(\"tools/parse-arena-report.py\", cfile=str(tmp / \"parse-arena-report.pyc\"), doraise=True)\nfinally:\n shutil.rmtree(tmp, ignore_errors=False)"); assert not any(repo.rglob("__pycache__"))' && bash tools/check-adversarial-coevolution-arena.sh` | ❌ W0 | ⬜ pending |
| 287-05-02 | 05 | 12 | ARENA-06, ARENA-08 | full workspace/authority/cleanup offline checks | `cargo test --workspace --all-targets --locked --offline && cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings && cargo fmt --all -- --check && bash tools/check-workspace-layering.sh && bash tools/check-negative-registry.sh && bash tools/check-fixture-freshness.sh && bash tools/check-runtime-panic-contract.sh && bash tools/check-arena-config-inventory.sh && git diff --check` | ❌ W0 | ⬜ pending |
| 287-05-03 | 05 | 12 | ARENA-06, ARENA-08 | isolation/CI/gate wiring | `bash tools/check-arena-isolation.sh --self-test && bash tools/check-gates-wired.sh && bash tools/check-arena-config-inventory.sh && git diff --check` | ❌ W0 | ⬜ pending |
| 287-06-01 | 06 | 13 | ARENA-01, ARENA-02, ARENA-03, ARENA-04, ARENA-05, ARENA-06, ARENA-07, ARENA-08 | independent P0/P1/P2 review/verification | `bash tools/check-arena-config-inventory.sh && CARGO_NET_OFFLINE=true bash tools/check-adversarial-coevolution-arena.sh && python3 -c 'import pathlib,re; paths=[pathlib.Path(".planning/phases/287-adversarial-co-evolution-arena/287-P0-P2-REVIEW.md"),pathlib.Path(".planning/phases/287-adversarial-co-evolution-arena/287-VERIFICATION.md")]; text="\n".join(p.read_text() for p in paths); assert all(len(re.findall(rf"(?m)^\\s*{key}:\\s*\\d+\\s*$", text)) == 2 and len(re.findall(rf"(?m)^\\s*{key}:\\s*0\\s*$", text)) == 2 for key in ("open_p0","open_p1","open_p2")); assert all(f"ARENA-0{i}" in text for i in range(1,9))' && git diff --check` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky. `File Exists` is not evidence of execution; it changes only when the named artifact is present and its exact command is green.*

## Wave 0 preflight requirements

- [ ] Plans 00/00A/00B/00C/00D/00E/00F/00G/00H (including 287-00-01 and 287-00-02) define two workspace crates with explicit offline dev dependencies, freeze the six-file ArenaConfig contract, seal corpus truth, and migrate/classify exactly 24 direct `SwarmConfig` constructions across the complete 23-path inventory; Red's resolved normal closure excludes runtime, ingest, policy, response, agents, network, process, filesystem, promotion, and every authority symbol reachable through `swarm-core`.
- [ ] Plan 00 defines `GraphLogicalTime` as the only graph-time contract visible to Red; runtime `GraphClock` is Blue-only at `swarm_runtime::hypothesis_graph::clock::GraphClock`.
- [ ] Phase 286's compile contract exposes `GraphInvestigationStrategy` (not a conflicting `InvestigationStrategy` struct), `Phase286StrategyBridge` implementing the existing `Clone + Send + Sync + 'static` async `swarm_runtime::investigation::InvestigationStrategy` trait, and proves `ConfiguredRuntimeStack` uses that bridge with no `SummaryInvestigator` fallback.
- [ ] The public `swarm_runtime::service::DryRunTraversalReceipt` fields/constructor and async `RuntimeService::rehearse_selected_simulation` path compile before Arena execution; `ArenaIngestResult { normalized_event, normalized_event_digest, findings, phase286_capture: Option<Phase286InvestigationCapture>, no_action: Option<NoActionFindingReplay>, safety }` has an injected-path-only constructor and no replay side channel. The valid arena event is single-finding: one request builder yields either one actionable rehearsal/receipt or a retained no-action finding with no policy traversal; the two handoff fields are mutually exclusive.
- [ ] `ArenaConfig::require_enabled()` fails before runner or ingest construction; the default-disabled test proves zero detector/stack/target downstream calls, and the full 24-site/23-path config scan proves one centralized default owner.
- [ ] Full `BlueOutcome` and Red `RedOutcomeProjection` have one-way, single-owner contracts; Red cannot deserialize or receive authority-bearing Blue fields.
- [ ] The independently parsed catalog uses closed tactic/technique/FixturePrimitive/FixtureTargetId enums; no raw target path/URL/IP/socket/process/file-write capability exists.
- [ ] Four immutable partition inputs have canonical IDs/content/partition digests and detached-signature metadata with a consistent runtime verification claim; membership is disjoint and withheld is never mutable feedback.
- [ ] `oracle-registry.json` is separately sealed with exact test names/counts, fixture/baseline/fingerprint digests, schema version, owner, and registry digest.
- [ ] The exact integer basis-point/asset-impact threshold formula and frozen known-evasion fingerprint formula are independently tested with nonzero denominators.
- [ ] `control_score_bp > 0` is asserted before learning arithmetic; the actual control score is the denominator, and zero/absent denominator mutations fail closed rather than falling back to 1.
- [ ] The corpus/oracle/self-test rejects zero or renamed tests, `ignored > 0`, wrong counts, missing/extra artifacts, digest/threshold/withheld mutations, stubs/placeholders/no-op success, and unsafe authority/target imports.
- [ ] Final parser validation compiles `tools/parse-arena-report.py` to a temporary explicit `.pyc` path in a `try/finally`, removes that temp directory in `finally`, and asserts no repository `__pycache__` directory exists; no `python3 -m py_compile <repo-file>` command is accepted.

## Execution-wave requirements

- [ ] Red campaigns are bounded, deterministic, catalogued, and mutate only from the narrow signed `RedOutcomeProjection`; no runtime `GraphClock`, raw telemetry, authority, or static replay path is reachable.
- [ ] Blue uses the exact raw fixture -> typed `TelemetryEvent` -> `ArenaDetectionStrategyAdapter` -> injected `process_bridge_event_at` -> composite detector -> `ConfiguredRuntimeStack<..., ..., Phase286StrategyBridge>::process_event_with_phase286_capture` -> one captured graph result/outcome/decision/simulation -> policy/Pouncer/Tom/operator approval -> receipt -> dispatcher -> simulated sandbox traversal, with negative zero-adapter-call proofs for each missing link and `ArenaIngestResult` safety evidence.
- [ ] Arena-owned `ArenaArtifactStore` uses signed CAS/generation/predecessor/fence semantics; Phase 286 graph/task/memory stores and planners are consumed rather than duplicated.
- [ ] Candidate synthesis requires detector and response candidates when both applicability predicates are present, and accepted candidates enter only a bounded signed `BlueLearnedState` projection for later Phase 288 evaluation.
- [ ] Learned-state patches use closed detector/graph strategy and policy-mode enums with deterministic candidate selection from canonical BTree order; unknown vocabulary, reordering, ties, digest-only patches, and no-op patches fail closed.
- [ ] Learning/control pairs freeze identical campaign/clock/config/graph/policy/signer/scheduler/target/partition inputs; only the bounded learned-state projection may differ, and mismatches invalidate scoring.
- [ ] The runner has a required config-level run root, deterministic stop precedence, frozen fingerprint comparison, ownership-scoped teardown, clean-run-root/worktree status checks, and no broad deletion.
- [ ] CI runs all arena/isolation/report/full-workspace checks with `CARGO_NET_OFFLINE=true` and `--locked --offline`; no live target, network, external secret, promotion, enforced response, or hosted/release claim is introduced.
- [ ] An independent report parser validates strict schema, unknown/missing fields, exact counts, ignored==0, denominators, thresholds, partitions, observations, and deterministic payloads.
- [ ] Independent final review and verification artifacts prove `open_p0: 0`, `open_p1: 0`, `open_p2: 0`, and executable evidence for ARENA-01..08 before completion.

## Manual-Only Verifications

None are acceptance requirements. A human may inspect report readability only after automated gates are green. Any hosted/release/deployment statement remains out of scope.

## Validation Sign-Off

- [ ] All planned tasks have an automated verification command and strict TDD behavior/negative tests.
- [ ] Sampling continuity: no three consecutive implementation tasks lack an automated check.
- [ ] `wave_0_complete` means only the Plan 00/00A/00B/00C/00D/00E/00F/00G/00H preflight bundle is green; it is not inferred from file existence or an execution-wave banner. Plan 00E is the final scanner after both migration halves and their supplementary ownership plans.
- [ ] No ignored tests, placeholders, static replay loop, live target, enforced response, promotion, wall-clock fitness, or no-op success path exists.
- [ ] Exact named test counts are asserted from the separately sealed registry with `ignored == 0`; absent or renamed tests fail.
- [ ] Paired learning/control runs use byte-identical frozen common inputs and differ only by bounded learned-state projection.
- [ ] Deterministic verdicts exclude wall-clock measurements; observations are labeled guard-only/non-gating.
- [ ] Independent parser, isolation gate, full combined-tree gate, and P0/P1/P2 review/verification are green.
- [x] `nyquist_compliant: true` is set after task IDs, dependencies, commands, preflight terminology, and execution waves were aligned; `preflight_complete` and `wave_0_complete` intentionally remain `false`.

**Approval:** approved 2026-08-21; preflight and execution evidence pending
