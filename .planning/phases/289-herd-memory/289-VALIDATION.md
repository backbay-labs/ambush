---
phase: 289-herd-memory
slug: herd-memory
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-08-21
---

# Phase 289 — Validation Strategy

> Validation contract for privacy-minimized, registry-trusted herd memory. The
> first wave owns independent public semantic outcomes, expected arm results,
> the canonical unseen-evasion fingerprint recipe, evaluator-only fingerprints,
> denominators, pinned baseline/digests, and a self-testing gate; implementation
> plans must not replace those truths with production-generated fixtures or
> expose evaluator-only expected material.

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in libtest invoked only through the locked/offline commands below, with `tokio::test` where runtime integration needs async execution; strict YAML/JSON fixtures use Serde; shell gate uses Bash. |
| **Config file** | Workspace `Cargo.toml`/package manifests; phase oracle at `scenarios/herd-memory/manifest.yaml`; evaluator-only bundle digest at external `/run/ambush/phase289/evaluator-v1/manifest.json` with external root `/run/ambush/phase289/evaluator-v1/root.v1`. |
| **Quick run command** | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-runtime --test herd_memory_oracle --locked --offline -- --exact allowlist_oracle_rejects_nested_privacy_fields --test-threads=1 && cargo test -p swarm-runtime --test negative_herd_memory_boundary --locked --offline -- --exact boundary_checker_rejects_privacy_and_authority_fixture --test-threads=1 && bash tools/check-herd-memory.sh --self-test'` |
| **Full suite command** | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'bash tools/check-herd-memory.sh && cargo test -p swarm-runtime --test herd_memory_phase_gate --locked --offline -- --exact independent_closure_artifact_mutations_fail_closed --test-threads=1 && bash tools/check-gates-wired.sh && cargo test --workspace --all-targets --locked --offline && cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings && cargo fmt --all -- --check && git diff --check'` |
| **Estimated runtime** | Quick feedback ~30 seconds after compilation; full phase gate is bounded by the workspace suite and must be run on the combined tree. |

All dependency-resolving Cargo commands in this contract use `--locked --offline`.
`cargo fmt --all -- --check` is retained in Cargo's native rustfmt syntax because
`cargo fmt` exposes no lockfile or network-resolution flags.

## Sampling Rate

- **After every task commit:** Run the task's exact focused command and `git diff --check`. No task is accepted from a renamed, ignored, zero-match, or wall-clock-only test.
- **After every plan wave:** Run the wave's package tests plus `bash tools/check-herd-memory.sh --self-test`.
- **Before `$gsd-verify-work`:** one canonical `bash tools/check-herd-memory.sh` run, the outer `herd_memory_phase_gate` test (which performs two independent typed benchmark runs with equal deterministic report digests), `bash tools/check-gates-wired.sh`, the full workspace test/clippy/format suite, and the privacy/authority mutation controls must be green.
- **CI wiring:** in job `test`, steps `Run Herd Memory canonical gate` and `Run Herd Memory closure gate` must invoke the exact `bash tools/check-herd-memory.sh` and exact `cargo test -p swarm-runtime --test herd_memory_phase_gate --locked --offline -- --exact independent_closure_artifact_mutations_fail_closed --test-threads=1` commands; `bash tools/check-gates-wired.sh` must parse those named steps and fail omission/recursion/flag mutations. The Plan 07 task command begins with the upstream gate before either named check.
- **Max feedback latency:** 60 seconds for focused tests after compilation; full-suite latency is reported as an observation, never as an acceptance metric.

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 289-00W-01 | 00W | 0 | HERDMEM-01, HERDMEM-02, HERDMEM-03, HERDMEM-04, HERDMEM-05, HERDMEM-06 | tools-only upstream prerequisite gate | `bash -n tools/sha256-root.sh && bash tools/sha256-root.sh --self-test && bash -n tools/check-herd-memory-upstreams.sh && bash tools/check-herd-memory-upstreams.sh --self-test && bash tools/check-herd-memory-upstreams.sh --require-accepted --locked-tree` | ❌ W0 | ⬜ pending |
| 289-00-01 | 00 | 1 | HERDMEM-01, HERDMEM-04, HERDMEM-06 | independent oracle/negative fixture | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-runtime --test herd_memory_oracle --locked --offline -- --exact allowlist_oracle_rejects_nested_privacy_fields --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-00-02 | 00 | 1 | HERDMEM-01, HERDMEM-03 | source-boundary mutation | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-runtime --test negative_herd_memory_boundary --locked --offline -- --exact boundary_checker_rejects_privacy_and_authority_fixture --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-00-03 | 00 | 1 | HERDMEM-01, HERDMEM-02, HERDMEM-03, HERDMEM-04, HERDMEM-05, HERDMEM-06 | exact shell gate/self-test | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'bash tools/check-herd-memory.sh --self-test'` | ❌ W0 | ⬜ pending |
| 289-01-01 | 01 | 2 | HERDMEM-01, HERDMEM-02, HERDMEM-05 | config unit/TDD | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-core --lib --locked --offline -- --exact herd_memory_config_contract --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-01B-01 | 01B | 3 | HERDMEM-01 | strict serialization/privacy unit | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-spine --test herd_memory_export --locked --offline -- --exact typed_body_rejects_unknown_and_prohibited_fields --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-01B-02 | 01B | 3 | HERDMEM-01, HERDMEM-05 | file-provider custody/bootstrap/rotation | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-spine --test herd_key_resolver --locked --offline -- --exact file_provider_bootstrap_requires_secure_root --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-01C-01 | 01C | 4 | HERDMEM-01, HERDMEM-05 | config-bound runtime factory | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-runtime --test herd_memory_factory --locked --offline -- --exact factory_requires_config_bound_file_provider --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-02-01 | 02 | 4 | HERDMEM-02 | registry/rotation unit | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-spine --test herd_memory_negative --locked --offline -- --exact registry_rotation_requires_continuity_and_scope --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-02-02 | 02 | 4 | HERDMEM-02 | mutation/integration negative | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-spine --test herd_memory_negative --locked --offline -- --exact registry_restart_preserves_rotation_and_revocation_history --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-03-01 | 03 | 5 | HERDMEM-02, HERDMEM-05 | locked verify-and-import/export-signer lifecycle/CAS | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-spine --test herd_memory_lifecycle --locked --offline -- --exact export_signer_requires_config_bound_custody --test-threads=1 && cargo test -p swarm-spine --test herd_memory_lifecycle --locked --offline -- --exact verify_and_import_rejects_crash_revocation_epoch_and_concurrent_same_head --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-03-02 | 03 | 5 | HERDMEM-05 | poisoning admission | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-spine --test herd_memory_poison --locked --offline -- --exact signed_poisoned_record_never_becomes_actionable --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-04-01 | 04 | 6 | HERDMEM-01 | Runtime-only ArenaSynthesisInput lineage and projection TDD; Phase 287 conversion is Arena-owned in 289-06 | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-runtime --test herd_memory_projection --locked --offline -- --exact arena_synthesis_input_accepts_phase287_lineage_and_phase288_adapter_evidence --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-04-02 | 04 | 6 | HERDMEM-01 | projection serialization negative | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-runtime --test herd_memory_projection --locked --offline -- --exact projection_serialization_rejects_authority_and_raw_fields --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-05-01 | 05 | 7 | HERDMEM-03, HERDMEM-05 | import/corroboration integration | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-runtime --test herd_memory_integration --locked --offline -- --exact restart_revocation_and_quarantine_remove_actionable_memory --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-05-02 | 05 | 7 | HERDMEM-03, HERDMEM-04 | advisory authority negative | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-runtime --test negative_herd_memory_authority --locked --offline -- --exact imported_memory_cannot_reach_response_authority --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-06-01 | 06 | 8 | HERDMEM-04, HERDMEM-06 | deterministic three-arm Arena bridge, exact Phase 287 conversion/golden vector/aggregate/attribution, and benchmark | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'cargo test -p swarm-arena --test herd_memory_benchmark_bridge --locked --offline -- --exact phase287_adapter_contract_and_three_arm_bridge_is_nonvacuous --test-threads=1 && cargo test -p swarm-arena --test herd_memory_benchmark_bridge --locked --offline -- --exact three_arms_use_real_blue_bridge_and_preserve_typed_lineage --test-threads=1 && cargo test -p swarm-arena --test herd_memory_benchmark_bridge --locked --offline -- --exact phase287_campaign_stage_conversion_is_exhaustive --test-threads=1 && cargo test -p swarm-arena --test herd_memory_benchmark_bridge --locked --offline -- --exact phase287_tuple_golden_vector_matches_upstream --test-threads=1 && cargo test -p swarm-arena --test herd_memory_benchmark_bridge --locked --offline -- --exact phase287_known_set_aggregate_digest_is_sorted_and_pinned --test-threads=1 && cargo test -p swarm-arena --test herd_memory_benchmark_bridge --locked --offline -- --exact phase287_attribution_is_derived_from_authenticated_source --test-threads=1 && cargo test -p swarm-runtime --test herd_memory_benchmark --locked --offline -- --exact three_arms_emit_identical_input_digests --test-threads=1 && cargo test -p swarm-runtime --test herd_memory_benchmark --locked --offline -- --exact evidence_coverage_formula_zero_and_rounding_are_exact --test-threads=1'` | ❌ W0 | ⬜ pending |
| 289-06-02 | 06 | 8 | HERDMEM-06 | acceptance/mutation/benchmark gate | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'bash tools/check-herd-memory.sh'` | ❌ W0 | ⬜ pending |
| 289-07-01 | 07 | 9 | HERDMEM-01, HERDMEM-02, HERDMEM-03, HERDMEM-04, HERDMEM-05, HERDMEM-06 | CI wiring/independent closure | `bash tools/check-herd-memory-upstreams.sh --run -- bash -c 'bash tools/check-gates-wired.sh && bash tools/check-herd-memory.sh && cargo test -p swarm-runtime --test herd_memory_phase_gate --locked --offline -- --exact independent_closure_artifact_mutations_fail_closed --test-threads=1'` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

### Literal checker matrix

The canonical `tools/check-herd-memory.sh` must execute the exact
package/target/filter matrix declared in `289-00-PLAN.md` (including the
`swarm-runtime` oracle/boundary/projection/integration/authority/benchmark
targets, `swarm-spine` export/resolver/negative/lifecycle/poison targets, and
the `swarm-arena` bridge target). Every matrix row is literally forwarded as
`bash tools/check-herd-memory-upstreams.sh --run -- cargo test -p <package> --test <target> --locked --offline -- --exact <filter> --test-threads=1`;
the wrapper executes the accepted prerequisite first. The one `--lib` config
row uses the same locked, offline, exact-filter discipline. The checker parses
libtest output and
requires exactly 15 rows, matched/executed/passed to be nonzero, and `ignored=0`;
a missing, duplicate, reordered,
renamed, zero-match, or ignored test is a hard failure. Plan 07 owns the
separate phase-gate rows and must not recurse through the canonical checker.

## Wave 0 Requirements

- [ ] `289-00W-01` — the sole Wave 0 tools-only task owns and executes `tools/check-herd-memory-upstreams.sh` plus retained `artifacts/phase289/upstream-prerequisite-gate.json` before any other task; no other plan has `depends_on: []`.
- [ ] `tools/check-herd-memory-upstreams.sh` plus retained `artifacts/phase289/upstream-prerequisite-gate.json` — executable prerequisite gate that runs before every Phase 289 task and requires exact `.planning/phases/286-collective-hypothesis-graph/286-07B-SUMMARY.md`, `.planning/phases/287-adversarial-co-evolution-arena/287-06-SUMMARY.md`, and `.planning/phases/288-autonomous-detector-response-synthesis/288-07-SUMMARY.md` closure sets, their independent review/verification/validation artifacts, typed current reviewed HEAD/tree object IDs, canonical frozen-tree/evidence digests, and recomputed zero findings; `File Exists: ❌ W0` until the script, retained record, and all closure artifacts exist. A partial `286-VALIDATION-EVIDENCE.md` or path string is explicitly not closure.
- [ ] Ownership distinction — `artifacts/phase289/upstream-prerequisite-gate.json` is the immutable 00W acceptance transcript; `scenarios/herd-memory/upstream-contract-pins.yaml` is the separate Plan 00 consumer pin map (including the frozen-tree allowlist pin). The gate record is not replaced by the pin map, and the pin map is not treated as the gate record; both remain `File Exists: ❌ W0` until their real paths, bytes, and digests exist.
- [ ] `tools/sha256-root.sh` — sole Wave 0 root helper with format test; output is exactly one unprefixed lowercase 64-hex SHA-256 value; `File Exists: ❌ W0` until created.
- [ ] `scenarios/herd-memory/manifest.yaml` — independent typed allowlist, privacy mutation matrix, lifecycle mutation matrix, three-arm metric schema, Phase 286 ceilings, and exact HERDMEM-06 thresholds.
- [ ] `artifacts/phase289/frozen-tree-allowlist.v1.json` — Plan 00-owned immutable sorted path/mode allowlist with self-field-excluded `allowlist_digest`; `File Exists: ❌ W0` until the artifact exists, and Plan 07 must consume rather than rewrite it.
- [ ] `scenarios/herd-memory/upstream-contract-pins.yaml` — exact `{path,digest: Digest64}` pins under `schema_version: phase289-upstream-contract-pins-v2` for accepted Phase 286 `286-07B-SUMMARY.md` plus its independent review/verification and retained `artifacts/phase286/collective-report-one.json` report/tree-manifest digests (the partial `286-VALIDATION-EVIDENCE.md` ledger is explicitly rejected), with reviewed HEAD/tree values as typed `GitObjectId`, Phase 287's three retained final-gate JSON files, actual adapter/Runtime DTO/Cargo membership, and the eight exact corpus files `catalog.yaml`, `partitions.yaml`, `historical-attacks.yaml`, `benign-controls.yaml`, `counterexamples.yaml`, `withheld-campaigns.yaml`, `baseline.json`, and `oracle-registry.json` under `scenarios/adversarial-coevolution-arena/`, plus the known-evasion-set digest/exact tuple schema, and Phase 288's `288-07-SUMMARY.md`/review/verification/validation plus run-1 manifest/report/packet/control/pair-view and `crates/swarm-arena/src/synthesis_adapter.rs` `Phase287ArenaSynthesisAdapter` -> `crates/swarm-runtime/src/synthesis/arena_input.rs` `ArenaSynthesisInput`/`ArenaSourceRef` role/schema/canonical-ID/content/payload/partition digest pins plus detached lineage source digest/selected source; missing/planned/pending/incomplete/head/tree/digest/adapter-contract drift is a hard failure.
- [ ] Phase 287 corpus aggregate — the eight exact files above are listed once by `oracle-registry.json` with `corpus_file_count: 8` and one sorted self-field-excluded `aggregate_manifest_digest`; missing/extra/duplicate/path-alias/reordered entries or aggregate-digest drift are fail-closed mutations.
- [ ] Typed object-ID grammar — `GitObjectId` is `{algorithm: Sha1, hex: [u8; 40]}` and accepts only the current `git rev-parse` 40-lowercase-hex output; uppercase, `0x`, abbreviations, SHA-256 length, and algorithm substitution are mutation failures. `Digest64` remains exactly 64 lowercase hex.
- [ ] External evaluator bundle `/run/ambush/phase289/evaluator-v1/manifest.json` plus root `/run/ambush/phase289/evaluator-v1/root.v1` — separately digested held-out corpus selected only by the evaluator after export/calibration; no candidate-tree path or content, and `File Exists: ❌ W0` until the external mount/pins exist.
- [ ] `crates/swarm-runtime/tests/herd_memory_oracle.rs` — strict local oracle for allowlist, nested prohibited-field, digest-disjointness, and non-vacuous benchmark-manifest mutations; it must not import production herd-memory projection code.
- [ ] `crates/swarm-runtime/tests/negative_herd_memory_boundary.rs` — clean/broken privacy and response-authority source fixtures proving the scanner can fail.
- [ ] `tools/check-herd-memory.sh` — exact named-test execution count, report-schema/threshold checks, evaluator-only contamination checks, source/privacy/authority mutations, no ignored/stubbed production tests, and `--self-test`; missing behavior remains a deliberate failure.
- [ ] Benchmark report/parser/CI schema — the exact integer `withheld_relative_gap_basis_points` field is required end-to-end; missing, duplicate, extra, renamed, float, and legacy short-form fields fail closed, and report digests use self-field-excluded canonical bytes.
- [ ] Candidate/public freeze validation — a root-signed `CandidateFreezeReceipt` binds the one canonical ArenaLineage digest, frozen allowlist/tree/HEAD^{tree}, public baseline/upstream digest, config-bound export-signer anchor, generation/predecessor/source-highwater, and metric schema before evaluator issuance; evaluator validation, review, and verification must carry and recompute the exact receipt digest/linkage, with no Scope B artifact admitted before Scope A.
- [ ] `crates/swarm-spine/src/herd_key_resolver.rs` and `crates/swarm-runtime/src/herd_memory_factory.rs` — repository-owned `FileOpaqueKeyProvider` at the validated `HerdMemoryConfig.opaque_key_root`, owner-only 0700/0600 custody, atomic rotation/restart state, and config-bound resolver factory; no process-local/test fallback.
- [ ] `crates/swarm-spine/Cargo.toml` — explicit `zeroize.workspace = true` dependency for provider key-byte cleanup.
- [ ] `Cargo.lock` — locked zeroize resolution/checksum metadata; provider/build verification must use `--locked`.
- [ ] Signed-default preservation — `rulesets/default.yaml` and `rulesets/attestation.json` are read-only; config tests recompute the pinned default digest/size and fail any byte mutation.
- [ ] First-run provisioning — explicit key-provider and trusted-issuer bootstrap operations use owner-only 0700/0600 custody, create-new/CSPRNG/atomic sync, and fail closed on missing/insecure/foreign/tampered state; runtime startup never auto-bootstraps.
- [ ] External issuer/export root custody — `/run/ambush/phase289/issuer-root/root-key.v1` and `/run/ambush/phase289/export-signer/root.v1` plus their pinned public Digest64/custody evidence are independently authenticated and root-signed; self-carried issuer keys/signatures, replacement, rotation, revocation, scope/domain/schema/epoch drift fail closed (`File Exists: ❌ W0` until external custody/pins exist). The external CI/root provisioner supplies the late path-plus-digest records; no Phase 289 candidate plan synthesizes or replaces them.
- [ ] Spine/runtime ownership — `HerdMemoryQuery` and `HerdMemoryContextKey` are spine-neutral exports; runtime `HerdMemoryContext` converts field-by-field and no spine module imports runtime types.
- [ ] `crates/swarm-runtime/tests/herd_memory_factory.rs` and `crates/swarm-spine/tests/herd_key_resolver.rs` — missing/retired/revoked/rotated-key, scope, and restart mutation tests.
- [ ] `crates/swarm-spine/src/herd_memory_store.rs`, `crates/swarm-spine/src/herd_memory_poison.rs`, and `crates/swarm-spine/tests/herd_memory_lifecycle.rs`/`herd_memory_poison.rs` — one locked `verify_and_import` CAS with generation/epoch/nonce/head revalidation, crash/concurrency/revocation-race cases, and typed poisoning admission before accepted/index state.
- [ ] `crates/swarm-arena/src/synthesis_adapter.rs` plus `crates/swarm-runtime/src/synthesis/arena_input.rs` — sole Arena-owned `Phase287ArenaSynthesisAdapter` and Runtime-owned `ArenaSynthesisInput`/`ArenaSourceRef` contract preserving the exact frozen known-evasion tuple; no Phase 289 adapter, Runtime-to-Arena import, or guessed path.
- [ ] `crates/swarm-runtime/src/herd_memory_evaluator.rs` — post-freeze provider-issued non-serializable evaluator capability; candidate/importer code cannot construct, persist, clone, debug, or reuse it.
- [ ] External evaluator bundle `/run/ambush/phase289/evaluator-v1/manifest.json` plus evaluator root `/run/ambush/phase289/evaluator-v1/root.v1` — separately signed/pinned out-of-tree artifacts with authenticated root/custody; candidate-tree copies, path/digest/root replacement, expired bundle, and unsigned bundle fail closed (`File Exists: ❌ W0` until the external mount/pins exist). The external CI/root provisioner must supply canonical `{path,digest: Digest64}` pins before Plan 06; Plan 06 is read-only with respect to the pin map.
- [ ] `docs/benchmarks/herd-memory-baseline.json` — Plan 00-owned immutable public semantic expected outcomes, public fingerprint recipe, metric denominators, pinned source/memory/baseline digests, and an opaque withheld version/digest handle; it must contain no withheld expected fingerprint or per-case content digest, and Plan 06 only consumes/revalidates it.
- [ ] `.github/workflows/ci.yml` — exact Herd Memory gate invocation recognized by `tools/check-gates-wired.sh`.
- [ ] `tools/check-gates-wired.sh` — exact-command parser and omission/rename/flag/path/duplicate/local-only mutations for both canonical CI commands.
- [ ] `.planning/phases/289-herd-memory/289-P0-P2-REVIEW.md` and `.planning/phases/289-herd-memory/289-VERIFICATION.md` — independent final review, goal-backward evidence, and zero open P0/P1/P2 counters.
- [ ] Final reviewer provenance — externally root-signed, out-of-band reviewer assignment/provenance evidence IDs are distinct from implementer evidence, pinned as `{path,digest}`, and linked in both final artifacts; no candidate-tree record satisfies this cell.
- [ ] External review-root assignment/provenance pins — root-authenticated records carry schema/version, `out_of_band: true`, root key ID/public-key digest/custody, exact artifact kind, distinct reviewer identities, assigned/reviewed head/tree, evidence IDs, and self-field-excluded digest/signature; `File Exists: ❌ W0` until the external artifacts and pins exist. The external root/CI provisioner supplies the final path-plus-digest records before Plan 07; Plan 07 only resolves them through its fail-closed resolver.

The prerequisite and helper cells above are intentionally red in this
pre-execution artifact. No `File Exists: ✅ W0` value may be written for a
future implementation/test/tool path; execution may change a cell only after
`test -f`/regular-file and the declared nonempty-content check pass on the
combined tree. Planned/path-only upstream records never turn a cell green.

## Manual-Only Verifications

All Phase 289 behaviors have automated verification. No manual-only checkpoint is permitted to substitute for the privacy, trust, lifecycle, advisory-boundary, or benchmark gates.

## Validation Sign-Off

This planning artifact is intentionally pre-execution with draft status,
nyquist_compliant false, and wave_0_complete false. Plan 289-07-01
must replace those three values only after the canonical checker, outer
phase-gate, exact CI wiring parser, full combined-tree suite, and independent
review evidence pass: status: complete, nyquist_compliant: true, and
wave_0_complete: true. The final artifact must contain no pending task/approval
status and must link the externally root-signed, out-of-band reviewer evidence IDs.

- [ ] All tasks have an `<automated>` verify command or a Wave 0 dependency that creates the command's target.
- [ ] Sampling continuity: no three consecutive tasks without automated verification.
- [ ] Wave 0 covers every initially missing oracle, mutation fixture, exact-test target, and withheld-digest reference.
- [ ] No watch-mode flags, ignored tests, `todo!`, `unimplemented!`, placeholder success, or production stubs are accepted.
- [ ] Feedback latency is bounded for focused tests; wall-clock measurements are observations only.
- [ ] `nyquist_compliant: true` may be set only after the exact gate and full combined-tree suite pass; `wave_0_complete` remains `false` in this pre-execution artifact.

**Approval:** pending
