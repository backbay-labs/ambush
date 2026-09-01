---
phase: 285
slug: assurance-foundation-closure
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-08-24
---

# Phase 285 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness, shell/Python repository gates, Docker Compose JetStream harness, Helm render checks, GitHub Actions hosted Linux |
| **Config file** | Workspace `Cargo.toml`, `.github/workflows/ci.yml`, `deploy/helm/swarm-team-six/Chart.yaml`, `.planning/phases/285-assurance-foundation-closure/285-WITNESS-ADAPTER-CONTRACT.md` |
| **Quick run command** | `cargo test -p swarm-governance --lib --locked --offline` |
| **Full suite command** | `test -n "${PHASE285_EVIDENCE_DIR:?}" && test -n "${PHASE285_SUBJECT_WORKTREE:?}" && SUBJECT_COMMIT="$(git -C "$PHASE285_SUBJECT_WORKTREE" rev-parse HEAD)" && SUBJECT_TREE="$(git -C "$PHASE285_SUBJECT_WORKTREE" rev-parse 'HEAD^{tree}')" && bash "$PHASE285_SUBJECT_WORKTREE/tools/check-phase285-evidence.sh" --verify-paths --evidence-dir "$PHASE285_EVIDENCE_DIR" --subject-worktree "$PHASE285_SUBJECT_WORKTREE" --commit "$SUBJECT_COMMIT" --tree "$SUBJECT_TREE" && (cd "$PHASE285_SUBJECT_WORKTREE" && bash tools/check-phase285-closure.sh --local --evidence-out "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json" --subject-commit "$SUBJECT_COMMIT" --subject-tree "$SUBJECT_TREE") && test "$SUBJECT_COMMIT" = "$(jq -er '.subject_commit' "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json")" && test "$SUBJECT_TREE" = "$(jq -er '.subject_tree' "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json")" && bash "$PHASE285_SUBJECT_WORKTREE/tools/check-phase285-evidence.sh" --verify-paths --evidence-dir "$PHASE285_EVIDENCE_DIR" --subject-worktree "$PHASE285_SUBJECT_WORKTREE" --commit "$SUBJECT_COMMIT" --tree "$SUBJECT_TREE" && bash "$PHASE285_SUBJECT_WORKTREE/tools/check-phase285-evidence.sh" --local-ledger --evidence-dir "$PHASE285_EVIDENCE_DIR" --subject-worktree "$PHASE285_SUBJECT_WORKTREE" --local-evidence "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json" --commit "$SUBJECT_COMMIT" --tree "$SUBJECT_TREE"` |
| **Estimated runtime** | quick ~30 seconds; affected-plan gates <=300 seconds; final local gate may be longer and records per-lane durations |

---

## Sampling Rate

- **After every task commit:** Run the task's exact non-vacuous command from the map below, then affected-package strict clippy, formatting, and `git diff --check`.
- **After every plan wave:** Run `bash tools/check-phase285-closure.sh --through-plan <plan-number>` and require every selected lane to report executed > 0, passed = executed, failed = 0, ignored = 0.
- **Before `$gsd-verify-work`:** Run the full exact subject-bound command from the Test Infrastructure table, including `--evidence-out`, `--subject-commit`, `--subject-tree`, ledger equality, and `--local-ledger`; a bare `check-phase285-closure.sh --local` is invalid.
- **After any review-driven edit:** Invalidate the prior evidence record and rerun the exact task, wave, and independent review against the new commit.
- **Max feedback latency:** 300 seconds for task/wave sampling. Long workspace, JetStream restart, and hosted lanes run only at their declared checkpoint/final gates and publish measured duration.

---

## Accepted Plan 03B Slice Evidence

Plan 03B is accepted at production commit `8abe28dbc42c444643ea473614bee7a8cf912b8b`, direct parent `cf0ad8b287a23fd1a4b57c922c8318b77c2cea81`, and reviewed tree `7ce5ed8e7ae305153170ff92b71f79dc218ae1cf`. Both `origin/work/v179-phase285-plan03b` and `origin/checkpoint/v179-phase285-plan03b-production` resolve to that exact commit. The accepted plan object is planning commit `7880321235e12c8ebc1ed2f969f5182207b42f69`, tree `7a9fd4983998b69963a2fb12ca4cb34e825afb83`. Independent whole-plan review reported P0/P1/P2=`0/0/0`.

The final authorization-critical checkpoint evidence ran through the root-supplied launcher SHA-256 `e59ba9f62bf126bccdf8c0d3331b54adae9e74f8fe1ee6e31d43e3dec9ca66b1` and manifest SHA-256 `1a8cbcc6dec726b414bbc5a1642a90dd46eed2fe6db9ab218af913839a44d5fb`. Its cumulative record contains exactly 5 positive families, 4 checkpoint cases, 8 checkpoint rows, 5 positive envelopes, 6 iterator rows, 1 release row, 140 controls, and 35 cumulative mutations, with exact digest `a023ecfddee58c87896c87c62180d7956647c33e4a11ae2c285e172fcf58a009`. The accepted selector evidence also records 5/5 JetStream CAS cases, 4/4 checkpoint cases, 30 independent crypto/nested/provenance/relation controls, 74 dynamic-ledger controls, 8 release-caller controls, 10 iterator-ledger controls, 10 unique iterator-source controls, and 8 selector-materialization controls.

This is a local Plan 03B slice checkpoint only. It does not complete Phase 285, authorize Plan 05A or later work, establish a frozen combined Phase 285 tree, supply hosted or closure evidence, mark a repository check protected-required, or implement the explicitly deferred provenance-distinct external GitHub App boundary. Plan 04 is the sole current/next plan.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 285-01-01 | 01 | 0 | ASSURE-06 | wire/failure unit + plan-schema mutation | `bash tools/check-phase285-witness-conformance.sh response-failure-wire && bash tools/check-phase285-plan-schema.sh --self-test` | ✅ `f29f283` | ✅ accepted |
| 285-01-02 | 01 | 1 | ASSURE-06 | candidate verifier mutation | `bash tools/check-phase285-witness-conformance.sh candidate-verifier` | ✅ `f29f283` | ✅ accepted |
| 285-01-03 | 01 | 1 | ASSURE-04, ASSURE-06 | slice gate | `bash tools/check-phase285-witness-conformance.sh protocol-checkpoint` | ✅ `f29f283` | ✅ accepted |
| 285-02-01 | 02 | 2 | ASSURE-06 | atomic-store contract | `bash tools/check-phase285-witness-conformance.sh atomic-store-contract` | ✅ `ff76223` | ✅ accepted |
| 285-02-02 | 02 | 2 | ASSURE-06 | model differential/fault injection | `bash tools/check-phase285-witness-conformance.sh in-memory-differential` | ✅ `ff76223` | ✅ accepted |
| 285-02-03 | 02 | 2 | ASSURE-04, ASSURE-06 | typed-proxy conformance | `bash tools/check-phase285-witness-conformance.sh typed-proxy` | ✅ `ff76223` | ✅ accepted |
| 285-03-01 | 03A | 3 | ASSURE-02, ASSURE-06 | dependency/layering negative | `bash tools/check-phase285-witness-conformance.sh transport-layering && bash tools/check-witness-dependency-closure.sh --library-only` | ✅ `cf0ad8b` | ✅ accepted |
| 285-03-02A | 03B | 4 | ASSURE-06 | closed raw config + pinned two-account harness | `bash tools/with-nats-jetstream.sh --self-test && bash tools/with-nats-jetstream.sh cargo test -p swarm-governance-witness --test jetstream_cas --locked --offline -- jetstream_cas_rejects_raw_config_unknown_field_or_persist_mode --exact && bash tools/with-nats-jetstream.sh cargo test -p swarm-governance-witness --test jetstream_cas --locked --offline -- jetstream_cas_rejects_each_raw_config_mutation --exact` | ✅ `8abe28d` | ✅ accepted |
| 285-03-02B | 03B | 4 | ASSURE-06 | JetStream CAS/header + 19-row differential | `bash tools/with-nats-jetstream.sh bash tools/check-phase285-witness-conformance.sh jetstream-cas` | ✅ `8abe28d` | ✅ accepted |
| 285-03-03 | 03B | 4 | ASSURE-04, ASSURE-06 | JetStream restart/non-skip plus root-pinned integrity boundary | `PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256=e59ba9f62bf126bccdf8c0d3331b54adae9e74f8fe1ee6e31d43e3dec9ca66b1 PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256=1a8cbcc6dec726b414bbc5a1642a90dd46eed2fe6db9ab218af913839a44d5fb bash tools/check-phase285-witness-integrity.sh --integrity-self-test && bash tools/with-nats-jetstream.sh env PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256=e59ba9f62bf126bccdf8c0d3331b54adae9e74f8fe1ee6e31d43e3dec9ca66b1 PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256=1a8cbcc6dec726b414bbc5a1642a90dd46eed2fe6db9ab218af913839a44d5fb bash tools/check-phase285-witness-integrity.sh jetstream-checkpoint` | ✅ `8abe28d` | ✅ accepted |
| 285-04-01 | 04 | 5 | ASSURE-06 | exact request-only nine-method API; outer-only Prepare routing before one authoritative typed verifier; bound taxonomy proved separately for startup refusal, unsigned request/response wire refusal, signed initial/proposed zero-CAS refusal, signed conflict-winner refusal after one attempted and zero applied CAS with no retry, and post-Applied confirmation ambiguity without deterministic signed rejection or retry; dispatcher 4/4 and mapping 9/9 | `test -n "${PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256:-}" && test -n "${PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256:-}" && bash tools/check-phase285-witness-integrity.sh --integrity-self-test && bash tools/check-phase285-witness-integrity.sh public-dispatcher && bash tools/check-witness-dependency-closure.sh --library-only` using only the separately reviewed Task 04-01 pin | ✅ `f52a25b` | ✅ accepted |
| 285-04-02 | 04 | 5 | ASSURE-06 | exact three-account/four-principal isolation 4/4 plus capability 20/20 | `bash tools/with-nats-jetstream.sh --self-test && bash tools/with-nats-jetstream.sh env PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256="$PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256" PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256="$PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256" bash tools/check-phase285-witness-integrity.sh full-service-path` using only the separately reviewed cumulative Task 04-02 pin | ✅ `5ade791` | ✅ accepted |
| 285-04-03A1 | 04 | 5 | ASSURE-04, ASSURE-06 | both shipping public `start` methods delegate to private `start_inner`; cfg(test) builders alone inject the recorder; source preflight 1+44; actual-runner receipts bind queue rows; real-constructor receipt joins row 9; exact 9/18/19/7/5/31/10 evidence; no live-grant/relay/recovery claim; exact 8-path digest 3b9e0dcdef3b37beb4dd22cfb576cb0f3d72d45e2c87c54042c548dbc4deacd7 | immutable command in 285-04-PLAN.md; accepted commit/tree `9ff689ce71a9a05892a9c0d7eda21210e467183e` / `96310ff48db788d1cfe6a735b1e9a78d586d911b`; both origin refs verified | ✅ `9ff689c` | ✅ accepted |
| 285-04-03A2a | 04 | 6 | ASSURE-04, ASSURE-06 | actual ordered A1 worker events plus proxy/store/publisher/server-issued connection records; all counts/digests derived from serialized evidence; library-internal test alone consumes crate-private A1 recorder injection through both shipping starts; explicit non-ambient exact-test/count harness prefix requires 1/1/0/0/17; no relay/grant/suppression/recovery claim; exact 9-path slice digest 919bf3addbcdbf8625f055f9c8737f22aa5b9d3dd99130fe8e62fc981b65d4c9 and 11-path cumulative digest aa6b8eae0de4d644ebb18c08a36264d09b6adc81cddc50288d3067ed3715030f | predecessor origin refs plus single-parent/direct-parent/candidate/tree/hash/scope gates, RED exact internal FQN `service_checkpoint_observation_tests::worker_observations_are_real_and_reconciled` under normal NATS, harness prefix refusal self-tests, source preflight, `--focused-service-checkpoint-observations`, A1 deadline rerun, strict immutable review/push chain in 285-04-PLAN.md | ✅ `bbfa4b1` | ✅ accepted/pushed; independent `0/0/0` |
| 285-04-03A2b1 | 04 | 7 | ASSURE-04, ASSURE-06 | fresh accepted A2a ledger is independently decoded/recomputed before complete-receipt construction and exact capacity-one reservation; private validator binds current tree/token/case; proxy row equals final private exchange; two publisher rows bind ordinals/workers/published state to the worker trace; valid cross-invocation, coherent proxy/publisher fabrication, invalid, partial, full, closed, zero/two-capacity, or failed reservation forwards; checker-owned explicit bounded ledger/receipt handoff from internal predicate to external independent decoder; no public test API or Rust-owned NATS lifecycle; exact 4-path digest ccd00d773edc3826aecd28bf6d451d0d2a5323ee766224e01b5633cb3815070a | NATS-wrapped exact RED; one checker-owned two-stage internal-producer/external-decoder invocation; 25/25 artifact/real-flow-signal/readiness/release/trap/metadata controls with PID/inode/type/mode binding, bidirectional EXIT release, and signal-specific termination; 10/10 compiled coherent controls with intended-relation and vacuous-zero enforcement; root-pinned integrity; A2a/A1 projections; exact immutable review/push chain in 285-04-PLAN.md | ✅ accepted | `a4b0103` / `0da809e`; immutable review 0/0/0; both refs fetched exactly |
| 285-04-03A2b2 | 04 | 8 | ASSURE-04, ASSURE-06 | exact six-subject init authority; exact account-bound four-principal inventory; absent versus malformed/duplicate authority declarations; Rust/shell projections over canonical plus unpredictable probe inputs; bounded 262144-byte config, 4096-byte credential, and 16384-byte mode-0600 distinct-inode projection artifacts; 23 isolated config, 3 comparator-deletion, and 7 projection/artifact controls; exact 5-path digest 964b80e1d926ccc78f1e2f487edb84169a01f1cb6a1eadcf3b294c3234ce98ff | exact immutable predecessor identity, root-pinned integrity, topology33, observation split/panic proof, deadline positives/mutations plus two debug receipts, one 900-second exact cold witness-release seed with retained fd, two 300-second Cargo-fresh release receipts content/path/device/mode-bound to seed with per-publication inode proof, unchanged downstream/API/artifact-scan/31-mutant controls, A2a/A1 projections, immutable review/push chain in 285-04-PLAN.md | ✅ accepted | `30eb13c` / `540d6d6`; immutable review 0/0/0; both refs fetched exactly |
| 285-04-03A2b3 | 04 | 9 | ASSURE-04, ASSURE-06 | live four-account relay on accepted A2b1/A2b2 seams; fresh public/private identities; historical 3,000/12,000-ms grant-fit claim invalidated because NATS starts its clock before responder observation; exact 11-path direct digest 4d9d95a9253af2cede7f42175322169a4deb3fafebc8fb0d58bcb845cd992adf and historical 14-path cumulative digest 4e6629733654f7b4b6f1233bfaaef96a0fede0368620380c8b97f9d75bb18664 | r66 exact detached-source/absent-target replay selected executable `3d9d359...`, proved five diagnostic tokens absent, and failed exact FQN 0/1/0/18 after abort-only recreation returned erased `Unavailable`; cumulative review later found 0/5/3 | ◇ banked; unaccepted | refs exact `ed77183`; source RED and architecture blockers proven; r72 required |
| 285-04-03A2b3R1a | 04 | 10 | ASSURE-04, ASSURE-06 | exact seven-path transport slice/digest `272eb9961675aa24a93164825a64c2db7930d1cfa544a520fddd7d085a10e9ab`; `TimedOut|Other -> OutcomeUnknown`, `NoResponders -> Unavailable`, `InvalidSubject -> Configuration`; enqueue not publication; real 3,000/12,000-ms pre-poll grant-expiry recovery | real async-nats branches plus public/private held-poll NATS cases; one applied CAS, requester unknown, byte-identical replay, zero second CAS; coherent mapping/clock/enqueue/CAS controls; package/static gates; immutable review; candidate refs only | ◇ frozen local candidate | exact `45f5104ed1c02bee2256357972d547e94f8424cf`; unaccepted; direct R1b child frozen |
| 285-04-03A2b3R1b | 04 | 11 | ASSURE-04, ASSURE-06 | measured exact twelve-path lifecycle/resource/secret slice/digest `25b98dbddeb4bd7f6c3d5fed9563896ce2340f05a20bd4f1efff34ee881ef541`; includes `Cargo.lock` and `secure_file.rs`; runner/connection supervision; idempotent bounded SIGINT/SIGTERM drain; 64-worker/1,024-item/512-MiB checked limits; descriptor-bound zeroized secret/config reads | real task/connection/reconnect/slow-consumer/SIGINT/SIGTERM/double-signal controls; count max/max-plus-one and overflow; symlink/link/type/owner/mode/rewrite controls; R1a regressions; immutable review; candidate refs only | ◇ frozen local candidate | exact `f79e67e9b6aff763ac9799723bc4a16a5d4a860e`; unaccepted; direct R1c child frozen |
| 285-04-03A2b3R1c | 04 | 12 | ASSURE-04, ASSURE-06 | measured exact ten-path CI slice/digest `9c733d2a8ce7f1c3799c2928aec1e1dd450f356f4cddeea13cca6af44b782594`; self-contained workspace tests; explicit ignored live/artifact tests; exact current two-bin closure; witness-integrity wiring; unchanged launcher | ordinary `cargo test --workspace`; exact ignored FQNs under real harness; library/current-target dependency modes and mutations; gate-wiring differential; static/actionlint; immutable review and exact hosted run; candidate refs only | ◇ frozen local candidate | exact `bf170c0ff562f0fa634f77cc45eef680f4e509c1`; unaccepted; exact R1d child frozen |
| 285-04-03A2b3R1d | 04 | 13 | ASSURE-04, ASSURE-06 | exact corrected seven-path relay/checker/pin slice/digest `5579e51a5346348b9050c7bf73c5cebb14b58edaedcc1436fd791e0ab3c68aa4`; 12-task abort+await; two-client drain; old connz absence; exact new 9/3 subscriptions; correct `NoResponders`/`Other` semantics | refreshed fail-closed exact source-byte hashes plus token-aware public item-name/header/module inventory; final manifest pins; sanitized and byte-pinned Git/curl/compiler provenance; canonical real/clone index pins and all seven committed blobs; fresh absent-target/compiler/executable/exact-argv positive; supervised bounded exact test inventory; one live FQN; 12 coherent compiled controls; R1a-R1c local canonical gates; exact hosted CI; immutable cumulative production review/push | ◇ frozen local candidate | exact `d229f90c4984fd882d4401fdb7923549fa7b0dbe` / tree `15dce0b2e157c7bfb9e71fee94d3818851a5751a`; local P0/P1/P2=`0/0/0`; unpushed/unaccepted because hydration, Docker/live NATS, hosted CI, and production refs are unavailable |
| 285-04-03A2c | 04 | 14 | ASSURE-04, ASSURE-06 | positive-first independent canonical/typed/causal oracle plus exact 38-name unconditional real-target corpus; exact 4-path slice digest `8b37d06097626b9d3f302ea1053ced7852e5553f095c8ead99964c8bca66b6c5`; cumulative digest must be repinned after R1d | genuine RED retained; only after accepted R1d and one narrow independently reviewed exact-parent/cumulative-digest repin may frozen partial bytes be replayed | ◇ stopped | three paths uncommitted; no mutation ran; R1d and repin block resumption |
| 285-04-03A3 | 04 | 15 | ASSURE-04, ASSURE-06 | 18/18 physical restart/lost-response rows plus coherent abort successor/binding mutants; cumulative digest must be repinned after accepted A2c | predecessor A2c refs plus exact parent/tree/scope gates, source preflight, observations, grants, relay oracle, recovery, deadline, CI, immutable review/push | ❌ W0 | ⛔ blocked by accepted A2c checkpoint |
| 285-04-03B | 04 | 16 | ASSURE-04, ASSURE-06 | 15/15 top-level plus reads 6/6, accepted restart/lost 18/18, bounds 66/66, rotation/retention 9/9 | both accepted A3 refs plus exact gates; switch dependency closure from current two-bin mode to final three-bin mode; immutable task and outer cumulative review | ❌ W0 | ⛔ blocked by accepted A3 checkpoint |
| 285-05-01 | 05A | 6 | ASSURE-06 | exact governance registry + fixed-lane seam/race matrix | `bash tools/check-phase285-governance-persistence.sh fixed-lanes && cargo test -p swarm-governance --test phase285_governance_persistence --locked --offline -- fixed_lanes_validate_complete_binding_and_namespace --exact` | ❌ W0 | ⬜ pending |
| 285-05-02 | 05B | 7 | ASSURE-06 | witness transaction crash/recovery and escrow reconstruction | `bash tools/check-phase285-governance-persistence.sh transaction-recovery` | ❌ W0 | ⬜ pending |
| 285-05-03 | 05B | 7 | ASSURE-06 | bootstrap crash/recovery matrix and exact registry | `bash tools/check-phase285-governance-persistence.sh transaction-recovery` | ❌ W0 | ⬜ pending |
| 285-05-04 | 05C | 8 | ASSURE-04, ASSURE-06 | no-witness/no-fallback + caller migration | `bash tools/check-phase285-governance-persistence.sh enforced-checkpoint && cargo test -p swarm-runtime -p swarm-agents -p swarm-ingest-runtime -p swarm-runtime-http -p swarm-cli --all-targets --locked --offline --no-run` | ❌ W0 | ⬜ pending |
| 285-06-01 | 06A | 9 | ASSURE-06 | retention/pool exhaustion mutation | `bash tools/check-phase285-governance-persistence.sh retention` | ❌ W0 | ⬜ pending |
| 285-06-02 | 06B | 10 | ASSURE-06 | offline maintenance/resume proof | `bash tools/check-phase285-governance-persistence.sh offline-maintenance` | ❌ W0 | ⬜ pending |
| 285-06-03 | 06B | 10 | ASSURE-06 | authenticated legacy migration and witness-backed inactive-lane rebind | `bash tools/check-phase285-governance-persistence.sh offline-maintenance` | ❌ W0 | ⬜ pending |
| 285-06-04 | 06C | 11 | ASSURE-06 | detector production construction and CLI routing through the materialized runtime worker | `bash tools/check-phase285-governance-persistence.sh detector-integration && bash tools/check-phase285-governance-persistence.sh cli-migration` | ❌ W0 | ⬜ pending |
| 285-06-05 | 06C | 11 | ASSURE-04, ASSURE-06 | combined governance/detector checkpoint | `bash tools/check-phase285-closure.sh --through-plan 06C` | ❌ W0 | ⬜ pending |
| 285-07-01 | 07A | 12 | ASSURE-03, ASSURE-05, ASSURE-06 | Helm bootstrap/serving render mutations | `bash tools/check-phase285-deployment.sh render` | ❌ W0 | ⬜ pending |
| 285-07-02 | 07A | 13 | ASSURE-03, ASSURE-05, ASSURE-06 | executable kind/NATS role isolation | `bash tools/check-phase285-deployment.sh live` | ❌ W0 | ⬜ pending |
| 285-07-03 | 07B | 14 | ASSURE-01, ASSURE-02, ASSURE-04, ASSURE-06 | final checker/CI/path-confinement mutation freeze | `bash tools/check-gates-wired.sh && bash tools/check-phase285-evidence.sh --self-test && bash tools/check-phase285-closure.sh --self-test` | ❌ W0 | ⬜ pending |
| 285-07-04 | 07B | 15 | ASSURE-01, ASSURE-02, ASSURE-04, ASSURE-06 | final authority and negative-registry inventory mutation | `bash tools/check-single-governor-key.sh && bash tools/check-negative-registry.sh` | ❌ W0 | ⬜ pending |
| 285-07-05 | 07B | 16 | ASSURE-01, ASSURE-02, ASSURE-04, ASSURE-06 | final local combined-tree gate | `test -n "${PHASE285_EVIDENCE_DIR:?}" && test -n "${PHASE285_SUBJECT_WORKTREE:?}" && SUBJECT_COMMIT="$(git -C "$PHASE285_SUBJECT_WORKTREE" rev-parse HEAD)" && SUBJECT_TREE="$(git -C "$PHASE285_SUBJECT_WORKTREE" rev-parse 'HEAD^{tree}')" && bash "$PHASE285_SUBJECT_WORKTREE/tools/check-phase285-evidence.sh" --verify-paths --evidence-dir "$PHASE285_EVIDENCE_DIR" --subject-worktree "$PHASE285_SUBJECT_WORKTREE" --commit "$SUBJECT_COMMIT" --tree "$SUBJECT_TREE" && (cd "$PHASE285_SUBJECT_WORKTREE" && bash tools/check-phase285-closure.sh --local --evidence-out "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json" --subject-commit "$SUBJECT_COMMIT" --subject-tree "$SUBJECT_TREE") && test "$SUBJECT_COMMIT" = "$(jq -er '.subject_commit' "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json")" && test "$SUBJECT_TREE" = "$(jq -er '.subject_tree' "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json")" && bash "$PHASE285_SUBJECT_WORKTREE/tools/check-phase285-evidence.sh" --verify-paths --evidence-dir "$PHASE285_EVIDENCE_DIR" --subject-worktree "$PHASE285_SUBJECT_WORKTREE" --commit "$SUBJECT_COMMIT" --tree "$SUBJECT_TREE" && bash "$PHASE285_SUBJECT_WORKTREE/tools/check-phase285-evidence.sh" --local-ledger --evidence-dir "$PHASE285_EVIDENCE_DIR" --subject-worktree "$PHASE285_SUBJECT_WORKTREE" --local-evidence "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json" --commit "$SUBJECT_COMMIT" --tree "$SUBJECT_TREE"` | ❌ W0 | ⬜ pending |
| 285-07-06 | 07B | 17 | ASSURE-01, ASSURE-02, ASSURE-03, ASSURE-04, ASSURE-05, ASSURE-06 | confined exact-subject hosted/review closure | `test -n "${PHASE285_EVIDENCE_DIR:?}" && test -n "${PHASE285_SUBJECT_WORKTREE:?}" && test -n "${PHASE285_HOSTED_EVIDENCE:?}" && test -n "${PHASE285_HOSTED_ATTESTATION:?}" && test -n "${PHASE285_REVIEW_EVIDENCE:?}" && test -n "${PHASE285_REVIEW_ATTESTATION:?}" && test -f "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json" && test -f "$PHASE285_HOSTED_EVIDENCE" && test -f "$PHASE285_HOSTED_ATTESTATION" && test -f "$PHASE285_REVIEW_EVIDENCE" && test -f "$PHASE285_REVIEW_ATTESTATION" && SUBJECT_COMMIT="$(jq -er '.subject_commit' "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json")" && SUBJECT_TREE="$(jq -er '.subject_tree' "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json")" && bash "$PHASE285_SUBJECT_WORKTREE/tools/check-phase285-evidence.sh" --verify-paths --evidence-dir "$PHASE285_EVIDENCE_DIR" --subject-worktree "$PHASE285_SUBJECT_WORKTREE" --commit "$SUBJECT_COMMIT" --tree "$SUBJECT_TREE" && bash "$PHASE285_SUBJECT_WORKTREE/tools/check-phase285-evidence.sh" --final-closure --evidence-dir "$PHASE285_EVIDENCE_DIR" --subject-worktree "$PHASE285_SUBJECT_WORKTREE" --local-evidence "$PHASE285_EVIDENCE_DIR/285-LOCAL-EVIDENCE.json" --hosted-evidence "$PHASE285_HOSTED_EVIDENCE" --hosted-attestation "$PHASE285_HOSTED_ATTESTATION" --review-evidence "$PHASE285_REVIEW_EVIDENCE" --review-attestation "$PHASE285_REVIEW_ATTESTATION" --closure-out "$PHASE285_EVIDENCE_DIR/285-CLOSURE-EVIDENCE.json" --commit "$SUBJECT_COMMIT" --tree "$SUBJECT_TREE" && test -f "$PHASE285_EVIDENCE_DIR/285-CLOSURE-EVIDENCE.json"` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

Every checker above must reject a missing test target, zero execution, ignored execution, partial lane selection, dirty tree where immutability is required, or evidence from a different commit/tree.

### Transport-layering exact registry

| Exact case ID | Exact command | Positive count | Mutation-failure count | Registry owner |
|---|---|---:|---:|---|
| `transport_layering_rejects_governance_reverse_dependency` | `bash tools/check-workspace-layering.sh --self-test phase285-witness-reverse-dependency` | 1 | 1 | `tools/check-phase285-witness-conformance.sh` |
| `transport_layering_rejects_raw_kv_subject` | `bash tools/check-negative-registry.sh --self-test phase285-raw-kv-subject` | 1 | 1 | `tools/check-phase285-witness-conformance.sh` |
| `transport_layering_rejects_second_governor_signer` | `bash tools/check-single-governor-key.sh --self-test phase285-second-governor-signer` | 1 | 1 | `tools/check-phase285-witness-conformance.sh` |
| `transport_layering_rejects_unrelated_authority_crate` | `bash tools/check-negative-registry.sh --self-test phase285-unrelated-authority-crate` | 1 | 1 | `tools/check-phase285-witness-conformance.sh` |
| `transport_layering_rejects_missing_library_target` | `bash tools/check-witness-dependency-closure.sh --self-test missing-library-target` | 1 | 1 | `tools/check-phase285-witness-conformance.sh` |
| `transport_layering_rejects_zero_or_omitted_mutation` | `bash tools/check-phase285-witness-conformance.sh --self-test transport-layering-zero-or-omitted` | 1 | 1 | `tools/check-phase285-witness-conformance.sh` |

The wrapper rejects any case-to-command mismatch, duplicate/extra/missing row, positive count other than 1, or mutation-failure count other than 1.

---

## Wave 0 Requirements

- [ ] `tools/check-phase285-witness-conformance.sh` — exact named-test registry and nonzero execution parser for pure, in-memory, proxy, JetStream, and full-service lanes.
- [ ] `tools/check-phase285-governance-persistence.sh` — Plan05A creates six exact baseline selector registries; Plans05B and 06B serially extend `transaction-recovery` and `offline-maintenance` with the literal bootstrap and migration/rebind controls; Plan06C adds the seventh `cli-migration` selector after its runtime worker exists. Every name has exact target/package ownership, nonzero executed/passed/failed/ignored parsing, and the same eight literal registry/count mutation IDs.
- [ ] `tools/check-phase285-deployment.sh` — Helm/bootstrap/serving render and live-isolation checker with deliberate bad mount/account/image/bucket/init/anchor fixtures.
- [ ] `tools/check-phase285-closure.sh` — dependency-ordered local orchestrator that records command, exit, duration, test counts, commit, tree, and cleanliness without treating a sub-lane as final acceptance.
- [ ] `tools/check-phase285-evidence.sh` and `tools/schemas/phase285-evidence.schema.json` — three disjoint fail-closed modes plus recursive deny-unknown exact schemas: `--verify-paths` for canonical path/detached linked-worktree identity, `--local-ledger` for pending-hosted local evidence only, and `--final-closure` with explicit local/hosted/hosted-attestation/review/review-attestation/closure-output paths for authenticated provenance, reviewer independence, zero P0/P1/P2, exact input digests, and truthful `wired`/`executed`/`passed`/`protected-required` states. No generic commit/tree-only final mode exists.
- [ ] `tools/check-phase285-plan-schema.sh` and `tools/schemas/phase285-plan-frontmatter.schema.yaml` — real YAML parsing plus nested-map validation for all Phase 285 plan frontmatters; malformed/flattened maps and missing key-link patterns fail closed.
- [ ] `.github/workflows/ci.yml` — unconditional credential-free hosted witness/Phase 285 lanes wired through the repository gate inventory and emitting a GitHub OIDC/Sigstore-attested exact-schema JSON artifact.
- [ ] `.github/workflows/phase285-independent-review.yml` — workflow-dispatch-only review attestation that binds the authenticated GitHub actor, exact subject and input digests, complete findings/count schema, and disjoint author/committer/implementer identities without editing the subject.
- [ ] `crates/swarm-governance/tests/phase285_witness_conformance.rs` or an equivalent explicit integration target — shared named conformance registry that cannot pass through substring filters alone.
- [ ] Transport-package JetStream/full-service integration targets — `#[ignore]` is permitted only when the checked wrapper explicitly selects and proves execution; ordinary skip-on-unavailable behavior is forbidden.

Wave 0 is complete only when each checker self-test demonstrates one green control and deliberate red fixtures for missing, zero, ignored, failed, stale-hash, and omitted-lane evidence.

---

## Manual-Only Verifications

All phase behaviors have automated verification. Hosted execution and independent hostile review are external actors, but `tools/check-phase285-evidence.sh` mechanically verifies their exact commit/tree binding, identities, outputs, and verdict before closure.

---

## ASSURE-01 Evidence Schema

Both `285-LOCAL-EVIDENCE.json` and `285-CLOSURE-EVIDENCE.json` use a deny-unknown-fields schema and contain top-level `subject_commit` and `subject_tree`. Their mandatory `assurance` object contains exactly the following named components; every component repeats the same exact `subject_commit` and `subject_tree` and records integer mutation-sensitive counts:

| Component | Mandatory component fields |
|---|---|
| `assumption_registry` | `subject_commit`, `subject_tree`, `artifact_digest`, `parsed_entry_count`, `positive_count`, `mutation_failure_count` |
| `invariant_mapping` | `subject_commit`, `subject_tree`, `artifact_digest`, `mapped_invariant_count`, `mapped_function_count`, `positive_count`, `mutation_failure_count` |
| `negative_registry` | `subject_commit`, `subject_tree`, `artifact_digest`, `entry_count`, `positive_count`, `mutation_failure_count` |
| `fixture_freshness` | `subject_commit`, `subject_tree`, `fixture_manifest_digest`, `checked_fixture_count`, `positive_count`, `mutation_failure_count` |
| `supply_chain` | `subject_commit`, `subject_tree`, `cargo_lock_digest`, `cargo_metadata_digest`, `sbom_digest`, `dependency_edge_count`, `positive_count`, `mutation_failure_count` |

`tools/check-phase285-evidence.sh` must reject a missing/extra component or field, a component subject different from the top-level subject, a non-integer or zero positive count, or a mutation-failure count different from the exact executed registry count. Local, hosted, and closure artifacts must report these five components independently; a generic `assurance_passed` boolean or aggregate lane count is invalid.

## Hosted, review, and closure artifact schemas

`tools/schemas/phase285-evidence.schema.json` is the executable authority for the four artifact kinds and the two independent-review inputs. It must use JSON Schema 2020-12, expose exact `$defs` named `localEvidence`, `hostedEvidence`, `reviewEvidence`, `closureEvidence`, `semanticReviewPacket`, and `reviewDispatchBundle`, require every field listed below, set `additionalProperties: false` recursively, and reject duplicate array members. Git objects are lowercase 40-hex strings, SHA-256 values are lowercase 64-hex strings, timestamps are RFC 3339 UTC strings, counts are unsigned JSON integers, identity/path/version strings are nonempty, and every set-like array is lexically sorted and unique. No field is nullable unless explicitly stated.

`phase285_plan_set_sha256` is computed identically everywhere: lexically sort the 15 files consisting of `285-{01,02,03A,03B,04,05A,05B,05C,06A,06B,06C,07A,07B}-PLAN.md`, `285-GOVERNANCE-PERSISTENCE-PROTOCOL.md`, and `285-VALIDATION.md`; compute `git hash-object` for each exact subject-tree file; concatenate the fifteen lowercase blob IDs with one LF after every ID and no path text; SHA-256 those bytes. Except for the explicitly defined `CargoGraphProjectionV1` and `CycloneDxProjectionV1` digests below, every other named `*_sha256` is SHA-256 over the exact raw file or canonical command-output bytes identified by that field, never a path, timestamp, pretty-printed reserialization, or Git tree standing in for artifact bytes.

`cargo_metadata_digest` and `cargo_metadata_sha256` are both the SHA-256 of one path-independent `CargoGraphProjectionV1`, never raw `cargo metadata` output. Generate it from `cargo metadata --locked --offline --format-version=1 --all-features`; reject a missing `resolve`; and map every resolved package to a stable key. A workspace key is `workspace:<repository-relative-manifest-path>#<name>@<version>`. A non-workspace key is `<source>#<name>@<version>#<checksum-or-none>`, where `source` is Cargo's registry or Git source string. Emit exactly: `schema_version: 1`; the lexically sorted workspace-member keys; and lexically sorted package records containing the stable key, sorted enabled features, and sorted dependency-edge records. Each edge contains stable `from` and `to` keys, Cargo dependency name, dependency kind (`normal`, `dev`, or `build`), and canonical target expression or null. Serialize UTF-8 JSON with recursively sorted object keys, no insignificant whitespace, and one terminal LF. Absolute `workspace_root`, `target_directory`, `manifest_path`, `src_path`, host paths, timestamps, and diagnostic fields are forbidden. Local, hosted, review, and closure equality applies to the digest of these canonical bytes; negative controls run the same tree in two different absolute worktrees and require equal projection bytes, then mutate a package, feature, edge, kind, target, member, source, version, or checksum and require a different digest.

`sbom_digest` and `sbom_sha256` are both the SHA-256 of one path-independent `CycloneDxProjectionV1`, never raw CycloneDX files or their concatenation. First run the pinned `tools/generate-sbom.sh` against the exact locked subject and validate every generated CycloneDX JSON document before projection. Parse with duplicate-key and nonstandard-number rejection. For each document, bind it to a unique repository-relative Cargo manifest identity, remove only the volatile top-level `serialNumber` and `metadata.timestamp` fields, replace an exact subject-worktree prefix in any JSON string with the literal `${WORKSPACE}` only at a path-component boundary, and reject every remaining absolute host path, alternate subject alias, missing/extra document, or duplicate manifest identity. Recursively sort object keys, preserve array order within each validated CycloneDX document, serialize with no insignificant whitespace, and place documents in lexical manifest-identity order inside an object containing exactly `schema_version: 1` and `documents`; terminate the UTF-8 JSON with one LF. Negative controls require byte-identical projections from two distinct absolute worktrees; require serial-number, timestamp, and subject-prefix changes alone to normalize identically; require component, dependency, `bom-ref`, package URL, hash, license, property, manifest membership, or array-order mutation to change the projection; and require an unknown absolute path or attempted prefix-boundary alias to fail closed.

### Shared exact records

| Record | Exact fields and constraints |
|---|---|
| `SelectorRecordV1` | `selector`, `target`, `case_id`, `command` strings; `executed: 1`, `passed: 1`, `failed: 0`, `ignored: 0`; `filtered_out` and `expected_filtered_out` integers with equality required. For Rust cases, `expected_filtered_out` is the exact target inventory count minus one; for shell-only transport rows both filtered counts are zero. |
| `SelectorMutationRecordV1` | `selector`; sorted unique nonempty `mutation_ids`; `mutation_failure_count == mutation_ids.length`. Plan01 Rust selectors have exactly the eight IDs `missing_target`, `zero_execution`, `ignored_test`, `failed_test`, `duplicate_registry_row`, `extra_registry_row`, `substring_only_match`, and `partial_or_filtered_only_wrong_count`; transport and later governance selectors contain exactly the literal negative IDs declared by their owning plan registries. |
| `GateRecordV1` | `gate_id`, `command`, `output_sha256`; `exit_code: 0`; positive `executed` and `passed == executed`; `failed: 0`, `ignored: 0`; sorted unique nonempty `mutation_ids`; `mutation_failure_count == mutation_ids.length`. |
| `RequirementStateV1` | `requirement_id` in `ASSURE-01` through `ASSURE-06` plus boolean `wired`, `executed`, `passed`, and `protected_required`. The array contains those six IDs exactly once in lexical order and must equal the stage matrix below. |
| `FindingV1` | `finding_id`, `severity` in `P0|P1|P2|P3`, `status` in `open|closed|not_applicable`, `summary`, and a nonempty sorted unique `evidence_anchors` array whose entries are exact `path:line` strings. |
| `CommandEvidenceV1` | `command`, `exit_code`, `stdout_sha256`, `stderr_sha256`, `started_at`, `completed_at`; final review commands require `exit_code: 0`. |
| `CommitIdentityAssociationV1` | exact object with `schema_version: 1`, lowercase 40-hex `commit_oid`, `role` in `author|committer`, lowercase `git_identity_sha256`, nonempty lowercase `github_login`, positive `commit_comment_id`, and lowercase `commit_comment_sha256`; recursively deny unknown fields. The digest is over the length-prefixed raw Git name and email bytes for that exact role. The referenced same-repository GitHub commit comment must have exact canonical JSON body binding every preceding field except its own comment ID/digest, API `commit_id == commit_oid`, and API-authenticated `user.login == github_login`. Subject freeze is the canonical `created_at` timestamp in the accepted local evidence; the comment API `created_at` must be strictly earlier, and its login must not be the independent reviewer. |
| `SemanticReviewPacketV1` | exact object with `schema_version: 1`, `artifact_type: phase285-semantic-review-packet`, `subject_commit`, `subject_tree`, nonempty `reviewer_login`, the exact six-row `reviewed_surfaces`, sorted `findings`, recomputed zero `open_counts`, nonempty sorted `commands`, `review_started_at`, and `review_completed_at`; recursively deny unknown fields. It contains no workflow/run/job/attestation, author, committer, implementer, or final artifact digest supplied by the reviewer. |
| `ReviewDispatchBundleV1` | exact object with `schema_version: 1`, `artifact_type: phase285-review-dispatch-bundle`, `subject_commit`, `subject_tree`, deterministic `local_evidence_gzip_base64`, `local_evidence_gzip_sha256`, `local_evidence_sha256`, positive `hosted_run_id`, positive `hosted_run_attempt`, nonempty `hosted_artifact_name`, exact `hosted_evidence_file` and `hosted_attestation_file`, `hosted_evidence_sha256`, `hosted_attestation_sha256`, and a lexically sorted unique `identity_associations` array of `CommitIdentityAssociationV1` records, empty only when every compare role resolves directly; recursively deny unknown fields. The gzip member is produced with metadata disabled, has exactly one member and no trailing bytes, expands within 262,144 bytes, and hashes exactly before and after decompression. Decompressed local evidence is canonical `localEvidence`. The named hosted artifact is downloaded from the exact run/attempt through the Actions API, contains exactly the two named regular files and no links or extra entries, and both downloaded bytes hash exactly. |

The requirement state matrix is literal (`W/E/P/PR` = `wired/executed/passed/protected_required`):

| Requirement | Local ledger | Hosted evidence | Final closure |
|---|---|---|---|
| `ASSURE-01` | `true/true/true/false` | `true/true/true/false` | `true/true/true/false` |
| `ASSURE-02` | `true/true/true/false` | `true/true/true/false` | `true/true/true/false` |
| `ASSURE-03` | `true/false/false/false` | `true/true/true/false` | `true/true/true/false` |
| `ASSURE-04` | `true/false/false/false` | `true/false/false/false` | `true/true/true/false` |
| `ASSURE-05` | `true/true/true/false` | `true/true/true/false` | `true/true/true/false` |
| `ASSURE-06` | `true/true/false/false` | `true/true/false/false` | `true/true/true/false` |

Local and hosted artifacts therefore cannot masquerade as final: ASSURE-03 is pending locally, ASSURE-04 is pending until independent review, and ASSURE-06 remains unpassed until the exact closure inputs validate. No artifact may report any Phase 285 row as protected-required while the external App/repository boundary is deferred.

The hosted `selector_records` set equals, with no omission or addition, every literal case row in Plan01's Rust registry, the six literal transport rows in this validation file, the literal governance/detector cases plus `cli-migration` registered by Plans05A through 06C, and Plan06C's five literal `combined_checkpoint_*` direct controls. The hosted `gate_records` set has exactly these IDs: `plan-schema`, `workspace-tests`, `serial-runtime-ingest-tests`, `strict-clippy`, `format`, `diff-check`, `clean-tree`, `workspace-layering`, `single-governor-key`, `mapping`, `negative-registry`, `fixture-freshness`, `supply-chain`, `sbom`, `witness-dependency-closure`, `deployment-render`, `deployment-live`, and `gates-wired`. Case/target inventories are enumerated before execution; a duplicate, extra, missing, substring-only, filtered-only, skipped, or wrong-filter-count record is invalid.

`workspace-tests` is produced only by `bash tools/check-phase285-workspace-tests.sh`, never by treating a raw successful `cargo test --workspace` exit as sufficient evidence. The orchestrator compiles every workspace test target; validates the exact FQN and stable-reason inventory of intentional external-environment `#[ignore]` tests; runs packages without intentional ignores normally; runs every ordinary test in packages containing intentional ignores while excluding exactly those inventoried FQNs, with each accepted summary reporting `ignored: 0`; and consumes one owned exact-selector receipt proving every excluded external test executed once in its required harness with `passed: 1` and `ignored: 0`. The union must equal the compiler-discovered test inventory exactly. An ignored pure test, ignored-FQN or reason drift, missing/extra/duplicate/substituted test, excluded ordinary test, nonzero accepted ignored count, receipt reuse, wrong target/filter count, or selector omission fails the gate. The checker self-test must kill each such mutation. `GateRecordV1.ignored: 0` therefore describes accepted executions, while intentionally ignored discovery entries are independently executed and bound rather than silently accepted.

### `phase285-local-evidence` exact object

The local JSON has exactly `schema_version: 1`, `artifact_type: phase285-local-evidence`, `phase_status: final-local-pending-hosted`, `subject_commit`, `subject_tree`, `phase285_plan_set_sha256`, `clean_subject: true`, sorted exact `selector_records`, sorted exact `selector_mutation_records`, sorted exact `gate_records`, the five-record `assurance` object, the six-row `requirement_states` array, the exact `non_claims` object defined below for hosted evidence, and `created_at`. Its canonical RFC 3339 UTC `created_at` is the subject-freeze timestamp. Every required identity-association comment must already exist with API `created_at` strictly earlier; ledger construction fails otherwise. It contains no workflow, runner, hosted, reviewer, attestation, closure, or final-pass field. `--local-ledger` recomputes the subject/tree/plan/checker/schema/input digests and exact record sets from the clean detached worktree and rejects a stale, dirty, slice-only, hosted, reviewed, protected, or final claim.

### `phase285-hosted-evidence` exact object

The hosted JSON has exactly these top-level fields:

| Field | Exact type/value |
|---|---|
| `schema_version` | integer constant `1` |
| `artifact_type` | string constant `phase285-hosted-evidence` |
| `phase_status` | string constant `hosted-passed-pending-review` |
| `subject_commit`, `subject_tree` | exact detached-subject Git objects |
| `repository` | string constant `backbay-labs/ambush` |
| `workflow` | object with exactly `path: .github/workflows/ci.yml`, `workflow_sha256`, positive `run_id`, positive `run_attempt`, nonempty `job_name`, positive `job_database_id`, `event: workflow_dispatch`, nonempty `actor`, `head_sha == subject_commit`, `github_run_identity_sha256`, and `github_job_identity_sha256` |
| `runner` | object with exactly `os: Linux`, nonempty `arch`, `image`, `image_version`, `name`, and `ephemeral: true` |
| `toolchain` | object with exactly nonempty `rustup_toolchain`, `rustc_version`, `cargo_version`, `gh_version: 2.87.3`, plus `cargo_lock_sha256`, `cargo_metadata_sha256`, and `sbom_sha256` |
| `inputs` | object with exactly `phase285_plan_set_sha256`, `validation_sha256`, `workflow_sha256`, and `evidence_schema_sha256` |
| `credential_free` | boolean constant `true`; the workflow must also prove no repository/environment secret or long-lived cloud/NATS credential was available |
| `selector_records` | sorted array of the exact `SelectorRecordV1` set above |
| `selector_mutation_records` | sorted array containing exactly one `SelectorMutationRecordV1` per selector |
| `gate_records` | sorted array of the exact `GateRecordV1` set above |
| `assurance` | exactly the five ASSURE-01 component records defined above |
| `requirement_states` | exact six-row `RequirementStateV1` array |
| `non_claims` | object with exactly `external_github_app: deferred`, `repository_protected_required_check: deferred`, `trusted_volume_rollback: outside-runtime-guarantee`, `coordinated_external_anchor_rollback: outside-runtime-guarantee`, and `phases_286_289: blocked` |
| `created_at` | RFC 3339 UTC timestamp after the workflow start and not after its attestation creation |

`$PHASE285_HOSTED_ATTESTATION` is a separate Sigstore bundle for the exact hosted JSON bytes, so the JSON never self-digests. It must be media type `application/vnd.dev.sigstore.bundle.v0.3+json`, contain a DSSE/in-toto subject SHA-256 equal to the recomputed hosted JSON digest, and verify with GitHub CLI exactly `2.87.3` against GitHub's public Fulcio/Rekor roots. The checker invokes `gh attestation verify "$PHASE285_HOSTED_EVIDENCE" --bundle "$PHASE285_HOSTED_ATTESTATION" --repo backbay-labs/ambush --signer-workflow backbay-labs/ambush/.github/workflows/ci.yml --signer-digest "$SUBJECT_COMMIT" --source-digest "$SUBJECT_COMMIT" --cert-oidc-issuer https://token.actions.githubusercontent.com --deny-self-hosted-runners --predicate-type https://slsa.dev/provenance/v1 --format json` and then requires exactly one result whose artifact digest, certificate workflow identity, workflow path/SHA, and source subject equal the hosted JSON and frozen subject. It separately fetches `gh api repos/backbay-labs/ambush/actions/runs/<run_id>` and `gh api 'repos/backbay-labs/ambush/actions/runs/<run_id>/attempts/<run_attempt>/jobs?per_page=100'`. The jobs response must report `total_count` equal to the returned array length and at most 100; pagination or an incomplete page is invalid. To avoid hashing status fields that legitimately change after artifact publication, the checker canonicalizes only immutable projections: run `{id, run_attempt, event, head_sha, workflow_id, path, actor.login, repository.full_name}` and the unique matching job `{id, name, runner_name, runner_group_name, labels, run_id, run_attempt}`; `run_id` and `run_attempt` in the job projection are the authenticated endpoint context added by the checker, not fields trusted from the job object. Their SHA-256 values must equal `github_run_identity_sha256` and `github_job_identity_sha256`. The run must match workflow/event/head/actor, and exactly one job record must match `job_database_id`, `job_name`, `runner.name`, Linux/architecture labels, and the attested GitHub-hosted environment. The evidence-generating workflow obtains `image` and `image_version` from the GitHub-hosted runner's immutable `ImageOS`/`ImageVersion` environment values and refuses if either is absent. A locally fabricated JSON, mutable workflow ref, wrong repository/workflow/issuer/subject/digest/actor/run/job/runner, self-hosted runner, or unattested rerun is invalid. This artifact authentication is evidence provenance, not the explicitly deferred protected-required GitHub App boundary.

### `phase285-independent-review` exact object

The review JSON has exactly these top-level fields:

| Field | Exact type/value |
|---|---|
| `schema_version` | integer constant `1` |
| `artifact_type` | string constant `phase285-independent-review` |
| `phase_status` | string constant `review-passed-pending-closure` |
| `subject_commit`, `subject_tree` | exact local/hosted subject |
| `repository` | string constant `backbay-labs/ambush` |
| `workflow` | object with exactly `path: .github/workflows/phase285-independent-review.yml`, `workflow_sha256`, positive `run_id`, positive `run_attempt`, nonempty `job_name`, positive `job_database_id`, `event: workflow_dispatch`, `head_sha == subject_commit`, nonempty `actor`, `github_run_identity_sha256`, and `github_job_identity_sha256` |
| `reviewer` | object with exactly `login == workflow.actor` and `role: independent-reviewer` |
| `identity_range` | object with exactly `base_exclusive: a9837f210b50bb391e6902e1e24ef84e4a8da4dc`, `head_inclusive == subject_commit`, and `github_compare_response_sha256` |
| `authors`, `committers`, `implementers` | lexically sorted unique nonempty lowercase GitHub-login arrays. For every commit and role in the complete `base_exclusive...head_inclusive` range, use the compare API login when non-null; otherwise require exactly one valid `CommitIdentityAssociationV1` and use its API-authenticated `github_login`. Duplicate, conflicting, surplus, wrong-role, wrong-commit, wrong-Git-identity, edited/deleted, post-freeze, or reviewer-authored associations are invalid. `implementers` is exactly the sorted union of `authors` and `committers`; `reviewer.login` is absent from all three. |
| `input_digests` | object with exactly `phase285_plan_set_sha256`, `local_evidence_sha256`, `hosted_evidence_sha256`, `hosted_attestation_sha256`, `semantic_review_packet_sha256`, `review_dispatch_bundle_sha256`, `evidence_schema_sha256`, and `checker_sha256` |
| `reviewed_surfaces` | exactly six sorted records with IDs `deployment`, `evidence`, `implementation`, `mutations`, `tests`, `trust-boundary`; each has a nonempty sorted unique `evidence_anchors` array |
| `findings` | sorted unique `FindingV1` array; it may be empty only when all six reviewed surfaces have evidence anchors |
| `open_counts` | object with exactly integer `p0`, `p1`, `p2`; each is recomputed from `findings` where matching severity has `status: open`, and all three equal zero |
| `commands` | nonempty sorted `CommandEvidenceV1` array containing at least the final checker self-test, local-ledger validation, hosted schema/attestation validation, workspace test, strict clippy, format, and diff commands for the exact subject |
| `review_started_at`, `review_completed_at` | RFC 3339 UTC timestamps with start before completion and both strictly after the canonical local-evidence `created_at` subject-freeze timestamp |

Null GitHub attribution is therefore not a permanent external-email dependency. After the final subject commit exists but before local closure writes its canonical `created_at` freeze timestamp, each unresolved author or committer creates one API-authenticated same-repository commit-comment association. Local closure re-fetches and validates the complete required set before writing the ledger; the dispatch bundle later carries the exact association records, and the review workflow independently fetches and validates the comments plus raw Git identity digests against the frozen local timestamp. An unresolved role without that proof remains blocked before freeze, while an exact valid association produces the same stable GitHub-login principal used by directly resolved commits.

`.github/workflows/phase285-independent-review.yml` is `workflow_dispatch` only with exact permissions `contents: read`, `actions: read`, `id-token: write`, and `attestations: write` and no subject-write permission. Its required dispatch inputs are the exact `SUBJECT_COMMIT`, a base64 encoding of canonical `SemanticReviewPacketV1`, and a base64 encoding of canonical `ReviewDispatchBundleV1`; the combined encoded inputs must fit GitHub's workflow-dispatch bound. Both decoded objects must match the checked-out subject commit/tree, and the semantic packet must have `reviewer_login == $GITHUB_ACTOR`. Before constructing review evidence, the workflow hashes the deterministic compressed ledger, safely decompresses exactly one bounded gzip member, validates the resulting bytes against `localEvidence`, recomputes `local_evidence_sha256`, downloads the named hosted artifact from the exact run and attempt with `actions: read`, rejects redirects to a different run, pagination, links, paths, duplicates, or extra files, validates the downloaded hosted evidence and attestation, and recomputes `hosted_evidence_sha256` and `hosted_attestation_sha256`. The workflow validates the semantic packet, but it—not the reviewer—constructs the final `phase285-independent-review` JSON by adding workflow/run/job identity, fixed-range author/committer/implementer sets, compare/API projection digests, and all subject/input digests. It fetches the GitHub compare API result for the exact fixed `a9837f210b50bb391e6902e1e24ef84e4a8da4dc...SUBJECT_COMMIT` range, rejects truncated/paginated/incomplete results and unresolved roles without a valid authenticated association, derives the exact identity arrays, recomputes finding counts and all input digests including the canonical semantic-packet digest, and publishes `$PHASE285_REVIEW_ATTESTATION`; it cannot edit or rebuild the subject. The review bundle has the same Sigstore media type, GitHub CLI `2.87.3`, OIDC issuer, source/signer digest, public-root, and self-hosted-runner refusal rules as hosted evidence, but its `--signer-workflow` is exactly `backbay-labs/ambush/.github/workflows/phase285-independent-review.yml` and its verified artifact is `$PHASE285_REVIEW_EVIDENCE`. The checker uses the same full attestation command shape with `--bundle "$PHASE285_REVIEW_ATTESTATION"`, the review signer workflow, and both digest flags set to `$SUBJECT_COMMIT`, then requires exactly one verified result. It authenticates reviewer identity by fetching the exact recorded Actions run and the attempt-specific jobs endpoint with `per_page=100`, rejecting `total_count` mismatch, more than 100 jobs, pagination, or an incomplete page, recomputing the same endpoint-context-augmented immutable run/job identity projections, requiring exact projection digests and workflow/job/event/head/run-attempt fields, requiring the unique job to equal `job_database_id`/`job_name`, and requiring API `actor.login == workflow.actor == reviewer.login`; no mutable predicate field alone authenticates the reviewer. Any author/committer/implementer overlap, self-authored artifact, wrong actor/workflow/run/job/subject/digest, semantic-packet or dispatch-bundle substitution, unavailable or mismatched evidence bytes, incomplete compare range, missing/tampered/conflicting/self-authored identity association, summary-only zero, unknown finding value, missing surface, or recomputed nonzero P0/P1/P2 is invalid.

Because GitHub emits `workflow_dispatch` only for workflow files present on the default branch, Task 285-07-06 has an explicit bootstrap prerequisite. After the subject is frozen, create ready, minimal bootstrap PRs against `main` containing byte-identical copies of the subject's complete `.github/workflows/ci.yml` and complete `.github/workflows/phase285-independent-review.yml`; obtain ordinary review/CI and land those bootstrap PRs before either dispatch. Re-read both default-branch blobs through the GitHub API and require their SHA-256 values to equal the frozen subject workflow digests. Dispatch an immutable tag pointing at `SUBJECT_COMMIT`, and require each run's `head_sha` to equal that commit. Bootstrap landing is enablement only: it does not accept Phase 285, does not make either check protected-required, and does not relax the deferred external-App statement. If the bootstrap PRs cannot be landed, Phase 285 remains blocked before dispatch rather than fabricating hosted or review evidence.

### `phase285-closure-evidence` exact object

The closure JSON is atomically written only by the subject's verified checker and has exactly these top-level fields:

| Field | Exact type/value |
|---|---|
| `schema_version` | integer constant `1` |
| `artifact_type` | string constant `phase285-closure-evidence` |
| `phase_status` | string constant `passed` |
| `subject_commit`, `subject_tree` | exact common local/hosted/review subject |
| `input_digests` | object with exactly `phase285_plan_set_sha256`, `local_evidence_sha256`, `hosted_evidence_sha256`, `hosted_attestation_sha256`, `review_evidence_sha256`, `review_attestation_sha256`, `evidence_schema_sha256`, and `checker_sha256`; every digest is recomputed from the explicit input bytes |
| `hosted_identity` | exact copy of hosted `repository`, `workflow.path`, `workflow.workflow_sha256`, `workflow.run_id`, `workflow.run_attempt`, `workflow.job_name`, `workflow.job_database_id`, `runner.os`, `runner.arch`, `runner.image`, and `runner.image_version` |
| `review_identity` | exact copy of review `workflow.actor`, `reviewer.login`, `workflow.run_id`, `workflow.run_attempt`, `workflow.workflow_sha256`, plus the three recomputed zero open counts |
| `assurance` | exactly the five ASSURE-01 component records, recomputed for the subject and equal to the validated local and hosted values |
| `requirement_states` | exact six-row `RequirementStateV1` array |
| `non_claims` | the exact hosted `non_claims` object, unchanged |
| `created_at` | RFC 3339 UTC timestamp after both attested inputs validate |

The closure checker must write to a new confined temporary file, fsync, no-replace rename to the requested absent closure path, fsync the evidence directory, reread the exact bytes, validate `closureEvidence`, and recompute every input digest. It must refuse if the output already exists or if any input/output path aliases. Negative controls remove/add/type-change every schema field; omit/duplicate/substitute a selector, gate, requirement, finding, surface, or identity; alter expected filtered/mutation/open counts; swap artifact or attestation digests; mutate repository/workflow/issuer/run/actor/subject; assert App/protection passed; unblock a later phase; claim an excluded rollback; precreate closure output; or compare evidence-tree with subject-tree. Every control must make the checker fail before closure publication.

---

## Final Immutable-Tree Matrix

`tools/check-phase285-closure.sh --local` must include, at minimum:

```text
cargo test -p swarm-governance --lib --locked --offline
cargo test -p swarm-runtime-http --bin swarm_detect --locked --offline
cargo test --workspace --exclude swarm-runtime --exclude swarm-ingest-runtime --locked --offline
cargo test -p swarm-runtime -p swarm-ingest-runtime --locked --offline -- --test-threads=1
cargo clippy --workspace --all-targets --all-features --locked --offline -- -D warnings
cargo fmt --all -- --check
bash tools/check-mapping.sh
bash tools/check-negative-registry.sh
bash tools/check-fixture-freshness.sh
bash tools/check-supply-chain.sh
bash tools/check-single-governor-key.sh
bash tools/check-workspace-layering.sh
bash tools/check-gates-wired.sh
bash tools/check-witness-dependency-closure.sh --all-targets
bash tools/check-phase285-plan-schema.sh
test -n "${PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256:-}" && test -n "${PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256:-}"
bash tools/check-phase285-witness-integrity.sh --integrity-self-test
bash tools/check-phase285-witness-integrity.sh --self-test jetstream-release-hook
bash tools/check-phase285-witness-integrity.sh response-failure-wire
bash tools/check-phase285-witness-integrity.sh candidate-verifier
bash tools/check-phase285-witness-integrity.sh protocol-checkpoint
bash tools/check-phase285-witness-integrity.sh atomic-store-contract
bash tools/check-phase285-witness-integrity.sh in-memory-differential
bash tools/check-phase285-witness-integrity.sh typed-proxy
bash tools/check-phase285-witness-integrity.sh transport-layering
bash tools/with-nats-jetstream.sh env PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256="$PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256" PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256="$PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256" bash tools/check-phase285-witness-integrity.sh jetstream-cas
bash tools/with-nats-jetstream.sh env PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256="$PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256" PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256="$PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256" bash tools/check-phase285-witness-integrity.sh jetstream-checkpoint
PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256="${PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256:?reviewed Plan04 pin required}" PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256="${PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256:?reviewed Plan04 pin required}" bash tools/check-phase285-witness-integrity.sh public-dispatcher
bash tools/with-nats-jetstream.sh env PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256="${PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256:?reviewed Plan04 pin required}" PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256="${PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256:?reviewed Plan04 pin required}" bash tools/check-phase285-witness-integrity.sh full-service-path
bash tools/with-nats-jetstream.sh env PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256="${PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256:?reviewed Plan04 pin required}" PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256="${PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256:?reviewed Plan04 pin required}" bash tools/check-phase285-witness-integrity.sh service-checkpoint
bash tools/check-phase285-governance-persistence.sh fixed-lanes
bash tools/check-phase285-governance-persistence.sh transaction-recovery
bash tools/check-phase285-governance-persistence.sh enforced-checkpoint
bash tools/check-phase285-governance-persistence.sh retention
bash tools/check-phase285-governance-persistence.sh offline-maintenance
bash tools/check-phase285-governance-persistence.sh detector-integration
bash tools/check-phase285-governance-persistence.sh cli-migration
PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256="${PHASE285_WITNESS_INTEGRITY_LAUNCHER_SHA256:?reviewed final-tree pin required}" PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256="${PHASE285_WITNESS_INTEGRITY_MANIFEST_SHA256:?reviewed final-tree pin required}" bash tools/check-phase285-witness-integrity.sh combined-checkpoint
bash tools/check-phase285-deployment.sh
git diff --check HEAD^ HEAD
bash tools/check-worktree-clean.sh "the Phase 285 final run"
```

The hosted lane reruns the declared credential-free subset from a fresh checkout. If a platform dependency prevents a local lane from running on hosted Linux, the evidence contract must name the separate trusted runner; it may not mark the omitted lane passed.

---

## Validation Sign-Off

- [x] All planned tasks have an automated verification command or explicit Wave 0 dependency.
- [x] Sampling continuity: no three consecutive tasks lack automated verification.
- [x] Wave 0 enumerates every currently missing checker and integration target.
- [x] No watch-mode flags are used.
- [x] Exact-test wrappers must prove nonzero execution and reject ignored/skipped results.
- [x] Task/wave feedback target is <=300 seconds; intentionally longer final lanes publish measured durations.
- [x] `nyquist_compliant: true` is set in frontmatter.

**Approval:** pending plan-checker verification and Wave 0 execution
