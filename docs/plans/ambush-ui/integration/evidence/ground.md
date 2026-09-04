# Ground — exit evidence

**Milestone:** Ground (`11-PLAN-GROUND.md`). **Exit commit:** `49a535535` on
`codex/ambush-wave3-ground-implementation`, rebased onto PR #12's head `38edc5681`
(`codex/ambush-wave3-ground`). **Tree state at exit:** clean (`git status --porcelain` empty).
**Recorded:** 2026-09-03.

Every claim below names the command that produced it. A row marked *not verified* is a
limitation, not a green check.

## Toolchains and services

| Component | Version |
|---|---|
| Engine Rust (root `rust-toolchain.toml`) | 1.97.1 (8bab26f4f 2026-07-14), edition 2024 |
| Workspace Rust (`workspace/rust-toolchain.toml`) | 1.95.0 (59807616e 2026-04-14), edition 2021 |
| Node / pnpm (Hermit, `workspace/bin`) | 24.15.0 / 11.4.0 |
| Flutter (Hermit) | 3.41.7 |
| lefthook | 2.1.3 |
| Postgres for the relay E2E | Homebrew PostgreSQL 14.19 on 127.0.0.1:5433 (throwaway cluster; all 40 relay migrations applied) |
| Redis for the relay E2E | Homebrew Redis 8.2.1 on 127.0.0.1:6380 (`--save "" --appendonly no`) |
| Relay under test | `cargo build -p ambush-relay` from this tree, bound to 127.0.0.1:3001 |
| Docker | **not available**: the local colima VM reports filesystem I/O errors, so `docker compose up` was not exercised (see limitations) |

## Task-by-task outcomes

| Task | Commit(s) | Evidence |
|---|---|---|
| 1 rename and re-pin | `42e44008b` | `grep -rE "ambush:(finding|…):v1|ambush\.perch\."` over `docs/plans/ambush-ui/build` → 0 files; `node fixtures/validate.mjs` → 0 failures, 14 envelope hashes recomputed and matched, 3 issuer chains intact (run with a temporary `ajv@8` install symlinked in, then removed); `bash skeleton/perch-wire/parity-gate.sh` → 312 declared fields across 17 schemas present on both sides |
| 2 three splits (MR-1, MR-2, AS-1…4, HV-1…4) | `8974cdb9c` … `95db2339c` (ten commits) | `AppShell.tsx`, `MessageRow.tsx`, `HomeView.tsx` below the 1000-gate-line ceiling; `MessageBody.tsx` carries the `perch seam` comment; desktop check/typecheck/unit suite green (5,822 tests at the end of the milestone) |
| 3 relay patches (46010, 26006) + repair kinds | `f1a9752cf`, `f150db60a`, `dbac27cb8` | unit: 7 `workflow_approval_*`, 3 `operator_alarm_frame_*`, `global_only_and_channel_scoped_are_disjoint`, the whole `handlers::ingest::tests` module (181) and `ambush-core --lib` (265) pass; E2E against the live relay on 3001: `e2e_workflow_approval` 6/6 and `e2e_operator_alarm_pgate` 8/8 including `a_named_principal_receives_the_frame_and_an_unnamed_one_does_not` and the needs-action INNER JOIN case; both binaries wired into the backend-integration job and the `test-unit` recipe; `CHANNEL_REPAIR_KINDS` gains 39005/40100/46010 with the coupling to the live channel filter, the E2E bridge and the mobile registry kept (`relayReconnectReplay.test.mjs` 35/35) |
| 4 H1 CSP pin | `b1229f784` | `csp_is_the_pinned_literal` failed before the pin (live CSP carried the mediapipe host) and passes after; `tests/csp.rs` 7/7; `grep -rn "mediapipe\|storage.googleapis.com" desktop/src desktop/src-tauri/src` → nothing; `@mediapipe/tasks-vision` removed from `desktop/package.json` and the lockfile |
| 5 H2 sign gate | `b10a8199c` | 4 gate tests; the inventory test lists seven signing commands (plan: five) and fails naming `src/commands/canvas.rs::set_canvas` when that call is removed, restored byte-identical |
| 6 H3 resetter registry | `5aa08b469` | 8 registry tests; dropping one name from a scratch copy fails exhaustiveness with the exact diff; 21 singletons = 21 resetters under the real loader; community switching green in the smoke suite (community-rail specs 3/3 in isolation) |
| 7 H7 ws-client | `f9a41cf6f` | `cargo test -p ambush-ws-client` 6/6; `grep -n "unwrap()\|unreachable!" connection.rs` → nothing; `tools/check-runtime-panic-contract.sh` reported the two sites before the fix and passes after with the crate enrolled (230 production files scanned) |
| 8 B0 nostr_pubkey | `483111298`, `d2f8b5d91` | `cargo test -p swarm-core` 89 passed incl. the four plan tests; `swarmctl validate` on `rulesets/default.yaml` still valid; `check-visibility-baseline.sh` holds |
| 9 dev ruleset + signer | `9b5234eaf` | `swarmctl validate --config rulesets-dev/perch-dev.yaml` → valid; **release refusal**: `Error: Signature { source_name: "rulesets-dev/perch-dev.yaml", source: UntrustedSigner { path: "rulesets-dev/perch-dev.yaml.sig.json" } }` (exit 1); debug `swarm_detect --serve` on 127.0.0.1:9099 answered `/readyz` 200 with `correlation_enabled: true` and the attestation `verified 4 repo-owned ruleset files`. Path is `rulesets-dev/` per W3-30 (the signed startup attestation enumerates `rulesets/`) |
| 10 dev stack | `2d8429496` | `docker compose config --quiet` ok; `bash -n` and shellcheck clean; `scripts/provision-perch.sh` ran twice against a private native relay: twelve lanes created, then all twelve reported existing; the derived operator pubkey cross-checked with an independent secp256k1 multiply |
| 11 perch preview feature | `49a535535` | manifest test failed first ("perch entry missing"), then 2/2; off by default, desktop only |
| 12 engine CI `changes` job | `04074118c` | PyYAML parses the workflow; zero ungated engine jobs; `tools/check-gates-wired.sh` accepts exactly the job-level path-gate condition and rejects a foreign `if:` |
| 13 docs | `a441929bc`, `3d0afc6b5` | W3-30 row and path rewrites; 01-DESIGN §9 H1/H8; the workspace guide names the registry |

## Milestone gates on the combined tree

| Gate | Result |
|---|---|
| root `cargo build --workspace` | ok |
| root `cargo fmt --all -- --check` | clean |
| root `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| root `cargo test --workspace` | every crate green except two `swarm-ingest-runtime` tests that CI runs single-threaded by design; `cargo test -p swarm-runtime -p swarm-ingest-runtime -- --test-threads=1` (the CI invocation) → 0 failures |
| the thirteen `tools/check-*.sh` gates CI wires | all exit 0 (adversary-emulation coverage 100%, fixture freshness, gates-wired, hot-path regression −21.12%, no-committed-keys over 8,376 files, no-include-files, platform OpenAPI, runtime panic contract, single-governor-key, stigmergic benchmark, supply chain, visibility baseline, workspace layering) |
| `workspace/just ci` (`CHECK_FILE_SIZES_BASE=38edc5681`) | exit 0 on the exit tree: fmt-check, workspace clippy, desktop check/typecheck/unit suite (5,846), Tauri fmt/clippy/check/tests (3,040+), web check/build, desktop build, mobile analyzer + 2,011 tests, security-review check, file-size ratchet |
| `workspace/desktop pnpm test:e2e:smoke` (single worker, 48.6 min, 15-minute load average 77–155 on 10 CPUs from concurrent cargo builds) | 1,255 passed, 6 failed, 1 skipped. Isolated reruns against the same bundle: `channels.spec.ts:2124`, `workflows.spec.ts:216`, `:359`, `:608` and `video-attachment.spec.ts:1470` pass (the two intermittent ones 10/10 on five repeats each); `huddle-transcription.spec.ts:763` is the pre-existing nondeterministic voice-menu spec (0/2 here, 1/3 on the base tree). The hosted four-shard smoke run on PR #13 is the authoritative result |
| file-size ratchet | `CHECK_FILE_SIZES_BASE=38edc5681 just file-size-check` passes; against `origin/main` only the two inherited over-cap files (`markdown.tsx`, `sidebar.tsx`) report, which is the reason PR #12 carries its temporary override |

## Negative and mutation controls

- Sign-gate inventory: removing the `set_canvas` call fails `every_content_signing_command_calls_the_gate` naming that command.
- Resetter registry: dropping `markdownNodeCache` from a scratch copy fails the exhaustiveness test with the exact diff.
- CSP pin: the test failed against the pre-pin CSP.
- Repair kinds: `repair_kinds_cover_perch_case_channel_kinds` failed before the constant grew.
- Panic contract: two violations reported before the ws-client fix, zero after.
- Release refusal of the debug-signed ruleset (above); release `swarm_detect --config rulesets/default.yaml --json` still exits 0 as the control.
- Engine CI contract: `check-gates-wired.sh` rejects a foreign job-level `if:` and accepts the path gate only when a `changes` job exists.
- Workspace CI contract: `scripts/test-workspace-ci-contract.sh` fails against the pre-change workflow and passes after.

## Community and devices exercised

Relay E2E: a relay built from this tree on 127.0.0.1:3001 with the `localhost:3001` deployment
community it seeded itself. Desktop: the mock-bridge smoke project (Playwright, Chromium
headless) on macOS; no physical device. Mobile: `flutter analyze` and the widget/unit suite;
no simulator run (Ground changes no mobile UI). No daemon→bridge→relay→desktop id joins exist
yet: Ground renders no card.

## Known limitations

- **RF-D1 is not enforced by the relay.** The rule that a kind:46010 hold notice never
  carries an `e` tag has no admission check: `required_scope_for_kind(46010, event)` ignores
  tags and there is no per-kind tag validation in `ambush-relay` or `ambush-core`. Because
  `requires_h_channel_scope(46010)` doubles as the NIP-10 thread gate, an `e`-tagged hold
  notice naming a parent in the same channel is admitted **and threaded**: it mutates
  `reply_count` and `descendant_count` on that root inside the insert transaction and makes
  the relay emit a signed kind:39005 summary. One naming a missing parent is refused as
  `invalid: reply parent not found`, the right outcome for the wrong reason. Producers hold
  the line today — the wire crate's tag builder refuses an `e` on 46010 — and
  `workflow_approval_e_tag_is_admitted_today_rf_d1_gap` pins the current behaviour with an
  instruction to replace it with a refusal assertion when the relay enforces the rule.
  Enforcement is not in Ground's scope and is not claimed.

- `docker compose up` for the relay stack was not run: the local Docker daemon (colima) has
  filesystem I/O errors. The compose model validates and the provisioning script was proven
  against a native relay; the hosted checks do not exercise the compose stack either.
- The relay E2E ran on Postgres 14, not the compose stack's Postgres 17.
- Two of the four Task 1 validators no longer apply: `tokens/perch-tokens.test.mjs` and
  `viz/contrast.mjs` read the rejected palette that `tokens/README.md` records as superseded
  by the Quiet decision (`art/DECISION.md`); `contrast.mjs` still names the deleted
  `tokens/perch-tokens.css`. Left as wave-2 artifacts; not converted into a green check.
- The smoke E2E suite has one nondeterministic pre-existing spec
  (`huddle-transcription.spec.ts` "assigns distinct agent voices…", 1 pass in 3 isolated
  runs on this branch before Ground) and four load-sensitive specs that pass in isolation.
- Hosted CI for this branch: **Workspace CI green, 25 of 25 checks** on PR #13
  (https://github.com/backbay-labs/ambush/pull/13), including all four desktop smoke shards,
  both desktop E2E integration shards, Relay E2E, Desktop Core, Windows Rust, Web, Admin
  Dashboard, Mobile and Mobile Swift. The root engine workflow (`.github/workflows/ci.yml`)
  triggers only on pull requests against `main`, and this PR is stacked on the
  repository-integration PR, so the engine lanes did not run hosted here; they ran locally
  (the rows above) and run hosted when this branch retargets `main` after #12 merges.
