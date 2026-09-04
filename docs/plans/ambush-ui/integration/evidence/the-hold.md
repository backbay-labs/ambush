# The hold — exit evidence

**Milestone:** The hold (`13-PLAN-THE-HOLD.md`). **Branch:** `codex/ambush-hold-watch`,
built by integrating four parallel tracks onto the First card head `codex/ambush-fc-devstack`.
**Recorded:** 2026-09-04.

Every claim names the command that produced it. A row marked *not verified* is a limitation,
not a green check. Where the plan and the implementation disagreed, the disagreement is
recorded in `00-DECISIONS.md` and repeated here, never resolved silently.

## What this milestone claims

A response the policy would have run is stopped at the human gate, persisted as a durable
hold, filed by the bridge into a case channel on the relay, addressed to a named operator,
and then decided by that operator with the daemon executing or refusing on their word.

**The daemon-and-relay half of that path ran live, end to end, on this tree.** The CONSOLE
half did not: the desktop's hold surface goes through Tauri commands that hold the daemon
bearer and the operator's Ed25519 key, so a browser cannot drive it and every desktop spec
runs against the Playwright mock. This milestone therefore claims its backend path as
demonstrated and its console path as implemented and unit-covered, not accepted.

| Segment | Evidence |
|---|---|
| telemetry → policy → durable hold | **live.** Real office-dropper telemetry through `/v1/ingest/events` produced `open_count: 1`, `store_durable: true`, one hold `notified` on `isolate_host` with a UUID case channel and a non-null `notified_at_ms` |
| hold → bridge → relay | **live.** The `46010` notice carries `h` (case channel), `p` (this operator) and `hold` (the id); exactly one `kind:9` card whose line 0 is `<!-- swarm:hold:v1 -->`; one `26006` alarm |
| the five-step publish sequence | **live.** `the_hold_sequence_is_admitted_by_a_live_relay` published 9007/9000/9/46010/26006 in the bridge's order, all accepted, and proved the alarm frame reaches the named operator and the notice reads back |
| decide: refuse | **live.** `state: refused`, `outcome: refused_by_operator`, operator `console`, no receipt, no lease |
| decide: grant | **live.** `state: executed`, `outcome: granted_executed`, a receipt in `enforced` mode, an `audit_trail_id`, and a capability lease expiring exactly 60 000 ms after the daemon's decision instant |
| decide: replay and conflict | **live.** The same body twice → `replayed: true`, state unchanged. A different decision on a decided hold → HTTP 409 `hold_already_decided`, "re-read the hold" |
| restart recovery | **live.** An open hold survived a full daemon restart onto a re-signed profile, still `notified`, still `store_durable: true` |
| the console: select, dwell-gated grant, two-leg rendering | **mock bridge only.** 40 perch Playwright specs pass, all against the mock |
| `refused_late` from a containment refusal | **not reproduced.** See W3-35 |

## Toolchains and services

| Component | Version |
|---|---|
| Engine Rust | 1.97.1, edition 2024 |
| Workspace Rust | 1.95.0, edition 2021 |
| Postgres | Homebrew PostgreSQL 14.19, throwaway cluster on 127.0.0.1:5433 |
| Redis | Homebrew Redis on 127.0.0.1:6380 (`--save "" --appendonly no`) |
| Relay | `cargo build -p ambush-relay` from this tree, `127.0.0.1:3000`, `RELAY_URL=ws://localhost:3000` |
| Daemon | `cargo build -p swarm-runtime-http --bin swarm_detect`, `--config rulesets-dev/perch-hold-dev.yaml --serve --bind 127.0.0.1:9090` |
| Docker | **never exercised**: the local colima VM has filesystem I/O errors |

The relay ran with `AMBUSH_GIT_CONFORMANCE_PROBE=false`. The probe demands an S3/MinIO
backend and is a git-on-object-storage deployment gate; nothing in this milestone touches
git objects. That is a deliberately narrowed configuration, stated here rather than hidden.

## The four tracks, and what integrating them cost

The milestone was built on four branches — the daemon store, the operator edges, the bridge,
and the console — and merged into one. The merge, not the branches, produced most of the
findings below. Each is a case of two correct halves that were wrong together.

**A defect the merge surfaced, in shipping code.** `perchRecordHoldVerdict` invoked
`perch_record_verdict` — the FINDING command, whose input requires `finding_card_id`,
`case_channel` and `incident_id`, none of which a hold decision carries. Serde would have
refused every hold decision at runtime. It survived because the E2E mock answered whichever
command name it was handed, so the specs proved the console talked to the mock and nothing
about the product. Two guards now close it: every `perch_*` name the client sends must be
registered by a `#[tauri::command]` somewhere in the commands directory, and
`PERCH_TAURI_COMMANDS` must equal exactly the set the client invokes, because that list is
what drives the mock's closed set. Reintroducing the defect fails the second with
`perchRecordHoldVerdict invokes perch_record_verdict`.

**Two ledgers for one fact.** The edges branch and the bridge branch each found that a hunt
being *routed* is not the same as its channel having been *created*, and each fixed it — one
inside `ensure_case_channel`, one at the caller. Merged, `RoutingState` carried both
`created` and `created_channels`; the guard read one and every writer wrote the other, so
"has the relay accepted this create" always answered no and the hold path would have
replanned `CreateChannel` forever. Collapsed onto `created_channels`, which has the public
reader and documents that the relay's `duplicate: channel already exists` counts as
acceptance.

**Two components at one path.** Both branches added a
`shared/ui/perch/WriteStateRow.tsx` for different surfaces, and both named their state union
`VerdictWriteState`. Kept as two components: the finding-card row has four phases and a
retry, the hold panel has nine including `superseded` and the two late refusals and
deliberately no retry. Merging them would have put the union of both state machines behind
one prop and let a hold render a phase it cannot reach.

**Two mocks for one seam.** Both branches grew a perch E2E mock, and both bound
`__AMBUSH_E2E_PERCH_SEED__` — one to a seeder function, one to seed data. Unified on one
mock with one seeding mechanism, so a spec cannot half-seed through the path the mock does
not read.

**One opt-in, twice.** Both branches independently found that `perch` must be opt-in for E2E
because it changes what an already-ubiquitous element renders. First card's mechanism is
kept: it throws when `preview-features.json` renames the id. The other wrote the override
AFTER `installMockBridge`, racing the mount that reads it.

## Gates on the merged tree

| Gate | Result |
|---|---|
| root `cargo build --workspace` | ok |
| root `cargo fmt --all -- --check` | clean |
| root `cargo clippy --workspace --all-targets -- -D warnings` | clean |
| root `cargo test --workspace` | 1,543 passed, 0 failed |
| `cargo test -p swarm-perch-bridge` | 103 + 2 passed, 6 live-relay tests ignored by default |
| the repository `tools/check-*.sh` gates | all 18 exit 0 (`check-perch-write-allowlist.sh` with `PERCH_DESKTOP_ROOT` set, which is how CI runs it: 5 routes, 5 Rust files, 46 renderer files) |
| Tauri `cargo clippy --all-targets -- -D warnings` | clean |
| Tauri `cargo test --lib` | 3,086 passed, 18 ignored |
| desktop `pnpm test` | 6,040 tests; see the load-sensitivity note below |
| desktop `pnpm run check` | clean, copy gate clean over 51 perch files |
| desktop `pnpm exec tsc --noEmit` | clean |
| file-size ratchet vs `codex/ambush-fc-devstack` | passes |
| perch E2E (`--project=smoke`, 6 specs) | 40 passed, on this checkout's own preview port |

**On that last row.** The preview port is per checkout (`AMBUSH_E2E_PREVIEW_PORT`, 4184
here) because `reuseExistingServer` had one worktree's Playwright run silently served by
another worktree's `dist`. The run above started a fresh server against this tree.

## Negative and mutation controls

- Dropping `perch_record_hold_verdict` from the publisher set fails the inventory with
  `the two verdict files declare 4 commands and the two lists account for 3`.
- Restoring the invoke defect fails the client guard with
  `perchRecordHoldVerdict invokes perch_record_verdict`.
- A routed-but-uncreated case channel re-emits its three-step plan; only after
  `record_channel_created` is `ensure_case_channel` idempotent. Both halves are asserted.
- The redaction floor is pinned: a sub-eight-character secret is not exact-matched, and the
  credential-prefix pass is what covers it. The test fails if either half moves.

## Two rules that were quietly not doing their job

Both were found by changing something else and watching the wrong thing happen.

- **The publisher inventory counted its own documentation.** It counted raw occurrences of
  the string `#[tauri::command]`, so a doc comment mentioning the attribute counted as a
  declaration. It now counts only lines that are the attribute.
- **Four grafted tests compiled, balanced their braces, and never ran.** They had been
  appended inside the previous test's body, where the harness silently ignores them. The
  suite reported the same 17 tests before and after, which is the only reason it was
  caught. Nested `#[test]` functions are legal Rust and invisible to the runner.
- **The mobile analyzer reported `No issues found` without its lint set.** `flutter analyze`
  printed `Failed to resolve package URI "package:flutter_lints/flutter.yaml"` as a warning
  and then passed. `flutter pub get` in this worktree fixed it.

These are the same shape as the two near-misses First card recorded: **a check that produces
no output looks like a check that passed.**

## Amendments this milestone recorded

**W3-34** — Task 28's exit criterion 2 reads the capability lease's TTL as
`expires_at_ms - issued_at_ms == 60000`. `swarm_policy::CapabilityLease` has no
`issued_at_ms`; it carries exactly `capability_id`, `expires_at_ms`, `action` and `scope`.
Measured live: `expires_at_ms` minus the daemon's own decision instant is exactly 60 000 ms,
and minus the console's signed `decided_at_ms` is 60 022 ms. The criterion is restated
against the instant the daemon recorded.

**W3-35** — Task 28's exit criterion 8 produces `refused_late` naming
`runtime.containment_refused` by removing `lease_store_path`. It does not. Run live with
`runtime.containment` removed entirely and the ruleset re-signed, a granted `isolate_host`
still returned `state: executed` with a capability lease. `RuntimeError::ContainmentRefused`
needs a containment action, a non-`DryRun` execution mode, and no bound store; the dev
profile's sandbox adapter reports `mode: enforced` while never reaching
`prepare_containment`. The code path is unit-covered but has no live recipe, and this
milestone does not claim one.

## Known limitations

- **The console was never driven against this stack.** Exit criteria 3, 7 and the rendered
  half of 2 and 8 are console behaviours. They are covered by unit tests and by 40 mock-bridge
  Playwright specs, and by the daemon-side halves above, but no desktop build has been driven
  against a real relay and daemon together. The roadmap's stop condition is explicit that a
  mock-only demonstration is not a milestone exit, so **this milestone is not claimed as
  accepted** on those criteria.
- **`docker compose up` was never exercised**, on any task, because the local Docker daemon
  has filesystem I/O errors. Every compose line was replaced by a native equivalent on a
  different substrate (PostgreSQL 14, not 17-alpine; a `cargo build` relay).
- **The dev profile's response adapter is a sandbox.** Its receipts read `mode: enforced`
  and `sandbox Enforced for isolate_host`. Nothing on this machine was isolated. Every
  "executed" above means the daemon's own record says executed.
- **Two dev credentials are well-known by construction** — the operator secret is
  `sha256("ambush-perch-dev-operator-v1")` and its verdict key is the Ed25519 derivation of
  the same material. They authenticate nothing outside a loopback stack, and a release
  daemon refuses the debug-signed ruleset that trusts them.
- **The desktop unit suite has a load-sensitive spec.** `useDocumentVisible.test.mjs`
  ("focused polling pauses on blur and resumes after activation yields") failed once during
  a run with the relay, daemon, Postgres and Redis all live, and passes 3/3 in isolation.
  It is timing-sensitive, not broken, and it is recorded rather than re-run until green.
- **The engine's live-relay suite has two tests this run did not cover.**
  `lane_carries_a_finding_card_from_the_ingest_identity` and `the_lane_seq_run_is_contiguous`
  need `PERCH_TEST_LANE_CHANNEL`; they are First card's lane tests, not this milestone's.
