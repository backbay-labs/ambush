# Operator-complete — exit evidence

**Milestone:** Operator-complete (`14-PLAN-OPERATOR-COMPLETE.md`). **Exit commit:** `b766c16d0` on
`codex/ambush-operator-complete`, 48 commits above The hold's head on `codex/ambush-the-hold`.
**Tree state at exit:** clean. **Recorded:** 2026-09-05.

Every claim names the command that produced it. A row marked *not run* is a limitation, not a
green check. Where the plan and the code disagreed, the disagreement is recorded here and ruled in
`00-DECISIONS.md`, never resolved silently.

## What the milestone claims, and what it does not

All twenty-two tasks are implemented and every gate below is green. **This milestone is not claimed
as accepted**, for the reason The hold and First card were not: the console's daemon surface goes
through Tauri commands that hold the bearer and the operator's Ed25519 key, a browser cannot drive
those, and so every one of the 46 perch Playwright specs runs against the mock bridge. The fifteen
exit criteria are behaviours on a running dev stack with the console, and the console half has not
been driven against that stack. The `perch` preview flag stays off by default.

Three milestones were blocked on that one fact when this was written. **Update, 2026-09-05:** the
console half has since been driven against the live stack through Tauri's own IPC layer — the
hold path and the finding path, with both of Task 24's controls — in `evidence/walking-skeleton.md`.
That run found and fixed two wire-shape defects on the hold path (`4ce2dcdb1`), filed W3-38 through
W3-40, and names the one seam left: the rendered React tree on a real window. Acceptance of the
three milestones on that record is the owner's read.

## Toolchains and services

| Component | Version |
|---|---|
| Engine Rust (root) | 1.97.1 (8bab26f4f 2026-07-14), edition 2024 |
| Workspace Rust (Hermit) | 1.95.0 (59807616e 2026-04-14), edition 2021 |
| Node / pnpm (Hermit) | 24.15.0 / 11.4.0 |
| Flutter (Hermit) | 3.41.7 |
| Helm / helm-unittest | 3.18.6 / 0.8.2 |
| Postgres, Redis for earlier live runs | Homebrew 14.19 / 8.2.1 (The hold's evidence) |
| Docker | **never exercised**: the local colima VM has filesystem I/O errors |

## Task outcomes

| Task | Evidence |
|---|---|
| 1–3 open decisions | filed in `00-DECISIONS.md` §3 with the fallback each plan builds against; not decided |
| 4 B4 deposits | `perch_deposit_slice` keeps rows summing to `total_strength` (test); route refuses `limit=0`; seven mounted paths, both disjointness tests count seven |
| 5 `ContainmentReleased` | published from both release paths; `lease_closed` re-read from the store; test drives both call sites |
| 6 partition stamp | two fields on five sides; parity gate reports 324 fields both ways |
| 7 B6 spine | signer, chain-head store, sealing on the publish path (`385ef8a3e`), head advances only on ACK (`pacer.rs` `commit_chain_head`), and the console's `perch_verify_envelope` — hash, Ed25519, chain link, tier derived in Rust; 11 tests including two for a defect its own test found |
| 8–9 wire, bridge | as landed in The hold |
| 10 containments | `/leases`, state model, timer, rollback list, release confirmation dialog, partition section; 7 E2E |
| 11 lane | `laneLiveNumbers`, `LaneScreen`, `/lanes/$laneId`, regime-B curve in the header slot, `PerchNav` |
| 12 governance | `derivePerchGovernanceMode`, `GovernanceStrip` mounted above the outlet on every route including the Watchfloor's bare chrome |
| 13 ledger, export, omnibox | `buildLedgerQuery`, `exportBundle`, `LedgerScreen`, `perch_export.rs` (7 tests: traversal refused, verbatim bytes, nothing written on a bad sibling), `PerchOmnibox` (emits intents, never writes; 7 E2E), the tier allowlist gate |
| 14 tuning | `tuningProvenance` (`null` for no denominator), `TuningScreen`, `/tuning` |
| 15 gaps | `gapsCatalog`, `GapsScreen`, `/gaps` |
| 16 policy | `evaluateTripleLocally`, `PolicyScreen`, `/policy` — renders an empty rule list and says the daemon's default is unknown; the daemon-side rules route was deliberately not built (see limitations) |
| 17 handoff | `composeReviewSession`, `watchClaim`, `shiftLedger`, `handoffPublish`, `HandoffScreen`, `/handoff`; 6 E2E; **W3-36** |
| 18 case | `caseTemplate`, `caseTtlClock`, `killChainLayout`, `CaseScreen`, `CaseCanvasTab`, `KillChainGraph`, the terminal pin in TS and Rust against one table |
| 19 Watchfloor | shared viz layer, three charts, `viz.css` + tokens, `WatchfloorScreen`, `/watch-floor`, four reducers, the telemetry publisher draining and signing them per tick (10 tests); 7 E2E; **W3-37 resolved** |
| 20 CI gates | route-tree (21 paths), surface-count (14 surfaces, 10 routed, 4 unrouted), notification-fields, tier-allowlist — all wired, all with fixtures |
| 21 packaging | compose gate (found two real defects in Ground's compose), relay chart as `file://` dependency, NetworkPolicy default-deny, perch secret, 12 chart tests, deployment section |
| 22 sidecar | supervisor with group kill (`kill(-pgid,0) == ESRCH` asserted), three commands, health poll, settings panel, opt-in bundle overlay; 7 tests |

## Gates on the exit tree

| Gate | Result |
|---|---|
| root `cargo build/fmt/clippy --workspace -D warnings` | clean |
| root `cargo test --workspace` | 1,609 passed, 0 failed |
| all 22 `tools/check-*.sh` | green (`check-worktree-clean` passes on a fresh tree; it flags gitignored residue only after other gates have run in the same checkout) |
| Tauri `cargo clippy -D warnings` + `cargo test --lib` | 3,123 passed |
| desktop `pnpm check` (biome, px-text, pubkey, resetters, copy over 92 files, svg-font-size, route-tree) | clean |
| desktop `pnpm test` | 6,232 passed |
| perch Playwright (`--grep perch`, smoke) | 46 passed |
| `helm lint` + `helm template` (perch values) + `helm unittest` | 12 passed |
| `workspace/just ci` with `CHECK_FILE_SIZES_BASE=origin/codex/ambush-the-hold` | exit 0 |
| **Hosted, PR #16 on `b766c16`** | **16 pass, 0 fail, 8 skipped** — every check run bound to this SHA |

## Defects found by this milestone's own tests

- **`coalesced_from` would have lied.** `MemorySpool` is last-wins, so at publish time the 26001
  slot holds one snapshot; a count derived from that slice reports `1` for a window that collapsed
  thirty, on the one field whose job is to admit the coalescing. The spool now counts puts per key.
- **The verifier's unsigned branch ignored the chain.** An unsigned envelope with a sequence gap
  reported only "carries no signature" and hid the missing card. Two regression tests hold it.
- **Two `null → false` coercions** in the containment board turned the daemon's silence on
  `fully_reversed` into "not fully reversed" — a finding the console invented. `RollbackStepList`
  now takes `boolean | null` and says the daemon did not report it.
- **The compose gate found two real defects in Ground's file:** the operator API published on
  every interface, and the Postgres password inline.
- **My own status table was wrong about B6.** It said sealing was not on the publish path; it was
  (`385ef8a3e`). Written from the plan's language rather than the code. What was actually missing
  was the console's verifier.
- **The Windows job caught a POSIX literal** in a path test; the fix also narrowed a claim the
  commit message had overstated — the TS mirror and Rust share the path's SHAPE, the variable
  names and the slug rule, not the byte string.

## A check that had been red on every run of this stack

`huddle-transcription.spec.ts:763` was recorded by two earlier milestones as a pre-existing
nondeterministic failure. It had become deterministic (3 of 3), which made it diagnosable. Three
probes ran before any fix: the trigger node is stable (a planted attribute survives two seconds);
the popover stays open once opened; only a click fired immediately after render fails. So it was a
readiness race at load and not a menu closing under a user — the click is now retried until the
popover reports open. 3 of 3 where it was 0 of 3; **PR #16 was the first green run of this stack.**
A retry would have masked a product bug had either of the first two probes gone the other way,
which is why they came first.

## Amendments this milestone recorded

- **W3-36** — the END WATCH block cannot go to `POST /v1/operator/review/sessions`: the route
  refuses an empty ref list and resolves every ref against the review workbench's own evidence
  stores, and a case channel is not one. Content negotiation on the route and a relaxed one-ref
  minimum were both built and reverted. The block publishes as a plain `kind:9` into each touched
  case.
- **W3-37** — the 26000 gauge cannot come from the spool (`Ingest` is `DroppedAtSource`).
  **Resolved:** `IngestWindow` lives in `SpoolSet` beside the slots; the receive loop does one
  `+= 1` and owns no timer.

## Known limitations

- **The walking skeleton ran headless, not through a real window** (2026-09-05,
  `evidence/walking-skeleton.md`): the real commands, IPC, keyring, relay and daemon; the React
  tree above them still against the mock. That seam is the remaining limitation.
- **`docker compose up` and `helm install` were not run**; no working Docker daemon and no cluster.
  Image digests are deliberately unpinned and `check-perch-compose` says so on every run.
- **Two daemon-side reads were not built** and the screens say so in their own copy: the policy
  screen states the daemon's default is unknown rather than serving rules the console reads
  independently, and the tuning screen renders no recommendations rather than fabricating them.
- **The OpenAPI generator, the SVG asset rewrite and the 72-hour soak** have no target in this
  tree, need a browser check, or are manual respectively.
- **Task 22's sidecar was never bundled or run**: it needs an engine release build and a Tauri
  bundle with the opt-in overlay.
- **One intermittent remains in shard 2**: `file-attachment.spec.ts:395`, failed once and passed
  on retry on the exit run. Unrelated to this work; it is not deterministic, so there is nothing
  solid to fix yet.
