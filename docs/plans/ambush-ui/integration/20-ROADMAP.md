# Wave 3 Implementation Roadmap

**Status:** planning baseline after the 2026-09-02 repository migration. Migration Tasks 1–8
are complete on `integrate/workspace`; nothing has been pushed. This roadmap sequences the
four implementation plans and does not convert planned work into delivered work.

**Goal:** move from the merged repository to an operator-complete Ambush console through four
evidence-bearing milestones: Ground, First card, The hold, and Operator-complete. At every exit,
the combined tree, the hosted checks, and the real workflow must agree.

**Authority:** `00-DECISIONS.md` wins over this roadmap. The task-level plans own implementation
detail. This file owns sequencing, decision deadlines, milestone entry/exit, staffing, sizing,
cuts, risks, success measures, and the handoff from local integration to hosted delivery.

---

## 1. Where the project actually is

| Item | State | Evidence / consequence |
|---|---|---|
| Repository merge | complete locally | full Ambush workspace history lives under `workspace/`; root and workspace remain separate Cargo workspaces |
| Integration branch | `integrate/workspace` | migration, design and all four milestone plans are complete in local history; this roadmap closes the planning set |
| Push / PR | five stacked PRs open, #12–#16, all green and mergeable on 2026-09-05 | none approved or merged; the roadmap makes first merge the owner's call |
| Migration Tasks 1–8 | complete | history rewrite, merge, Cargo boundary, ignore/gate fixes, Hermit hooks and workspace CI re-rooting |
| Migration Tasks 9–11 | open | first-push strategy, repository policy, eventual retirement of the standalone chat checkout |
| Product implementation | all four milestones landed | Ground accepted; First card, The hold and Operator-complete implemented with every gate green and **not self-declared accepted** — the console's commands were driven against the live stack on 2026-09-05 through Tauri's own IPC layer (`evidence/walking-skeleton.md`); the rendered React tree on a real window is the stated seam, and acceptance on that record is the owner's read |
| Normative contradictions found during recovery | resolved as W3-27 and W3-29 | the wire crate remains transport-neutral; real receipt, escalation and 26000–26005 producers have named owners rather than stubs or mock-only consumers |

The branch contains the imported repository's history, so its commit count against the old
`origin/main` is large by design. Review the merge by topology and tree delta, not by treating
every imported historical commit as newly authored product work.

---

## 2. The critical path

```text
First push and hosted baseline
        |
        v
Ground -- rename, splits, relay admission, security prerequisites, dev stack
        |
        v
First card -- wire + bridge + finding + E promotion + D feedback
        |
        v
The hold -- durable state machine + decide route + Watch + two-legged hold decision
        |
        v
Operator-complete -- deposits, signed envelopes, leases, ledger, remaining surfaces, packaging
        |
        v
Internal release candidate and eight-week product measurement window
```

No milestone may claim completion from its unit tests alone. The edge to the next milestone opens
only after the previous plan's exit criteria are met on one clean commit and its real workflow
evidence records the ids that join the daemon, bridge, relay and desktop.

There are two kinds of parallelism:

1. **Within a milestone:** engine and workspace tasks may proceed on separate branches/worktrees
   where the plan says their interfaces are fixed. This is the useful parallelism.
2. **Across milestone exits:** pure UI exploration may occur, but later-milestone code does not
   merge past an unaccepted earlier milestone. Otherwise mocks become the de facto contract and
   the acceptance chain becomes impossible to interpret.

---

## 3. Gate zero — land the repository baseline

This is the only immediate owner decision. Migration Task 9 gives two legitimate routes:

| Route | Mechanism | Cost / risk | Recommendation |
|---|---|---|---|
| **A. Direct fast-forward** | fast-forward local `main` to `integrate/workspace`, then push `main` | clean file-size baseline immediately; requires direct pushes to be permitted and knowingly bypasses a PR review of the initial import | preferred if branch protection permits it and the owner accepts a direct import |
| **B. Bootstrap PR** | open a PR with a one-run `CHECK_FILE_SIZES_BASE` override, merge it, remove the override in the next PR | preserves hosted review; the override must be exact, temporary and removed immediately or the ratchet is weakened | use when direct pushes are prohibited or an auditable PR is required |

Before either route:

- [ ] Re-run the migration plan's root and workspace gates from the clean branch.
- [ ] Confirm `git merge-base origin/main integrate/workspace` and review the first-parent
  topology; do not re-run the history rewrite.
- [ ] Confirm the selected branch-protection path with `gh` rather than assuming it.
- [ ] Confirm repository-wide `git commit -s` plus Conventional Commit subjects.
- [ ] Push only after the owner explicitly selects A or B.

After the first push:

- [ ] Both root `CI` and `Workspace CI` reach their `changes` jobs.
- [ ] Every relevant lane runs from the intended working directory; a skipped lane is explained by
  the path filter, not silently absent.
- [ ] Fix forward on the integration branch; do not rewrite the imported history a second time.
- [ ] Delete the throwaway filtered clone only after the remote contains the merge.
- [ ] Keep `/Users/connor/Medica/backbay/buzz` until the first release from the merged repository;
  only then retire it under Migration Task 11.

**Gate-zero exit:** remote `main` contains the merged tree, both hosted workflows are green on the
landed SHA, the file-size ratchet compares against a baseline that already contains `workspace/`,
and no temporary CI override survives.

---

## 4. Decisions and their last responsible moments

Defaults let the plans be executable, but defaults are not owner approval. Batch these decisions
at milestone entry so implementation does not stop halfway through a security-sensitive contract.

| Decision | Default in the plans | Decide no later than | If changed later |
|---|---|---|---|
| First-push strategy | A, direct fast-forward | before any push | re-run the full bootstrap analysis |
| Commit policy | signed-off Conventional Commits | before the first post-import commit is pushed | branch history or DCO enforcement may need repair |
| D3 whole workspace | keep it; console is a feature area | Ground entry | route, deletion and packaging plans all change |
| D4 runtime modes | detect-only for First card; live-response dev profile for The hold | Ground entry | the milestone acceptance environments change |
| D-FC-1 Nostr derivation / seed | `swarm.perch.bridge.nostr.v1`; 32-byte seed through `PERCH_BRIDGE_NOSTR_SEED` | before First card Task 7 | identity continuity and every admitted issuer change |
| D-FC-2 admitted issuers | unauthenticated public-key-only daemon metrics read through Tauri | before First card Task 17 | marker admission and E2E fixtures change |
| D-FC-3 finding verdict shape | subject-discriminated verdict; no cross-channel `e` tag | before First card Task 20 | schema, goldens, signer and renderer change |
| D-FC-4 daemon credentials UX | debug env seeds OS keyring; Settings arrives later | before First card Task 19 | Tauri command and onboarding scope change |
| D-FC-5 lane creator | bridge creates twelve committed UUIDs idempotently | before First card Task 13 | provisioning and identity scopes change |
| Operator verdict key | typed public key on `OperatorPrincipalConfig`; console secret in OS keyring | before The hold Task 13 | every decision signature and voter-binding test changes |
| Operator artwork | plan Task 1's default | Operator-complete entry | only the glyph asset and snapshots change if decided on time |
| Watch claim | plan Task 2's default | Operator-complete entry | Handoff and governance-strip state ownership change |
| Umbrella chart name | plan Task 3's default | before Operator-complete packaging | Helm release migration changes |
| Local directory rename | leave `standalone/swarm-team-six` | after remote merge, before shell automation is standardized | local aliases and memory pointers only; never product behavior |

W3-27 is not an open decision. It is an integrator ruling required to preserve D2 and ADR 0014:
the Tauri process may depend on `swarm-perch-wire`, but that crate may depend on no other
`swarm-*` package. Engine conversions and signing live in the bridge; the desktop verifies the
shared canonical bytes with its own Ed25519 implementation.

---

## 5. Milestone 0 — Ground

**Plan:** `11-PLAN-GROUND.md` · **size:** about 11.5 engineer-days · **expected wall clock with two
tracks:** about six working days.

**Entry:** gate zero accepted; D3/D4 and commit policy confirmed; branch clean; Hermit active for
workspace Git and hook operations.

### Engine track

1. Apply `swarm:` / `swarm.perch.*` to every wave-2 artifact and regenerate every hash pin.
2. Re-land relay kind 46010 and p-gate behavior directly against the merged workspace.
3. Add the repair-kinds constant and its equality test.
4. Add `nostr_pubkey` to the operator principal and validate it fail-closed.
5. Land the signed debug ruleset and signer binary.
6. Compose the detect-only local stack and add the engine CI `changes` job.

### Workspace track

1. Split `AppShell.tsx`, `MessageRow.tsx` and `HomeView.tsx` before feature edits consume their last
   gate-line headroom.
2. Remove animated-avatar capture and the remote script host; pin the CSP.
3. Gate every content-signing path against reserved `swarm:*` markers and kind 46010.
4. Replace the hand-maintained community reset list with the typed exhaustive registry.
5. Replace the four ws-client panic sites with typed errors.
6. Add the `perch` preview entry, off by default.

**Join:** the local stack uses the re-landed relay, the new principal field and the repaired
ws-client; the desktop is below its file-size ceilings and its sign/reset boundaries are gated.

**Exit:** all fourteen Ground criteria pass, including real 46010 admission and p-gate rejection,
the omission mutation for the sign-gate inventory, community-switching E2E, a release refusal of
the debug ruleset, root gates, `workspace/just ci`, and a clean combined tree. Record the exit SHA
and hosted run URLs in this roadmap's evidence index.

**Uncuttable:** relay authorization, CSP pin, sign gate, resetter registry, panic removal and real
stack. A prettier split layout is not a substitute for any of them.

---

## 6. Milestone 1 — First card

**Plan:** `12-PLAN-FIRST-CARD.md` · **size:** 74.5 engineer-days / 14.9 engineer-weeks.

**Entry:** Ground accepted; D-FC-1 through D-FC-5 confirmed; detect-only dev stack green; exact
golden corpus hashes known.

### Engine / bridge critical path

1. Build the transport-neutral wire crate and TypeScript mirror; prove dual-toolchain compilation,
   zero internal `swarm-*` dependencies and engine-versus-wire JCS parity.
2. Build the bridge skeleton and exhaustive `RuntimeEvent` classifier.
3. Land disk spool recovery, receive-before-network ordering, per-issuer sequence assignment,
   redaction, NIP-42 identities, 1 Hz pacer, retry window and metrics.
4. Mount the bridge into `swarm_detect` with bounded shutdown.
5. Land B3r, B3i, B3 and `RuntimeEvent::CasePromoted`.
6. Let the bridge create the case channel and twelve lane channels idempotently.

### Desktop track

1. Add the case route and use the off-by-default feature gate.
2. Add exact marker parsing, raw-signer admission, adversary-text escaping and the finding-card
   registry entry.
3. Add the seven-REQ budget, gap state and community resetters.
4. Add the five-route Tauri client, fixed daemon routes and write-allowlist gate.
5. Add the finding-subject verdict schema and the one sanctioned relay signer.
6. Add the delegated E2E module, E promotion, D two-legged feedback, visible write states and
   leg-2-only retry.
7. Land the copy gate with real Perch source as its first required subject; report the W3-24
   `docs/assets` deferral conspicuously rather than claiming complete asset coverage.

**Exit narrative:** one real detector finding is spooled, published, stored and admitted; E causes
the daemon to mint an incident/case and the bridge to create it; D publishes one operator intent
card and separately records feedback; only the daemon acknowledgement changes the tuning report.
The evidence file joins every id and includes both an unadmitted-signer negative control and a
daemon-down-between-legs recovery.

**Stop conditions:** any engine dependency in `swarm-perch-wire`; any canonical-byte mismatch;
any generic renderer-to-daemon passthrough; any action on an unadmitted marker; any retry that
re-signs leg 1; or a mock-only demonstration with no real Tauri/relay/daemon evidence.

---

## 7. Milestone 2 — The hold

**Plan:** `13-PLAN-THE-HOLD.md` · **size:** 94 engineer-days / 18.8 engineer-weeks.

**Entry:** First card accepted; live-response dev profile and durable hold-store path configured;
operator verdict-key decision recorded; the bridge can route a real case and the copy/admission
gates already run in CI.

### Daemon / bridge critical path

1. Confirm D4 and the verdict-key contract.
2. Add `ResponseHoldSettings`, `HeldAction`, the state machine, guard, memory/file stores and
   restart recovery in `swarm-runtime/src/held_action.rs`.
3. Publish `RuntimeEvent::ResponseHeld` for creation and every terminal transition.
4. Intercept RequireHuman, sweep expiry/stalled decisions, and mount B2r, B2o, B2g, B2, B5.
5. Extend the bridge with the hold store, case/card/notice callbacks and global 26006 alarm.
6. Re-land relay verification for the hold notice and repair kinds against the real stack.

### Desktop track

1. Extend the delegated fixture only after the daemon DTOs freeze.
2. Add hold reads, verdict signing, decide command and the second signing-funnel inventory.
3. Build the ephemeral store, reconciliation, The Watch queues and instrumentation.
4. Build the fixed-order Verdict Row, grant dwell/read gate, refusal path and keymap.
5. Implement the two-legged hold decision, 409 re-read, supersession update and two-console test.
6. Flip the `perch` feature on by default only in the exit task.

**Exit narrative:** a real RequireHuman decision becomes a durable hold, a case card, p-gated
notice and global alarm; grant cannot execute before blast-radius visibility and dwell; refusal
never dispatches; restart, expiry, late governance refusal and two-console races remain legible and
correct. Exactly one daemon decision record is authoritative.

**Uncuttable:** durable store before queue, CAS before dispatch, B2g re-evaluation, B2o operator
attribution, signed intent before daemon decision, two-console authority rule, and the real
live-response workflow. A fixture-backed queue is not a milestone exit.

---

## 8. Milestone 3 — Operator-complete

**Plan:** `14-PLAN-OPERATOR-COMPLETE.md` · **size:** 135 engineer-days / 27
engineer-weeks, plus an optional five-day laptop sidecar.

**Entry:** The hold accepted with durable storage; all fourteen surface ids remain closed; the
three Operator-complete decisions are recorded; no unresolved wire/resetter/path contradiction
remains.

### Engine and bridge

1. Add B4 deposits read and B1c containment-release events.
2. Stamp partition state at hold and execution through the existing `perch_ops/holds.rs` path.
3. Add B6 signing in the bridge, per-issuer durable chain heads, and Tauri-side independent
   verification over the transport-neutral wire bytes.
4. Publish lease, rollback and lane-topic edge cards without widening INV-01.
5. Add the policy read and the on-demand tuning/coverage reads the surfaces require.

### Console surfaces

1. `/leases` containment board and release outcomes.
2. `/lanes/$laneId` plus the fixed lane sidebar.
3. Governance strip on every surface.
4. `/ledger`, export bundle, tier-2 verification and the closed Cmd-K omnibox.
5. `/tuning`, `/gaps`, `/policy`, `/handoff`.
6. Case canvas, kill-chain graph and case-pinned terminal.
7. `/watch-floor` and the six dependency-free SVG primitives.
8. Remaining route/surface/notification/tier/copy gates; atomically activate the deferred
   `docs/assets` copy scope and clear all twelve SVGs.
9. Compose hardening and the relay/Postgres/Redis Helm composition.

The optional laptop sidecar is the only pre-authorized cut. Omitting it changes no exit criterion
numbered 1–14. Cutting any required surface or B6 means the milestone is a partial release, not
Operator-complete, and requires a written amendment. If schedule pressure forces a partial order,
carry the old sequence—policy shadow analysis, handoff frontier transfer, case terminal, then B6—
but never describe tier-0 cards as tier 2 and never call the partial state complete.

**Exit narrative:** all fourteen surfaces work against one packaged deployment; signed bridge
cards verify at tier 2 and chain per issuer; leases/rollback remain honest under partition and
inverse failure; Ledger export preserves source bytes and states what it cannot answer; Watchfloor
survives its soak; Helm and compose enforce the network boundary.

---

## 9. Staffing and schedule model

All estimates are engineer effort, not elapsed calendar promises.

| Work | Engineer-days | Engineer-weeks |
|---|---:|---:|
| Ground | 11.5 | 2.3 |
| First card | 74.5 | 14.9 |
| The hold | 94 | 18.8 |
| Operator-complete | 135 | 27.0 |
| **Remaining required implementation** | **315** | **63.0** |
| Optional sidecar | 5 | 1.0 |

Migration effort already spent is excluded. Gate-zero hosted landing adds roughly half a day if
the baseline is green; it is not buried in an implementation milestone.

Recommended team shape:

- **1 engine Rust owner:** bridge, runtime, stores, routes, signing, relay integration. This is the
  serial constraint and must have a named reviewer for the hold state machine and B6.
- **2 desktop engineers:** one on evidence/Watch/decision flows, one on surfaces/viz/export. They
  share the wire/DTO review and do not independently invent schemas.
- **0.5 platform/test capacity:** CI, dev stack, Helm, real workflow evidence, soak and hosted-run
  triage. Without this capacity the Rust owner becomes the de facto operator and the schedule
  lengthens.

With that 3.5-FTE shape, ideal division understates the calendar because the Rust chain is serial.
The current task estimates imply roughly **29–33 working weeks** after gate zero, assuming decisions
arrive at entry, no cross-milestone rework, and one engineer is not the sole reviewer of their own
safety-critical state machine. Confidence: **moderate**. Re-estimate at every milestone exit from
actual task days; do not reinterpret engineer-weeks as elapsed weeks.

---

## 10. Evidence index and release discipline

Create one row when a milestone exits; until then its state is `not accepted`.

| Milestone | Exit SHA | Local combined gates | Hosted run | Real workflow evidence | State |
|---|---|---|---|---|---|
| Repository baseline | — | migration plan Tasks 1–8 only | — | n/a | not landed |
| Ground | `49a535535` | root build/fmt/clippy/tests + 13 gate scripts; `workspace/just ci`; smoke E2E | Workspace CI 25/25 on PR #13 | `evidence/ground.md` | **accepted 2026-09-03** |
| First card | `642270647` | root fmt/clippy/tests, six tool gates, copy + write-allowlist gates, provisioning test | pending on PR | `evidence/first-card.md` | **not self-declared accepted** — all 24 tasks implemented and gates green; the walking skeleton ran 2026-09-05 with `E`, `D`, both controls (`evidence/walking-skeleton.md`), the console's commands live through Tauri IPC and the rendered tree mock-backed; the owner's read |
| The hold | `9c2d7ad41` | root build/fmt/clippy + 1,543 workspace tests; all 18 tool gates; Tauri clippy + 3,086 tests; desktop check/typecheck/6,040 unit tests; file-size ratchet | pending on PR | `evidence/the-hold.md` | **not accepted** — the daemon-and-relay half ran live end to end (hold produced, filed, addressed, refused, granted with a 60 s lease, replayed, 409 on conflict); the CONSOLE half's commands were driven live 2026-09-05 through Tauri IPC — grant to `executed` with a lease, refuse, replay, `refused_late` with its rule (`evidence/walking-skeleton.md`); the rendered tree remains mock-backed; the owner's read |
| Operator-complete | `b766c16d0` | root build/fmt/clippy + 1,609 workspace tests; all 22 tool gates; Tauri clippy + 3,123 tests; desktop check + 6,232 unit tests + 46 perch E2E; 12 chart tests; `workspace/just ci` exit 0 | **16/16 green on PR #16 at this SHA** — the first green run of this stack | `evidence/operator-complete.md` | **not self-declared accepted** — all 22 tasks implemented and every gate green; the console's commands driven live 2026-09-05 (`evidence/walking-skeleton.md`), which found two wire-shape defects (`4ce2dcdb1`) and filed W3-38–W3-40; the rendered tree on a real window is the seam; the owner's read |

Each evidence record contains:

- exact commit and dirty-tree state;
- toolchain versions and service image digests;
- commands and terminal outcomes, including negative/mutation controls;
- device or simulator and community/deployment exercised;
- ids joining the daemon record, bridge spool, relay event and desktop render;
- known limitations stated as limitations, never converted into green checks.

An internal release candidate requires Operator-complete exit, both hosted workflows green on the
same SHA, install/package evidence, the network-policy check, and a clean checkout reproduction.
Unsigned internal distribution remains a separate accepted packaging fact; managed external
distribution reopens signing/notarization as its own project.

---

## 11. Product measures and reversal rules

The metrics ship on The Watch at The hold exit and are evaluated after eight weeks of live use:

| Measure | Baseline | Target / interpretation |
|---|---|---|
| Page open → verdict recorded | undefined; no path exists today | instrument at The hold; after eight weeks p50 < 90 s and p90 < 8 min; p50 below about 15 s is a habituation warning, not automatically success |
| Operator `FalsePositiveMeasurement` records | 0 | greater than 0 at The hold exit; at least 20/week in a single-analyst deployment after eight weeks |
| Friday recommendations sourced from this week's verdicts | 0 | at least 0.5 of supporting signals after eight weeks |
| Sequence gaps | 0 | any nonzero value is P0 until explained and repaired |
| Console/`swarmctl` concentration disagreement | 0 | one reproducible disagreement blocks release |
| Cases promoted ÷ suppressed | unmeasured | between 1:5 and 5:1; outside it re-open the promotion bar |
| Required bridge-authored cards above tier 0 after B6 | 0 before B6 | 100% after B6; any unsigned branch blocks Operator-complete |

Only K3 survives the repository/whole-workspace decision: if a third stored event kind is needed
within two quarters of The hold, the marker-comment strategy failed and the project must price a
proper kind family across Rust, desktop and mobile registries. K1, K1b and K2 are retired by D2/D3,
not silently forgotten.

The softer product reversal also survives: fewer than five operator-written
`FalsePositiveMeasurement` records per week by the end of the Operator-complete measurement window
means operators do not want the queue. Do not respond by adding more surfaces.

---

## 12. Risk register for execution

| Risk | Early evidence | Response |
|---|---|---|
| First push makes every workspace file look new | file-size ratchet reports inherited over-cap files | choose gate-zero A or exact one-run B; remove any override immediately |
| Wire crate pulls engine into Tauri | metadata lists another `swarm-*` dependency or Rust 1.95 build fails | stop; preserve W3-27; move conversion/signing back to bridge |
| Two canonicalizers disagree | any golden/RFC byte mismatch | stop B6 and signatures; reduce to the smallest vector and fix before new schema work |
| Imported plans drift from landed code | wrong file, route constant or resetter name in a task | update decision row and all downstream plans before implementation, never improvise silently |
| Mock becomes the product contract | mock E2E green while real ids cannot be joined | milestone remains unaccepted; repair real workflow first |
| Relay and daemon failure are conflated | operator sees generic "events stopped" | preserve separate metrics/runbooks for Redis relay fan-out and daemon/NATS substrate |
| Two-legged write is visually collapsed | checkmark or success copy appears after relay OK | fail the UI gate; render recorded and daemon-acknowledged separately |
| Community switch leaks module state | a new Map/cache lacks a registry member | fail the exhaustive resetter test in the same commit |
| Operator key provisioning arrives late | Task 13 begins with no verified public-key source | stop The hold; decide and test multi-workstation behavior first |
| Rust bus factor dominates calendar | one engineer authors and approves store/signing changes | pair review the state machine and B6; use independent failure-injection tests |
| Packaging exposes port 9090 | deployment diagram or values allow operator-LAN access | block release; console reaches daemon only through Tauri and named routes |

---

## 13. The next five actions

1. The owner selects migration Task 9 **A or B** and confirms signed-off Conventional Commits.
2. Re-run the clean migration gates, inspect live branch protection, and land the merged baseline.
3. Record D3 and D4 confirmation; create the Ground execution board directly from its fourteen
   tasks without copying prose into a second planning system.
4. Execute Ground's engine and workspace tracks in parallel, merging only at the named join.
5. Accept Ground on one combined SHA before starting the First-card bridge implementation.

The roadmap ends there operationally on purpose: the next action after planning is not another
design pass. It is choosing the first-push route and establishing a hosted baseline the later gates
can trust.
