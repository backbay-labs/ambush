# Perch — the build set

Wave 2. Sixteen artifacts a team builds *from*: drawn screens, real schemas, real signatures, real
tests, a real task list. Wave 1 (`../`) says **what** Perch is; this directory says **what you type**.

**Three files first, in this order:**

1. **[`gallery.html`](gallery.html)** — open it by double-clicking. The drawn work, presented: five
   prototypes with what each shows, the palette as real swatches with its measured contrast, the four
   ramps and the six chart primitives. This is the fastest way to understand what was built.
2. **[`00-REGISTRY.md`](00-REGISTRY.md)** — the values more than one artifact tried to decide, each
   with one ratified answer and one owner. **It wins over any artifact that restates one of them.**
   It also carries the consolidated amendment set the wave-1 plan needs — twenty-three rows, not the
   forty-plus that were proposed.
3. **[`20-TASK-BREAKDOWN.md`](20-TASK-BREAKDOWN.md)** and **[`tasks.tsv`](tasks.tsv)** — 55 tasks,
   56.5 engineer-weeks, to the file level, with dependencies. Phase 0 is 27 tasks / 24.75 ew; Phase 1
   is 28 tasks / 31.75 ew.

**The art direction is decided.** [`art/DECISION.md`](art/DECISION.md) — Quiet, with Night
Bridge's guarded throw adopted for the grant control; the tokens already ship in `desktop` on
`block/buzz`.

---

## How this relates to the wave-1 plan set

| | `../` (wave 1) | `./` (wave 2) |
|---|---|---|
| Answers | what Perch is, and why | what to type, and in what order |
| Form | twelve prose documents, ~127k words | sixteen documents plus **225 files** of applicable artifact |
| Authority | `00-BRIEF.md` is the constitution; `APPENDIX-NORMATIVE.md` is the registry | this set **cites** those; where it must change one, `00-REGISTRY.md` §3 files the amendment |
| Reading | `../README.md` has the reading paths | this page has them below |

The wave-1 rule holds unchanged: **a document cites the registry, it does not restate it.** Wave 2
added sixteen artifacts' worth of new cross-cutting decisions without extending the registry, and
each one shipped a private `COMMITMENTS` block declaring its own reading binding. `00-REGISTRY.md`
is the structural fix for that, and it is the only file here with authority over its peers.

---

## The artifacts

### Documents

| # | File | What it is for | Who uses it |
|---|---|---|---|
| **00** | [`00-REGISTRY.md`](00-REGISTRY.md) | the ratified value for anything two artifacts decided differently; the consolidated amendment set | **everyone, first** |
| 10 | [`10-RELAY-FORK.md`](10-RELAY-FORK.md) | the relay fork clause by clause, the upstream PR body, the fallback if upstream declines, and eight E2E tests | the engineer cutting the fork |
| 11 | [`11-BRIDGE-CRATE.md`](11-BRIDGE-CRATE.md) | `swarm-perch-bridge`: modules, the four streams, the disk spool, the coalescer, identity, metrics, failure modes | the engineer writing the Rust |
| 12 | [`12-BACKEND-BILL-API.md`](12-BACKEND-BILL-API.md) | all fifteen bill items as route specs — DTOs, status codes, state machine, the process they mount in | the engineer writing the Rust |
| 13 | [`13-WIRE-SCHEMAS.md`](13-WIRE-SCHEMAS.md) | the seven marker cards, the ephemeral block, the tag budget, the verification tier per card type | both engineers, and the designer |
| 14 | [`14-CLIENT-ARCHITECTURE.md`](14-CLIENT-ARCHITECTURE.md) | the feature tree, routing, React Query keys, the subscription manager, the twelve Tauri commands, `resetColonyState` | the engineer cutting the fork |
| 15 | [`15-FILE-SPLIT-PLAN.md`](15-FILE-SPLIT-PLAN.md) | the unblocking refactor: `AppShell` / `MessageRow` / `HomeView`, ten commits each green | the engineer cutting the fork, **first** |
| 16 | [`16-INVARIANT-TESTS.md`](16-INVARIANT-TESTS.md) | the safety invariants as executable tests, and what cannot be mechanized | both engineers |
| 17 | [`17-COMPONENT-SPECS.md`](17-COMPONENT-SPECS.md) | every new component: props, states, testids, refusals, and the dependency-ordered build order | the designer, then the engineer cutting the fork |
| 18 | [`18-DATAVIZ.md`](18-DATAVIZ.md) | the six chart primitives, the concentration mathematics, the accessibility ledger | the designer |
| 19 | [`19-TOKENS.md`](19-TOKENS.md) | the token package, where every value came from, and the mechanism that forces `--perch-*` | the designer |
| 20 | [`20-TASK-BREAKDOWN.md`](20-TASK-BREAKDOWN.md) | Phase 0 and Phase 1 to the file level, the dependency graph, the critical path, the walking skeleton | the person planning the work |
| 21 | [`21-ADRS.md`](21-ADRS.md) | eight ADRs written to move into `docs/decisions/` verbatim, plus the four questions that decide the schedule | everyone |
| 22 | [`22-DEMO-FIXTURE.md`](22-DEMO-FIXTURE.md) | the canonical scenario, its arithmetic, and the seven-minute demo script | everyone |

### Applicable files

| Path | Files | What it is | Runnable? |
|---|---:|---|---|
| [`prototypes/`](prototypes/) | 5 | the drawn surfaces — standalone HTML, no build step, no network | **open by double-clicking** |
| [`gallery.html`](gallery.html) | 1 | this set's presentation of the drawn work | **open by double-clicking** |
| [`tokens/`](tokens/) | 6 | `perch-tokens.css`, the Buzz-name bridge, the alias table, `severity.ts`, the Tailwind preset | `node tokens/perch-tokens.test.mjs` — 20/20 |
| [`schemas/`](schemas/) | 18 | JSON Schema for the seven cards, the eight frames, `46010`, and the shared `$defs` | validated by `fixtures/validate.mjs` |
| [`skeleton/perch-wire/`](skeleton/perch-wire/) | 25 | the wire crate: Rust types, a TypeScript mirror, zod decoders, 16 golden vectors, a pinned hash, a parity gate | `bash skeleton/perch-wire/parity-gate.sh` — 312 fields |
| [`skeleton/swarm-perch-bridge/`](skeleton/swarm-perch-bridge/) | 20 | the bridge crate's module skeleton with its doc contracts | no — no crate to build into |
| [`skeleton/desktop/`](skeleton/desktop/) | 8 | the client's new files: routes, keys, subscriptions, the Tauri surface, the boundary | no — drop-in sources |
| [`skeleton/tools/`](skeleton/tools/), [`skeleton/scripts/`](skeleton/scripts/) | 13 | the CI gates, both halves of the copy gate, their shared ban list and fixture corpus | yes — all refuse to pass silently |
| [`skeleton/tests/`](skeleton/tests/) | 12 | Playwright specs, node registry tests, Rust invariant tests | node ones run; Rust ones have no crate |
| [`fixtures/`](fixtures/) | 51 | the canonical demo fixture, 24 wire vectors, 8 HTTP snapshots, the mock-bridge data, the demo script | `node fixtures/validate.mjs` — 0 failures |
| [`patches/`](patches/) | 2 | the two relay patches, as real diffs | `git apply --check` — both clean |
| [`openapi/`](openapi/) | 5 | the operator OpenAPI in JSON and YAML, its generator and its CI gate | `python3 openapi/render-perch-openapi.py --check` |
| [`adr/`](adr/) | 8 | ADRs 0011–0018, in this repository's format, ready to move verbatim | — |
| [`refactor/`](refactor/) | 9 | the extracted modules for the file split, plus the line ledger that proves the arithmetic | `node refactor/line-ledger.mjs` |
| [`viz/`](viz/) | 5 | the chart fixture, the render audit, the contrast tool, two CI guards | `node viz/contrast.mjs` — 180 pairs |
| [`tasks.tsv`](tasks.tsv) | 1 | 55 tasks, 8 columns, importable | the self-check in `20` §8 reproduces exactly |

---

## Build order

The order is not negotiable at the top — three things gate everything else, and the first is
unglamorous.

**Phase 0 — Ground (27 tasks, 24.75 ew).**

1. **Split the three capped files first.** `AppShell.tsx`, `MessageRow.tsx` and `HomeView.tsx` sit at
   998 / 999 / 994 lines against a hard 1000-line CI gate. Nothing new can be added to any of them
   until they are split, so this blocks every surface. `15-FILE-SPLIT-PLAN.md`, ten commits, each
   green on its own.
2. **Fork, rebrand, delete.** Huddle, animated avatars, the accent picker, relay-hosted audio. The
   deletion pays for the surfaces.
3. **Apply the relay fork** (`patches/relay-46010.patch`, and `relay-26006-pgate.patch` with it) and
   wire its tests into CI.
4. **Land the token layer, the wire crate, the copy gate and the invariant gates** — each merged
   with the subject it guards, never before it. Three of the four Perch gates exit 1 on a tree with
   no Perch source, which is correct and is why they land with their first subject rather than
   ahead of it.
5. **Ratify the amendment set.** `00-REGISTRY.md` §3 is the list. This is a real task (P0-24) with a
   real cost, because sixteen artifacts cite values that must stop disagreeing before anyone writes
   a decoder against them.

**Phase 1 — The Hold (28 tasks, 31.75 ew).** B1 first — the `HeldActionStore` and its state machine —
because nothing else in the phase means anything without a hold to decide. Then B2 (the decide
route), B2r (the reads that are the reconciliation authority), the bridge, and the five frontend
surfaces. The critical path is 34 of the 55 tasks; `20` §6 walks it.

**The walking skeleton** (`20` §8) is the thing to build on day one of Phase 1: real telemetry into
the daemon, a real detection, a real hold, a real card across the seam, a real verdict. It is written
as a runnable script and it is the only artifact that proves the two repositories can talk.

---

## What is verified, and what is proposed

**Verified** means it was run this session, from its committed path, and reproduced its number.

Two conventions before the tables. `adr/00NN` appearing in prose is shorthand for the numbered file
in [`adr/`](adr/); the four links in the reading paths below are the full names. And the vocabulary
ban list is scoped to Perch's **own rendered strings** (RF-A5, `00-REGISTRY.md` §2) — it is not run
against plan prose, patches or PR bodies, which necessarily quote the words the product may not use.
[`gallery.html`](gallery.html) *is* rendered strings, and it passes: 954 scanned, 0 hits.

| Verified | Evidence |
|---|---|
| Both relay patches | `git apply --check` exits 0 at `block/buzz@eed74bde2`, clean tree |
| The fixture corpus | `fixtures/validate.mjs`: 0 failures, 14 envelope hashes recomputed and matched, 3 issuer chains intact; `shasum -c SHA256SUMS` clean |
| The golden vectors | `GOLDEN.sha256` reproduces exactly: 16 vectors, sorted by filename, manifest excluded |
| The wire parity gate | 312 declared fields across 17 schemas, present on both the Rust and zod sides, exit 0, no env overrides |
| The token package | `perch-tokens.test.mjs` 20/20, including the new **T-M2** that asserts the `--perch-*` rename was *applied*, not merely tabled |
| The palette | `viz/contrast.mjs`: 180 ink-on-surface pairs from the shipping CSS, **0 below bar in either theme**, lowest readable 4.74:1 |
| The drawn surfaces | `viz/render-audit.mjs`: 36 render combinations clean; type census 594 nodes, 43.4% ≥14px, **0 at 8px** |
| The concentration arithmetic | `viz/dataviz-fixture.mjs`: 5 canonical checkpoints reproduced to six decimals |
| The OpenAPI | `render-perch-openapi.py --check`: self-test round-trips byte-identically; JSON matches the authoring YAML |
| The key map | `perchKeymapRegistry.test.mjs` 8/8 against `APPENDIX-NORMATIVE.md` §2 |
| The refactor arithmetic | `refactor/line-ledger.mjs`: every anchor matched against the real Buzz files |
| The copy gate's two halves | the `.mjs` runner reports `19 (file, row) pair(s), exact match` over the shared corpus; the `.sh` runner finds 29 real violations in 12 of 20 assets and exits 1 |
| The task list | `20` §8's own `awk` self-check reproduces `rows=55 total=56.50 P0=27/24.75 P1=28/31.75 critical=34 not-cuttable=17` |
| The CI gates' refusal behaviour | all four `check-perch-*` scripts refuse to pass over a tree nobody supplied, and print the wiring |

| Proposed — specified and priced, but not built | Note |
|---|---|
| Every backend bill route | none of the fifteen exists. `12` specifies them to the DTO |
| `swarm-perch-bridge` and `swarm-perch-wire` | no crate exists to compile them into; nothing here has been built |
| Every `tools/check-perch-*` path cited anywhere | Buzz has **no `tools/` directory**; this workspace's holds 14 other `check-*.sh` and not these |
| `desktop/src/features/perch/` | does not exist at `eed74bde2` |
| `skeleton/perch-wire/ts/golden.test.mjs` | correct for its destination; **cannot be run from here** — it needs Buzz's TS test loader and an installed `zod`. Not demonstrated either way |
| The `#watch` operations channel | retired by `00-REGISTRY.md` R-1, not built |

---

## Reading paths

**The engineer cutting the fork** (Buzz, TypeScript + Tauri Rust).
`00-REGISTRY.md` → `15-FILE-SPLIT-PLAN.md` (start here; it blocks you) → [`adr/0011`](adr/0011-perch-shell-is-the-buzz-desktop-app.md), [`adr/0014`](adr/0014-two-legged-writes-and-the-process-boundary.md) →
`14-CLIENT-ARCHITECTURE.md` → `10-RELAY-FORK.md` → `17-COMPONENT-SPECS.md` §12's build order →
`16-INVARIANT-TESTS.md`. Keep `prototypes/watch.html` and `prototypes/verdict-hold.html` open beside
the component sheet; they are the same surfaces and they draw the states the sheet only names.

**The engineer writing the Rust** (Ambush, daemon + bridge).
`00-REGISTRY.md` → [`adr/0012`](adr/0012-relay-is-the-substrate-daemon-is-the-only-writer.md) (the single-writer rule you must not break) → `12-BACKEND-BILL-API.md`
§1 (**which process the routes mount in — the plan set got this wrong once**) → `12` §3 (B1, and
nothing works before it) → `11-BRIDGE-CRATE.md` → `13-WIRE-SCHEMAS.md` → `skeleton/perch-wire/`.
Then `20` §8's walking skeleton, which is the first thing worth running.

**The designer.**
[`gallery.html`](gallery.html) → the five prototypes, in the order the gallery lists them →
`19-TOKENS.md` §4 (the measured contrast, and why `--perch-*` is not optional) →
`17-COMPONENT-SPECS.md` §4 (the safety-critical tier) → `18-DATAVIZ.md`. Then
`00-REGISTRY.md` §5, which names the one design question this set could not settle: whether the
density is right for a tired analyst at 3am. Nobody in this run has evidence for that; it needs a
shift of real use.

**The person deciding whether to fund this.**
`21-ADRS.md` §3 (the four questions that decide the schedule) → `20` §2.3 (why the programme is 105
engineer-weeks, not 95) → `20` §6 (the critical path) → `00-REGISTRY.md` §5 (what is still open).

---

## The one rule

Perch never authorizes. A human decision is two legs — a signed `kind:9` intent card published to
the relay, and a separate `POST` to the daemon, which re-derives authority from scratch — and that
is guaranteed by a process boundary, not a convention. [`adr/0014`](adr/0014-two-legged-writes-and-the-process-boundary.md) is the record. Every other
decision in this directory is negotiable; that one is the product.
