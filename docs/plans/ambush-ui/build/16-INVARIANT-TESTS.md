# 16 — The invariants as executable tests

**Status:** build artifact. Turns `08-TRUST-AND-GOVERNANCE-UX.md` §9 into things CI runs.
Values come from `APPENDIX-NORMATIVE.md`; this file never restates one. Where I depart from a
plan document because a ground pass found the source says otherwise, the departure is marked
**CORRECTION** and carries the path:line that forced it.

`[V]` marks a claim I read in source this session. Anything unmarked is a proposal.

**Revision note.** Four red-team critics audited this artifact against real source. Nine findings
were correct and are fixed here; the fixes changed what the client and the wire actually do, not
just wording. §9 lists every one with what changed and how it was re-verified. Two claims I had
made were measured against a file that was not the one in the tree — that is called out in §3 and
in §9 rather than quietly corrected, because the failure mode matters more than the numbers.

---

## 0. What this file decides

| # | Decision | Where |
|---|---|---|
| D1 | The copy gate is **cross-repo**. `tools/check-copy-banned-terms.sh` lives in Ambush (so `check-gates-wired.sh` sees it) and scans a checkout of `block/buzz` supplied through `PERCH_DESKTOP_ROOT`. The second `actions/checkout` is a cost nobody budgeted. | §6.1 |
| D2 | The ban list is **data**, in `tools/copy-ban-list.tsv`, read by the shell gate **and** by `BUZZ desktop/scripts/check-copy-banned-terms.mjs` — which is now written, ships here, and runs the same parity corpus. One place to add, soften or scope a ban. | §6.2 |
| D3 | INV-32 is enforced in its **strict** form: one key, one verdict verb, globally — not "in the same list". Enumerating which row types co-occur would be a second registry that can drift. | §5.32 |
| D4 | INV-14 is enforced by the **type system**, not by a lexical gate. `AdversaryText` is a branded string; `tsc` is the exhaustive half and `check-perch-adversary-strings.sh` guards the brand's four escape hatches. | §5.14 |
| D5 | INV-01 has **two** mechanisms: a Rust `PERCH_DAEMON_WRITES` table consulted at call time (behaviour) and a shell gate over the table's shape (reviewability). Neither alone is the invariant. | §5.1 |
| D6 | INV-08's `UNATTESTED — BY DESIGN` arm is **unassertable today** and its test ships `skip`ped with the blocker named. No Ambush type records partition state at execution. | §5.8, §7.2 |
| D7 | The card-scoped `signed`/`verified` ban is a **DOM assertion**, not a ban-list row. A flat scan cannot see which card a string lands on and would false-fail on "the daemon signed the release attestation". | §6.2 |
| D8 | Wiring the copy gate requires **rewriting strings in 12 of the 20 `docs/assets/*.svg`**, across **eight** ban rows and **41** violations, in the same PR. Measured three times this session — before the ban-list amendments, after them, and after the two self-scan fixes — with the same result each time. | §6.3 |
| **D9** | **The marker guard is placed at the relay-egress boundaries, not on one command**, and its completeness is asserted by set-equality against `egress_guard`'s call sites. `sign_event` was never the only renderer-reachable signer. | §5.29 |
| **D10** | **INV-35 is split into three renderings and the word `FORGED` is struck.** A rendered card is admitted by construction, so no reachable state is a forgery; the shipped default's ordinary restart produces exactly the state the word accused. | §5.35 |
| **D11** | **The strict dwell reading is adopted** for INV-11: the 1500 ms accrues only while BLAST RADIUS is fully visible and freezes otherwise. The appendix's two-condition wording is defeatable by a scroll. | §5.11 |
| **D12** | **A new P0, INV-36: two operators, one hold.** Both signed verdict cards land in the immutable case channel; the losing console publishes `leg2.state: "superseded"` naming the winner. | §5.36 |
| **D13** | **The four gates are wired in Phase 0 and are green there**, via `tools/perch-source-roots.tsv` — a manifest that fails in BOTH directions, so the refusal arrives on the commit that creates the Perch tree without anyone remembering. | §6.4 |
| **D14** | **This artifact binds to peers rather than re-deciding.** The mock-bridge seam is `14-CLIENT-ARCHITECTURE.md`'s; the fixture is `22-DEMO-FIXTURE.md`'s; `hold_id`'s shape is `13-WIRE-SCHEMAS.md`'s. Three private registries became one. | §8 |

---

## 1. The invariants, in one table

**Layer:** where the assertion actually holds. **Priority:** §2. **Gate:** the artifact, all under
`build/skeleton/`.

| ID | Falsifiable assertion | Layer | Gate | P | Blocked on |
|---|---|---|:-:|---|---|
| INV-01 | The set of non-GET requests the console process issues to an Ambush host equals exactly the five B2/B3/B3i/release/review-session routes. An unlisted `(method, path)` is refused **before a socket opens**. | Rust unit + CI guard | `tests/rust/buzz/perch_daemon_client_tests.rs`, `tools/check-perch-write-allowlist.sh` | **P0** | B5 (review-session scope) |
| INV-02 | For each of the 15 `ResponseAction` variants the verdict pane renders 5 `[data-perch-role="verdict-slot"]` elements in the fixed DOM order, none omitted, none with empty text. | Playwright | `tests/playwright/perch-verdict-pane.spec.ts` #01 | **P0** | B1, B2r |
| INV-03 | An enabled Undo affordance exists **iff** `resolve_inverse(action, step)` is `Ok` for every step. `terminate_user_session` is contained **and** irreversible. | Rust unit + Playwright | `tests/rust/ambush/response_taxonomy_invariants.rs`, `perch-verdict-pane.spec.ts` #02 | **P0** | — (Rust half runs today) |
| INV-04 | The five `RollbackStepStatus` variants produce five pairwise-distinct DOM texts and five distinct wire strings; only `Reversed` answers `restored()`. | Rust unit + Playwright | same two files | P1 | — (Rust half runs today) |
| INV-05 | A release answering HTTP 200 with `lease_closed: false` renders in the error register and never the word "Released". | Playwright | `perch-containment.spec.ts` #02 | **P0** | — |
| INV-06 | `remaining_ms` and `expired` occupy two elements; `{0,false}` and `{0,true}` produce different DOM; no `<progress>` under a containment-release role. | Playwright | `perch-containment.spec.ts` #01 | P1 | — |
| INV-07 | Zero enabled extend affordances on a containment surface; exactly one disabled item carrying `data-perch-role="containment-extend-disabled"` and its reason. | CI guard + Playwright | `check-perch-grant-affordance.sh` R5, `perch-containment.spec.ts` #04 | P1 | — |
| INV-08 | `governance_attestation: None` renders the literal `UNATTESTED` in no success register; the `— BY DESIGN` variant renders **iff** partition state at execution was `Partitioned`/`Healing`. | Playwright | `perch-provenance.spec.ts` #02, #03 (**skipped**) | **P0** | §7.2 field addendum |
| INV-09 | Zero matches for `/\d+\s*\/\s*\d+\s*governors?/i` and for `quorum` followed by a fraction, in any rendered string. | CI guard | `tools/copy-ban-list.tsv` row `quorum-fraction` | hygiene | — |
| INV-10 | The grant control never resolves to `buttonVariants()`'s default arm (class **and** computed background), and its accessible name never matches `/^\s*approve\b/i`. | CI guard + Playwright | `check-perch-grant-affordance.sh` R4/R7, `perch-verdict-pane.spec.ts` #03 | **P0** | — |
| INV-11 | `G` arms and is ignored on `event.repeat`; confirm stays disabled until the pane has accrued ≥1500 ms **while BLAST RADIUS was fully visible**, and the accrual **freezes** when it is not; arming resets on `hold_id` change; no grant element exists in a multi-select DOM. | Playwright + CI guard | `perch-verdict-pane.spec.ts` #04, `check-perch-grant-affordance.sh` R2/R3 | **P0** | B1, B2r |
| INV-12 | Every `swarm:verdict:v1` card the console publishes carries an `h` tag equal to the open case's channel UUID. | Rust unit (builder) + E2E | `tests/rust/buzz/identity_perch_gate_tests.rs` (feature-gated); relay E2E | **P0** | relay fork, B2 |
| INV-13 | A verdict card whose `h` tag ≠ the case channel does not render in that case's timeline; the mismatch is named. | Playwright | `perch-marker-admission.spec.ts` #03 | **P0** | — |
| INV-14 | Every wire string field is `AdversaryText`; the brand's four escape hatches (`as` casts, bare-`string` wire fields, template interpolation, `String()`/`toString()`) are absent. | Type + CI guard + Playwright | `tsc`, `tools/check-perch-adversary-strings.sh`, `perch-marker-admission.spec.ts` #05 | **P0** | — |
| INV-15 | Marker sniffing fires only when the marker is the whole of line 0 (`trimEnd`, never `trimStart`) **and** the raw signer is admitted. An unadmitted marker never becomes a card, never enters the queue, never wakes anyone, and is counted. | Playwright | `perch-marker-admission.spec.ts` #01, #02 | **P0** | — |
| INV-16 | Every `data-perch-role="source-count"` element matches `/\d+ sources? \/ \d+ agents?/`. The chart layer accepts only `sourceIds`. | Playwright | `perch-provenance.spec.ts` #05 | P1 | B4 |
| INV-17 | Every `data-perch-role="derived"` element carries a non-empty `data-perch-derived-fn`; `DERIVED.json` is non-empty **iff** at least one derived element rendered. | Playwright | `perch-provenance.spec.ts` #06, #07 | P1 | — |
| INV-18 | A hold reaching `PERCH_HOLD_TTL_MS` undecided becomes `Expired`, produces no receipt / no `AuditTrail` / no capability lease, stays listed, and is not decidable — refused with a **typed** `hold_expired`. | Rust integration + Playwright | `tests/rust/ambush/perch_hold_lifecycle.rs`, `perch-queue-lifecycle.spec.ts` #01 | **P0** | **B1** |
| INV-19 | `/handoff`'s end-watch control is disabled while `expired_undecided > 0` and enabled only after an explicit acknowledgement that does not reduce the count. | Playwright | `perch-queue-lifecycle.spec.ts` #02 | P1 | B1 |
| INV-20 | Exactly four notification classes can produce an OS notification; a fifth registered class fails. | CI guard | `tools/check-perch-notification-fields.sh` (**PROPOSED**, §7.5) | P1 | — |
| INV-21 | All twelve threat-class channels carry `data-perch-muted="true"` on first run; zero carry `"false"`. | Playwright | `perch-queue-lifecycle.spec.ts` #05 | P1 | — |
| INV-22 | No value crossing the Tauri IPC boundary contains the daemon bearer token, across five error shapes; redaction stays visible and does not erase the diagnosis. | Rust unit | `tests/rust/buzz/perch_daemon_client_tests.rs` | **P0** | — |
| INV-23 | `RESETTERS` is `Record<ColonyScopedSingleton, () => void>` — a missing or extra key fails `tsc`; and every `features/perch*` module holding a module-level singleton appears in it. | Type + node:test | `tsc`, `tests/node/perchResetterRegistry.test.mjs` + `perchResetterRegistry.ts` | **P0** | — |
| INV-24 | No empty state contains any of the four banned phrases (**universal**); a `swarm-produced-nothing` state links `/gaps` exactly once and names a technique count; every other state links it zero times and names its own number. | CI guard + Playwright | `copy-ban-list.tsv` row `reassurance`, `perch-queue-lifecycle.spec.ts` #06 | hygiene | — |
| INV-25 | Every verification result renders two `provenance-row` elements: one naming the chain (`Ed25519`/`secp256k1`), one naming the tier (0/1/2). No shield or lock glyph anywhere near it. | Playwright | `perch-provenance.spec.ts` #01 | P1 | B6 for tier 2 |
| INV-26 | A receipt read back from the store is byte-identical to the bytes written; `1.0` survives as `1.0`. | Rust integration | `tests/rust/ambush/perch_hold_lifecycle.rs` | P1 | **B1** |
| INV-27 | No route on the perch operator router names `override`/`force`/`break-glass`/`bypass`; its only non-GET route is `/decide`; no Perch source file carries an override affordance. | Rust unit + CI guard | `perch_hold_lifecycle.rs`, `check-perch-grant-affordance.sh` R6 | **P0** | B1 |
| INV-28 | A daemon `refused_late` renders with `data-perch-register="outcome"`, quotes the rule name and reason verbatim, and offers no retry. The governance arm is drawn as not-yet-reachable. | Playwright | `perch-verdict-pane.spec.ts` #06, #07 | P1 | B2; arm needs B2g |
| INV-29 | No path in the desktop process signs or publishes a governance artifact except `perch_record_verdict`. The guard refuses `kind:46010` and any content whose line 0 is an `ambush:*:v<n>` marker, agrees with the renderer's parse **in both directions**, and is wired at **exactly** the boundaries `egress_guard` is wired at plus `sign_event`. | Rust unit + structural test | `tests/rust/buzz/identity_perch_gate.rs` + `_tests.rs` — **4 of 6 run today, 4/4 green** | **P0** | 2 tests need B2 / the Buzz crate |
| INV-30 | `security.csp` equals the pinned literal; no bare `https:`/`http:`/`wss:`/`ws:` in `connect-src`; no remote host in any fetch directive; no `<meta>` CSP in the live document. | CI guard + Playwright | `scripts/check-csp-pin.mjs`, `perch-marker-admission.spec.ts` #06 | **P0** | delete animated avatars first |
| INV-31 | No binding carrying a `verb` has `key` lowercasing to `"a"`; `Approve`/`Approved` appears in no rendered string. | CI guard + node:test | `check-copy-banned-terms.sh` keymap pass, `copy-ban-list.tsv` row `approve`, `perchKeymapRegistry.test.mjs` + `perchKeymapRegistry.ts` | **P0** | — |
| INV-32 | No key is bound to two different verdict verbs. Asserted over `PERCH_BINDINGS` and again over the rendered key hints in the interleaved queue. | node:test + CI guard + Playwright | `perchKeymapRegistry.test.mjs`, `check-copy-banned-terms.sh`, `perch-queue-lifecycle.spec.ts` #05 | **P0** | — |
| INV-33 | Grant, refuse, release and finding verdict each pass through `sending` → `recorded` → `acknowledged` as three distinct `data-perch-decision-state` values, and no undo affordance exists on any of them. | Playwright | `perch-verdict-pane.spec.ts` #05 | **P0** | B2 |
| INV-34 | In one list carrying both row types, a hold row's snooze is disabled and states its reason; a finding row's is enabled. The registry declares snooze `disabledOn: ["hold"]` rather than omitting it. | Playwright + node:test | `perch-containment.spec.ts` #05, `perchKeymapRegistry.test.mjs` | P1 | — |
| INV-35 | A `kind:46010` on the relay and absent from `GET /v1/response/holds` renders `UNRECONCILED` — with `store_durable` in the reason when the store is not durable, in the destructive register when it is — offers no grant, is excluded from the export manifest, and increments `perch_queue_reconcile_divergences_total`. An **unadmitted** issuer's hold renders **nothing of its own** and increments a **separate** counter. | Rust integration + Playwright | `perch_hold_lifecycle.rs`, `perch-queue-lifecycle.spec.ts` #03a/#03b/#03c | **P0** | B1, B2r |
| **INV-36** | When two consoles decide one hold, the console whose `POST /decide` answers 409 with a decision id that is not its own leg-1 event id publishes an update card with `leg2.state: "superseded"` and `superseded_by` = the winner's event id, stops rendering its own card as the decision, offers no retry and no undo, and the export marks it superseded rather than dropping it. | Playwright + schema | `perch-queue-lifecycle.spec.ts` #04, `schemas/card-swarm-verdict-v1.schema.json` | **P0** | B2 |

**Layer counts.** 5 CI-guard-only · 14 Playwright-only · 3 Rust-only · 12 two-or-more-layer ·
2 type-level (INV-14, INV-23, both with a runtime backstop). Nothing is "runtime assertion only":
a runtime assertion that nobody drives is a comment.

---

## 2. Priority: P0, P1, hygiene

The question is **what a violation costs**, not how hard it is to fix.

### 2.1 P0 — a violation is a safety incident (22)

INV-01 · 02 · 03 · 05 · 08 · 10 · 11 · 12 · 13 · 14 · 15 · 18 · 22 · 23 · 27 · 29 · 30 · 31 · 32 ·
33 · 35 · 36.

Four failure shapes, and every P0 is one of them:

1. **An operator authorizes something they did not intend.** INV-02 (a missing BLAST RADIUS slot),
   INV-03 (an Undo that cannot undo), INV-10/11/31 (a grant that is one keystroke or one primary
   button away), INV-32 (a key that means Dismiss on one row and Refuse on the next), INV-33 (an
   optimistic "done" before the daemon answered).
2. **A destructive action runs, or appears to have run, without a human.** INV-18 (an expired hold
   that dispatches), INV-27 (an override path), INV-01 (a write the console should not be able to
   make), INV-29 (a forged consent record — the renderer minting the evidence that a person
   deliberated).
3. **The console asserts a fact it did not receive.** INV-05 (reading success from a status code
   while a host is still contained), INV-08 (a false attestation state), INV-12/13/15/35 (a card
   from the wrong case, the wrong signer, or no daemon at all, rendered as evidence), INV-36 (a
   human decision record for a decision that did not execute).
4. **Data leaves, or crosses, a boundary.** INV-14 (adversary bytes into the renderer), INV-22 (the
   bearer token into the webview), INV-23 (one colony's findings under another colony's name),
   INV-30 (a CSP that permits an exfiltration `fetch` from anywhere in a 100k-LOC tree).

### 2.2 P1 — an honesty defect an operator could act on wrongly (12)

INV-04 · 06 · 07 · 16 · 17 · 19 · 20 · 21 · 25 · 26 · 28 · 34.

These do not cause a wrong decision on their own; they degrade the operator's model until one
becomes likely. INV-04 conflating `Irreversible` with `Unsupported` teaches "retry it". INV-06
merging `remaining_ms` and `expired` into one bar teaches "the sweep works". INV-21's unmuted
threat-class channels plus level-triggered escalation at 10 Hz
(`AMB crates/swarm-runtime/src/escalation.rs:105-207` — a pure level comparison with no memory of
prior state, publishing one event per over-threshold class per tick) `[V]` produce habituation in
about a day, and habituation is how a P0 eventually happens.

### 2.3 Hygiene (2)

INV-09 and INV-24. Both are pure string bans about claims the product does not make. A violation is
embarrassing and cheap to fix, and neither changes what an operator does next. They are in CI
because a phrase ban that lives in a style guide is a phrase ban that decays; they are not in P1
because calling everything urgent is how a P0 list stops being read.

**Three priority calls worth arguing with.** I put INV-12 in P0 rather than P1: the relay already
requires an `h` tag on `kind:9`, so a *missing* one fails loudly — but a *wrong* one publishes an
operator's decision into a different case's channel, which is a disclosure with a signature on it.
I left INV-07 at P1 rather than P0: there is no extend route on the daemon, so an extend button
could only ever produce a 404. It is an honesty defect, not an authority one. And INV-36 is P0
rather than P1 although the *daemon* resolves the race correctly: the relay does not, the losing
card is immutable and signed, and the Ledger export's `holds/` directory would carry two
unqualified human-decision records for one hold with nothing marking the loser.

---

## 3. The artifacts

```
build/skeleton/
  tools/
    check-copy-banned-terms.sh          INV-31, INV-32, INV-09, INV-24 (phrase half), the ban list
    copy-ban-list.tsv                   the ONE ban list, 13 rows, shared with the Buzz-side .mjs
    copy-ban-allowlist.tsv              deliberately empty; header explains why
    perch-source-roots.tsv          NEW the Phase-0 / tree-landed manifest, shared by all four gates
    lib/perch-roots.sh              NEW the manifest reader; sourced, never enumerated as a gate
    fixtures/copy-corpus/               the .sh/.mjs parity corpus + expected.tsv (both modes)
    check-perch-grant-affordance.sh     INV-07, INV-10, INV-11 (static), INV-27, role closure
    check-perch-adversary-strings.sh    INV-14 (the brand's four escape hatches)
    check-perch-write-allowlist.sh      INV-01 (shape)
    ci-wiring.snippet.yml               the workflow steps — mandatory, see check-gates-wired.sh
  scripts/
    check-csp-pin.mjs                   INV-30 (Buzz-side; wires into `pnpm check`)
    check-copy-banned-terms.mjs     NEW D2's other half; runs the same corpus, same list
  tests/playwright/
    helpers/perchBridge.ts              the Perch fixtures + the two window seams
    perch-verdict-pane.spec.ts          INV-02, 03, 10, 11, 28, 33
    perch-containment.spec.ts           INV-04, 05, 06, 07, 34
    perch-provenance.spec.ts            INV-08, 16, 17, 25, card-scoped signed/verified ban
    perch-marker-admission.spec.ts      INV-13, 14 (runtime), 15, 30 (live half)
    perch-queue-lifecycle.spec.ts       INV-18, 19, 21, 24, 32, 35, 36
  tests/rust/ambush/
    response_taxonomy_invariants.rs     INV-03, INV-04 — COMPILES AGAINST HEAD
    perch_hold_lifecycle.rs             INV-18, 26, 27, 35 — needs B1/B2
  tests/rust/buzz/
    identity_perch_gate.rs              INV-29 implementation (Buzz target: perch_marker_guard.rs)
    identity_perch_gate_tests.rs        INV-29 — 4 of 6 RUN TODAY, 4/4 green
    perch_daemon_client_tests.rs        INV-01 (behaviour), INV-22
  tests/node/
    perchKeymapRegistry.ts          NEW the ratified keymap as data — the test's subject
    perchKeymapRegistry.test.mjs        INV-31, INV-32, INV-34 — RUNS TODAY, 8/8 green
    perchResetterRegistry.ts        NEW the colony-scoped singleton registry
    perchResetterRegistry.test.mjs      INV-23 — RUNS TODAY, 3 pass / 1 named skip
```

**What actually ran this session, and its output.** Not a claim about future CI. Every row was
produced by invoking the exact committed artifact from the exact committed path — the discipline the
review had to impose after three wave-2 claims turned out to be measured against something else.

| Artifact | Run | Result |
|---|---|---|
| `check-copy-banned-terms.sh` | Ambush-shaped tree with the real `docs/assets/`, `PERCH_DESKTOP_ROOT` = real Buzz `desktop/` | exit 1; **41 violations across 12 of 20 assets, 8 ban rows**; fixture and parity corpus clean |
| `check-copy-banned-terms.sh` | same, after the four ban-list exemptions and the two self-scan fixes landed | exit 1; **still 41 / 12 / 8** — no exemption weakened the asset scan |
| `check-copy-banned-terms.sh` | clean synthetic asset tree, no Perch source | exit 0, **WARNING naming the unscanned half**, not a success line |
| `check-copy-banned-terms.sh` | Perch tree present, manifest row still `absent` | exit 1, `LANDED src/features/perch-watch` |
| `check-copy-banned-terms.sh` | manifest flipped, one planted `aria-label="Approve this hold"` | exit 1, the `approve` row fires on the product file |
| `check-copy-banned-terms.sh` | `expected.tsv` mutated by one row | exit 1, parity diff naming the row |
| `check-perch-grant-affordance.sh` | Phase 0 | exit 0 + WARNING; fixture and roots self-test ran |
| `check-perch-grant-affordance.sh` | a grant control with the render-law-6 label and **no** `data-perch-role` | exit 1, **R7** — the defect the old rules were all blind to |
| `check-perch-grant-affordance.sh` | a file calling `perch_decide_hold` and declaring no verdict role | exit 1, **R8** |
| `check-perch-grant-affordance.sh` | the same tree with a properly declared grant control only | exit 0, "clean over 1 file(s)" |
| `check-perch-adversary-strings.sh` | Phase 0; then `` {`${hold.summary}`} `` | exit 0 + WARNING; break → A4 |
| `check-perch-write-allowlist.sh` | Phase 0; then `PERCH_DESKTOP_ROOT` one directory too high | exit 0 + WARNING; wrong path → exit 1 naming `PERCH_DESKTOP_ROOT` |
| `check-csp-pin.mjs` | **the real `BUZZ desktop/src-tauri/tauri.conf.json`** | exit 1, **6 failures**: pin mismatch, four bare schemes, one remote script host |
| `check-copy-banned-terms.mjs` | `--self-test` against the corpus, expected set derived from the **shell** gate | **19 (file, row) pairs, exact match** |
| `identity_perch_gate.rs` + tests | `rustc --edition 2021 --test`, the file as committed | **4 passed, 0 failed**; 2 tests cfg'd out with named blockers |
| `perchKeymapRegistry.test.mjs` | `node --experimental-strip-types --test`, importing the shipped registry | **8/8 pass** |
| `perchKeymapRegistry.ts` | the shell gate's own lexical keymap parser, over the shipped file | clean — the two implementations agree on the real file |
| `perchResetterRegistry.test.mjs` | `node --experimental-strip-types --test` | 3 pass, **1 skip naming its blocker**; the sweep's own detector test fires on both planted violations |

**Two numbers I previously reported that were wrong, and why.** `identity_perch_gate.rs` was
reported as "4/4 green"; the figure was real but it was measured on a four-test file, and the
five-test file actually in the tree did not compile (`E0433` twice plus an `E0282`) because its
fifth test called `crate::commands::perch_writes`, a module my own PROPOSED list says does not
exist. And the two `node:test` files were reported passing while importing sibling `.ts` modules
that were not in the artifact set at all — `ERR_MODULE_NOT_FOUND` on both. Both are fixed by
shipping the missing subjects and feature-gating the blocked test, and both are recorded here rather
than silently corrected: the lesson is the procedure, which is now stated as a rule in §9.

Every shell guard runs a **fixture before the real scan** — planted violations that must be caught
and clean controls that must pass, following `AMB tools/check-single-governor-key.sh:131-224`'s
pattern `[V]`. That fixture earned its place four times this session: awk regex literals in argument
position evaluating to `$0 ~ /re/`; four word-boundary false positives (`release`, `control-plane`,
`resources`, `hunting`); the copy gate's asymmetric refuse-to-pass; and — in the node sweep — an
`includes("registered.ts")` assertion that also matched `unregistered.ts` and was passing while the
sweep flagged its own clean control.

---

## 4. What cannot be mechanized

Stated plainly, because a list of green checks is exactly the artifact that makes people stop
looking.

### 4.1 Six invariants whose *completeness* no gate can establish

| ID | Mechanized | **Not** mechanized | Human review that substitutes |
|---|---|---|---|
| INV-02 | presence and DOM order of five slots, for all 15 variants | **whether the text in a slot is true.** A BLAST RADIUS slot rendering last week's preview passes every assertion here. | The preview is derived through the public `SwarmService::rehearsal_preview` (`AMB crates/swarm-runtime/src/service/runtime_service.rs:861-868`) `[V]` so the pane shows the plan the containment lease will bind. Reviewer's question on any PR touching the pane: *which call produced this value, and is it the same one the daemon will execute from?* |
| INV-14 | the brand's four escape hatches; the wrapper's runtime behaviour | **whether a new wire field was classified correctly.** `AdversaryText` is applied by a human writing the wire type. | The `WIRE_TEXT_FIELDS` list in `check-perch-adversary-strings.sh` is that review, written down: adding a wire field means adding a name there in the same commit, and a reviewer sees a two-file diff. |
| INV-17 | that every marked value names its function, and the `DERIVED.json` iff | **whether an unmarked value is genuinely served.** A console-computed number with no marker is invisible. | Pair the marker with the fetch: any value not traceable to a field on a daemon response must carry `DerivedMarker`. Enforceable later by deriving the served-field set from `openapi/perch-operator-v1.yaml`; not proposed as Phase 1 work. |
| INV-01 | the table's shape, and refusal of an unlisted pair at call time | **a route reached by a mechanism that is not `perch_daemon_request`** — a `reqwest` client constructed elsewhere in the Tauri process. | `check-perch-write-allowlist.sh` W2 greps the Perch Rust surface for non-GET verbs, which catches the obvious case. The rest is the rule that all daemon I/O lives under `src-tauri/src/perch/`, and a reviewer noticing when it does not. |
| INV-27 | the router's route table; the five words people reach for | **a synonym.** "Proceed anyway", "administrative unlock", "expedite". | The structural answer does the real work: the daemon has no override route, so a console override could only ever produce a 404 or a lie. Anyone adding one has to add a daemon route too, and that is a design review. |
| INV-24 | four banned phrases, universally; the `/gaps` link scoping | **whether an empty state's governing number is the *right* number.** "0 of 6 recommendations acted on" passes even if the 6 is stale. | The number is read from the daemon response, never from copy. Reviewer's question: *which field is this rendering?* |

### 4.2 Two invariants that are currently unassertable

- **INV-08's second arm.** See §7.2. No Ambush type records partition state at execution;
  `ResponseGovernanceAudit` is `{governing_agent_id, reason, receipt}`
  (`AMB crates/swarm-response/src/lib.rs:137-142`) `[V]` and `partition_state` appears only on
  `GovernanceStatusReport` (`AMB crates/swarm-policy/src/governance.rs:62-71`) `[V]`, which is the
  *current* state. The test ships `test.skip` with the blocker in the skip reason.
- **INV-25's tier-2 branch.** Needs B6, and B6 is not "add a call": the workspace's one non-test
  `build_signed_envelope` caller derives its keypair from `sha256("approval-ledger-envelope:{id}")`
  — a public identifier — then discards the signature and keeps only `envelope_hash`
  (`AMB crates/swarm-runtime/src/approval.rs:1800-1841`) `[V]`. Until a real signing identity is
  provisioned, tier 2 is unreachable and the badge must say tier 0 or 1.

### 4.3 One thing this whole file cannot do

None of these tests asks whether the operator was **right**. A tuned detector, a well-chosen
`human_gate_severity`, a case worth promoting — the tests assert that the console told the truth
about what it knew. `09`'s C9 counters are the only instrument aimed at whether the loop works, and
they live on `/` because a counter whose home is a Phase-3 surface ships two phases after the claim
it falsifies (brief A6).

---

## 5. Notes on individual invariants

Only where the artifact makes a decision or a ground pass changed something.

### 5.1 INV-01 — two mechanisms, and B3i named twice on purpose

The shell gate reads a Rust table; the Rust test drives the dispatcher. The table is written out a
second time inside the test file, deliberately: a careless author editing both still passes, but the
diff shows two files, and a reviewer looking at a PR that touches the console's write surface in two
places is the outcome the invariant wants.

`POST /v1/operator/incidents` (B3i) is asserted by name in both. It was missing from `08` §9's first
draft of the allowlist and would have failed the build on the first promote-to-case.

The traversal case matters: `perch_daemon_request` takes a **template plus params**, never a
pre-built path, so `/v1/response/holds/../../operator/control/mode/decide` is not a template match.
That is the grep's blind spot, closed by the test.

### 5.3, 5.4 INV-03 / INV-04 — the half that runs today

`tests/rust/ambush/response_taxonomy_invariants.rs` compiles against `HEAD` and needs no bill item.
It asserts the real ladder — **12 destructive → 4 leased → 3 reversible** — against source:
`is_containment_action` matches exactly `QuarantineFile | SuspendProcess | IsolateHost |
TerminateUserSession` (`AMB crates/swarm-runtime/src/containment.rs:54-63`) `[V]`, and
`TerminateUserSession` maps to `InverseGap::Irreversible` with a quotable reason
(`AMB crates/swarm-response/src/rollback.rs:183-189`) `[V]`.

**CORRECTION to `APPENDIX-NORMATIVE.md` §7's badge taxonomy.** The appendix's "two badge families
(12 destructive · 3 reversible)" omits the middle tier. Eight destructive actions are never leased,
so a hold card for `revoke_credential` must render **no** pending containment-lease slot, no
countdown and no rollback receipt — and `terminate_user_session` shows that "has a containment
lease" does not imply "can be undone". Both cases are asserted, in opposite directions. *Proposed
brief amendment: the ladder is three tiers, 12 → 4 → 3.*

Import trap, recorded because it costs a compile: `ResponseRollbackStepKind` lives in
`swarm_core::types` (`:517-533`, fifteen variants) `[V]`, not in `swarm_response::rollback`.

### 5.8 INV-08 — the arm that has no field

Arm 1 (`UNATTESTED`, no success register) is assertable today and is asserted. Arm 2 is not. See
§7.2 for the one-field addendum.

### 5.11 INV-11 — the strict dwell reading, adopted [REVISED]

The appendix words the gate as **two independent conditions**: the BLAST RADIUS block having been
fully visible **and** ≥1500 ms on this `hold_id`. My first draft asserted exactly that, and the
reading is defeatable in the obvious way: open the pane, spend 1.4 s on the ACTION slot, scroll, and
the control enables about 100 ms after the blast radius first appears. That is the anti-habituation
gate the entire two-stroke design exists for, satisfied by a scroll.

`proto-verdict` — the artifact that actually built the gate — found this and committed to the strict
reading: **the 1500 ms accrues only while the BLAST RADIUS block's last child is fully visible, and
freezes (never resets) when it is not.** The strict reading implies both of the appendix's
conditions; the conjunction does not imply the strict one. That correction did not propagate into
this file in wave 2. It has now.

`perch-verdict-pane.spec.ts` #04 asserts the **freeze**, not the conjunction, because a test both
readings pass is a test that does not choose:

- scroll the block out of view mid-dwell, wait **2 s** — comfortably past 1500 ms — and the control
  is still disabled, with the dwell indicator reading `0%`;
- accrue 800 ms with the block fully visible, scroll away, wait 1 s, and the indicator's text is
  **unchanged** (frozen, not reset — a reset punishes an operator who glanced at the queue, and
  punishing a careful operator is how a gate gets removed);
- scroll back and it completes.

**PROPOSED BRIEF AMENDMENT.** `APPENDIX-NORMATIVE.md` §2's `G` row and `08` §3.5 should read
"accrues only while the BLAST RADIUS block is fully visible; freezes otherwise", replacing the
two-condition wording. Until that lands, the appendix and this test disagree and the test is the
stricter of the two.

The gate needs **two** mechanisms and `check-perch-grant-affordance.sh` R3 greps for both: an
`IntersectionObserver` at threshold 1.0 on the block's last child, **and** a periodic
`getBoundingClientRect` sample — because a fast scroll can carry the sentinel past without the
observer ever reporting a full frame. A safety gate must not be defeatable by scroll velocity.

The other three claims are unchanged and separately asserted: `event.repeat` is ignored (house
practice already — `useAppShellKeyboardShortcuts.ts` bails on `!hasPrimaryShortcutModifier ||
altKey || event.repeat || defaultPrevented` before dispatching any of its six chords, `:57-64`
`[V]`); arming resets on `hold_id` change; no grant element exists in a multi-select DOM.

The static half asserts the grant control is declared in **exactly one file** and that file mentions
`.repeat`, `IntersectionObserver` and `1500`. `.repeat` rather than `event.repeat`: the handler's
parameter is named `e` as often as `event`, and a gate that fails on a variable name gets switched
off. The guard's own fixture uses `e.repeat` to prove it.

### 5.14 INV-14 — why the type system and not a gate

INV-14 as written is *"every interpolated string not on the trusted-value allowlist is wrapped"*. A
lexical gate cannot decide that: `{row.summary}` is adversary-controlled and `{row.severity}` is
not, and nothing about the two expressions says so. A gate that guesses produces a wall of false
positives and is switched off, which is worse than no gate.

So: `type AdversaryText = string & { readonly __adversary: unique symbol }`, every wire string field
branded, and `<AdversaryString value={…}>` the only component whose prop accepts it. JSX text
position, `title`, `aria-label`, `alt` and `placeholder` all take `string` and therefore reject it.
`tsc --noEmit` — already on every pre-push `[V]` — is then exhaustive over exactly the thing the
invariant wants.

The shell gate exists only to close four escape hatches: `as string`/`as unknown`/`as any`; a wire
type declaring a bare `string`; **template-literal interpolation**, which coerces a branded string
with no cast at all and would otherwise make the whole scheme decorative; and
`String()`/`.toString()`. A2 and A4 only hold *together* — a value renamed into a local keeps its
type unless a cast laundered it, and A2 is what forbids the cast.

**This is also the only mechanism covering daemon-supplied text**, which the copy gate cannot see at
all. See §7.7.

### 5.15 INV-15 — line-0-exact, and the negative that must still be visible

Five parse cases are driven, including `\r\n` (which passes, because line 0 is `trimEnd`-ed) and a
leading space (which does not, because the strictest reading of "the marker is the entire first
line" is free). Buzz's own sniff is `content.trimStart().startsWith(WAVE_MESSAGE_MARKER)` over
arbitrary body text (`BUZZ desktop/src/features/messages/lib/waveMessage.ts:15-19`, called from
`MessageRow.renderBody`'s `default:` arm at `:414-426`) `[V]` — safe for a wave, unsafe here,
because `ProcessStartEvent.command_line` and `DetectionFinding.evidence` reach this renderer.

**The leading-space case is only safe because of where the guard runs**, and that is now asserted
rather than assumed — see §5.29.

Three separate assertions for the unadmitted case, because a renderer can get one right and the
other two wrong: not a card, not in the queue, not a wake class. And a fourth: it is **still
visible**, as prose, and counted. Dropping an unadmitted governance-shaped card silently would hide
a live attempt from the person best placed to notice it.

### 5.29 INV-29 — the placement, corrected [REVISED]

**The first draft was wrong, and the way it was wrong is the shape worth naming.** It located
`sign_event` at a real line, correctly described that it signs whatever the renderer hands it, and
concluded that gating it closed the verdict-card forgery path. The citation was accurate and the
conclusion was not, because nobody asked *what would still pass*.

`send_channel_message` (`BUZZ desktop/src-tauri/src/commands/messages.rs:409`) `[V]` is a separate
`#[tauri::command]` the renderer calls for every message. It takes `channel_id`, an arbitrary
`content: String` and `kind: Option<u32>`; it reads the operator's key with `state.signing_keys()`
at `:445` `[V]`, builds through `events::build_message` at `:505` `[V]`, signs inside
`submit_event_at_created_at` at `:527` `[V]` and POSTs the event to the relay's `/events`. The first
draft's gate was nowhere in that path. A renderer bug — or a compromised renderer — publishes a
`<!-- swarm:verdict:v1 -->` `kind:9` card into a case channel signed by the operator's own key,
which is the exact identity the admission rule treats as authoritative for verdict cards.

It is worse in one detail. `build_message` is handed `content.trim()` at `:505` `[V]`, which strips
the leading whitespace my own test relied on to make a marker un-sniffable. A gate placed *before*
that trim signs `" <!-- swarm:verdict:v1 -->"` as harmless and the relay stores
`"<!-- swarm:verdict:v1 -->"`, which the renderer parses as a card. Placement has to be after every
transform the content undergoes.

**D9, the placement.** A forged card only matters once it reaches a relay, and Buzz already has a
fail-closed guard at every relay-bound egress boundary with its boundary list written down and a
test that fails the build when a ninth appears: `crate::egress_guard`
(`BUZZ desktop/src-tauri/src/egress_guard.rs:1-58`, table at `:7-17`) `[V]` and
`egress_guard_tests.rs`'s `events_url_inventory_is_fully_guarded` (`:371-380`) `[V]`, which scans
every `.rs` under `src-tauri/src` and compares each file's `/events` URL-construction count **and**
its guard-call count against a site-granular inventory — failing on a new site in a new file, a new
site in an already-listed file, and a deleted guard call beside a surviving egress site.

So `perch_marker_guard` is wired at **exactly the boundaries `egress_guard` is wired at**, plus
`sign_event`. Measured at `BUZZ eed74bde2`, that is eight calls across six files `[V]`:

| File | egress-guard calls | Boundary |
|---|:-:|---|
| `src/relay.rs` | 2 | 2, 4 |
| `src/relay/submit.rs` | 1 | 1 + 3 (the shared funnel `send_channel_message` lands in) |
| `src/huddle/pipeline.rs` | 1 | 5 |
| `src/commands/team_snapshot.rs` | 1 | 6 |
| `src/commands/personas/snapshot/import.rs` | 1 | 7 |
| `src/native_websocket.rs` | 2 | 8 — text and binary frames, the single choke point for every webview-originated relay websocket frame (`:191-207`) `[V]` |

Plus `src/commands/identity.rs` × 1: `sign_event`, pre-sign, before `state.signing_keys()` at
`:115` `[V]`, so a refusal never touches the key. It is not an egress boundary — it hands signed JSON
back to the renderer — so it is declared in `NON_EGRESS_GUARDED_SITES` with its written reason.

**The completeness half is a test, not a promise.**
`perch_marker_guard_call_sites_match_egress_guard` walks `src-tauri/src`, counts both needles per
file, and fails on any file where the counts differ and which is not a declared non-egress site. It
also refuses to pass silently: eight egress calls is the measured floor, and finding fewer means the
needle broke rather than that the tree is clean. A ninth submission path fails an **existing**,
in-tree test first and this one second, which is the property I wanted and could not get from a
hand-written list of publish paths.

**Verification, stated exactly.** `rustc --edition 2021 --test identity_perch_gate.rs` compiles and
runs **4 tests, 4 passed** — the pure-predicate group. The call-site test is
`#[cfg(feature = "perch-boundary")]` (it reads the Buzz crate's own tree through
`CARGO_MANIFEST_DIR`) and the builder test is `#[cfg(feature = "perch-writes")]` (it calls
`commands::perch_writes`, which does not exist and is 14's B2 work). Neither compiles outside the
Buzz crate and neither pretends to. **4 of 6, and the other two name their blockers.**

The sharpest predicate test is `the_gate_matches_the_renderers_parse_exactly`, which asserts
agreement in **both directions**. A string the gate signs and the renderer treats as a card is a
forgery channel. A string the gate refuses and the renderer ignores is a bug report — an operator
who types a marker into a case message to talk about one must not be blocked. Eleven cases, five
signable and six refused, plus one that asserts the trim: `" <!-- swarm:verdict:v1 -->…".trim()`
must be refused, because that is the byte sequence `send_channel_message` actually publishes.

**What INV-29 still does not claim**, and §7.7 repeats it: it does not stop a compromised renderer
signing an ordinary `kind:9` case message (that is the product), and it does not cover a marker
published by a process that is not this one — the bridge, `buzz-cli`, a raw `POST /events` with the
operator's key. The relay fork and the admission rule are what bound those.

### 5.30 INV-30 — the ordering that makes or breaks it

The pinned literal drops `https: http: wss: ws:` from `connect-src`, the `@mediapipe` host from
`script-src`, and `https: http:` from `img-src`/`media-src`. **Pinning first would pin the hole**:
the animated-avatar feature must be deleted before the pin lands, or the literal has to keep the
remote script host and INV-30 asserts nothing worth asserting. Run against the real
`tauri.conf.json` this session the guard produces six failures — the pin mismatch plus one line per
bare scheme plus the remote host — which is the shape a reviewer can act on.

Equality, not a regex, and the failure message says why: a regex forbidding `https:` would pass
`connect-src … https://evil.example`.

Revised this session: the guard now resolves its config through `PERCH_TAURI_CONF` and **refuses
with a named error** rather than throwing an `ENOENT` stack when the path is wrong. An unreadable
config is not a clean CSP, and a stack trace is the shape a reader dismisses as "the script is
broken" rather than "the path is wrong".

### 5.32 INV-32 — the strict reading, decided

INV-32's letter is "in the same list". Every Perch list interleaves at least two row types — the
needs-action queue carries holds *and* findings, which is the entire reason `D` cannot mean both
Refuse and Dismiss — and no surface shows a row type in isolation. Enumerating which pairs co-occur
would be a second registry that can drift from the first. **Decided: one key, one verdict verb,
globally.** Asserted three ways (registry table test, shell keymap pass, rendered key hints) because
this is the invariant a keymap refactor most easily breaks.

The registry test also pins `D` to `dismiss` and asserts `D` is offered on **no** hold row, not even
as a no-op. Dismiss retroactively removes every deposit at or before the marker, keyed on
`FeedbackSuppressionKey { threat_class, event_id }` (`AMB crates/swarm-pheromone/src/substrate.rs:345-348`,
applied inside `concentration_for` at `:1286`) `[V]` — it reaches detectors the operator never
reviewed. Refuse does nothing of the kind.

`tests/node/perchKeymapRegistry.ts` now ships beside the test, so the assertion has a subject. It is
the appendix §2 keymap transcribed, nothing more; the shell gate's lexical parser reads the same
file and finds it clean, which is the cross-implementation half of the same claim.

### 5.35 INV-35 — the split, and why `FORGED` is struck [REVISED]

My first draft made it P0 that a `kind:46010` on the relay and absent from `GET /v1/response/holds`
renders **`FORGED`** in the destructive register. That word is wrong in every reachable case, and
making it P0 made the error load-bearing — it was echoed into `13-WIRE-SCHEMAS.md` §5.4,
`adr/0012` and `17-COMPONENT-SPECS.md`'s `{ status: "absent" }` comment.

Three reasons, in order of how quickly they bite:

1. **It accuses on the shipped default's ordinary restart.** B1's `hold_store_path` defaults to
   `None`, so the store is in memory; after any daemon restart every legitimate open hold is
   relay-known and daemon-unknown. `12-BACKEND-BILL-API.md` §4.3 describes exactly this state and
   calls it *unreconcilable*, answering `store_durable: false`. Two documents had two words for one
   state. The daemon-side word wins, because it is the one with a field behind it.
2. **It is unreachable in its literal sense.** A card renders at all only if its raw signer resolves
   to an admitted issuer (INV-15). A rendered card is therefore never a forgery in the signature
   sense. The only residue — an admitted issuer minting an id no daemon ever held — is a compromised
   bridge, which this console cannot distinguish from a restart and must not pretend to.
3. **A prominent refusal banner keyed on an unadmitted issuer is a plantable signal.**
   `17-COMPONENT-SPECS.md` rules that the unadmitted outcome "renders NOTHING of its own — prose
   fallthrough plus a counter — because a refusal card is a signal an adversary can plant at will".
   A queue an adversary can add rows to is a queue an adversary can use to bury a real one.

**D10, the split.** Three renderings, two counters:

| Case | Renders | Register | Counter |
|---|---|---|---|
| Admitted issuer, absent from a **non-durable** store | `UNRECONCILED`, reason naming `store_durable` | ordinary | `perch_queue_reconcile_divergences_total` |
| Admitted issuer, absent from a **durable** store | `UNRECONCILED`, reason "the daemon has a durable hold store and no record of this hold" | destructive | same |
| **Unadmitted** issuer | nothing of its own; prose fallthrough | — | `perch_frame_unadmitted_total` |

Both `UNRECONCILED` arms offer no grant and are excluded from the export manifest. The counters are
separate deliberately: a reconcile divergence is the daemon and the relay disagreeing; an unadmitted
frame is a stranger talking. Merging them lets an adversary inflate the divergence count until an
operator stops reading it.

`perch-queue-lifecycle.spec.ts` #03a/#03b/#03c drive the three, and each asserts
`not.toContainText(/forged/i)` so a future copy change cannot quietly reintroduce the word.

**PROPOSED BRIEF AMENDMENT.** Strike `FORGED` from INV-35 and from `13-WIRE-SCHEMAS.md` §5.4,
`adr/0012` and `17-COMPONENT-SPECS.md`. The product has no state it can honestly call forged.

The divergence itself is expected and must render rather than being reconciled away: the relay's
mention index is written **outside** the event transaction with failure downgraded to a `warn!`
(`BUZZ crates/buzz-db/src/store/event.rs:1690-1696`) `[V]`, so a hold can be stored, OK'd, and
permanently invisible to the feed.

### 5.36 INV-36 — two operators, one hold [NEW]

Nothing in the wave-2 set handled this, and it is reachable on the shipped default.
`APPENDIX-NORMATIVE.md` §4 layer 1 `p`-tags **every** `OperatorScope::Approve` principal, and
`00-BRIEF.md` §13's declined-amendment note confirms the watch claim does not narrow it. So more
than one console can legitimately hold the same open hold.

The daemon resolves its side: `12-BACKEND-BILL-API.md` §4.4 answers `409 hold_already_deciding` /
`409 hold_already_decided`. The relay does not. Leg 1 is published to the relay **before** leg 2 is
POSTed (`13-WIRE-SCHEMAS.md`'s publish order), the relay has no compare-and-set, and a `kind:9`
event is immutable. Both signed verdict cards land in the case channel and stay there. Without a
qualification, the case channel and the Ledger export's `holds/` directory carry two unqualified
human-decision records for one hold and nothing marks the loser — and the operator who closes the
window leaves the stronger of the two claims standing.

**The losing console is the only party that can publish the qualification.** It is the only one that
knows both which card it published and which 409 it received; the daemon never saw the loser's leg-1
event id in a decision role, and the winner never learns there was a race.

`13-WIRE-SCHEMAS.md` has landed the wire half: `card-swarm-verdict-v1.schema.json`'s `leg2.state`
enum is now `sending | recorded | acknowledged | refused_late | superseded`, with `superseded_by`
(`$ref` `common.schema.json#/$defs/Hex64Lower`) required **non-null exactly when** state is
`superseded` and required null otherwise, asserted by an `allOf`/`oneOf` pair `[V]`. This is the
client half.

`perch-queue-lifecycle.spec.ts` #04 asserts the full shape: `data-perch-decision-state` is
`superseded` and not `recorded`; the outcome names the winning event id and quotes the daemon's
reason; there is no retry (retrying would publish a third card) and no undo (INV-33 does not relax
here); the update card is **published**, not merely rendered, carrying
`data-perch-superseded-by`; and the export marks the loser rather than dropping it — a human intent
record that did not become the decision is still evidence a person deliberated, and deleting it
would be the console editing the record.

---

## 6. The copy gate, in detail

### 6.1 It is cross-repo, and that is a real cost

`APPENDIX-NORMATIVE.md` §§2 and 7 name `tools/check-copy-banned-terms.sh` as the enforcing gate. It
exists in **neither** repository: Buzz has no `tools/` directory at all, and Ambush's `tools/` holds
14 other `check-*.sh` and one `verify-*.sh` `[V]` and not this one. Ten documents cited a filename.

It must live in Ambush, because `tools/check-gates-wired.sh` enumerates every `tools/check-*.sh`
**tracked or untracked** (`git ls-files -c -o --exclude-standard`, `:66-73`) `[V]` and fails on any
not named by a real `run:` step — so an Ambush-side gate is automatically load-bearing. But the copy
it must scan lives in `block/buzz`. Hence `PERCH_DESKTOP_ROOT`, and hence a second `actions/checkout`
in the `gates` job, which today needs no toolchain beyond python3. `tools/ci-wiring.snippet.yml`
carries the exact steps. **Nobody budgeted the second checkout.**

The script refuses to run without it rather than reporting a pass over a directory nobody supplied,
and prints the CI wiring in the refusal.

### 6.2 The ban list is data, and there are now two runners

`tools/copy-ban-list.tsv`, 13 rows, columns `id / severity / flags / minlen / pattern / exempt /
message`. Both the shell gate and `BUZZ desktop/scripts/check-copy-banned-terms.mjs` read it.

**The `.mjs` half now exists.** D2 asserted it in wave 2 and it was not written, which made the
parity test D2 describes impossible — the one missing gate another delivered artifact depended on.
It ships at `build/skeleton/scripts/check-copy-banned-terms.mjs`, resolves the list through
`PERCH_BAN_LIST` or `PERCH_AMBUSH_ROOT` (**not vendored** — one file, two runners), and `SKIP`s with
a printed reason when neither is set so a Buzz contributor with no Ambush checkout is not blocked.
`--require` turns that skip into an error, which is what Buzz CI passes.

**The parity corpus is real and was derived the honest way.** `tools/fixtures/copy-corpus/` now
carries four files — `violations.copy.ts`, `clean.copy.ts`, `violations.markup.tsx`,
`clean.markup.tsx` — covering **both** scan modes; mode rides the filename suffix inside that
directory and a file matching neither suffix is **refused** rather than scanned in the wrong mode.
`expected.tsv` was generated by running the **shell** gate over the corpus and then matched by the
`.mjs`: **19 (file, row) pairs, exact match**, first run. Both scanners run the corpus on every
invocation, and mutating one row of `expected.tsv` produces a named diff from the shell side.

Six scoping decisions inside the list, each written into the file:

- **awk has no `\b`.** The boundary idiom is `(^|[^a-z])word([^a-z]|$)`, needed on five rows. The
  four false positives it fixes were live on this repository's own assets.
- **`Deny` is case-sensitive.** Capital-D `Deny`/`Denied` is banned as an operator control label;
  lowercase mono `deny` as a wire value is fine, which matches the register rule (`lower_snake_case`
  in mono for anything that is a literal config key, action kind or wire field).
- **`sources` is exempt when the same string names an agent**, which is exactly render law 2's
  requirement rather than an approximation of it.
- **The `approve` row exempts the daemon's own reason.** [ADDED] The daemon returns exactly one
  reason for every hold today — `"authorized but held for human approval"`
  (`AMB crates/swarm-policy/src/static_gate.rs:297`, set by `StaticApprovalGate::evaluate` inside
  `swarm_detect --serve` and carried onto every `PolicyDecision` and thus onto B1's `HoldRationale`)
  `[V]` — and render law 1's fourth slot **requires** it be rendered verbatim.
  `12-BACKEND-BILL-API.md` commits it as part of B1's record and two peer prototypes render it. The
  exemption is `static\.human_gate|policy_decision\.reason|rationale\.reason|hold\.reason|authorized but held for human approval`,
  which is `22-DEMO-FIXTURE.md`'s proposed amendment C-A2 plus the literal. Without it, the build
  fails on a required render. Quoting the daemon is not the product claiming an authority.
- **The `bare-lane` row exempts the ratified nav label.** [ADDED] `APPENDIX-NORMATIVE.md` §1's route
  table carries `/lanes` and `/lanes/$laneId`, whose sidebar item and page heading are the bare word
  — naming exactly the twelve threat-class channels the vocabulary ruling permits. The exemption is
  anchored to the **whole string** (`^lanes?$|^open lanes?$|^all lanes?$`), so it exempts a label and
  never a sentence: `open the async lane` still fails, and both cases are in the parity corpus in
  that order so a future "simplification" of the exemption breaks parity. Without this the gate
  fails the product's own ratified route copy.
- **Two rows carry word-boundary exemptions found by self-scan**: `trust-claim` exempts the
  hyphenated-compound form (`[a-z]-proof`, `proof-?read`), and `exclamation` exempts a literal that
  is entirely an HTML comment carrying no other `!`, so the seven marker constants pass. §7.1
  items 5 and 6.
- **`signed`/`verified` on a card is NOT a row.** A flat scan cannot see which card a string lands
  on. It would false-fail on "the daemon signed the release attestation" — true and renderable — and
  still miss `verified` reaching a finding card through a variable. It moves to
  `perch-provenance.spec.ts` #04, which drives the four unsigned card kinds (finding, escalation,
  hold, containment lease — brief A8) and asserts each renders neither token and does render *"no
  signature of its own"*.

**Scope, stated so it survives contact.** Copy modules: every string literal (they are values by
construction). Everywhere else: only `aria-label`/`title`/`placeholder`/`alt` attributes, the six
copy field names, and JSX text nodes — including a text node alone on its own line, which the
`>TEXT<` rule cannot see. Skipped on purpose: whole-line comments, imports, `href=`, `to="`,
`data-testid=`, and test files. `06` §7.2's own note says a guard that fails on
`href="/ledger?q=ambush:lease"` gets switched off in a week; the fixture proves it does not.

**And a scope limit that is not a nicety:** the gate covers **authored literals only**. See §7.7.

### 6.3 Wiring it requires rewriting 12 SVG assets [D8, restated with the full scope]

Run against `AMB docs/assets/` this session: **41 violations in 12 of the 20 files, across eight ban
rows**, every one in an `aria-label` or a `<text>` node — the strings that reach a screen reader or
a rendered chart label. Re-run after the four ban-list exemptions and the two self-scan boundary
fixes landed: **still 41 / 12 / 8**, so no exemption weakened the asset scan. Measured three times.

| Rule | Hits | Files |
|---|:-:|---|
| `bare-lane` | 14 | `architecture` (4), `architecture-mobile` (2), `security-v2` (2), `security-mobile-v2` (2), `pillars` (2), `pillars-mobile` (2) |
| `trust-claim` | 7 | `security-v2` (2), `security-mobile-v2` (2), `pillars` (1), `pillars-mobile` (1), `architecture` (1) |
| `bare-source-count` | 4 | `stigmergy` (2), `stigmergy-mobile` (2) |
| `hunt-noun` | 4 | `paths` (2), `paths-mobile` (2) |
| `clowder` | 4 | `roadmap` (2), `roadmap-mobile` (2) |
| `legacy-codename` | 4 | `pillars`, `pillars-mobile`, `architecture`, `architecture-mobile` |
| `approve` | 2 | `architecture`, `architecture-mobile` |
| `bare-lease` | 2 | `architecture`, `architecture-mobile` |

The twelve files: `architecture`, `architecture-mobile`, `paths`, `paths-mobile`, `pillars`,
`pillars-mobile`, `roadmap`, `roadmap-mobile`, `security-v2`, `security-mobile-v2`, `stigmergy`,
`stigmergy-mobile`.

These are **not** debt to allowlist. An asset whose accessible name carries the legacy codename
cannot appear in a console whose product name is Ambush; `ASYNC LANE` / `CONTEXT LANE` /
`EVOLUTION LANE` are exactly the collision brief A9 exists to resolve; and `Proof` beside a security
diagram is the claim `08` §6.2 spent a section refusing to make. `tools/copy-ban-allowlist.tsv`
therefore ships **empty**, with a header saying so, and the landing PR rewrites the strings.

**Note for `20-TASK-BREAKDOWN.md` P0-25.** Its acceptance criterion names one rule and six files.
The binding figure is this one: **eight** rule classes fire, **41** violations, **twelve** files
change, and every one of the eight is an asset rewrite the PR must carry. `bash tools/check-copy-banned-terms.sh` must exit 0 over
`docs/assets` **before** the workflow step lands, and `check-gates-wired.sh` makes those one commit.
0.5 ew has not priced twelve asset rewrites.

**CORRECTION to `design-ground.md`.** It records six assets carrying the legacy codename; measured,
it is **four** (`architecture`, `architecture-mobile`, `pillars`, `pillars-mobile`) `[V]`. It also
did not record `clowders` in the two roadmap assets, which the appendix bans outright.

**CORRECTION to `05` §5's implied scope.** `hero-v2`/`hero-mobile-v2` say "autonomous threat
hunting". With the word-boundary form `(^|[^a-z])hunts?([^a-z]|$)` these do **not** trip, which is
right: `06` §3 drops `hunt` as a **noun** and keeps `hunt_id` as a field label. The verb is
untouched. Stated so nobody "fixes" the pattern back to a substring match.

### 6.4 Phase 0: the four gates are wired and green, and the refusal still arrives [NEW]

**The problem, measured.** Run from an Ambush-shaped tree with `PERCH_DESKTOP_ROOT` pointed at the
real Buzz `desktop/`, three of the four gates exited 1 — `check-perch-grant-affordance.sh` with "no
Perch source files found … refusing to pass silently", and the other two with the same shape. That
is every tree until the first Perch feature PR. `20-TASK-BREAKDOWN.md`'s T5 puts the gate commit in
Phase 0, and `check-gates-wired.sh` forbids an `if:` other than `always()` / `!cancelled()` /
`success() || failure()` (`PERMISSIVE_CONDITIONS`, `:106`) `[V]`. Landing them as written turned CI
red on the commit that added them.

**The wrong fix is a blanket "tree absent, pass" arm**, because then the refusal never arrives: the
gate stays green forever if a root is renamed, if the checkout path is wrong, or if `desktop/` and
the repo root get mixed up. That is the same silent-green these gates exist to prevent, moved one
level up.

**D13, the mechanism.** `tools/perch-source-roots.tsv` — one row per Perch root, read by all four
gates through `tools/lib/perch-roots.sh` (sourced, and named so `check-gates-wired.sh`'s pathspec
does not enumerate it as a gate). It is wrong in **both** directions:

| Manifest status | Directory | Outcome |
|---|---|---|
| `absent` | missing | WARNING naming the unscanned half; exit 0. The fixture still ran. |
| `absent` | **present** | **HARD FAIL** — the tree landed and the row was not flipped |
| `required` | missing | **HARD FAIL** — renamed root, wrong checkout, or a `desktop/` vs repo-root mix-up |
| `required` | present | scan |
| `probe` | missing | **HARD FAIL** naming `PERCH_DESKTOP_ROOT` as the likely cause |
| `probe` | present | not scanned, not counted as Perch source; the checkout is proved |

**The commit that flips it is not a promise in a document.** It is the commit that creates the
directory, because that commit fails CI until it also flips the row — a one-word diff a reviewer can
see. The `probe` status exists so a totally wrong `PERCH_DESKTOP_ROOT` can never look like Phase 0:
`src-tauri/src/commands` already exists in `block/buzz` at `eed74bde2` `[V]`, so a gate that cannot
find it has not found the Buzz tree at all. Verified: with `PERCH_DESKTOP_ROOT` one directory too
high, the writes gate exits 1 naming the variable.

`perch_roots_selftest` runs inside every gate's fixture and proves all four arms against a throwaway
manifest and tree, because a presence gate that cannot fail is worse than no presence gate.

**The copy gate's asset half is exempt from all of this** and is enforced from day one — which is
why D8's twelve asset rewrites are a Phase-0 cost rather than a Phase-1 one.

---

## 7. Findings the invariant set produced

### 7.1 The gates found six bugs in themselves before finding any in the tree

Four caught by the mandatory fixture, all of the "reports success over a region it never
inspected" shape `AMB .planning/STATE.md` records three times:

1. awk regex literals in argument position evaluating to `$0 ~ /re/`, i.e. `0` or `1` — the
   extractor matched nothing and the gate was green;
2. four word-boundary false positives (`release` → `bare-lease`, `control-plane` → `bare-lane`,
   `resources` → `bare-source-count`, `hunting` → `hunt-noun`);
3. the copy gate's **asymmetric** refuse-to-pass — an asset-half guard and none on the desktop half,
   so `scanned 20 asset(s), 0 copy module(s), 0 component file(s)` printed inside a success message
   with every vocabulary ban unenforced on the product surface (§6.4 and the script's own header);
4. in the resetter sweep, an `includes("registered.ts")` assertion that also matched
   `unregistered.ts` and was passing while the sweep flagged its own clean control.

Two more came from scanning **this artifact set's own files** with the ban list, which is a step
worth making routine because it costs nothing and both were P0-row defects:

5. **`trust-claim` had no word boundary**, so `proof` matched `repeat-proof` — one of my own test
   names. Adding the boundary idiom was not enough on its own: awk's `[^a-z]` treats a hyphen as a
   boundary, so hyphenated compounds still matched. The exempt column now carries `[a-z]-proof` and
   `proof-?read` explicitly, because loosening the boundary class globally would break `bare-lane`,
   which genuinely wants a hyphen to be a boundary. Two rows, two rules, both written down.
6. **`exclamation` fired on every marker literal.** `<!--` contains a `!`, and the seven
   `<!-- ambush:<slug>:v1 -->` markers are wire literals a copy module must carry verbatim. The
   exemption is anchored and `[^!]*`-bounded — `^<!--[^!]*-->$` — so a marker constant passes and
   `<!-- Great news! -->` still fails. Both arms are in the parity corpus.

Neither would have been caught by the corpus as it stood, because the corpus only contained strings
somebody had already thought to write down. Running a gate over the artifacts that describe it is a
cheap second source of cases.

### 7.2 INV-08 needs a field that does not exist — a one-field bill addendum

`ResponseGovernanceAudit` is `{governing_agent_id, reason, receipt}`
(`AMB crates/swarm-response/src/lib.rs:137-142`) `[V]`. `grep -rn partition_state crates --include='*.rs'`
returns hits only in `GovernanceStatusReport`, `TomAgent`'s internal state, `/healthz`'s JSON at
`ingest/mod.rs:1852`, and tests `[V]`. Nothing stamps it on a receipt or a hold.

So the console cannot distinguish "unattested because governance was unreachable under a partition"
from "unattested because nothing attested it", and INV-08's `iff` is unassertable.

**PROPOSED addendum, call it B2g-p (~0.25 ew).** `IngestState` already holds
`Option<Arc<dyn GovernanceAuthority>>` (`AMB crates/swarm-ingest-runtime/src/ingest/mod.rs:1375`)
`[V]`, so `status_report().partition_state` is one call away in the process that creates the hold
and in the one that decides it. Stamp `partition_state_at_hold` on B1's `HoldRecord` and
`partition_state_at_execution` on B2's decide outcome. Without it, `perch-provenance.spec.ts` #03
stays `skip`ped and the badge renders plain `UNATTESTED` in all four partition states — which is
honest, and less informative than `08` §6.2 promises.

### 7.3 The keymap gate cannot be written without the registry existing

`check-copy-banned-terms.sh`'s keymap pass parses
`features/perch/lib/perchKeymapRegistry.ts`. It fails when the Perch tree exists and that file does
not, and it fails when `PERCH_BINDINGS` parses to zero entries or carries no verdict binding, or
when any of the five verbs is unbound. Those four "refusing to pass silently" arms are the ones that
matter: an empty registry would otherwise make INV-31 and INV-32 vacuously true, which is the exact
way this pair of invariants dies.

The registry now ships at `tests/node/perchKeymapRegistry.ts`. Its shape is constrained by the shell
parser — a flat array of flat objects with `key:` and `verb:` as double-quoted literals — and that
constraint is written into the file's header, because a `verb` behind a helper call would be
invisible to the lexical pass and INV-31 would go quiet with nothing failing.

### 7.4 The mock-bridge seam, reconciled to one design [REVISED]

Three artifacts specified three non-interoperable ways to wire Perch into Buzz's E2E mock bridge.
The tiebreak is ownership, not preference, and this artifact owns neither half:

- `14-CLIENT-ARCHITECTURE.md` owns the client seam and commits **one** delegating guard,
  `if (command.startsWith("perch_"))`, before `e2eBridge.ts`'s `default:` throw at `:14594` `[V]`
  (the arm reads `throw new Error(\`Unsupported mocked Tauri command: ${command}\`)`), with fixtures
  in a new `desktop/src/testing/perchBridgeFixtures.ts`.
- `22-DEMO-FIXTURE.md` owns the scenario and commits `fixtures/perch-demo-fixture.json` as canonical
  with every id regenerable by `node fixtures/derive-ids.mjs`.

**Both adopted.** My earlier `src/testing/perch/e2ePerchBridge.ts` module path is withdrawn, and my
own fixture corpus is withdrawn — which removes the second fixture corpus at the same time.
`e2eBridge.ts` is 14,620 lines behind one `switch (command)` and 162 specs depend on it; one line
changes upstream and it is 14's line, not a second one.

**Five window seams became two**, both installed by `perchBridgeFixtures.ts` rather than by
`e2eBridge.ts`:

| Withdrawn | Replaced by | Why the replacement is better, not just cheaper |
|---|---|---|
| `__BUZZ_E2E_PERCH_QUEUE_RECONCILED__` | `[data-perch-queue-reconciled]` | an assertion about what rendered; INV-35 needs the attribute anyway |
| `__BUZZ_E2E_EMIT_PERCH_EPHEMERAL__` | `__BUZZ_E2E_PERCH_CONTROL__.emitEphemeral` | one object, two methods, instead of four globals |
| `__BUZZ_E2E_PERCH_ADVANCE__` | `__BUZZ_E2E_PERCH_CONTROL__.advanceClock` | same |
| `__BUZZ_E2E_PERCH_COUNTER__` | `[data-perch-counter="<name>"]` | a counter nobody renders is a counter nobody reads; the global let it be right and invisible |
| `__BUZZ_E2E_PERCH_EXPORT_MANIFEST__` | `[data-perch-export-manifest]` | same |

The two that remain: `__BUZZ_E2E_PERCH__` (the fixture, seeded by `addInitScript` **before**
`installMockBridge` — React reads state on mount and the bridge triggers mount), which falls back to
the canonical scenario when unset so a spec wanting the demo state seeds nothing; and
`__BUZZ_E2E_PERCH_CONTROL__`, because a 26006 frame is not a Tauri command and not a channel message
and no existing seam carries it, and a frozen clock is what lets INV-18 assert a 60-minute TTL
without sleeping for one.

### 7.5 Three invariants have no artifact in this file

Named rather than quietly dropped:

- **INV-20** (four notification classes) needs `tools/check-perch-notification-fields.sh`, whose
  typed-field allowlist `06` §7.2 already specifies. It is a sibling of the guards here and follows
  the same shape; it is not written because the notification module's shape is
  `14-CLIENT-ARCHITECTURE.md`'s to decide and a gate written against a guess is a gate that gets
  rewritten.
- **INV-12**'s relay half is a `buzz-test-client` E2E (`crates/buzz-test-client/tests/`), which
  needs the relay fork applied. `10-RELAY-FORK.md` owns the patch; the builder-side assertion is in
  `identity_perch_gate_tests.rs` and is feature-gated on B2.
- **INV-26**'s console half — that the export writes the bytes the daemon returned — needs the
  export bundle format, which is `08` §6.4's. The daemon half is written.

### 7.6 The gates are two-part changes, always

`tools/check-gates-wired.sh` counts a script on the commit that **adds** it, tracked or untracked
`[V]`, and rejects a step carrying any `if:` other than `always()`, `!cancelled()` or
`success() || failure()` (`:106`) `[V]`. Adding any of the four shell guards without its workflow
edit in the same PR fails CI in a way that reads like the new guard is broken.
`ci-wiring.snippet.yml` exists so nobody has to rediscover that, and now carries the Phase-0 story
and the measured exit codes as well as the steps.

### 7.7 The copy gate covers authored literals only — and that is the strings that matter least [NEW]

Stated as its own finding because a green line from the copy gate is the single most likely thing to
be over-read.

The markup mode extracts four attribute names, six field names and literal JSX text nodes. It never
sees a value interpolated from a variable. So **every daemon-supplied string reaching a rendered
slot is out of scope, in every case** — and those are the strings an adversary is closest to. The
daemon's own hold reason is the demonstration: exactly one string today, required by render law 1's
fourth slot, containing a word the ban list forbids, and invisible to the gate in both directions
until the exemption was added.

What covers daemon text instead:

- **INV-14's `AdversaryText` brand and `<AdversaryString>`** — the type system, which is exhaustive
  over exactly the set the copy gate cannot see.
- **The card-scoped DOM assertions** in `perch-provenance.spec.ts`, which read rendered output
  rather than source.

Neither is a lexical ban, and neither should become one. But nobody should read "copy gate clean"
as "no banned word will render".

Two further limits, for the same reason:

- **The prototypes under `docs/plans/ambush-ui/build/prototypes/` are out of scope.** They are
  drawings, not product source, and they are not under any root in the manifest. A banned string —
  or an ungated grant control — in a prototype is a review finding against the drawing, not a build
  failure. The grant gate's R7 would catch the peer prototype's ungated grant button if that markup
  were in the Perch tree; it is not, and the gate does not pretend otherwise.
- **INV-29 does not cover processes other than the desktop app.** The bridge, `buzz-cli` and a raw
  `POST /events` with the operator's key are all outside any client-side gate.

### 7.8 The grant gate could not fail on the defect it exists for [NEW]

`check-perch-grant-affordance.sh`'s first version keyed **every** rule on the presence of
`data-perch-role="grant"`: R2 counted declarations, R3 grepped only the declaring file, R4 matched
lines carrying the attribute. A second grant control that simply omits the attribute left the count
at 1 and passed all four at once — while the script's own header claimed the opposite ("which is why
R2 asserts the declaration count rather than only scanning for bad ones"). Counting declarations
inside the roots cannot detect an **undeclared** control anywhere. That sentence is deleted.

Two new rules, keyed on things a second implementation cannot change and still be a grant control:

- **R7, the accessible name.** Render law 6 fixes the words: *record my decision and send it to the
  daemon*. Any line in the Perch tree carrying that phrase must also carry
  `data-perch-role="grant"` within six lines — enough for a multi-attribute JSX opening tag, small
  enough that two adjacent controls do not alias. Its fixture is the real defect shape, transposed
  to TSX from a peer prototype: a `<button className="grant" data-armed=… onClick=…>` with the
  render-law-6 label, no role attribute, no `IntersectionObserver`, no dwell timer and no `1500`.
  Verified: R7 fires on it and passes a properly declared control in the same tree.
- **R8, write reachability.** A control that cannot reach `POST /decide` is not a grant control; one
  that can, is. The literal `perch_decide_hold` may appear under the Perch roots only in files
  declaring `data-perch-role="grant"` or `"refuse"`. Verified: fires on a helper module that calls
  it and declares no role.

R7 catches a control that looks right and is ungated; R8 catches one that is relabelled and still
writes. Neither depends on the attribute the defect omits. The third angle is
`perch-verdict-pane.spec.ts` #03's DOM assertion that exactly one element with that accessible name
exists in a rendered pane — source, source, and rendered output.

---

## 8. Where this artifact binds rather than decides [NEW]

The review's systemic finding was sixteen private registries wearing a COMMITMENTS heading. This
section is the deliberate opposite: every cross-cutting value this file touches, and whose it is.

| Value | Owner | What this file does |
|---|---|---|
| Mock-bridge seam and fixture module path | `14-CLIENT-ARCHITECTURE.md` | binds; withdrew its own competing design (§7.4) |
| The demo scenario and every opaque id | `22-DEMO-FIXTURE.md` | binds; `helpers/perchBridge.ts`'s constants are copied from `fixtures/perch-demo-fixture.json`, and the earlier five-way-conflicting ids are gone |
| `hold_id` shape | `13-WIRE-SCHEMAS.md` (`common.schema.json#/$defs/HoldId`) | binds; `assertHoldId` runs on every fixture hold the helper builds, so a spec cannot invent a seventh format. Fourteen spec fixture ids were renamed to satisfy `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`; four were under 8 characters and would have failed the schema |
| `leg2.state` enum incl. `superseded` | `13-WIRE-SCHEMAS.md` | binds; INV-36 is the client half of a wire decision that landed there |
| The six Perch feature roots | `17-COMPONENT-SPECS.md` §1.1, scoped once in `14` §2.1 | binds; `tools/perch-source-roots.tsv` is the machine-readable copy and cites both |
| `data-perch-role`'s thirteen values | `17-COMPONENT-SPECS.md` §1.4 | binds; R1 asserts closure |
| The keymap | `APPENDIX-NORMATIVE.md` §2 | binds; `perchKeymapRegistry.ts` is a transcription, and §5.11 proposes an amendment to one row rather than diverging silently |
| Token namespace `--perch-*` | `19-TOKENS.md` | binds; INV-10's Playwright assertion reads Buzz's `--primary` deliberately, because the inline-written Buzz variable is the actual threat the grant control must not match. A Perch component reading a bare shadcn name is 19's gate, not this one |
| The three-tier ladder 12 → 4 → 3 | this file, §5.3 | **decides**, and proposes the appendix amendment |
| The strict dwell reading | `proto-verdict`; ratified here | binds, and proposes the appendix amendment (§5.11) |
| `FORGED` struck from INV-35 | this file, §5.35 | **decides**, and names the four documents to change |

**Three proposed brief amendments this file carries**, all under `00-BRIEF.md` §12:

1. The badge taxonomy is three tiers, 12 → 4 → 3 (§5.3).
2. The `G` key's dwell condition is the strict reading (§5.11).
3. `FORGED` is struck; the state is `UNRECONCILED` with `store_durable` in the reason, and the
   unadmitted case renders nothing (§5.35).

And two **bill addenda**:

- **B2g-p**, `partition_state_at_hold` / `partition_state_at_execution`, ~0.25 ew (§7.2).
- **B1-d**, `HeldActionStore::is_durable() -> bool`, from which `GET /v1/response/holds`'s
  `store_durable` is derived. Trivial in cost and load-bearing in effect: it is the single field the
  two `UNRECONCILED` reasons key on, and without it the console must pick one rendering for both
  causes. Asserted in `perch_hold_lifecycle.rs`. `12-BACKEND-BILL-API.md` already commits
  `store_durable` on the response (its D10); this names where the value comes from, so two
  implementations cannot disagree about it.

---

## 9. What the review changed, and how each fix was re-verified [NEW]

| # | Finding | Fix | Re-verified by |
|---|---|---|---|
| 1 | INV-29's gate was on `sign_event` only; `send_channel_message` signs arbitrary content two files over | gate moved to the seven relay-egress boundaries plus `sign_event`, with a set-equality test against `egress_guard`'s call sites | read `messages.rs:409-527`, `relay/submit.rs:16-110`, `relay.rs:637-676`, `native_websocket.rs:191-207`, `egress_guard.rs:1-58`, `egress_guard_tests.rs:263-434`; counted eight guard calls across six files |
| 2 | `identity_perch_gate.rs` did not compile; "4/4" was measured on a different file | fifth test behind `#[cfg(feature = "perch-writes")]`, sixth added behind `perch-boundary`, claim restated as 4 of 6 | `rustc --edition 2021 --test` on the committed file: 4 passed, 0 failed |
| 3 | Three guards exit 1 in Phase 0 but are wired unconditionally | `tools/perch-source-roots.tsv` + `tools/lib/perch-roots.sh`, failing in both directions | all four gates run in Phase 0: exit 0 with WARNINGs; tree-landed → exit 1; wrong `PERCH_DESKTOP_ROOT` → exit 1 |
| 4 | The copy gate reported a pass over zero Perch files | symmetric guard plus the WARNING arm; the zero is never inside a success message | re-ran both arms; clean tree now prints the WARNING and a qualified success line |
| 5 | `bare-lane` fires on the ratified `/lanes` nav label | whole-string exemption, with both cases in the parity corpus | corpus derived from the shell gate, matched exactly by the `.mjs`; asset scan unchanged at 41 / 12 / 8 |
| 6 | The `approve` row fails on the daemon's verbatim hold reason | C-A2's exemption plus the literal; §7.7 states the daemon-text limit | read `static_gate.rs:285-300`; clean corpus file carries the reason and passes |
| 7 | `check-perch-grant-affordance.sh` could not fail on an undeclared grant control | R7 (accessible name) and R8 (write reachability), each with a fixture | R7 fires on the peer prototype's markup transposed to TSX; R8 fires on a stray decide call; both pass a declared control |
| 8 | INV-35 called the shipped default's restart `FORGED` | split into three renderings, two counters; the word struck | reconciled against `12-BACKEND-BILL-API.md` §4.3's `store_durable: false` and `17-COMPONENT-SPECS.md`'s plantable-signal rule |
| 9 | Nothing handled two operators deciding one hold | INV-36, P0, with the two-console E2E | `card-swarm-verdict-v1.schema.json` now carries `superseded` + `superseded_by` with the conditional `allOf` |
| 10 | Both node:test files failed to run — missing sibling modules | `perchKeymapRegistry.ts` and `perchResetterRegistry.ts` ship; the tree sweep skips with a named blocker instead of failing | `node --experimental-strip-types --test`: 8/8 and 3 pass / 1 named skip |
| 11 | Three mock-bridge designs, two fixture corpora | bound to 14's seam and 22's fixture; five window seams down to two | §7.4; helper constants now copied from `perch-demo-fixture.json` |
| 12 | INV-11 asserted the loose dwell reading | strict reading adopted; the test asserts the freeze | `perch-verdict-pane.spec.ts` #04 rewritten with the 2 s out-of-view hold and the frozen-indicator assertion |
| 13 | `desktop/scripts/check-copy-banned-terms.mjs` was named as load-bearing and not written | written, with the parity corpus in both modes | `--self-test`: 19 pairs, exact match against a set derived from the shell gate |
| 14 | `hold_id` had six formats in circulation | bound to `HoldId`; `assertHoldId` on every fixture | fourteen spec ids renamed; all satisfy the pattern |

**The procedural rule this file now follows**, because three wave-2 claims were measured against a
file that was not the one in the tree: **re-run the exact committed artifact from the exact committed
path before quoting a number from it.** Every row in §3's table was produced that way this session,
including the two that had been wrong.

---

## 10. Reading order for someone implementing this

1. `tests/rust/ambush/response_taxonomy_invariants.rs` — compiles against HEAD, needs no bill item,
   and encodes the 12 → 4 → 3 ladder every hold card renders from. Land it first; it is the cheapest
   proof that the taxonomy in the plan set is the taxonomy in the source.
2. `tests/rust/buzz/identity_perch_gate.rs` + `_tests.rs` — INV-29 closes the forged-consent hole and
   four of its six tests run today. It is Phase 0 work and it is small. Wire the guard at all seven
   sites in one commit; the call-site test is what stops the eighth being forgotten.
3. `scripts/check-csp-pin.mjs` — after the animated-avatar deletion, not before.
4. `tools/perch-source-roots.tsv` + `lib/perch-roots.sh` + `copy-ban-list.tsv` +
   `check-copy-banned-terms.sh` + `check-copy-banned-terms.mjs` + the **twelve asset rewrites** +
   the workflow edit, as one PR. The asset rewrites are the bulk of it; see D8.
5. The remaining three shell guards, each with its workflow step. They are green in Phase 0 and
   start enforcing on the commit that creates the Perch tree.
6. `tests/node/perchKeymapRegistry.{ts,test.mjs}` and `perchResetterRegistry.{ts,test.mjs}` with the
   real registries.
7. The five Playwright specs, as their surfaces land. Register each in `playwright.config.ts`'s
   `smoke` project — the config has no catch-all, so an unregistered spec is silently never run, and
   that is the single most likely way this whole set becomes decoration.
