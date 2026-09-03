# 21 — ADRs, and the four questions that decide the schedule

**Revision 2.** Four things changed and none of them is a wording change. §2.0 is new and is
the reason this file exists in the form it now has. The rest of the header is unchanged from
revision 1.

| # | Change | Where |
|---|---|---|
| 1 | **§2.0 is new: an arbitration table for values two or more wave-2 artifacts decided differently.** Three arbitrated here, three ceded to a named owner, with the rule for which is which stated | §2.0 |
| 2 | **ADR 0017's `26006` decision is replaced.** It now ratifies `10-RELAY-FORK.md`'s RF-D5 — two layers, an `h` tag to a private `#watch` **and** the `P_GATED_KINDS` backstop — instead of competing with `13-WIRE-SCHEMAS.md`'s W-1. Amendment AD-A7 is withdrawn into RF-A6 | ADR 0017; §2 |
| 3 | **ADR 0014 gains C4 (two operators, one hold) and a rewritten C1** (the signing gate covers 33 sites, not one). **ADR 0018 C2 names the case-channel creator** and prices bill item B1d | ADRs 0014, 0018; Q2; Q3 |
| 4 | **Q4's tier gate is restated as an allowlist**, because as a ceiling it contradicted its own section forty lines later and would have failed the build on rollback cards | Q4 |

---

**What this file is.** Two things, and they are separable.

**Part one** is an index of eight architecture decision records, written in this
repository's existing ADR format and living in `build/adr/`. They are drafted to be moved
into `docs/decisions/` **verbatim** on adoption, taking numbers `0011`–`0018` after
`0010-containment-release-goes-through-the-daemon.md`. The plan set makes eight decisions
that a contributor will otherwise re-derive wrong in eighteen months; these are those eight,
each with the measurement that forced it, the alternatives that were actually considered,
and what would reverse it.

**Part two** resolves the four open questions the plan set's README names as the ones that
decide the schedule. Each gets a recommendation, the evidence behind it, what it costs,
the trigger that reverses it, and — where the honest answer depends on something nobody in
this run has — a statement of what that information is and who holds it.

**What was verified for this file.** Every `path:line` below was read at
`block/buzz@eed74bde2` (clean tree) or in this repository this session, and every one
answers three questions in the same sentence: who calls it, what process it is in, and what
it does to the data. Where a claim is a proposal rather than a report it says **PROPOSED**.
Where a value in `APPENDIX-NORMATIVE.md` is believed wrong it is raised as a brief
amendment in §2 rather than silently replaced. Where a peer artifact and this one disagreed,
§2.0 records who won and why, rather than leaving two ratified answers standing.

**Path prefix convention.** Unprefixed paths are this repository. `BUZZ ` prefixes
`block/buzz`. The ADRs use the same convention and state it individually, because they are
written to survive being moved.

---

## 1. The eight ADRs

| # | File | Decides | What would reverse it |
|---|---|---|---|
| **0011** | [`adr/0011-perch-shell-is-the-buzz-desktop-app.md`](adr/0011-perch-shell-is-the-buzz-desktop-app.md) | Perch's shell is a hard fork of `BUZZ desktop/` — not a new application and not the `swarmctl serve` review workbench. Fourteen surfaces across eleven routes, closed. The capped files split **before** the first surface. | Kill criteria K1 (blocking split + deletion exceeds 16 ew against 8 budgeted) or K2 (rebase over 8 engineer-hours for three consecutive months). Both are already written with numbers in `09` §8. |
| **0012** | [`adr/0012-relay-is-the-substrate-daemon-is-the-only-writer.md`](adr/0012-relay-is-the-substrate-daemon-is-the-only-writer.md) | The Buzz relay is the read / subscribe / search substrate; `swarm_detect --serve` stays the only writer of Ambush state; every bill route mounts on the daemon and none on `LocalOperatorSurface`; the relay is never the record. **Extends ADR 0010.** | Nothing short of revisiting ADR 0010's single-writer argument. `00-BRIEF.md` §10 Q5's trigger is literally "never, without" that. |
| **0013** | [`adr/0013-durable-evidence-rides-kind-9-marker-cards.md`](adr/0013-durable-evidence-rides-kind-9-marker-cards.md) | Durable evidence rides `kind:9` with seven versioned marker comments; `46010` is the single stored-kind exception and it is a repair, not an addition; an eighth marker or a third stored kind needs a written argument and a named registry maintainer. | K3 — needing a third stored kind within two quarters of Phase 1. The marker bet failed and `00-BRIEF.md` §10 Q3 reopens with a real price attached. |
| **0014** | [`adr/0014-two-legged-writes-and-the-process-boundary.md`](adr/0014-two-legged-writes-and-the-process-boundary.md) | **Rev 2.** A human decision is two legs — a signed `kind:9` intent card, then a `POST` to the daemon — and the console is *structurally* incapable of authorizing. The signing gate is a property asserted across **every** command that signs renderer-supplied content, not a patch on one. Concurrent decision by two operators is legitimate: the daemon arbitrates and the losing console publishes `superseded`. | Nothing. This is the product's safety claim. Cutting B2g is permitted and has a rendered consequence; cutting the boundary is not. |
| **0015** | [`adr/0015-swarm-perch-bridge-sits-below-the-tcb.md`](adr/0015-swarm-perch-bridge-sits-below-the-tcb.md) | `swarm-perch-bridge` is strictly downstream of the ADR 0009 trusted computing base, **joins `TRUST_SENSITIVE`**, is write-only (zero `REQ`, zero `COUNT`), and vendors its relay egress so the panic contract covers it. **Extends ADR 0009** by one registry line. | A measurement showing the crate has no influence on what an operator concludes — which would also mean it is not needed. |
| **0016** | [`adr/0016-two-identity-chains-never-conflated.md`](adr/0016-two-identity-chains-never-conflated.md) | **Rev 2.** Ed25519 swarm identities and secp256k1 Nostr keys are two chains; every verification result names the chain **and** the tier; the one real signature check the console can surface reads neither a trust anchor nor the attestation's own `Approve`/`Veto`, so the rollback badge renders `decision` beside the tier. | A NIP-OA extension that can bind a foreign-chain identity, which would make the mapping provable rather than configured. Not available today. |
| **0017** | [`adr/0017-ephemeral-telemetry-block-26000-26006.md`](adr/0017-ephemeral-telemetry-block-26000-26006.md) | **Rev 2.** The `26000`–`26006` block carries aggregates and opaque ids only and renders only from admitted issuers. `26006` is compartmented in **two layers**: an `h` tag naming a **private** standing `#watch` operations channel (the compartment), plus a `P_GATED_KINDS` entry that fences the global form (the backstop). Ratifies `10-RELAY-FORK.md` RF-D5 / RF-D6. | A decision to accept the disclosure, which would also have to explain why the case compartment exists. |
| **0018** | [`adr/0018-the-case-is-a-channel-and-promotion-mints-the-incident.md`](adr/0018-the-case-is-a-channel-and-promotion-mints-the-incident.md) | **Rev 2.** A case is a private, TTL-bearing Buzz channel whose UUID *is* the case id; promote-to-case mints the `IncidentRecord` a verdict attaches to; **the bridge is the only creator of the channel, on two triggers**, the second of which is bill item B1d. | Evidence that the correlation engine correlates enough findings that manual promotion is rare — measurable, and question 2 says how. |

**Reading order for someone about to build.** 0011 → 0012 → 0014 (the safety spine) →
0013 and 0017 (the wire) → 0015 (the crate) → 0018 (the case) → 0016 (every badge). 0016 is
last because it constrains rendering rather than structure, and it is the one most likely to
be violated by a well-meaning "just show a checkmark".

### 1.1 What these ADRs deliberately do not decide

- **The relay patch itself.** `10-RELAY-FORK.md`. ADR 0012 owns the rule that the fork stays
  a bug fix; ADR 0017 **ratifies** that file's RF-D5 rather than deciding the `26006` question
  a second time.
- **The bridge's modules, spool format, coalescer and metrics.** `11-BRIDGE-CRATE.md`.
  ADR 0015 owns only placement, trust classification, write-only-ness and the panic-blast-radius
  argument.
- **The bill's route shapes, DTOs and status codes.** `12-BACKEND-BILL-API.md`, whose
  commitment C1 (every route on `swarm_detect --serve`) ADR 0012 records as an architecture
  decision rather than restating as an API detail. Its §4.4 and §4.8 own the `409` taxonomy
  ADR 0014 C4 depends on.
- **The seven card payloads.** `13-WIRE-SCHEMAS.md`, including the `superseded` enum value
  ADR 0014 C4 requires and the `hold_id` pattern ADR 0017 C2 pins.
- **File-level task sizing.** `20-TASK-BREAKDOWN.md`. Question 3 below recomputes the *Rust
  chain length* because that is what the staffing question turns on; it does not re-size
  individual items.

---

> **INTEGRATOR RULING, 2026-08-30 — see [`00-REGISTRY.md`](00-REGISTRY.md) R-1.** The `h`-tag
> layer below is **retracted**. `kind:26006` is **global and carries no `h` tag**; `P_GATED_KINDS`
> is the whole delivery fence, and every Perch REQ that can match `26006` carries `#p` equal to the
> reader's own pubkey on every filter. The relay findings in this section are all correct and
> unchanged — what is overruled is only the conclusion that both layers should ship. R-1 states the
> four grounds and states plainly what the ruling gives up. **`relay-26006-pgate.patch` is
> unaffected** and still applies clean.

## 2.0 Arbitration: values two or more artifacts decided differently

**Why this section exists.** Sixteen wave-2 artifacts each wrote a commitments block declaring
its own reading binding, and nothing reconciled them against each other. Where two collided,
the later producer usually did not know it was colliding, and in the worst case both fixes
looked ratified — which is strictly worse than an item with no owner, because there is nothing
left to notice.

**The rule for what belongs here.** A row qualifies when (a) two or more artifacts wrote
incompatible decisions about the same value, **and** (b) an ADR-level property depends on the
answer. Everything else is named with its owner and left there. An ADR index is a tiebreak
holder for architecture, not a licence to re-decide a peer's schema, palette or fixture.

### Arbitrated here

| # | The value | The competing answers | **Arbitrated** | Consequent edits, by owner |
|---|---|---|---|---|
| **AR-1** | **How `kind:26006` is delivered and compartmented** | (a) `13-WIRE-SCHEMAS.md` W-1: an `h` tag naming a standing `#watch` channel, zero relay change. (b) ADR 0017 rev 1 C3: `26006` into `P_GATED_KINDS`, stays global — and it *explicitly rejected* (a). (c) `14-CLIENT-ARCHITECTURE.md`'s shipped skeleton: a global `{kinds:[26006],"#p":[me]}` REQ, the only one actually implemented | **Both (a) and (b), layered, per `10-RELAY-FORK.md` DECISION RF-D5** — which is the arbitration of record because that file owns the patch, delivered eight E2E tests that distinguish "the two conflict" from "the two compose under a rule", and `11-BRIDGE-CRATE.md` §8.6 reached the same answer independently. **ADR 0017 rev 2 ratifies it.** (c) is superseded. | `13-WIRE-SCHEMAS.md`: W-1 stands as layer 1; the frame keeps both `h` and `p`. `14-CLIENT-ARCHITECTURE.md`: `perchSubscriptions.ts`'s watch-alarm filter becomes `{kinds:[26006],"#h":[watchChannelId]}` — as written it delivers **zero** frames under (a) and fails nothing loudly. `10-RELAY-FORK.md`: owns `relay-26006-pgate.patch` and RF-D6's composition rule. `11-BRIDGE-CRATE.md` §8.3: owns the three `#watch` provisioning obligations |
| **AR-2** | **What `distinct_sources` counts** (render law 2) | Seven producers read `pipeline.rs:573` and concluded **strategy-scoped**. Two — `13-WIRE-SCHEMAS.md` (W-6) and `17-COMPONENT-SPECS.md` — read `whisker_agent.rs:148-149`, stopped there, and concluded **agent-instance**, then compiled that reading into a `const`, a `z.literal`, a golden vector and a pinned hash | **Strategy-scoped. `APPENDIX-NORMATIVE.md` §8 law 2 is correct as written and needs no rewrite.** Re-verified at the line for this revision: `resolve_deposits` (`crates/swarm-runtime/src/detection/pipeline.rs:543-580`, a `pub(crate)` fn called at `:79-80` by `detect_and_deposit_with_role` inside `swarm_detect --serve`'s detection pipeline) writes each `PheromoneDeposit.agent_id` as `strategy_scoped_agent_id(agent_id, &finding.strategy_id)` at `:573`, which `crates/swarm-whisker/src/stream.rs:20-22` formats as `"{base}:{strategy_id}"`, and each deposit is written to the substrate at `:84`. `concentration_for` then does `sources.insert(deposit.agent_id.0.clone())` at `crates/swarm-pheromone/src/substrate.rs:1295`. The id `WhiskerAgent::tick` derives is the **base**; the strategy suffix is appended below it | `13-WIRE-SCHEMAS.md`: **withdraw W-6.** `card-swarm-escalation-v1.schema.json`'s `distinct_sources_counts` const becomes `strategy_scoped_agent_id`; `skeleton/perch-wire/ts/zod.ts`'s `z.literal` and `common.schema.json`'s x-note follow; the golden vector and its pinned hash are regenerated. `17-COMPONENT-SPECS.md`: withdraw the `SourceCount` mechanism note; the expansion text stands unchanged. **This is the row where being right did not propagate**, because the two artifacts holding the minority reading own the decoder |
| **AR-3** | **The `hold_id` format** | Six formats in circulation across the wave-2 artifacts: `hold_a1f4c2e9…`, `hold:01K3QJ…`, `hold:01JQ8Z…`, `hold-9c1e77b204`, `hold-4c1f7a20`, `h_a07aeacf`. Every schema that carries the field declares it a bare `"type": "string"` | **NARROWED BY `00-REGISTRY.md` R-3: the wire contract is the PATTERN `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`** — no colon, URL-safe, bounded — held as `common.schema.json#/$defs/HoldId` and enforced at the publish seam by `HoldId::parse`. What B1 mints inside it is B1's choice; `12-BACKEND-BILL-API.md` commits it to a UUID and the canonical fixture derives `h_a07aeacf`. Both satisfy the pattern, which already forbids the derived `hold:{hunt_id}:{held_at_ms}` form this row exists to forbid. The original ruling read "a lowercase hyphenated UUID", which no shipped artifact implements. `12-BACKEND-BILL-API.md` already commits the minter's side ("opaque (uuid)") and `11-BRIDGE-CRATE.md` §8.6 already enforces it at the publish seam with `HoldId::parse` (test `T-20`), so this arbitration follows the two artifacts that own minting and publishing. Two of the six circulating forms use the `hold:` colon prefix the schemas' own descriptions warn against, which reads as the forbidden derived form even when it is not | **ADR 0017 C2 pins the pattern.** `13-WIRE-SCHEMAS.md` adds a `$defs/HoldId` to `common.schema.json` and `$ref`s it from `card-swarm-hold-v1`, `card-swarm-verdict-v1` and `frame-26006-hold-alarm`; `12-BACKEND-BILL-API.md` adds it to the OpenAPI path parameters; the prototypes and `22-DEMO-FIXTURE.md` regenerate their fixture ids from it |

Two further values were twice-decided and are arbitrated **inside** an ADR rather than in this
table, because each is a single artifact's own subject:

- **Who creates the case channel on the manual-promotion path** — nobody, in revision 1.
  Arbitrated in **ADR 0018 C2**: the bridge, on two triggers, the second being bill item
  **B1d** (`RuntimeEvent::CasePromoted`, ~0.5 ew, uncuttable while clause 3 is the enabled one).
- **What happens when two operators decide one hold** — unhandled, in revision 1. Arbitrated in
  **ADR 0014 C4**: the daemon's compare-and-set arbitrates, the losing console publishes a
  `superseded` update card carrying the winner's `nostr_intent_event_id`, and a verdict card
  with no matching daemon decision record renders as an intent record that did not execute.

### Ceded, with the owner named

These are real disagreements and this file is **not** the place to settle them. Each is a data,
palette or presentation decision whose owner is unambiguous; recording them here is so the
integrator has one list rather than sixteen.

| The value | The disagreement | Owner | This file's only ask |
|---|---|---|---|
| **The demo fixture** | Five artifacts each declare a different "canonical" set for `case-0042`: five channel UUIDs, five `total_strength` values, six `hold_id` grammars, overlapping-by-one agent rosters | `22-DEMO-FIXTURE.md` and `fixtures/derive-ids.mjs` — the only machine-validated set, in which every id is `sha256` of a public label and is therefore regenerable | Whatever is chosen, `hold_id` must satisfy AR-3 |
| **The CSS custom-property namespace** | `19-TOKENS.md` makes `--perch-*` binding, having measured that `ThemeProvider` writes 38 bare Buzz shadcn names **inline on the root element**; the five prototypes and `17-COMPONENT-SPECS.md` were drawn against the bare names and nothing propagated backward | `19-TOKENS.md` | None. It touches no ADR-level property |
| **The type ramp on the drawn surfaces** | The prototypes' primary hierarchy step is 11px→12px with 8px carrying up to 39% of a wall screen | `05-DESIGN-SYSTEM.md` and the prototype producers | None |
| **The interpolation tolerance** | `18-DATAVIZ.md` derives `EPSILON = evaporation_threshold`; a peer uses 2% of `alert_threshold` | `18-DATAVIZ.md` (amendment A11) | None |

---

## 2. Proposed brief amendments, consolidated

Raised across the eight ADRs. Per `APPENDIX-NORMATIVE.md`'s own rule, changing it is a brief
amendment under `00-BRIEF.md` §12, recorded in §13. **File these as a single amendment set.**
Several overlap with amendments other wave-2 artifacts raise; the overlaps are resolved here so
the integrator files one row, not three. Two rows are **withdrawn** in this revision and say so
rather than disappearing.

| # | Target | Was | Proposed | Raised in |
|---|---|---|---|---|
| **AD-A1** | `APPENDIX-NORMATIVE.md` §6 verified counts | `AppShell.tsx` / `MessageRow.tsx` = **997 / 998** against a hard 1000 cap, basis `wc -l` | **998 / 999, plus a new row `HomeView.tsx` = 994** — basis the gate's own `content.split(/\r?\n/).length` (`BUZZ scripts/check-file-sizes-core.mjs:24-29`). Re-measured with that arithmetic this session: 998 / 999 / 994. The row's purpose is to state remaining headroom and it currently overstates it by 50%, and omits the third capped file, which is the one `F1` rewrites. **Absorbs the identical amendment raised as `15-FILE-SPLIT-PLAN.md`'s and as `20-TASK-BREAKDOWN.md`'s A-1 and A-7 — file one row.** | ADR 0011 |
| **AD-A2** | `APPENDIX-NORMATIVE.md` §4 item 3 | "`query_needs_action` on connect, on reconnect and on every `26006`" | Name which of **two** paths is meant and budget the change. No desktop code path reaches `query_needs_action` (`BUZZ crates/buzz-db/src/store/feed.rs:171-201`); it is reachable only through the `feed_types` extension on `POST /query` (`BUZZ crates/buzz-relay/src/api/bridge.rs`), whose only in-repo producer is `BUZZ crates/buzz-cli/src/commands/feed.rs:59`. The desktop's needs-action query is a hand-built `{"kinds":[46010,46011,46012],"#p":[me],"limit":20}` at `BUZZ desktop/src-tauri/src/commands/messages.rs:97-101`. | ADR 0012 |
| **AD-A3** | — | — | **WITHDRAWN into `10-RELAY-FORK.md`'s RF-A6.** Its substance (the marker path costs zero of the four client registration points) is correct and survives inside RF-A6. It was independently raised three times — here, as RF-A1, and inside AD-A7 — which is the exact pattern §2.0 exists to stop. | ADR 0013 |
| **AD-A4** | `APPENDIX-NORMATIVE.md` §2 and §7 | `tools/check-copy-banned-terms.sh` enforces the bans | Mark it **PROPOSED** everywhere cited, and name the half that is still missing. **Corrected count:** this workspace's `tools/` holds 23 files, of which **14** are `check-*.sh` and 1 is `verify-*.sh` — not "23 check scripts"; `block/buzz` has no `tools/` directory at all. `16-INVARIANT-TESTS.md` now ships the AMBUSH-side script and `copy-ban-list.tsv` as skeletons, so the remaining gap is narrower and sharper: **`BUZZ desktop/scripts/check-copy-banned-terms.mjs` does not exist**, and `16`'s decision D2 asserts a parity test over `tools/fixtures/copy-corpus/` in which both sides read that TSV byte for byte and return identical verdicts. That test cannot exist until the `.mjs` half is written. **CORRECTED by the integration pass:** `16-INVARIANT-TESTS.md` now ships BOTH halves as skeletons — `skeleton/tools/check-copy-banned-terms.sh` and `skeleton/scripts/check-copy-banned-terms.mjs` — and D2's parity test **runs**: the `.mjs` runner over `tools/fixtures/copy-corpus/` reports `copy-ban parity corpus: 19 (file, row) pair(s), exact match`. The remaining gap is narrower still: neither script exists at its destination path in either repository, so every `tools/check-*` citation stays PROPOSED. See also `00-REGISTRY.md` §3 W2-7. | ADR 0015 |
| **AD-A5** | `APPENDIX-NORMATIVE.md` §5 B6 row; `09` §3.1 | "B6 is one call per fact" | "One call per fact **plus** a configured signing identity and a per-issuer `seq` / `prev_envelope_hash` store." The single non-test `build_signed_envelope` caller derives its keypair from `sha256("approval-ledger-envelope:{ledger_id}")` — a public identifier — and discards the signature, keeping only `envelope_hash` (`crates/swarm-runtime/src/approval.rs:1807-1809`, `:1836-1840`). The existing call proves the API compiles, not that a signing identity exists. | ADR 0016 |
| **AD-A6** | `00-BRIEF.md` §4.7 | Each agent's Nostr keypair is "bound to its `swarm:ed25519:<hex>` identity by a NIP-OA owner attestation" | NIP-OA binds an agent **Nostr** key to an owner **Nostr** key — its preimage is `"nostr:agent-auth:" \|\| agent_pubkey_hex \|\| ":" \|\| conditions`, Schnorr-signed by the owner's secret (`BUZZ crates/buzz-sdk/src/nip_oa.rs:1-18`). It buys the ban cascade (`BUZZ crates/buzz-relay/src/handlers/auth.rs:100-130`) and the 120/min rate tier (`BUZZ crates/buzz-relay/src/connection.rs:690-695`), not a binding to the swarm identity. That mapping is configured and unsigned, and the UI must say so. | ADR 0016 |
| **AD-A7** | — | — | **WITHDRAWN into `10-RELAY-FORK.md`'s RF-A6**, which supersedes it, W-1 and AD-A3 together and carries the corrected arithmetic. AD-A7 described the `buzz-core` change as "one line in one array"; measured (`10-RELAY-FORK.md` §11.8) it is the `P_GATED_KINDS` entry plus its comment, the kind constant plus a doc comment (`#![warn(missing_docs)]` is on at `BUZZ crates/buzz-core/src/lib.rs:2`, and the array holds only named constants today), an `ALL_KINDS` entry (`kind.rs:635`), and three unit tests. It also asserted the frame stays global, which AR-1 reverses. | ADR 0017 |
| **AD-A8** | `APPENDIX-NORMATIVE.md` §6 shared constants | no `hold_id` row | Add one: **`hold_id` matches `common.schema.json#/$defs/HoldId`, never carries a colon, and is never derived from `hunt_id`.** B1 mints a UUID inside that pattern (`00-REGISTRY.md` R-3 narrows this row from the original "is a lowercase hyphenated UUID", which no shipped artifact implements). Six formats were in circulation and two used the `hold:` prefix the schemas warn against. See AR-3; enforced by ADR 0017 C2 and `11-BRIDGE-CRATE.md`'s `HoldId::parse`. | ADR 0017 |
| **AD-A9** | `APPENDIX-NORMATIVE.md` §5 backend bill labels | eleven items | **Fifteen.** Wave 2 added four, each with an owner and a price, and the label set is the registry that keeps them from being re-derived under different names: **B0** `nostr_pubkey: Option<String>` on `OperatorPrincipalConfig` (~0.5 ew, uncuttable — without it a hold cannot be `p`-tagged and reaches nobody); **B1c** `RuntimeEvent::ContainmentReleased` (~0.5 ew, cuttable with a rendered consequence); **B1d** `RuntimeEvent::CasePromoted` (~0.5 ew, uncuttable while manual promotion is the enabled clause — ADR 0018 Fact 6); **B2g-p** stamping partition state at hold and at execution (~0.25 ew, without which `08` INV-08's `UNATTESTED — BY DESIGN` arm is unassertable). `20-TASK-BREAKDOWN.md` raised B0 as its own amendment A-5; **this row absorbs it**. | ADR 0018, Q3 |

Two further corrections that are **not** amendments, because they concern prose rather than
a normative value, recorded for the integrator:

- `09` §7's dependency-graph label reads "Phase 1 — The Hold (27 ew, 14 Rust)" while `09`
  §3.4's own sizing table totals **28 ew with 15 Rust**. The label predates B3i. Question 3
  uses the table.
- `09` §3.5's cut order lists "F4's promotion counter" as the second thing cut, as a written
  time-boxed exception to `00-BRIEF.md` §8.2. Question 2 argues it should be moved off the
  cut list entirely, and gives the measured reason.

---

## 3. The four questions that decide the schedule

Each answer states the recommendation first, then the evidence, then what it costs, then the
trigger that reverses it, then what nobody in this run knows.

---

### Q1 — Does the hold store land before the console?

> **Recommendation: yes, B1 first — and the answer carries a rider the plan set does not
> have. Six deployment facts must be true before an end-to-end grant works at all. Five are
> configuration or provisioning and one is a bill item; none was on the eleven-item bill. Put
> them on the Phase-1 entry checklist or the queue will be finished and still unable to grant
> anything.**

**Evidence.**

B1 gates everything, and the reason is a refusal rather than a gap.
`crates/swarm-runtime/src/lib.rs:1133-1146` — reached in `swarm_detect --serve` through
`AgentDispatcher` → `IngestRuntimeRequestResponseRouter::route_request`
(`crates/swarm-ingest-runtime/src/ingest/mod.rs:140-150`) → `audit_authorize_and_execute` —
matches `PolicyVerdict::RequireHuman` when `mode == RuntimeMode::LiveResponse` and
`allow_human_approved_execution` is false, and emits `AuditResponseRecord::Skipped { reason }`
with a `None` capability lease, `response_attempted` false, `response_succeeded` false. The
action is dropped. No queue row is created, because there is no queue. The sibling refusal at
`lib.rs:975-983` returns `ApprovalError::Denied` and has no production caller.

Two things have improved since `09` sized this at 5 ew and set its trigger at "if B1 has no
design by end of Phase 0, invoke D3 immediately":

- **B1 now has a design.** `12-BACKEND-BILL-API.md` §3 specifies `HeldAction`,
  `HeldActionStore`, memory and file implementations, `HoldSweep`, and a nine-value
  `HoldState` with every transition. That does not shrink 5 ew of implementation and tests,
  but it removes the most likely cause of the trigger firing.
- **The frontend can genuinely proceed against fixtures.** `BUZZ desktop/src/testing/e2eBridge.ts`
  installs a mock Tauri IPC via `mockIPC(..., {shouldMockEvents:true})` at `:14601`, and its
  `default:` arm at `:14593-14594` throws `Unsupported mocked Tauri command: ${command}`. That
  throw is a feature here: a Perch command without a bridge case breaks every mock-mode spec
  loudly rather than silently, so fixture drift is a red build rather than a demo surprise.
  (It is also a trap: the symptom is a "Community connection failed" render that looks exactly
  like a product bug. Any artifact prescribing a new Tauri command must prescribe the bridge
  case in the same breath.)

**The rider — six facts that are not true on shipped defaults.** Three were in revision 1;
three are new and come from the `26006` arbitration (AR-1), which moved the alarm onto a
channel that has to exist and have members.

| # | Fact | Kind | Symptom when missed |
|---|---|---|---|
| 1 | **A granted containment action fails at the decide route.** `ContainmentSettings.lease_store_path` defaults to `None` (`crates/swarm-core/src/config/runtime.rs:94-95`, `:103`), and `prepare_containment` (`crates/swarm-runtime/src/lib.rs:823-864`) returns `RuntimeError::ContainmentRefused` at `:836-844` when `self.containment` is `None`. Four of the twelve destructive actions are containment actions — `QuarantineFile \| SuspendProcess \| IsolateHost \| TerminateUserSession` (`crates/swarm-runtime/src/containment.rs:54-63`) | configuration, ~0 ew, **mandatory** | the human decides, then `isolate_host` fails |
| 2 | **The tuning evidence dies on restart.** `CorrelationSettings.incident_store` defaults to `BundleStoreConfig::Memory` (`crates/swarm-core/src/config/storage.rs:62-71`), and `operator_review_status` reads `incident_store.recent(config.audit.recent_decisions_limit)` with the default 20 (`crates/swarm-core/src/config/defaults.rs:3-5`; `crates/swarm-runtime/src/service/runtime_service.rs:1134-1136`, `:1174-1175`) | configuration for the store; see Q2 for the limit | the thesis fails silently |
| 3 | **The hold cannot be `p`-tagged, so it reaches nobody.** `OperatorPrincipalConfig` (`crates/swarm-core/src/config/operator.rs:118-129`) is `{operator_id, token_env, token_expires_at_ms?, scopes}` with `#[serde(deny_unknown_fields)]`, and `grep -rn 'pubkey\|npub\|nostr'` over `crates/swarm-core/src/config/` returns nothing. `APPENDIX-NORMATIVE.md` §4 layer 1 requires the bridge to `p`-tag every principal holding `OperatorScope::Approve` via `effective_principals()` (`operator.rs:153-168`), which yields operator ids and environment-variable names | **code — bill item B0**, ~0.5 ew, uncuttable | the alarm names nobody |
| 4 | **`#watch` must exist and be `visibility: "private"`.** `filter_fanout_by_access` returns early at `BUZZ crates/buzz-relay/src/handlers/event.rs:195` (`Ok(v) if v != "private" => return matches`) for any non-private channel | provisioning, ~0 ew | **layer 1 of the alarm compartment is a complete no-op and looks identical from the console** |
| 5 | **The `perch-alarm` identity must be a member of `#watch`.** `handle_ephemeral_event` runs `check_channel_membership` on the **publisher** for any `h`-tagged ephemeral (`event.rs:850-852`) | provisioning, ~0 ew | every alarm gets `OK false`; no hold reaches the shift |
| 6 | **Every operator console's pubkey must be a member of `#watch`.** A channel-scoped REQ filters its requested channels against `accessible_channels` (`req.rs:189-195`) and answers `CLOSED "restricted: not a channel member"` when nothing survives (`:200-208`) | provisioning, ~0 ew | that console gets a terminal notice on the one subscription that carries holds |

Facts 4–6 are `11-BRIDGE-CRATE.md` §8.3's provisioning items 8–10 and none of them has a
runtime workaround — a membership row is provisioning, not backoff. **The bridge cannot
pre-flight any of them**, because ADR 0015 makes it write-only and it therefore has no read
path with which to check a membership row. The first alarm is the test. Fact 6 is the one
that reaches a human, and `14-CLIENT-ARCHITECTURE.md` must render that `CLOSED` as *"you are
not on the watch floor"* with the remedy, never as a quiet shift.

**Cost of the recommendation.** At one Rust engineer, B1's five weeks are five calendar weeks
in which the frontend builds F1 and F2 (7 ew) against fixtures. For *Phase 1 alone* the
serialization is close to free. It stops being free in Phase 2 — which is Q3.

**Cost of the fallback, corrected.** `09` D3's named v0 is `/watch-floor` + `/ledger` +
`/gaps` with the queue labelled *not yet wired*. That is **not** a Rust-free escape: `09`
§7's own dependency graph has `B4 --> W`, so the Watchfloor's concentration curve needs
`GET /v1/operator/pheromone/deposits` (B4, 2 ew Rust, Phase 2), and `GA --> LD` puts `/gaps`
ahead of `/ledger`. So invoking D3 trades 5 ew of B1 for 2 ew of B4 plus pulling three
Phase-2/3 surfaces forward. Worth knowing before it is invoked under pressure.

**Trigger that reverses it.** Two, and the second is new:

- `09` §12's existing trigger stands — if the daemon work slips past the console by more than
  one milestone, invoke D3.
- **New: if all six rider facts are not resolved by Phase 1 week four, invoke D3 regardless of
  B1's state.** A queue that lets an operator grant a hold which then fails at the decide route
  is strictly worse than a labelled empty queue: it teaches the operator that the control does
  not work, which is the one lesson this product cannot survive. Facts 4 and 5 are worse still,
  because they produce a queue that is *empty for a reason nobody can see*.

**What nobody in this run knows.** **Whether the target deployment runs
`RuntimeMode::LiveResponse` at all.** `RequireHuman` refuses only in `LiveResponse`;
`DetectOnly` falls through and dry-runs (`lib.rs:1133-1135`). If the first deployment is
`DetectOnly`, there are no holds to queue and Phase 1's exit criteria 1, 2, 3 and 5 are
unobservable — the whole phase would need to be demonstrated against a deliberately-configured
live-response environment. **Who has it:** whoever owns the deployment's `runtime.mode`. This
is an operator question, not an engineering one, and it should be asked in week one of Phase 0.

---

### Q2 — Where does the case-promotion bar sit?

> **Recommendation: ship all three clauses as configuration, and enable only the third —
> manual promotion — in the first shipped build. Enable clauses 1 and 2 after four weeks of
> counter data. Move the promoted/suppressed counter off the cut list: with the shipped
> evidence window, an un-instrumented bar can destroy the tuning loop silently. And budget
> B1d, because the clause this answer enables first is the one that had no case-channel
> creator.**

This is a change from `00-BRIEF.md` §10 Q2's default, which enables all three from the start.

**Evidence.**

This question is on the critical path of the *thesis*, not adjacent to it, because a verdict
has nowhere to land until a finding belongs to an incident record.
`SwarmProvidenceFeedbackRequest.incident_id` is a required `String`
(`crates/swarm-core/src/types.rs:144-152`); `providence_feedback_handler`
(`crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:119-192`, serving
`POST /v1/providence/feedback` in `swarm_detect --serve`) loads the incident by id at
`:129-137` and 404s if it misses; and `build_alert_tuning_report`
(`crates/swarm-runtime/src/alert_tuning.rs:85`) takes `&[IncidentRecord]`, with
`dedupe_measurements` (`:258-271`) reaching measurements only through
`record.false_positive_measurements`. That is why B3i exists (ADR 0018).

**Why clause 2 is the weakest, and should not be first.** `CorrelatedIncident` is minted only
by `CorrelationEngine::assemble_incident_at` (`crates/swarm-runtime/src/correlation.rs:110-233`),
with `incident_id = format!("incident:{}:{created_at_ms}", seed.hunt_id)`, no status, no
assignee and **no merge operation**. A second correlation run over the same material produces
a different id. A bar clause that auto-opens a case on "a `CorrelatedIncident` with ≥ 2 members"
can therefore open a second case for the same material, and nothing in either tree can join
them.

**Why clause 1 is second-weakest.** "A held destructive action" ties case volume to policy
configuration nobody has tuned yet: `StaticApprovalGate::evaluate`
(`crates/swarm-policy/src/static_gate.rs:294-299`) returns `RequireHuman` for any destructive
action at or above `human_gate_severity`, which is `HIGH` in the shipped ruleset
(`rulesets/default.yaml:93`). Lower that once and case volume changes shape with no UI change.

**The measurement that inverts the usual intuition.** With `recent_decisions_limit = 20` over
an in-memory store (Q1's rider fact 2), **promoting more is actively harmful**: every
auto-promoted case pushes a genuinely analyst-reviewed incident out of the twenty-record
window the ranker reads. On shipped defaults a wide bar does not merely add noise — it evicts
signal. That is the strongest available argument for starting narrow, and it is a measured
property of `runtime_service.rs:1134-1136`, not a preference.

**The consequence of choosing clause 3, discovered in revision 2 and priced here.** Clause 3
is the only clause that emits **no runtime event**: a held action emits
`RuntimeEvent::ResponseHeld`, and an analyst pressing `E` emits nothing. The bridge is the only
component that can create a case channel (ADR 0018 Fact 6 closes the console and the daemon as
candidates), and it creates channels by draining runtime events. So enabling clause 3 first —
which this answer recommends on the eviction argument — **requires bill item B1d**,
`RuntimeEvent::CasePromoted`, or the recommended configuration produces a promotion that
`404`s at `IncidentMintRequest.case_id`. This is the shape of defect worth naming: a
configuration recommendation with a Rust dependency that nobody notices until the demo.

**The minting contract, which the bar's config must satisfy.** `resolve_feedback_target`
(`crates/swarm-runtime/src/providence.rs:799-836`) runs before any write and imposes three
requirements whose violation is silent (ADR 0018 Fact 3): `included_members` must contain the
`finding_id`; a `None` `trigger_strategy_id` becomes the literal string `"unknown"`
(`providence_handlers.rs:482-485`), collapsing the per-detector bucket; and `host_id` resolves
only from a `host:`-prefixed key (`providence.rs:838-841`), absent which `HostExclusionReview`
— the highest-value recommendation kind, at thresholds 2/2/0.75 (`alert_tuning.rs:6-15`) — is
unreachable for that measurement forever.

**Cost.**

| Item | Cost | Note |
|---|---|---|
| Three clauses as config on `/settings#case-promotion` | small, inside F4's 3 ew | The anchor already has no owner (ADR 0018 follow-on); this is it |
| **B1d — `RuntimeEvent::CasePromoted`** | **0.5 ew Rust, uncuttable** | The creator for the clause this answer enables first. Seven upstream edits, itemised in `11-BRIDGE-CRATE.md` §9.1.5. Carried in Q3's arithmetic |
| The promoted/suppressed counter on `/` | inside F4's 3 ew | `09` §3.5 currently lists it as the second thing cut. **Move it off the list** — the eviction property above means an un-instrumented bar can destroy the loop with no visible symptom |
| `incident_store: LocalFiles` in the deployment config | ~0 ew | Configuration. Must be on the demo checklist and in the deployment documentation |
| A separate, larger limit for the tuning read path | **PROPOSED ~0.25 ew Rust** | `recent_decisions_limit` is `audit.recent_decisions_limit` and is shared with the audit read path; raising it globally changes an unrelated surface. A dedicated limit for `operator_review_status`'s two reads is the narrow fix |

**Trigger that reverses it.** Two directions, both measurable:

- **Widen** (enable clauses 1 and 2): four consecutive weeks in which manual promotions per
  operator per week are below 5 while the needs-action queue is non-empty. The bar is too
  narrow and the operator is working around it.
- **Narrow** (raise thresholds or disable a clause): any week where `suppressed` exceeds
  `promoted` by 20×, or the open case list exceeds ~30 (`00-BRIEF.md` §10 Q2's own trigger),
  or the promoted ÷ suppressed ratio leaves the 1:5 – 5:1 band (`09` §13).

**What nobody in this run knows.** **The real finding volume per shift in the target
deployment.** Every threshold above is a guess without it, including the "below 5" in the widen
trigger. This is cheap to settle and does not need Perch: `GET /v1/operator/status` already
serves `OperatorStatusReport`, and a week of `swarmctl` polling would give finding rate,
escalation rate and the current `false_positive_tracking` baseline (which should be zero — the
only non-test `FalsePositiveMeasurement` constructor today is the webhook path). **Who has it:**
whoever runs the existing Ambush deployment. Ask before Phase 1 F4 starts, not after.

---

### Q3 — One Rust engineer or two?

> **Recommendation: two, and the second one starts in Phase 0 on the bridge crate. The plan's
> default is one; the arithmetic that default was computed against has moved twice — once in
> revision 1 and again here — and the plan's own dependency graph shows there is genuinely
> parallel Rust work available from day one.**

**Evidence.**

`09` §6 states the case for one: "Nineteen of the 95 weeks are Rust in Ambush's daemon (B1 5,
B2 2, B2r 1, B2g 2, B2o 1.5, B3 1.5, B3i 1, B3r 0.5, B5 0.5, B4 2, B6 2) and they are serial
through one engineer … Nineteen serial weeks against a ~32-week schedule is 59% of the
calendar on one person." The addition is right and the dependencies are right.

The **19 is not the Rust total**, and six things have been added to it since.

| | ew | Source |
|---|---:|---|
| Daemon bill, as sized | 19 | `09` §6, addition verified |
| Phase 0 item 0.6, relay fork | 0.5 | `09` §2.4 — Rust, excluded from the 19 |
| Phase 0 item 0.7, bridge skeleton | 3 | `09` §2.4 — Rust, excluded from the 19 |
| **Plan's real Rust total** | **22.5** | |
| **B0** — `nostr_pubkey` on `OperatorPrincipalConfig` + validation + consumers | **+0.5 PROPOSED, uncuttable** | Q1 rider 3; amendment AD-A9 |
| Vendor `BUZZ crates/buzz-ws-client` and type its four panic sites | **+0.5 PROPOSED** | ADR 0015 C6. Four sites: `.unwrap()` at `connection.rs:170` and `:229`, `unreachable!()` at `:172` and `:231`. `Cargo.toml:139-141` sets `panic = "abort"`, proved to reach the release `rustc` invocation by `tools/verify-release-hardening.sh:23-24`, so `catch_unwind` cannot help and a panic there aborts the daemon holding the containment-lease map |
| `26006` compartmenting: the `P_GATED_KINDS` patch + `e2e_operator_alarm_pgate.rs` | **+0.5 PROPOSED** *(revised up from 0.25)* | AR-1. Revision 1 priced "one line in one array". `10-RELAY-FORK.md` §11.8 measures four hunks plus three `kind.rs` unit tests, and §11.7 specifies **eight** E2E tests — the E2E suite is the bulk of the number. The `#watch` half is provisioning, ~0 ew of Rust |
| A dedicated tuning-read limit | **+0.25 PROPOSED** | Q2 |
| **B1c** — `RuntimeEvent::ContainmentReleased` | **+0.5 PROPOSED, cuttable** | `11-BRIDGE-CRATE.md` §15; without it a TTL-driven containment release produces no rollback card |
| **B1d** — `RuntimeEvent::CasePromoted` | **+0.5 PROPOSED, uncuttable** | ADR 0018 Fact 6 and Q2. The creator for the only promotion clause enabled first |
| **Wave-2 additions** | **+2.75** | of which **2.25 uncuttable** |

And the bridge is under-priced. `09` §2.4 puts 0.7 at 3 ew for "New crate, spool format,
sequence, NIP-42 handshake, first marker card." `11-BRIDGE-CRATE.md` specifies, additionally:
four transport streams with distinct loss policies, a three-cause loss taxonomy carried on the
card schema, an edge-triggering coalescer, a pacer, a `perch`-prefixed metrics registry served
at `GET /metrics/perch`, case-channel provisioning on **two** triggers requiring `ChannelsWrite`
+ `AdminChannels`, three identity slots with derived keys, and eleven configuration keys.
**`20-TASK-BREAKDOWN.md` owns the file-level number and this file does not re-size it** — but
the ADR set's obligation is to say that 3 ew prices a skeleton and `11` no longer describes
one. If the crate is 6–8 ew, add 3–5.

**The arithmetic, stated so it can be argued with:** 22.5 (plan, including the two Rust items
`09` §6's 19 excludes) + 2.75 (wave-2 additions) = **25.25**, plus 0–5 for the bridge's
under-pricing = **25.25–30.25 ew of Rust on one engineer**, against a ~32-calendar-week plan.
That is **79–95% of the calendar on one person.** The 59% figure was computed against 19 and
is stale; revision 1's 77–92% was computed before B1d.

**The structural argument, which matters more than the arithmetic.** The chain is serial by
*data dependency*, not by skill — and the bridge is not on it. `09` §7's own graph has only two
edges out of `A07` (`A07 --> B6` and `A07 --> A08`/`F1`) and **none into it** from B1, B2, B2r,
B2g or B2o. So a second Rust engineer has roughly 6–10 ew of genuinely parallel work available
from day one: the bridge crate, the vendored egress, the relay fork, B0, the `P_GATED_KINDS`
patch with its eight E2E tests, B1c and B1d. That is the test for whether a second hire helps
rather than adds communication overhead, and the plan's own graph passes it.

**Cost.** Roughly 0.3 additional FTE across about a third of the schedule. At the plan's own 20%
coordination tax that is ~3 ew of overhead, against ~8 ew removed from the critical path. It is
also not a generalist slot: the second engineer needs Ambush commit rights and must clear ADR
0009's layering rules, `tools/check-runtime-panic-contract.sh` and
`tools/check-gates-wired.sh`'s workflow-edit-in-the-same-PR requirement (decision D9).

**Cost of staying at one, stated so it is chosen rather than discovered.** Phase 1 takes about
fourteen calendar weeks rather than eight; the frontend runs ahead of the daemon for most of
them against the E2E bridge; and decision D2's "never a mocked gate" means the queue ships
labelled *not yet wired* for at least one milestone. That is a legitimate outcome. It is only
illegitimate if nobody said it in advance.

**Trigger that reverses it — in both directions.**

- **Back to one:** if by Phase 0 exit the bridge has landed inside 3 ew and B1's design review
  found no widening, the parallel work was smaller than estimated and the second engineer moves
  to the background deletion track (0.3b, 8 ew, which is otherwise unstaffed).
- **Two becomes non-negotiable:** **B1 exceeding 7 ew.** At that point the chain exceeds the
  calendar on one person and no reordering recovers it, because everything downstream of B1 is a
  data dependency rather than a preference.

**What nobody in this run knows.** **Whether the one Rust engineer already exists.** `09` §6's
team assumption is "1 Rust engineer with Ambush commit rights" — present tense. If that person
is a current contributor with context, the range above is real. If they are a hire, add ramp to a
chain that has no slack, and the answer is two without argument. **Who has it:** whoever staffs
it. `09` §12 already says this must be answered *before* Phase 1 starts, and the reason bears
repeating: deciding late does not shorten the chain, it only moves the surprise.

---

### Q4 — Does B6 land before the first external demo?

> **Recommendation: after. The case is stronger than the plan's, because wave 2 removed B6's
> only load-bearing dependency. Mechanize the honesty instead — but as an **allowlist**, not a
> ceiling. Revision 1 proposed a ceiling and it was wrong: it would have failed the build on
> the one card type that legitimately verifies today.**

**Evidence.**

The plan recorded a dependency that no longer holds. `00-BRIEF.md` §8.1 makes a per-issuer
monotonic sequence non-negotiable — a gap must render as a gap — and the reading was that B6
supplies it, since `seq` is a `build_signed_envelope` parameter. But the bridge subscribes
**in-process** via `IngestState::subscribe_runtime_events()`
(`crates/swarm-ingest-runtime/src/ingest/mod.rs:1875-1882`), so it never reads
`/v1/events/stream`, whose SSE `id` is `event.emitted_at_ms().to_string()`
(`crates/swarm-ingest-runtime/src/ingest/demo.rs:1703`) — a millisecond timestamp that collides
at the concentration monitor's 10 Hz cadence and is not monotonic across issuers.
`11-BRIDGE-CRATE.md` §15 decision 4 assigns `seq` at spool append, per `(colony_id, issuer)`.
**Gap-marking therefore does not depend on B6**, and that was the strongest argument for pulling
it forward.

B6 is also more expensive than sized, not less. Its only non-test caller derives its keypair as
`Keypair::from_seed(sha256("approval-ledger-envelope:{ledger_id}"))`
(`crates/swarm-runtime/src/approval.rs:1807-1809`) — from a public identifier anyone can
reproduce — then verifies its own signature and **discards it**, keeping only `envelope_hash`
(`:1836-1840`). `verify_chain_link` has zero consumers outside its own module. So B6 needs a
provisioned daemon key (the `Ed25519Signer::from_secret_material(env)` pattern at
`crates/swarm-runtime/src/providence.rs:129`, `:169`) plus a per-issuer `seq` and
`prev_envelope_hash` store — amendment AD-A5.

And tier 0 is a **rendered honest state**. `08` INV-25 requires every verification result to name
the chain **and** the tier; INV-08 requires the literal `UNATTESTED`, and
`UNATTESTED — BY DESIGN` under a partition contingency. A demo at tier 0 is showable — provided
the badge says so and the presenter says so first.

**The one thing that genuinely could go wrong, and it is a copy failure not an engineering one.**
`09` §13's last hygiene metric is "cards rendering above tier 0: **0** before B6; **100%** of
finding / escalation / hold / rollback cards after." The named failure mode is a demo whose badge
says tier 2 because nobody re-read `08` §6.2.

**Cost of deferring.** The demo audience sees `UNATTESTED` on four of the seven card types —
`finding`, `escalation`, `hold` and containment `lease` carry no Ed25519 signature under any
condition today (`crates/swarm-whisker/src/detector.rs:51-59`;
`crates/swarm-response/src/siem.rs:17-27`; `crates/swarm-response/src/lib.rs:100-116`;
`crates/swarm-spine/src/lib.rs:114-122`). For a security buyer that is a credibility asset if the
presenter names it first and a credibility problem if the audience finds it. The mitigation is one
slide, one sentence in the demo script, and the CI assertion below.

**The exception that keeps "nothing is signed" from being the wrong claim in the other
direction — and it is why revision 1's gate was wrong.**
`RollbackReceipt.governance_attestation` is checked by `verify_release_attestation`
(`crates/swarm-runtime/src/containment.rs:235-269`, called by the release handler at
`crates/swarm-runtime-http/src/http/containment.rs:219-222` in `swarm_detect --serve`, which
turns its `Ok`/`Err` into the `attestation_verified` boolean on the response body). It verifies
the detached Ed25519 signature **and** the subject binding — `attestation.payload.proposal_id`
against `release_subject_id(receipt)`. **Rollback receipts are tier 1 today with no new work.**
`13-WIRE-SCHEMAS.md`'s W-4 additionally makes `swarm:verdict:v1` tier 1 from day one, conditional
on B2 provisioning the operator's Ed25519 key. Two of the seven card types therefore legitimately
resolve above tier 0 before B6.

Two limits print beside that badge, and the second is new in revision 2:

1. ADR 0010's: `attestation_verified: true` means "this attestation matches this body", **not**
   "a governor we trust authorized this" — nothing compares the signer to a configured governor
   set.
2. **The verifier never reads the receipt's own verdict.**
   `ConsensusGovernanceReceipt::verify` (`crates/swarm-consensus/src/lib.rs:425-448`) checks the
   detached signature and that `payload.issued_by` derives from the same key (`:441-447`), and
   never touches `payload.decision`, whose type is `GovernanceReceiptDecision { Approve, Veto }`
   (`:353-358`). So a `Veto` receipt verifies. ADR 0016 C6a therefore requires the badge to render
   `decision` beside the tier.

**Cost of pulling it forward.** 2 ew of the scarcest resource in the project (Q3), inserted into a
serial chain, in exchange for a badge — pushing Phase 1 exit by two weeks at one Rust FTE.

**The mechanization, restated as an allowlist. PROPOSED.**

Revision 1 proposed "the build fails if any card can render a tier above 0 before B6". That is a
**ceiling**, and it contradicts the paragraph above: it fails the build on day one on `rollback`,
which is tier 1 with no new work and which two prototypes already draw at tier 1. Carve `rollback`
out and the gate no longer asserts the property it was written to mechanize. The fix is to invert
the shape:

> **`tools/check-perch-tier-ceiling.sh` (PROPOSED, ~0.25 ew, must land with its workflow
> `run:` step per `tools/check-gates-wired.sh`).** Every entry in the marker registry
> (`17-COMPONENT-SPECS.md`'s `ambushCardRegistry.tsx`, a closed seven-member
> `satisfies Record<AmbushMarkerKind, AmbushCardEntry>`) declares `maxTier: 0 | 1 | 2`. The gate
> asserts that the set of entries declaring a `maxTier` above 0 is **exactly equal** to a
> checked-in allowlist, with a precondition column:
>
> | Card type | `maxTier` | Precondition |
> |---|---|---|
> | `rollback` | 1 | none — `verify_release_attestation` ships today |
> | `verdict` | 1 | **B2 has landed** and provisions the operator's Ed25519 key (`13-WIRE-SCHEMAS.md` W-4) |
> | the other five | 0 | — |
>
> Both directions fail: an entry that raises its `maxTier` without an allowlist row fails, and an
> allowlist row with no matching entry fails. A row whose precondition is unmet is a failure, so
> `verdict` cannot quietly claim tier 1 before B2.
>
> The post-B6 flip is changing five rows from `0` to `1` — still a one-line-per-row change to a
> checked-in table, which is what made revision 1's mechanization attractive and is preserved
> here.

Paired with a DOM assertion in `perch-provenance.spec.ts` that any rendered badge above tier 0
belongs to an allowlisted card type, and that a tier-1 badge renders its chain, its limit
sentence and — for `rollback` — the attestation's `decision` (ADR 0016 C6a).

This converts "nobody re-read `08` §6.2" from a risk managed by attention into a build failure,
which is this repository's own stated preference (ADR 0009: "the boundary is a build failure
rather than a review catch"), **without** asserting a falsehood about the two card types that
genuinely verify.

**Trigger that reverses it.** Two:

- **Hard:** any external commitment that a fact is signed — a customer contract, a security
  questionnaire answer, an external deck asserting an Ed25519 chain over findings or receipts.
  On that date B6 becomes a Phase-1 blocker, because the alternative is withdrawing the claim,
  which is decision D20's own reversal condition.
- **Soft:** if the first demo audience asks "how do I know the daemon said this" and the tier-0
  answer — re-fetch from the daemon through B2r — does not satisfy them, that is evidence B2r is
  insufficient for the auditor. D20 then applies in full: either ship B6, or delete the Ed25519
  claim from every render law **in the same change**, not just from the roadmap.

**What nobody in this run knows.** **Who the first external demo is for, and what they have
already been told.** If a deck, a data-room document or a security questionnaire already asserts
signing, the hard trigger has already fired and the answer flips to "before". **Who has it:**
whoever owns `01-POSITIONING.md`'s external copy and the demo calendar. This is a five-minute
question with a two-week consequence, and it should be asked before Phase 2 planning rather than
during it.

---

## 4. What this file does not decide

- **Whether the plan set is adopted.** All eight ADRs are `Proposed`. Adoption fills in the
  status line and the phase number.
- **The exact threshold values in the case-promotion configuration.** Q2 gives the structure,
  the default enablement, the eviction argument and the triggers; the numbers need the finding
  volume Q2 names as missing.
- **File-level sizing.** `20-TASK-BREAKDOWN.md`. Q3 recomputes only the Rust chain length,
  because that is the quantity the staffing decision turns on, and it flags the bridge's
  under-pricing without re-pricing it.
- **The demo script.** `22-DEMO-FIXTURE.md`. Q1's six rider facts and Q4's tier-0 sentence
  both belong on its checklist, and this file records them so they are not rediscovered on the
  morning of.
- **Anything in §2.0's ceded list.** The fixture, the token namespace, the type ramp and the
  interpolation tolerance each have one owner and no ADR-level dependency. Naming them is the
  service this file can offer; deciding them is not.
