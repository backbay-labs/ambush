# 00 — The wave-2 registry

**Status: normative for the build set.** This page holds the values that more than one wave-2
artifact tried to decide. Where an artifact still restates one of them, this page wins.

Written by the integration pass, 2026-08-30, against `block/buzz@eed74bde2` (clean tree) and this
repository's `main`.

---

## Why this file exists

`APPENDIX-NORMATIVE.md` was created in wave 1 because nine documents had no registry and five
values got re-decided independently in three or four of them. Wave 2 then produced sixteen
artifacts, each with its own **COMMITMENTS** block declaring its own reading binding, and did not
extend the registry. Sixteen private registries is the same defect one level up, and it is worse in
one specific way: where two artifacts collided, *both* fixes looked ratified, so there was nothing
left to notice.

`21-ADRS.md` §2.0 saw this and arbitrated three values. That section is good and stands. This file
is its completion: it carries §2.0's rows, adds the ones §2.0 could not reach because they are not
ADR-level, records the values the integration pass had to break a tie on, and — the part nobody
else could do — states which of the **forty-plus** proposed brief amendments survive, which were
absorbed, and which are withdrawn.

**The rule for using this page.** An artifact cites a row. It does not restate the value. If you
believe a row is wrong, change it here and say so in the pull request; do not fix it in your own
file and leave the two disagreeing.

---

## 1. Arbitrated values

Each row states the answer, who owns it going forward, and the passages it supersedes. A row marked
**INTEGRATOR RULING** is one the integration pass decided because no producer had standing to; every
other row ratifies an existing owner's decision.

### R-1 · How `kind:26006` reaches an operator — **INTEGRATOR RULING**

> **The frame is GLOBAL and carries no `h` tag. `26006` is added to `P_GATED_KINDS`, and that entry
> is the whole delivery fence. Every Perch REQ that can match `26006` carries `#p` equal to the
> reader's own pubkey, on every filter in the frame.**

Three artifacts shipped three designs. This is the only value in the set where two of them each
called itself binding and each said no other mechanism was needed.

| Design | Where | Status |
|---|---|---|
| global + `P_GATED_KINDS` | `13-WIRE-SCHEMAS.md` W-9; `schemas/frame-26006-hold-alarm.schema.json`; `fixtures/wire/frame-26006-*.json`; `skeleton/desktop/src/shared/api/perchSubscriptions.ts` | **RATIFIED** |
| `h` tag to a standing `#watch` channel, layered under the p-gate | `10-RELAY-FORK.md` §11.5 RF-D5 and §11.6 RF-D6; `11-BRIDGE-CRATE.md` §8.3 items 8–10 and §8.6; `21-ADRS.md` AR-1; `adr/0017-…` C3 rev 2 | **SUPERSEDED — layer 1 is retracted** |
| `h` tag alone, zero relay change | `13-WIRE-SCHEMAS.md` W-1, revision 1 | already withdrawn by its own author |

**Why the ruling went this way.** `10-RELAY-FORK.md` §11 is the best-argued section in the wave and
its relay findings are all correct — §11.2 showing that an `h`-tagged ephemeral takes the shipped
`KIND_HUDDLE_REACTION` route, §11.3 showing that the p-gate runs only when `channel_id.is_none()`,
and §11.4's discovery that `extract_channel_id_from_filters` and `extract_channel_ids_from_filters`
disagree about what counts as channel-scoped. None of that is disputed. What the ruling rejects is
the *conclusion* that both layers should ship, on four grounds:

1. **Layer 1's stated advantage does not exist.** RF-D5 argues the `h` tag enforces "on the sending
   pod at delivery time, not at subscription time — so a stale subscription that survives a
   membership change cannot leak." Under the global form there is no membership to change: `#p`
   filter matching is evaluated per frame against that frame's own `p` tags, so a stale global
   subscription registered with `#p:[me]` can only ever receive frames that name *me*. The property
   layer 1 was chosen for is already held by layer 2.
2. **Layer 1 puts a precondition on the one frame that may never fail.** `handle_ephemeral_event`
   runs `check_channel_membership` on the **publisher** for any `h`-tagged ephemeral. The `26006`
   alarm has a ≤400 ms budget and a never-shed rule; adding "the bridge must currently be a member
   of `#watch`" to its publish path adds a failure mode to the most safety-critical frame in the
   product. `11-BRIDGE-CRATE.md` F19 handles it loudly, which is right, but the correct move is not
   to need it.
3. **Layer 1 is coarser than layer 2 and cannot be made finer.** Channel fan-out does not consult
   `p` tags, so every `#watch` member receives every operator's alarms. `10-RELAY-FORK.md` §11.9
   concedes this and can only mitigate it with a configuration requirement ("`#watch` membership
   must be exactly the `Approve` principal set") that nothing enforces. Layer 2 is per-principal by
   construction.
4. **Applying both makes layer 2 dead in production and buys a client landmine.** Under the layered
   design no production frame is global, so `P_GATED_KINDS` fences a route nothing takes; and
   RF-D6 — the rule that a REQ matching `26006` must name exactly one channel across every filter,
   or the relay closes the whole subscription with a message about `#p` tags — exists solely to
   manage the interaction the `h` tag creates. Remove the `h` tag and RF-D6 is unnecessary.

**What the ruling gives up, stated plainly.** If `P_GATED_KINDS` is not carried — upstream declines
patch 2 *and* the fork drops it — there is no compartment at all, and any authenticated community
member can open `REQ {"kinds":[26006]}` and enumerate every hold's existence, severity, action kind
and case channel. `10-RELAY-FORK.md` §8 commits the fork to carrying it, and that commitment is now
load-bearing rather than belt-and-braces. Say so in the fork's PR.

**Consequent edits, all applied by the integration pass:**

- `patches/relay-26006-pgate.patch` — **no change.** The patch is neutral between the two designs:
  it reserves `KIND_OPERATOR_ALARM_FRAME`, adds the `P_GATED_KINDS` entry, and its own doc comment
  already says a producer that also sets `h` gets the ordinary channel path. It applies clean.
- `skeleton/desktop/src/shared/api/perchSubscriptions.ts` — the `watch-alarm` filter stays
  `{kinds:[26006], "#p":[myPubkey], limit:0}`. Its comment block is rewritten to cite this row
  rather than to argue with a peer.
- `10-RELAY-FORK.md` §11.5, §11.6, RF-A6 — carry a ruling banner. RF-D5's layer 1 is retracted;
  RF-D6 is retired as unnecessary; §11.7 tests 1–4 stand and tests 5–8 are reclassified as
  documentation of the design not taken.
- `11-BRIDGE-CRATE.md` §8.3 items 8–10, §8.6, F19, T-21, `config.rs` `watch_channel`,
  `channels.rs` `PublishAlarm` — carry a ruling banner. `perch.watch_channel` becomes dead
  configuration; delete it in the crate's first PR.
- `21-ADRS.md` §2.0 AR-1 and `adr/0017-…` clause C3 — carry a ruling banner.

**Brief amendment.** `APPENDIX-NORMATIVE.md` §3's ephemeral row ("global (no `h`)") and §4 layer 2
stand **unchanged**. The only amendment needed is an addition: *`26006` is listed in
`P_GATED_KINDS`; every REQ that can match it carries `#p = self` on every filter.* This
**supersedes RF-A6 and ADR 0017's AD-A7**, both of which proposed the `h` tag. File one row.

### R-2 · What `distinct_sources` counts

> **Strategy-scoped agent ids.** `APPENDIX-NORMATIVE.md` §8 render law 2 is correct exactly as
> written and needs no amendment.

Re-verified independently by the integration pass, at the line, this session:

- `resolve_deposits` (`crates/swarm-runtime/src/detection/pipeline.rs:543-580`, `pub(crate)`,
  called at `:79-80` by `detect_and_deposit_with_role` inside `swarm_detect --serve`'s detection
  pipeline) sets **every** deposit's `agent_id` to
  `strategy_scoped_agent_id(agent_id, &finding.strategy_id)` at `:573`, then writes each deposit to
  the substrate at `:84`.
- `strategy_scoped_agent_id` (`crates/swarm-whisker/src/stream.rs:20-22`) is
  `AgentId(format!("{}:{strategy_id}", base.0))` — it **appends** a third segment.
- `concentration_for` (`crates/swarm-pheromone/src/substrate.rs`, run on each monitor tick) does
  `sources.insert(deposit.agent_id.0.clone())` at `:1295` and reports `sources.len()`.
- The id `WhiskerAgent::tick` derives at `whisker_agent.rs:148-149` is the **base**. Stopping there
  is how this was misread twice.
- The workspace asserts it itself: `strategy_scoped_agent_ids_count_as_distinct_sources_across_instances`
  (`crates/swarm-pheromone/tests/multi_instance.rs:352-388`) deposits under **one** base agent
  `"shared-whisker"` with **two** strategy ids and asserts `distinct_sources == 2`.

So one Whisker running two detectors is **two sources / one agent**, and it clears
`min_sources_for_escalation: 2` on its own. The canonical demo fixture reproduces exactly that.

**Ground-agent correction C-5 is REJECTED.** It read `substrate.rs:1295` and `whisker_agent.rs:148-149`
and concluded the counting unit is the agent instance. It did not follow `resolve_deposits`, which
rewrites `agent_id` between those two points. Its conclusion ("four detectors agreeing FAILS to
escalate") is the opposite of what the tree does. Recorded here so it is not re-raised.

**State in the artifacts: already correct.** `13-WIRE-SCHEMAS.md` withdrew W-6; the `const` in
`schemas/card-ambush-escalation-v1.schema.json`, the `$defs/SourceCountMechanism` in
`common.schema.json`, `skeleton/perch-wire/ts/zod.ts`, `ts/types.ts`, `rust/src/cards.rs`, the
golden vector and its pinned hash all say `strategy_scoped_agent_id`. The integration pass corrected
two stale prose paragraphs (`17-COMPONENT-SPECS.md` §4.8, `18-DATAVIZ.md` §17) that still described
the pre-fix state as current.

### R-3 · `hold_id` — **INTEGRATOR RULING, narrowing AR-3**

> **The wire contract is the pattern `^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$` — no colon, URL-safe,
> bounded — held as `common.schema.json#/$defs/HoldId` and enforced at the bridge's publish seam by
> `HoldId::parse`. What B1 mints inside that pattern is B1's choice.**

`21-ADRS.md` AR-3 and AD-A8 ratified "a lowercase hyphenated UUID". The schemas, the Rust parser,
the zod decoder and the canonical fixture shipped the pattern instead, and the fixture's own ids
(`h_a07aeacf`, `h_1c28ae79`) are not UUIDs. Rather than regenerate a validated fixture to satisfy a
sentence, the ruling adopts what shipped: the pattern is the machine-checkable contract, and it
already forbids the thing AR-3 existed to forbid — the derived `hold:{hunt_id}:{held_at_ms}` form,
because `hunt_id` is a join key into detection data and the id rides a `kind:26006` frame.

`12-BACKEND-BILL-API.md` commits B1 to a UUID; that satisfies the pattern and stays. **Amend AR-3
and AD-A8 to state the pattern, with UUID as B1's satisfying choice.** Applied.

The six formats the census found (`hold_a1f4c2e9`, `hold:01K3QJ…`, `hold:01JQ8Z…`, `hold-9c1e77b204`,
`hold-4c1f7a20`, `h_a07aeacf`) survive only in changelog tables and in `tags.rs`'s accept/reject test
inputs. No prototype and no fixture renders a colon form.

### R-4 · The CSS custom-property namespace — closed, and now enforced

> **`--perch-*`, matching `tokens/perch-tokens.css` name for name.** `tokens/perch-token-aliases.tsv`
> is the mapping; it ships its own `sed` recipe.

`19-TOKENS.md` owns this and `21-ADRS.md` ceded it there. All five prototypes had already been
re-authored in revision 2. The integration pass closed the residue and the hole that let it exist:

| Was | Now | Why it mattered |
|---|---|---|
| `watch.html` declared `--text-xs/-sm/-base/-lg` on `:root`, 82 live references | `--perch-text-*` | those four are Buzz's own (`globals/typography.css:18-21`) and carry the conversation type contract 13/14/15px; declaring them re-sizes every inherited Buzz surface |
| `case.html` used `--perch-t-*` | `--perch-text-*` | namespaced but not canonical — a fourth prefix for one ramp |
| `watchfloor-ledger.html` used `--dur-*`, `--ease-*`, `--rail` | `--perch-duration-*`, `--perch-ease-*`, `--perch-rail-hue` | two names for one duration is the same defect as two names for one colour |
| `verdict-hold.html` used `--proto-dur-*`, `--proto-ease` | `--perch-duration-*`, `--perch-ease-standard` | a private twin of a shipped token |
| `dataviz.html` used `--font-sans`, `--font-mono`, `--plate-rail`, `--perch-viz-track` | `--perch-font-*`, `--perch-rail-hue`, `--perch-viz-unfilled` | — |

**The hole.** `perch-tokens.test.mjs`'s T-M asserted every bare name has a *row*. It never asserted
the row was *acted on*, which is how 82 bare Buzz names shipped past a green gate. The integration
pass added **T-M2**, which fails on any live `var(--x)` or `--x:` reference to a name the table marks
`rename`, while deliberately leaving prose that *names* the defect readable. 20/20 pass.

**The one open question this does not close.** `tokens/perch-bridge.css`'s
`[data-perch-theme-pin]` block is the only thing that holds the palette while `ThemeProvider` is
writing inline, and `19-TOKENS.md` §15 commits to deleting it once the inline writers are scoped.
Until that scoping lands, **the pin is permanent**. Say so in the file rather than carrying a
deletion commitment nothing has scheduled.

### R-5 · The canonical fixture

> **`fixtures/perch-demo-fixture.json`, with every id regenerated by `fixtures/derive-ids.mjs` from
> a public label.** `22-DEMO-FIXTURE.md` owns it.

Verified this session: `fixtures/validate.mjs` reports **0 failures**, recomputes **14** envelope
hashes and matches them, and walks three issuer chains intact; `shasum -a 256 -c SHA256SUMS` is
clean across all 24 files. The case channel `27799e23-ab25-4659-b381-3de47ea7ca4d` and
`total_strength 2.696884` now appear across the prototypes, the wire vectors, the HTTP snapshots and
the viz fixture. The five-canonical-fixtures problem is closed.

Two ids that are *not* the case channel and should not be mistaken for competitors:
`b8240a37-88b1-4a9f-8b77-5cc005891115` is the **execution lane** channel and
`426cef7e-808f-4988-af82-42d911a0d480` is the standing ops channel.

### R-6 · The verification tier of a receipt

> **`ambush:receipt:v1` is tier 0.** Tier 1 is reserved for `ambush:rollback:v1`.

A `ResponseReceipt` carries no attestation of its own body. Where `audit.governance.receipt` is
present, the attestation is a consensus signature over a *proposal*, not over this receipt — and
`ConsensusGovernanceReceipt::verify()` checks the signature without reading whether the payload says
Approve or Veto, or whether it concerns this action. `adr/0016-…` rev 2 states that limit correctly.
`watchfloor-ledger.html` and `case.html` now agree; the export manifest stamps
`"verification_tier": 0` on receipt entries.

### R-7 · The terminal chord

> **⌘/Ctrl-J**, inherited from Buzz, not rebound.

`APPENDIX-NORMATIVE.md` §2 says `Cmd-\``. The shipped binding is
`BUZZ desktop/src/features/terminal/TerminalBootstrap.tsx:146-168` — a capture-phase listener on
both `keydown` and `keyup` in the renderer, matching `event.code === "KeyJ"` with meta-or-ctrl and no
alt or shift, calling `stopImmediatePropagation`, toggling only on the keyup. Rebinding to backtick
is work nobody costed. Every wave-2 artifact already agrees; **brief amendment TB-3** files it once.

---

## 2. Values with one owner, recorded so nobody re-decides them

| Value | Answer | Owner |
|---|---|---|
| Route table | eleven routes, fourteen surfaces, exactly as `APPENDIX-NORMATIVE.md` §1. `skeleton/desktop/src/app/routes.ts` matches it line for line | `04` §1.1 |
| Row key map | exactly `APPENDIX-NORMATIVE.md` §2. `skeleton/tests/node/perchKeymapRegistry.ts` is the machine-readable copy; its sibling test passes 8/8 | `04` §3.0 |
| Interpolation tolerance | ε = `policy.evaporation_threshold`, computed in exactly one function | `18-DATAVIZ.md` (A11) |
| Type ramp | nine rem-derived steps, `--perch-text-3xs` … `--perch-text-xl`. Measured census: 594 nodes, 43.4% ≥14px, **0 at 8px** | `19-TOKENS.md` §7 |
| Three-hue pillar borders | decoration, not classification (1.31–1.58:1). The 2.5px top rail at 8.6–10.6:1 is the classification channel | `19-TOKENS.md` §3 |
| `FactIssuer.role` | required **and** nullable. `infer_agent_role` returns `None` for every `swarm:ed25519:` identity, so the shipped daemon path produces `role: null` on every card | `13-WIRE-SCHEMAS.md` (W-A1) |
| `source_ids` on a Phase-1 card | always `null`, with `source_ids_absent_reason: "not_carried_by_runtime_event"`. The `M agents` half of render law 2 renders that **named absence**, never a fabricated count, until B4 lands in Phase 2 | `13-WIRE-SCHEMAS.md` §3 + `17` §4.8 |
| Case-channel creation on manual promotion | the bridge, on two triggers; the second is bill item **B1d** (`RuntimeEvent::CasePromoted`, ~0.5 ew) | `adr/0018-…` C2 |
| Two operators, one hold | legitimate. The daemon's compare-and-set arbitrates; the losing console publishes a `superseded` card carrying the winner's `nostr_intent_event_id` | `adr/0014-…` C4 |
| OpenAPI CI contract | the **JSON** is the gated artifact (generator-reproducible); the YAML is the reviewable form, kept in step by `openapi/render-perch-openapi.py --check`, which passes | `12-BACKEND-BILL-API.md` §14 |
| Copy-gate scope | authored literals in Perch's own roots only. Every daemon-supplied string reaching a rendered slot is out of scope and needs runtime treatment instead | `16-INVARIANT-TESTS.md` §6 + RF-A5 |

---

## 3. The amendment set for the wave-1 plan, consolidated

Over forty amendments were proposed across the sixteen artifacts, several superseding each other.
This is the deduplicated set. **File this list, not the sixteen.**

| # | Target | Amendment | Absorbs | Status |
|---|---|---|---|---|
| **W2-1** | `APPENDIX-NORMATIVE.md` §6 verified counts | `AppShell.tsx` / `MessageRow.tsx` / `HomeView.tsx` = **998 / 999 / 994** on the gate's own arithmetic (`content.split(/\r?\n/).length`, `BUZZ scripts/check-file-sizes-core.mjs:24-29`), not 997 / 998 on `wc -l`. Real headroom is 2 / 1 / 6 lines | AD-A1, `15`'s and `20`'s A-1 / A-7 | accepted |
| **W2-2** | `APPENDIX-NORMATIVE.md` §3 | The fork is **three hunks in `ingest.rs`** plus a second patch of **four hunks in `kind.rs`**; **zero client registration points**, because `46010` is a queue record and `ambush:hold:v1` on `kind:9` is the rendered row. Keep the four-point cost documented as the price of a future decision to render raw `46010` | RF-A1, AD-A3, AD-A7's arithmetic half | accepted |
| **W2-3** | `APPENDIX-NORMATIVE.md` §3 | Add: **`26006` is listed in `P_GATED_KINDS`; every REQ that can match it carries `#p = self` on every filter.** The "global (no `h`)" row itself is unchanged | supersedes RF-A6 and AD-A7's `h`-tag half | accepted — **R-1** |
| **W2-4** | `APPENDIX-NORMATIVE.md` §3 | `requires_h_channel_scope` is at **`:704-733`** (`matches!` body `:705-732`; append after `:731`). Same drift in `03` §5.1 and `00-BRIEF.md` §4.4 / §11.3 | RF-A2 | accepted |
| **W2-5** | `APPENDIX-NORMATIVE.md` §4 item 2 | `subscription.rs` **`:487-492`**, inside `fan_out_scoped` (`:379-495`). The claim itself is correct | RF-A3 | accepted |
| **W2-6** | `APPENDIX-NORMATIVE.md` §3 tag budget | **`46010` carries `h` and `p` only — never `e`.** `requires_h_channel_scope` double-duties as the NIP-10 thread-metadata gate at `ingest.rs:2987-2997`, so an `e`-tagged hold mutates `reply_count`/`descendant_count` on its root and triggers a relay-signed `kind:39005` fan-out. Also: once `46010` is channel-scoped, `check_channel_membership` applies to it — the bridge must be a member of every case channel, or the channel must be `visibility: "open"`, before a hold can be published | RF-A4 | accepted |
| **W2-7** | `APPENDIX-NORMATIVE.md` §2, §7 | `tools/check-copy-banned-terms.sh` is **PROPOSED** everywhere cited. Buzz has **no `tools/` directory**; this workspace's `tools/` holds 14 `check-*.sh` + 1 `verify-*.sh`, and this one is not among them. `16-INVARIANT-TESTS.md` now ships **both** halves as skeletons and their shared-corpus parity **runs**: 19 (file, row) pairs, exact match | AD-A4 (**corrected** — AD-A4 says the `.mjs` half does not exist; it does) | accepted |
| **W2-8** | `APPENDIX-NORMATIVE.md` §4 item 3 | Name which of two paths "`query_needs_action` on connect / reconnect / every `26006`" means, and budget it. **No desktop code path reaches `query_needs_action`**; the desktop's needs-action query is a hand-built `{"kinds":[46010,46011,46012],"#p":[me],"limit":20}` at `BUZZ desktop/src-tauri/src/commands/messages.rs:97-101`, with the limit hard-coded to 20 regardless of the caller's request | AD-A2 | accepted |
| **W2-9** | `APPENDIX-NORMATIVE.md` §5 bill labels | **Fifteen items, not eleven.** Adds **B0** (`nostr_pubkey` on `OperatorPrincipalConfig`, ~0.5 ew, uncuttable — without it a hold cannot be `p`-tagged and reaches nobody), **B1c** (`RuntimeEvent::ContainmentReleased`, ~0.5 ew, cuttable with a rendered consequence), **B1d** (`RuntimeEvent::CasePromoted`, ~0.5 ew, uncuttable while manual promotion is the enabled clause), **B2g-p** (stamp partition state at hold and at execution, ~0.25 ew) | AD-A9, `20`'s A-5 | accepted |
| **W2-10** | `APPENDIX-NORMATIVE.md` §5 B6; `09` §3.1 | B6 is one call per fact **plus** a configured signing identity and a per-issuer `seq` / `prev_envelope_hash` store. The single non-test `build_signed_envelope` caller derives its keypair from `sha256("approval-ledger-envelope:{ledger_id}")` — a public identifier — and discards the signature | AD-A5 | accepted |
| **W2-11** | `00-BRIEF.md` §4.7 | NIP-OA binds an agent **Nostr** key to an owner **Nostr** key. It buys the ban cascade and the 120/min tier; it does **not** bind the `swarm:ed25519:` identity. That mapping is configured and unsigned, and every surface that shows it must say so | AD-A6 | accepted |
| **W2-12** | `APPENDIX-NORMATIVE.md` §6 | Add `hold_id`: **matches `common.schema.json#/$defs/HoldId`; never carries a colon; never derived from `hunt_id`.** B1 mints a UUID inside that pattern | AD-A8, **narrowed** by R-3 | accepted |
| **W2-13** | `APPENDIX-NORMATIVE.md` §2 | The terminal chord is **⌘/Ctrl-J**, not `Cmd-\`` | TB-3 | accepted — **R-7** |
| **W2-14** | `APPENDIX-NORMATIVE.md` §6 | Relay quotas: the **operator publishing a verdict card is a HUMAN pubkey on `human_messages_per_min = 60`**, selected at `connection.rs:690-695` by `is_agent = ctx.agent_owner_pubkey.is_some()` — not the 120/min agent tier the row names. Add the second, tighter ceiling the plan set never recorded: **every inbound EVENT/REQ/COUNT frame is charged against a 50-frames-per-5-second budget with no agent exemption** (`connection.rs:671-681`, `admission.rs:9,40-45`), which makes the coalesced 10 Hz → 1 Hz rule a hard requirement rather than an optimisation. The "elevated/platform tiers read by no enforcement site" half is verified true | ground-agent corrections | accepted |
| **W2-15** | `APPENDIX-NORMATIVE.md` §6 | `lease_ttl_ms: 60,000` is **`policy.lease_ttl_ms`**, the capability lease. The object an operator watches count down is a **`ContainmentLease`**, whose TTL is `runtime.containment.lease_ttl_ms`, default **900,000 ms / 15 min**, which `rulesets/default.yaml` cannot set. A third, unrelated **contingency** lease defaults to **300,000 ms / 5 min**. Any surface rendering 60 s beside a `ContainmentLeaseView` is off by 15×; `06` §2.2's "60-second contingency lease" cites a `#[tokio::test]` fixture and is off by 5× | ground-agent corrections C-1, `06` §2.2 | accepted |
| **W2-16** | `APPENDIX-NORMATIVE.md` §5, §6; `09` §3.1 | The 49 operator routes run under **`swarmctl serve`** (default `127.0.0.1:7766`), a different process from `swarm_detect --serve` (default `:9090`) with a different `IngestState` and a different incident store. Mounting the bill there answers "no such hold" for every hold the daemon holds. Also: one of the 49 is `/metrics` on an **unprotected** router, so 48 are authenticated, and two further `/v1/operator/*` routes exist in `containment.rs:262-270` | ground-agent correction C-2, `12` §1 | accepted |
| **W2-17** | `APPENDIX-NORMATIVE.md` §7 | The badge ladder is **12 destructive → 4 leased → 3 reversible**. Only `QuarantineFile`, `SuspendProcess`, `IsolateHost` and `TerminateUserSession` mint a `ContainmentLease`; of those, `TerminateUserSession` is `InverseGap::Irreversible`. **The eight unleased destructive actions have no lease, no TTL, no countdown and no rollback receipt**, so their hold cards must not render a pending-lease slot | ground-agent correction C-4 | accepted |
| **W2-18** | `09` §3.1 | `/v1/events/stream` is **not** unauthenticated — it inverts the usual leak. `resolve_demo_scope` returns `Ok(requested_scope)` unverified when `context_token` is absent and `runtime_event_matches_scope` short-circuits on an empty scope, so an **anonymous** caller receives `TamperAlert`, `AgentHealth` and `EvolutionStatus` while a token-bearing **scoped** caller is denied all three. B5's fix is "make the token mandatory", not "add auth" | ground-agent correction C-7 | accepted |
| **W2-19** | `03` §4.2 | `RuntimeEvent::AgentAction` is **not** carrier H. No operator route serves agent actions, so "fetch the full details from the daemon on demand" is unbuildable. `07` §4 is right: tallies fold into the `26002` frame and `details` never crosses the wire | `07` §14's unapplied request | accepted |
| **W2-20** | `05` §2.4, §2.3, §11, §12 | The design-system numbers are superseded by `19-TOKENS.md` and `tokens/perch-tokens.css` wherever they differ. Specifically: light `--muted-foreground` `#5d7269` **fails AA** at 4.42:1 on chrome; `--ring` rebound to `--border-strong` gives **1.77:1** against `--card`, failing SC 1.4.11; the sidebar is **300px** not 256 (256 is the screenshot crop width); the inbox is **365px** not 420; the case members panel is **380px** not 320; the governance strip is **28px** | `19-TOKENS.md` §5, ground-agent corrections | accepted |
| **W2-21** | `04` §2.2 | The Verdict Row wireframe was never redrawn after `04` §6.1 recorded "adopt 08". As it stands it shows a plain outline grant button and "hold expires in 12m"; a producer drawing from it ships the one-keypress grant INV-11 forbids. Take `08` §3.3, and take `prototypes/verdict-hold.html` over both | ground-agent correction | accepted |
| **W2-22** | `09` §7 | The dependency-graph label "Phase 1 — 27 ew, 14 Rust" is stale; `09` §3.4's own table totals **28 ew with 15 Rust**. The label predates B3i | AD's second note | accepted |
| **W2-23** | `05` §3.1, §5, §9, intro | There are **20** SVGs in `docs/assets/`, not 19; six carry a banned string in their `aria-label`. The px-text guard does **not** fire on hand-authored SVG labels (`FONT_SIZE_PX_RE` needs a `font-size` colon; an SVG attribute is `font-size="11"`), so the rule stands and its enforcement needs a third regex — which `viz/check-svg-font-size.mjs` now delivers. `colony.svg` assigns **hues**, not glyphs: all 17 marks are unbuilt art with no source. The reuse-verbatim list is 47 files, and 16 `shared/ui` files receive no verdict at all — six of which render adversary-controlled remote content into a security console | `18-DATAVIZ.md` §14, `17` §10, ground-agent corrections | accepted |
| **RF-A5** | copy-gate scope note | The ban list is scoped to Perch's own rendered strings and Perch's feature roots. It is never run against a patch, a PR body, or a test written against another project's code | — | accepted |

**Withdrawn, and recorded so they are not re-raised:** `13`'s **W-1** and **W-6**; `17`'s SourceCount
amendment; `21`'s **AD-A3** and **AD-A7**; `10`'s **RF-A6** and DECISION **RF-D5** layer 1 and
**RF-D6**; `21`'s **AR-1** as written.

**Rejected:** ground-agent correction **C-5** (see R-2).

---

## 4. What the integration pass changed

Every edit is inside `docs/plans/ambush-ui/build/`. Nothing in either source repository was touched.

| Change | Files |
|---|---|
| Token namespace unified; canonical `--perch-text-*` / `--perch-duration-*` / `--perch-ease-*` / `--perch-rail-hue` / `--perch-font-*` applied | all five prototypes |
| Twelve alias rows added, covering the last uncovered names | `tokens/perch-token-aliases.tsv` |
| **T-M2** added: fails on any live reference to a name marked `rename` | `tokens/perch-tokens.test.mjs` |
| `26006` ruling banners; the subscription comment rewritten to cite R-1 | `10`, `11`, `21`, `adr/0017-…`, `skeleton/desktop/src/shared/api/perchSubscriptions.ts` |
| AR-3 / AD-A8 narrowed to the pattern; AD-A4 corrected | `21-ADRS.md` |
| Two stale paragraphs describing the pre-fix `const` as current | `17-COMPONENT-SPECS.md`, `18-DATAVIZ.md` |
| `viz/contrast.mjs` delivered — the tool `18` §15 cites as "in scratch" | new |
| `gallery.html`, `README.md`, this file | new |

---

## 5. What this registry does not decide

- **The density of the drawn surfaces.** The type census is now measured and clean (0 nodes at
  8px, 43.4% at 14px or above), but whether a 14px conversation baseline is right for an analyst at
  3am is a design judgement nobody in this run has evidence for. It needs one shift of real use.
- **Whether the `h`-tag design should return.** R-1 is a ruling on the evidence available. If the
  fork cannot carry `P_GATED_KINDS` — upstream declines *and* the maintainers refuse the carry — the
  `#watch` compartment is the only remaining mechanism and this row reverses. `11-BRIDGE-CRATE.md`'s
  `#watch` work is retired, not deleted, for exactly that reason.
- **Anything that requires compiling.** No Rust in this set has been built, because no crate exists
  to build it into.
