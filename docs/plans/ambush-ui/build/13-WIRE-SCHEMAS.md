# 13 — Wire schemas: markers, ephemerals, types

> **Wave 3 (2026-09-02): the marker namespace is `swarm:` and the fact schema id is `swarm.perch.<card>.v1` (00-DECISIONS W3-1); the verdict preimage has four members (W3-16). The bodies of this document still say `ambush:` where they quote wave 2; the schemas and goldens are authoritative.**

**Status:** buildable artifact, **revised after red-team review**. The schemas,
the skeletons and the gate are the deliverable; this file carries the argument
around them.

**Read §9.1 first if you have read an earlier revision.** Three of this file's
own amendments are **withdrawn**, and two of the three had already been compiled
into a `const`, a `z.literal`, a Rust enum, a golden vector and a pinned hash —
so they were not prose errors. §7.2 (the counting mechanism), §4.4 (`26006`
delivery) and §9.1 (the withdrawals) are where the corrections live, with the
source read at the line in each case.

**Scope.** Everything that crosses the relay: seven `kind:9` marker cards, one
stored `kind:46010` queue record, and the seven ephemeral frames
`26000`–`26006`. The HTTP contract these cards are read back against is
[`openapi/perch-operator-v1.yaml`](openapi/perch-operator-v1.yaml); the relay
fork that admits `46010` is [`10-RELAY-FORK.md`](10-RELAY-FORK.md). This file
does not restate either.

**Values.** Shared constants, the route table, the key map, the backend-bill
labels and the vocabulary rulings live in
[`../APPENDIX-NORMATIVE.md`](../APPENDIX-NORMATIVE.md). Where this artifact
disagrees with it, §9 says so with the argument.

**Example corpus.** There is now **one**. The golden vectors are re-keyed onto
`fixtures/perch-demo-fixture.json` — 22-DEMO-FIXTURE's canonical scenario, whose
ids are all `sha256` of a public label and regenerable with
`node fixtures/derive-ids.mjs`. Case channel
`27799e23-ab25-4659-b381-3de47ea7ca4d`, hold `h_a07aeacf` (`isolate_host`,
`CRITICAL`), threat class `execution`, crossing at `2.696884` with 2 sources.
This file previously carried a second, invented set; two normative example
corpora for one card is zero.

---

## 0. The artifacts, and how to run them

```
build/schemas/                            17 JSON Schemas (draft 2020-12)
  common.schema.json                      40 shared definitions, each with its source
  card-envelope.schema.json               the swarm.spine.envelope.v1 wrapper
  card-swarm-{finding,escalation,hold,verdict,receipt,lease,rollback}-v1.schema.json
  event-46010-hold-notice.schema.json     an EVENT schema: a closed tag set + a content grammar
  frame-2600{0..6}-*.schema.json          the ephemeral block
  _index.json                             registry, tier and issuer type per card

build/skeleton/perch-wire/
  golden/*.json                           16 vectors, EXTRACTED from the schemas'
  golden/GOLDEN.sha256                    own `examples`, hash-pinned by BOTH suites
  rust/                                → AMB  crates/swarm-perch-wire/
  ts/                                  → BUZZ desktop/src/features/perch/wire/
  parity-gate.sh                       → AMB  tools/check-perch-wire-parity.sh
  README.md                               the sync story, and an honest ledger of
                                          what was executed while writing it
```

**Reproduce, with no environment variables, from the committed paths:**

```bash
cd docs/plans/ambush-ui/build
bash skeleton/perch-wire/parity-gate.sh              # 312 fields, 17 schemas
bash skeleton/perch-wire/parity-gate.sh --self-test  # 5 cases, each a way it must fail
```

Verified in this session by running exactly those files from exactly those paths:

| Check | Result |
|---|---|
| All 17 schemas are valid draft 2020-12 | pass |
| Every `examples` entry validates against its own schema, cross-file `$ref` resolved | **16/16** |
| A positive/negative mutation suite over the contested clauses | **25/25 behave** (below) |
| `parity-gate.sh`, as committed, no env vars | **312 declared fields across 17 schemas, all present on both sides** |
| `parity-gate.sh --self-test` | **5/5** — including the string-literal near-miss that had made the gate satisfiable by an error message |
| `parity-gate.sh` live self-test | deleting `dedupe_key` from `rust/src/cards.rs` → exit 1 naming it; renaming `source_ids_absent_reason` in `ts/zod.ts` → exit 1 naming it |
| Golden hash, now asserted by **both** suites | `10233c15…` |
| 22-DEMO-FIXTURE's 23 wire fixtures against these schemas | **20 pass, 3 fail**, each with a one-line fix named in §11 |
| Every TypeScript file clears the 1000-line cap | `zod.ts` 820, `types.ts` 759, `golden.test.mjs` 576, `marker.ts` 210, `tags.ts` 153, `index.ts` 127 gate-lines (the gate counts `content.split(/\r?\n/).length` = `wc -l` **plus one**, `BUZZ scripts/check-file-sizes-core.mjs:24-29`); `src/features` is a governed root |
| Rust gate-lines, for the record | `cards.rs` **992**, `tags.rs` 552, `frames.rs` 495, `tests/golden.rs` 374, `envelope.rs` 334, `marker.rs` 323, `narrowing.rs` 179, `lib.rs` 133. AMBUSH's `tools/` has **no file-size gate** (15 `check-*.sh`, none of them one), so 992 is legal there; the `cards/{mod,evidence,hold,verdict}.rs` split is a readability call, and `parity-gate.sh` uses `rglob` so taking it cannot make the Rust half go vacuous |

The mutation suite, all 25 behaving:

| Family | Cases |
|---|---|
| source count | the withdrawn `agent_instance_id` const is **rejected**; `strategy_scoped_agent_id` accepted; `source_ids` and `source_ids_absent_reason` both null rejected; both populated rejected; the post-B4 shape (ids populated, reason null) accepted; a missing `source_ids_absent_reason` rejected |
| 46010 tags | a `t`, an `l`, a `k`, an `e`, a second `h`, a missing `hold`, an uppercase `p` — each rejected; two `p` tags accepted |
| hold id | a `hold:`-prefixed derived id rejected on the verdict card, on the 26006 frame **and** inside the 46010 content line; a 7-char id rejected; a path-shaped id rejected; `h_a07aeacf` accepted |
| verdict issuer | `role: "tom"` rejected; `role: "whisker"` rejected; `role: null` accepted |
| leg 2 | `superseded` with no `superseded_by` rejected; `recorded` **with** one rejected; the losing console's card accepted |

**Three corrections to this file's own previous numbers**, since a count quoted
as a measurement is a claim like any other. It said *18 JSON Schemas* — there
are **17** (7 cards + 7 frames + the 46010 event + `common` + `card-envelope`).
It said *15 golden vectors* — there are **16**, because `swarm:verdict:v1` now
has two examples. And it reported a golden hash and a 308-field parity result as
verification results when **neither was reachable from a committed file**: the
hash was computed at a shell prompt and asserted nowhere, and the 308 required
three environment overrides because the gate's default roots pointed at a
directory that existed in no tree. Both are now assertions in committed files
that run green from the committed path.

Still not executed, and flagged where it matters: the Rust crate does not compile
(it is a skeleton with `todo!()` in seven `human_line` bodies), the zod module
was not run (`node_modules` is not installed in this checkout), and
`gpt_markdown`'s handling of an HTML comment was not verified — see §8.4.

---

## 1. The card content grammar

### 1.1 The marker, exactly

```
<!-- swarm:<card>:v1 -->
```

`19 + len(slug)` characters — **23 to 29**, not a fixed width: `hold` is 23,
`lease` 24, `finding`/`verdict`/`receipt` 26, `rollback` 27, `escalation` 29. (An
earlier revision said "twenty-six characters", which is true only of the three
seven-letter slugs. It matters because the marker's cost is subtracted from the
93-character search-preview window in §8.5.) `<card>` is one of the seven slugs,
which is also the `k` tag's value and the second segment of `fact.schema`.

The format is **Buzz's own, with one word changed**. The only HTML-comment
content marker Buzz ships is
`WAVE_MESSAGE_MARKER = "<!-- buzz:wave:v1 -->"`
(`BUZZ desktop/src/features/messages/lib/waveMessage.ts:1`). A repo-wide grep for
`MARKER` across `desktop/src` returns exactly one other set — the projects
feature's plain-prose context markers
(`projectDetailAgentContext.ts:7,9`) — and no other HTML comment sentinel. So
there is one precedent and Perch matches it rather than inventing a shape.

### 1.2 The three parts, in this order

````
<!-- swarm:hold:v1 -->
hold h_a07aeacf · isolate_host · CRITICAL · host host-ops-1 · expires 2026-03-17T10:14:42+00:00

```swarm:hold:v1
{"schema":"swarm.spine.envelope.v1","issuer":"swarm:ed25519:…","seq":3, …}
```
````

1. **Marker.** Whole first line, nothing else.
2. **Human fallback line.** One line, ` · `-separated. The degradation contract.
3. **Fenced JSON**, info string `swarm:<card>:v1`, one line of JSON.

**This is not the plan's ordering, and the change is the point.**
`03` §3.2's sketch is marker / JSON / human line. Two things break under it, and
both were measured this session:

**(a) The search preview shows the JSON and never the human line.** Buzz's
`buildSearchResultPreview(content, query, maxLength = 96)`
(`BUZZ desktop/src/features/search/lib/searchMatch.ts:169-200`) is a pure
function in the renderer, called from the Cmd-K result list at
`BUZZ desktop/src/features/search/ui/TopbarSearch.tsx:699` with the default
length. When the query does not match inside the body it returns
`text.slice(0, 93) + "..."`; when it does, it slices 96 characters around the
first match. With the JSON second, every Ledger result reads
`<!-- swarm:hold:v1 --> {"schema":"swarm.spine.envelope.v1","issuer":"swarm:ed`.
With the human line second, the marker costs 27 characters (26 + a newline) and
the remaining 69 carry the hold id, the action kind, the severity and the host.
`golden.test.mjs` asserts exactly that, on the 95-character line above.

**(b) A bare JSON line is a wall in every degraded renderer.** Buzz's own
structured-payload precedent fences it: `buzz-acp`'s setup listener emits
```` ```buzz:config-nudge ```` at `BUZZ crates/buzz-acp/src/setup_mode.rs:296`
(built by `nudge_body`, `:243-300`) and its parser's doc comment says why — "The
prose above the fence is left untouched and used as a plaintext fallback for
non-card clients" (`BUZZ desktop/src/shared/lib/configNudge.ts:5-16`). Perch puts
the prose *above* the fence for the same reason and keeps the marker on top so
the renderer can route before it parses.

**Separability is preserved.** The plan's stated reason for JSON-on-one-line —
"so the fallback is separable by the first newline" — is satisfied by the fence,
which is a stronger delimiter and survives a JSON body that ever grows a newline.

### 1.3 How the renderer sniffs it, and how Perch hardens it

`MessageRow.renderBody()`
(`BUZZ desktop/src/features/messages/ui/MessageRow.tsx:381-459`) is a closure
inside the memoized `MessageRow` component, in the renderer process. It switches
on `message.kind` for exactly two kinds — `KIND_STREAM_MESSAGE_DIFF` at `:383`,
`KIND_HUDDLE_STARTED` at `:406` — and falls through to a `default:` arm at `:414`
whose **first** action is a content sniff, `parseWaveMessageContent(message.body)`
at `:415`, before it hands the body to `VideoReviewCommentMarkdown` at `:429`.

That arm is the entire mechanism, and it is why the seven markers cost **zero**
of the four client registration points: they ride `kind:9`, which is already in
`CHANNEL_EVENT_KINDS` (`kinds.ts:100-113`), `CHANNEL_TIMELINE_CONTENT_KINDS`
(`:137-149`) and `isTimelineContentEvent`
(`formatTimelineMessages.ts:52-66`).

Perch's sniff differs in two ways, both required by INV-15:

| | Buzz | Perch |
|---|---|---|
| Predicate | `content.trimStart().startsWith(MARKER)` (`waveMessage.ts:15-19`) | the marker is the **entire first line** |
| Issuer | none | the event's **raw signer** must resolve to an admitted bridge identity |

The first matters because `startsWith` after `trimStart` accepts
`"<!-- swarm:hold:v1 --> and here is what I want you to believe"`.
`routeCard` compares whole lines and `golden.test.mjs` pins four negative cases.

The second has its own shipped precedent, and it is a better one than the wave
card. `getConfigNudgeAuthorPubkey`
(`BUZZ desktop/src/features/messages/ui/configNudgeAuthPubkey.ts:22-34`) gates the
config-nudge card and its doc comment states the rule outright: authenticate
against `message.signerPubkey`, "the raw event signer (**NOT** `message.pubkey`,
which may be a relay-delegated display author)". Perch's admission predicate is
the same distinction with a different identity set, and `admitCard` takes it as a
parameter so the set stays configuration.

### 1.4 Size

The relay's hard cap is 256 KB — `MAX_EVENT_CONTENT_BYTES` at
`BUZZ crates/buzz-relay/src/handlers/ingest.rs:2233-2240`, checked inside
`ingest_event` in the relay process *after* signature verification and the
±900 s timestamp gate, rejecting with
`"invalid: content exceeds maximum size of 262144 bytes (got N)"`.

`PERCH_CARD_MAX_BYTES = 192 KB` (**PROPOSED**, 75%). The only unbounded field in
the whole registry is `DetectionFinding.evidence`
(`AMB crates/swarm-whisker/src/detector.rs:56`, a `serde_json::Value` built from
telemetry). The bridge replaces it with
`evidence_truncated: {bytes, sha256}` rather than a smaller blob, so the card
renders an explicit absence. A cap enforced *after* signing has one remedy —
re-sign — which is why the margin exists.

---

## 2. The registry

### 2.1 Seven markers, one stored kind, seven frames

| Marker | Kind | Channel | `k` | Carries | Tier |
|---|:-:|---|---|---|:-:|
| `swarm:finding:v1` | 9 | lane channel | `finding` | `SwarmFindingEnvelope` + `host_id` from the `RuntimeEvent::Finding` wrapper | 0 |
| `swarm:escalation:v1` | 9 | lane channel | `escalation` | one of three causes (§4.2) | 0 |
| `swarm:hold:v1` | 9 | case | `hold` | the `HeldActionStore` record; open card + one terminal card | 0 |
| `swarm:verdict:v1` | 9 | case | `verdict` | the human decision — leg 1 | **1** |
| `swarm:receipt:v1` | 9 | case | `receipt` | `AuditTrail` | 0 · 1 scoped |
| `swarm:lease:v1` | 9 | case | `lease` | `ContainmentLease` on open | 0 |
| `swarm:rollback:v1` | 9 | case | `rollback` | `RollbackReceipt` (+ the release body when manual) | 0 · **1** when attested |
| — | **46010** | case | — | the needs-action queue record: one human line, a closed four-name tag set | n/a |
| — | 26000–26006 | **global, no `h`** | — | aggregates (§4); `26006` is compartmented by `P_GATED_KINDS`, not by a channel (§4.4) | n/a |

An eighth marker needs `03` §4.4's justification shape — *what an operator cannot
reconstruct without it after the ephemeral has decayed* — and the two suites'
registry tests are where that conversation starts:
`the_registry_is_seven_cards_one_stored_kind_and_seven_frames` (`tests/golden.rs`)
and its `golden.test.mjs` twin. **Both count distinct `fact.schema` values, not
files**, because `swarm:verdict:v1` has two vectors: the leg-1 card and the
losing console's `superseded` update card (§3.5). Counting files would have made
the second one look like an eighth marker.

### 2.2 The envelope: `swarm.spine.envelope.v1`, unsigned, from day one

Every card body is a swarm-spine envelope with the card as its `fact`:

```jsonc
{
  "schema": "swarm.spine.envelope.v1",   // AMB crates/swarm-spine/src/envelope.rs:11
  "issuer": "swarm:ed25519:<64 hex>",    // WHO PUBLISHED — the bridge
  "seq": 3,                              // per issuer, per stream, bridge-assigned
  "prev_envelope_hash": "0x…" | null,
  "issued_at": "2026-08-30T02:41:07Z",   // RFC 3339, SECOND precision, Z
  "capability_token": null,              // envelope.rs:89 hardcodes it
  "fact": { "schema": "swarm.perch.hold.v1", "issuer": {…}, … },
  "envelope_hash": "0x…"                 // keyless
  // "signature" — ABSENT UNTIL B6
}
```

**This is not an invention.** The field set and the ordering of the signing
preimage are `build_signed_envelope`
(`AMB crates/swarm-spine/src/envelope.rs:71-101`), which the daemon already calls
once — from the approval-ledger vote path at
`AMB crates/swarm-runtime/src/approval.rs:1810`.

**Why adopt the wrapper before B6 exists.** Two facts make it free:

- `compute_envelope_hash_hex` (`envelope.rs:47-51`) **takes no keypair**. It
  canonicalizes with `swarm_crypto::canonicalize_json`
  (`AMB crates/swarm-crypto/src/lib.rs:37`) and hashes.
- `verify_chain_link` (`AMB crates/swarm-spine/src/chain.rs:75`, **zero consumers
  outside its own module**) reads only `issuer`, `seq`, `prev_envelope_hash` and
  `envelope_hash`, compares against a persisted `IssuerChainHead` (`chain.rs:9-15`),
  and returns one of five `ChainLinkVerdict` outcomes. **Also keyless.**

So adopting it now buys two things for ~200 bytes a card:

1. **B6 becomes additive** — a configured key and two fields — instead of a
   `v1` → `v2` marker bump. Every card ever published stays `v1` forever, so a
   version bump means both renderers live in the tree for good. `09` §3.1 files
   B6 as separable; this is what makes that true.
2. **Gap detection exists at all.** This is the answer to a named blocker:
   `GET /v1/events/stream` sets `.id(event.emitted_at_ms().to_string())`
   (`AMB crates/swarm-ingest-runtime/src/ingest/demo.rs:1703`) — a millisecond
   timestamp that collides at the concentration monitor's 10 Hz cadence and is
   not monotonic across issuers — and `RuntimeEvent` has no `seq` field at all
   (`AMB crates/swarm-runtime/src/runtime_events.rs:214-305`). The bridge's `seq`
   is the first sequence number anywhere on this path, and `09` §13's "sequence-gap
   count across all issuers = 0, always" becomes measurable without B6.

**What it does not buy, stated so nobody reads it as more.** The presence of
`envelope_hash` **does not raise the tier**. `08` §6.2 defines tier 1 as a
detached Ed25519 signature over the body; a keyless hash is not one. Nor does a
`seq` gap prove the bridge saw everything the daemon sent:
`RuntimeEventBroadcaster::publish` is `let _ = self.tx.send(event)`
(`runtime_events.rs:116-118`), both existing subscribers drop a `Lagged` silently
with `let Ok(event) = result else { return None; }` (`ingest/demo.rs:1689`,
`ingest/platform_api.rs:1388`), and `rg 'Lagged|RecvError'` over `AMB crates/`
returns zero matches. Loss upstream of the bridge is countable only as
`perch_bridge_broadcast_lagged_total`, which the bridge publishes separately.

Both constraints are enforced by tests: `envelope.rs`'s
`an_unsigned_envelope_is_tier_zero_even_with_a_hash`, `golden.rs`'s
`every_card_vector_is_a_spine_envelope_with_no_signature`, and
`golden.test.mjs`'s `an envelope hash without a signature is still tier 0`.

### 2.3 Two issuers, and why they are two

`envelope.issuer` is a **string** — `verify_chain_link` runs it through
`parse_issuer_pubkey_hex` (`chain.rs:36-39`), which requires the literal
`swarm:ed25519:` prefix and exactly 64 hex characters. `03` §3.2's sketch puts a
three-field issuer *object* at the top level; it cannot live there.

So the registry has two:

| Field | Is | Type |
|---|---|---|
| `envelope.issuer` | **who published** — the bridge's spine keypair, one per colony (the operator's own on a verdict card) | `swarm:ed25519:<64 hex>` |
| `fact.issuer` | **who produced the fact** — the Whisker, Pouncer or monitor | `{swarm_agent_id, role, nostr_pubkey?}` |

The distinction is load-bearing: the Whisker that produced a finding did not
publish it and must not appear to have signed it. `fact.issuer.nostr_pubkey` is
**null in every deployment today** — no Ambush agent holds a Nostr keypair and
`grep -rn 'pubkey|npub|nostr' AMB crates/swarm-core/src/config/` returns nothing,
which is the same gap that forces the bridge to hold the operator_id → npub map
for `p` tags (§3.4).

---

## 3. The hold path's wire objects

### 3.1 `kind:46010` is a queue record, not a card

[`10-RELAY-FORK.md`](10-RELAY-FORK.md) decision **RF-D3** (binding) establishes
that Perch pays **zero** of the four client registration points and that the
rendered row is the `kind:9` `swarm:hold:v1` card. This artifact binds to it and
draws the consequence the fork document leaves open: **what is in the 46010's
`content`?**

The answer is **one human line, no marker, no JSON**, and three verified facts
force it:

1. **Nothing parses it.** The desktop's needs-action queue is a hand-built
   `{"kinds":[46010,46011,46012],"#p":[me],"limit":20}` POSTed to `/query` from
   the Tauri process (`BUZZ desktop/src-tauri/src/commands/messages.rs:97-101`),
   and the only TypeScript that knows the number is a headline `switch` arm at
   `BUZZ desktop/src/features/home/lib/inbox.ts:165` and an empty-content
   substitution at `:186`. A marker would route nothing, because `MessageRow`'s
   sniff is only reached for kinds that are timeline content — and RF-D3 keeps
   46010 out of that set deliberately.
2. **Its content is FTS-indexed.** `schema.sql:223-227`'s privacy `CASE` nulls
   `search_tsv` for kinds `{1059, 30179, 30300, 30350, 30622, 44100, 44101, 44200}`
   and 46010 is not among them. A human sentence is what makes a hold findable in
   the Ledger; a JSON blob is what makes the 96-character snippet unreadable.
3. **Empty is worse than either.** Buzz's shipped mobile app renders this content
   raw: `displayContent` returns `content.trim()` and substitutes
   `'A workflow is waiting for approval.'` when it is empty
   (`BUZZ mobile/lib/features/activity/feed_item.dart:84-89`), beside the headline
   `'Approval requested'` at `:63`. That is a false sentence containing a banned
   control label, shown to a Perch operator on a phone. The desktop does the same
   at `inbox.ts:186`.

### 3.2 The 46010's four tags, and the schema that now enforces it

```
["h",    "<case channel UUID>"]        exactly 1, SQL-pushed, relay-enforced
["p",    "<64 lowercase hex>"]         >= 1, one per Approve-scoped principal
["hold", "h_a07aeacf"]                 exactly 1, the reconciliation key
["card", "<64 hex Nostr event id>"]    <= 1, the sibling swarm:hold:v1 card
```

`e`, `t`, `l` and `k` are **forbidden**, and until this revision that ban lived
only in prose. The schema's `tags` **description** said "EXACTLY the four tag
names below" while its `items` was an open `array of string`, so a fixture
carrying `t`/`l`/`k` validated silently — and one does: `fixtures/wire/
event-46010-hold-a.json` ships seven tags and `fixtures/validate.mjs` reported it
`ok`. Three artifacts ended up with three answers to one question because nothing
mechanical was asking it.

It is asked now. `items.prefixItems[0]` is
`{"enum": ["h", "p", "hold", "card"]}`, with `contains`/`maxContains` pinning the
cardinalities above and `maxItems: 67` (h + hold + card + 64 principals). Both
46010 fixtures **fail** against it, naming the offending tag index. The Rust
producer already refused all four — `TagSet::assert_publishable` has had
`ExtraNoticeTag` since the first draft — so what this closes is the gap between a
producer that refuses and a schema that admits.

**Why `t`/`l`/`k` cost something rather than nothing.** Two verified facts, and
they point the same way:

1. **They are indexed.** All three are single-letter, so the relay writes each
   into the tag index on insert, widening the closed `{h, p, e, d}` budget
   APPENDIX §3 sets. RF-D1 fixes the 46010's single-letter set at `{h, p}`.
2. **They buy no query.** `filter_fully_pushable`
   (`BUZZ crates/buzz-relay/src/handlers/req.rs:851-895`) sends `#t`, `#l` and
   `#k` to its **default arm at `:885-890` — not pushed to SQL** — so a filter
   naming one cannot use the fast COUNT path and post-filters a diluted page.
   And nothing selects a 46010 by tag anyway: the desktop's needs-action query is
   `{"kinds":[46010,46011,46012],"#p":[me],"limit":20}`
   (`BUZZ desktop/src-tauri/src/commands/messages.rs:97-101`) and the mobile app's
   is the same shape (`BUZZ mobile/lib/features/activity/activity_provider.dart:476`).
   Kinds and `#p`. Nothing else.

Index cost with no query benefit is the definition of a tag that should not ship.

The `e` ban has teeth of a different kind: `requires_h_channel_scope` also gates
`resolve_nip10_thread_meta`
(`BUZZ crates/buzz-relay/src/handlers/ingest.rs:2987-2997`), so an `e`-tagged
46010 becomes a NIP-10 reply, mutates `reply_count`/`descendant_count` on its
root **inside the insert transaction**, and emits a relay-signed `kind:39005`
thread summary (`:3219-3226`).

`hold` and `card` are **multi-letter** and therefore outside RF-D1's scope by its
own wording. Neither is ever used in a filter, and both are read from an event
the client already holds: `FeedItemInfo` carries `tags` and `pubkey` across the
Tauri boundary (`BUZZ desktop/src-tauri/src/models.rs:198-210`, built by
`feed_item_from_event` at `commands/messages.rs:954-968`). **It does not carry
`sig`**, so the client cannot re-verify the Nostr signature and relies on the
relay's ingest check — worth stating because two invariants read like they could.

`hold` exists because layer 3 of the hold path reconciles each relay row against
`GET /v1/response/holds`, and INV-35 requires a 46010 present on the relay and
absent from the daemon to render as the forgery it is. Both need the hold id off
the event, which is why a `hold`-less notice is now a `TagError::MissingHoldTag`
rather than a publish. `card` builds the
`buzz://message?channel={case}&id={card}` deep link, and its presence forces a
publish **order** — the `kind:9` card first, then the 46010 — which is the order
we want anyway: the row exists before the queue points at it.

### 3.2.1 `hold_id` has a format contract now, because six were in circulation

Every schema that carried `hold_id` declared it as bare `"type": "string"` with a
prose warning ("An OPAQUE RANDOM TOKEN. Never `hold:{hunt_id}:{held_at_ms}`").
Prose is not a contract, and by the end of wave 2 the artifact set contained
`hold_a1f4c2e93b70c815`, `hold:01K3QJ7ZV9M2R4TX8N6B0DWCA5`,
`hold:01JQ8Z3K9V7M2R4T`, `hold-9c1e77b204`, `hold-4c1f7a20` and `h_a07aeacf` —
**two of them using the exact colon prefix the warning names**.

`common.schema.json#/$defs/HoldId` is the one place the shape is decided:

```
^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$
```

Three constraints, each with a reason:

| | Why |
|---|---|
| **No colon** | `hold:{hunt_id}:{held_at_ms}` is the derived form. `hunt_id` is the telemetry event id (`AMB crates/swarm-runtime/src/service/runtime_service.rs:391`), a join key into detection data, and the hold id rides a `kind:26006` frame every Approve-scoped operator receives. The pattern makes the forbidden shape **unrepresentable** rather than warned about. |
| **URL-safe** | It is a path parameter on `POST /v1/response/holds/{hold_id}/decide`. The class is the unreserved URL set minus `.` and `~`. |
| **Bounded 8–64** | It is also a Nostr tag value and an FTS lexeme inside the 46010's content line — whose `pattern` now pins the same class, so a colon-derived id fails the content grammar as well as the tag. |

`$ref`'d from the hold card (twice), the verdict card (twice), the 26006 frame
and both 46010 tag and content positions; mirrored in Rust as
`tags::is_opaque_hold_id` (hand-written, no `regex` dependency — this crate is
depended on by the bridge, which sits below the TCB, and the assert must be
readable by a reviewer who will not open a regex engine) and in TypeScript as
`zod.ts`'s `holdId`. 12-BACKEND-BILL-API commits B1 to a UUID and the canonical
demo fixture derives `h_a07aeacf`; **both satisfy the pattern**, which is the
wire's floor and not a licence to mint a seventh format.

### 3.3 `p` appears exactly twice in the whole registry

On `kind:46010` and on `kind:26006`. Nowhere else, and both exclusions are
deliberate:

- **Not on the hold card.** A `p` tag creates `event_mentions` rows and puts the
  event in the desktop's mentions queue
  (`HOME_MENTION_EVENT_KINDS`), so one hold would occupy two queues.
- **Not on the verdict card.** The natural recipient is the requesting agent —
  and there is no Nostr pubkey to put there. `ActionRequest.requested_by` is an
  Ambush `AgentId` (`AMB crates/swarm-core/src/types.rs:9-13`), and no mapping to
  a Nostr key exists anywhere in `swarm-core/src/config`. The id lives in the body
  instead. `TagSet::assert_publishable` returns `TagError::CardMentions` for a
  `p` tag on `kind:9`.

### 3.4 The `p`-tag assertion is the whole mitigation for a silent failure

`insert_mentions` (`BUZZ crates/buzz-db/src/runtime/mod.rs:41-113`) runs in the
relay process **after** `tx.commit()` (`:943-948`, and identically at
`BUZZ crates/buzz-db/src/store/event.rs:1690-1696`), on a separate pool
transaction, with any failure downgraded to `tracing::warn!`. Before that it
filters any `p` value that is not exactly 64 ASCII-hex characters with a
`tracing::debug!` and lowercases the survivors (`:65-81`).

So a malformed or uppercase pubkey produces a stored event, an `OK true` to the
publisher, and **no row** in `event_mentions` — which `query_needs_action` INNER
JOINs (`BUZZ crates/buzz-db/src/store/feed.rs:183`). A republish is deduplicated
by event id, so the hole is not self-healing. For Buzz a missed mention is a
missed notification; here it is a destructive action awaiting a human nobody
showed it to.

`TagSet::assert_publishable` runs `is_relay_pubkey` over every `p` value **before
signing** and a failure is a bridge error, never a published event. Two Rust
tests pin it (`an_uppercase_pubkey_is_refused_before_signing`,
`a_truncated_pubkey_is_refused_before_signing`) and the golden suites assert the
vector's own tags.

The operator_id → npub map itself is an **unsigned trust root the whole
hold-delivery path depends on**, and it is not this artifact's to fix.
`OperatorPrincipalConfig` is `{operator_id, token_env, token_expires_at_ms?,
scopes}` with `#[serde(deny_unknown_fields)]`
(`AMB crates/swarm-core/src/config/operator.rs:116-129`), so adding
`nostr_pubkey` is a typed field addition and a bill item nobody has budgeted.

### 3.5 Two operators, one hold — the case nothing in the set handled

`APPENDIX` §4 layer 1 `p`-tags **every** `OperatorScope::Approve` principal, and
§13's declined-amendment note confirms the watch claim does not narrow it. So two
consoles can legitimately be looking at the same open hold, and both can press
the grant control.

What happens is fully determined and, until this revision, half-recorded:

1. Console A publishes its signed leg-1 `swarm:verdict:v1` card to the case
   channel. Console B publishes its own, a tick later. **Both are now permanent.**
   The relay has no compare-and-set, `kind:9` is immutable, and both cards are
   signed by real operators with real Ed25519 keys.
2. Both POST leg 2. `12-BACKEND-BILL-API` §4.4 resolves the daemon side: the
   compare-and-set into `deciding` admits one and the other gets
   `409 hold_already_deciding` or `409 hold_already_decided`.
3. **And then nothing.** The case channel holds two unqualified human-decision
   records for one hold; `leg2.state`'s enum was
   `sending | recorded | acknowledged | refused_late` with no value meaning
   *another operator's decision was the one that executed*; and the Ledger
   export's `holds/` directory would carry both as human intent records. A grep
   for `two operators` or `concurrent` across `build/` found one unrelated
   sort-order remark.

Three things close it, and they are wire-level, which is why they are here.

**(a) A fifth `leg2.state`: `superseded`.** Carrying `superseded_by` — the
**winning leg-1 card's Nostr event id**, which the losing console reads out of
the 409 body — and `superseded_at_ms`, its own clock at the 409, because it never
observes the winner's `decided_at_ms`. Both are **required non-null on that state
and required null on every other**, asserted three ways: a JSON Schema `oneOf`,
`Leg2State::assert_superseded_shape`, and a `z.discriminatedUnion` branch. A
`superseded` card with no winner is a dead end for the reconciler; a `recorded`
card carrying one asserts something the console cannot have observed.

`nostr_intent_event_id` is available for this only because 12-BACKEND-BILL-API
made it `POST /decide`'s idempotency key. The 409 body names the decision that
won, and the decision that won *is* a leg-1 card id.

**(b) It has to be the losing CONSOLE that publishes it.** The daemon never saw
the losing leg-1 card — it is a relay object the daemon does not read, by
construction (ADR 0012). The bridge did not produce it either. Only the console
holds both its own card's event id and the 409 body. That is a real weakness and
it is stated rather than hidden: **an operator who closes the window before the
409 arrives leaves an unqualified human-decision record**, and no retry will fix
it because the console that owed the update card is gone.

**(c) So the render rule does not depend on the publish rule.** This is what
makes (b) survivable:

> A verdict card whose `hold_id` has **no matching decision record** at
> `GET /v1/response/holds/{id}` — or whose matching record names a different
> `nostr_intent_event_id` — renders as **not the decision**, whatever its `leg2`
> says or does not say.

That is layer 3 of the hold path doing the job it already does for INV-35, on one
more input. It is proposed as a **P0 invariant beside INV-12 and INV-35**, with a
two-console E2E: two authenticated principals, both `p`-tagged, both publish leg
1, one 409s, and the assertion is that the case timeline renders exactly one
decision and one superseded intent record — never two decisions, and never a
silent drop of the loser's signed card, which is evidence and must not vanish.

**Not in scope here, and named so nobody assumes it is handled:** the daemon's
409 taxonomy, the `deciding` state's crash behaviour, and the `Retry-After` are
12-BACKEND-BILL-API's; the two-console fixture is 16-INVARIANT-TESTS'; the queue
row's rendering of a superseded card is 17-COMPONENT-SPECS'. This artifact owns
the value on the wire and the reconciliation rule that makes the value optional.

---

## 4. The ephemeral block `26000`–`26006`

### 4.1 Why it needs zero relay change, and the two ceilings

`handle_event` short-circuits every 20000–29999 kind into
`handle_ephemeral_event` and **returns** at
`BUZZ crates/buzz-relay/src/handlers/event.rs:751`, before `ingest_event` is
reached at `:761`. So `required_scope_for_kind` never sees a `26xxx` — proved
in-tree by `ephemeral_kinds_not_in_scope_allowlist`
(`BUZZ crates/buzz-relay/src/handlers/ingest.rs:3851-3854`).

`POST /events` has no such branch (`BUZZ crates/buzz-relay/src/api/bridge.rs:925`
goes straight into `ingest_event`), so the block is **WebSocket-only** and the
bridge must hold a live socket.

Two ceilings, and the tighter one is not the message quota:

| Ceiling | Value | Where |
|---|---|---|
| **WS frame budget** | **50 frames per rolling 5 s per pubkey**, charged on EVERY inbound `EVENT`, `REQ` **and** `COUNT`, **no agent exemption** | `connection.rs:671-681` → `admission.rs:40-45`, `WS_BURST_WINDOW_SECS = 5` at `:9`, `human_ws_events_per_sec = 10` |
| Message quota | 120/min for an owner-attested key, **60/min for a human** | `connection.rs:690-695`, `is_agent = ctx.agent_owner_pubkey.is_some()` at `:665` |

Seven 1 Hz streams are 35 of 50, leaving 15 for un-shed alarms **and REQ frames**.
A pre-coalescing 10 Hz `26001` is 50 by itself. `frames.rs`'s
`seven_one_hz_streams_fit_the_ws_frame_budget` encodes both numbers.

The operator publishing verdict cards is on the **60/min human** tier, not the
120. No plan document budgets REQ frames against the 50, and a reconnect storm
that opens one REQ per case channel can exhaust the window before a frame is
sent — recorded here because it lands on the bridge's design, not this one's.

### 4.2 What each frame narrows, and why

| Kind | Source | Dropped, and why | Cadence |
|---|---|---|---|
| `26000` | `RuntimeEvent::Ingest` | **everything per-event**: `correlation_id`, `event_id`, `source`, `host_id`, `reason`. `host_id` alone fails the aggregates-only rule, and at 3,645 events/second one frame per event is not a design | 1 Hz counts |
| `26001` | `ConcentrationSnapshot` | cadence only — coalesced 10 Hz → 1 Hz **in the bridge, before IPC** | 1 Hz, last-wins |
| `26002` | `AgentHealth` + `AgentAction` | `AgentAction.hunt_id` (a telemetry event id, a join key) and `AgentAction.details` (unbounded agent JSON). Only the `{action_kind: count}` tally survives | on change |
| `26003` | `ModeTransition` | nothing | on change |
| `26004` | `GovernanceStatusReport` | nothing — **all eight fields** (§9, W-7) | 1 Hz or on change |
| `26005` | `TamperAlert` | `unexpected_library_loads` (host paths) → a count plus a sha256; `details` (free-form) dropped | on event |
| `26006` | `ResponseHeld` (B1) | nothing | on event, **never coalesced, never shed** |

Each narrowing is named at its field in `frames.rs`, and `classify()` in
`narrowing.rs` is an **exhaustive match with no `_` arm** over all eleven
`RuntimeEvent` variants — so B1's twelfth variant is a compile error in the
bridge rather than a fact nobody publishes.

Three variants are **dropped at source** with a reason on the arm:
`ResponseExecution` (the receipt card carries the `AuditTrail`, which is the same
fact with the policy record attached — publishing both puts two rows in a case
timeline for one execution), `Replay` (demo mode only, gated behind
`demo_mode_enabled()`), and `EvolutionStatus` (no Perch surface; one would need
an eighth marker).

Two variants have **two destinations**, and both splits are the disclosure
boundary:

- `ModeTransition` → the `26003` frame in **both directions**, and a durable
  `swarm:escalation:v1` card **only into `incident`**. A lane channel that fills
  with "back to normal" rows teaches an operator to scroll past it. The frame
  still carries de-escalation, because `transition_down`
  (`AMB crates/swarm-core/src/agent.rs:148-155`) exists beside `transition_to`
  (`:137-146`) and a band that can only ever appear is one an operator learns to
  ignore.
- `TamperAlert` → the `26005` frame with a **count and a hash**; a durable card
  with the **paths and the detail string** when `fail_closed`. The
  aggregates-only rule is scoped to the community-global block; a lane channel is
  membership-gated, and an operator investigating a tamper alert needs the paths.
  The sha256 over the sorted path list is on **both**, so the two can be joined
  without the frame disclosing anything.

### 4.3 The two rules, and where they bite

**Aggregates-only.** `handle_ephemeral_event`'s channel-less branch publishes to
Redis `EventTopic::Global` under a `Uuid::nil()` routing sentinel and fans out
with `channel_id = None` (`BUZZ crates/buzz-relay/src/handlers/event.rs:875-903`),
and `filter_fanout_by_access` returns **every** match at `:177-179` for a
channel-less event after applying only the receiver tenant label,
`AUTHOR_ONLY_KINDS` and `SHARED_GATED_KINDS`. No host id, no indicator, no
finding id, no library path, no non-opaque join key.

Mechanised: both golden suites walk every frame vector for nine banned key names
(`host_id`, `unexpected_library_loads`, `details`, `evidence`, `finding_id`,
`event_id`, `hunt_id`, `correlation_id`, `indicator`) and assert zero hits. Run
this session: **0 violations across all seven frame vectors.**

**Admitted issuer.** The ephemeral ingest gate is a single scope test with **no
per-kind allowlist** — `if !scopes.is_empty() && !scopes.contains(&Scope::MessagesWrite)`
(`event.rs:699-707`) — and an empty scope set passes outright. So every
chat-capable member of the community can publish a `26xxx`. Without the rule, a
member can page the rotation with a fabricated `26003`, paint the Watchfloor with
a fabricated `26001`/`26002`, or put a phantom row in every queue with a
fabricated `26006`. `admitCard`/`admitFrame` check the **event's** signer, never
`Frame.issuer`, which is inside content an adversary controls.

### 4.4 `26006`: the `h` tag is WITHDRAWN, and `P_GATED_KINDS` is the answer

**The hole is real and this section does not soften it.** For a channel-less
ephemeral, `filter_fanout_by_access`
(`BUZZ crates/buzz-relay/src/handlers/event.rs:115-222`) applies only the
receiver tenant label, `AUTHOR_ONLY_KINDS` and `SHARED_GATED_KINDS` and then
`return matches` at `:177-179`. Without a further gate, **any authenticated
community member who opens `REQ ["…", {"kinds":[26006]}]` receives every hold
alarm** — `hold_id`, `action_kind`, `severity`, `case_channel`, `expires_at_ms` —
including alarms `p`-tagged to other operators. The `p` tags are a client-side
paging hint; the admitted-issuer rule is a client render rule. Neither stops a
third party reading the frames off the wire.

**The previous revision of this file chose an `h` tag naming the standing
`#watch` ops channel (amendment W-1). That was wrong, and it was wrong in the
direction that matters.** I went back to the source with the question "what would
still pass?" and the answer is: everyone in `#watch`.

`p_gated_filters_authorized` — the gate that would make a `p` tag mean something
— is **scoped to global subscriptions only**:

```rust
// crates/buzz-relay/src/handlers/req.rs:215-226
// Only applies to GLOBAL subscriptions (channel_id = None):
// channel-scoped subs can never receive globally-stored events because of
// the fan_out() invariant in subscription.rs.
if channel_id.is_none() {
    let authed_pubkey_hex = hex::encode(&pubkey_bytes);
    if !p_gated_filters_authorized(&filters, &authed_pubkey_hex) {
        conn.send(RelayMessage::closed(
            &sub_id,
            "restricted: p-gated events require #p matching your pubkey",
        ));
        return;
    }
```

So an `h`-tagged `26006` is delivered through the channel index — `fan_out_scoped`
routes it there and the symmetric invariant is stated in the source at
`BUZZ crates/buzz-relay/src/subscription.rs:487-492` — **where the gate is never
consulted**. Any `#watch` member opening `{kinds:[26006],"#h":[watch]}` reads
every operator's alarms. W-1 narrows the disclosure ring from the community to
the ops channel. It does not close it, and it reads as if it does.

It has a second consequence the previous revision did not cost. The only shipped
client implementation writes a **global** filter —
`{ kinds: [26006], "#p": [myPubkey], limit: 0 }`
(`skeleton/desktop/src/shared/api/perchSubscriptions.ts:167-168`, whose own
comment cites the `subscription.rs` invariant) — and under W-1 that REQ delivers
**zero frames with nothing failing loudly**, while APPENDIX §4's ≤400 ms budget
rides this frame. A silent zero on the only live path to a hold is the worst
available outcome.

**The four options, re-costed:**

| | Cost |
|---|---|
| (a) accept it | An operator queue's contents become community-readable. `26006` is the one frame naming a case channel and a destructive action kind. **Rejected.** |
| (b) `h` = the **case channel** | Membership-gated, but the operator has not joined a case they have never seen, so the alarm reaches nobody. **Rejected — it does not work.** |
| (c) `h` = the standing `#watch` channel (**the withdrawn W-1**) | Routes the frame past the only gate that would compartment it, and delivers zero to the shipped global filter. **Rejected on evidence.** |
| **(d) add `26006` to `P_GATED_KINDS`** | **Chosen.** One line in `buzz-core`. |

**What (d) actually does.** `P_GATED_KINDS`
(`BUZZ crates/buzz-core/src/kind.rs:159-169`) already carries
`KIND_AGENT_OBSERVER_FRAME` — **an ephemeral**, included for exactly this
filter-layer enforcement, and the doc comment at `:156-158` says so: *"Ephemeral
kinds (20000–29999 …) are included for filter-layer enforcement but are never
stored, so the storage-layer search defense does not apply to them."* So there is
an in-tree precedent for the exact move, on the exact kind range.

With `26006` in that array, `p_gated_filters_authorized` (`req.rs:1182-1215`)
requires every filter that names it to carry a `#p` **whose values are all the
reader's own pubkey** (`:1211-1213`) and CLOSEs the subscription otherwise. A
member cannot subscribe to another operator's alarms at all. The `p` tags stop
being a paging hint and become the relay's own authorization test — which is why
`TagSet::assert_publishable` now returns `NoRecipients` for a `p`-less `26006`: a
frame with no `p` tag matches no admitted filter and reaches nobody.

The `ids` exemption at `:1204-1210` does not open a side door here: an ephemeral
is never stored, so an `ids` lookup returns nothing from the store, and a live
match would require knowing an event id before the event exists.

**Cost, stated plainly.** This is a **third fork site**, in `buzz-core` rather
than `buzz-relay/src/handlers/ingest.rs`. The correct framing everywhere is
therefore *"three hunks in `buzz-relay/src/handlers/ingest.rs` and one line in
`buzz-core/src/kind.rs`; zero client registration points"* — which is exactly
brief amendment **AD-A7**, already filed by the ADR set. This artifact is not
proposing a new mechanism; it is **withdrawing its own competing one** and
binding to the ratified one.

**What does not change.** APPENDIX §3's "global (no `h`)" stands. The Watch's
live REQ stays `{kinds:[26006],"#p":[me]}`. The Watchfloor opens **one** global
REQ for `26000`–`26006`, not two. `perchSubscriptions.ts` needs no edit. The
standing `#watch` ops channel from `04` §2.11 still exists for its other
purposes; it is simply not the alarm's delivery mechanism.

Recorded as **W-9** (§9), which supersedes and withdraws **W-1**.

---

## 5. Tags: the closed budget and its query consequences

### 5.1 Per card

| | `h` | `e` | `p` | `t` | `l` | `k` | `broadcast` |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| `finding` | lane channel | — | — | ✓ | ✓ | `finding` | — |
| `escalation` | lane channel | — | — | ✓ | ✓ | `escalation` | `"1"` iff mode→incident |
| `hold` (open) | case | finding card | — | ✓ | ✓ | `hold` | — |
| `hold` (terminal) | case | the open card | — | ✓ | ✓ | `hold` | — |
| `verdict` | case | the open hold card | — | ✓ | ✓ | `verdict` | — |
| `receipt` | case | the verdict card | — | ✓ | ✓ | `receipt` | — |
| `lease` | case | the receipt card | — | ✓ | ✓ | `lease` | — |
| `rollback` | case | the lease card | — | ✓ | ✓ | `rollback` | — |
| **46010** | case | **forbidden** | ✓ | **forbidden** | **forbidden** | **forbidden** | — |
| `26006` | **none** | — | ✓ | — | — | — | — |

`t` is the threat-class slug; a `ThreatClass::Custom` becomes the literal
`custom`, with the class name in the body. That is APPENDIX §3's ruling and the
only one of the three in-tree conventions that keeps an operator-supplied string
out of an indexed tag — `threat_class_name`
(`AMB crates/swarm-runtime/src/escalation.rs:389-405`) returns the raw name and
the NATS subject builder (`AMB crates/swarm-pheromone/src/jetstream.rs:1190`)
returns `custom_{sanitized}`, while
`AMB crates/swarm-runtime/src/sphinx_agent.rs:1799` returns the literal
`"custom"` and is the one the appendix matches.

`l` is `Severity` in **SCREAMING_SNAKE**
(`AMB crates/swarm-core/src/types.rs:406-414`) — the only enum in the Ambush
workspace with `rename_all = "SCREAMING_SNAKE_CASE"` while ~40 siblings are
`snake_case`.

`broadcast` is not single-letter; it is Buzz's own, with a stored boolean column
(`BUZZ crates/buzz-db/src/store/thread.rs:489`) and the predicate
`tags.some((tag) => tag[0] === "broadcast" && tag[1] === "1")`
(`BUZZ desktop/src/features/messages/lib/threading.ts:17`).

### 5.2 SQL-pushed vs post-filtered, read arm by arm

`filter_fully_pushable` (`BUZZ crates/buzz-relay/src/handlers/req.rs:851-895`)
runs in the relay process and decides whether a filter can use the fast COUNT
path:

| tag | pushed? | line |
|---|---|---|
| `h` | yes — the caller has already put the complete authorized set through `EventQuery::channel_id`/`channel_ids` | `:863-866` |
| `p` | **a single value only**; two or more return `false` | `:867-873` |
| `e` | yes, any count, JSONB containment | `:882-884` |
| `d` | only when **every** kind in the filter is NIP-33 | `:874-881` |
| `t`, `l`, `k`, `broadcast`, `hold`, `card` | **no** — the default arm, which names `#t` and `#a` | `:885-890` |
| a NIP-50 `search` filter | **no** | `:892-895` |

`EventQuery` has no generic tag field beyond `custom_tag: Option<(String,String)>`
— **one pair** (`BUZZ crates/buzz-db/src/store/event.rs:81-83`).

**Two binding consequences:**

1. **Paging depth must be sized for dilution.** A REQ of
   `{kinds:[9], "#h":[case], "#k":["receipt"]}` fetches a page of *all* `kind:9`
   in the case and drops non-matching rows afterwards; a `limit:200` on a busy
   case can return a handful of receipts. **Where per-card-type selection
   matters, fetch one page of `{kinds:[9], "#h":[case]}` and partition
   client-side on the parsed marker.**
2. **Such a filter disqualifies the fast COUNT path**, so the Ledger's result
   count is an estimate over a page and the copy says so.

`t`, `l` and `k` are **display and post-filter hints**. No document may describe
them as indexed selection. `pushdownClass()` in `ts/tags.ts` is the machine-
readable form of this table.

### 5.3 The permanent cost, named

`strategy_id`, `host_id`, `receipt_id`, `lease_id` and `hunt_id` are reachable
through **NIP-50 FTS only**, never as a `#filter`. The events are signed and
cannot be re-tagged.

FTS does reach them, and that is the second reason the fenced JSON earns its
bytes: `search_tsv` is `to_tsvector('simple', content)` and the privacy `CASE` at
`BUZZ schema/schema.sql:223-227` nulls it only for kinds
`{1059, 30179, 30300, 30350, 30622, 44100, 44101, 44200}` — neither `9` nor
`46010`. Every join key in a card body is searchable, in the fence, without a
tag.

---

## 6. Verification tier, per card type, with the reason

The taxonomy is `08` §6.2's and this artifact does not redefine it: **tier 0** is
a secp256k1 Nostr signature over the transport event and nothing over the body;
**tier 1** is a detached Ed25519 signature over the body; **tier 2** is a
`build_signed_envelope` wrapper with `seq` and `prev_envelope_hash` — a signature
**and** a chain.

| Card | Tier today | Why, in one sentence |
|---|:-:|---|
| `finding` | **0** | `DetectionFinding` (`AMB crates/swarm-whisker/src/detector.rs:50-59`, seven fields) and `SwarmFindingEnvelope` (`AMB crates/swarm-response/src/siem.rs:17-27`, eight fields) both carry no signature field at all. |
| `escalation` | **0** | Three `RuntimeEvent` variants, none signed; they exist only on an in-process `tokio::sync::broadcast` channel. |
| `hold` | **0** | The `HeldActionStore` record is B1's, and B1 does not sign. A `governance_receipt` may ride inside `action_request.evidence`; that is a separate object with its own badge, never the card's. |
| `verdict` | **1** | The operator's own `DetachedSignature` over `{decided_at_ms, decision, hold_id}` is **in the body**. See below. |
| `receipt` | **0**, or **1 scoped** | `AuditTrail` (`AMB crates/swarm-spine/src/lib.rs:112-122`) is unsigned. `audit_trail.response.audit.governance.receipt` is an untyped `Option<serde_json::Value>` (`AMB crates/swarm-response/src/lib.rs:139-141`) that may hold a `ConsensusGovernanceReceipt`, which **is** tier 1 — the badge scopes to that nested object and the receipt around it stays tier 0. |
| `lease` | **0** | A `ContainmentLease` carries no signature; `governance_receipt_id` is an **id**, and resolving an id is not a verification. |
| `rollback` | **0**, or **1 when attested** | `governance_attestation` (`AMB crates/swarm-response/src/rollback.rs:263-285`) is a serialized `ConsensusGovernanceReceipt` over this receipt's canonical form **with that field cleared**, and `verify_release_attestation` (`AMB crates/swarm-runtime/src/containment.rs:235-269`) checks the signature **and** the subject binding — and is actually called, at `AMB crates/swarm-runtime-http/src/http/containment.rs:219-222`. |

Nothing is tier 2 before B6, by construction: `signature` is absent from every
card, and `envelopeTier()` returns `0` whenever it is.

**A tier is not a verdict about what happened.** A `superseded` verdict card
(§3.5) is **tier 1** — it carries a real Ed25519 signature by a real operator
over a real preimage, and every check on it passes. It is also *not the decision*:
another operator's card was the one the daemon executed. The two facts are
orthogonal and a surface that collapses them renders two decisions for one hold.
`leg2.state` and the daemon reconciliation carry "did this execute"; the tier
carries only "can this signature be checked". This is the same separation `08`
§6.2 draws when it says `attestation_verified: true` is not a trust anchor, one
level down.

**Two things a verification surface must say beside a tier-1 badge.**
`UNATTESTED` does not mean "misconfigured": under a partition contingency it is
`UNATTESTED — BY DESIGN`, which is why the rollback card carries
`partition_state_at_execution` and why a `null` there must render as *"the
console could not establish it"* rather than as healthy (INV-08). And
`attestation_verified: true` is not a trust anchor — `08` §6.2 quotes ADR
0010:125-131 on that, and INV-25 requires the badge to name the chain
(`Ed25519`) and the tier, never a shield.

**The one place this artifact corrects the tier table.** `08` §6.2 files
`swarm:verdict:v1` as tier 0 "until B1.6" (= **B2o**). That is one step too
conservative: B2o is what puts the operator on the **receipt**. The operator's
`DetachedSignature` is produced by the console for **leg 2** regardless of B2o,
so the card carries it from the first day leg 2 exists. Recorded as **W-4**.

---

## 7. The human fallback line, per card

### 7.1 The seven grammars

One line, no markdown, fields separated by ` · ` (U+00B7 with a space either
side — not a hyphen, because a hyphen is a lexeme boundary in Postgres's `simple`
configuration, so `web-04` already contributes `web` and `04`).

| Card | Grammar |
|---|---|
| `finding` | `{Agent}-{short} · {threat_class} · {SEVERITY} · confidence {0.00} · host {host_id\|unknown} · finding {finding_id}` |
| `escalation` (crossing) | `{threat_class} · {LEVEL} · strength {0.00} · {n} sources / {m} agents · mode {mode}` when `source_ids` is present; `{n} sources / agents not yet resolved` when it is not (§7.2) |
| `escalation` (mode) | `mode {from} → incident · {triggering_threat_class\|none} · {reason}` |
| `escalation` (tamper) | `tamper fail-closed · {n} unexpected library loads · debugger {attached\|not attached}` |
| `hold` | `hold {hold_id} · {action_kind} · {SEVERITY} · {scope_kind} {scope_value} · expires {ISO-8601 with offset}` |
| `verdict` | `{grant\|refuse} · hold {hold_id} · by {operator_id} · {ISO-8601 with offset}` |
| `receipt` | `receipt {receipt_id\|none} · {action} · {status} · {mode} · trail {trail_id}` |
| `lease` | `containment lease {lease_id} · {action_kind} · issued {ISO} · expires {ISO} · origin receipt {receipt_id}` |
| `rollback` | `rollback {rollback_id} · containment lease {lease_id} · {trigger} · {status} · {k} of {n} steps reversed` |

Voice law L5 — every number carries its denominator and its unit — is why it is
`{k} of {n} steps reversed` and not `{k} reversed`, and why confidence carries
two decimals **and** the word.

### 7.2 Render law 2 stands. This file had it backwards, and the const was the damage.

**The previous revision of this artifact was wrong about the counting mechanism,
and because it owns the schemas the wrong reading was compiled into a
`const`, a single-variant Rust enum, a `z.literal`, a golden vector and a pinned
hash.** Six peer producers read the same source and got it right; two — this one
and the component sheet — traced only as far as `whisker_agent.rs:148-149` and
stopped one call short. A prose disagreement would have been cheap. A `const` in
the admission path is not: a bridge publishing the *truthful* value would have
been rejected at `admitCard`, and `fixtures/wire/card-04-escalation-execution-alert.json`
— which carries the truthful value — failed against the schema. That is the
`oneOf` branch going unselectable on a correct card.

**The mechanism, hop by hop, all inside `swarm_detect --serve`:**

1. `WhiskerAgent::tick` builds a base id
   `AgentId(format!("{}:{}", derived_identity.0, self.id.0))`
   (`AMB crates/swarm-agents/src/whisker_agent.rs:148-149`) — **already
   instance-scoped, two segments** — and hands it to
   `detect_and_deposit_with_role` at `:150-156`. *This is where the previous
   reading stopped.*
2. `detect_and_deposit_with_role`
   (`AMB crates/swarm-runtime/src/detection/pipeline.rs:60-91`) calls
   `resolve_deposits` at `:80`.
3. `resolve_deposits` — the `pub(crate)` fn at `:543-580` — writes, on **every**
   deposit it builds, `agent_id: strategy_scoped_agent_id(agent_id, &finding.strategy_id)`
   (`pipeline.rs:573`). **A third segment, per detector.**
4. `strategy_scoped_agent_id` is `AgentId(format!("{}:{strategy_id}", base.0))`
   (`AMB crates/swarm-whisker/src/stream.rs:20-22`).
5. `concentration_for`, on each monitor tick, does
   `sources.insert(deposit.agent_id.0.clone())`
   (`AMB crates/swarm-pheromone/src/substrate.rs:1295`) and reports
   `sources.len()` at `:1301`.

So one Whisker running two detectors is **two sources**, and it clears
`min_sources_for_escalation: 2` on its own. The workspace asserts this itself, in
a test whose name is the whole answer:
`query_counts_strategy_scoped_agent_ids_as_distinct_sources`
(`AMB crates/swarm-pheromone/src/substrate.rs:2105`).

**Why it was misread, recorded so it is not misread a third time.**
`PheromoneConcentration`'s own doc comments are wrong about the unit:
`AMB crates/swarm-core/src/pheromone.rs:323` says *"Sum of effective strengths
from distinct agents"* and `:325` says *"Number of distinct agents
contributing"*. A reader who trusts the doc comment on the type gets the wrong
answer; the deposit path is the only place that decides it. Both the schema's
`$defs/SourceCountMechanism` and the Rust enum's doc comment now carry that
warning at the point of use.

**APPENDIX §8 render law 2 therefore stands exactly as written.**
`N sources / M agents` is two genuinely different numbers, and the expansion does
not collapse. Amendment **W-6** (`{n} distinct agent instances`, "the two numbers
are always equal") is **WITHDRAWN**; so is 17-COMPONENT-SPECS' proposed APPENDIX
§8 amendment built on the same misread. The copy gate's `bare-source-count`
replacement text — "Always `N sources / M agents`" — was right all along.

**What changed on the wire:**

| Field | Was | Is |
|---|---|---|
| `distinct_sources_counts` | `const: "agent_instance_id"` | `$ref` to `common.schema.json#/$defs/SourceCountMechanism`, `const: "strategy_scoped_agent_id"` |
| `SourceCountMechanism` (Rust) | one variant, `AgentInstanceId` | one variant, `StrategyScopedAgentId` |
| `zod.ts` | `z.literal("agent_instance_id")` | `z.literal("strategy_scoped_agent_id")` |
| `common.schema.json` `x-note` | claimed `distinct_sources == 1` for four detectors on one Whisker | states the four-hop path and the wrong upstream doc comment |
| golden vector | `agent_instance_id` | `strategy_scoped_agent_id`, re-pinned |

Still exactly one enum variant. A closed single-variant enum makes the wrong
mechanism unrepresentable; a second counting unit would be a wire change with its
own argument, not a value a producer picks.

### 7.2.1 The `M agents` half has no Phase-1 data source, and the wire says so

Render law 2 has two halves and the wire can only serve one of them today. This
is a real gap and it is now a **named state** rather than a `null` every consumer
interprets differently.

`RuntimeEvent::Escalation` carries seven scalars and **no ids**
(`AMB crates/swarm-runtime/src/runtime_events.rs:288-296`). Its input
`RuntimeThreatConcentration` is four scalars (`:193-197`, built
`From<&PheromoneConcentration>` at `:199-207`). And the bridge cannot resolve them
either: it takes a `broadcast::Receiver` and holds no substrate handle, by
11-BRIDGE-CRATE's own decision 6. Only **B4**
(`GET /v1/operator/pheromone/deposits`) can serve the ids, and B4 is Phase 2 in
APPENDIX §5.

So the escalation card carries **two** fields where it carried one:

```jsonc
"source_ids": null,
"source_ids_absent_reason": "not_carried_by_runtime_event"
```

with **exactly one of them null**, enforced three ways — a JSON Schema `allOf`
`oneOf`, a `.refine()` on `escalationFact`, and a required `Option` field in
Rust. Both-null and both-populated are decode errors. Two of the 25 mutation
cases are exactly those.

The point of the second field is that an absence with a name is something a
screen can **say**, and an absence without one is something a component
improvises around — by fabricating a number, or by spinning on data that is never
coming. 18-DATAVIZ's CR-5 forbids a `sources: number` prop and 17-COMPONENT-SPECS
declares `sourceIds: readonly string[]` non-optional; neither can be fed in
Phase 1, and this is the shape that lets both be built honestly:
`sourceIds: string[] | null` plus the reason.

**Post-B4** the derivation is one line and it is correct *only* under the
strategy-scoped mechanism, which is why the mechanism travels beside the ids:

```ts
const agents = new Set(sourceIds.map((id) => id.split(":").slice(0, -1).join(":")));
// M = agents.size, N = sourceIds.length
```

That is 18-DATAVIZ's derivation, unchanged, and it is now the one this file
agrees with.

**Handoff, explicitly.** The Phase-1 human-line grammar for an escalation is
`{n} sources / agents not yet resolved`. It satisfies render law 2's substance —
the count is never bare and the second number is never fabricated — but the copy
gate's `bare-source-count` row must admit a non-numeric agent clause, or 06's
owner must supply a different string that does. That is 16-INVARIANT-TESTS'
`copy-ban-list.tsv` to decide; this file names the requirement rather than
assuming a regex.

## 8. Degradation, verified

The plan set claims honest degradation "for free". Three of the four surfaces
hold; one claim is false and one is unverified.

### 8.1 Desktop — the fallback path, verified

A card that fails admission falls through `MessageRow`'s `default:` arm to
`VideoReviewCommentMarkdown` (`MessageRow.tsx:429`), which is `react-markdown`
`^10.1.0` with `remark-gfm` and `remark-breaks` and **no `rehype-raw`**
(`BUZZ desktop/package.json:78-80`; `grep -n 'rehype' desktop/src/shared/ui/markdown.tsx`
returns nothing). react-markdown does not render raw HTML by default, so the
marker comment is **dropped entirely** and the operator sees the human line
followed by a fenced code block. That is the correct untrusted-prose rendering
INV-15 asks for, and it costs nothing.

### 8.2 Mobile Flutter — reachable, and partly unverified

`kind:9` is in `EventKind.channelTimelineContentKinds`
(`BUZZ mobile/lib/shared/relay/nostr_models.dart:85-98`), so marker cards **do**
reach a mobile case-channel timeline and render through `MessageContent`
(`mobile/lib/features/channels/message_content.dart`, `GptMarkdown`).

`kind:46010` is **not** in that list, so a hold notice does not appear in a mobile
channel timeline — but it **does** reach the mobile Activity feed, which
subscribes to `kinds: [46010, 46011, 46012]`
(`mobile/lib/features/activity/activity_provider.dart:476`) and renders
`displayContent` = `content.trim()`, raw
(`mobile/lib/features/activity/feed_item.dart:84-89`). That is exactly why §3.1
makes the 46010's content a readable sentence.

**Unverified:** whether `gpt_markdown ^1.1.6` (`mobile/pubspec.yaml:30`) renders
an HTML comment as literal text or drops it. The package is not in this
machine's pub cache and `flutter pub get` was not run. Both outcomes are
acceptable — the human line is line 1 either way — but the answer changes one
line of copy. **The test that settles it**, as a mobile widget test under
`mobile/test/`:

```dart
testWidgets('an ambush marker line is not rendered as body text', (tester) async {
  await tester.pumpWidget(WidgetHelpers.testable(
    MessageContent(content: '<!-- swarm:hold:v1 -->\nhold h_1 · isolate_host', ...),
  ));
  expect(find.textContaining('swarm:hold:v1'), findsNothing);
});
```

### 8.3 Web client — the claim is FALSE, and harmlessly so

**`BUZZ web/` has no message renderer at all.** It is a repo browser and an
invite page: 49 files under `web/src`, of which the feature directories are
`features/repos/` (17 files) and `features/invite/` (3). There is no channel
view, no timeline, no `kind:9` handling; the only `channel` reference is a
`channelId: null` field on a repo fixture (`web/src/features/repos/mock-repos.ts:26`)
and the only `message` reference is `ws.addEventListener("message", …)`
(`web/src/shared/lib/nostr-client.ts:80`).

So the degradation story for `web/` is not "renders honestly" but **"is not
reachable"**. No Perch card can appear there. That is fine, and it is better
stated than assumed — a producer who budgets a web renderer is budgeting a file
that does not exist. Recorded as **W-3**.

### 8.4 CLI — verified, with two real limits

`buzz --format compact messages thread` projects every event to **exactly
`{id, content, created_at}`**, dropping `kind`, `pubkey`, `tags` and `sig`
(`BUZZ crates/buzz-cli/src/commands/messages.rs:335-354`, pinned by the test
`compact_event_format_remains_the_three_key_contract` at `:1082-1106`). Two
consequences:

1. **The human line is the entire card in compact mode.** Nothing is stripped —
   the marker, the human line and the whole fenced JSON all arrive in `content` —
   so the human line's job is to be the first readable thing, which the ordering
   in §1.2 gives it.
2. **The CLI cannot apply either admission clause.** No `kind`, so it cannot tell
   a 46010 from a `kind:9`; no `pubkey`, so it cannot check the issuer. Default
   (`--format json`) output keeps the seven canonical signed fields and can do
   both.

Also: `buzz messages list` builds `kinds: [9, 40002, 40008, 45001, 45003]`
(`commands/messages.rs:368-372`) — **46010 is not in the CLI's default set**, so a
hold notice needs an explicit `--kinds 46010`.

### 8.5 Search snippet — verified, and it drove the ordering

`buildSearchResultPreview(content, query, 96)`
(`BUZZ desktop/src/features/search/lib/searchMatch.ts:169-200`), called from
`TopbarSearch.tsx:699`. When the query matches inside the body it centres a
96-character window on the first match with 32 characters of leading context;
when it does not, it returns the first 93 characters plus `...`. Measured on the
real hold line: the marker plus its newline costs **24**, leaving **69**
characters — enough for the hold id, the action kind, the severity and the host —
and the fence starts at character **121**, outside the window. Worst case is the
longest marker: `escalation` costs 30 and leaves 63, which still clears the class
and the level. (An earlier revision said "27, leaving 69", which does not add up
to 93; both numbers are recomputed here against the canonical line.) `golden.test.mjs`'s *"the human line survives
the desktop's 96-character search preview"* asserts all three.

### 8.6 The matrix

| Surface | `kind:9` card | `kind:46010` notice | `26xxx` frame |
|---|---|---|---|
| Perch desktop, admitted | rich card | queue row | live update |
| Perch desktop, unadmitted | human line + fenced JSON, marker dropped | untrusted prose row, never in the queue, never a wake class (INV-15) | counted and dropped, count visible |
| Buzz desktop (unmodified) | same as unadmitted | `"Approval requested"` + the human line (`inbox.ts:165`, `:186`) | not subscribed |
| Mobile Flutter | human line + fence in the case timeline (marker handling §8.2) | Activity feed: `"Approval requested"` + the human line raw | not subscribed |
| Buzz `web/` | **unreachable** — no message renderer exists | unreachable | unreachable |
| `buzz` CLI, `--format json` | whole `content`, plus tags and pubkey | whole `content`, plus tags | not stored, unreachable |
| `buzz` CLI, `--format compact` | whole `content`, no kind/pubkey/tags | same | unreachable |
| NIP-50 FTS snippet | first 96 chars: marker + ~69 of the human line | the whole one-line content (86 chars) | not indexed |

---

## 9. Departures, and the three this artifact WITHDRAWS

Each row is a place this artifact does something the appendix or an owning
document does not say. Each carries the argument; none is silent. **The three
withdrawals come first, because a wrong amendment that got compiled into a
`const` does more damage than a missing one.**

### 9.1 Withdrawn

| # | Was | Withdrawn because |
|---|---|---|
| **W-1** | `26006` carries an `h` tag naming the standing `#watch` ops channel. | `p_gated_filters_authorized` runs **only** for `channel_id.is_none()` (`BUZZ crates/buzz-relay/src/handlers/req.rs:218`, comment at `:215-217`). An `h` tag routes the frame through the channel index, past the only gate that would compartment it, so every `#watch` member reads every operator's alarms — the ring narrows, the hole does not close. It also delivers **zero frames** to the only shipped client filter, which is global, while APPENDIX §4's ≤400 ms budget rides this frame. Superseded by **W-9**. Full argument: §4.4. |
| **W-6** | Render law 2's expansion becomes `{n} distinct agent instances`; the two numbers are always equal. | Factually wrong. `resolve_deposits` writes `strategy_scoped_agent_id(agent_id, &finding.strategy_id)` onto every deposit (`AMB crates/swarm-runtime/src/detection/pipeline.rs:573`) *after* the instance scoping, so `distinct_sources` is per detector and one Whisker with two detectors is two sources. The workspace's own `query_counts_strategy_scoped_agent_ids_as_distinct_sources` (`substrate.rs:2105`) asserts it. **Render law 2 stands as written.** 17-COMPONENT-SPECS' identical proposed amendment should be withdrawn with it. Full argument: §7.2. |
| **W-8** | `FactIssuer.role` on a verdict card is a placeholder no surface may render; filed as a *request* for an `AgentRole`-free issuer. | A placeholder nobody renders is still a value in a signed record, and the placeholder chosen was `tom` — the governance/veto actor (`AMB crates/swarm-core/src/agent.rs:26-27`), the one conflation APPENDIX §7 forbids and `adr/0016` exists to prevent. Superseded by **W-11**, which implements the `AgentRole`-free issuer instead of requesting it. |

### 9.2 Standing

| # | Departure | Against | Argument |
|---|---|---|---|
| **W-2** | **Card bodies are `swarm.spine.envelope.v1` from day one, `signature` absent.** | `03` §3.2's flat sketch | `compute_envelope_hash_hex` and `verify_chain_link` are both keyless and `pub`. Makes B6 additive rather than a `v1`→`v2` bump, and supplies the sequence number `GET /v1/events/stream` does not have. Explicitly does **not** raise the tier. |
| **W-3** | **The `web/` degradation claim is withdrawn.** | `03`'s "honest degradation for free" | `BUZZ web/` has no message renderer; it is a repo browser plus an invite page. Perch cards are unreachable there — a stronger statement than "degrades honestly", and it needs no work. |
| **W-4** | **`swarm:verdict:v1` is tier 1 from day one**, conditional on B2's operator Ed25519 key. | `08` §6.2 ("until B1.6") | The operator's `DetachedSignature` is produced for leg 2 regardless of B2o; B2o is what puts the operator on the **receipt**. |
| **W-5** | **`swarm:receipt:v1` carries `AuditTrail` only.** | APPENDIX §3 | `AuditResponseRecord::Success(ResponseReceipt)` (`AMB crates/swarm-spine/src/lib.rs:103-110`) already embeds the whole receipt; carrying both puts a byte-for-byte duplicate in a card INV-26 then has to reconcile against the daemon's stored body. |
| **W-7** | **`26004` carries all eight `GovernanceStatusReport` fields**, plus `contingency_lease_ttl_ms`. | APPENDIX §3 (six fields) | `last_transition_at_ms` and `last_reconciliation_report_id` are on the type (`AMB crates/swarm-policy/src/governance.rs:62-71`), and the first is the governance strip's staleness clock. The TTL is carried because `06` §2.2's "60-second" figure cites a `#[tokio::test]` fixture; the production default is 300,000 ms. |

### 9.3 New in this revision

| # | Departure | Against | Argument |
|---|---|---|---|
| **W-9** | **`26006` stays global with no `h` tag, and `26006` is added to `P_GATED_KINDS`** in `BUZZ crates/buzz-core/src/kind.rs:159-169`. | nothing — it **binds to** `adr/0017` clause C3 and restores APPENDIX §3 | This is not a new mechanism; it is this artifact abandoning its own competing one. `P_GATED_KINDS` already carries an ephemeral (`KIND_AGENT_OBSERVER_FRAME`) for exactly this filter-layer enforcement, per the doc comment at `:156-158`, so there is an in-tree precedent on the exact kind range. The correct framing everywhere is **AD-A7**'s: "three hunks in `buzz-relay/src/handlers/ingest.rs` and one line in `buzz-core/src/kind.rs`; zero client registration points." §4.4. |
| **W-10** | **`distinct_sources_counts` is `strategy_scoped_agent_id`,** and `SourceCountMechanism`'s only variant is renamed to match. | this file's own previous `const` | See W-6 above. The change is in five places (`card-swarm-escalation-v1.schema.json`, `rust/src/cards.rs`, `ts/types.ts`, `ts/zod.ts`, the golden vector) plus the two `x-note`/`x-source` blocks in `common.schema.json` that carried the wrong tracing. §7.2. |
| **W-11** | **A verdict card's issuer is `OperatorFactIssuer`, whose `role` is `const: null`.** | `08` §6.2's silence; this file's withdrawn W-8 | A human produced the fact. `AgentRole` has no human member, and the value previously in the golden vector was `tom`. A separate type with a `null`-only role makes the conflation a schema error, a `tsc` error and a serde error, in the same shape on all three sides. `NeverARole` is a unit struct so `{"role":"tom"}` fails to deserialize with the same force the schema's `"type": "null"` rejects it. |
| **W-A1** | **`FactIssuer.role` is NULLABLE AND REQUIRED** on every other card. | APPENDIX §3's implicit non-null | Two production paths disagree: `WhiskerAgent::tick` passes `Some(AgentRole::Whisker)` explicitly (`whisker_agent.rs:150-156`), while `infer_agent_role` (`pipeline.rs:583-604`) prefix-matches and returns `None` for every `swarm:ed25519:<hex>` identity the HTTP ingest lane uses. Both shapes are real. Required-but-nullable, never optional: a **missing** key stays a decode error while a genuine absence is an explicit `null`, so a truncated body cannot pass as an unattributed fact. Independently filed by 22-DEMO-FIXTURE as its F-2; this is the same amendment and the two agree. **This one change takes 22-DEMO-FIXTURE's 11 marker-card fixtures from failing to passing.** |
| **W-12** | **`common.schema.json#/$defs/HoldId` pins the hold-id shape**, `$ref`'d from all three card/frame schemas and both 46010 positions. | nothing — it closes an unowned gap | Six formats were in circulation and two used the `hold:` prefix the schema's own prose forbade. §3.2.1. |
| **W-13** | **`leg2.state` gains `superseded`**, carrying the winning `nostr_intent_event_id`, plus a reconciliation rule so a verdict card with no matching daemon record renders as **not the decision**. | nothing — nothing in the set handled two operators deciding one hold | The relay has no compare-and-set and `kind:9` is immutable, so both signed cards are permanent. Proposed as a **P0 invariant beside INV-12 and INV-35**, with a two-console E2E. §3.5. |
| **W-14** | **The 46010's tag set is enumerated in the schema**, so `t`/`l`/`k` fail validation. | this file's own previous schema, whose prose said "exactly four" while `items` was open | The Rust producer already refused them; the schema admitted them; a fixture shipped seven tags and a validator called it `ok`. §3.2. |

### Corrections inherited and applied

Applied rather than re-litigated: the containment lease TTL is 900,000 ms and not
the 60,000 ms `policy.lease_ttl_ms` (carried as `ttl_source` on the
`swarm:lease:v1` card); the contingency lease TTL is 300,000 ms and not 60,000
(carried on `26004`); the ladder is 12 destructive → 4 leased → 3 reversible, so
a hold card for one of the eight unleased kinds renders no pending containment
slot (`leases_a_containment`); `requires_h_channel_scope` is at
`ingest.rs:704-733`; and `tools/check-copy-banned-terms.sh` **does not exist in
either repository** and is PROPOSED wherever it is cited.

## 10. Sync without a codegen step

Full argument in
[`skeleton/perch-wire/README.md`](skeleton/perch-wire/README.md). In one
paragraph: the JSON Schemas are normative; the golden vectors are **extracted**
from the schemas' own `examples` by a generator, so a schema and its vector
cannot disagree and a hand-edited vector is a bug rather than a fix; the Rust
suite reads them with `include_str!` and the TypeScript suite from disk, and
**both now assert `GOLDEN.sha256`** (`10233c15…`), with the TypeScript suite
additionally reading the Rust constant out of a sibling checkout when it is
reachable and asserting the two pin the same corpus; and `parity-gate.sh`
compares **field-set names only** across schema, Rust and zod, which catches the
one failure a golden vector cannot — a field added to one side and to no vector.

Four serde traps have named tests on both sides. A fifth is not a serde trap but
a decode-strictness one and is asserted the same way: `FactIssuer.role` is
**required and nullable**, so a missing key is a decode error while a genuine
absence is an explicit `null`.

| Trap | Wire form | Source |
|---|---|---|
| `ThreatClass` externally tagged with a `Custom(String)` | `"lateral_movement"` \| `{"custom":"…"}` | `AMB crates/swarm-core/src/pheromone.rs:13-30` |
| `ResponseAction` internally tagged on `type` | `{"type":"isolate_host","host_id":"web-04"}` | `AMB crates/swarm-core/src/types.rs:416-467` |
| `AuditResponseRecord` internally tagged over **newtype** variants | `{"kind":"success", …seven receipt fields}` | `AMB crates/swarm-spine/src/lib.rs:102-110` |
| `Severity` is the workspace's only SCREAMING_SNAKE enum | `"HIGH"` beside `"isolate_host"` | `AMB crates/swarm-core/src/types.rs:406-414` |

### 10.1 Two defects in the gate itself, found by self-testing it

The gate now carries the `--self-test` its own header had promised since the
first draft without implementing it. Building the fixture found two ways the gate
could report success over a region it had not inspected — the exact failure shape
its header names:

1. **A string literal counted as a declaration.** The object-key regex's
   lookahead is `[:,}]`, so a field named inside a `.refine()` message —
   `"escalation.source_ids_absent_reason: exactly one must be null"` — satisfied
   it. Renaming the **real** key in `zod.ts` left the gate green. String literals
   are stripped before extraction now, with `z.literal("…")` values harvested
   first because a serde-tagged discriminator has no object key. **Self-test case
   4 is exactly this**, and it fails on the un-hardened gate.
2. **A flat `glob("*.rs")` would have gone silently vacuous on a module split.**
   `cards.rs` is 992 gate-lines and the obvious next move is a
   `cards/{mod,evidence,hold,verdict}.rs` split, which a flat glob drops entirely
   from the Rust side. It is `rglob` now, and an empty result is exit 2. (AMBUSH's
   `tools/` has no file-size gate, so 992 is legal there; the split is a
   readability call, not a forced one.)

A third defect was in its **defaults**, and it is the reason the previous
revision's "308 fields" was not reproducible: `REPO_ROOT` resolved to
`build/skeleton/` and the defaults pointed at
`build/skeleton/crates/swarm-perch-wire/schemas`, which exists in no tree. Run as
committed it printed `VACUOUS … exit 2`. It probes both layouts now — its
destination and this build tree — and **prints the one it resolved** before
reporting anything.

**Landing the gates.** In AMBUSH, `tools/check-gates-wired.sh` enumerates every
`tools/check-*.sh` — tracked or untracked — and fails on any not named by a real
workflow `run:` step, so `check-perch-wire-parity.sh` lands with its workflow
edit in the same PR. The exact steps are in the skeleton README for
`ci-wiring.snippet.yml` to absorb. In BUZZ there is no `tools/` directory at all;
the Buzz-side gate is a `desktop/scripts/check-perch-wire.mjs` wired into
`desktop/package.json`'s `check` script beside `check:px-text` and
`check:pubkey-truncation`, and the golden test rides `pnpm test`, one of
lefthook's pre-push groups. **That `.mjs` is specified and not written**; it is
row `W-5` in §12.

## 11. What this artifact hands to whom

### 11.1 Bindings

| Producer | What binds |
|---|---|
| `10-RELAY-FORK.md` / `21-ADRS.md` | **W-9 binds to ADR 0017 clause C3.** `26006` joins `P_GATED_KINDS` — one line in `BUZZ crates/buzz-core/src/kind.rs:159-169`, a third fork site, plus the two-connection E2E proving a non-`p`-tagged member is CLOSEd. The h-tag alternative is withdrawn and the reason is in §4.4, not a preference. |
| `11-BRIDGE-CRATE.md` | `narrowing::classify` is the fan-out table. `TagSet::assert_publishable` is the pre-signing gate and it now refuses four more things: a `hold`-less 46010, a `p`-less 46010 or `26006`, an `h`-tagged `26006`, and any hold id that is not `$defs/HoldId`-shaped. `26001` coalescing stands. `envelope.seq` is bridge-assigned per issuer per stream. **`fact.issuer.role` may be `null` and the bridge must emit an explicit `null`, never omit the key.** |
| `12-BACKEND-BILL-API.md` | `HeldActionView` ≡ `HoldCard.hold` minus `remaining_ms`/`expired`. The decide route's signing preimage is `{decided_at_ms, decision, hold_id}` and the verdict card reuses it byte-for-byte. **B1 must mint a hold id matching `$defs/HoldId`** — its "opaque (uuid)" commitment satisfies it. **The 409 body must name the winning `nostr_intent_event_id`**, because that is the only way a losing console can publish `leg2.superseded` (§3.5). |
| `14-CLIENT-ARCHITECTURE.md` | `admitCard`/`admitFrame` run **once per event at admission**, never in a render path. **`perchSubscriptions.ts` needs no edit under W-9** — its global `{kinds:[26006],"#p":[me]}` is exactly the admitted form, and was the thing W-1 would have silently broken. The Watchfloor opens **one** global REQ for `26000`–`26006`, not two. The paging-for-dilution rule in §5.2 stands. |
| `16-INVARIANT-TESTS.md` | INV-15's two clauses are asserted on both sides. **New P0 candidate from §3.5**, beside INV-12/INV-35: two consoles, both `p`-tagged, both publish leg 1, one 409s — the case timeline renders exactly one decision and one superseded intent record, and the loser's signed card is never dropped. **`copy-ban-list.tsv`'s `bare-source-count` row must admit `{n} sources / agents not yet resolved`**, or 06's owner supplies a different Phase-1 string; §7.2.1 names the requirement rather than assuming a regex. |
| `06`'s copy owner | The seven human-line grammars in §7.1. **W-6 is withdrawn: `N sources / M agents` is correct and the copy does not change.** The escalation card's Phase-1 line is the one open question, above. |
| `17-COMPONENT-SPECS.md` / `18-DATAVIZ.md` | The chart layer receives `distinct_sources` plus `distinct_sources_counts: "strategy_scoped_agent_id"`, `source_ids: null` and `source_ids_absent_reason: "not_carried_by_runtime_event"` until B4. 18-DATAVIZ's `sourceIds.map(id => id.split(":").slice(0,-1))` agent derivation is **correct and stays**. 17's `SourceCount` needs `sourceIds: readonly string[] \| null` plus the named absence, and its proposed APPENDIX §8 amendment should be **withdrawn with W-6**. |
| `22-DEMO-FIXTURE.md` | **Three one-line fixes and its 23 wire files all validate**, below. Its `fixtures/perch-demo-fixture.json` is the corpus the golden vectors were re-keyed onto, so there is one set of ids, not two. |

### 11.2 The three fixture failures, each with its one-line fix

Ran this session: `build/fixtures/wire/*.json` against `build/schemas/`, exact
committed bytes. **20 of 23 pass.** Before this revision **12 of 24 failed**, all
on `role: null` — W-A1 is what turned those over.

| File | Failure | Fix |
|---|---|---|
| `card-04-escalation-execution-alert.json` | missing `source_ids_absent_reason` | add `"source_ids_absent_reason": "not_carried_by_runtime_event"` beside its existing `"source_ids": null` |
| `event-46010-hold-a.json` | tags `t`, `l`, `k` | delete those three tags |
| `event-46010-hold-b.json` | same | same |

The fixture's `distinct_sources_counts: "strategy_scoped_agent_id"` was **right**
and this artifact's `const` was wrong; that is now fixed on this side and the two
agree. Its `fixtures/validate.mjs` departure allowlist should lose the
`FactIssuer.role` entry once W-A1 lands, so an unvalidatable fixture fails
instead of being recorded.

---

## 12. Work this artifact adds to the plan, for `20-TASK-BREAKDOWN.md`

`grep -c` over `20-TASK-BREAKDOWN.md` returns **0** for `swarm-perch-wire`,
`perch-wire`, `zod`, `golden` and `wire schema`. The 52-file deliverable this
file specifies is budgeted by none of its 50 task cards, and its totals (P0 23.5
ew, P1 28.5 ew) were computed without it. These are the rows, offered in that
document's shape so they can be pasted rather than re-derived. **Every ew figure
is an estimate**, in the same sense 20 §14 already marks its own.

| id | task | owner | ew | phase | cuttable | depends on |
|---|---|---|:-:|:-:|---|---|
| `W-1` | `crates/swarm-perch-wire` — the crate, its manifest, the workspace-members edit, and the seven `human_line` bodies the skeleton leaves as `todo!()` | Rust | 1.0 | P0 | no | nothing; it names existing domain types |
| `W-2` | `desktop/src/features/perch/wire/` — `types.ts`, `zod.ts`, `marker.ts`, `tags.ts`, `index.ts` | Desktop | 1.0 | P0 | no | `W-1` (the schemas, not the crate) |
| `W-3` | `scripts/sync-perch-golden.sh` — re-extract vectors from `examples`, rewrite the manifest, re-pin `GOLDEN.sha256` on both sides | Rust | 0.25 | P0 | no | `W-1` |
| `W-4` | `tools/check-perch-wire-parity.sh` **plus its `.github/workflows` `run:` step in the same commit** (`tools/check-gates-wired.sh` enumerates untracked scripts too) | Rust | 0.25 | P0 | no | `W-1`, `W-2` |
| `W-5` | `desktop/scripts/check-perch-wire.mjs`, wired into `desktop/package.json`'s `check` script beside `check:px-text` | Desktop | 0.25 | P0 | no | `W-2` |
| `W-6` | The two golden suites — `tests/golden.rs` and `golden.test.mjs` — including the four serde traps, the hash pin on both sides, and the cross-suite pin comparison | both | 0.5 | P0 | no | `W-1`, `W-2`, `W-3` |
| `W-7` | `26006` into `P_GATED_KINDS` + the two-connection E2E (**shared with the relay fork's bill; count it once**) | Rust | 0.25 | P0 | no | ADR 0017 C3 |

**≈3.5 ew, of which ~2.0 is Rust.** Against 20's recomputed 24.0 ew of Rust
through one engineer that is not a rounding error, and it lands on the critical
path because the bridge cannot publish a card before the card's type exists.

`W-4`, `W-5` and `W-7` also belong on the "eleven named CI gates, five
delivered" ledger: `tools/check-perch-wire-parity.sh` is delivered here as
`skeleton/perch-wire/parity-gate.sh` — it runs green from either tree with no env
vars and carries a `--self-test` — and `desktop/scripts/check-perch-wire.mjs` is
specified but **not written**, which §10 says rather than implies.
