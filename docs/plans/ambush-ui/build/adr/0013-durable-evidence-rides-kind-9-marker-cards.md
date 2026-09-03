# ADR 0013: Durable Evidence Rides `kind:9` Versioned Marker Cards, Not New Event Kinds

## Status

Proposed on 2026-08-30. Perch, Phase 0 (`03` wire registry) and Phase 1 (the first cards).

Depends on ADR 0012. Constrains ADR 0017 (the ephemeral block) by exclusion: what is not
durable evidence does not get a marker card.

Path prefix convention as in ADR 0011: `BUZZ ` is `block/buzz` at `eed74bde2`.

## Context

Every Ambush artifact Perch renders — a finding, an escalation, a hold, a human verdict, a
response receipt, a containment lease opening, a rollback receipt — has to reach the
relay's Postgres as a signed, queryable, searchable row. There are two ways to do that on a
Nostr relay: define a new kind per artifact type, or ride an existing kind and discriminate
on the body.

### Fact 1: a new stored kind is a six-file wound that reopens every rebase

`block/buzz` maintains three hand-synced event-kind registries with no compiler link
between them:

- `BUZZ crates/buzz-core/src/kind.rs` — the constants, `ALL_KINDS`, `P_GATED_KINDS`,
  `AUTHOR_ONLY_KINDS`, `SHARED_GATED_KINDS`, `is_command_kind`, and an invariant test at
  `BUZZ crates/buzz-relay/src/handlers/ingest.rs:3829-3838` that sweeps `0..=65535`
  asserting global-only and channel-scoped kinds are disjoint;
- `BUZZ desktop/src/shared/constants/kinds.ts` — `CHANNEL_EVENT_KINDS` (`:100-113`) and
  `CHANNEL_TIMELINE_CONTENT_KINDS` (`:137-149`);
- `BUZZ mobile/lib/shared/relay/nostr_models.dart` — 416 lines, the Flutter mirror.

A stored kind also costs, in the relay: an arm in `required_scope_for_kind`, a decision
about `requires_h_channel_scope`, and possibly an entry in the `search_tsv` `CASE`
(`BUZZ schema/schema.sql:223-227`) plus a migration. In the client it costs four
registration points — the two arrays above, `isTimelineContentEvent`
(`BUZZ desktop/src/features/messages/lib/formatTimelineMessages.ts:52-66`), and a
`renderBody` switch arm (`BUZZ desktop/src/features/messages/ui/MessageRow.tsx:381-459`) —
whose parity with each other is enforced in both directions by a `node:test` at
`formatTimelineMessages.test.mjs:663-676`.

Seven artifact types × that cost, on a repository moving at 20.7 commits a day, is the
shape of the year-two problem the contrarian described.

### Fact 2: the content-sniffing renderer path already ships

`BUZZ desktop/src/features/messages/lib/waveMessage.ts:1` declares
`WAVE_MESSAGE_MARKER = "<!-- buzz:wave:v1 -->"`. `buildWaveMessageContent` (`:7-10`)
composes `MARKER + "\n" + text`; `parseWaveMessageContent` (`:12-22`) tests
`content.trimStart().startsWith(MARKER)` over arbitrary body content and returns a
`fallbackText`. It is called from `MessageRow.renderBody`'s `default:` arm
(`MessageRow.tsx:414-426`, call at `:415`) — a closure inside the memoized `MessageRow`
component in the renderer process, which switches on `message.kind` to pick a body
renderer and falls through to a content sniff before rendering markdown.

This is not a hypothetical seam. It is a shipped, upstream-maintained one, with a producer
that already puts the marker on its own first line.

### Fact 3: `kind:9` is already registered at all four client points

`KIND_STREAM_MESSAGE = 9` (`BUZZ crates/buzz-core/src/kind.rs:479`) is in
`CHANNEL_MESSAGE_EVENT_KINDS` (`kinds.ts:90-95`), which `CHANNEL_EVENT_KINDS` spreads at
`:104`; it is named explicitly in `CHANNEL_TIMELINE_CONTENT_KINDS` at `:138`; it is the
first arm of `isTimelineContentEvent` (`formatTimelineMessages.ts:54`); and it reaches
`renderBody`'s `default:` arm, which already sniffs.

So a card riding `kind:9` costs **zero** of the four registration points.
`APPENDIX-NORMATIVE.md` §3's instruction to "say two relay arms, six registration points"
over-charges the marker path by four. This correction was raised three times independently —
here as AD-A3, in `10-RELAY-FORK.md` as RF-A1, and again in ADR 0017 as AD-A7 — and all three
are now **folded into `10-RELAY-FORK.md`'s RF-A6**, which carries this half plus ADR 0017's
`26006` half plus the measured `buzz-core` arithmetic. **File one amendment row.** Recorded
this way rather than silently deleted: three producers filing three rows for one correction is
the wave-2 failure mode `21-ADRS.md` §2.0 exists to stop.

### Fact 4: the one kind that is forked is not a new kind

`kind:46010` is already defined (`BUZZ crates/buzz-core/src/kind.rs:578`), already in
`ALL_KINDS` (`:745`), and already queried by the desktop's needs-action query. It is rejected
at ingest only because it is missing from `required_scope_for_kind`. Adding it is a bug
fix (ADR 0012, clause 5), not an exercise of the appetite this ADR is restraining.

## Decision

**Every durable Ambush artifact Perch publishes is a `kind:9` message whose body's first
line is a versioned marker comment, followed by JSON and a one-line human fallback. There
are exactly seven markers and an eighth requires a written argument. `kind:46010` is the
single stored-kind exception and it is a repair, not an addition.**

**The seven markers**, all `kind:9`, are `APPENDIX-NORMATIVE.md` §3's registry:
`swarm:finding:v1`, `swarm:escalation:v1`, `swarm:hold:v1`, `swarm:verdict:v1`,
`swarm:receipt:v1`, `swarm:lease:v1`, `swarm:rollback:v1`.

**The body shape is fixed**, and its ordering is the honest-degradation property:

```
<!-- swarm:finding:v1 -->
{"schema":"swarm:finding:v1", …}
Whisker flagged lateral movement on host web-04 at 14:02 UTC.
```

Line 0 is the marker and nothing else. Lines 1..n are the JSON payload. The final line is
prose a human can read with no client support at all. That last line is why the card
degrades correctly in the Flutter app, the browser client, `buzz messages thread` and a
NIP-50 search snippet — four consumers that will never learn what a marker is.

**Two rules bound the appetite.**

- **An eighth marker must answer `03` §4.4's question in writing:** *what can an operator
  not reconstruct without it, after the ephemeral frame that carried the same fact has
  decayed?* Convenience is not an answer.
- **A third stored kind must be argued against the marker alternative and must name who
  maintains the three-registry sync.** If one is needed within two quarters of Phase 1,
  the bet in this ADR failed and `09` §8's kill criterion K3 fires: reopen `00-BRIEF.md`
  §10 Q3 and price a proper kind family honestly.

**The sniff is hardened, and the hardening is a security control, not a nicety.** Perch's
parser fires only when **the marker is the entire first line** — `line0 === MARKER`, not
`startsWith` — **and** the event's `pubkey` resolves to an admitted bridge identity. The
same admission rule applies to `kind:46010`: a hold from an unadmitted signer renders as
untrusted prose, never enters a queue, and never reaches a wake class. This is `08` INV-15
and it exists because adversary-authored telemetry reaches this renderer: without the
admission half, any community member can publish a `kind:9` beginning
`<!-- swarm:verdict:v1 -->` and manufacture the appearance of a human deliberation.

**The registry is lifted out of `MessageRow` before the first card.** Seven new sniff
branches cannot be added to a file with one gate-line of headroom (ADR 0011, Fact 3), and
a per-marker `switch` inside a memoized component with a 60-clause comparator
(`MessageRow.tsx:935-995`) is the wrong shape regardless of the cap.

## Alternatives Considered

**Seven new stored kinds, one per artifact.** Typed `#filter` queries over kind, native
`COUNT`, no body sniffing, and a schema that documents itself. Rejected on Fact 1: 42
registry edits across three hand-synced files, in a fork we rebase monthly, for a
discrimination the body already carries. `trust-the-trigger`'s six-new-kinds proposal is
where this came from and its safety reasoning was adopted wholesale; only its wire cost
was rejected.

**One new stored kind with a `k` tag discriminator.** One registry edit instead of seven,
and `#k` is a single-letter tag so it is SQL-indexed. Genuinely closer. Rejected because it
still costs the four client registration points and the `search_tsv` decision, still
degrades to nothing in the three non-Perch clients, and buys a filter axis that
`APPENDIX-NORMATIVE.md` §3 already spends `k` on as a post-filter. Worth reopening under K3
as the *cheapest* third-kind option if the marker bet fails.

**`46030`/`46031` for the human verdict.** Rejected with evidence, and this is brief
amendment A2 rather than a preference. `is_command_kind`
(`BUZZ crates/buzz-core/src/kind.rs:815-826`) is a `const fn` evaluated by `ingest_event`
at `ingest.rs:2278` in the relay process, **after** scope validation; a `true` result
routes the event to `command_executor::handle_command` instead of storage. Its set is
`{WORKFLOW_DEF, DM_OPEN, DM_ADD_MEMBER, DM_HIDE, WORKFLOW_TRIGGER, APPROVAL_GRANT (46030),
APPROVAL_DENY (46031)}`. `handle_approval_grant` (`command_executor.rs:1020`) then rejects
with `"invalid: approval not found"` at `:1045` when no `workflow_approvals` row matches,
before `persist_command_event` at `:1064`. A Perch-published 46030 is never stored. The
same check confirms 46010 is **absent** from that set, so the forked kind falls through to
ordinary insert.

## Consequences

### Positive

- The fork of `block/buzz` for durable evidence is one kind, three hunks in one relay file,
  and zero client registration points.
- The cards degrade honestly in four consumers that will never be taught to parse them.
- A marker is versioned in its own name, so `swarm:finding:v2` can ship beside `v1`
  without a registry negotiation.

### Negative

- **`strategy_id`, `host_id`, `receipt_id`, `lease_id` and `hunt_id` are reachable through
  NIP-50 full-text search only, never as a `#filter`.** NIP-01 indexes single-letter tags,
  the single-letter budget is closed (`APPENDIX-NORMATIVE.md` §3), and the events are
  signed, so they cannot be re-tagged later. This is a real, permanent, named cost and it
  is the one this ADR is most likely to be wrong about. K3 is its tripwire.
- Body sniffing is a parser over attacker-reachable bytes in the renderer process. The
  INV-15 hardening is mandatory, not advisable.
- A card's kind tells a relay operator nothing about what it is. Moderation, deletion and
  retention tooling written against kinds will treat an Ambush receipt as an ordinary chat
  message. For a private per-colony relay (`00-BRIEF.md` §10 Q7) that is acceptable;
  for a shared one it would not be, and this ADR should be revisited before any such
  deployment.

## Verification

- The parity `node:test` at
  `BUZZ desktop/src/features/messages/lib/formatTimelineMessages.test.mjs:663-676` already
  fails the build if `CHANNEL_TIMELINE_CONTENT_KINDS` and `isTimelineContentEvent`
  disagree in either direction. This ADR does not change it and does not need to; it is
  recorded so nobody "helpfully" adds a marker to a kind array.
- **PROPOSED** a table test over the marker registry asserting exactly seven entries, each
  with a `v`-suffixed version, and that the parser rejects a body where the marker is not
  the whole of line 0.
- **PROPOSED** an E2E test: a `kind:9` carrying `swarm:verdict:v1` from a pubkey outside
  the admitted-identity set renders as prose, does not enter a queue, and produces no
  notification (`08` INV-15).

## Follow-On Work

- **Amendment AD-A3 is withdrawn into `10-RELAY-FORK.md`'s RF-A6.** Its substance stands:
  `APPENDIX-NORMATIVE.md` §3's "**four client registration points** … Say 'two relay arms, six
  registration points'" is correct for a stored kind and over-charges the marker path, which
  costs zero (Fact 3); the row should read "three relay hunks in `ingest.rs` — the two match
  arms plus the `KIND_WORKFLOW_APPROVAL_REQUESTED` import, absent today — **zero client
  registration points**", keeping the four-point cost documented as the price of a future
  decision to render raw `46010` rows. RF-A6 carries it, together with the `26006` half. One
  row.
- `13-WIRE-SCHEMAS.md` owns the seven payload schemas. This ADR owns only the carrier
  decision and the two rules that bound it.
- The `swarm:rollback:v1` card for a **TTL-driven** containment release has no producer:
  the operator-driven one is the console's leg-1 publish, and nothing broadcasts a runtime
  event when the sweep closes a **containment lease** on its own. `11-BRIDGE-CRATE.md` §15
  names the smallest fix (a `RuntimeEvent::ContainmentReleased`, bill item **B1c**, PROPOSED,
  ~0.5 ew, cuttable). Until it lands, `/leases` must render the TTL-release case as a daemon
  read, never as a missing card.
