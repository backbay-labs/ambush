# ADR 0017: The Ephemeral `26000`–`26006` Block Carries Aggregates Only, Renders Only From Admitted Issuers, And The Hold Alarm Is Compartmented In Two Layers

## Status

Proposed on 2026-08-30. **Revision 2** — the decision changed; see *Revision history* below.
Perch, Phase 0 (the alarm's provisioning and the `buzz-core` backstop) and Phase 3 (the
telemetry surfaces).

Depends on ADR 0013 (durable evidence goes on `kind:9`; this block is what does not).
**Decides the open item both `10-RELAY-FORK.md` §11 and `11-BRIDGE-CRATE.md` §15 originally
handed to each other**: the `26006` disclosure hole. This revision **ratifies**
`10-RELAY-FORK.md`'s DECISION RF-D5 and RF-D6 rather than competing with them; that file
owns the patch and did the arbitration, and an ADR's job here is to record the decision so
it is not re-fought in eighteen months.

Path prefix convention as in ADR 0011: `BUZZ ` is `block/buzz` at `eed74bde2`.

### Revision history

| Rev | What changed | Why |
|---|---|---|
| 1 | `26006` is global; `P_GATED_KINDS` is the fix; the `h`-tag option is rejected | — |
| **2** | **`26006` carries an `h` tag naming a private standing `#watch` operations channel (layer 1) AND is listed in `P_GATED_KINDS` (layer 2).** The rejection of the `h`-tag option is **withdrawn** as having been argued against the wrong option. Fact 3's mechanism statement is corrected. The proposed verification is replaced by `10-RELAY-FORK.md` §11.7's eight tests, two of which correct tests this ADR originally proposed and which would have failed | Revision 1 asserted C3 closed the hole; measured, it fences the **global-REQ route only** and has no effect on a channel-scoped subscription or on fan-out (Fact 3 below). `13-WIRE-SCHEMAS.md`'s W-1 and this ADR's C3 were then two "binding" decisions on one hole. `10-RELAY-FORK.md` §11 arbitrated them, `11-BRIDGE-CRATE.md` §8.6 reached the same answer independently, and both are right |

## Context

Live telemetry — ingest rate, concentration, agent health, swarm mode, governance status,
tamper counts, and the hold alarm — must reach the console within a second and must never
become a durable record. Nostr's ephemeral range (20000–29999) is the right carrier, and it
is nearly free.

### Fact 1: the ephemeral block needs no relay change, and here is why

`handle_event` (`BUZZ crates/buzz-relay/src/handlers/event.rs:694-751`) runs in the relay
process on the per-connection WebSocket task. `if is_ephemeral(kind_u32)` short-circuits:
it checks `Scope::MessagesWrite` (`:699-707`), applies the community write fence
(`:708-732`), calls `handle_ephemeral_event` (`:733-748`), and **returns at `:750`** —
before `ingest_event` is reached at `:761`. So `required_scope_for_kind` never sees a
`26xxx`, and the test `ephemeral_kinds_not_in_scope_allowlist`
(`BUZZ crates/buzz-relay/src/handlers/ingest.rs:3851-3854`) pins that property against a
presence kind.

Two consequences follow and neither is optional:

- **The block is WebSocket-only.** `POST /events` calls `ingest_event` directly
  (`BUZZ crates/buzz-relay/src/api/bridge.rs:925`) with no ephemeral branch, so an HTTP
  publish of a `26xxx` is rejected. The bridge must hold a WebSocket.
- **The publish gate is one scope check, and an empty scope set passes.** The condition is
  literally `if !scopes.is_empty() && !scopes.contains(&Scope::MessagesWrite)`. Every
  chat-capable community member can publish a fabricated `26003` mode transition or a
  fabricated `26006` hold alarm. Nothing below changes that; C5 is the whole defence.

### Fact 2: the relay does not enforce `#p` on delivery of a channel-less event

`filter_fanout_by_access` (`BUZZ crates/buzz-relay/src/handlers/event.rs:115-222`) is the
single guarded send chokepoint for relay-local WebSocket delivery — it is called by
`fan_out_event_to_local_subscribers` at `:247`, which is what both the ingest fan-out path
and the Redis cross-node subscriber loop run. For a channel-less event it applies the
receiver tenant-label filter (`:126-131`), `AUTHOR_ONLY_KINDS` (`:139-152`) and
`SHARED_GATED_KINDS` (`:157-175`), and then hits

```rust
177    let Some(channel_id) = stored_event.channel_id else {
178        return matches;
179    };
```

— returning every match **without consulting `p` tags**. `26006` is in neither
`AUTHOR_ONLY_KINDS` nor `SHARED_GATED_KINDS`, so under revision 1's "global, no `h`" design
any authenticated community member who opened `REQ {"kinds":[26006]}` received every hold
alarm in the colony: `hold_id`, `action_kind`, `severity`, `case_channel`, `expires_at_ms`
— including alarms `p`-tagged to other operators.

`APPENDIX-NORMATIVE.md` §3's admitted-issuer rule is a **render** rule and does not close
this. It governs what a client draws, not what a relay sends.

### Fact 3: `P_GATED_KINDS` fences one route — the global REQ — and nothing else

This fact is **rewritten in revision 2.** Revision 1 described the gate correctly and then
attributed to it a property it does not have.

`P_GATED_KINDS` (`BUZZ crates/buzz-core/src/kind.rs:159-169`) holds six kinds, one of them
— `KIND_AGENT_OBSERVER_FRAME = 24200` (`:469`) — **ephemeral**, and the constant's own doc
comment at `:144-158` anticipates exactly that case:

> Ephemeral kinds (20000–29999, e.g. `KIND_AGENT_OBSERVER_FRAME`) are included for
> filter-layer enforcement but are never stored, so the storage-layer search defense does
> not apply to them.

So the precedent for adding an ephemeral is real. **What it buys is narrower than revision 1
claimed.** `p_gated_filters_authorized`
(`BUZZ crates/buzz-relay/src/handlers/req.rs:1182-1222`) is called from the relay's REQ
handler at `req.rs:221`, and that call site sits **inside `if channel_id.is_none()`** at
`:219` — a condition whose own comment at `:211-218` states the reason: *"Only applies to
GLOBAL subscriptions (channel_id = None): channel-scoped subs can never receive globally
stored events because of the `fan_out()` invariant in `subscription.rs`."* When it returns
false the relay sends `RelayMessage::closed(&sub_id, "restricted: p-gated events require #p
matching your pubkey")` and returns (`:222-227`), refusing the whole REQ frame.

Three consequences, each measured:

1. **It is a filter-admission check, not a fan-out check.** `filter_fanout_by_access` never
   reads `P_GATED_KINDS`; grep it and the set does not appear. So the gate constrains what
   subscription may be *registered*, not what any given event is *sent to*.
2. **It does not run at all on a channel-scoped REQ.** `extract_channel_id_from_filters`
   (`req.rs:1153-1180`) returns `Some(uuid)` when every filter in the frame carries an `h`
   naming one and the same channel; the p-gate is then skipped entirely.
3. **The delivery half is real but only for global subscriptions.** `register_with_scope`
   (`BUZZ crates/buzz-relay/src/subscription.rs:190-199`) routes a fully-`#p`-constrained
   global filter into `global_p_kind_index` rather than `global_kind_index` (the routing
   decision is `extract_global_p_kind_index_keys` at `:662-694`, which returns `None` unless
   **every** filter has explicit `kinds` and a non-empty `#p`), and `fan_out_scoped`'s global
   branch at `:428-450` iterates `event_p_tag_values(event)` and looks that index up by the
   event's own `p` tag values.

   **Rebuttal, recorded so the objection cannot recur.** A wave-2 critic read
   `global_p_kind_index` as "a database index over stored events" and concluded the mechanism
   cannot apply to an ephemeral. It is not a database index. It is declared at
   `subscription.rs:97` as
   `global_p_kind_index: DashMap<GlobalPKindIndexKey, Vec<(ConnId, SubId)>>` — an in-memory
   field of the relay process's `SubscriptionRegistry`, populated at REQ time and read at
   fan-out time. It never touches Postgres. The `StoredEvent` handed to `fan_out_scoped` for
   an ephemeral is constructed in memory at `event.rs:901`
   (`StoredEvent::new(event.clone(), None)`) for an event that was never persisted, exactly
   as `handle_ephemeral_event` builds it. The mechanism applies. **It is still not the
   production delivery path under this ADR's decision**, because layer 1 makes the frame
   channel-scoped — which is the actual reason revision 1's argument needed replacing.

### Fact 4: the source cadence is level-triggered at 10 Hz and would exhaust the write budget

`ConcentrationMonitor::evaluate_all` (`crates/swarm-runtime/src/escalation.rs:105-207`) is
driven by `run_until_shutdown(CONCENTRATION_MONITOR_INTERVAL_MS)` with the constant at
`crates/swarm-runtime-http/src/bin/swarm_detect.rs:40` = **100 ms**, spawned at `:1002-1006`.
It publishes one `RuntimeEvent::Escalation` per over-threshold class per tick (`:148`) with
no memory of prior state, plus one `ConcentrationSnapshot` carrying all twelve classes
unconditionally per tick (`:198-199`). Twelve classes over threshold is up to 120 escalation
events per second.

Against that, the relay charges **every** inbound `EVENT`, `REQ` and `COUNT` frame against a
50-frames-per-5-second budget (`BUZZ crates/buzz-relay/src/connection.rs:671-681`;
`admission.rs:9, 40-45`: `WS_BURST_WINDOW_SECS = 5` × `human_ws_events_per_sec = 10`) with
**no** agent exemption, and separately picks a per-minute message tier of 120
(owner-attested agent) or 60 (human) at `connection.rs:690-695`.

### Fact 5: an `h`-tagged ephemeral has a complete, shipped, compartmented delivery path

New in revision 2, and it is the fact revision 1 did not establish before rejecting the
option that rests on it.

`handle_ephemeral_event` (`BUZZ crates/buzz-relay/src/handlers/event.rs:795-905`), called by
`handle_event` at `:733` on the relay's per-connection task, branches at `:850` on
`extract_channel_id(&event)`:

| | `h` tag present (`:850-874`) | no `h` tag (`:875-902`) |
|---|---|---|
| Publisher check | `check_channel_membership` at `:851-852` — a **non-member publisher is refused**, `OK false` | none beyond Fact 1's scope check |
| Redis topic | `EventTopic::Channel(ch_id)` at `:860` | `EventTopic::Global` at `:888` |
| Fan-out input | `StoredEvent::new(event.clone(), Some(ch_id))` at `:873` | `StoredEvent::new(event.clone(), None)` at `:901` |
| Index consulted | `channel_kind_index` / `channel_wildcard_index` (`subscription.rs:392-484`) | `global_p_kind_index` / `global_kind_index` / `global_wildcard_index` (`:428-474`) |
| Receiver check | `filter_fanout_by_access` `:177-221`: if channel visibility is `private`, a per-connection `is_member_cached` loop at `:205-216` drops every non-member | `:177-179` returns every match |

Two properties of the left column are load-bearing and both are easy to lose:

- **The channel must be `private`.** `filter_fanout_by_access` returns early at `:195`
  (`Ok(v) if v != "private" => return matches`) for any non-private channel. An **open**
  `#watch` makes layer 1 a complete no-op while looking identical from the console.
- **The subscribing console must be a member.** A channel-scoped REQ has its requested
  channel ids filtered against `accessible_channels` (`req.rs:189-195`) and, when nothing
  survives, the relay answers `CLOSED "restricted: not a channel member"` (`:200-208`). A
  `p`-tagged operator who is not a `#watch` member gets a terminal notice, not silence.

The symmetry that makes the two layers non-overlapping is stated in the relay's own comment
at `subscription.rs:487-492`: *"Global subscriptions (channel_id = None) do NOT receive
channel-scoped events. Channel-scoped subscriptions do NOT receive global events."*

> **INTEGRATOR RULING, 2026-08-30 — see [`00-REGISTRY.md`](../00-REGISTRY.md) R-1.** Clause C3's
> `h`-tag layer is **retracted**. `kind:26006` stays **global with no `h` tag**, and the
> `P_GATED_KINDS` entry is the whole delivery fence: every Perch REQ that can match `26006` carries
> `#p` equal to the reader's own pubkey on every filter. Facts 1–5 below are all verified and
> unchanged; Fact 5 now documents a delivery path the design does **not** take. This restores the
> revision-1 mechanism with the revision-2 evidence attached, and it means `26006` needs no
> standing `#watch` channel and imposes no publisher-membership precondition on the alarm.

## Decision

**Seven ephemeral kinds, `26000`–`26006`, aggregates and opaque ids only, rendered only from
admitted issuers. `26000`–`26005` are global and ungated. `26006` is compartmented in two
layers: an `h` tag naming a private standing `#watch` operations channel, and a
`P_GATED_KINDS` entry that fences the global form.**

**C1. The aggregates-only payload rule, enforced by construction.** The bridge's ephemeral
builders take a narrow struct per kind, never a `RuntimeEvent`. So `26005` carries tamper
**counts**, never library paths; `26002` carries `AgentHealth` plus `AgentAction` tallies
and its `details` never crosses the wire; `26006` carries exactly
`{hold_id, action_kind, severity, case_channel, expires_at_ms}`. A payload rule enforced by
a code review is a payload rule that leaks on the third card; a builder that cannot be
handed the rich type cannot leak it. Asserted over the serialized JSON by
`11-BRIDGE-CRATE.md` §14's `T-21`, so a widened struct fails rather than leaks.

**C2. `hold_id` is an opaque random token with a pinned shape.** Never
`hold:{hunt_id}:{held_at_ms}`. `hunt_id` in the hot path is literally the telemetry event id
— `ActionRequest.hunt_id` is built as `HuntId(primary_finding.event_id.clone())`
(`crates/swarm-runtime/src/service/runtime_service.rs:391`) — a join key into detection data.

**The shape is a lowercase hyphenated UUID**, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`,
minted by B1 and never derived from anything. This pins a value that was drifting: six
`hold_id` formats were in circulation across the wave-2 artifacts, two of them using the
`hold:` colon prefix the schemas' own descriptions warn against — which reads as the
forbidden derived form even when it is not. `12-BACKEND-BILL-API.md` commits the minter's
side ("opaque (uuid)"); `11-BRIDGE-CRATE.md` §8.6 enforces it at the publish seam with a
`HoldId` newtype whose `parse` is the only constructor, refusing with
`BridgeError::MalformedHoldId` and **building no event** (test `T-20`). A colon anywhere is
a hard refusal. `13-WIRE-SCHEMAS.md` owns adding the pattern to the three schemas that carry
the field.

**C3. The hold alarm is compartmented in two layers. This ratifies
`10-RELAY-FORK.md` DECISION RF-D5 verbatim; that file owns the patch.**

- **C3a — layer 1, the compartment: the `h` tag.** `26006` carries an `h` tag naming the
  standing `#watch` operations channel, which **must be provisioned
  `visibility: "private"`**. This is the primary mechanism. It costs **zero relay change**
  (Fact 5's left column is entirely shipped code), it enforces publisher membership, and it
  re-authorizes **per recipient at delivery time** rather than at subscription time — so a
  stale subscription that outlived a membership change cannot leak. The frame **also** carries
  one `p` tag per principal holding `OperatorScope::Approve`, per `APPENDIX-NORMATIVE.md` §4
  layer 1; the `p` tags are what let a console tell *"this hold names me"* from *"this hold
  is on the floor"*, and what make the frame safe if it is ever read through a global filter.
- **C3b — layer 2, the backstop: `26006` is added to `P_GATED_KINDS`** in
  `BUZZ crates/buzz-core/src/kind.rs`. Layer 1 has exactly one failure mode and it is silent:
  if the bridge ever publishes a `26006` **without** an `h` tag — a bug, a config default, a
  fallback path, a partially applied rebase of the bridge's publish seam —
  `handle_ephemeral_event` takes the `else` branch at `:875-902`, the frame becomes
  community-global, `filter_fanout_by_access` returns every match at `:177-179`, **and
  nothing fails loudly**: the alarm still arrives at the right operators, so the console looks
  correct while the frame is readable by every member. This is the only mechanism in the relay
  that fences that route. It is a backstop and must be described as one — *"it closes the
  global form"*, never *"it closes the hole"*.
- **C3c — the composition rule (ratifying RF-D6, binding on the console).** Any REQ frame
  whose filter set can match `26006` must satisfy **one** of: **(a)** every filter carries
  `#h` and all of them name the **same single** channel; or **(b)** every filter carries `#p`
  equal to the reader's own pubkey. A frame satisfying neither is refused **in its entirety**,
  including its unrelated filters, because `p_gated_filters_authorized` is an `.all()` over
  filters (`req.rs:1184`) and `extract_channel_id_from_filters` returns `None` when any filter
  lacks an `h` **or** when two filters name different channel ids (`:1163-1176`). The alarm
  REQ is one of `14-CLIENT-ARCHITECTURE.md`'s seven and **may not be merged into another** to
  save a slot.

**This changes the fork's framing and the framing must change with it.** The `buzz-core`
change is real but is **not** "one line in one array" — measured by `10-RELAY-FORK.md` §11.8
it is the `P_GATED_KINDS` entry plus its comment, the kind constant plus its doc comment
(`#![warn(missing_docs)]` is on for the crate, `BUZZ crates/buzz-core/src/lib.rs:2`, and
`P_GATED_KINDS` contains only named constants today — a bare `26006` would be the file's only
integer literal), an `ALL_KINDS` entry (`kind.rs:635`), and three unit tests. Revision 1's
proposed amendment AD-A7 is **withdrawn in favour of `10-RELAY-FORK.md`'s RF-A6**, which
carries both halves and the corrected arithmetic. **File one amendment row, not two.**

**C4. `26000`–`26005` are not compartmented, deliberately.** They carry no `p` tag, no `h`
tag and no per-host identifier; they are colony-wide aggregates by construction, and gating
them would make them undeliverable to everyone. Their confidentiality argument is C1 — there
is nothing in them worth compartmenting — and it has to keep being true. **A payload change
that adds a `p` tag, an `h` tag or a per-host identifier to any of the six is a change to
this ADR**, not a schema tweak.

**C5. The admitted-issuer rule is a render rule and stays one — and neither delivery layer
touches forgery.** A `26xxx` frame renders only if its pubkey resolves to an admitted bridge
identity; others are counted and dropped. Fact 1's publish gate admits any token with
`MessagesWrite`, so a community member can publish a well-formed `26006` of their own into
`#watch` if they are a member of it. **Two delivery fences do not imply a third property.**
C3a and C3b stop a reader from *receiving* other operators' alarms; C5 is the whole defence
against a writer *fabricating* one that renders. `08` INV-15 extends the same admission rule
to `kind:46010`.

**C6. Coalescing `26001` from 10 Hz to 1 Hz before the IPC boundary is a hard requirement,
not an optimisation** (Fact 4). Seven 1 Hz publishers fit inside a 50-frames-per-5-second
budget with room; one 10 Hz publisher consumes it alone and takes the alarm frame down with
it. `PERCH_CONCENTRATION_TICK_HZ = 1` is settled (`APPENDIX-NORMATIVE.md` §6).

**The mechanism is edge-triggering, not deduplication.** A dedupe on
`(threat_class, level, timestamp)` would never fire: `RuntimeEvent::Escalation` and
`ConcentrationSnapshot` each stamp `emitted_at_ms: now_ms()` at publish
(`crates/swarm-runtime/src/escalation.rs:253` and `:288`), so ten ticks in a second are ten
distinct events. The bridge emits on a level **change** and on a bounded heartbeat.
`11-BRIDGE-CRATE.md` §6.2 owns the implementation and issued this correction against the
ground survey; this ADR binds to it because a producer who implements the dedupe ships a
firehose that passes review.

**C7. `26006` is never coalesced and never shed.** Every other frame kind may drop under
pressure and say so. The alarm frame may not. Its budget is the ≤400 ms one; the durable
`kind:46010` row has no such budget (`APPENDIX-NORMATIVE.md` §4).

## Alternatives Considered

**Accept the disclosure.** Argument: a colony is one security team, everyone is cleared, and
the payload is five fields. Rejected. The console's compartment story is that a case is
private and membership is re-authorized on every delivery (ADR 0012, Fact 1); an alarm frame
that names `case_channel` for every hold in the colony leaks the existence, severity and
action kind of every incident to every member, which is precisely the thing the case
compartment exists to prevent. It would also be a strange thing to have built the compartment
for.

**`P_GATED_KINDS` alone, with the frame left global — revision 1's decision.** Rejected in
revision 2 on Fact 3. It fences the global-REQ route and nothing else, so it is a good
backstop and a poor compartment: it depends on the frame carrying a correct `p` tag on every
publish, it re-authorizes at subscription time rather than at delivery time, and it needs a
`buzz-core` change to do a job an already-shipped path does better. It is retained as C3b for
the one failure it uniquely covers.

**Give `26006` an `h` tag naming the *case* channel.** This — and **only** this — is what
revision 1 rejected, and the rejection stands: it re-imposes the case-membership precondition
on the alarm, meaning an operator must already be a member of a case before they can be told a
hold exists in it, which inverts the alarm's whole job. Revision 1's error was writing that
rejection as though it disposed of the `h`-tag option in general. It does not: `#watch` is a
**standing operations channel**, not a per-case one, and membership in it is a shift roster
rather than an incident compartment. **The rejection is withdrawn as to option (d)** —
`13-WIRE-SCHEMAS.md`'s W-1 — which is now C3a.

**Encrypt the `26006` payload to each recipient (NIP-44, one frame per operator).** Closes
the disclosure without touching `buzz-core` or provisioning a channel. Rejected on two counts:
it multiplies the alarm frame count by the number of `Approve` principals against the tightest
budget in the system (Fact 4), and it makes the alarm undecryptable by the console until it has
resolved the operator's key — which is the mapping ADR 0016 Fact 2 shows is configured and
unsigned. Worth revisiting if the principal count ever exceeds two or three.

**Leave it and document it.** Rejected as the shape of defect this repository catalogues: a
check reporting over a region it never inspected. `10-RELAY-FORK.md` and `11-BRIDGE-CRATE.md`
each correctly declined to decide it and named the other as owner; that is how a known hole
ships. The wave-2 sequel is worth naming too: **two** artifacts then decided it independently,
each writing that no other mechanism was needed, which is worse, because both fixes looked
ratified. The cure is this ADR pointing at one arbitration (RF-D5) rather than adding a third.

## Consequences

### Positive

- The alarm is delivered to `#watch` members and to nobody else, by a relay mechanism that
  already exists, is already tested, and re-authorizes per recipient on the sending pod.
- The global route is fenced by a change of the same class as `24200`'s, separately
  upstreamable to `block/buzz` with the same one-sentence justification.
- C1's builder shape makes the payload rule a compile-time property.
- The two layers cover **different** failures, which is what makes shipping both worth its
  cost: layer 1 covers a correct frame reaching the wrong reader; layer 2 covers a frame that
  should have been compartmented and was not.

### Negative

- **Three provisioning obligations, none of them code, all of them silent when missed.**
  `11-BRIDGE-CRATE.md` §8.3 items 8–10 own them: (8) `#watch` exists and is `private` — an
  open one makes layer 1 a no-op; (9) the `perch-alarm` identity is a **member** of it, or
  every alarm gets `OK false` and no hold reaches the shift; (10) **every operator console's
  pubkey is a member**, or that console gets `CLOSED "restricted: not a channel member"` on
  the one subscription that carries holds. Item 10 is the one that reaches a human, and
  `14-CLIENT-ARCHITECTURE.md` must render it as *"you are not on the watch floor"* with the
  remedy, never as a quiet shift. The bridge cannot pre-flight any of them — it is write-only
  by ADR 0015, so it has no read path with which to check a membership row. **The first alarm
  is the test.**
- **A third fork site.** `buzz-core/src/kind.rs` was, before this, a file Perch did not touch,
  and ADR 0013's whole argument is about not touching the three kind registries. It is a much
  smaller wound than a kind definition — no `search_tsv` `CASE`, no client registry, no
  Flutter mirror — but it is four hunks and three tests, not one line, and repeating "two relay
  arms" would be dishonest.
- **`26006` is now a second reason `#watch` must exist**, and `#watch` is a Perch construct
  from `04` §2.11 that nobody has built. It is provisioned once by the relay operator, not by
  the bridge — `perch.watch_channel` is configuration — because it is a standing object shared
  across colonies and shifts, and having the bridge create it would extend its `AdminChannels`
  authority from TTL-bounded case channels to a permanent one.
- `26000`–`26005` remain readable by every community member. That is a decision (C4), not an
  oversight, and it is only safe while C1 holds.
- The console cannot distinguish "no alarm frame arrived" from "the alarm frame was filtered"
  from "I am not a `#watch` member and my REQ was closed". The third is now distinguishable
  (it is a `CLOSED` with a message); the first two are not. Reconciliation against
  `GET /v1/response/holds` (ADR 0012, clause 3) is the only detector, which is another reason
  it is mandatory.

## Verification

**The verification revision 1 proposed was wrong in two of its three cases and is replaced.**
It asserted that a `p`-tagged operator receives a production `26006` through a global
`{"kinds":[26006],"#p":[B]}` subscription. Under C3a a production frame is channel-scoped, and
`subscription.rs:487-492`'s symmetry means it reaches **no** global subscription — so those
cases would have failed against a correct implementation. Recorded here rather than quietly
deleted, because it is the exact failure shape the wave-2 red team named: a mechanism verified
at the line, and a conclusion attributed to it that it does not have.

The suite of record is `10-RELAY-FORK.md` §11.7's eight tests in
`e2e_operator_alarm_pgate.rs`, which this ADR ratifies:

| Covers | Tests |
|---|---|
| C3b, the backstop, in the direction that matters | 1 (`global_alarm_subscription_without_a_p_filter_is_closed`), 2 (`…naming_another_pubkey_is_closed`), 3 (`a_named_principal_receives_the_frame_and_an_unnamed_one_does_not`, over a deliberately `h`-less frame) |
| The premise that lets the patch skip the `search_tsv` obligation | 4 (`an_alarm_frame_is_never_stored`) |
| C3a, and that the two layers compose | 5 (`a_channel_scoped_frame_reaches_a_member_and_no_global_subscriber`) |
| C3a's publisher-membership precondition | 6 (`a_non_member_cannot_publish_a_channel_scoped_frame`) |
| C3c | 7 (`mixing_an_h_scoped_alarm_filter_with_a_global_filter_closes_the_whole_req`), 8 (`naming_two_channels_in_one_req_closes_an_alarm_filter`) |

Additionally:

- **PROPOSED** a bridge unit test that the ephemeral builders reject a `RuntimeEvent` argument
  by type (C1); that the `26006` carries exactly one `h` equal to `perch.watch_channel` and one
  `p` per `Approve` principal, asserted over the serialized JSON (C3a); and that `HoldId::parse`
  accepts a lowercase hyphenated UUID and refuses `hold:01K3…`, `hold_a1f4c2e9`, an uppercase
  UUID and the empty string, each with no event constructed (C2). These are
  `11-BRIDGE-CRATE.md` §14's `T-20` and `T-21`.
- **PROPOSED** a frame-budget test: seven publishers at their specified cadences over a
  simulated minute stay under 50 frames per rolling 5 seconds and under 120 per minute.
- `08` INV-15 covers C5. Note what it does **not** cover: a `#watch` member with `MessagesWrite`
  publishing a fabricated alarm that is *dropped* by the admitted-issuer rule still consumed a
  frame slot and is invisible unless the drop is counted. `14-CLIENT-ARCHITECTURE.md` commits to
  counting and rendering unadmitted frames; that count is the only signal.

## Follow-On Work

- **Amendment: `10-RELAY-FORK.md`'s RF-A6, filed once.** It supersedes both
  `13-WIRE-SCHEMAS.md`'s W-1 and this ADR's revision-1 C3 by absorbing them, and it carries the
  corrected `buzz-core` arithmetic. `21-ADRS.md` §2's AD-A7 is withdrawn to it; AD-A3 was
  already folded into AD-A7 and travels with it. **One row, not three.**
- `13-WIRE-SCHEMAS.md` owns the seven payloads and the `hold_id` pattern in
  `card-swarm-hold-v1`, `card-swarm-verdict-v1` and `frame-26006-hold-alarm`.
- `14-CLIENT-ARCHITECTURE.md` owns the alarm REQ's shape. Its `perchSubscriptions.ts` watch-alarm
  filter is written against revision 1 (`{kinds:[26006],"#p":[me],limit:0}` — global) and under
  C3a would deliver **zero** frames while failing nothing loudly. It becomes
  `{kinds:[26006],"#h":[watchChannelId]}`, and C3c forbids merging it with any other filter.
- `11-BRIDGE-CRATE.md` §8.3 owns the three provisioning obligations and their runbook entries.
- Revisit C4 if any of `26000`–`26005` acquires a per-host, per-case or per-operator identifier.
