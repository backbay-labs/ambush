# Realtime, data flow, and performance

The systems half of Perch: every hop from a telemetry event landing in
`swarm_detect --serve` to a pixel changing on an operator's screen, with the
rate ceiling, coalescing rule, loss policy and latency budget for each. The
governing fact is a 1,800:1 mismatch — Ambush's measured hot path is 3,645
events/sec end-to-end and one Buzz relay identity is admitted at 2 events/sec —
so this document is mostly about where detail is deliberately destroyed and how
the console says so out loud. Citations are `path:line`, prefixed `BUZZ/` for
`block/buzz` and `AMB/` for `backbay-labs/ambush`.

**Method note, applied throughout this revision.** For every load-bearing
citation this document now answers three questions in the same sentence as the
citation: *who calls this*, *what process is it in*, and *what does it do to the
data*. A name existing is not a mechanism existing. Four claims in the previous
draft failed that test and are corrected below in §5.2, §5.3, §5.4 and §5.6; two
of them invert a design decision, not merely a sentence.

---

## 0. Words, and the four this document gives back

The set uses **"lane"** in four incompatible senses, one of which is an
operator-visible nav label. That is the defect `06-COPY-AND-VOICE.md:31-35`
identifies and bans for "lease" — two unrelated objects sharing one word — and
the set was applying its own rule to the domain's vocabulary and not to its own
invention. Ambush's source uses the word a fifth way: `AsyncLaneStatusSnapshot`
(`AMB/crates/swarm-runtime/src/runtime_events.rs:34-60`) is the investigation and
correlation lane, and `03-DOMAIN-EVENT-MAPPING.md:229-252` uses A/C/D/E/H "lanes"
for carrier classes.

**This document gives the word back.** "Lane" means one of the twelve standing
threat-class channels and nothing else. What this document previously called
lanes are **streams**: `evidence`, `telemetry`, `alarm`, `dropped-at-source`.
Bare "lane" outside the twelve-channel sense goes on
`tools/check-copy-banned-terms.sh` next to bare "lease". The corresponding
renames requested of peers — 04's inbox categories to *queues*, 05's hue
taxonomy to *pillars* — are listed in §14 and are theirs to make.

---

## Decisions made here

1. **Ingress is one in-process `broadcast::Receiver`, drained into a disk spool before any Nostr I/O.** The spool is not an optimization; at measured ingest rates the 1,024-slot broadcast overflows after ~281 ms of stall.
2. **Four streams, not one.** Every `RuntimeEvent` variant is assigned to `evidence` (durable kind:9 card), `telemetry` (ephemeral, coalesced), `alarm` (durable, never coalesced, never shed) or `dropped-at-source`, by an exhaustive Rust `match` on `RuntimeEvent` with no `_` arm, so a twelfth variant upstream fails to compile.
3. **`created_at` is a transport timestamp stamped at publish, never at emit.** This is forced, not preferred: the relay rejects any event whose `created_at` is more than 900 s from server time (`BUZZ/crates/buzz-relay/src/handlers/ingest.rs:2224-2231`), so a true-emit-time design cannot drain a spool after a 16-minute outage at all. The domain time is `emitted_at_ms` in the body, and every Perch surface sorts and renders on the body. §5.2.
4. **The pacer is written fresh in `swarm-perch-bridge` against buzz-acp's stated invariants, not ported.** `ObserverPublishQueue` is a private struct (`BUZZ/crates/buzz-acp/src/lib.rs:440`, no `pub`) inside a crate `02-ARCHITECTURE-INTEGRATION.md` deletes. The invariants are the specification; the code is not lifted, so there is no second vendoring event. §5.3.
5. **Capacity comes from identity count, not from raising a limit.** Rate limits are keyed `buzz:{community}:ratelimit:{pubkey}:{suffix}` (`BUZZ/crates/buzz-auth/src/rate_limit.rs:167-172`), so eight per-agent Nostr identities plus one telemetry and one alarm identity buy 10 × 120/min.
6. **Every published envelope carries a per-issuer monotonic `seq`.** A gap renders as a labelled gap row with a **re-fetch from the daemon** affordance; it is never smoothed over and it is never healed by re-requesting from the relay.
7. **The bridge's signature proves publication, not provenance.** Four of the seven marker card types (finding, escalation, hold, lease) wrap objects that carry no Ed25519 signature at all. Until the daemon wraps its facts in `build_signed_envelope` (§5.4, offered to 03 as backend item 6), "verify" means *re-fetch from the daemon and diff the canonical bytes*, and the copy says exactly that.
8. **Concentration decay is computed server-side and *interpolated* client-side, with the interpolation labelled.** The runtime's `ConcentrationSnapshot.total_strength` is authoritative; the client curve is a marked derivation that snaps visibly with a reason row on disagreement.
9. **Two clock domains are typed apart at the TypeScript boundary** — `UnixSeconds` for pheromone timestamps, `UnixMillis` for everything else. A shared `now()` helper is banned.
10. **No optimistic UI on any governance path.** A grant, refusal, release, or finding verdict renders `sending → recorded → daemon-acknowledged` as three distinct states. Optimistic updates are allowed only for read-state, snooze, and canvas text.
11. **The needs-action queue is reconciled against the daemon, not trusted from the relay.** Buzz's mention index is written *outside* the event's transaction and a failure is a `warn!` (§5.6), so a hold can be stored, OK'd, and permanently invisible to `query_needs_action`. The relay carries the notification; the daemon's open-hold list is the queue's authority.
12. **Query keys are a typed factory whose first element is the source**, replacing Buzz's hand-maintained 34-root allowlist (`BUZZ/desktop/src/shared/api/relayQueryInvalidation.ts:1-35`), with two healing predicates because relay and daemon fail independently.
13. **`resetCommunityState` becomes `Record<ColonyScopedSingleton, () => void>`** — a mapped type over a string union, which fails to compile when a module-level singleton is added without a resetter.
14. **The Substrate view is hand-authored SVG rebuilt at 1 Hz in a `useMemo`, with a 4 ms scripting budget per tick**, measured with the existing CDP harness. No charting library, no canvas.
15. **The first (and for v1, only) Web Worker parses and verifies spool replay batches.** Buzz ships zero workers today; this is net-new and scoped to one job.
16. **Retention is a monthly `DETACH PARTITION` job Perch adds.** Buzz creates partitions forward and never drops one (`BUZZ/crates/buzz-db/src/store/partition.rs:1-57`).
17. **Timestamps render in a colony-configured zone with an explicit UTC toggle.** Buzz hardcodes `en-US` and never passes `timeZone` (`BUZZ/desktop/src/shared/lib/datetime.ts:14-47`).
18. **Perf budgets are numbers in `playwright.perf.config.ts`**, extending the five specs Buzz already ships, plus three end-to-end hop budgets stamped by the bridge. The C9 counters' Phase-1 home is **The Watch (`/`)**, the only Phase-1 surface.

---

## 1. The path, hop by hop

```
 ┌── swarm_detect --serve (:9090) ─ sole writer, holds every store ────────────┐
 │ POST /v1/ingest/events                                                      │
 │   → detector → signed deposit → policy → receipt → ReplayBundle             │
 │   → publish_runtime_event(RuntimeEvent::…)   [ingest/mod.rs:1913]           │
 │        │                                                                    │
 │        ├─► tokio::broadcast, capacity 1_024   [runtime_events.rs:13]        │
 │        │        │                                                           │
 │        │        ├─► SSE /v1/events/stream  ✗ NOT USED (see §2)              │
 │        │        └─► swarm-perch-bridge  ◄── IngestState::subscribe_         │
 │        │                 │                   runtime_events() [mod.rs:1875] │
 │        └─ ConcentrationMonitor @ 10 Hz  [swarm_detect.rs:40,1004]           │
 └─────────────────────────────────────────────────────────────────────────────┘
                            │  (in-process, same address space)
                            ▼
        ┌── swarm-perch-bridge ──────────────────────────────────────┐
        │ recv loop → classify → APPEND TO DISK SPOOL (never blocks) │
        │ pacer @ 1 Hz → pack ≤64 KB → stamp created_at → sign       │
        │                (secp256k1) → EVENT                         │
        └────────────────────────────────────────────────────────────┘
                            │ WebSocket, NIP-42, one per identity
                            ▼
   ┌── buzz-relay ───────────────────────────────────────────────────────┐
   │ enforce_ws_admission  [connection.rs:652-708]  ← THE CEILING        │
   │ verify_event → ±900 s created_at gate [ingest.rs:2224] → 256 KB     │
   │   content gate [ingest.rs:2233] → Postgres INSERT                   │
   │   + BEFORE INSERT: roster-snapshot guard    [schema.sql:1074]       │
   │   + AFTER INSERT: enqueue_push_match        [schema.sql:949]        │
   │   + DEFERRED constraint: refresh_channel_ttl [schema.sql:995]       │
   │   + DEFERRED constraint: created_at_floor    [schema.sql:1115]      │
   │   + out-of-transaction, best-effort: insert_mentions [runtime/      │
   │     mod.rs:945]  ← §5.6                                             │
   │ → Redis PUBLISH buzz:{community}:channel:{uuid}                     │
   │ → subscriber loop → fan_out_scoped → filter_fanout_by_access        │
   │                                       [event.rs:116-217]            │
   └─────────────────────────────────────────────────────────────────────┘
                            │ WS frame
                            ▼
   ┌── Perch (Tauri) ────────────────────────────────────────────────────┐
   │ plugin:websocket → Channel<unknown> → relayInboundBuffer (256 cap)  │
   │   [relayClientSession.ts:545-556; relayInboundBuffer.ts:1]          │
   │ → handleWsMessage → subscription dispatch → React Query cache       │
   │ → memo boundary → virtualized row → paint                           │
   └─────────────────────────────────────────────────────────────────────┘
```

**Latency budget.** Two hops are measured; the rest are targets this document
sets and §12 tests. The pacer tick dominates by design and that is the correct
trade: a verdict queue is not a trading terminal.

| Hop | Budget (p95) | Source |
|---|---|---|
| Telemetry POST → `ReplayBundle` persisted | **8.14 ms** (measured, `local_journal`) | `AMB/README.md:536` |
| `publish_runtime_event` → bridge `recv()` | < 1 ms | in-process broadcast |
| Bridge classify + spool append | ≤ 2 ms | target, no fsync per record |
| Spool → pacer slot | **0–1000 ms**, mean 500 ms | by construction, §5.3 |
| Stamp + sign + WS send + relay admit + verify | ≤ 60 ms | target |
| Postgres insert + four triggers | ≤ 40 ms | target; see the trigger note |
| Redis publish → fan-out → WS frame | ≤ 30 ms | target |
| Frame → React Query cache → paint | ≤ 80 ms | target, §9 |
| **Ingest → visible row in a case** | **≤ 1.3 s** | sum |
| **Alarm stream (held action) end to end** | **≤ 400 ms** | alarm bypasses the pacer, §4 |

**Note on trigger cost, corrected.** `events` carries four triggers, not two
(`BUZZ/schema/schema.sql:949, 995, 1074, 1115`). Two are `DEFERRABLE INITIALLY
DEFERRED` constraint triggers, so their cost lands at `COMMIT`, not at
`INSERT`. `refresh_channel_ttl_after_event_insert` takes a **shared** per-channel
advisory lock — the comment at `schema.sql:955-959` states this explicitly, and
shared means permanent-channel commits admit each other rather than serializing
— then `SELECT`s `ttl_seconds` and `UPDATE`s the `channels` row only when a TTL
is set. TTL case channels are the brief's chosen shape, so **every evidence card
in a case carries one extra row update**, and it is one more independent reason
the pacer exists.

One honest consequence to carry into the case-TTL design: that trigger's
`EXCEPTION WHEN OTHERS` arm downgrades a failed TTL refresh to a
`RAISE WARNING` (`schema.sql:984-988`) so it cannot reject a valid event. A case
channel whose refresh silently fails keeps a stale `ttl_deadline` and can archive
under an active investigation. Perch therefore treats the daemon's case record,
not the channel row, as the answer to "is this case open", and `/handoff` reads
open cases from the daemon.

---

## 2. Transport: what exists, and what we refuse

| Candidate | What it actually is | Verdict |
|---|---|---|
| `GET /v1/events/stream` (SSE) | All 11 kinds, `event:` = kind slug, `id:` = `emitted_at_ms`, 15 s keepalive, wrapped in `Access-Control-Allow-Origin: *` (`AMB/crates/swarm-ingest-runtime/src/ingest/demo.rs:1644-1718`). Unauthenticated: `resolve_demo_scope` returns the caller's requested scope when no `context_token` is present (`ingest/mod.rs:636-652`). Silently drops lagged frames: `let Ok(event) = result else { return None }`. No `Last-Event-ID` resumption. Served over TLS with `keep_alive(false)` and ALPN pinned to http/1.1. | **Rejected as Perch's transport. Gated regardless** — it leaks tamper alerts with library paths, receipt ids and arbitrary agent `details` to anyone who can reach :9090. |
| `GET /v2/api/stream/findings` and the rest of `/v2/api` | Bearer + `x-api-key`. Serializes only the inner `SwarmFindingEnvelope`, discarding `host_id` and `emitted_at_ms` from the enclosing `RuntimeEvent::Finding` (`platform_api.rs:1391-1414`). The list path is worse than slow: `load_platform_findings` calls `store.recent(usize::MAX)` and then `load_by_bundle_id` **once per record** (`platform_api.rs:720-740`) — a full scan plus an N+1, per request. | **Rejected.** A finding you cannot attribute to a host is not evidence, and a console that polls a full scan is a self-inflicted outage. |
| In-process `subscribe_runtime_events()` | `Option<broadcast::Receiver<RuntimeEvent>>`, returns `None` when the runtime has no broadcaster (`AMB/crates/swarm-ingest-runtime/src/ingest/mod.rs:1875-1881`). Called by whatever is mounted into `swarm_detect --serve`; the bridge is mounted there (02, decision 3), so this is a same-process call, not a hop. | **Chosen.** Deletes the absent CORS layer, the unauthenticated route, the SSE-hostile TLS config and one network hop, exactly as the brief settled. `None` is a real state: the bridge refuses to start and says the runtime has no broadcaster, rather than idling silently. |
| Tauri `Channel<T>` for daemon→UI push | Already the relay socket's IPC primitive (`BUZZ/desktop/src/shared/api/relayClientSession.ts:1,545-556`). | **Chosen for the local IPC path only** — hold decisions, lease TTL ticks, spool health. Not for evidence. |
| `buzz-ws-client` for egress | 314 lines: connect → wait AUTH challenge → sign kind:22242 → `send_event`. But `send_event` is *strictly serial*: send, then `wait_for_ok` up to 30 s (`BUZZ/crates/buzz-ws-client/src/connection.rs:96-101`). | **Chosen, with one change**: the bridge uses `send_raw` plus a separate OK-reaper task. One in-flight event per connection is an RTT-bound ceiling we cannot afford even at 1 Hz with ten identities. |
| `POST /events` HTTP bridge | Rejects kind 1059 and kind 20001 (`BUZZ/crates/buzz-relay/src/handlers/ingest.rs:2193-2196`). | **Rejected for the telemetry stream.** Ephemerals need the socket. |

**The shipped Python client is an open scope question, and it is 02's to close.**
`clients/python/swarm-platform-client/` is a real, generated OpenAPI client in the
Ambush tree (`client.py`, `types.py`, ~20 model modules, plus
`clients/python/smoke_platform_client.py`), and it is an external contract against
the same `/v2/api` surface this section rejects and whose list path melts under
polling. Perch does not poll `/v2/api` — that is settled here — but that
statement covers Perch and not the client that already polls it. Whether
`/v2/api` is frozen at its current shape, kept working, or deprecated with a date
belongs in `02-ARCHITECTURE-INTEGRATION.md`'s module-by-module verdict tables;
this document flags it as unowned rather than deciding it. Recorded in §14.

**Why the receive loop must not do Nostr I/O.** `DEFAULT_RUNTIME_EVENT_CAPACITY`
is `1_024` (`AMB/crates/swarm-runtime/src/runtime_events.rs:13`). A lagged
`broadcast::Receiver` drops the oldest frames and the SSE handler's pattern
throws the `Err` away without counting it. At the measured end-to-end rate of
3,645 events/sec, `RuntimeEvent::Ingest` alone (published once per accepted
event, `ingest/mod.rs:1122,1135,1200`) fills 1,024 slots in **281 ms**. Any Nostr
write, any DNS lookup, any TLS handshake inside the receive loop exceeds that.
The loop does exactly three things: `recv()`, classify, append.

---

## 3. What Ambush produces vs what the relay accepts

### Production, at rest and under load

| Producer | Rate | Source |
|---|---|---|
| `RuntimeEvent::ConcentrationSnapshot` | **10 Hz, always**, each carrying 12 `RuntimeThreatConcentration` | `CONCENTRATION_MONITOR_INTERVAL_MS = 100` (`AMB/crates/swarm-runtime-http/src/bin/swarm_detect.rs:40,1004`); `snapshot_concentrations` loops `standard_threat_classes()` (escalation.rs:267-278, 315-330) and publishes every tick (escalation.rs:198-199) |
| `RuntimeEvent::Ingest` | 1 per accepted telemetry event; hot path sustains 6,364/s in-memory, 3,645/s over HTTP | `ingest/mod.rs:1122,1135,1200`; `AMB/README.md:528,536` |
| `RuntimeEvent::AgentAction` | **1 per agent turn per action**, plus governance drains and restarts | `dispatcher.rs:940-958` (`publish_agent_action`), `:1034` (governance drain), `:1139` (`agent_restart`) |
| `RuntimeEvent::Finding` | 1 per detector finding; a burst multiplies per strategy | `providence_handlers.rs:779`, `publish_runtime_findings` |
| `RuntimeEvent::AgentHealth` | transition-only | `runtime_events.rs:276-282` |
| `RuntimeEvent::Escalation` / `ModeTransition` | rare, event-driven | `escalation.rs:246,292` |
| `RuntimeEvent::TamperAlert` | anti-tamper loop, default 5 s check interval | `AMB/crates/swarm-core/src/config/defaults.rs:61` |

At rest, with zero telemetry, the broadcast still carries **864,000
ConcentrationSnapshots per day**.

### The relay's ceiling

`enforce_ws_admission` runs on every `EVENT`, `REQ` and `COUNT` frame
(`BUZZ/crates/buzz-relay/src/connection.rs:652-708`):

| Gate | Default | Applies to |
|---|---|---|
| `LimitType::WsEvents` | `human_ws_events_per_sec` = **10** (`rate_limit.rs:123-125`), evaluated over a 5 s window as 50 (`admission.rs:9,39-44`) | every EVENT/REQ/COUNT, agent or human |
| `LimitType::Messages` | `agent_standard_messages_per_min` = **120** (2/s, `rate_limit.rs:126-128`) for any connection whose auth context has `agent_owner_pubkey`; `human_messages_per_min` = 60 otherwise (`rate_limit.rs:117-119`) | every EVENT — **ephemerals included** |

Four findings that shape the whole design:

- **Ephemerals are not free.** `is_event = matches!(msg, ClientMessage::Event(_))`
  (`connection.rs:657`) is computed on the raw client message, before any kind
  dispatch. A kind-26xxx telemetry event bills the same 120/min quota as a
  kind:9 card. The brief's "coalesce to 1 Hz before IPC" is therefore not a UI
  nicety — it is the only rate the relay will admit.
- **The elevated and platform tiers are dead.** `agent_elevated_messages_per_min`
  and `agent_platform_messages_per_min` are defined (`rate_limit.rs:111,114`),
  defaulted (300, 600, `:143-152`) and settable by env
  (`BUZZ/crates/buzz-relay/src/config.rs:418-426`) but read by **no enforcement
  site** — verified by grep across `crates/`; `connection.rs:690` always selects
  `agent_standard_messages_per_min`. Do not plan capacity on them. Raising the
  standard tier is the only lever, and it raises it for every agent.
- **Quotas are per-pubkey.** `rate_limit_key` is
  `buzz:{community}:ratelimit:{pubkey}:{suffix}` (`rate_limit.rs:167-172`), so
  identity count *is* capacity.
- **Admission fails closed on a Redis outage.** `check_principal` returns
  `AdmissionError::Unavailable` when the limiter errors (`admission.rs:33-36`),
  and `send_admission_result` rejects the frame with
  `rate-limited: shared admission unavailable` (`connection.rs:728-735`). A
  Redis outage therefore stops the bridge publishing **entirely**, presenting as
  per-frame rejections rather than a disconnect, and that string carries no
  `retry in Ns` hint — so `parseRateLimitHint` returns `null` and the client gate
  falls back to `DEFAULT_RATE_LIMIT_SECONDS = 10`
  (`BUZZ/desktop/src/shared/api/relayRateLimitGate.ts:15,39-41,56-60`). The
  bridge needs its own exponential backoff for this case and must render it as a
  distinct failure in §10's table, not as "relay unreachable".

### The gap, and the arithmetic that closes it

3,645 events/sec produced; 2 events/sec admitted per identity. **1,822:1.** The
brief already chose one Nostr identity per agent for attribution; that choice
also buys the capacity:

| Identity | Stream | Budget spent |
|---|---|---|
| 8 × `swarm:ed25519:<hex>` agent keys | evidence cards, 1 Hz each | 8 × 60/min of 8 × 120 |
| 1 × `perch-telemetry` | ephemeral concentration / agent frames / ingest gauge, 1 Hz | 60/min of 120 |
| 1 × `perch-alarm` | holds, mode transitions, tamper, lease failures | ≤ 10/min, large headroom |

Total sustained ≈ **10 events/sec across ten sockets**, half of each pubkey's
quota, exactly the headroom rule Buzz's own harness documents for observer
frames (`BUZZ/crates/buzz-acp/src/lib.rs:386-393`). Everything above that rate is
coalesced or shed, visibly.

**Twelve lanes are inside that budget, not outside it.** The twelve standing
threat-class channels do not each get an identity or a publish slot: an
`Escalation` is last-wins per threat class per slot on the evidence stream
(§4), and the lane topic line is rewritten from the 1 Hz telemetry frame the
client already has, not from a per-lane write. A per-lane topic write at 1 Hz
would be 720 events/min against a 120/min quota, and Buzz's topic write is a
durable system message per write — 12 × 86,400 rows/day for a gauge. The lane
header reads the telemetry frame; nothing is written per lane per tick.

---

## 4. The four streams

Each `RuntimeEvent` variant gets exactly one stream, assigned by an exhaustive
`match` on `RuntimeEvent` in `swarm-perch-bridge` with **no `_` arm**, so the
twelfth variant fails to compile. `RuntimeEvent` has eleven variants today
(`AMB/crates/swarm-runtime/src/runtime_events.rs:214-305`), and
`RuntimeEventKind` (`:127`) with its `kind()` accessor (`:324-337`) is the key
the lane spec is declared against. The previous draft's table listed ten and
silently omitted `AgentAction`; that is fixed here.

| RuntimeEvent variant | Stream | Wire (owned by 03) | Coalescing | Over-production |
|---|---|---|---|---|
| `ResponseHeld` *(proposed 12th variant, 03 §11 item 1)* | **alarm** | `kind:46010` + `ambush:hold:v1`, `p` tag per on-shift operator, `h` = case channel | none | never shed; see the alarm rule below |
| `ModeTransition` | **alarm** + telemetry | ephemeral `26003`; **plus an `ambush:escalation:v1` card with `broadcast=1` when `to == Incident`** (03 §4.2) | none | never shed |
| `TamperAlert` | **alarm** + telemetry | ephemeral `26005` (counts only); **plus an `ambush:escalation:v1` card when `fail_closed`** (03 §4.2) | none | never shed |
| `Escalation` | **evidence** | `kind:9` + `ambush:escalation:v1`, lane channel | last-wins per threat class per slot | oldest-first eviction, counted |
| `Finding` | **evidence** | `kind:9` + `ambush:finding:v1`, lane channel | batch by `(threat_class, host_id)` within a slot | oldest-first eviction, counted |
| `ResponseExecution` | **evidence** | `kind:9` + `ambush:receipt:v1`, case channel | none | oldest-first eviction, counted |
| `ConcentrationSnapshot` | **telemetry** | ephemeral `26001` | **last-wins, 10→1** | drop older; last-wins is lossless in meaning |
| `AgentHealth` | **telemetry** | ephemeral `26002` | last-wins per `agent_id` | drop older |
| `AgentAction` | **telemetry** | folded into the same `26002` agent frame as a per-agent `{action_kind: count}` tally. **`details` never crosses the wire.** | rolled up per tick | drop older |
| `Ingest` | **dropped at source** | reduced to the `26000` rate gauge `{accepted, rejected, by_source}` | n/a | n/a |
| `Replay` | **dropped at source** | not published (03 §4.2, lane H) — `/watch-floor` and the case PTY read the daemon | n/a | n/a |
| `EvolutionStatus` | **dropped at source** | not published (03 §4.2, lane H) — `/tuning` reads the daemon | n/a | n/a |

**Three markers this document previously invented are withdrawn.** The earlier
draft wired `ModeTransition` → `ambush:mode:v1`, `TamperAlert` →
`ambush:tamper:v1`, `EvolutionStatus` → `ambush:evolution:v1`, and put `Replay`
on the relay as a durable card. `03-DOMAIN-EVENT-MAPPING.md` owns the wire
(§decision 1), freezes exactly **seven** markers (§decision 2 — the seventh,
`ambush:verdict:v1`, replaces the withdrawn 46030/46031 carrier) with a
change-control rule in §13, and routes all four differently. 07 does not get to add
a marker in a table; the seven stand, and this document routes through them.

**`AgentAction.details` is dropped at the bridge, and there is nothing to fetch.**
`publish_agent_action` sets `details: serde_json::to_value(action)` over the
entire `SwarmAction` (`dispatcher.rs:951`), which is why `08-TRUST-AND-
GOVERNANCE-UX.md` §7.7 classes it adversary-influenced. There is no durable store
and no route for it: the operator router registers 49 routes
(`AMB/crates/swarm-runtime-http/src/http/state.rs:294-485`) and none serves agent
actions, so "fetch the full `details` from the daemon on demand" would be
fiction. The bridge publishes tallies only. The tally key is `action_kind`, and
its vocabulary is **not** closed: nine `&'static str` values from
`swarm_action_kind` (`dispatcher.rs:1251-1263`), plus the literal
`"agent_restart"` (`:1142`), plus whatever `governance_policy
.drain_runtime_events()` supplies (`:1034`). The bridge allowlists the known set
and buckets everything else as `other` rather than assuming the set is closed.
If the swarm's narrative turns out to be worth more than a tally, the honest fix
is a sixth Ambush route argued in 03 — not a seventh marker.

**`Ingest` is the one stream we refuse to carry.** Publishing one relay event per
ingested telemetry event is the naive design and it is wrong at every layer: it
exceeds the quota by 1,800×, it fills the case channel with rows no operator
reads, it doubles Postgres write volume, and it is *already* recorded — the
`ReplayBundle` carries the event (`AMB/crates/swarm-spine/src/lib.rs:126`). The
console shows an ingest **rate**, and the drill-down is the case-scoped
`swarmctl` terminal, which is where the raw record actually lives. Rejected
alternative: sampling 1-in-N `Ingest` events. A 1-in-N sample of a security
event stream is worse than a rate, because it looks like a record.

**The alarm rule, stated once so it cannot be re-stated wrong.** The earlier
draft's table said the alarm stream's overflow behaviour was "spool blocks",
which contradicted this document's own receive-loop rule two sections later. A
blocking spool write inside `recv()` drops *every* stream silently after 281 ms —
precisely the correctness bug the spool exists to prevent. The correct
behaviour, matching §5.5, is three-tiered:

1. Alarm work is **never coalesced and never shed**.
2. When the alarm spool cannot drain, the bridge **stops accepting evidence-stream
   work** — the evidence stream sheds so the alarm stream keeps its budget — and
   the governance strip says `holds are not reaching the console`.
3. If the alarm spool itself reaches its own budget, the bridge **refuses new
   alarm work and alarms**: it logs, increments
   `perch_bridge_alarm_spool_full_total`, and surfaces the refusal. It never
   blocks `recv()`. A bridge that blocks its receive loop to protect one stream
   destroys all four.

---

## 5. Backpressure, coalescing, shedding — and saying so

### 5.1 The spool

```rust
// AMB/crates/swarm-perch-bridge/src/spool.rs  (proposed)
//
// The receive loop's ONLY job. DEFAULT_RUNTIME_EVENT_CAPACITY is 1_024
// (swarm-runtime/src/runtime_events.rs:13) and a lagged receiver drops
// silently; at the measured 3,645 events/sec that is 281 ms of head room.
// Nothing that can block — no TLS, no DNS, no fsync-per-record — runs here.
loop {
    match rx.recv().await {
        Ok(event) => spool.append(stream_of(&event), event)?,   // <= 2 ms
        Err(RecvError::Lagged(n)) => {
            // The one case the SSE handler throws away. We count it, and the
            // count reaches the operator as a gap row, not as nothing.
            spool.append_gap(GapCause::BroadcastLagged, n)?;
            metrics::counter!("perch_bridge_broadcast_lagged_total").increment(n);
        }
        Err(RecvError::Closed) => break,
    }
}
```

The spool is a segmented append-only log with a committed-offset cursor,
`fsync` on segment roll rather than per record. It survives a bridge crash and a
relay outage; on restart the pacer resumes from the cursor. **It holds unsigned
bodies**: `created_at` is stamped and the envelope signed in the pacer, at
publish time (§5.2), so nothing in the spool is a signed artifact and the spool
is not a second record.

### 5.2 The publish window is 900 seconds, and that decides the timestamp rule

This is the correction that inverts a design decision. The earlier draft said
"the bridge stamps `created_at` from the daemon's clock (the same source as
`emitted_at_ms`)" and budgeted a 256 MiB spool at **~68 minutes** of sustained
over-production. Those two statements cannot both hold, because of a relay gate
the draft cited by its client-side mirror and never checked server-side:

| Gate | Value | Where | What it does to the data |
|---|---|---|---|
| `MAX_TIMESTAMP_DRIFT_SECS` | **900 s, both directions** | `BUZZ/crates/buzz-relay/src/handlers/ingest.rs:2224-2231` | **Rejects** the event: `invalid: event timestamp too far from server time`. Runs after signature verification, before scope resolution. |
| `CREATED_AT_FLOOR_SECS` | 960 s | `BUZZ/crates/buzz-db/src/runtime/replica_fence.rs:74`, armed as the `buzz.created_at_floor` GUC on the writer pool (`runtime/mod.rs:524`) | A `DEFERRABLE INITIALLY DEFERRED` constraint trigger (`schema.sql:1115-1120`) raises `check_violation` at `COMMIT` for any channel-bearing row older than the floor. Deliberately looser than the ingest envelope (`replica_fence.rs:68-73`), so it never fires for an event that passed ingest. |
| `MAX_EVENT_CONTENT_BYTES` | 256 KB | `ingest.rs:2233-2240` | Rejects oversized content. Our 64 KB frame sits well under it. |

So a spooled evidence card that carries its true emit time in `created_at`
becomes **permanently unpublishable 15 minutes after it was produced**. A 68-
minute spool under that design drains 15 minutes of backlog and then rejects
every remaining frame, one at a time, forever. And `created_at` is inside the
Nostr signature, so it cannot be corrected after the fact without re-signing.

**Decision, forced rather than preferred:**

- **`created_at` is stamped at publish time**, from the daemon's clock, inside
  the pacer, immediately before signing. It is a transport timestamp and the
  copy calls it one.
- **`emitted_at_ms` in the body is the domain timestamp.** Every Perch surface
  sorts and renders on it. Buzz's own comparator sorts on `(created_at, id)`
  (`BUZZ/desktop/src/shared/api/relayClientShared.ts:114-125`); Perch's case
  timeline comparator sorts on the body's `emitted_at_ms` when present and falls
  back to `created_at` when it is not, so a backlog drain does not reorder an
  incident.
- **When they disagree by more than two pacer ticks, the row is marked
  `late-published`** and names the delta: `late-published — held in the bridge
  spool 22 min`. The disagreement is a rendered fact, not a smoothed one.
- The spool budget stays 256 MiB per stream, and it is now honest: it is
  **storage** depth, decoupled from the relay's drift window. `~68 minutes` of
  sustained over-production before eviction is the storage claim; the
  publishability claim is unbounded, because the timestamp is stamped at drain.

The same rule is what makes the reconnect-replay lookback intelligible:
`RECONNECT_REPLAY_CHANNEL_LOOKBACK_SECS = 900 + 960 + 5 = 1,865 s`
(`BUZZ/desktop/src/shared/api/relayReconnectReplay.ts:17-28`) is the ingest
envelope plus the storage fence plus clock margin — all three of which are now
verified server-side rather than inferred from the client constant.

### 5.3 The pacer: written fresh, against a specification we can cite

`ObserverPublishQueue` is **private** — `struct ObserverPublishQueue` at
`BUZZ/crates/buzz-acp/src/lib.rs:440`, no `pub` — inside `buzz-acp`, which
`02-ARCHITECTURE-INTEGRATION.md` §5 deletes outright. The pacer is needed in
`swarm-perch-bridge`, in the Ambush workspace, which 02's decision 2 says never
gains a Buzz crate. "Ported" therefore meant a second act of vendoring
Apache-2.0 code that 02's NOTICE paragraph does not cover, that its dependency
bill does not count, and that would hit the same `unwrap_used`/`expect_used`
problem as the ws client.

**The pacer is written fresh in `swarm-perch-bridge`.** What we take is the
specification, and buzz-acp states it in prose we can cite line by line:

| Constant / rule | Perch value | The invariant, and where it is stated |
|---|---|---|
| Publish tick | `PERCH_PUBLISH_TICK` = 1 s | *"AT MOST ONE relay frame per tick — not one per channel, and not one per drain… At 1 frame/s telemetry spends at most 60/min — half that budget"* (`BUZZ/crates/buzz-acp/src/lib.rs:382-394`). |
| Frame size | `PERCH_FRAME_MAX_BYTES` = 64 KB | Mirrors `OBSERVER_MAX_PLAINTEXT_LEN = 65_535` (`BUZZ/crates/buzz-core/src/observer.rs:25`). Under both `DEFAULT_MAX_FRAME_BYTES = 512 KiB` (`BUZZ/crates/buzz-relay/src/config.rs:14`) and `MAX_EVENT_CONTENT_BYTES = 256 KB` (`ingest.rs:2233`), so a full frame is never a protocol risk. |
| Retention budget | `PERCH_SPOOL_MAX_BYTES` = 256 MiB per stream | *"a single channel drains at ~64KB/s and 4 MiB buys roughly 64 seconds of sustained over-production before the oldest items are dropped WITH accounting"* (`lib.rs:396-413`). Scaling that documented ratio: 256 MiB ≈ 68 minutes of storage. A security console gets a disk and an hour. |
| Eviction | oldest first, counted | *"the OLDEST events are dropped (the viewer wants recent state) with accounting"* (`lib.rs:434-439`). |
| Accounting invariant | `ingested == dropped + Σ source_events over published` | Stated verbatim at `lib.rs:453`. This is what makes "we dropped detail" a fact rather than a suspicion, and it is the one line of the specification that must be asserted in a unit test. |
| Packing | greedy over the **front run of one channel**, never a global scan | `next_frame` (`lib.rs:551-585`) takes `self.events.front()`'s `channel_id` and gathers only that channel's run. A front-run packer degrades to one event per slot under round-robin producers; a channel-scan packer starves the tail. Buzz learned that; we do not re-learn it, and we do not copy the code to inherit it. |

Everything above is a behavioural contract expressible as a test. The Perch
implementation is a few hundred lines of `?`-returning Rust that satisfies
Ambush's `unwrap_used = "deny"` natively, adds no NOTICE obligation, and adds
nothing to 02's dependency bill.

### 5.4 What the bridge can and cannot sign

The doc set's integrity story rested on a claim that does not survive reading
the types. **Four of the seven marker card types — finding, escalation, hold,
lease — wrap objects that carry no signature at all**, and the chain machinery the set cites is nearly dead code.

| Marker (03, frozen) | Underlying type | Signature today |
|---|---|---|
| `ambush:finding:v1` | `SwarmFindingEnvelope` (`AMB/crates/swarm-response/src/siem.rs:17-27`, 8 fields) from `DetectionFinding` (`AMB/crates/swarm-whisker/src/detector.rs:50-59`, 7 fields) | **None** |
| `ambush:escalation:v1` | `RuntimeEvent::Escalation` / `ModeTransition` / `TamperAlert` (`runtime_events.rs:286-305`); `EscalationRecord` (`swarm-core/src/pheromone.rs:238`) | **None** |
| `ambush:hold:v1` | the proposed `HeldActionStore` record | **None — and it does not exist yet, so this is the one free opportunity to add one** |
| `ambush:receipt:v1` | `ResponseReceipt` (`swarm-response/src/lib.rs:100-116`) + `AuditTrail` (`swarm-spine/src/lib.rs:113-122`) | **None.** `audit.governance.receipt` is an untyped `Option<serde_json::Value>` (`:136-142`); when present it is a serialized `ConsensusGovernanceReceipt`, which *is* signed — so this card is verifiable only in the nested, sometimes-present case. |
| `ambush:lease:v1` | `ContainmentLeaseView` (`swarm-runtime-http/src/http/containment.rs:70-90`) | **None** |
| `ambush:rollback:v1` | `RollbackReceipt` (`swarm-response/src/rollback.rs:242-286`) | **None of its own.** It carries ids back to the governance receipt (`:250-262`) and an opaque `governance_attestation: Option<serde_json::Value>` (`:285`) documented as excluded from its own subject and verifiable only by `swarm_runtime::containment::verify_release_attestation` (`:266-284`). Verifiable **iff** attested. |

And the chain:

- `build_signed_envelope` (`AMB/crates/swarm-spine/src/envelope.rs:71`) has
  **exactly one non-test, non-vendor caller in the whole workspace** —
  `crates/swarm-runtime/src/approval.rs:1810`, the approval ledger's vote
  envelope. Verified by grep over `crates/`.
- `verify_chain_link` / `ChainLinkVerdict` (`swarm-spine/src/chain.rs:20,75`)
  have **zero consumers outside swarm-spine's own module and tests**; the only
  other occurrence is the re-export at `swarm-spine/src/lib.rs:61`.
- The only routinely Ed25519-signed objects in the pipeline are
  `PheromoneDeposit.signature` (`swarm-core/src/pheromone.rs:231-232`) — which 03
  decides is never published — and `swarm-consensus` receipts.

**What this document therefore claims, precisely.** The bridge signs the Nostr
envelope with a secp256k1 key at publish time. That proves *this bridge
published this body*. The per-issuer `seq` proves *no envelope from this issuer
is missing*. Neither proves *the daemon said it*, and no wording in Perch may
imply otherwise.

**The verify affordance is renamed and re-specified.** It is
**"re-fetch from the daemon"**, not "verify signature". Contract: fetch the
authoritative object by the card's `locator`, canonicalize both sides with
RFC 8785, show a byte diff. Three outcomes, three distinct renderings:
`matches the daemon` / `differs from the daemon` (loud) / `daemon unreachable`
— and the third is **not** a pass.

**The upgrade path, offered to 03 as backend item 6.** Wrap each fact in
`build_signed_envelope(keypair, seq, prev_envelope_hash, fact, issued_at)`
before it leaves the daemon — the identical one-call pattern
`approval.rs:1802-1830` already uses, including its
`verify_envelope`-immediately-after check — and publish that envelope verbatim
in the card body. Three things become true at once: the bridge's per-issuer
`seq` *is* the spine's `seq`; a gap becomes a
`ChainLinkVerdict::SequenceMismatch` rather than a bridge-local counter; and the
verify affordance upgrades from a re-fetch to a local Ed25519 check with no
change to the wire format. This is one call site per fact and it is the change
that makes "the daemon's chain is the record" true rather than aspirational.
Sizing and ordering are 09's; the transport consequence is that **nothing in
this document depends on it**, and the transport is honest either way.

Until item 6 lands, three sentences elsewhere in the set cannot pass as written
and are listed in §14.

### 5.5 What the UI shows when it is dropping detail

Render law 4 in the brief ("derived-vs-served marking") extends to loss. Three
concrete rows, all in the domain's own words:

- **In a case channel, at the position where it happened:**
  `— 340 finding cards coalesced into 12 (bridge over budget 14:22:01–14:22:09) —`
  with a disclosure that lists the suppressed `(threat_class, host_id, count)`
  triples. This is a message row in the timeline, not a toast; it is part of the
  record of what the operator could see.
- **On a gap:** `— gap: sequence 4,118 → 4,393 from whisker-7a3f (275 envelopes
  not delivered) —` with a `re-fetch from the daemon` button that reads the
  daemon for the range. A gap is never smoothed by re-requesting from the relay,
  because the relay is not the record.
- **In the governance strip:** a `bridge: shedding` state alongside the four
  `PartitionState` values, using the same 2 s debounce as `useRelayConnection`
  (`BUZZ/desktop/src/shared/api/useRelayConnection.ts:24-56`). A strobing
  indicator teaches operators to ignore indicators.

Loss on the **alarm** stream is not shedable; the three-tier rule in §4 governs.

### 5.6 The mention-index hole, and why the queue reads the daemon

This is the second correction that changes a design decision rather than a
sentence, and it is the mechanism behind decision 11.

`query_needs_action` is an `INNER JOIN event_mentions` on `m.pubkey_hex` with
`kind IN (46010, 40007)` (`BUZZ/crates/buzz-db/src/store/feed.rs:181-192`).
`event_mentions` is populated **only** from `p` tags
(`BUZZ/crates/buzz-db/src/runtime/mod.rs:41-53`) — which resolves an item this
document previously listed as unverified. Two further facts change the design:

1. **Malformed p-tags are dropped silently.** A tag value that is not exactly
   64 ASCII-hex characters is filtered out with a `tracing::debug!`
   (`runtime/mod.rs:66-80`), and pubkeys are lowercased before insert (`:79`).
   An uppercase or truncated pubkey on a hold produces a stored event, an
   `OK true` to the publisher, and **no queue row**. The bridge therefore
   normalizes every `p` tag to lowercase 64-hex and asserts the length before
   signing; a failed assert is a bridge error, not a published event.
2. **The mention write is out-of-transaction and best-effort.**
   `insert_mentions` runs *after* `tx.commit()` and a failure is a
   `tracing::warn!(…, "Failed to insert mentions: {e}")`
   (`BUZZ/crates/buzz-db/src/runtime/mod.rs:943-948`, and identically at
   `store/event.rs:1361-1367`). The event is stored, the relay returns OK, and
   the hold is invisible to the needs-action queue **permanently** — a retry of
   the publish is deduplicated by event id, so the hole is not self-healing.

For Buzz a missed mention is a missed notification. For Perch it is a
destructive action awaiting a human that no human is shown.

**Decision.** The relay carries the hold's *notification*; the daemon's open-hold
list is the queue's *authority*. The Watch runs a `perchKeys.holds()` daemon
query on an interval and on focus, and reconciles it against the relay-sourced
needs-action queue. Three renderings:

| Daemon says | Relay says | Render |
|---|---|---|
| open hold | present in `needs_action` | normal row |
| open hold | **absent** | the row, from the daemon, with `not in the relay queue — notification may not have reached other operators` |
| no such hold | present | the row, marked `decided or expired — the daemon no longer holds this`, non-actionable |

The reconciliation counter `perch_queue_reconcile_divergences_total` is exported
from day one. A divergence is a bug in the notification path, and it must be
countable before anyone argues it does not happen.

---

## 6. Subscription model: how the client avoids the firehose

Buzz enforces a **symmetric scoping invariant** — global subscriptions never
receive channel-scoped events and channel subscriptions never receive global
events (`BUZZ/crates/buzz-relay/src/subscription.rs:487-492`). So "one firehose
REQ" is not merely discouraged, it is structurally unavailable. Good.

Ceilings: `max_subscriptions` 1024, `max_filters` 10 per REQ, `max_subid_length`
256, `max_limit` = `DEFAULT_MAX_PAGE_LIMIT`
(`BUZZ/crates/buzz-relay/src/nip11.rs:124-143`);
`MAX_EXPLICIT_CHANNEL_VALUES` = 128 `#h` values across one REQ's filters
(`BUZZ/crates/buzz-relay/src/handlers/req.rs:42,1110`).

| Surface | Subscription | Filters | Steady-state rate |
|---|---|---|---|
| The Watch `/` — live | one global REQ, ephemeral kind `[26006]`, `#p` = me | 1 | ≤ 10/min |
| The Watch `/` — authority | `query_needs_action` over HTTP on connect, on reconnect and on every `26006`, reconciled against `GET /v1/response/holds` | 0 | on demand |
| The Watch `/` — snoozes | one REQ, kind `[30300]`, `authors` = me (client-computed due times) | 1 | negligible |
| The Watch, lane movement | one REQ, `#h` = all 12 lane UUIDs, kinds `[9]`, `limit` 1 | 1 | ≤ 12/min (Escalation only) |
| Case `/cases/$caseId` | `subscribeToChannelLive` pattern, kinds = `CHANNEL_EVENT_KINDS` | 1 | 1–8/s while hot |
| `/lanes/$laneId` | reuses the Watch lane REQ | 0 extra | — |
| `/watch-floor` | one REQ, ephemeral kinds `[26000–26006]`, no `#h` (global) | 1 | 1/s |
| `/leases` | poll the daemon over Tauri, 5 s | 0 | — |
| `/ledger` | NIP-50 `search`, on submit only | 0 | — |
| Governance strip | rides the `/watch-floor` telemetry REQ | 0 | — |

(The route is `/watch-floor`, not `/watch`: 04's route table renames it because
`/watch` collided with The Watch at `/` — `04-SURFACES-AND-UX.md` §1.1, ratified as brief
amendment A3.)

**Twelve lanes on one REQ, not twelve REQs.** `#h` accepts up to 128 values;
twelve lane UUIDs in one filter costs one subscription slot instead of twelve.
The rejected alternative — a REQ per lane so each can carry its own `limit` — is
how you spend 12 slots and 12 admission tokens for a view nobody is reading.

**Open cases are subscribed lazily and torn down on navigation.** An operator
with 30 open cases who subscribes to all of them burns 30 slots and 30× the
fan-out. The Watch's `activity` queue already tells them a case moved. Rejected
alternative: a persistent per-case subscription for accurate unread counts. Buzz
already solves unread with read frontiers in `AppShellContext`
(`BUZZ/desktop/src/app/AppShellContext.tsx:11-123`) plus server-side thread
counters, and does not need the socket open.

**Two corrections this revision owes `03` §5.4, which settled both against this document.**

First, **a REQ of `{kinds:[46010], "#p":[me]}` cannot work at all.** The two-arm fork makes
`46010` channel-scoped, and `fan_out_scoped` routes an event with `channel_id = Some(..)`
through the channel indexes only (`BUZZ/crates/buzz-relay/src/subscription.rs:387-423`), while a
REQ with no `#h` registers as a *global* subscription — the invariant is stated outright at
`:486-491`. The HTTP backfill still works, so the defect is invisible in a cold-load test and
shows only as "the queue never updates live". The live path is therefore the ephemeral **`26006`
alarm frame** (global, no `h`, `p` = each Approve-scoped operator); the durable `46010` is the
record and `query_needs_action` plus the daemon's hold list are the authority. **The ≤ 400 ms
budget in §1 is a budget on the alarm frame, not on the durable row**, and it is relabelled as
such. A Perch that is disconnected when the alarm fires misses it, which is exactly why the
queue re-reads on connect, on reconnect and on every alarm.

Second, **`/handoff` does not re-publish open holds.** `event_mentions` rows come from the `p`
tags on the *stored* event, so re-tagging means publishing a second, differently-signed hold —
a duplicate signed by the wrong key. `03` §5.4 settles the v1 answer: the bridge `p`-tags **every
operator principal holding `OperatorScope::Approve`** (`OperatorAuthConfig::effective_principals()`,
`swarm-core/src/config/operator.rs:153-168`), which in the shipped default is exactly one person.
Per-shift `p`-tag routing is a named, priced v2 item (`on_shift_operator_pubkeys` plus
`POST /v1/operator/watch/claim`), not an assumption.

**What `04` §2.11's watch claim still governs, and it is not the `p` tag.** The claim is a
client-side *paging* filter: every Approve-scoped operator's queue receives the row, and only the
claim holder's client raises an OS notification for wake classes 1–3 (`04` §3.2). That needs no
bridge read of the relay and no daemon field, which is why the two decisions are compatible even
though they read like rivals. With no claim held, everyone pages.

---

## 7. Client state architecture

### Query keys

Buzz has ~50 flat per-feature key constants, no factory, and one hand-maintained
allowlist of exactly 34 relay-dependent key roots that reconnect healing consults
(`BUZZ/desktop/src/shared/api/relayQueryInvalidation.ts:1-35`, counted). The
landmine is documented and real: a new surface that forgets to register goes
stale after every reconnect, silently, and only under network churn. Perch
replaces the allowlist with a property of the key:

```ts
// desktop/src/shared/api/perchKeys.ts
type Source = "relay" | "daemon" | "local";

const key = <const S extends Source, const P extends readonly unknown[]>(
  source: S, ...parts: P
) => [source, ...parts] as const;

export const perchKeys = {
  holds:        ()            => key("daemon", "holds"),
  hold:         (id: string)  => key("daemon", "hold", id),
  leases:       ()            => key("daemon", "leases"),
  deposits:     (tc: string)  => key("daemon", "deposits", tc),
  caseTimeline: (id: string)  => key("relay",  "case", id, "timeline"),
  caseCanvas:   (id: string)  => key("relay",  "case", id, "canvas"),
  laneTopic:    (id: string)  => key("relay",  "lane", id, "topic"),
  ledger:       (q: string)   => key("relay",  "ledger", q),
  spoolHealth:  ()            => key("local",  "spool"),
} as const;

// Reconnect healing: no registry to forget to update.
export const isRelayDependentQuery = (q: { queryKey: readonly unknown[] }) =>
  q.queryKey[0] === "relay";
// Daemon-reachability healing is a separate, symmetric predicate.
export const isDaemonDependentQuery = (q: { queryKey: readonly unknown[] }) =>
  q.queryKey[0] === "daemon";
```

Two healing predicates, not one, because Perch has two backends that fail
independently — the relay can be up while the daemon is unreachable, and that is
precisely the state in which `/leases` must degrade honestly (ADR 0010: with the
daemon down, the lease TTL is the only backstop). Buzz's single-backend
assumption does not survive the fork.

Client defaults inherit from Buzz (`retry: 1`, `refetchOnWindowFocus: false`,
`networkMode: "always"`, `gcTime` 5 min, `focusManager` rewired to app focus —
`BUZZ/desktop/src/shared/api/queryClient.ts:23-37`) with **one change**:
`daemon`-source queries get `retry: 0`. A retried governance read on a
partitioned daemon is a lie with a delay attached.

### Colony-scoped singletons

`resetCommunityState` is **21 hand-written calls, three of them behind two
conditionals**, in one function
(`BUZZ/desktop/src/features/communities/useCommunityInit.ts:54-84`), with a
doc-comment contract and no type enforcement. For Buzz a miss is a stale cache.
For Perch, colonies are separate monitored estates; a miss is cross-tenant
disclosure of security findings. The brief calls for a typed registry; here it
is:

```ts
// desktop/src/features/colony/colonyScopedRegistry.ts
export type ColonyScopedSingleton =
  | "relayClient" | "rateLimitGate" | "deepLinkDrain"
  | "spoolCursorCache" | "holdStoreMirror" | "leaseTtlTicker"
  | "concentrationRingBuffer" | "depositSuppressionCache"
  | "agentRosterStore" | "verdictDraftStore" | "snoozeStore";

// A mapped type over the union: adding a member without adding a resetter is a
// compile error, and an extra key is a compile error too. This is the whole
// mechanism — no lint rule, no review checklist.
const RESETTERS: Record<ColonyScopedSingleton, () => void | Promise<void>> = {
  relayClient: () => relayClient.disconnect(),
  rateLimitGate: resetRateLimitGate,
  deepLinkDrain: resetNavigationDeepLinkDrain,
  spoolCursorCache: resetSpoolCursorCache,
  holdStoreMirror: resetHoldStoreMirror,
  leaseTtlTicker: resetLeaseTtlTicker,
  concentrationRingBuffer: resetConcentrationRingBuffer,
  depositSuppressionCache: resetDepositSuppressionCache,
  agentRosterStore: resetAgentRosterStore,
  verdictDraftStore: resetVerdictDraftStore,
  snoozeStore: resetSnoozeStore,
};

export async function resetColonyState() {
  for (const reset of Object.values(RESETTERS)) await reset();
}
```

Paired with a test that asserts every module under `features/**` exporting a
`reset*` function appears in `RESETTERS` — the type catches "declared but not
wired", the test catches "written but not declared".

**One limit, stated because the original names it.** Buzz's doc comment
(`useCommunityInit.ts:50-52`) records that hook-managed singletons —
`ChannelMuteSyncManager`, `ChannelSectionSyncManager` — are destroyed by effect
cleanup and deliberately have no entry. The registry covers module-level
singletons only. Anything colony-scoped that lives in a hook is fenced by the
`key={colonyKey}` remount boundary and by nothing else, and the test must not
claim otherwise.

### Optimistic updates

| Action | Optimistic? | Why |
|---|---|---|
| Mark case read, collapse a section, resize the inbox pane | **Yes** | Pure local read-state; Buzz already does this. |
| Snooze a queue row | **Yes**, with rollback | Local scheduling; a failure re-surfaces the row. |
| Canvas edit | **Yes** | Last-writer-wins text; Buzz's canvas already behaves this way. |
| Post a message in a case | **Yes** — Buzz's `pending`/`localKey` on `RelayEvent` (`BUZZ/desktop/src/shared/api/types.ts:188,195`) | Human conversation; a failed send is visibly failed. |
| **Record a grant / refusal on a held action** | **NO** | Two legs, two authorities. Leg 1 (a signed `kind:9` `ambush:verdict:v1` card — `03` §5.5) is an *intent record*; leg 2 is the daemon's own re-evaluation of policy and governance. The daemon may refuse. |
| **Confirm / Dismiss / Investigate a finding** | **NO** | `Dismiss` retroactively removes every deposit at or before the marker from the concentration sum (`AMB/crates/swarm-pheromone/src/substrate.rs:1367-1380`, applied inside `concentration_for` at `:1286`). An optimistic dismiss shows a curve collapse that may not have happened. |
| **Release a lease** | **NO** | A 200 does not mean released; `lease_closed` and `fully_reversed` are read from the body (ADR 0010). There is no optimistic state that can honestly represent this. |

The verdict row therefore renders a **three-state** control, not a spinner:

```
[ record my decision and send it to the daemon ]
   → sending…            (leg 1 in flight)
   → recorded 14:22:07   (verdict card OK'd by the relay; nothing has been authorized)
   → daemon: dispatched  |  daemon: refused — governance partitioned
```

The middle state is the one that matters. It is the state in which the operator's
decision exists as a signed intent and the world has not changed, and collapsing
it into a checkmark is the single easiest way to make Perch lie.

---

## 8. Time

### Two clock domains, typed apart

Pheromone timestamps are **unix seconds** — `PheromoneDeposit::timestamp`,
`decay_half_life`, `EscalationRecord::timestamp`, and the `now` argument to
`strength_at` / `is_evaporated` / `query_concentration`
(`AMB/crates/swarm-core/src/pheromone.rs:281,290`). Everything else is **unix
milliseconds** (`emitted_at_ms`, `expires_at_ms`, `issued_at_ms`). A single
shared `now()` helper produces a 1,000× wrong decay curve, silently, in the
direction of "everything looks evaporated".

```ts
// desktop/src/shared/time/domains.ts
declare const S: unique symbol; declare const M: unique symbol;
export type UnixSeconds = number & { readonly [S]: true };
export type UnixMillis  = number & { readonly [M]: true };
export const nowSeconds = (): UnixSeconds => Math.floor(Date.now() / 1000) as UnixSeconds;
export const nowMillis  = (): UnixMillis  => Date.now() as UnixMillis;
// No conversion helper is exported. Crossing domains requires naming the
// conversion at the call site, which is where the reviewer can see it.
```

### Where decay is computed, and why

`strength(t) = confidence · 0.5^((t − timestamp)/half_life)` is pure and cheap,
so "compute it on the client" is tempting. It is wrong, for three reasons a
client cannot see:

1. `concentration_for` skips evaporated deposits *before* summing, using
   `policy.evaporation_threshold`, and the policy is per-threat-class and
   overridable (`substrate.rs:1268-1300`; `pheromone.rs:290,297`).
2. It skips deposits suppressed by a later `Dismiss` marker
   (`substrate.rs:1286`, `1367-1380`) — a retroactive, non-local edit to the past.
3. `distinct_sources` counts `deposit.agent_id.0`, which
   `findings_to_deposits` sets to `"{agent}:{strategy}"`
   (`AMB/crates/swarm-whisker/src/stream.rs:20-22,46`). A client counting
   "agents" gets a different number than the runtime's escalation test.

**Decision.** The runtime's `ConcentrationSnapshot` is authoritative and is what
the header and every threshold comparison read. The client interpolates *between*
snapshots for the curve only, and labels it. On disagreement — the next snapshot
differs from the interpolation by more than 2% of `alert_threshold` — the curve
**snaps** and emits a reason row (`snapshot corrected interpolation: dismiss at
14:19 suppressed 22 deposits`). It never eases.

The `GET /v1/operator/pheromone/deposits` route (03 §11 item 4) must therefore do
work the substrate trait cannot: `query_deposits(DepositQuery)` takes **no `now`**
(`substrate.rs:384-387`), and `filter_deposits` applies suppression and the
`host_id` / `threat_class` / `since` filters but **not evaporation**
(`substrate.rs:1306-1331`). Only `query_concentration(threat_class, now)` applies
`is_evaporated`. So the route:

```
GET /v1/operator/pheromone/deposits?threat_class=…&since=…&host_id=…&limit=…
200 {
  "now_seconds":   1793481600,          // the runtime's clock, not the client's
  "policy":        { "half_life_secs":…, "evaporation_threshold":…,
                     "alert_threshold":…, "incident_threshold":…,
                     "min_sources_for_escalation":… },   // resolve_threat_class_policy
  "concentration": { "total_strength":…, "distinct_sources":…,
                     "peak_confidence":… },              // query_concentration(now)
  "deposits":      [ … ],   // filter_deposits + evaporation applied at now_seconds
  "suppressed":    [ { "event_id":…, "at":…, "by":… } ]  // what Dismiss removed
}
```

Returning `now_seconds` is what lets the client detect its own clock skew
against the daemon and render the curve in the daemon's time base. Returning
`suppressed` separately is what makes render law 5 possible: the timeline shows
the suppression as an explicit row rather than a hole.

### Clock skew, ordering, and what `created_at` means

Per §5.2, `created_at` is a **transport** timestamp stamped at publish. Perch's
rules follow from that:

- The bridge stamps `created_at` from the daemon's clock at publish time, so all
  evidence shares one clock and no frame can fall outside the relay's ±900 s
  gate.
- Every envelope body carries `emitted_at_ms` **and** the per-issuer `seq`.
  Display order is `emitted_at_ms`, with `seq` breaking ties within an issuer;
  `created_at` is used only when a body carries no domain time. A `created_at`
  that disagrees with `emitted_at_ms` by more than two pacer ticks renders the
  `late-published` marker with its delta.
- Perch checks its own `Date.now()` against `now_seconds` from the deposits route
  on every fetch and shows a chrome warning past ±30 s. An operator reading
  "expires in 40s" off a workstation 5 minutes fast is exactly the failure the
  lease board exists to prevent.

### Timezone and locale

`BUZZ/desktop/src/shared/lib/datetime.ts:14-47` builds six
`Intl.DateTimeFormat("en-US", …)` singletons and passes `timeZone` nowhere;
`timeZone` does not appear anywhere in `desktop/src`. Everything renders in the
workstation's local zone, in US English, without seconds. For a follow-the-sun
SOC where the handoff artifact crosses regions, that is a defect, not a
preference. Perch: one colony-level `displayZone` (default: the workstation
zone), an operator-level override, a **UTC toggle in the chrome**, seconds shown
on every machine timestamp, and every absolute time in a handoff or receipt
rendered as ISO-8601 with an explicit offset.

### Retention

`ensure_future_partitions` creates monthly partitions of `events` and
`delivery_log` forward and **never drops one**
(`BUZZ/crates/buzz-db/src/store/partition.rs:1-57`); the table is
`PARTITION BY RANGE (created_at)` with `PK (community_id, created_at, id)`
(`BUZZ/schema/schema.sql:203-236`). Buzz has no retention policy at all. Perch
adds `perch-retention`, a monthly job that `DETACH PARTITION`s months older than
a configured window and archives the detached table.

Two constraints, and one honest caveat now that §5.4 is on the table. **The window is set from
a configured audit-retention requirement, not from the longest case TTL** — `04` A12 is right
that a floor of "≥ the longest case TTL" is a floor measured in hours, and `/ledger`'s quarterly
export (`04` §2.9) needs a horizon measured in quarters. The deployment doc states the number.
And detaching a month whose evidence a receipt
still references must leave the receipt's `re-fetch from the daemon` affordance
working — which it does, because the daemon's stores are the record and the relay
is transport. The caveat: **until backend item 6 lands, "the record" means the
daemon's file-backed stores, not a hash-linked signed chain**, so what survives a
detach is a re-fetchable object, not an independently verifiable one. That is the
concrete cost of the current signature story, and the deployment doc states it.

---

## 9. Rendering performance

### Virtualization

Buzz already virtualizes with `@tanstack/react-virtual` behind one primitive
(`BUZZ/desktop/src/shared/ui/VirtualizedList.tsx:1-70`) with an explicit
migration contract — rows must tolerate unmount/remount; surfaces with in-DOM
row state use `content-visibility` instead
(`BUZZ/desktop/src/shared/styles/globals/utilities.css:8-46`). Nine surfaces use
it today, including `MessageTimeline`, `InboxListPane` and `MembersSidebar`.

| Perch surface | Strategy |
|---|---|
| The Watch queue | `VirtualizedList` — rows are pure functions of an inbox item |
| Case timeline | `VirtualizedList` — inherited from `MessageTimeline` |
| Ledger results | `VirtualizedList` |
| Leases board | plain list; a colony with >200 open leases is an incident, not a scrolling problem |
| Policy rules | `content-visibility-auto-row` — rules are `<details>`-shaped and expand in place |
| Tuning bench | `content-visibility-auto-row` — cards carry expanded evidence |
| Substrate SVG | neither; see below |

### The `React.memo` traps, made concrete

Gotcha 6 in `BUZZ/AGENTS.md` names two repeat offenders: React Query result
objects are a new identity every render (depend on `mutation.mutateAsync`, not
the object), and derived `Map`/array state needs a content-equality ref cache —
`useStableMap`, `useStableArrayShallow`, `useStableSet` in
`BUZZ/desktop/src/shared/hooks/useStableReference.ts:1-55`. Perch's four
predictable offenders, all on the hot path:

| Offender | Fix |
|---|---|
| `Map<threatClass, Concentration>` rebuilt from each 1 Hz snapshot | `useStableMap` — 11 of 12 classes are usually unchanged, so the memo bails on 11 rows |
| `Map<agentId, AgentFrame>` from the telemetry stream | `useStableMap` |
| `useMutation` result threaded into `<VerdictRow>` | pass `mutateAsync` and a `status` string, never the mutation object |
| Lease `remaining_ms` recomputed per second for every open lease | one `useLeaseClock()` tick at the board level publishing a single `nowMillis`; each row derives from a scalar prop, not a per-row interval |

The measurement discipline is Buzz's, verbatim: measure with DevTools **closed**
and no per-keystroke logging, and isolate by removing one suspect at a time.

### The Substrate SVG budget

No charting library exists in Buzz — no recharts, d3, visx, echarts, chart.js or
plotly — and `--chart-1..5` are *not* emitted by `createThemeVars`, so building
on them yields colors that ignore the theme. The brief forbids adding one. The
Substrate is therefore hand-authored SVG sourcing CSS custom properties, and it
has a budget:

- 12 curves × ≤ 120 sampled points = 1,440 points, rebuilt at **1 Hz**, not per
  frame. Path strings are computed in a `useMemo` keyed on the snapshot's
  `emitted_at_ms`; the interpolated "now" marker moves via a CSS transform on a
  single `<g>`, so 59 of 60 frames touch no React and no layout.
- ≤ **4 ms** `ScriptDuration` per tick, measured by `measureAction`
  (`BUZZ/desktop/tests/e2e/perf/metrics.ts:42-68`).
- Axis and threshold labels use named rem tokens (`text-2xs`, `text-3xs`), because
  `check:px-text` scans all of `desktop/src` including `.css` and rejects
  arbitrary literals — px *and* rem.
- `prefers-reduced-motion` removes the travelling marker entirely. A wallboard
  in a SOC runs for years.

### Worker offloading

`desktop/src` contains **zero** `new Worker`, `worker_threads` or Comlink usage.
Everything — JSON parse, signature-adjacent work, markdown — is on the main
thread. Perch adds exactly one worker, for exactly one job: **parsing and
order-checking spool replay batches after a reconnect.** A 68-minute backlog is
up to ~4,000 batched frames; parsing them on the main thread blows every frame
budget during the exact minute the operator is trying to re-orient. The worker
returns parsed, order-checked, gap-annotated batches; the main thread does
dispatch and render only. Rejected alternative: chunking the parse with
`scheduler.yield()`. That keeps the work on the thread that is trying to paint,
and the replay path is already asynchronous, so a worker costs nothing in
complexity we do not already have.

---

## 10. Offline, reconnect, resync, gap detection, backfill

Buzz's reconnect machinery is ~30 modules with more test LOC than source, and it
is genuinely good. What Perch inherits, unchanged:

- Six-state connection model including `stalled` — socket open per the WS layer
  but no inbound frames, the half-open/VPN-split-brain case
  (`relayClientShared.ts:6-23`).
- 2 s debounce on degraded states, immediate clear on recovery
  (`useRelayConnection.ts:24-56`).
- `lastSeenCreatedAt` per live subscription, plus **`pendingReplaySince`** — a
  pinned floor for a backfill window that has not completed, because live events
  advance the cursor regardless of backfill success and the cursor alone would
  make the next reconnect skip the unresolved window
  (`relayClientShared.ts:70-83`). This is the single most valuable piece of code
  in the fork and the least likely to be reinvented correctly.
- Paged backfill: 500 rows/page, 4-way concurrency, `PAGE_REPLAY_MAX_ATTEMPTS = 3`,
  then degrade to live-only for this connection rather than tearing the socket
  down into the same rate-limit window (`relayReconnectReplay.ts:28-46`).
- REQ burst control on reconnect: 8 subscriptions per batch, 50 ms between
  batches (`relayReconnectReplay.ts:47-61`).
- `MAX_PENDING_RELAY_FRAMES = 256` during the connect/AUTH window, with an
  overflow that rejects rather than growing (`relayInboundBuffer.ts:1,22-28`).
- The rate-limit gate: parse `retry in Ns` from CLOSED and 429, 10 s default with
  no hint, clamp at `MAX_HINT_SECONDS = 300`, never shrink an active window
  (`relayRateLimitGate.ts:15,25,39-41,56-64`).

What Perch adds, because the relay is not the record:

| Failure | Buzz behavior | Perch behavior |
|---|---|---|
| Relay unreachable | banner, retry, replay on return | banner **plus** the queue falls back to the daemon's open-hold list over Tauri (§5.6); the case timeline says `history unavailable — the daemon still has it` |
| **Relay up, Redis down** | n/a — presents as generic rate limiting | distinct state. Every EVENT/REQ is rejected `rate-limited: shared admission unavailable` (`connection.rs:728-735`) with no `retry in Ns`; the strip says `relay admission unavailable — nothing is being published`, the bridge backs off exponentially, and the spool grows. Never rendered as "connected". |
| Daemon unreachable | n/a | `/leases` renders `remaining_ms` from the last known lease **greyed and marked stale**, with the ADR-0010 line: with the daemon down, the TTL is the only backstop. The release button disables and says why. The queue keeps its last daemon-sourced hold list, marked stale. |
| Sequence gap | n/a | gap row + `re-fetch from the daemon` for that `(issuer, seq-range)` |
| Bridge down | n/a | governance strip shows `bridge: down (last envelope 14:22:07)`; the queue is labelled stale, not empty |
| Queue/daemon divergence | n/a | §5.6's three renderings, plus `perch_queue_reconcile_divergences_total` |
| Both up, disagreeing | n/a | the daemon wins, visibly, with a reason row |

**A quiet queue is never rendered as "all clear."** The brief's render law and
`/gaps` exist for exactly this: an empty Watch links to the 18 intentionally
uncovered ATT&CK techniques across 11 detectors. "Everything looks good" is the
one sentence Perch will not print.

---

## 11. Multi-runtime and federated colonies

The roadmap's federated colonies (each operator activates locally, shares
evidence not control) and any MSSP deployment force four properties the client
must have from v1, even though v1 ships one colony per relay:

1. **Sequence namespaces are `(colony_id, issuer)`, never `issuer`.** Two colonies
   both running a `whisker` will both emit `seq: 1`. Merging them under one key
   produces a false gap or a false continuity, and the second is worse.
2. **No cross-colony ordering claim, ever.** Colonies have independent clocks and
   no shared chain. A cross-colony view sorts within a colony and interleaves by
   `emitted_at_ms` with a visible `ordering is approximate across colonies`
   marker.
3. **Every query key is colony-prefixed and every module-level singleton is
   colony-scoped.** `perchKeys` already carries the source; the colony id is
   injected by the per-colony `QueryClient`, mirroring Buzz's two-client pattern
   (machine-scoped at `App.tsx:805`, community-scoped at `:235`).
   `resetColonyState()` (§7) is the fence.
4. **The colony rail answers "which deployment am I looking at" and nothing more.**
   The brief's non-goal is binding: no shared-tenancy claim, because
   internet-exposed or multi-tenant operator governance is a declared Ambush
   non-goal (`AMB/docs/CONSENSUS.md:312`).

One thing the client should *not* anticipate: a merged cross-colony verdict
queue. Approving an action in colony B from colony A's queue requires B's daemon
to re-evaluate B's policy, which is fine, but the queue would then present two
governance domains as one, which is exactly the conflation the brief forbids.
Cross-colony is read-only in the client's model until a real federation protocol
exists.

---

## 12. Perf budgets and how they are tested

Buzz ships `playwright.perf.config.ts` (single worker, no retries, `dist` served
on :4173, `testMatch: ["**/*.perf.ts"]` at `:12-13`) and five perf specs —
`typing-latency`, `scroll-smoothness`, `cold-switch-longtask`,
`warm-switch-markdown`, `scrollback-buzzbugs` — plus a CDP metrics harness
(`tests/e2e/perf/metrics.ts`) that reads `LayoutDuration`,
`RecalcStyleDuration`, `LayoutCount`, `ScriptDuration`, `TaskDuration` around an
action and settles on two `requestAnimationFrame`s. `typing-latency.perf.ts` uses
the Event Timing API with `durationThreshold: 16` and reports median/p95/max plus
a count of >50 ms keystrokes, under 4× CPU throttle. That is the harness; Perch
extends it rather than building one.

| Budget | Target | Spec |
|---|---|---|
| Verdict keypress → next paint. Keys are **`C`/`D`/`I`** (Confirm/Dismiss/Investigate, findings) and **`G`/`R`** (record Grant / Refuse, holds), plus `S`/`E`; never `A` | p95 ≤ 50 ms, zero >100 ms, 4× throttle | `verdict-keys.perf.ts` (pattern: `typing-latency.perf.ts`) |
| Cold open of `/` with 200 queue rows | total longtask ≤ 200 ms, no single task > 100 ms | `watch-cold.perf.ts` (pattern: `cold-switch-longtask.perf.ts`) |
| Case scroll, 500 evidence cards | ≥ 55 fps, no frame > 33 ms | `case-scroll.perf.ts` (pattern: `scroll-smoothness.perf.ts`) |
| Substrate at 1 Hz, 12 curves, 10 min | ≤ 4 ms `ScriptDuration`/tick, `LayoutCount` delta ≤ 2 | `substrate.perf.ts` (uses `measureAction`) |
| Telemetry burst: 1 Hz snapshots + 8 agents for 60 s while typing | quiet-vs-busy p95 keystroke delta ≤ 15 ms | `watchfloor-busy.perf.ts` |
| Reconnect with a 5,000-event backfill | UI interactive throughout; no task > 100 ms | `reconnect-backfill.perf.ts` |
| Ingest → row visible in a case | p95 ≤ 1.3 s | bridge-stamped hop timings, exported as Prometheus histograms from the daemon; asserted in an integration test, not Playwright |
| Hold published → row in `needs_action` | p95 ≤ 400 ms | same |
| Grant recorded → daemon response | p95 ≤ 800 ms | same |

**The keymap is 04's, and this document previously shipped the banned one.** The
earlier draft named the spec `Verdict keypress (A/D/E/S)`. `A` for "approve" is
the word render law 6 forbids on the control it fires, and `D` cannot mean both
Dismiss (a finding, which retroactively suppresses deposits) and Deny (a hold,
which refuses a destructive action) when holds and findings interleave in the
same queue and the same detail pane. `04-SURFACES-AND-UX.md:23-25` settles
`C`/`D`/`I` and `G`/`R`; this document now uses that map, and §14 lists the five
other places that still ship the banned one.

Two harness rules carried over verbatim: build with `pnpm build:e2e`, never
`pnpm run build` — the mock bridge only compiles under `--mode e2e` and a plain
build fails every spec with `Cannot read properties of undefined (reading
'invoke')`, which looks exactly like a product bug. And kill port 4173 before
re-running, because `reuseExistingServer: true` will happily serve the previous
build's code.

**Counters the bridge exports from day one**, because §5's honesty rules are only
credible if they are measured: `perch_bridge_broadcast_lagged_total`,
`perch_bridge_spool_bytes`, `perch_bridge_dropped_events_total`,
`perch_bridge_alarm_spool_full_total`,
`perch_bridge_publish_latency_seconds`,
`perch_bridge_admission_rejections_total`,
`perch_bridge_late_published_seconds`, and
`perch_queue_reconcile_divergences_total`.

**The C9 counters have one home, and it is The Watch (`/`).** The brief's three
falsification numbers — median seconds page-to-verdict, measurements written per
week, fraction of this week's recommendations sourced from this week's verdicts —
plus the case-promotion `promoted`/`suppressed` pair are rendered in The Watch's
first queue header. That is the only Phase-1 surface, and 09's non-negotiable is
that these ship in Phase 1. `/tuning`, `/handoff` and `/watch-floor` restate them
read-only and link back to `/`; none of them owns the number. The instrumentation
that is supposed to falsify the thesis cannot live on three surfaces that do not
exist yet.

---

## 13. Numbers this document owns

Every figure below appears in more than one document in the set. This table is
the source; peers should cite it rather than restate it, and a change here is a
brief amendment.

| Constant | Value | Verified at |
|---|---|---|
| `DEFAULT_RUNTIME_EVENT_CAPACITY` | 1,024 | `AMB/crates/swarm-runtime/src/runtime_events.rs:13` |
| `RuntimeEvent` variant count | **11** | `AMB/crates/swarm-runtime/src/runtime_events.rs:214-305` |
| `CONCENTRATION_MONITOR_INTERVAL_MS` | 100 (10 Hz) | `AMB/crates/swarm-runtime-http/src/bin/swarm_detect.rs:40` |
| Measured hot path | 3,645/s HTTP, 6,364/s in-memory | `AMB/README.md:528,536` |
| Operator router route count | **49** | `AMB/crates/swarm-runtime-http/src/http/state.rs:294-485` |
| `human_ws_events_per_sec` | 10, windowed 5 s as 50 | `BUZZ/crates/buzz-auth/src/rate_limit.rs:123-125`; `admission.rs:9,39-44` |
| `agent_standard_messages_per_min` | 120 | `BUZZ/crates/buzz-auth/src/rate_limit.rs:126-128` |
| `human_messages_per_min` | 60 | `BUZZ/crates/buzz-auth/src/rate_limit.rs:117-119` |
| Elevated / platform tiers | 300 / 600, **read by no enforcement site** | `rate_limit.rs:111,114,143-152`; `connection.rs:690` |
| `MAX_TIMESTAMP_DRIFT_SECS` | **900 s, rejects** | `BUZZ/crates/buzz-relay/src/handlers/ingest.rs:2224-2231` |
| `CREATED_AT_FLOOR_SECS` | 960 s, deferred constraint trigger | `BUZZ/crates/buzz-db/src/runtime/replica_fence.rs:74`; `schema.sql:1115-1120` |
| `MAX_EVENT_CONTENT_BYTES` | 256 KB | `ingest.rs:2233-2240` |
| `DEFAULT_MAX_FRAME_BYTES` | 512 KiB | `BUZZ/crates/buzz-relay/src/config.rs:14` |
| `OBSERVER_MAX_PLAINTEXT_LEN` | 65,535 | `BUZZ/crates/buzz-core/src/observer.rs:25` |
| `MAX_EXPLICIT_CHANNEL_VALUES` | 128 | `BUZZ/crates/buzz-relay/src/handlers/req.rs:42` |
| `MAX_PENDING_RELAY_FRAMES` | 256 | `BUZZ/desktop/src/shared/api/relayInboundBuffer.ts:1` |
| Rate-limit gate defaults | 10 s no-hint, 300 s cap | `BUZZ/desktop/src/shared/api/relayRateLimitGate.ts:15,25` |
| `PRESENCE_TTL_SECS` | 180 | `BUZZ/crates/buzz-pubsub/src/presence.rs:16` |
| `relayQueryInvalidation` roots | 34 | `BUZZ/desktop/src/shared/api/relayQueryInvalidation.ts:1-35` |
| `resetCommunityState` calls | 21, three conditional | `BUZZ/desktop/src/features/communities/useCommunityInit.ts:54-84` |
| Buzz perf specs | 5 | `desktop/tests/e2e/*.perf.ts` |
| `build_signed_envelope` non-test callers | **1** | `AMB/crates/swarm-runtime/src/approval.rs:1810` |

Perch-proposed values, which are decisions rather than measurements:
`PERCH_PUBLISH_TICK` 1 s, `PERCH_FRAME_MAX_BYTES` 64 KB,
`PERCH_SPOOL_MAX_BYTES` 256 MiB per stream, interpolation tolerance 2% of
`alert_threshold`, clock-skew warning ±30 s, `late-published` threshold 2 ticks.

---

## 14. Corrections this revision issues to peer documents

The set has nine owners and no registry, and 07 was one of the documents
overriding earlier ones silently. These are the edits this revision forces
elsewhere. Each was a request to that document's owner, not an edit made here.

**Status:** every row below has since been applied by the cross-document reconciliation pass, and
the registry it asks for exists as `APPENDIX-NORMATIVE.md`. Two rows were adjudicated *against*
this document: the hue taxonomy took **pillar**, not *family* (`05` §2.1 — *family* is spent on
the two badge families), and §6's Watch subscription and `/handoff` hold re-publish were both
replaced by `03` §5.4's settled mechanism. The `path:line` pointers below predate those edits.

| To | What changes, and why |
|---|---|
| **02 §5, 03 §4.2** | Replace the reason for not using Nostr presence. It is **not** single-node: a kind:20001 update writes Redis presence state and then falls through to the shared channel-less ephemeral path, which does `publish_event(&conn.tenant, EventTopic::Global, &event)` — the comment says so explicitly (`BUZZ/crates/buzz-relay/src/handlers/event.rs:844-846`, publish at `:884-891`). The correct reason is the **180 s TTL lie-window** (`buzz-pubsub/src/presence.rs:16`): presence is a heartbeat-decayed status, not a liveness signal, so agent liveness reads the ephemeral `26002` frame. Decision unchanged; justification wrong. |
| **01:167, 01:349, 08:297-300, 08:823, 09:144, 09:170** | Adopt 04's keymap: `C`/`D`/`I` for findings, `G`/`R` for holds, `S`/`E` surviving. INV-11's key-repeat invariant is written against `G`. Add the banned `A` to `tools/check-copy-banned-terms.sh`. 07 has already made this change. |
| **04 §2.2 / 08 §3.5** | Reconcile the grant control: 04's wireframe grants on one keypress with an outline button, 08 mandates a scroll-to-end-gated modal. One of them, and the CI guard written against it. |
| **02 §13, 09 §2 exit criterion 1** | Neither can pass as written: there is no Ed25519 signature over a `DetectionFinding` to verify (§5.4). Rewrite as either (a) *"the daemon wraps the fact in `build_signed_envelope`; the card body carries that envelope verbatim; `verify_envelope` passes in the Perch process"* — which requires backend item 6 — or (b) *"the card body is byte-identical to the daemon's canonical JSON on re-fetch; the envelope carries the bridge's secp256k1 signature and nothing more"*. |
| **08 §6.4** | The export bundle's "three separately-reported checks (signature, subject binding, chain linkage)" has nothing to check for finding, escalation, hold and lease cards today. Either gate the claim on item 6 or state per card type which checks are available. |
| **03 §11, 09 §6** | Consider backend item 6 (envelope-wrapping at the daemon) on its merits: one call site per fact, the pattern already in tree at `approval.rs:1810`, and it is what turns the set's central integrity claim from aspiration into mechanism. |
| **03 §4.2** | Add an `AgentAction` row. 07 proposes: telemetry stream, tallies folded into the `26002` agent frame, `details` never crossing the wire, `action_kind` allowlisted with an `other` bucket. |
| **02 §5 (or a new §15)** | Give `clients/python/swarm-platform-client/` and `/v2/api` a disposition: frozen at current shape, or deprecated with a date. It is a real generated client against a surface whose list path is a full scan plus an N+1 (`platform_api.rs:720-740`). |
| **04 §2.1/§2.10, 08 §3.6/§7.1, 09 exit criterion 6** | Name The Watch (`/`) as the C9 counters' Phase-1 home; the other three surfaces restate read-only. 09's criterion currently names a Phase-3 surface. |
| **00-BRIEF §5.1, 09 F3** | `invokeTauri` call sites: 02 measured 264 call-shaped occurrences and 205 distinct command-name literals. The brief's 209 is wrong and 09 inherited it into a sizing note without the `unverified` marker it applies elsewhere. |
| **04, 05** | The "lane" rename: 04's inbox categories to *queues* (**done**, 04 §2.1), 05's hue taxonomy to *pillars* (**done**, 05 §2.1 — 05 chose *pillar* over the *family* this table first proposed, and it is right: *family* is spent on the two badge families). 07 has renamed its four transport classes to *streams* (§0). |
| **09 K-criteria** | K3 counts stored kinds; nothing counts markers. Add a marker-count gate: a seventh `ambush:*:v1` marker without 03 §4.4's justification shape fails review. 07 introduced three markers in its previous draft with no gate to catch it. |

---

## 15. What I could not verify

Corrections resolved in this revision, listed so they are not re-raised: presence
*does* publish globally (moved to §14 as a correction to 02 and 03, with the
right reason substituted); `event_mentions` *is* populated from `p` tags only
(`runtime/mod.rs:41-53`, now load-bearing in §5.6); `CREATED_AT_FLOOR_SECS`
*does* exist server-side (`replica_fence.rs:74`, now load-bearing in §5.2).

Still open:

- Relay-side per-hop latencies (verify, insert, triggers, Redis, fan-out) are
  budgets I set, not measurements. I found no published Buzz relay latency
  numbers in either repo.
- The spool sizing (256 MiB → ~68 min of storage) is arithmetic scaled from
  buzz-acp's documented 4 MiB → ~64 s ratio at ~64 KB drained per slot
  (`lib.rs:396-413`). Not measured. The publishability half of that claim is now
  independent of the number (§5.2).
- I read the in-memory and one file-backed `PheromoneSubstrate::query_deposits`
  (both route through `filter_deposits`, `substrate.rs:1306`); I did not read the
  NATS JetStream backend's implementation. If it diverges on suppression or
  ordering, §8's route contract needs re-checking against it.
- Whether `DETACH PARTITION` is safe against every index and FK on `events` in a
  live relay is untested here. The table shape makes it look straightforward and
  it needs a migration test before it ships.
- Ephemeral kinds `26000`–`26005` are 03's allocation; nothing enforces the
  reservation against future upstream `block/buzz` allocations in that block.
- `RuntimeEventKind` exists and has a `kind()` accessor
  (`runtime_events.rs:127,324-337`), so the Rust-side exhaustive match is real.
  The TypeScript mirror of the stream table has no compiler enforcement — only
  the Rust side fails to compile on a twelfth variant, and a drifted TS mirror is
  caught by a fixture test, not by the type system.
- The proposed spool, pacer, stream table, worker, retention job, branded time
  types, query-key factory, colony registry and daemon reconciliation are
  proposals. None of this code exists in either repo today.
- The `late-published` threshold of two pacer ticks and the ±30 s skew warning
  are chosen numbers with no measurement behind them.

---

*Cross-references: `02-ARCHITECTURE-INTEGRATION.md` for the crate topology and
the two-arm relay fork; `03-DOMAIN-EVENT-MAPPING.md` for the marker-comment wire
format, the seven frozen markers and the tag budget — it owns the wire and this
document routes through it; `04-SURFACES-AND-UX.md` for the route table, the
keymap and what each surface renders; `08-TRUST-AND-GOVERNANCE-UX.md` for the
two-legged write and the honest-badge taxonomies; `09-ROADMAP-AND-RISKS.md` for
sizing the bridge and the hold store.*
