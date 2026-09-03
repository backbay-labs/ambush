# Normative appendix — the things that cross all nine documents

**Status:** normative. Changing anything on this page is a brief amendment under
`00-BRIEF.md` §12, recorded in `00-BRIEF.md` §13.

This file exists because the coherence review found the set's structural defect: nine documents,
no registry. Five things genuinely crossed all nine — the route table, the key map, the
marker/kind/tag registry, the shared constants, and the mechanism by which a hold reaches a human
— and each was re-decided independently in three or four documents, with the later ones silently
overriding the earlier. That produced a keymap specified two incompatible ways and a safety
invariant written against the banned key.

**The rule:** a document *cites* this page. It does not restate it. Where a document still
restates a value, this page wins.

Every row names its owning document. The owner is where the *argument* lives; this page is where
the *value* lives.

---

## 1. Route table (owner: `04` §1.1)

Eleven routes, fourteen surfaces.

| Path | View id | Surface | Phase |
|---|---|---|:-:|
| `/` | `watch` | The Watch (+ the Verdict Row as its detail pane, + the C9 strip) | 1 |
| `/cases/$caseId` | `case` | Case (+ the Case Canvas as a tab, + the swarmctl terminal pinned to it) | 1–2 |
| `/lanes/$laneId` | `lane` | Lanes — twelve fixed threat-class channels | 2 |
| `/leases` | `leases` | Containments (nav label; route unchanged) | 2 |
| `/policy` | `policy` | Policy, read-only in v1 | 2 |
| `/watch-floor` | `watchfloor` | Watchfloor — the wall screen | 3 |
| `/ledger` | `ledger` | Ledger, also the `Cmd-K` overlay; carries the export | 2 |
| `/tuning` | `tuning` | Tuning bench | 2 |
| `/handoff` | `handoff` | Handoff — Take the watch / End watch | 2 |
| `/gaps` | `gaps` | Gaps | 2 |
| `/settings` | `settings` | Settings — **must become a real route before the first new surface** | 0 |

Not routes: the Verdict Row (detail pane of `/`), the Case Canvas (tab), the governance strip
(chrome on every route), the swarmctl terminal (panel).

`/watch-floor`, not `/watch` — `/watch` collides with The Watch at `/`. Brief amendment A3.

---

## 2. Key map (owner: `04` §3.0)

| Key | Meaning | Row type |
|---|---|---|
| `C` | Confirm | finding |
| `D` | Dismiss — two-stage; a modal only when the delta crosses `alert_threshold` | finding |
| `I` | Investigate | finding |
| `G` | **Arms** the grant. A second stroke (`Enter`) records it, gated on the BLAST RADIUS block having been fully visible and ≥1500 ms on this `hold_id`. Ignored on `event.repeat`. | hold |
| `R` | Refuse — one keypress, no dialog, no undo | hold |
| `S` | Snooze — **findings and case rows only** | finding / case |
| `E` | **Promote to a case** — one meaning, always. Not "route to another operator"; no operator directory exists in either tree. | finding / hold / lane row |
| `J` / `K` | Move selection | any list |
| `Enter` | Open (case, lane, lease detail) | any list |
| `M` / `U` | Mark done / unread — **localStorage only, never a decision record** | any row |
| `Escape` | Close the topmost surface. **Never marks read** (Buzz binds bare `Escape` to mark-channel-read; a queue must not be clearable by accident). | global |
| `Cmd-K` | Omnibox: query mode; `>` switches to command mode | global |
| `Cmd-\`` | Toggle terminal | global |

**`A` is banned as a verdict key**, enforced by `tools/check-copy-banned-terms.sh`
(`08` INV-31). `D` is Dismiss and never Deny — holds and findings interleave in one pane, and
Dismiss retroactively removes deposits from a concentration sum. **No single key may be bound to
two verdict verbs across row types in the same list** (`08` INV-32).

Buzz's six existing global bindings survive with remapped targets
(`desktop/src/app/useAppShellKeyboardShortcuts.ts:56-98`); `Ctrl-Shift-Space` (huddle) is deleted.

---

## 3. Wire registry (owner: `03` §3, §13)

**Stored kinds forked into the relay: `46010` only.** Two relay match arms
(`required_scope_for_kind` before the default at `BUZZ crates/buzz-relay/src/handlers/ingest.rs:545`,
and `requires_h_channel_scope` at `:703-732`), plus **four client registration points**
(`CHANNEL_TIMELINE_CONTENT_KINDS`, `CHANNEL_EVENT_KINDS`, `isTimelineContentEvent`, a `MessageRow`
renderer arm). Say "two relay arms, six registration points". A third stored kind requires a
written argument in `03` §13 against the marker path.

**Seven markers**, all on `kind:9`:

| Marker | Carries | Channel |
|---|---|---|
| `ambush:finding:v1` | `DetectionFinding` / `SwarmFindingEnvelope` + `host_id` from the `RuntimeEvent` wrapper | lane |
| `ambush:escalation:v1` | `RuntimeEvent::Escalation`, `ModeTransition`→Incident, `TamperAlert` when `fail_closed` | lane |
| `ambush:hold:v1` | the `HeldActionStore` record; also the expiry record | case |
| `ambush:verdict:v1` | **the human decision — leg 1 of the two-legged write** | case |
| `ambush:receipt:v1` | `ResponseReceipt` + `AuditTrail` | case |
| `ambush:lease:v1` | `ContainmentLeaseView` on open | case |
| `ambush:rollback:v1` | `RollbackReceipt`, as a NIP-10 reply to the lease card | case |

An eighth marker needs `03` §4.4's justification shape: *what an operator cannot reconstruct
without it after the ephemeral has decayed.*

**`ambush:verdict:v1`, not `46030`/`46031`.** `is_command_kind` routes 46030/46031 to
`command_executor::handle_command`, which rejects them absent a `workflow_approvals` row; the
event is never stored. Brief amendment A2.

**Ephemeral block `26000`–`26006`**, global (no `h`), aggregates and opaque ids only:

| Kind | Payload | Cadence |
|---|---|---|
| `26000` | ingest rate `{accepted, rejected, by_source}` | 1 Hz |
| `26001` | `ConcentrationSnapshot`, 12 classes | **coalesced 10 Hz → 1 Hz in the bridge, before IPC** |
| `26002` | `AgentHealth` + `AgentAction` tallies (`details` never crosses the wire) | on change |
| `26003` | `ModeTransition` | on change |
| `26004` | `GovernanceStatusReport` | 1 Hz or on change |
| `26005` | `TamperAlert` — **counts, not paths** | on event |
| `26006` | the hold alarm `{hold_id (opaque), action_kind, severity, case_channel, expires_at_ms}` | on event, never coalesced, never shed |

Two rules govern the block: an **aggregates-only payload rule** and an **admitted-issuer rule**
(a `26xxx` frame renders only if its pubkey resolves to an admitted bridge identity; others are
counted and dropped). `08` INV-15 extends the same admission rule to `46010`.

**Single-letter tag budget, closed.** `h` (channel, mandatory), `e`/`p` (NIP-10 + mentions),
`t` (threat-class slug), `l` (`Severity`, SCREAMING_SNAKE), `k` (card-kind slug), `d`
(addressable kinds). **Only `h`, a single `#p`, `#e` and `#d`-on-NIP-33 are pushed into SQL**;
`t`, `l` and `k` are post-filters over a fetched page, never indexed selection, and a filter
using one disqualifies the fast COUNT path. `strategy_id`, `host_id`, `receipt_id`, `lease_id`
and `hunt_id` are reachable through NIP-50 FTS only — a permanent cost, because the events are
signed and cannot be re-tagged.

---

## 4. How a hold reaches one human (owners: `03` §5.4, `04` §3.2, `07` §5.6)

This is the path that was specified three incompatible ways. One statement, four layers:

1. **Durable record.** The bridge publishes `kind:46010` into the **case channel** with an `h`
   tag and a `p` tag naming **every operator principal holding `OperatorScope::Approve`**
   (`OperatorAuthConfig::effective_principals()`, `AMB swarm-core/src/config/operator.rs:153-168`
   — one person in the shipped default). Both are load-bearing: `query_needs_action` INNER JOINs
   `event_mentions` (populated from `p` tags only) **and** scopes to visible channels. Satisfy one
   and not the other and the hold reaches nobody, silently.
2. **Live nudge.** An ephemeral **`26006`** frame, global, no `h`, `p` = the same set. This is the
   only live path: the fork makes `46010` channel-scoped, and global subscriptions never receive
   channel-scoped events (`BUZZ buzz-relay/src/subscription.rs:486-491`). A REQ of
   `{kinds:[46010], "#p":[me]}` cannot work and no document may specify it.
3. **Authority.** `query_needs_action` on connect, on reconnect and on every `26006`, reconciled
   against `GET /v1/response/holds` (**B2r**). The relay's mention index is written *outside* the
   event transaction and a failure is a `warn!`, so a hold can be stored, OK'd, and permanently
   invisible to the feed. Divergence renders (`07` §5.6's three cases) and is counted
   (`perch_queue_reconcile_divergences_total`).
4. **Paging.** The watch claim (`04` §2.11 — the topic of a standing `#watch` ops channel)
   decides whose *phone rings* for wake classes 1–3. It does **not** change the `p` tag. With no
   claim, or a stale one, everyone pages. Narrowing the `p` tag itself needs the v2 daemon field
   `on_shift_operator_pubkeys` plus `POST /v1/operator/watch/claim`.

**The ≤400 ms budget is on the `26006` alarm frame, not on the durable row.**

---

## 5. Backend bill labels (owner: `09` §3.1)

Eleven items. Cite the label; `09` §3.1 carries who calls it, what process it runs in, what it
does to the data, and its verified state today.

| Label | Item | Phase | Cuttable? |
|---|---|:-:|---|
| **B1** | `HeldActionStore` + `RuntimeEvent::ResponseHeld` | 1 | no — gates everything |
| **B2** | `POST /v1/response/holds/{id}/decide`, lease minted at **decision** time | 1 | no |
| **B2r** | `GET /v1/response/holds` + `GET /v1/response/holds/{id}` | 1 | no |
| **B2g** | governance + partition re-evaluation on the decide path (`08` B1.5) | 1 | yes, with a *rendered* consequence |
| **B2o** | `approved_by: Option<OperatorApproval>` into `ResponseReceiptAudit` (`08` B1.6) | 1 | no |
| **B3** | `POST /v1/operator/findings/{id}/feedback` | 1 | no |
| **B3i** | mint a single-member `IncidentRecord` on promote-to-case | 1 | no |
| **B3r** | `GET /v1/operator/findings/reviewed?since_ms=` | 1 | no |
| **B5** | gate `/v1/events/stream` **and** drop its wildcard ACAO; scope-check `review_session_create_handler` | 1 | yes |
| **B4** | `GET /v1/operator/pheromone/deposits` — post-suppression, post-evaporation, plus the resolved policy | 2 | no |
| **B6** | `build_signed_envelope` on the publish path (`08` B1.7) | 2 | yes, with a *rendered* consequence |

Legacy labels, for reading the older documents: `08`'s B1.5 = **B2g**, B1.6 = **B2o**,
B1.7 = **B6**, B5+ = **B5**. `02`'s "bill 6a" = **B2r**, "bill 6b" = **B6**, "step 3.5" = **B2o**.

---

## 6. Shared constants

| Constant | Value | Status | Owner |
|---|---|---|---|
| `PERCH_HOLD_TTL_MS` | **3,600,000** (60 min), configurable per threat class | proposed | `08` §3.6 |
| `PERCH_QUEUE_DEPTH_ALARM` | **12** open holds | proposed | `04` §3.0 / `08` §7.1 |
| `PERCH_WATCH_CLAIM_TTL_MS` | 43,200,000 (12 h) | proposed | `04` §2.11 |
| `PERCH_PUBLISH_TICK` | 1 s | proposed | `07` §5.3 |
| `PERCH_FRAME_MAX_BYTES` | 64 KB | proposed | `07` §5.3 |
| `PERCH_SPOOL_MAX_BYTES` | 256 MiB **per stream** | proposed | `07` §5.3 |
| `PERCH_CONCENTRATION_TICK_HZ` | 1 | settled | brief §4.3 |
| Interpolation tolerance | 2% of `alert_threshold` | invented | `07` §8 |
| Clock-skew warning | ±30 s vs the daemon's `now_seconds` | invented | `07` §8 |
| C9 counters' home | **The Watch (`/`)**, queue-1 header | settled | `04` §3.0 / brief A6 |
| Wake classes | exactly **four** | settled | brief §10 Q9 |
| Retention floor | a configured **audit-retention** requirement, **not** the longest case TTL | settled | `04` A12 / `07` §8 |

**Verified counts** (measured from source; a document disagreeing with one is stale):

| Fact | Value | Where |
|---|---|---|
| Destructive / human-gated / receipt-required actions | **12** of 15 | `static_gate.rs:37-53` ≡ `dispatcher.rs:1276-1292` ≡ `tom_agent.rs:1276-1291` |
| Executable inverses (`ContainmentInverse`) | **3** | `rollback.rs:66-78` |
| Standard threat classes / lanes | **12** | `escalation.rs:315-330` |
| `AgentRole` variants | **8**, closed enum | `swarm-core/src/agent.rs:17-34` |
| `RuntimeEvent` variants | **11** today, **12** after B1 | `runtime_events.rs:214-305` |
| Operator router routes (process **B**, `swarmctl serve`) | **49**, none accepting feedback | `http/state.rs:293-497` |
| Intentionally-uncovered ATT&CK techniques / detectors | **18** / **11** | `rulesets/evasion/attack-technique-catalog.yaml` |
| `swarmctl` subcommands / `reqwest` sites in `core.inc` | 126 / **3** in 5,750 lines → "~124 of 126 are not HTTP clients" | `swarm-cli/src/core.inc` |
| Ambush workspace members | **20** (+1 untracked empty dir `ls` counts and cargo does not) | `Cargo.toml:3-24` |
| `invokeTauri` | **264** call-shaped occurrences / **205** distinct command literals / 57 files | `desktop/src`, measured — **not** the 209 that circulated |
| `AppShell.tsx` / `MessageRow.tsx` | **997** / **998** against a hard 1000 cap | `wc -l` |
| `e2eBridge.ts` | **14,620** lines — do **not** split it | `desktop/src/testing/` |
| Buzz `web/` client | 49 files / 4,259 LOC incl. CSS; 48 `.ts`/`.tsx` / 4,159 LOC excl. | direct count |
| `lease_ttl_ms` | **60,000** — mint at decision time, never hold time | `rulesets/default.yaml:94` |
| `human_gate_severity` | **HIGH** | `rulesets/default.yaml:93` |
| Tuning thresholds (reviewed / FP / rate) | host 2/2/0.75 · threshold 4/2/0.50 · rule 3/2/0.34, capped at 6 | `alert_tuning.rs:6-15` |
| `DEFAULT_RUNTIME_EVENT_CAPACITY` | **1,024**; lagged receivers drop **silently** | `runtime_events.rs:13` |
| Relay per-pubkey write quota | **120/min** (`agent_standard`); elevated/platform tiers exist and are read by no enforcement site | `buzz-auth/src/rate_limit.rs:126-128`, `connection.rs:690` |
| `MAX_TIMESTAMP_DRIFT_SECS` | **900 s, rejects** — hence `created_at` is stamped at *publish* | `buzz-relay/src/handlers/ingest.rs:2224-2231` |
| `PRESENCE_TTL_SECS` | **180** on a 60 s heartbeat — the reason liveness reads `26002`, not presence | `buzz-pubsub/src/presence.rs:16` |
| `build_signed_envelope` non-test callers | **1** (`approval.rs:1810`) | grep over `crates/` |
| `verify_chain_link` consumers outside its module | **0** | grep over `crates/` |

---

## 7. Vocabulary, ruled

One word, one sense. `tools/check-copy-banned-terms.sh` enforces the bans.

| Word | Means | Never means |
|---|---|---|
| **lane** | one of the twelve standing threat-class channels | an inbox category, a colour token, a bridge transport class, README's agent scheduling tier |
| **queue** | one of The Watch's four inbox categories | a surface name |
| **pillar** | the three-hue semantic taxonomy (substrate / authority / evidence) | anything else — brief A9 |
| **stream** | one of the bridge's four transport classes (evidence / telemetry / alarm / dropped-at-source) | — |
| **family** | one of the **two badge families** (12 destructive · 3 reversible) | the hue taxonomy |
| **group** | lefthook's and CI's parallel units | — |
| **track** | `09`'s parallel workstreams | — |
| **capability lease** / **containment lease** / **contingency lease** | three unrelated objects | bare "lease" in a label, heading, nav item or badge |
| **refuse** (operator) / **deny** (policy) / **veto** (Tom · governance) | three actors, three typed words | each other |
| **case** | Perch's own noun: a private TTL channel; the case id **is** the channel UUID | `CorrelatedIncident`, which is a recomputed Ambush artifact |
| **hold** | a `RequireHuman` made durable in the daemon | a Buzz `workflow_approvals` row |

Banned outright in rendered strings: `Approve`/`Approved` as a control label; `A` as a verdict
key; `Deny` as an *operator* control label; `verified by` / `trusted` / `proof` / a shield or
lock glyph beside an attestation; `signed`/`verified` on a finding, escalation, hold, lease or
bare response-receipt card; a quorum fraction; a bare source count; `Everything looks good` /
`All clear` / `You're all caught up` / `no data` / `nothing to see`; `hunt` as a nav item;
`clowder`; `Swarm Team Six`; `!` in any rendered string longer than three characters.

---

## 8. The render laws, in one place (owner: `00-BRIEF.md` §7)

1. **Fixed verdict field order, never varying by action type:** ACTION → BLAST RADIUS → IF YOU
   UNDO → WHY WE ARE ASKING → WHAT GRANTING OPENS. An unfillable slot renders an explicit
   absence; it never collapses.
2. **Never a bare source count.** Always `N sources / M agents`, expandable to the ids grouped by
   real agent. `distinct_sources` counts strategy-scoped ids, so one Whisker with four detectors
   defeats `min_sources_for_escalation`.
3. **Honest badges.** Verification renders a **tier** (0/1/2) and names the chain it checked.
   `None` is `UNATTESTED`, and `UNATTESTED — BY DESIGN` under a partition contingency. Rollback
   renders five statuses. A 200 on release is read from `lease_closed`. `remaining_ms` and
   `expired` are two facts. Governance renders `committee of 1 (solo transport)`. 0 promotions is
   correct by design and says so.
4. **Derived-vs-served marking.** Anything the console computes that the runtime does not carries
   a marker naming the function. The runtime's snapshot is authoritative; disagreement snaps
   visibly with a reason row.
5. **Dismiss is never a gesture.** It retroactively removes every deposit at or before the marker,
   keyed on `(threat_class, event_id)` — so it reaches detectors the operator never reviewed. The
   row previews the arithmetic; the suppression renders as an explicit timeline row.
6. **The grant control says "record my decision and send it to the daemon."** In a component that
   cannot be styled as a primary action without failing a check.
7. **Empty states name what is deliberately not covered.** The *phrase ban* is universal; the
   `/gaps` **link is scoped** to swarm-produced-nothing states (`04` §2.12). Other empty states
   name their own governing number.
