# Surface-by-surface UX specification

Perch is fourteen surfaces on the Buzz desktop shell. This document specifies each one: the job it
does, its objects, its layout, every state it can be in, and what it refuses to do. It then settles
the cross-cutting model — navigation, the palette, query, paging, assignment, handoff, realtime,
density, mobile — walks a full shift end to end, and walks three flows. Architecture is settled in
`02-ARCHITECTURE-INTEGRATION.md`; the event wire is settled in `03-DOMAIN-EVENT-MAPPING.md`; colour
and type in `05-DESIGN-SYSTEM.md`; every string in `06-COPY-AND-VOICE.md`. This document owns
shape, order, and behaviour, and — as of this revision — the **normative route table (§1.1), the
normative key map (§3.0), and the shared surface constants (§3.0)**, which the other eight documents
cite rather than restate.

**Revision note.** This is the red-team revision. Fourteen findings were raised against the first
draft. Twelve are accepted and fixed here; two are partially rebutted with evidence in place
(§6.3). Every fix is grounded in source read this session, and §6 lists the cross-document conflicts
this revision resolves along with the brief §12 amendments it requests. The largest changes: the
findings review queue is now a first-class surface with served state (§2.1), the Lanes topic rewrite
is deleted as unaffordable and unsafe (§2.5), the Ed25519 verification claim is corrected per card
type because four of the seven card types carry no signature at all (§2.2), and `/handoff` gains the
watch-claim control that the paging model was already assuming (§2.11).

---

## Decisions made here

1. **Route table is eleven paths, not fourteen.** The Verdict Row, the Case Canvas and the governance
   strip are not routes: they are the detail pane of `/`, a tab inside a case, and persistent chrome.
   §1.1 is the normative table.
2. **`/watch-floor`, ratified.** The brief's `/watch` for the Watchfloor collides with The Watch at
   `/`, and `06 NAV` already maps `/watch` → "Watchfloor" while The Watch owns `/`. §1.1 settles it
   and §6.1 files the brief §12 amendment with the exact downstream sites, including the five
   v0-fallback sentences that currently read `/watch + /ledger + /gaps`.
3. **`Cmd-K` is one omnibox with two modes.** No query prefix = Ledger search (NIP-50 → FTS). A
   leading `>` = command mode. One dialog, one keyboard reflex.
4. **`Escape` does not mark read in Perch.** Buzz binds bare `Escape` to mark-channel-read
   (`desktop/src/app/useMarkAsReadShortcuts.ts:23-45`). In a queue where "read" and "decided" are
   different facts, an accidental Escape must not clear a queue. Escape closes the topmost surface.
5. **Verdict keys are `C` / `D` / `I` for findings and `G` / `R` for holds** — not the brief's
   `A`/`D`/`E`/`S`. `A` for "approve" is exactly the word render law 6 forbids; `D` cannot mean both
   Dismiss and Deny on rows that interleave in one pane. §3.0 is the normative map and §6.1 files the
   amendment. **The friction asymmetry from `08-TRUST-AND-GOVERNANCE-UX.md` §3.5 is adopted whole:**
   `R` refuses in one keypress; `G` opens a scroll-gated, non-primary confirmation. Keys are a copy
   decision and belong here; friction is a safety decision and belongs there.
6. **Assignment is channel membership.** "Taking" a case publishes a kind:39002 membership for you on
   that case channel. Ambush has no assignee field and we invent none.
7. **The watch itself is claimed, and the claim is a channel topic.** `/handoff` gains **Take the
   watch** alongside **End watch**. The claim is the `topic` of a standing `#watch` ops channel — one
   member-authorized `kind:9002` write producing one relay-signed durable `kind:40099` row
   (`crates/buzz-relay/src/handlers/side_effects.rs:1548-1564, 762-793`, authorization at `:592-630`).
   Zero new kinds, zero new markers, one audit row per shift. Without this control the per-shift
   paging model in §3.3 has no publisher and degrades to page-everyone.
8. **Paging bypasses `shouldNotify`; toasts do not.** Buzz's opt-in-to-noise predicate
   (`features/notifications/lib/shouldNotify.ts:28-76`) keeps governing in-app toasts. The four wake
   classes take a separate path that never consults it.
9. **The Watch's four inbox categories are "queues", never "lanes".** "Lane" is reserved for the
   twelve threat-class channels — it is the only operator-visible sense. §6.2 records the four-way
   collision across the set and the CI ban that fixes it.
10. **Findings get a first-class review queue with served state.** They are the tuning loop's only
    input, so they cannot live in a collapsed drawer that never pages. Queue 3 on The Watch is
    `FINDINGS TO REVIEW`, expanded by default, with a per-row reviewed/unreviewed/ineligible state and
    a shift target. Multi-select is permitted for `Confirm` and `Investigate` only.
11. **One queue-depth constant.** `PERCH_QUEUE_DEPTH_ALARM = 12` (§3.0), fires the "this is a tuning
    problem" banner from `08` §7. **Grouping above 50 is deleted** — `08` §7 forbids select-all and
    range-select on grants, so a group would be a folder with no verb, and adding a click at the
    moment the operator is most behind is a regression.
12. **Two densities, one default.** Comfortable (default) and Compact. Density changes row height and
    gutter only — never which fields render, because render law 1 is positional.
13. **Empty states name their own governing number; only swarm-produced-nothing states link `/gaps`.**
    No surface says "all clear", "no data" or "everything looks good" — that ban is universal and
    CI-enforced. The `/gaps` link is not: an empty `/leases` means nothing is contained and 18
    uncovered ATT&CK techniques answer a question it did not ask.
14. **An empty hold queue must name what ran without asking.** `StaticApprovalGate::evaluate` requires
    a human only when `destructive_action(request) && request.severity >= self.human_gate_severity`
    (`crates/swarm-policy/src/static_gate.rs:295-300`); everything else returns
    `static.default_allow`, "authorized for immediate execution" (`:301-304`). With the shipped
    `human_gate_severity: HIGH` (`rulesets/default.yaml:93`), every one of the twelve destructive
    actions at MEDIUM executes with no hold. A zero on this queue is not quiet.
15. **Four of the seven evidence card types — finding, escalation, hold, lease — carry no
    verifiable signature today, and the UI says so.**
    §2.2 renders per-card-type provenance instead of a blanket "Ed25519 ✓".
16. **The surface list stays closed at fourteen, and this revision adds no surface.** Take-the-watch
    is a control on surface 12; the Ledger export is a control on surface 10 that the brief already
    names ("Export a filtered set", `00-BRIEF.md` §3 row 10) and the first draft dropped; the review
    queue is a queue inside surface 1. The brief's own rule is that mechanisms inside surfaces are not
    routes.

---

## 1. The shell

### 1.1 Route table — NORMATIVE

Buzz declares twelve `route()` entries plus an `index()` in its virtual file routes
(`desktop/src/app/routes.ts:3-19`) and derives top-level view identity from a hand-written pathname
switch producing `AppView = home | channel | messages | agents | workflows | pulse | projects`
(`desktop/src/app/AppShell.helpers.ts:5-12`). That union is duplicated with no compiler link as
`SidebarSelectedView` in `features/sidebar/ui/AppSidebarPinnedHeader.tsx:16-23` — seven members each.
Perch replaces both unions in one edit and adds a `satisfies` cross-check so the next surface cannot
mis-highlight the rail.

This table is the single normative source for Perch routes. Any document naming a Perch path cites
this table.

| Path | View id | Lazy | Notes |
|---|---|---|---|
| `/` | `watch` | no | **The Watch.** The shift queue. Never lazy — it is the cold-start screen, and the Phase-1 home of the C9 counters (§3.0). |
| `/cases/$caseId` | `case` | yes | Case id **is** the NIP-29 channel UUID. |
| `/lanes/$laneId` | `lane` | yes | Twelve fixed threat-class channels. |
| `/leases` | `leases` | yes | Nav label "Containments" per `06` §2; route unchanged. |
| `/policy` | `policy` | yes | Read-only in v1. |
| `/watch-floor` | `watchfloor` | yes | **The Watchfloor.** Wall screen. Renamed from the brief's `/watch`; see decision 2 and §6.1. |
| `/ledger` | `ledger` | yes | Also mounted as the `Cmd-K` overlay. Carries the query-scoped export. |
| `/tuning` | `tuning` | yes | |
| `/handoff` | `handoff` | yes | Take the watch / End watch. |
| `/gaps` | `gaps` | yes | |
| `/settings` | `settings` | yes | **Must become a real route first.** Today `routes/settings.tsx:29-34` returns `null` and `AppShell` swaps the whole layout on `pathname === "/settings"`. |

Eleven routes, fourteen surfaces. The Verdict Row is `/`'s detail pane; the Case Canvas is a tab on
`/cases/$caseId`; the governance strip is chrome on every route; the swarmctl terminal is the
existing panel (`features/terminal/`) pinned to the open case.

### 1.2 Chrome

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ●●● GOVERNANCE healthy · committee of 1 (solo transport) · recv 41m ago       │ ← strip
│     watch held by connor since 22:00                                         │
├────┬──────────────────────┬──────────────────────────────────────────────────┤
│ C  │ WATCH             12 │                                                  │
│ O  │  Holds             4 │                                                  │
│ L  │  Findings   87 / 214 │                  ROUTE OUTLET                    │
│ O  │  Case activity     7 │                                                  │
│ N  │  Named you         — │                                                  │
│ Y  │                      │                                                  │
│    │ LANES                │                                                  │
│ ▣  │  lateral-movement  ● │                                                  │
│ ▢  │  data-exfiltration   │                                                  │
│ ▢  │  … 10 more           │                                                  │
│    │ CASES (3 open)       │                                                  │
│    │  case-0042      2h ⏱ │                                                  │
│    │ ─────────────────────│                                                  │
│    │  Containments Policy │                                                  │
│    │  Tuning       Gaps   │                                                  │
├────┴──────────────────────┴──────────────────────────────────────────────────┤
│ swarmctl ▸ case-0042                                            ⌃`  ▲        │ ← terminal
└──────────────────────────────────────────────────────────────────────────────┘
```

The colony rail is Buzz's `CommunityRail` (`features/sidebar/ui/CommunityRail.tsx`) verbatim: one
Ambush deployment per Buzz community, keyed remount on `communityKey`
(`desktop/src/app/App.tsx:402-407`). It answers "which deployment am I looking at" and nothing else —
`docs/CONSENSUS.md:307` names multi-tenant operator governance a non-goal and the rail must not imply
one. *(unverified: the CONSENSUS.md line number is carried from recon; the file was not re-read this
session.)*

The sidebar is Buzz's sidebar system (`features/sidebar/`) with four groups. Lane rows carry the
standard menu badge; a filled dot means the lane's live concentration is above `alert_threshold`,
**read from the ephemeral telemetry stream, not from a channel topic** (§2.5). Case rows carry a TTL
glyph, because a case channel archives itself on silence. The `Findings` row renders `reviewed /
total` for the shift, which is the only sidebar number that is a target rather than a count.

**Governance strip.** Persistent, 28px *(proposed height)*, above everything, reading the four
`PartitionState` values. It reuses `shared/api/useRelayConnection.ts:22-64`'s debounce discipline —
non-healthy states must persist 2s before painting, healthy clears instantly — because governance
flaps on a tick and a strobing strip teaches operators to ignore the one row that matters at decision
time. It renders `committee of 1 (solo transport)`, never a fraction: `SoloGovernorTransport` serves a
committee of one and refuses larger committees. It carries a **staleness clock** — "recv 41m ago" —
since governance liveness is not restart-safe and a strip that says `healthy` from a stale snapshot is
worse than one that says nothing. And, new in this revision, it carries **who holds the watch**,
because §3.3 routes pages to that person and a routing model whose subject is invisible is a routing
model nobody can audit. When no claim is held it reads `no watch claimed — classes 1–3 page everyone`.

---

## 2. The fourteen surfaces

### 2.1 The Watch — `/`

**Job.** The only screen a shift starts on, and the only screen that can end one. It answers: what
needs a decision from me, in what order, what did I already handle, and what happened without asking.

**Objects.** Primary: the four-queue inbox of `InboxItem`s. Secondary: filters, the resize handle,
the done/unread overlay, the served review-state map, the C9 strip.

**Provenance.** `features/home/ui/HomeView.tsx` (993 lines) two-pane, `features/home/lib/inbox.ts`
(626 lines), `features/home/useFeedItemState.ts`, `features/home/useResizableInboxListWidth.ts` (all
line counts by `wc -l` this session). The category machinery is already exactly the shape we need:
`FeedItemCategory` priority order is `needs_action=0, mention=1, agent_activity=2, activity=3`
(`lib/inbox.ts:326-337`) and `isActionRequired` is literally `categories.includes("needs_action")`
(`:615`). Perch keeps that priority function unchanged; only the labels, sources and per-row state
change.

#### Queue remap — corrected

| Buzz category | Perch queue | Source, verified |
|---|---|---|
| `needs_action` | **HOLDS** — held destructive actions (kind 46010) | `buzz-db/src/store/feed.rs:171-201`: `kind IN (46010, 40007)` **INNER JOIN `event_mentions`**, which `buzz-db/src/runtime/mod.rs:14-21, 95-105` populates from **p tags only**. The `p` tag on a 46010 is therefore load-bearing: a hold without one reaches nobody. |
| `mention` | **NAMED YOU** — a person named you in a case | `build_mentions_query` (`feed.rs:86-116`) is the same p-tag join restricted to `kind IN (9, 40002, 1, forum, git)`; `KIND_STREAM_MESSAGE = 9` (`buzz-core/src/kind.rs:479`), so a human's kind:9 message with a p tag lands here. |
| `agent_activity` | **FINDINGS TO REVIEW** — `ambush:finding:v1` cards, with served review state | `RuntimeEvent::Finding` → kind:9 marker card, per `03` §4 |
| `activity` | **CASE ACTIVITY** — movement on cases you joined | NIP-10 replies in a joined case channel |

Three corrections against the first draft, each verified:

**Due snoozes are not a relay-served needs-action row.** The first draft claimed the feed query
covers them. It does not. Buzz's snooze mechanism publishes **kind 30300**
(`KIND_EVENT_REMINDER`, `buzz-core/src/kind.rs:102`), NIP-44 encrypted to self, tagged only `d` plus
`not_before` or `expiration` — no `p` tag anywhere in
`desktop/src/features/reminders/lib/reminderService.ts:168-263`. The needs-action query's other kind,
`KIND_STREAM_REMINDER = 40007` (`kind.rs:491`), is queried, allow-listed and tested but **published by
nothing** in either tree — grep over `KIND_STREAM_REMINDER` returns only the feed query, the ingest
allowlists, the migration matcher and tests. So: a due snooze can never enter `needs_action` through
the relay. Perch computes due snoozes **client-side** from the operator's own 30300 reminders and
merges them into queue 1 locally, which is what Buzz already does. They render with a `local` marker
per render law 4, because they are the console's own state and not the daemon's. `07` §6's Watch
subscription must therefore be `{kinds:[46010]}` plus a separate `{kinds:[30300], authors:[me]}`.

**Escalations do not populate NAMED YOU.** The first draft sourced `mention` from
`Escalate { summary, urgency }`. That variant has exactly two fields and neither is a recipient
(`crates/swarm-core/src/types.rs:466-467`), and `RuntimeEvent::Escalation` carries `threat_class`,
`level`, `total_strength`, `distinct_sources`, `peak_confidence`, `mode_changed`, `current_mode` and
nothing else (`crates/swarm-runtime/src/runtime_events.rs:288-297`) — no operator, no host, no
summary. Nothing in Ambush names an operator. The only way an escalation could reach this queue is if
the bridge p-tagged an operator the event does not name; `03` already concedes that when shift
assignment is unknown the bridge p-tags every Approve-scoped operator, so every escalation would
mention everyone and the queue would become a duplicate of the lane channels and CASE ACTIVITY.
**Perch does not p-tag escalations.** Escalation cards go to their lane channel and to the case they
promote. NAMED YOU renders only when a *person* named you; in a solo deployment its header is
**absent, not zero**, and the sidebar row shows `—`. That is the honest rendering of a category that
exists because `FeedItemCategory` has four members.

**FINDINGS TO REVIEW is a queue, not a drawer.** The first draft collapsed `agent_activity` by
default and exempted it from all notification. That is the surface the entire tuning loop feeds
through: `01` leads on `is_suppressed_by_feedback`, `09` sets "≥20 `FalsePositiveMeasurement`
records/week per operator" and "≥0.5 of Friday's recommendations sourced from this week's verdicts",
and `01`'s falsification table kills the thesis below 20% traceable. Twenty verdicts a week is not
reachable from a collapsed drawer with no reviewed state and a modal per verdict. So:

- **Expanded by default**, with a shift target in the header: `87 reviewed / 214 this shift`.
- **Per-row review state**, three values (below).
- **Multi-select for `Confirm` and `Investigate` only.** Both set `false_positive: false` —
  `false_positive: matches!(request.action, ProvidenceFeedbackAction::Dismiss)`
  (`crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:492`) — so neither suppresses a
  single deposit. `08` §7's "no bulk anything" is scoped to grants, where it is correct and stays
  absolute; it was never an argument about a verb that changes no arithmetic.
- **Findings still never page.** A `Whisker` at 3,000 findings/hour must not produce an OS
  notification. The queue is the entry point; the shift target is the prompt.

#### Review state — served, with a client hint

Three per-row values, and they are three different facts:

| Value | Meaning | Source |
|---|---|---|
| `unreviewed` | No `FalsePositiveMeasurement` exists for this `finding_id` | Absence in the served map |
| `reviewed` | A measurement exists | `FalsePositiveMeasurement { finding_id, reviewed_at_ms, analyst_id, action, false_positive }` (`crates/swarm-spine/src/incident.rs:46-61`) |
| `not-yet-correlated` | The finding belongs to no incident, so no feedback route can accept it | See below |

The authority is the daemon. `providence_feedback_handler` writes through
`incident.upsert_false_positive_measurement(...)` and persists the incident
(`providence_handlers.rs:170-178`), and `build_alert_tuning_report` reads `IncidentRecord`
(`crates/swarm-runtime/src/alert_tuning.rs:4`). The console therefore needs a **read** of that state,
which `03` §11's wire-level list does not include (it is `B3r` in `09` §3.1's reconciled bill). This document names it as a dependency
rather than inventing it: **`GET /v1/operator/findings/reviewed?since_ms=` returning
`{finding_id, reviewed_at_ms, action, analyst_id}[]`**, a pass-through over data the daemon already
stores. Without it the review queue has no state, the operator cannot tell what they read last shift,
and the C9 "measurements written this week" counter is unmeasurable. It is a read, it authorizes
nothing, and it is the cheapest item on the bill.

The client may also keep a **hint**: a finding card with a verdict reply in its thread is probably
reviewed, and Buzz materializes `reply_count` on thread roots already. The hint paints instantly; the
served map is authoritative; disagreement snaps to the served value with a visible reason row. That is
render law 4 applied to review state, and it is the only place in Perch where the relay is allowed to
front-run the daemon — because the failure mode is a row that looks unread for two seconds, not a
wrong verdict.

#### `not-yet-correlated` — a verified blocker, designed around

`SwarmProvidenceFeedbackRequest` has `incident_id: String` — **not** an `Option`
(`crates/swarm-core/src/types.rs:144-152`) — and the handler 404s when the incident store cannot
resolve it: `load_by_incident_id(&request.incident_id) … ok_or_else(|| … not_found(format!("incident
`{}` was not found", …)))` (`providence_handlers.rs:129-137`). So the loop the product is named after
does not close for an uncorrelated finding. Perch does not hide this:

- A finding whose incident the daemon cannot resolve renders `not-yet-correlated`. Its verdict
  controls are **visible and disabled**, with the reason on the row: *"no incident record — feedback
  needs one. Promote to a case (`E`) to create it."*
- Promoting creates the case and the incident, and the verdict controls enable. This is the brief's
  own third arm of the case-promotion bar ("an analyst promoting by hand"), and it now has a concrete
  trigger rather than a vibe.
- If `03`'s `POST /v1/operator/findings/{id}/feedback` mints a single-finding incident itself, this
  state disappears and the copy goes with it. Either resolution is fine; **shipping the verdict
  control enabled against a route that 404s is not.**

#### Default view

Comfortable density. HOLDS, NAMED YOU (hidden when empty), FINDINGS TO REVIEW and CASE ACTIVITY all
expanded. Selection auto-lands on **the oldest undecided hold**, or — if there are none — the oldest
unreviewed finding. A queue sorted newest-first with selection on newest is how the 03:00 item at the
bottom never gets read.

**Wireframe (list pane, 365px default, 300–520 clamp —
`features/home/useResizableInboxListWidth.ts:3-6`):**

```
┌─ HOLDS ────────────────────────────── 4 ─┐┌─ VERDICT ─────────────────────────┐
│ ▸ HELD · kill_process                    ││                                   │
│   whisker-7a3f · web-04 · 02:41   ⏱ 12m  ││   (the Verdict Row, §2.2)         │
│   3 sources / 2 agents · lateral-movement││                                   │
│ ─────────────────────────────────────────││                                   │
│   HELD · block_egress                    ││                                   │
│   pouncer-11c2 · 203.0.113.10 · 02:38    ││                                   │
│   6 sources / 3 agents · command-and-c…  ││                                   │
│ ─────────────────────────────────────────││                                   │
│   SNOOZE DUE · dns_exfiltration  ·local  ││                                   │
│   returned 02:40 · you snoozed 3h ago    ││                                   │
├─ FINDINGS TO REVIEW ───── 87 / 214 ──────┤│                                   │
│ ○ dns_exfiltration · build-agent-07      ││                                   │
│   whisker-7a3f · 0.71 · 1 source/1 agent ││                                   │
│ ✓ lateral_movement · web-04   reviewed   ││                                   │
│ ⊘ beacon_v2 · db-02      not-yet-correl… ││                                   │
├─ CASE ACTIVITY ────────────────────── 7 ─┤│                                   │
│   case-0042 · weaver correlated 2 more   ││                                   │
└──────────────────────────────────────────┘└───────────────────────────────────┘
  12 promoted / 340 suppressed · median 41s to verdict · 87 measurements this wk
```

Row anatomy, fixed: **action verb or detector** (typed, mono) · **who** · **target** · **when** ·
**TTL if held** / second line **`N sources / M agents`** · **threat class slug**. Render law 2 is
enforced at the row, not just the detail: `findings_to_deposits` sets
`agent_id = "{agent}:{strategy_id}"` (`crates/swarm-whisker/src/stream.rs:20-22, 33-51`) and
`concentration_for` does `sources.insert(deposit.agent_id.0)`
(`crates/swarm-pheromone/src/substrate.rs:1294`), so `distinct_sources` counts strategy-scoped ids.
With `min_sources_for_escalation: 2` (`rulesets/default.yaml:57`) one Whisker running two detectors
clears the bar alone. The row shows both numbers always; expansion groups the ids by real agent.

The bottom strip is the **C9 instrumentation, and The Watch is its Phase-1 home** (§3.0). `/tuning`
and `/handoff` restate these three numbers and link here; they do not own them. `09`'s exit criterion
6 currently names a Phase-3 surface; §6.1 files the correction.

**Affordances.** Click selects (URL-mirrored). `J`/`K` move. `Enter` opens the case if one exists.
`E` promotes to a case. `S` snoozes with Buzz's five presets — *In 30 minutes / In 1 hour / In 3 hours
/ Tomorrow at 9am / Next Monday at 9am* (`features/reminders/lib/timePresets.ts:31-43`) — **on
findings only**. `S` is not offered on a hold, for `08` §3.5's reason rather than an arithmetic one:
a hold is a live gate with its own clock, the queue *is* the reminder, and a snoozed hold that
expires while hidden is a fail-closed action nobody chose. (The settled `hold_ttl_ms` is
**3_600_000** — 60 minutes, `08` §3.6 — so the 30-minute preset no longer outlives every hold; the
rule stands on the safety argument, not on the clock.) On a hold the honest verbs are `G`, `R`, and
letting it expire, which the row says. `M` marks done (`features/home/useFeedItemState.ts:67`), `U` marks unread (`:76`) — both
localStorage-backed per-pubkey with a 500-item cap (`:3-5`) and therefore explicitly **not** a
decision record; the copy never says "resolved". Right-click adds "Copy hold id" and "Open in Ledger".

**States.**

| State | Render |
|---|---|
| Empty (holds) | *"No held actions. **N destructive actions ran without a hold in this window** — below `human_gate_severity: HIGH`, or matched by an allow rule. [see /policy]"*, sourced from `RuntimeEvent::ResponseExecution` filtered to the twelve destructive kinds with an allow verdict. Never "all clear". |
| Empty (findings) | *"No findings this shift. 18 ATT&CK techniques across 11 detectors are intentionally uncovered → /gaps"* — this is a swarm-produced-nothing state, so the `/gaps` link is the right answer here (decision 13). |
| Loading | Buzz `SkeletonReveal` rows, queue headers real, counts absent (not zero). |
| Partial | Queue loaded, one queue errored: that header shows "count unavailable" and its own retry. Others render. |
| Stale | Bridge sequence gap → a full-width amber row *above* queue 1: "gap in the evidence stream: sequence 4471→4478 · 6 events not received · [verify with daemon]". Never a toast. |
| Degraded | Governance strip owns it; the queue keeps working and each held row gains "governance degraded — decision will be re-evaluated on submit". |
| Error | The existing full-pane error card — "Home feed unavailable" + message + Try again (`HomeView.tsx:593-600`), retitled. |
| Permission-denied | `OperatorScope::Read` is enforced on exactly one handler in the tree, `platform_api.rs:974` (the `/v2/api` surface), and on **no** `/v1/operator/*` handler. The Watch renders in full and `/settings` carries the honest note. |
| High volume | Above `PERCH_QUEUE_DEPTH_ALARM` (12) open holds: a banner — *"12 holds open. A queue this deep is a tuning problem, not a staffing one. → /tuning"* — the flat age-ordered list is retained, and the promoted/suppressed counter shows. **No grouping, no truncation, no cap.** |

**Does NOT.** Bulk-grant anything, ever. Bulk-dismiss. Sort by severity by default (age-first is
deliberate: severity sort buries the old quiet thing). Show a chart. Auto-refresh selection out from
under you — new items insert and the selected `conversationId` is stable by construction
(`lib/inbox.ts:38-45`). Group rows into folders with no verb. Claim a finding is reviewed on the
strength of a client-side hint alone.

### 2.2 The Verdict Row — detail pane of `/`

**Job.** Turn one held action or one finding into one typed, signed human act, without leaving the
queue.

**Provenance.** `features/home/ui/InboxDetailPane.tsx` (923 lines) is the frame;
`features/workflows/ui/WorkflowApprovalCard.tsx` is the card — today 31 lines whose entire action
surface is the string *"Approval actions are not yet available in Desktop."* (`:27`). That component
is the hole this product fills.

**Fixed field order (render law 1) — never varies by action type:**

```
┌──────────────────────────────────────────────────────────────────────┐
│ ACTION            kill_process                                       │
│                   host_id=web-04  process_name=svchost.exe           │
│                                                                      │
│ BLAST RADIUS      process_terminated · scope: process                │
│                   1 process on 1 host                                │
│                                                                      │
│ IF YOU UNDO       ✗ no executable inverse                            │
│                   KillProcess has no ContainmentInverse. Suspend is  │
│                   reversible; kill is not.                           │
│                                                                      │
│ WHY WE ARE ASKING no rule matched → static gate                      │
│                   human_gate_severity = HIGH; severity = HIGH        │
│                   selector: threat_class lateral_movement (read from │
│                     the requesting agent's evidence)                 │
│                             severity HIGH (asserted by whisker-7a3f) │
│                             action   kill_process                    │
│                   [see /policy — 3 rules, none matched this triple]   │
│                                                                      │
│ WHAT GRANTING     CapabilityLease · ttl 60s · scope host:web-04      │
│ OPENS             minted at your decision, not now                   │
│                                                                      │
├──────────────────────────────────────────────────────────────────────┤
│ EVIDENCE  3 sources / 2 agents  ▾                                    │
│   whisker-7a3f:suspicious_process_tree   0.91  02:39:12              │
│   whisker-7a3f:fileless_execution        0.77  02:39:12              │
│   stalker-22b8:lateral_movement          0.64  02:40:01              │
│   ⚠ 3 sources come from 2 agents. min_sources_for_escalation = 2.    │
├──────────────────────────────────────────────────────────────────────┤
│ PROVENANCE   signed by the bridge (secp256k1 Nostr envelope)         │
│              this card carries no Ed25519 signature of its own       │
│              [ verify against the daemon ]                           │
├──────────────────────────────────────────────────────────────────────┤
│ [ Record my decision and send it to the daemon ]   G                 │
│ [ Refuse ]                                          R                │
│ hold expires in 12m · after that the daemon dispatches nothing       │
└──────────────────────────────────────────────────────────────────────┘
```

Every one of those five labels is load-bearing and positional. At 02:41 the operator reads by
position, not by parsing. The field renders even when its answer is "unmapped" — an absent row is a
worse failure than an ugly one.

**The selector line is inside WHY WE ARE ASKING, not a sixth slot.** This is new in this revision and
it is the most authorization-relevant fact on the screen. The rule that judges a destructive action is
selected by values the *requesting agent* supplies:
`ConfigurableApprovalGate::threat_class_from_request` reads
`request.evidence["escalation"]["threat_class"]`, falling back to `request.evidence["threat_class"]`
(`crates/swarm-policy/src/configurable_gate.rs:34-41`); `selector_matches` then matches on that plus
`request.severity` and the action (`:44-56`); `evaluate` returns on the **first** match in file order
(`:143-180`); and `severity` is a plain field on `ActionRequest`
(`crates/swarm-policy/src/lib.rs:47-58`), set by the requester. Under the shipped default,
`command-and-control-emergency-block` allows `block_egress` at CRITICAL with no human
(`rulesets/default.yaml:107-117`) while `human_gate_severity` is HIGH (`:93`). A pane that renders
only `rule_name` never tells the operator that the rule was chosen by a value the requester asserted.
So the slot renders the matched triple with per-field provenance, marking `threat_class` and
`severity` as request-carried.

#### Provenance, per card type — the correction

The first draft rendered a blanket "attestation matches this body (Ed25519)". That is false for most
cards. Read this session:

| Card | Ed25519 signature on the artifact? | Verified at |
|---|---|---|
| `ambush:finding:v1` | **No.** `DetectionFinding` has seven fields, none a signature | `crates/swarm-whisker/src/detector.rs:50-59` |
| — its runtime envelope | **No.** `SwarmFindingEnvelope` has eight fields, none a signature | `crates/swarm-response/src/siem.rs:17-27` |
| `ambush:escalation:v1` | **No.** `RuntimeEvent::Escalation` is seven scalars | `runtime_events.rs:288-297` |
| `ambush:hold:v1` | **No.** `ActionRequest` is five fields; `HeldActionStore` does not exist yet | `swarm-policy/src/lib.rs:47-58` |
| `ambush:receipt:v1` | **No.** `ResponseReceipt` has no signature; `audit.governance.receipt` is an untyped `Option<serde_json::Value>` | `swarm-response/src/lib.rs:99-142` |
| the audit trail it sits in | **No.** `AuditTrail` is seven fields, none a signature | `crates/swarm-spine/src/lib.rs:113-122` |
| `ambush:rollback:v1` | **Yes, when attested.** `governance_attestation: Option<Value>` holds a serialized `ConsensusGovernanceReceipt` (`payload` + `DetachedSignature`) over the canonical receipt with that field cleared | `swarm-response/src/rollback.rs:265-285`; verifier `swarm-runtime/src/containment.rs:235-269`; type `swarm-consensus/src/lib.rs:379-383` |
| `PheromoneDeposit` | **Yes** — `signature: Vec<u8>` + `agent_key: Vec<u8>` over canonical content. But `03` §4.1 settles that deposits are never published | `crates/swarm-core/src/pheromone.rs:231-232` |

And the chain machinery the doc set cites is near-dead: `build_signed_envelope`
(`crates/swarm-spine/src/envelope.rs:71`) has **exactly one non-test caller in the workspace** —
`crates/swarm-runtime/src/approval.rs:1810`, the approval ledger — and `verify_chain_link` /
`ChainLinkVerdict` have zero consumers outside `swarm-spine`'s own `chain.rs` and its tests. (Matches
in `vendor/reference/clawdstrike/` are a reference tree, not the workspace.)

So the Verdict Row renders **PROVENANCE**, not ATTESTATION, and it renders one of four sentences:

1. **Unsigned artifact (finding, escalation, hold, response receipt):** *"signed by the bridge
   (secp256k1 Nostr envelope) · this card carries no Ed25519 signature of its own"*, with a
   **[verify against the daemon]** affordance that re-fetches the fact from `:9090` and reports
   agreement or disagreement. The daemon is the record; the relay is transport.
2. **Attested rollback receipt:** *"governance attestation verifies against this receipt body
   (Ed25519)"* — plus, mandatorily, the caveat the runtime itself wrote: `verify_release_attestation`'s
   own doc comment says *"do not read `attestation_verified: true` as 'a governor we trust authorized
   this'"* (`swarm-runtime/src/containment.rs:227-230`), because the governor public keys are not
   reachable from the runtime. Perch prints that limit next to the badge.
3. **`governance_attestation: None`:** the literal token **UNATTESTED**, in the warning family, no
   success styling. `attest_release_receipt` logs and tolerates a missing attestation rather than
   refusing to release a host (`containment.rs:271-278`), so `None` is a normal and important state.
4. **Malformed / signature failure / subject mismatch:** the three `ReleaseAttestationError` arms
   render as three distinct sentences, never one "invalid".

No shield icon exists in the design system to reach for (`05` §, icon list). The word "verified" never
appears without naming which chain was checked and what the check does not cover.

**If the daemon later wraps each fact in `build_signed_envelope` before it leaves** — the same one-call
pattern `approval.rs:1810` already uses — sentence 1 is replaced by a real Ed25519 row and the export
bundle in `08` §6.4 gains something to check. This document recommends that as **backend bill item 6**
and names it as `03` §11's to accept or reject. It does **not** make any Perch acceptance criterion
depend on it: the surfaces above ship correctly against today's unsigned facts, and they ship
*honestly*, which is the point.

**Who approved this is not in the chain either, and the row says so once.** `ActionRequest` has five
fields and none is an operator (`swarm-policy/src/lib.rs:47-58`); `ApprovalContext` has four and none
is an operator (`:61-72`); `ResponseGovernanceAudit` carries `governing_agent_id: AgentId` — Tom, not
the human (`swarm-response/src/lib.rs:136-142`); and
`audit_authorize_and_execute_human_approved_instrumented` takes `(detection, request, context)` and no
approver argument (`swarm-runtime/src/lib.rs:1085-1092`), differing from the autonomous path only by
the `allow_human_approved_execution: bool` at `:1133-1136`. A granted destructive action is therefore
byte-indistinguishable in Ambush's own record from an autonomous one except that `policy.verdict`
reads `require_human`. The operator id lives only in the proposed `HeldActionStore`, which is not the
chain. Perch's Ledger and any export must say *"a human was asked"*, never *"connor approved this"*,
until `03` §11 threads an `approved_by` through the receipt. §6.1 files that as a dependency.

**The two badge families (panel correction).** All three judges said "3 receipt-gated actions". It is
false and this document does not propagate it. `response_action_requires_governance_receipt`
(`crates/swarm-runtime/src/dispatcher.rs:1276-1292`) enumerates the same twelve variants as
`StaticApprovalGate::destructive_action` (`crates/swarm-policy/src/static_gate.rs:37-53`) — both
re-read this session, both `BlockEgress, IsolateHost, RevokeCredential, SinkholeDns,
TerminateUserSession, InjectFirewallRule, QuarantineFile, KillProcess, SuspendProcess,
DisableUserAccount, ForcePasswordReset, RemoveScheduledTask`. The genuinely-three set is
`ContainmentInverse` (`crates/swarm-response/src/rollback.rs:66-78`): `ReleaseQuarantinedFile`,
`ResumeProcess`, `RestoreHostConnectivity`.

| Family | Members | Where it renders |
|---|---|---|
| **Destructive / human-gated / receipt-required** | 12 of 15 actions | ACTION row badge |
| **Reversible** | 3 inverses | IF YOU UNDO row |
| **Which rule decided** | rule name + matched selector triple | WHY WE ARE ASKING row (text, never a badge) |

`SuspendProcess` is reversible; `KillProcess` is not. That non-obviousness is the whole reason the
row exists.

**Findings, not holds.** When the selected item is a finding, the same five slots render (BLAST RADIUS
becomes "none — this is a detection, not an action"; WHAT GRANTING OPENS becomes "nothing — feedback
opens no lease") and the action bar becomes the three typed verbs from `ProvidenceFeedbackAction`
(`swarm-core/src/types.rs:110-116`): **Confirm** `C`, **Dismiss** `D`, **Investigate** `I`. These
words are not decoration — they are the enum, and the moment Dismiss becomes a thumbs-down the tuning
loop is fed by an emoji.

**Dismiss is never a gesture (render law 5), but it is not always a modal.** `is_suppressed_by_feedback`
(`substrate.rs:1367-1380`) returns true when a `Dismiss` marker's timestamp is `>=` the deposit's, so
every matching deposit at or before the marker leaves the concentration sum. Two-stage commit:

- **First `D` arms** and expands the arithmetic inline in the row — deposits removed,
  `total_strength` before → after, and the `alert_threshold` it is measured against. Second `D`
  commits. Nothing is hidden; nothing costs a dialog.
- **A modal fires only when the delta crosses `alert_threshold`**, i.e. when the Dismiss will take a
  threat class below the line that decides whether anyone is ever told again:

```
Dismiss removes 4 deposits from lateral-movement concentration.
  total_strength 3.41 → 1.88   (alert_threshold 2.0)
  This lane will fall below its alert threshold.
[ Dismiss and suppress ]  [ Cancel ]
```

Suppression then renders as an explicit row in the case timeline. A retroactive edit to the swarm's
memory does not get to be invisible. Multi-select Dismiss does not exist.

**The grant control (render law 6, reconciled with `08` §3.5).** Its label is *"Record my decision and
send it to the daemon"*. It uses `variant="outline"`, never `variant="default"`, and a CI check —
`tools/check-perch-grant-affordance.sh`, patterned on
`desktop/scripts/check-pubkey-truncation.mjs` — fails the build if the verdict component names the
primary variant, or if the string `Approve` appears as a control label. `G` **opens** the scroll-gated
confirmation from `08` §3.5; it does not grant. `R` refuses in one keypress. `08`'s INV-11 ("does not
fire on key-repeat") is written against `A`; rewritten against `G`, it stands unchanged in substance
and §6.1 files the edit. Perch never authorizes: leg 1 is a signed `kind:9` card carrying the
`ambush:verdict:v1` marker into the case channel (**not** 46030/46031 — those are Buzz command kinds
that never reach storage; `03` §5.5), leg 2 posts to the daemon behind `invokeTauri`
(`shared/api/tauri.ts:296-309`), and the daemon re-evaluates policy and governance from scratch.

**States.**

| State | Render |
|---|---|
| Submitting | Button disabled, "sending to daemon…", no optimistic success. |
| Daemon accepted, policy re-refused | The row does **not** turn green. "The daemon re-evaluated and refused: `<reason>`. Your decision is recorded; the action did not run." |
| Hold expired mid-read | Whole card dims, action bar replaced by "this hold expired at 03:28 · no action was taken · [open in Ledger]". The row stays in queue 1 for the shift per `08` §3. |
| Daemon unreachable | "Cannot reach the daemon. Your intent record was published; the decision has not been delivered. [retry]". Never queues silently. |
| Finding not-yet-correlated | Verdict controls visible and disabled with the reason; `E` promotes and enables them (§2.1). |
| Provenance | One of the four sentences above. Never a shield, never a bare check. |
| Stale/derived | Any number Perch computed that the runtime did not carries a marker naming the producing function: `derived · alert_tuning.rs:build_alert_tuning_report`. |

**Does NOT.** Offer "approve with modifications". Offer a Deny button on any *approval-ledger* vote
(`validate_and_append_vote` hardcodes `ApprovalVote::Approve` — there is no signed reject path, and
the ledger surface is v2 anyway). Collapse the five fields for "simple" actions. Show a governance
quorum fraction. Claim the receipt names who approved.

### 2.3 Case — `/cases/$caseId`

**Job.** Hold one promoted hunt or `CorrelatedIncident` and everything said about it, by humans and
agents, until it goes quiet.

**Objects.** Primary: the timeline (kind:9 marker cards + human messages). Secondary: threads,
members, canvas, TTL, terminal scope.

**Provenance.** `features/channels` + `features/messages` timeline wholesale, including inline/drawer
thread modes and the members sidebar. The case id **is** the channel UUID. Membership is
re-authorized on every single delivery by `filter_fanout_by_access`
(`buzz-relay/src/handlers/event.rs:116-217`) — a stale subscription surviving a compartment change
cannot leak.

**TTL is the archive policy.** `channels.ttl_seconds` / `ttl_deadline` exist
(`desktop/src/shared/api/types.ts:20-21`) and `refresh_channel_ttl_after_event_insert`
(`schema/schema.sql:960-998`) pushes the deadline forward on every durable insert under a shared
per-channel advisory lock, with a `RAISE WARNING` fallback so a TTL failure never rejects an
otherwise-valid event. Activity renews; silence archives. The header renders the deadline as a clock,
not a bar — a bar implies a budget you are spending, and the operator is not spending anything.

**Case TTLs are hours; the audit horizon is not.** `07`'s retention job must not take its floor from
the longest case TTL, or a spec-compliant deployment detaches last quarter before the auditor asks
(§2.9, §6.1).

```
┌ case-0042 · lateral-movement · 2 members · archives in 5h 12m ──────┐
│ [Timeline] [Canvas] [Members] [Evidence]                            │
├─────────────────────────────────────────────────────────────────────┤
│ 02:39  whisker-7a3f                                                 │
│   ┌ FINDING · suspicious_process_tree · conf 0.91 ─────────────┐    │
│   │ web-04 · svchost.exe ← powershell.exe                      │    │
│   │ ▸ raw                             bridge-signed · unsigned │    │
│   └────────────────────────────────────────────────────────────┘    │
│ 02:40  weaver-9d01  ↳ 2 replies                                     │
│   ┌ CORRELATION · 3 included · 1 rejected ───────────────────┐      │
│   │ rejected: evt-8812 (temporal: 41m gap > window)          │      │
│   └───────────────────────────────────────────────────────────┘     │
│ 02:41  you                                                          │
│   ┌ HOLD · kill_process · web-04 ────────────────────────────┐      │
│   │ granted by you at 02:43 · lease cap-77f expires 02:44    │      │
│   └───────────────────────────────────────────────────────────┘     │
│ 02:44  ┌ RECEIPT · rollback: irreversible ───────────────────┐      │
│ 02:51  ── suppression: 4 deposits removed by your Dismiss ──         │
└─────────────────────────────────────────────────────────────────────┘
```

Evidence cards are kind:9 with versioned marker comments sniffed by content, using Buzz's own
`WAVE_MESSAGE_MARKER` path — the marker is `"<!-- buzz:wave:v1 -->"` at
`features/messages/lib/waveMessage.ts:1`, sniffed in `MessageRow.renderBody`'s default arm at
`features/messages/ui/MessageRow.tsx:413-427`. Ambush adds the seven `ambush:*:v1` markers
(`03` §13) to the same registry. Two hard requirements ride with that:

1. **The registry must come out of `MessageRow.tsx` first.** It is **998 lines** against a hard
   1000-line CI cap (`wc -l`, this session).
2. **The sniff must be hardened per `08` §7.7.** Buzz's own predicate is
   `content.trimStart().startsWith(WAVE_MESSAGE_MARKER)` (`waveMessage.ts:15-19`) over arbitrary
   content. Perch's fires only when the marker is the entire first line **and** the event's pubkey
   resolves to an admitted agent identity, because `ProcessStartEvent.command_line` and friends are
   adversary-authored and reach this renderer.

**Correlation is a thread.** `CorrelatedIncident` records `rejected_members` alongside
`included_members`; the rejected ones render with their per-dimension explanation, because "what we
decided not to link" is the part of a correlation an analyst actually audits.

**States.** Empty case (promoted but no evidence yet): "promoted by `<rule/analyst>` at 02:38 · no
evidence has landed" — a swarm-produced-nothing state, so it links `/gaps`. Archived: read-only
banner, composer replaced by "this case archived at 08:12 after 6h of silence · [reopen]". High
volume (>2,000 events): the existing virtualized timeline and the `top_level` window with composite
keyset cursors carry it unchanged.

**Does NOT.** Let you edit a signed artifact. Let you delete evidence. Offer huddle, video, GIFs,
reactions-as-verdicts, or custom emoji.

### 2.4 Case Canvas — tab inside a case

**Job.** Be the incident write-up while the incident is still happening.

`features/channels/ui/ChannelCanvas.tsx` is kind 40100, one shared markdown document per channel, with
`useCanvasQuery` / `useSetCanvasMutation` (`:5-6, 28-29`), a defer on the large parse and an existing
archived/read-only path. Perch seeds it from a template on case open — timeline, hypothesis, actions
taken, open questions, handoff notes — and both humans and agents write to it. *(The template is a
proposal; `ChannelCanvas.tsx` has no template mechanism today.)*

This is not a small win. Ambush's entire narrative capacity today is one `Option<String>` `notes`
field set at review-session creation. The canvas is the post-incident report, authored during the
incident, by everyone, versioned by the relay.

**Does NOT.** Auto-summarize. Lock to one editor. Replace the timeline.

### 2.5 Lanes — `/lanes/$laneId`

**Job.** The swarm's resting state, and the durable home for escalation cards that have not been
promoted to a case. Twelve permanent open channels, one per entry in `standard_threat_classes()`
(`crates/swarm-runtime/src/escalation.rs:315-330`), verified twelve this session: lateral_movement,
data_exfiltration, privilege_escalation, command_and_control, initial_access, persistence,
supply_chain, defense_evasion, credential_access, discovery, execution, impact.

#### The 1 Hz topic rewrite is deleted

The first draft rewrote each lane's channel topic on every `ConcentrationSnapshot`, coalesced to 1 Hz.
That is unaffordable and it pollutes the record. Three verified costs:

1. **A topic write emits a durable relay-signed message.** `set_topic` is followed unconditionally by
   `emit_system_message(… {"type":"topic_changed","actor":…,"topic":…})`
   (`crates/buzz-relay/src/handlers/side_effects.rs:1548-1564`), and that helper builds a
   `Kind::Custom(40099)` event signed with the relay keypair whose **durable insert is the completion
   boundary** (`:762-793`). So twelve lanes at 1 Hz is 720 `kind:9002` events **plus** 720 `kind:40099`
   rows per minute — about 2.07 million durable rows a day, to render a number that changes by 0.01.
2. **It is 6× one identity's entire write quota.** `enforce_ws_admission` bills every
   `ClientMessage::Event` against `LimitType::Messages` at `agent_standard_messages_per_min`
   (`crates/buzz-relay/src/connection.rs:652-708`), whose default is **120/min**
   (`crates/buzz-auth/src/rate_limit.rs:129-131`), and `LimitType::WsEvents` at
   `human_ws_events_per_sec = 10` windowed over 5s (`rate_limit.rs:126-128`,
   `crates/buzz-relay/src/admission.rs:40-45`). 720/min against 120/min. `07`'s identity budget table
   has no line for topic rewrites at all.
3. **It puts a `topic_changed` row in every lane timeline every second**, which is the timeline an
   analyst is supposed to read.

**Replacement.** The lane's live numbers — strength / sources / threshold — are read from the
**ephemeral telemetry stream** (`03`'s 26000-block `ConcentrationSnapshot`, coalesced to 1 Hz before
IPC) and rendered in the sidebar row and the lane header. Ephemerals are not stored and cost no
durable rows. The channel `topic` is written **only on a threshold crossing** — an
`EscalationLevel` change — which is a real event worth a durable audit row, and is bounded by
`deescalation_cooldown_secs: 300` (`rulesets/default.yaml:60`) rather than by a clock.

```
lateral-movement — strength 3.41 / 5 sources / 3 agents · alert 2.0 · incident 5.0
                   [live · 1 Hz · ephemeral]
```

Thresholds come from config (`rulesets/default.yaml:57-59`: `min_sources_for_escalation: 2`,
`alert_threshold: 2.0`, `incident_threshold: 5.0`) and render as numbers, not as a percentage of
anything. `RuntimeEvent::Escalation` is richer than the brief assumed — `threat_class`, `level`,
`total_strength`, `distinct_sources`, `peak_confidence`, `mode_changed`, `current_mode`
(`runtime_events.rs:288-297`) — so the escalation row renders completely with zero extra lookups. What
it does **not** carry is any host, region or operator key, which is why lanes are keyed on threat class
and nothing else, and why they never populate NAMED YOU (§2.1).

`ThreatClass::Custom(String)` findings land in the nearest standard lane and the row says so
explicitly (`classified Custom("beacon-v2") → shown in command-and-control`).

**All twelve ship muted.** `shouldNotifyForEvent` returns `true` for every top-level post
(`shouldNotify.ts:56-58`: `if (parentId === null) return true`), so an unmuted lane would notify on
every escalation card. Muting them is not a preference; it is the only way the four-wake-class model
in §3.3 survives contact with `features/notifications`.

**On keeping this surface at all.** The red team argued for cutting Lanes, and two of its three
arguments are now moot: the unaffordable behaviour is deleted, and the duplicated numbers now come from
the same ephemeral source the Watchfloor reads rather than from a second store. The third argument —
that a channel refusing human messages is a channel that does not want to be one — is answered by what
lanes are for: they are the `h`-scoped durable home for escalation cards that were never promoted, and
they are what a `#h`-filtered REQ subscribes to. Delete them and un-promoted escalations have nowhere
durable to live, which is precisely the "quiet queue" failure `/gaps` exists to fight. The surface
stays; its cost does not.

**Does NOT.** Accept human messages that are not annotations. Get created dynamically. Show a chart
(that is `/watch-floor`). Rewrite its topic on a timer.

### 2.6 Containments — `/leases`

**Job.** Answer "what is still contained right now, and is anything stuck".

Nav label and H1 are **Containments** per `06` §2 — `CapabilityLease` (a 60-second authorization,
`rulesets/default.yaml:94`) and `ContainmentLease` are two unrelated objects sharing one word. Route
unchanged.

One table, sorted by `expires_at_ms` then `lease_id` — the server already sorts this way and comments
that a listing whose order depends on the store makes two operators' screens disagree
(`crates/swarm-runtime-http/src/http/containment.rs:177-183`). Perch does not re-sort.

```
LEASE          ACTION            SCOPE        REMAINING   STATE
cap-77f3a2     kill_process      host:web-04  0s          ⚠ EXPIRED — still contained
cap-19bd04     block_egress      net:203.0…   00:41       open
```

`remaining_ms` and `expired` are two columns because they are two facts. The Rust doc comment says it
outright: `remaining_ms` *saturates at zero*
(`ContainmentLease::remaining_ms` is `expires_at_ms.saturating_sub(now_ms).max(0)`,
`crates/swarm-response/src/containment.rs:275-277`), so it "cannot distinguish 'expires in an instant'
from 'expired an hour ago and the sweep has not managed to release it'"
(`http/containment.rs:72-88`).

**The expired-lease copy is split by state.** This is a correction. An `expired: true` row that is
still listed does not mean "the TTL will handle it" — the doc comment is explicit that it means
*"the sweep has tried and failed to release it — see `release_lease`, which keeps such a lease open
rather than abandoning a host that is still contained"* (`http/containment.rs:82-87`), and
`is_expired(now_ms)` is a pure `now_ms >= expires_at_ms` comparison
(`swarm-response/src/containment.rs:270-272`). So:

| Lease state | Copy |
|---|---|
| Open | "The TTL is the backstop. This lease self-releases at 03:44." |
| `expired: true`, still listed | "**The TTL expired at 03:44. The sweep tried and failed. Nothing will release web-04 without you.**" |

There is **no extend affordance** — the type has one constructor and no settable expiry
(`containment.rs:74-95`). The disabled control stays visible with the reason, per `08` §4.

**Release.** `POST /v1/operator/containment/leases/{id}/release`, `OperatorScope::Maintenance`. The
result is read from the body, never the status code: `lease_closed` is computed by re-listing open
leases (`http/containment.rs:219-226`) and `fully_reversed` comes from `receipt.fully_reversed()`,
which is deliberately strict — non-empty steps AND every step `Reversed`; `Simulated`, `Irreversible`,
`Unsupported` and `Failed` all make it false (`rollback.rs:288-296`). A 200 with
`lease_closed: false` renders as a failure, in the fail-closed register, with the receipt. The
response's `attestation_verified` renders per §2.2's sentence 2 or 3.

**Daemon down.** The release button disables itself. The copy is state-split, same as the table: on an
**open** lease, "early release needs the running daemon. The TTL is the only backstop; this lease
self-releases at 03:44." On an **expired** lease, "early release needs the running daemon. The TTL has
already passed and the sweep already failed. This will not clear on its own."

**Empty state.** "Nothing is contained. `N` destructive actions ran without a hold in this window."
Not `/gaps` — an empty containment board is not a detection-coverage question (decision 13).

### 2.7 Policy — `/policy`

**Job.** Show which rule will decide before any human is asked, and show what selects it.

Rules are read from `policy.rules` and rendered in file order, reusing the workflows YAML document view
and the `CronExpressionInput` human-description pattern (a machine expression with a plain-language
line under it). `evaluate` returns on the first `selector_matches` hit
(`configurable_gate.rs:143-180`), so file order *is* precedence. The shipped default has three rules
(`rulesets/default.yaml:96-125`) and the middle one is the whole reason this surface exists:

```
policy.human_gate_severity = HIGH          lease_ttl_ms = 60000

EVALUATE AGAINST:  [ threat_class ▾ ] [ severity ▾ ] [ action ▾ ]      ← interactive
                     command_and_control   CRITICAL     block_egress

1  execution-after-hours-autorespond            ALLOW      · not matched
   threat_class execution · actions deploy_decoy, escalate · HIGH…CRITICAL
   ⓘ no human will be asked for these actions on execution findings at HIGH or above.

2  command-and-control-emergency-block           ALLOW      ← DECIDES THIS TRIPLE
   threat_class command_and_control · actions block_egress, escalate · CRITICAL only
   ⚠ THIS RULE OUTRANKS THE HUMAN GATE.
     block_egress is destructive and human_gate_severity is HIGH, but this rule
     matches first and allows it outright at CRITICAL.

3  credential-access-destructive-deny             DENY      · not reached
   threat_class credential_access · actions revoke_credential · LOW…HIGH
   ⓘ these are refused before any human sees them.

   ↓ no rule matched → StaticApprovalGate → RequireHuman at ≥ HIGH,
     else static.default_allow ("authorized for immediate execution")

⚠ threat_class and severity are supplied by the requesting agent.
  threat_class is read from request.evidence["escalation"]["threat_class"]
  (configurable_gate.rs:34-41); severity is a field on ActionRequest
  (swarm-policy/src/lib.rs:54-55). An agent chooses which rule judges its own
  destructive action.
```

**Shadowing is evaluated, not dimmed.** The first draft dimmed "shadowed" rules statically. Shadowing
is only computable per `(threat_class, severity, action)` triple, because that is exactly what
`selector_matches` consumes (`:44-56`). So `/policy` renders an **evaluation control**: pick a triple,
and every rule shows `decides` / `not matched` / `not reached`. Static dimming would assert a
containment relation the type system does not have.

The warning banner about request-carried selectors is permanent, not conditional. Read-only in v1:
`rulesets/default.yaml` is sha256-pinned inside a signed attestation whose key is deliberately absent
from the repo, so an edit UI would produce a config the runtime refuses to start on. The page says
that, with the file path.

**Empty state.** `policy.rules` empty: "no configured rules. Every request falls through to
StaticApprovalGate: RequireHuman for the twelve destructive actions at ≥ HIGH, `static.default_allow`
otherwise." Not `/gaps`.

### 2.8 Watchfloor — `/watch-floor`

**Job.** The ambient wall screen. Deliberately not the homepage — physics does not make decisions.

Hand-authored SVG, no charting library (Buzz has none, and the `--chart-1..5` tokens are not emitted by
`createThemeVars`, so anything built on them ignores the theme). Colour comes from CSS custom
properties and every label uses a named rem token so `check:px-text` passes.

Three bands:

1. **Decay field.** Per lane, the client evaluates `strength_at(now)` forward from the served
   deposits, draws the curve, and dashes the `alert_threshold` and `incident_threshold` rules. A
   crossing fires a ring once. **Render law 4 applies hard here**: the header shows the runtime's own
   `total_strength` from `ConcentrationSnapshot`, the curve is labelled `interpolation`, and on
   disagreement beyond tolerance the display snaps to the runtime's number and inserts a reason row.
   The client curve must never quietly out-vote `swarmctl`. This is why
   `GET /v1/operator/pheromone/deposits` must return the **post-suppression, post-evaporation** slice
   plus the resolved `ThreatClassPolicy` — `concentration_for` skips evaporated deposits, skips
   suppressed ones, and skips any whose strength has decayed to zero before summing
   (`substrate.rs:1279-1296`). A client re-deriving from raw deposits will disagree, and the operator
   will believe the screen.
2. **Colony health.** Eight roles × instances, from the ephemeral health stream. `AgentHealth` is
   `Healthy | Degraded | Failed` (`swarm-core/src/agent.rs:39-46`) rendered on
   `features/agents/ui/AgentStatusBadge.tsx` with its 15s presence grace period (`:8, :28-35`).
   **One change is mandatory:** that component applies `motion-safe:animate-pulse` whenever an agent is
   working (`:58`). Eight roles times N instances of simultaneously pulsing badges on a 24/7 wallboard
   is an attention-hijack and a photosensitivity problem. Perch caps pulsing to agents in an active
   turn on the *selected* case, and never on the wall screen.
   **Liveness is read from the ephemeral 26002 health stream, never from Nostr presence — and the
   reason is the lie-window, not the transport.** The first draft said presence is "single-node with
   no Redis `PUBLISH`". That is wrong: a kind:20001 update writes Redis presence state and then falls
   through to the shared channel-less ephemeral path, which does
   `publish_event(&conn.tenant, EventTopic::Global, &event)` before local fan-out — the code comment
   says so explicitly (`crates/buzz-relay/src/handlers/event.rs:813-847`, publish at `:877-891`). The
   real disqualifier is that presence is a **TTL-decayed status**: `SET … EX 180`
   (`crates/buzz-pubsub/src/presence.rs:3, 28-41`) refreshed on a 60s heartbeat
   (`crates/buzz-pubsub/src/lib.rs:331`), so a dead agent reads "online" for up to three minutes. A
   security console cannot render a three-minute lie about whether a detector is running. The decision
   is unchanged; the justification is now correct, and §6.1 files the same correction against `02` §5
   and `03` §4.2.
3. **Mode.** `SwarmMode = Normal | Alert | Incident` (`agent.rs:112-119`), monotonic upward, with
   `deescalation_cooldown_secs: 300` remaining as a number.

**Does NOT.** Accept clicks that change anything. Show per-host maps. Animate above 1 Hz. Show the
brand SVGs' numbers — the marketing asset says `alert_threshold 1.20` and the shipped default is
`2.0`; the console reads config, always.

### 2.9 Ledger — `/ledger` and the `Cmd-K` overlay

**Job.** One query bar over findings, receipts, leases, canvases and human verdicts — and the
quarterly artifact.

`features/search/lib/parseSearchOperators.ts` already parses `from:` / `in:` / `after:` / `before:`
with a deliberate token-start regex `/(?:^|\s)(from|in|after|before):(\S+)/gi` that avoids `\b`
because `\b` fires after `-` and `/` and would turn `built-in:react` into an operator (`:9-12, :37`).
`after:` maps to local-midnight `since`; `before:` maps to one second *before* local midnight because
NIP-01 `until` is inclusive (`:24-34`). Perch keeps all four verbatim and adds `class:`, `action:`,
`host:` and `agent:` as text-prefixed FTS terms — **not** as `#tag` filters, because NIP-01 indexes
only single-letter tags and the events are signed, so `strategy_id`, `host_id`, `receipt_id` and
`lease_id` are reachable through FTS only. That is a real, named, permanent cost and the empty-result
copy says so.

```
from:whisker-7a3f in:case-0042 after:2026-08-01 block_egress          [ Export ▾ ]
```

The row write is the index update (`search_tsv` is a generated stored column), so there is no
consistency window between a receipt landing and being findable. `buzz-search` returns candidates and
the relay re-authorizes each hit — Perch must not add a second search path that skips that.

**Export, restored.** The brief names it (`00-BRIEF.md` §3 row 10: "Export a filtered set") and the
first draft dropped it, leaving the named tertiary user — *"show me every destructive action in Q3 and
who approved it"* (`00-BRIEF.md` §1.1) — with no surface that does the job. `08` §6.4's export bundle
is scoped to one case; a quarter spans dozens. So `/ledger` exports **the current result set** in
`08`'s bundle shape: byte-identical stored events and any receipts they name, no reserialization, plus
`DERIVED.json` listing everything the console computed, plus `VERIFY.md`. Two constraints ride with it,
both stated in the export dialog:

1. **It answers "a human was asked", not "who approved this"**, until `03` §11 threads an
   `approved_by` through `ResponseReceiptAudit` (§2.2). The bundle says which, in words.
2. **Its horizon is the relay's retention window, not the case TTL.** `07` §'s monthly
   `DETACH PARTITION` job must take its floor from a configured audit-retention requirement; a floor
   of "≥ the longest case TTL" is a floor measured in hours (§2.3). §6.1 files it.

The alternative — dropping the auditor from the named users and pointing the quarterly job at
`swarmctl` against the daemon's own store — is coherent and cheaper, but it costs `01`'s
renewal-artifact argument. This document recommends the export and names the price.

This replaces an operator surface with **zero free-text search** and no way to enumerate incidents at
all: `/v1/operator/replay|investigation|incident` reject anything but exactly one selector, and the 49
routes registered in `crates/swarm-runtime-http/src/http/state.rs` (counted this session) include no
search route.

**Empty result.** "No matches. `strategy_id`, `host_id`, `receipt_id` and `lease_id` are searchable as
text but not as filters — NIP-01 indexes only single-letter tags and these events are signed." Not
`/gaps`: an empty search result is a query problem, not a coverage problem.

**Does NOT.** Offer saved searches in v1. Offer a SQL box. Return results the relay did not authorize.
Export a PDF (`08` §6.4 rejects it as unverifiable).

### 2.10 Tuning bench — `/tuning`

**Job.** Show what this week's verdicts changed, and make the next step a signed diff.

`build_alert_tuning_report` ranks three recommendation kinds against shipped thresholds — re-verified
at `crates/swarm-runtime/src/alert_tuning.rs:6-15`:

| Kind | min reviewed | min FP | min rate |
|---|---|---|---|
| `HostExclusionReview` | 2 | 2 | 0.75 |
| `DetectorThresholdReview` | 4 | 2 | 0.50 |
| `DetectorRuleReview` | 3 | 2 | 0.34 |

Capped at 6 recommendations (`:6`). Cards carry `summary`, `next_step`, `strategy_id`, `host_id`,
`reviewed_findings`, `false_positive_findings`, `false_positive_rate` and `supporting_signals` — every
field renders, and each card links through to the underlying verdicts in the Ledger. The UI pattern is
`features/settings/ui/ModerationQueueCard.tsx`'s grouped queue card with its severity chip, target
mono label, per-reporter lines and prior-action warning strip — reports-as-signals-never-triggers is
exactly the right posture for detector tuning. *(Note against the brief, which cites
`features/moderation`: that directory exists but holds `ReportMessageDialog`, timeout and
restriction-state code; the review-queue card is in `features/settings/ui`.)*

**The C9 numbers are restated here, not owned here.** The Watch (`/`) is their Phase-1 home (§3.0);
this page repeats median seconds page-to-verdict, measurements written this week, and the fraction of
*this report's* recommendations produced by this week's verdicts, and links back. If those numbers are
bad, the product's whole claim is false and the operator should see it before the recommendations.

**Empty state names its own number, not `/gaps`.** "No recommendations yet. `DetectorThresholdReview`
needs 4 reviewed findings and 2 false positives on one detector; `dns_exfiltration` has 1 reviewed."
That sentence tells the operator exactly what to do; a link to 18 uncovered ATT&CK techniques does not.

**Does NOT.** Auto-apply. The next step after a recommendation is a config-diff proposal a human
signs, and v1 stops at "here is the recommendation and here is what it came from" — no disabled Apply
button.

### 2.11 Handoff — `/handoff`

**Job.** Claim a watch, and end one, so the next analyst resumes exactly where this one stopped.

Composed entirely from parts that exist. `AppShellContext`
(`desktop/src/app/AppShellContext.tsx:11-123`) exposes three read frontiers as first-class API:
`getChannelReadAt` (NIP-RS channel marker), `getThreadReadAt` / `markThreadRead` (`thread:<rootId>`
context keys), and `getMessageReadAt` / `markMessageRead` (`msg:<id>` keys folded through the active
channel resolver, the "LP4 v3 per-message badge model") — read at `:29-48`. Those three are the entire
resumption payload.

#### Take the watch — new, and the paging model depends on it

§3.2 routes pages per-shift "to whoever holds the current watch claim". Nothing published one.
This surface now does, using verified relay machinery and no new event kind. **What it does not
do is change who is `p`-tagged on a hold:** `03` §5.4 settles that as every Approve-scoped
operator, because the bridge runs inside `swarm_detect --serve` and has no relay read path. The
claim is a *client-side paging filter* — every Approve-scoped operator's queue gets the row;
only the claim holder's client rings a phone. The two mechanisms are at different layers and
both ship:

- The claim is the **`topic` of a standing `#watch` ops channel**. Setting a topic requires only
  channel membership (`side_effects.rs:592-630`: "topic/purpose: any member"), writes through
  `set_topic`, and emits one relay-signed durable `kind:40099` `topic_changed` row
  (`:1548-1564`, helper at `:762-793`). One audit row per shift change, signed by the relay, readable
  by everyone, in a channel anyone can subscribe to.
- The claim carries the holder's pubkey and a **claim TTL** (proposed: 12 hours). Past the TTL the
  claim renders **stale**, the governance strip says so, and paging falls back to everyone.
- **End watch** clears the topic in the same mechanism.
- **Takeover is explicit and logged.** A second operator taking a held watch overwrites the topic —
  which is exactly one more `topic_changed` row naming both times. Perch does not gate it; it records
  it. The outgoing holder sees the change in the strip.

Everything about this is a proposal except the relay mechanics, which were read this session. The
alternative — deleting the per-shift routing claim from §3.3 and stating that v1 pages every
Approve-scoped operator — is the honest fallback if this control slips, and §3.3 names it.

#### End watch

Composes an Ambush `ReviewSession` from: every case you joined this shift with your three frontiers per
case; each case's canvas; open leases with their remaining TTLs and any `expired: true`; every snooze
you set and when it returns; every verdict you recorded; **reviewed and unreviewed finding counts**
(new — without them the incoming analyst cannot tell what was already read, which is the single
resumption fact the first draft omitted); and the promoted/suppressed counter. It publishes as a
case-channel message and posts the session to the daemon.

```
END WATCH — connor, 22:00 → 06:12

  CASES TOUCHED             3
    case-0042  lateral-movement   you read to 05:58 · canvas 14 lines · 1 open thread unread
    case-0039  archived 03:11
  FINDINGS REVIEWED       87 / 214   (127 unreviewed carry forward)
  HOLDS EXPIRED UNDECIDED    1   ⚠ must be acknowledged before ending
  OPEN CONTAINMENTS          2   (1 EXPIRED, host still contained → /leases)
  SNOOZES RETURNING          4   next 09:00
  VERDICTS RECORDED         11   9 confirm · 1 dismiss · 1 grant
  PROMOTED / SUPPRESSED  12 / 340

  [ End watch and publish handoff ]
```

Per `08` §3, `/handoff` cannot complete with unacknowledged expired-undecided holds. It does not block
on anything else — it lists.

**Empty state.** "No watch is claimed. [Take the watch]" — not `/gaps`.

**Does NOT.** Force a narrative. Block on unfinished work other than unacknowledged expired holds.
Assign the next shift to anyone — the incoming analyst claims; nobody is assigned.

### 2.12 Gaps — `/gaps`

**Job.** Be the honest answer to a quiet queue.

Verified from `rulesets/evasion/attack-technique-catalog.yaml` this session: **18** intentionally-
uncovered techniques (18 `technique:` keys) across **11** distinct detectors (11 unique `detector:`
values), each with a written rationale. Grouped by detector, each row: technique id, threat class,
rationale verbatim. No editorializing — the file's prose is better than any summary of it.

**Which empty states link here — narrowed.** The first draft required every empty state on every
surface to link `/gaps`. That turns a good idea into a mandatory non-sequitur: an empty `/leases`
means nothing is contained, an empty `/tuning` means the `alert_tuning` minimums are unmet, an empty
`/handoff` means no cases were touched, and an empty search means the query missed. Pointing all of
them at 18 uncovered ATT&CK techniques answers a question none of them asked, and under CI enforcement
the operator learns the link is boilerplate and stops following it on the one screen where it is the
right answer.

| Empty state | Links `/gaps`? | Names instead |
|---|---|---|
| The Watch — no findings this shift | **yes** | plus the technique counts |
| A lane with no escalations | **yes** | |
| A case promoted with no evidence | **yes** | |
| The Watch — no holds | no | destructive actions that ran without a hold (§2.1) |
| `/leases` | no | destructive actions that ran without a hold |
| `/tuning` | no | the unmet `alert_tuning` minimum, per kind |
| `/ledger` | no | the FTS-vs-tag limit |
| `/policy` | no | the static-gate fall-through |
| `/handoff` | no | "no watch is claimed" |

What **is** universal and CI-enforced is the ban: no Perch string ever contains "all clear",
"no data", "everything looks good", or "nothing to see". `tools/check-copy-banned-terms.sh` asserts
the phrase ban across `console/src`; it does not assert a `/gaps` link.

### 2.13 swarmctl terminal — panel, case-scoped

**Job.** Host the ~124 of 126 swarmctl subcommands that have no HTTP surface, honestly and
attributably.

`features/terminal/` over `src-tauri/src/terminal_runtime.rs` with `portable-pty`. The existing
`TerminalAttachRequest` already carries `channelId`, `channelName`, `threadId`, `npub` and `relayUrl`
(`features/terminal/terminalClient.ts:5-15`) — Perch adds the case id and pre-injects the right
`--*-results-dir` flags so every invocation is attributable to a case. The panel header says which
case it is pinned to; switching cases re-pins and says so.

The panel banner carries the non-fiction line: *"124 of 126 swarmctl subcommands are not HTTP clients.
This is a real shell on this host."*

Per `08` §7.7, the PTY is **the operator's tool, not an agent's**: adversary-controlled text never
crosses into it as instruction.

**Does NOT.** Wrap swarmctl in buttons. Pretend the CLI is an API.

### 2.14 Governance strip

Specified in §1.2. It is a surface because it is the only thing on screen at the moment of decision
that can tell you the decision will not hold — and, since this revision, the only thing that says who
the page would have gone to.

---

## 3. Cross-cutting UX

### 3.0 Normative key map and shared constants

Every document that names a Perch key or a Perch threshold cites this section. §6.1 files the brief
§12 amendment and the downstream edit list.

**Key map — NORMATIVE.**

| Key | Perch | Rationale |
|---|---|---|
| `Cmd-K` | Omnibox: query mode; `>` for command mode | One reflex; reuses the search dialog shell |
| `J` / `K` | Move selection in any list | |
| `Enter` | Open (case, lane, lease detail) | The only "open" verb |
| `C` / `D` / `I` | Confirm / Dismiss / Investigate a **finding** | The `ProvidenceFeedbackAction` enum's own words |
| `G` | **Open** the grant confirmation on a **hold** | `A` for "approve" is forbidden by render law 6; `G` opens, it does not grant |
| `R` | **Refuse** a hold, one keypress, no dialog | Asymmetric friction per `08` §3.5 |
| `S` | Snooze — **findings only** | A hold is a live gate with its own clock; a snoozed hold that expires while hidden is a fail-closed action nobody chose (`08` §3.5) |
| `E` | **Promote to a case** — one meaning, always | |
| `M` / `U` | Mark done / unread (local only) | |
| `Escape` | Close topmost surface. **Never** marks read | Decision 4 |
| `Cmd-\`` | Toggle terminal | |

`D` is Dismiss and never Deny. Deny is `R` (Refuse) and is a deliberately different letter, because
holds and findings interleave in the same queues and the same detail pane — under an `A`/`D` map, `D`
on one row refuses a destructive action and `D` on the row below it retroactively deletes deposits
from a concentration sum. The brief's render law 5 warns specifically about "a mis-keyed `D` at
03:00"; this is that hazard, and it is why the map changed.

`E` is **not** "route to another operator". `08` §3.3 proposes that binding, but no operator directory
exists anywhere in either tree, so there is nothing to route to. The verb is unbound until one does.

Buzz's six existing global bindings are verified at
`desktop/src/app/useAppShellKeyboardShortcuts.ts:56-98`: `Cmd-F` search current surface, `Cmd-K` search
everything, `Cmd-Shift-K` new message, `Cmd-Shift-N` create, `Cmd-Shift-O` browse, `Cmd-Shift-A` go
home. Perch keeps all six with remapped targets, **deletes** `Ctrl-Shift-Space` (huddle) and
**changes** `Escape`.

`tools/check-copy-banned-terms.sh` gains the key map: a `key: "A"` literal in any verdict-control
definition fails the build, alongside the `Approve` label ban and the bare-`lane` ban (§6.2).

**Shared surface constants — NORMATIVE.**

| Constant | Value | Status | Where it binds |
|---|---|---|---|
| `PERCH_QUEUE_DEPTH_ALARM` | 12 | proposed | The Watch banner (§2.1); `08` §7's queue-depth alarm. One constant, one behaviour. |
| `PERCH_HOLD_TTL_MS` | 3_600_000 | settled by `08` §3.6 | Hold expiry; the row's countdown; `08` INV-18 |
| `PERCH_WATCH_CLAIM_TTL_MS` | 43_200_000 (12 h) | proposed | `/handoff` claim staleness (§2.11) |
| `PERCH_CONCENTRATION_TICK_HZ` | 1 | settled by the brief | Coalescing before IPC |
| C9 counters' home | The Watch (`/`) | settled here | Phase-1 surface; `/tuning` and `/handoff` restate and link |
| Uncovered-technique counts | 18 techniques / 11 detectors | **verified** | Every `/gaps` link and swarm-empty state |
| Destructive action count | 12 of 15 | **verified** | Badge family 1 |
| Reversible inverse count | 3 | **verified** | Badge family 2 |

### 3.1 The omnibox

`Cmd-K` opens one dialog reusing `SearchDialogInputRow`
(`features/search/ui/SearchScopeControls.tsx:37-70`) including its scope chip. Empty input shows recent
cases and the five most-used commands. Typing searches (§2.9). Typing `>` switches to commands:
`> take the watch`, `> end watch`, `> release cap-77f3a2`, `> open gaps`. Commands that write are never
executed on `Enter` alone — they open the surface with the action staged. The palette is navigation and
staging, never a second authorization path.

**Rejected alternative:** a separate `Cmd-Shift-P` palette. Two overlays with near-identical chrome is
how operators end up in the wrong one at 03:00, and Buzz's `Cmd-K` reflex is already trained.

### 3.2 Notification and paging — the tension, resolved

Buzz's default is opt-in-to-noise, and it is real at the subscription level: `shouldNotifyForEvent`
(`features/notifications/lib/shouldNotify.ts:28-76`) returns true only for a broadcast reply, an
`@`-mention, a top-level post in an unmuted channel, or a thread you follow, participated in, or
authored. Everything else is silence by construction. A security console must page. These are not
reconcilable by tuning a setting, so they are **two paths**.

| Path | Governed by | Reaches |
|---|---|---|
| **In-app** (toast, badge, dock count) | `shouldNotify` unchanged | Whoever is looking |
| **Page** (OS notification, sound, external) | A separate predicate that never consults `shouldNotify` | Whoever holds the watch |

The page predicate admits exactly four classes, and the answer to a request for a fifth is no, at least
four times:

1. Mode transition to `Incident` (broadcast).
2. A held destructive action naming you (p-tagged mention).
3. A lease that failed to release — `expired: true` on a listed lease.
4. A due snooze.

Note what is absent: findings. A `Whisker` at 3,000 findings/hour must never page; the review queue in
§2.1 is their entry point, and a shift target is the prompt.

**Routing.** Classes 1–3 route to the watch holder published on `/handoff` (§2.11). **When no claim is
held, or the claim is stale, classes 1–3 page every Approve-scoped operator and the page body says
`no watch is claimed`.** Class 4 always pages only the operator who set the snooze, because a 30300
reminder is NIP-44-encrypted to self and nobody else can read it anyway. In the primary deployment —
one person and a laptop, per `00-BRIEF.md` §1.1 — "everyone" is one person and the distinction is moot;
the model exists for the rota, which is the elaboration.

**Class 3 has no backstop, and the copy must not pretend otherwise.** This is a correction. The first
draft said class 3 "has a backstop that needs no human at all: the lease TTL". For class 3 the TTL has
*already* expired and the sweep has *already* failed — that is what `expired: true` on a still-listed
lease means (`http/containment.rs:82-87`, §2.6). The 3am push for the one class where a host is
definitely still contained shipped the one sentence guaranteed false at that moment. The class-3 page
reads: *"web-04 is still contained. The TTL expired at 03:44 and the sweep failed. This will not clear
on its own."* No TTL-backstop sentence appears anywhere on the class-3 path.

Buzz's dock-badge and activation-queue machinery (which preserves click order when macOS drains several
notifications at once) is reused unchanged so a page lands on the exact hold.

### 3.3 Triage, assignment, and the four words

Ambush has no assignee field, no comments, no threads, no presence. Rather than invent an assignment
model we use the one already enforced end-to-end: **taking a case = joining its channel.** Publishing
your kind:39002 membership makes you a member, and membership is what `filter_fanout_by_access`
re-checks on every delivery. The members sidebar is therefore the assignee list.

Four states per queue item, and they are deliberately four different words:

| State | Meaning | Where it lives |
|---|---|---|
| **Read** | You looked | `AppShellContext` read frontiers, relay-synced |
| **Done** | You are finished with the row | `features/home/useFeedItemState.ts`, **localStorage only**, per-pubkey |
| **Reviewed** | A `FalsePositiveMeasurement` exists for this finding | The daemon, via the served map (§2.1) |
| **Decided** | You recorded a typed verdict on a hold | A signed `ambush:verdict:v1` card + the daemon's dispatch record |

Done is not a decision, Reviewed is not Read, and the copy never conflates them.
`useFeedItemState.ts:3-5` keys are `buzz-home-feed-done.v1` / `buzz-home-feed-unread.v1` with a
500-item cap — local, lossy, and fine for what it is, provided nothing calls it "resolved" and nothing
uses it as the review state.

### 3.4 Realtime — what is allowed to move

Two hard rules, because a console people watch for eight hours must be nearly still.

1. **Nothing moves under the cursor.** New items insert; selection never jumps; the selected
   `conversationId` is stable by construction (`lib/inbox.ts:38-45`). A new hold arriving while you
   read one shows as a count increment on the queue header, not a reflow.
2. **One coalesced tick.** `ConcentrationSnapshot` is coalesced to 1 Hz before it crosses the IPC
   boundary. TTL clocks tick at 1 Hz. Nothing else animates on a timer. Buzz's documented React perf
   trap applies directly: `React.memo` is all-or-nothing and a React Query result object is a new
   identity every render — a high-frequency telemetry stream will hit exactly this, and the debugging
   advice is to measure with DevTools closed.

**Loss is a rendered state, not a silence.** The bridge stamps a monotonic per-issuer sequence; a gap
renders as a gap (§2.1 Stale). The `RuntimeEvent` broadcast has capacity 1024 and a lagged receiver
drops silently — for this product that is a correctness bug, so the bridge spools to disk inside the
receive loop and the console shows what the spool could not fill.

### 3.5 Density and progressive disclosure

Two densities. **Comfortable** (default) and **Compact**, differing only in row height and gutter.
Density never changes *which* fields render, because render law 1 is positional and a compact mode that
hides IF YOU UNDO is a safety regression.

Disclosure has exactly three levels, everywhere:

1. **Row** — verb, who, target, time, `N sources / M agents`, review state.
2. **Card** — the five fixed fields plus evidence and provenance.
3. **Raw** — the untruncated artifact: full 64-hex ids, the canonical bytes, and any signature that
   exists. Buzz's `PubKey` component already encodes the doctrine — `variant="full"` is *required* on
   security-decision surfaces — and a CI guard bans ad-hoc `pubkey.slice(0, N)` because truncated
   prefixes are forgeable by vanity grinding. Perch extends that guard to Ed25519 identities and shows
   the RFC 8785 bytes before any signature check (contrarian C5). Where no signature exists, the raw
   view says so rather than showing an empty field.

### 3.6 Mobile

Out of scope for v1, per the brief. Worth stating what that costs and what it does not: because durable
evidence rides marker-prefixed kind:9 rather than new stored kinds, the Flutter app, the web client,
`buzz messages thread` and search snippets all render Ambush evidence *today* as a message with a
one-line human fallback. Mobile does not need a port to be honest — it needs a port to be useful. The
v1 answer to "page me at 3am" is the OS notification and a deep link that cold-starts the desktop app,
using Buzz's queue-with-explicit-ack deep-link protocol whose drain fails closed during a community
switch so a link queued for colony A can never route inside colony B.

### 3.7 One shift, walked end to end

The red team's sharpest structural note was that the surfaces were specified individually and never
walked as a day. Here is the day, with the surface each step lands on.

| Time | What happens | Surface | What the design owes it |
|---|---|---|---|
| 22:00 | Analyst opens Perch, presses **Take the watch** | `/handoff` | Without this the paging model has no subject (§2.11) |
| 22:01 | Lands on `/`. Selection is on the oldest undecided hold, not the newest row | `/` | Age-first selection (§2.1) |
| 22:03 | Works 6 holds: `G` opens the gate, `R` refuses one | `/` detail | Asymmetric friction (§2.2) |
| 22:40 | Works findings. `C`/`I` multi-select for the obvious ones; `D` twice on a nightly job; a modal only when the delta crosses `alert_threshold` | `/` queue 3 | Bulk scoped to non-suppressing verbs (§2.1) |
| 23:15 | Hits a `not-yet-correlated` finding. `E` promotes it; the case and incident exist; the verdict enables | `/` → `/cases/…` | The `incident_id` blocker, designed around (§2.1) |
| 01:00 | Break. Comes back. `87 / 214` in the sidebar says exactly what is left | sidebar | Served review state (§2.1) |
| 02:41 | Page: held `kill_process` naming them. Notification lands on the exact row | OS → `/` | Class 2 (§3.2) |
| 02:43 | Grants. Daemon re-evaluates, mints the lease at decision time, dispatches | `/` detail → daemon | Two-legged write (§2.2) |
| 03:44 | Page: a lease failed to release. The push says nothing will clear it | OS → `/leases` | Class 3 copy (§3.2, §2.6) |
| 05:30 | Reads `/tuning`. `DetectorThresholdReview` on `dns_exfiltration` from tonight's four Dismisses | `/tuning` | Thresholds 4/2/0.50 (§2.10) |
| 06:12 | **End watch.** Frontiers, canvases, leases, snoozes, verdicts, reviewed counts | `/handoff` | Reviewed counts carried forward (§2.11) |
| Quarter | Auditor runs one query and exports the result set | `/ledger` | Export, and its two honest caveats (§2.9) |

Four jobs the brief names and the first draft left unowned — claiming a watch, working 214 findings
without losing your place, knowing what you already reviewed, and handing an auditor a quarter — each
now has exactly one surface and one control.

---

## 4. Three end-to-end flows

### 4.1 A live escalation with a human gate

```
02:39  Whisker deposits 2 findings on web-04  → lateral-movement crosses alert_threshold
       strength 1.9 → 3.41 · sources 3 / agents 2 · alert_threshold 2.0
02:40  Weaver correlates; SwarmMode Normal → Alert
02:41  Pouncer requests kill_process. ConfigurableApprovalGate reads threat_class from
       the request's own evidence, walks policy.rules in file order: 3 rules, none match
       (threat_class=lateral_movement, severity=HIGH, action=kill_process).
       Falls through to StaticApprovalGate → RequireHuman (destructive && HIGH ≥ HIGH).
       Daemon persists a HeldActionStore entry and emits RuntimeEvent::ResponseHeld.
```

1. Bridge receives `ResponseHeld` in-process via `IngestState::subscribe_runtime_events()`, spools it,
   stamps sequence 4472, publishes a kind:46010 into the case channel **p-tagging the watch holder** —
   without that p tag `query_needs_action`'s INNER JOIN on `event_mentions` never fires and the hold
   reaches nobody — and an ephemeral for the lane.
2. Perch's HOLDS queue increments. Because the hold names this operator, page class 2 fires: one OS
   notification, one sound.
3. Operator clicks the notification. The activation queue lands on `/` with that item selected. The
   Verdict Row renders the five fields in order. `IF YOU UNDO` says **no executable inverse** —
   `KillProcess` is not one of the three `ContainmentInverse` variants. `WHY WE ARE ASKING` says
   **no rule matched → static gate**, prints the matched-nothing triple, and marks `threat_class` and
   `severity` as request-carried.
4. Operator expands EVIDENCE. `3 sources / 2 agents` — two of the three ids are the same Whisker under
   two strategies. That is the fact that changes the answer.
5. Operator presses `Enter` to open the case, reads Weaver's correlation, sees one rejected member with
   a 41-minute temporal gap, and returns.
6. Operator presses `G`. The scroll-gated confirmation opens; confirming publishes leg 1 — a signed
   `ambush:verdict:v1` human intent record into the case channel — and posts leg 2 to the daemon behind
   `invokeTauri`. The daemon re-evaluates policy and governance from scratch, mints the
   `CapabilityLease` **now** (`lease_ttl_ms` is 60000, so a lease minted at hold time would have died
   45 minutes ago), dispatches, and writes the receipt.
7. `/leases` gains `cap-77f3…`, remaining 00:60. The case timeline gains a HOLD card marked granted and
   a RECEIPT card whose rollback line reads **irreversible**, not "undo available", and whose
   provenance line reads *"signed by the bridge · this card carries no Ed25519 signature of its own ·
   [verify against the daemon]"*.
8. If the daemon refuses on re-evaluation, the row does not turn green: "your decision is recorded; the
   action did not run" plus the reason.
9. What the record does **not** say: who approved it. `ResponseReceiptAudit` carries
   `governing_agent_id` (Tom) and no operator field, and the human-approved entry point takes no
   approver argument. The Ledger row for this action reads "a human was asked" until `03` §11 threads
   `approved_by` through.

### 4.2 A retrospective hunt over last week's pheromones

1. `Cmd-K`, type `in:lane-credential-access after:2026-08-18 before:2026-08-25 kerberos`. Four
   operators are parsed by `parseSearchOperators`; `kerberos` goes to FTS. Note the semantics the
   parser already encodes: `before:2026-08-25` excludes the 25th, Slack-compatible (`:24-34`).
2. Results are candidates from `buzz-search`, re-authorized per hit by the relay, rendered as Ledger
   rows: findings, receipts, and the human verdicts on them side by side. Nothing here is reachable in
   Ambush today — the 49 operator routes include no free-text search and cannot enumerate incidents at
   all.
3. Operator opens `/watch-floor`, scopes the decay field to credential-access over that week. The
   header shows the runtime's `total_strength`; the curve is labelled `interpolation`; the served slice
   is post-suppression and post-evaporation so it agrees with `swarmctl`.
4. Operator spots a cluster that never crossed `alert_threshold` because `distinct_sources` was 1.
   Expanding shows one agent under one strategy. They promote it by hand with `E` — the third arm of
   the case-promotion bar — and the promoted/suppressed counter on `/` increments on the promoted side.
5. The new case seeds a canvas from the retro template. The swarmctl panel re-pins to the case with the
   right results dirs, and they run the ~124 subcommands that have no HTTP surface, attributably.
6. Quarter end: the same query, plus `action:` terms, exported from `/ledger` as an `08`-shaped bundle
   whose manifest states both caveats — no approver in the chain, and a horizon set by the relay's
   configured audit retention rather than by any case TTL.

### 4.3 A detector tuned after a false positive

1. A `dns_exfiltration` finding on `build-agent-07` reaches the FINDINGS TO REVIEW queue,
   `unreviewed`. The operator recognizes a nightly job.
2. They select it. The Verdict Row's action bar is Confirm / Dismiss / Investigate. They press `D`
   once: the row expands to show 4 deposits removed, `total_strength 3.41 → 1.88`, against
   `alert_threshold 2.0`.
3. Because the delta crosses the threshold, the modal fires. They accept.
4. Leg 2 POSTs to `/v1/operator/findings/{id}/feedback`, which writes the **same**
   `FalsePositiveMeasurement` the Providence webhook writes — `finding_id`, `hunt_id`, `strategy_id`,
   `host_id`, `feedback_id`, `reviewed_at_ms`, `analyst_id`, `action`, `reason`, `false_positive`
   (`crates/swarm-spine/src/incident.rs:46-61`), with `false_positive: true` because
   `matches!(request.action, ProvidenceFeedbackAction::Dismiss)`
   (`providence_handlers.rs:492`). `analyst_id` is the operator, not a webhook — the one place in the
   product where a human's identity does reach Ambush's own record.
5. The row flips to `reviewed` from the served map on the next poll; the client hint flips it
   immediately and is overridden if they disagree.
6. The case timeline gains an explicit suppression row. The lane's live numbers fall on the ephemeral
   stream; the lane topic is untouched, because no threshold was crossed downward yet.
7. After four such verdicts on `dns_exfiltration`, `build_alert_tuning_report` clears
   `DETECTOR_THRESHOLD_MIN_REVIEWED = 4`, `MIN_FALSE_POSITIVE = 2`, `MIN_RATE = 0.50`
   (`alert_tuning.rs:10-12`) and a `DetectorThresholdReview` card appears on `/tuning` with its
   `supporting_signals`, linking back to the four verdicts.
8. The C9 strip on `/` updates: measurements written this week, median page-to-verdict, and the
   fraction of the current recommendations produced by this week's verdicts. The loop is closed and,
   more importantly, it is *measured* on the surface the operator is already looking at.

**The precondition, stated.** Steps 4–7 require the finding to belong to an incident, because
`SwarmProvidenceFeedbackRequest.incident_id` is not optional and the handler 404s on an unresolvable id
(`swarm-core/src/types.rs:144-152`; `providence_handlers.rs:129-137`). If `03`'s new route does not
mint a single-finding incident, this flow begins with `E` to promote, and the queue says so on the row
rather than failing at submit.

---

## 5. What Perch deliberately does not do

The surface list is closed at fourteen. Adding one requires deleting one, and that rule is enforced by
the route table in §1.1 being a hand-declared list a reviewer can count. **This revision adds no
surface:** Take-the-watch and the Ledger export are controls on existing surfaces 12 and 10, and the
review queue is a queue inside surface 1.

Deleted from Buzz (surgery scoped in `02-ARCHITECTURE-INTEGRATION.md`): huddle, the burst/poof/sound
layer, the 10-swatch accent picker (it overwrites `--primary` with Red/Green/Orange and destroys
severity legibility — the accent is pinned), GIFs and remote link previews, projects/git forge, forum,
pulse-as-social, top-level DMs, the agent process-management half of `features/agents` (the roster,
`AgentStatusBadge` and the 15 `AgentActivityRenderClass` presenters stay —
`features/agents/ui/agentSessionTypes.ts:24-39`, counted this session), mesh-llm, mobile.

Never built: a second authorization path, a second audit chain, an approval-ledger voting surface (the
no-Deny-button and show-the-RFC-8785-bytes constraints ride with it into v2), a ruleset editor,
auto-apply of tuning recommendations, a charting dependency, role-gated UI (until `OperatorScope::Read`
is enforced on any `/v1/operator/*` handler — it is enforced today only at
`crates/swarm-ingest-runtime/src/ingest/platform_api.rs:974`, on the `/v2/api` surface, and `/settings`
says so plainly), a shared-tenancy claim, a bulk grant, a group with no verb, and any empty state that
says everything looks good.

Never claimed: that the console authorizes anything; that a finding, escalation, hold or response
receipt carries its own Ed25519 signature today; that the audit chain names who approved a destructive
action; that a quiet queue means a quiet night.

**Housekeeping that blocks the first surface, not a follow-up:** `AppShell.tsx` is 997 lines and
`MessageRow.tsx` is 998 against a hard 1000-line CI cap (both by `wc -l`, this session). Split both,
and lift the renderer registry out of `MessageRow` before the first evidence card lands.
`resetCommunityState` becomes a typed registry with an exhaustiveness check in the same change that
adds the first Ambush singleton — a missed reset there is cross-colony disclosure, not a stale cache.

---

## 6. Cross-document reconciliation

### 6.1 Amendments this document requests under brief §12

Each row is a conflict where two or more documents specify incompatible behaviour. This document takes
a position and names the sites; none of these can be resolved inside one document.

**Status, after the cross-document reconciliation pass.** Every row below has been adjudicated and
the sibling documents edited. A1, A3, A4, A5, A6, A7, A8, A9, A12, A13 and A14 are **applied** and
are recorded as brief amendments in `00-BRIEF.md` §13 (A1→A1, A3→A3, A4→A6, A8→A8) or inside the
owning document. A2 was already satisfied (§2.2 adopts `08`'s friction). A10 and A11 became backend
bill items **B3i** and **B3r** in `09` §3.1. **The `path:line` pointers in the right-hand column are
from before those edits and are stale; use the section references.** Values that used to be restated
in three documents now live once in `APPENDIX-NORMATIVE.md`.

| # | Conflict | Position taken here | Sites to change |
|---|---|---|---|
| A1 | **Keymap.** `04` specifies `C`/`D`/`I` + `G`/`R`; `01`, `05`, `06`, `07`, `08`, `09` ship `A`/`D`/`E`/`S` | Adopt §3.0. `A` = "approve" violates render law 6; `D` cannot mean Dismiss and Deny on interleaved rows | `01:167, 348-351`; `05:836`; `06:566-570` (grant key; rename `deny` → `refuse`/`R`); `07:749` (spec name); `08` §3.3 wireframe, §3.5 table, INV-11 (`A` → `G`); `09:144, 170`. Brief §3 row 2. |
| A2 | **Grant friction.** `04`'s first-draft wireframe granted on one keypress; `08` §3.5 mandates a scroll-gated modal | Adopt `08`. `G` opens the gate; `R` refuses in one key. Fixed here in §2.2 | none in `08` |
| A3 | **Watchfloor route.** `04` uses `/watch-floor`; every other doc uses `/watch`, which `04` gives to The Watch | Ratify `/watch-floor` (§1.1) | `00 §3` row 8; `01` (6); `02` (3); `03` (2); `05` §11; `06` §2.2 route table, `NAV.watchfloor`, `EMPTY.watchAll.action`; `07` (3); `08` (2); `09` §5 and the **five v0-fallback sentences** which must read ``/watch-floor` + `/ledger` + `/gaps`` |
| A4 | **C9 counters' home.** Named on `/watch` (brief §8.2, `01` §8), `/` (`04` §2.1), `/tuning` (`04` §2.10), `/handoff` (`08` §3.6, §7.1); `09` makes them Phase 1 while `/tuning`, `/handoff` and the Watchfloor are Phase 2–3 | The Watch (`/`) owns them; the others restate and link (§3.0) | `09` exit criterion 6; `08` §3.6, §7.1 (mark as restatement) |
| A5 | **Queue-depth constant.** `04` grouped at 50; `08` §7 banners at 12 | One constant, `PERCH_QUEUE_DEPTH_ALARM = 12`; grouping deleted (§3.0, §2.1) | `08` §7 cites §3.0 |
| A6 | **Snooze on holds.** `08` §7 prescribes snooze as the anti-habituation valve and elsewhere disables every preset on a hold | Every Buzz preset (≥30 min) outlives a 900 s hold. `S` is findings-only (§3.0) | `08` §3, §7 |
| A7 | **Presence justification.** `02` §5 and `03` §4.2 say presence is "single-node with no `PUBLISH`" | Wrong; it publishes to `EventTopic::Global` (`event.rs:877-891`). The real reason is the 180 s TTL lie-window (`presence.rs:3`) — `07` §13 already has this right | `02` §5 crate table; `03` §4.2 |
| A8 | **Ed25519 verification.** `03` §2, `08` §6, `09` §2 exit criterion 1 and `02` §13's contract test all assume a signed artifact | Four of the seven card types carry none (§2.2 table). Rewrite the exit criterion and contract test against bridge-signature + daemon re-fetch, and add `build_signed_envelope` as optional backend item 6 | `02` §13; `03` §2; `08` §6; `09` §2 |
| A9 | **Approver in the chain.** The product spine claims "who approved it" | No field exists anywhere on the path (§2.2). Add `approved_by` as backend item 1.5, or drop the claim from `01` and `08` §6.4 | `03` §11; `01` §7; `08` §6.4 |
| A10 | **Feedback needs an `incident_id`.** `03`'s route as specified cannot accept an uncorrelated finding | Either mint a single-finding incident in the route, or ship the `not-yet-correlated` state (§2.1). Both are acceptable; silence is not | `03` §11 item 3 |
| A11 | **Review-state read.** No route serves it; the review queue and the C9 metric both need it | Add `GET /v1/operator/findings/reviewed?since_ms=` (§2.1) | `03` §11 |
| A12 | **Retention floor.** `07` sets it at "≥ the longest case TTL"; case TTLs are hours | Set it from a configured audit-retention requirement and state it in the deployment doc (§2.9) | `07` §; deployment doc |
| A13 | **Lanes topic rewrite.** `03:231, 473` and the brief make it a 1 Hz kind:39000 rewrite | Deleted: a topic write emits a durable relay-signed kind:40099 (`side_effects.rs:1548-1564, 762-793`) and 720/min is 6× a 120/min quota. Change-triggered only; live numbers ride ephemerals (§2.5) | brief §3 row 4; `03:231, 473`; `07`'s identity budget and subscription tables |
| A14 | **Empty-state `/gaps` rule.** `04` decision 8, `06`, and `09:251` make the link universal and CI-enforced | Scoped to swarm-produced-nothing states; the phrase ban stays universal (§2.12) | `06` empty-state module; `09:251` |

### 6.2 The word "lane"

"Lane" is load-bearing in four incompatible senses across the set: twelve threat-class channels
(`04` §2.5, `03`); the four inbox categories (`04` first draft, `06` `LANE_LABELS`); the three-hue
semantic taxonomy (`05`: `--lane-substrate`, `--lane-authority`, `--lane-evidence`); and four bridge
transport classes with per-lane spool budgets (`07`). "The evidence lane" is simultaneously a colour
token and a 256 MiB disk spool. This is exactly the defect `06` identifies and bans for "lease" — two
unrelated objects sharing one word, both rendering only as the compound.

The set applied its own rule to the domain's word and not to its own invention. Fix:

| Sense | New word | Owner |
|---|---|---|
| Twelve threat-class channels | **lane** (kept — the only operator-visible sense) | `04` §2.5 |
| Four inbox categories | **queue** | `04` §2.1 (done in this revision), `06` `QUEUE_LABELS` |
| Three-hue taxonomy | **pillar** (`--pillar-substrate`, …) — `05` §2.1 chose this over *family* because `docs/assets/pillars.svg` is the trio's source file and *family* is already spent on the two badge families | `05` |
| Four bridge transport classes | **stream** | `07` |

`tools/check-copy-banned-terms.sh` gains bare `lane` outside the nav sense, alongside bare `lease` and
the `Approve` label ban.

### 6.3 Findings partially rebutted

**"RollbackReceipt carries only ids back to the governance receipt, no signature of its own."** Half
right. `RollbackReceipt.governance_attestation: Option<serde_json::Value>` holds a serialized
`ConsensusGovernanceReceipt` — `payload` plus a `DetachedSignature`
(`crates/swarm-consensus/src/lib.rs:379-383`) — over the canonical receipt *with that field cleared*
(`rollback.rs:277-285`), and `verify_release_attestation` checks the signature **and** the subject
binding, refusing on `Unattested`, `Malformed`, `Signature`, `Canonicalization` or `SubjectMismatch`
(`swarm-runtime/src/containment.rs:235-269`). The release route already reports `attestation_verified`
(`http/containment.rs:219-221`). So rollback receipts are the one response-side artifact with a real,
already-wired Ed25519 verification, and §2.2 renders it — with the runtime's own caveat that
`attestation_verified: true` is not "a governor we trust authorized this" (`containment.rs:227-230`).
The finding's *conclusion* stands for the other five card types and the correction is made; the
rollback row is the exception and is now cited rather than assumed.

**"Cut Lanes."** Rejected as a surface cut, accepted as a behaviour cut. The two strongest arguments —
the unaffordable 1 Hz rewrite and the duplicated numbers — are both answered by deleting the rewrite
and sourcing the numbers from the same ephemeral stream the Watchfloor reads (§2.5). What remains is
that lanes are the durable `h`-scoped home for escalation cards that were never promoted to a case, and
the anchor for the twelve-value `#h` REQ that `07` already budgets. Deleting them would leave
un-promoted escalations with no durable home, which is the failure `/gaps` exists to fight. The freed
budget is real and is spent on the ephemeral path, not on a new surface.

---

## 7. Unverified in this document

Everything below is a proposal or a carried claim, not something read from source this session.

- The entire route table (§1.1): paths, view ids, lazy flags. Only Buzz's twelve `route()` entries plus
  an `index()` (`routes.ts:3-19`) were verified.
- Every Perch keybinding in §3.0. Only Buzz's six global bindings
  (`useAppShellKeyboardShortcuts.ts:56-98`) and the `Escape` behaviour
  (`useMarkAsReadShortcuts.ts:23-45`) were verified.
- `HeldActionStore`, `RuntimeEvent::ResponseHeld`, `POST /v1/response/holds/{id}/decide`,
  `POST /v1/operator/findings/{id}/feedback`, `GET /v1/operator/findings/reviewed` and
  `GET /v1/operator/pheromone/deposits` do not exist. Absence verified: 49 routes in
  `http/state.rs`, no `feedback` route among them.
- `PERCH_QUEUE_DEPTH_ALARM = 12`, `PERCH_WATCH_CLAIM_TTL_MS`, the 28px strip height and the
  "recv Nm ago" staleness clock are proposed numbers with no measurement behind them.
  `PERCH_HOLD_TTL_MS = 3_600_000` is `08` §3.6's settled proposal, not a constant in either tree.
- The watch-claim-as-channel-topic design (§2.11). The relay mechanics were verified
  (`side_effects.rs:592-630, 1548-1564, 762-793`); that a `#watch` ops channel should exist, and the
  12-hour claim TTL, are proposals.
- The seeded case-canvas template contents. `ChannelCanvas.tsx` has no template mechanism.
- That case channels will be created with a `ttl_seconds` value. The columns and the refresh trigger
  are verified; nothing sets a TTL on an Ambush case today.
- `tools/check-perch-grant-affordance.sh` and `tools/check-copy-banned-terms.sh` do not exist; they are
  proposals patterned on `desktop/scripts/check-pubkey-truncation.mjs` and the repo's existing gate
  scripts.
- "Median seconds page-to-verdict" and "fraction of recommendations from this week's verdicts" do not
  exist in either repo; they are proposed instrumentation.
- `PartitionState` having exactly four values and the `docs/CONSENSUS.md:307` multi-tenant non-goal
  citation are carried from recon; neither file was read this session.
- `ThreatClass::Custom(String)` existing alongside the twelve named variants is carried from recon;
  the twelve standard classes were re-verified at `escalation.rs:315-330`.
- That `CommunityRail` can carry one Ambush deployment per Buzz community is architectural inheritance
  from recon; the file exists but its implementation was not read.
- The claim that the desktop `MessageRow` default arm will route an unknown kind 46010 through the
  marker sniff is inferred from reading the switch's default case (`MessageRow.tsx:413-427`); which
  kinds reach `renderBody` at all was not traced.
- The ~2.07M-rows/day figure in §2.5 is arithmetic over verified per-write behaviour (one `kind:9002`
  plus one durable `kind:40099` per topic set, twelve lanes, 1 Hz), not a measurement.
