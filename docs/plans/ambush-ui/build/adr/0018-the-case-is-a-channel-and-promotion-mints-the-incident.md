# ADR 0018: A Case Is A Buzz Channel, And Promoting To One Mints The Incident Record A Verdict Attaches To

## Status

Proposed on 2026-08-30. **Revision 2** — C2 now names the creator; see *Revision history*.
Perch, Phase 1 (`B3`, `B3i`, `B1d`, `F4`).

Depends on ADR 0012 (the relay holds the conversation) and ADR 0014 (leg 1 lands in the
case channel). It is the structural decision that
`docs/plans/ambush-ui/build/21-ADRS.md` question 2 sets thresholds against.

### Revision history

| Rev | What changed | Why |
|---|---|---|
| 1 | C2 said promote-to-case "creates the case channel and mints the incident" and named no creator | — |
| **2** | **C2 names the creator: `swarm-perch-bridge`'s `ensure_case_channel`, on two triggers.** Fact 6 is added; the second trigger is a new, uncuttable bill item **B1d** | Revision 1's C4 enables **only** manual promotion in the first build, and `11-BRIDGE-CRATE.md`'s first draft fired channel creation only on `RuntimeEvent::ResponseHeld` — which manual promotion does not emit. On the one enabled clause nothing created the channel, while `IncidentMintRequest.case_id` (B3i, required, "the Perch case's channel UUID") needs one to already exist. The console cannot create it either: `10-RELAY-FORK.md`'s INV-RF1 restricts the operator key to exactly one published kind |

Path prefix convention as in ADR 0011: `BUZZ ` is `block/buzz` at `eed74bde2`.

## Context

Perch's product spine is "a human decision becomes next week's detector tuning input". That
sentence has a hidden precondition: the decision must land on an object the tuning engine
reads. It does not, today, and the object it needs does not exist for most findings.

### Fact 1: Ambush has three grains and none of them is a case

- **`hunt_id` is the telemetry event id.** `ActionRequest.hunt_id` is constructed as
  `HuntId(primary_finding.event_id.clone())`
  (`crates/swarm-runtime/src/service/runtime_service.rs:391`). Thousands an hour.
- **`CorrelatedIncident` is recomputed, not owned.** The only production minting site is
  `CorrelationEngine::assemble_incident_at`
  (`crates/swarm-runtime/src/correlation.rs:110-233`), seeded from an
  `InvestigationBundle`, minting `incident_id = format!("incident:{}:{created_at_ms}",
  seed.hunt_id)` with a single seed member at confidence 1.0. It has no status, no assignee
  and no merge operation. A second correlation run produces a different id for the same
  material.
- **Escalation is per threat class** and carries no host and no hunt.

So a case — a thing with an identity, a membership, a conversation and an end — is Perch's
one domain invention. `00-BRIEF.md` §8.2 says so and requires the bar for opening one to be
a configured, instrumented threshold rather than a constant somebody picked.

### Fact 2: a verdict on an uncorrelated finding has nowhere to land

`SwarmProvidenceFeedbackRequest.incident_id` is a **required** `String`
(`crates/swarm-core/src/types.rs:144-152`). `providence_feedback_handler`
(`crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:119-192`) — the seven-step
template B3 copies, serving `POST /v1/providence/feedback` in `swarm_detect --serve` —
loads the incident by id at step 2 (`:129-137`) and returns not-found if it misses. The
measurement is then **upserted onto the incident record**, and
`build_alert_tuning_report` (`crates/swarm-runtime/src/alert_tuning.rs:85`) takes
`&[IncidentRecord]`, with `dedupe_measurements` (`:258-271`) reaching measurements only
through `record.false_positive_measurements`.

A measurement not attached to a persisted incident is invisible to the ranking engine. So
without a mint-on-promotion path, `E` promotes a finding into a case whose verdict controls
stay disabled forever — a queue the operator can work but not close.

### Fact 3: the minted incident has a contract, and three ways to be silently useless

`resolve_feedback_target` (`crates/swarm-runtime/src/providence.rs:799-836`) runs before
any write:

- `select_feedback_member(&incident.included_members, finding_id)` must find the finding, or
  the whole call fails with `"incident \`x\` does not contain finding \`y\`"`.
- `strategy_id` comes from `record.trigger_strategy_id`, an `Option`. `None` becomes the
  **literal string `"unknown"`** in the measurement
  (`providence_handlers.rs:482-485`: `.unwrap_or_else(|| "unknown".to_string())`), which
  collapses every such measurement into one per-detector bucket and makes
  `DetectorThresholdReview` and `DetectorRuleReview` rank a detector that does not exist.
- `host_id` is resolved **only** from a key literally prefixed `host:` in
  `member.shared_keys` or `record.correlation_keys`
  (`extract_host_id_from_keys`, `providence.rs:838-841`). Absent, `host_id` is `None`
  (`FalsePositiveMeasurement.host_id: Option<String>`,
  `crates/swarm-spine/src/incident.rs:50-51`) and `HostExclusionReview` — the highest-value
  of the three recommendation kinds — is unreachable for that measurement forever.

`threat_class` falls back to `ThreatClass::Custom("unknown")` and `severity` to
`Severity::Medium`, so both are also worth setting explicitly.

The write itself is cheap: `IncidentStore::persist(&CorrelatedIncident) -> IncidentRecord`
is a **public** trait method (`crates/swarm-spine/src/incident.rs:318-337`), implemented by
`ConfiguredIncidentStore` (`:357-419`) over the memory and file stores, reached in the
daemon as `state.current_incident_store()`. `CorrelatedIncident` (`:136-170`) has 20 fields
of which 9 are non-defaulted. B3i needs no new store — it needs a correctly-shaped struct.

### Fact 4: the Buzz side of a case already exists, and one field has no owner

A Buzz channel is created by `kind:9007` (`KIND_NIP29_CREATE_GROUP`,
`BUZZ crates/buzz-core/src/kind.rs:343`). `BUZZ schema/schema.sql:102` carries
`ttl_seconds INT` on the channel row, `:117` indexes the live TTL population, and
`refresh_channel_ttl_after_event_insert` (`:960-998`) is a Postgres trigger that pushes
`ttl_deadline` forward by `ttl_seconds` on every event insert into a channel that has one.
So a case that is still being talked about does not expire, with no client cooperation and
no cron.

What has no owner is **what sets `ttl_seconds`**. `03` §7's "from the incident's severity"
is a suggestion with no config key behind it.

### Fact 5: `analyst_id` is self-asserted today

`false_positive_measurement` (`providence_handlers.rs:473-495`) takes
`analyst_id: request.analyst_id.clone()` — from the **request body**
(`swarm-core/src/types.rs:149`), not from authentication. That is correct for an HMAC
webhook speaking for an external SOAR. It is not acceptable for an operator route.

### Fact 6: the only promotion clause enabled first is the one that emits no runtime event

`RuntimeEvent::ResponseHeld` is B1's twelfth variant and it is emitted when a destructive
action is held — clause 1 of C4's bar. Clauses 2 and 3 emit nothing: a `CorrelatedIncident`
crossing two members is a correlation-engine fact with no runtime event, and an analyst
pressing `E` is a console gesture with no daemon-side event at all.

So the promotion path that C4 enables **first** has no producer for the object every other
step needs. Three candidate creators were checked and two are closed:

| Candidate | Verdict |
|---|---|
| The bridge, on `RuntimeEvent::ResponseHeld` | correct for clause 1 and silent for clause 3 — the enabled one |
| The console, publishing `kind:9007` itself | **closed.** `10-RELAY-FORK.md`'s INV-RF1 restricts the operator's own key to exactly one published kind, `kind:9` / `swarm:verdict:v1`, via `perch_record_verdict`. `14-CLIENT-ARCHITECTURE.md`'s write set has no channel-create command, and widening it would put a channel-creation authority in the renderer's reach |
| The daemon, publishing directly to the relay | **closed.** ADR 0015 makes the bridge the only Ambush component holding a relay identity, and ADR 0012 clause 3 keeps the daemon off the relay entirely |

That leaves the bridge, on a **second** trigger — which means a runtime event must exist for
manual promotion. `11-BRIDGE-CRATE.md` §9.1.5 specifies it as bill item **B1d**,
`RuntimeEvent::CasePromoted { hunt_id, case_id, clause }`, ~0.5 ew, seven upstream edits,
supplied by the daemon route that performed the promotion.

## Decision

**A case is a private, TTL-bearing Buzz channel. The case id *is* the channel UUID.
Promoting a finding to a case mints the `IncidentRecord` the verdict will attach to, in the
same operation, and the mint satisfies Fact 3's contract explicitly rather than by
accident.**

**C1. `case` is Perch's noun and it never means `CorrelatedIncident`.** The vocabulary
ruling is `APPENDIX-NORMATIVE.md` §7 and it is load-bearing here rather than stylistic: the
case is owned, has members and ends; the incident is recomputed and has neither. The case
timeline may show the incident it minted; it never calls it the case.

**C2. Promote-to-case is one operation with two writes, it is explicit, and
`swarm-perch-bridge` is the only creator of the channel.** `E` on a finding, hold or lane row
(one meaning, always — never "route to another operator", because no operator directory
exists in either tree) creates the case channel **and** mints the incident. `03` §4.3 rejects
implicit promotion on Dismiss and this ADR keeps that: a `Dismiss` that silently minted an
incident would put a suppression marker's blast radius behind a keystroke nobody chose.

**Rewritten in revision 2 to name the creator.** The `kind:9007` that creates the channel is
published by the bridge's single entry point `ensure_case_channel`
(`11-BRIDGE-CRATE.md` §9.1), taking a two-arm `CasePromotionTrigger`:

| Trigger arm | Source | `case_id` | What else fires |
|---|---|---|---|
| `Held { hunt_id, hold_id }` | `RuntimeEvent::ResponseHeld` (bill **B1**) with no case already routed for its `hunt_id` | **minted by the bridge** (`Uuid::new_v4`) — `ResponseHeld`'s seven fields carry `hunt_id` and `hold_id` and no case id | `CreateCaseChannel` + one `AddOperator` per operator, then the hold publish and the alarm |
| `Promoted { hunt_id, case_id, clause }` | `RuntimeEvent::CasePromoted` (bill **B1d**, PROPOSED, Fact 6) | **supplied** by the daemon route that promoted | `CreateCaseChannel` + one `AddOperator` per operator, and nothing else — **a promoted finding is not a held action and must not alarm the shift** |

**B1d is not cuttable while clause 3 is the enabled one.** Cutting it does not degrade
promotion; it deletes it, and the symptom is a `404` from B3i on a `case_id` that was never
created. The console cannot substitute (Fact 6) and neither can the daemon.

**C3. The minted `CorrelatedIncident` sets six fields deliberately**, because each has a
downstream consequence in Fact 3:

| Field | Value | Because |
|---|---|---|
| `incident_id` | a scheme that **cannot collide** with `incident:{hunt_id}:{created_at_ms}` | the correlation engine owns that namespace and recomputes into it |
| `included_members` | exactly one member, carrying the promoted `finding_id` | `select_feedback_member` fails otherwise |
| `trigger_strategy_id` | `Some(...)` from the finding | `None` becomes the literal `"unknown"` and collapses the per-detector bucket |
| `correlation_keys` | includes a `host:<id>` key | otherwise `HostExclusionReview` is permanently unreachable |
| `threat_class` | `Some(...)` from the finding | otherwise `Custom("unknown")` |
| `severity` | `Some(...)` from the finding | otherwise `Medium` |

**C4. The promotion bar is configured, instrumented, and visible from day one.** Three
clauses — a held destructive action, a `CorrelatedIncident` with ≥ 2 included members, or an
analyst promoting by hand — expressed as configuration, with a **promoted / suppressed
counter on `/`** in the first shipped build. `00-BRIEF.md` §8.2 requires the counter and
`09` D14 requires its home. Promote too much and the console floods a partitioned `events`
table and becomes the product Ambush positions against; promote too little and the case room
is empty while the evidence stays in `data/*`. The counter is how that is discovered in week
two rather than quarter two. **The threshold values are question 2 in `21-ADRS.md`; the
structure is this ADR.**

**C5. `analyst_id` on any operator route comes from `AuthenticatedOperatorPrincipal`, never
from the request body.** The webhook path keeps its body-supplied field; the operator path
must not, or the one record whose job is naming a human accepts any name.

**C6. `ttl_seconds` is set by the bridge at case creation from a named config key, and the
retention floor is a separate, audit-derived number.** The bridge sets it on the `kind:9007`
event from `perch.case_ttl_seconds` (`11-BRIDGE-CRATE.md` §9.1, PROPOSED). The retention
floor comes from a configured **audit-retention** requirement and **not** from the longest
case TTL (`APPENDIX-NORMATIVE.md` §6, settled) — a case may end long before the record of
what was decided in it may be discarded.

**C7. The case channel is private, and the bridge is a member of it from creation — on both
triggers.** Private
by default with membership re-authorized on every delivery (`00-BRIEF.md` §10 Q4); lanes
stay open. Because the channel is private there is no open-channel fallback, so the bridge's
Nostr key joins in the same operation that creates the channel, never lazily on the first
hold — a membership failure at hold time is the worst available moment
(`10-RELAY-FORK.md`'s RF-D2, which this ADR binds to).

## Alternatives Considered

**Make the case a `CorrelatedIncident` and drop the channel.** One object instead of two.
Rejected on Fact 1: the incident has no status, no assignee, no merge and a recomputed id,
so "the case I was working on" would change identity under the operator. It also throws away
the compartment, the conversation and the search that ADR 0012 exists to rent.

**Make the case a channel and skip the incident — record verdicts only on the relay.**
Cheaper by one bill item. Rejected on Fact 2: the tuning engine reads
`IncidentRecord.false_positive_measurements` and nothing else, so verdicts would accumulate
on the relay and reach the ranker never. That is the thesis failing silently, which is the
exact failure mode `09` §13's third metric is designed to expose.

**Mint the incident lazily, on the first verdict, instead of at promotion.** Fewer records.
Rejected: it moves a write that can fail into the middle of a decision the operator has
already committed to, and it makes the "not yet correlated" state
(`04` §2.1) unresolvable at the moment the operator is looking at it. Promotion is the
natural transaction boundary.

**Let B3 accept `incident_id: null` and mint on demand.** `09` §3.1 offers this as the
alternative to a `POST /v1/operator/incidents` route and it is genuinely simpler. Not
rejected — deferred to `12-BACKEND-BILL-API.md` §9, which owns the route shape. What this
ADR fixes is that **one of the two must exist**, and that whichever it is satisfies C3.

## Consequences

### Positive

- The tuning loop closes for findings the correlation engine never touched, which is most of
  them. Without this it closes only for findings Weaver happened to correlate.
- The case has a TTL that refreshes itself from activity, using machinery already in the
  relay's schema, so an abandoned case ages out and an active one does not.
- The promoted/suppressed ratio is a real product signal on day one. `09` §13 already names
  its healthy band: between 1:5 and 5:1.

### Negative

- **The tuning evidence window is 20 incidents, in memory, destroyed on restart.**
  `operator_review_status` computes both `false_positive_tracking` and `alert_tuning` from
  `incident_store.recent(self.config.audit.recent_decisions_limit)`
  (`crates/swarm-runtime/src/service/runtime_service.rs:1134-1136`, `:1174-1175`);
  `default_recent_decisions_limit()` is **20**
  (`crates/swarm-core/src/config/defaults.rs:3-5`); and
  `CorrelationSettings.incident_store` defaults to `BundleStoreConfig::Memory`
  (`crates/swarm-core/src/config/storage.rs:62-71`, `#[default] Memory`). On a shipped
  configuration the recommendations see the twenty newest incidents and a daemon restart
  destroys every measurement ever written. **"By Friday it is why the detector got retuned"
  is unachievable until a deployment sets `incident_store` to `LocalFiles` and raises
  `recent_decisions_limit` for this path.** It is not a code change — it is a deployment
  prerequisite that must be on the demo checklist
  and in the deployment documentation; `09`'s bill as sized does not cover it. Sized in
  `21-ADRS.md` question 2.
- Two objects means two ids on screen. C1's vocabulary rule is the mitigation.
- **A promotion path that runs through the bridge is a promotion path that can be behind.**
  The console's `E` returns when the daemon's promotion route returns, but the channel exists
  only after the bridge has drained `RuntimeEvent::CasePromoted`, published `kind:9007` and
  added the operators. `14-CLIENT-ARCHITECTURE.md` must render that interval as *"opening the
  case"* and must not navigate into a channel that does not exist yet. The alternative —
  having the daemon block on the bridge — would make a relay outage a promotion outage, which
  is exactly the coupling ADR 0012 refuses.
- **B1d is one of four bill items wave 2 added to `09`'s eleven** (B0, B1c, B1d, B2g-p —
  `21-ADRS.md` amendment AD-A9). ~0.5 ew of Rust on the chain question 3 measures, and it is
  uncuttable while manual promotion is the enabled clause.
- A minted single-member incident is a real `IncidentRecord` that the correlation engine did
  not produce. Anything that enumerates incidents will see it. `/tuning` must be able to say
  which recommendations were sourced from analyst-promoted incidents versus
  correlation-produced ones, or the ranking will look like it discovered something it was
  told.

## Verification

- `08` INV-01's write allowlist **includes the incident-minting write**. It did not in the
  first draft, which would have failed the build on the first promotion — recorded here
  because it is the cheapest possible illustration of why the allowlist is enumerated rather
  than described.
- **PROPOSED** an integration test: promote a finding, then `POST` a `Dismiss` verdict
  against it, then read `/v1/operator/status` and assert the measurement appears in
  `false_positive_tracking` **and** that `strategy_id` is not `"unknown"` and `host_id` is
  `Some`. Asserting only the first would pass with a useless measurement.
- **PROPOSED** a test that the minted id cannot collide with
  `incident:{hunt_id}:{created_at_ms}` for any input.
- **PROPOSED** a test that `analyst_id` on the operator route is the authenticated
  principal's, by posting a body naming a different one and asserting the stored measurement
  ignores it (C5).

## Follow-On Work

- **`B1d` needs a home on the bill and on the schedule.** `11-BRIDGE-CRATE.md` §9.1.5 specifies
  it; `12-BACKEND-BILL-API.md` owns the promotion route that emits it; `20-TASK-BREAKDOWN.md`
  owns its task card and P1-22's acceptance list. `21-ADRS.md` question 3 carries its 0.5 ew.
- Decide the seeded case-canvas template contents. Three plan documents rely on it and none
  owns it, and `BUZZ ChannelCanvas` has no template mechanism today.
- Decide whether `/tuning` distinguishes analyst-promoted from correlation-produced
  incidents in its recommendation provenance. This ADR argues it must.
- The two `/settings` anchors every empty state deep-links to — `#case-promotion` and
  `#ledger-syntax` — have no owner. The first is this ADR's subject and should be its
  configuration surface.
