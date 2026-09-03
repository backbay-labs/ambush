# The Angle: why a Buzz-shaped UI is the right body for Ambush

Ambush already computes the answer to "was that alert real?" and has no door a
human can walk it back through — 49 operator routes, zero of which accept a
verdict. Buzz already built the door and has nothing to put through it — a
needs-action feed hardwired to an event kind nothing can emit. Perch is the
graft: Buzz's shell as the operator console for a swarm that can isolate
production, where every human decision is a typed act that becomes the swarm's
next tuning input. This document argues the category, the user, the wedge, the
pitch, the adoption arc, and the case against.

It also states, first and plainly, the three things that are **not** true yet
and that the positioning may not outrun: the hold does not exist, the human's
decision is not in the Ed25519 chain, and the feedback loop is incident-scoped.
§2.3 and §2.4 are the bill; every claim later in the document is written to be
survivable if those items slip.

## Decisions made here

1. **Perch is not a SIEM/SOAR/XDR console and will not be positioned against
   one on feature parity.** Its category is *the decision surface for
   autonomous defense*: the unit of work is a typed human verdict that is an
   engine input, not a ticket field. §1, §5.
2. **The wedge is "one record, two asymmetries"** — authority and attention —
   not "agents and humans in one workspace." The cheap version of that phrase is
   chatops and we reject it explicitly; the honest version admits that agents
   write to the case and do not read it. §4.
3. **The category-defining claim is `is_suppressed_by_feedback`** — a Dismiss
   retroactively removes deposits from the concentration sum
   (`crates/swarm-pheromone/src/substrate.rs:1286`, `:1367-1380`). Every pitch
   leads with the arithmetic, not with the workspace. §1, §5, §6.
4. **The named user is "the operator," singular, on shift** — not "the SOC," not
   "the analyst team." Ambush's own shipped contract declares multi-tenant
   operator governance a non-goal (`docs/CONSENSUS.md:309-315`). §3.
5. **The demo is the two-minute hold-to-verdict-to-curve loop**, and it may not
   be shown until the daemon-side hold store exists. A demo of a gate that
   `RequireHuman` currently denies
   (`crates/swarm-runtime/src/lib.rs:979-982`) would be the one lie this brand
   cannot survive. The demo also carries a phase column, because three of its
   nine beats land on surfaces that do not exist until Phase 2–3. §6.
6. **We say "signed" only where a signature exists.** Four of the seven evidence
   card types — finding, escalation, hold, lease — carry no Ed25519 signature today, and no artifact anywhere records
   *which human* approved a held action. Positioning requires closing that; §2.3
   states which artifacts verify today and §2.4 states the missing record, and
   until both land the audit claim is "a human was asked", never "who approved
   it."
7. **We ship `/gaps` in v1 as a positioning surface, not a feature.** Ambush's
   credibility is negative space; every empty state links there rather than
   saying "no data." §7.
8. **The name is Perch** and the metaphor is the cat's, not the ant's: the
   stigmergy math is ant, the cast is feline, and the human sits above the
   colony and waits. §10.
9. **The C9 falsification counters live on The Watch (`/`)** — the only surface
   that exists in Phase 1 — and every other surface that shows them restates and
   links. §8.
10. **Vocabulary carried from the reconciliation pass:** the four inbox
    categories are **queues**, "lane" is reserved for the twelve threat-class
    channels, verdict keys are **`C`/`D`/`I`** on a finding and **`G`/`R`** on a
    hold. This document uses no other spelling of either. §3, §6; owned by
    `04-SURFACES-AND-UX.md` and `06-COPY-AND-VOICE.md`.

---

## 1. The category question

Every security console on the market answers a question about the past. Perch
answers a question about authority in the present, and the answer it records
changes the engine's arithmetic. That difference is the category.

Here is the taxonomy, with each category's actual unit of work:

| Category | The question the console answers | Unit of work | What a human decision *does* to the engine |
| --- | --- | --- | --- |
| SIEM (Splunk ES, Elastic Security, Panther, Google SecOps) | "What happened, and can I query it?" | A search, then a notable/alert | Sets a status field. The detection logic is unchanged until someone edits a rule in a different tool. |
| SOAR (Splunk SOAR, Chronicle SOAR, Tines/Torq) | "Can I run the same playbook every time?" | A playbook run | Approves or aborts one run. The next identical alert re-asks the same question. |
| XDR/EDR (CrowdStrike Falcon, SentinelOne, Defender) | "What did the agent block?" | A detection, already mitigated | Confirms or reverses a containment. Tuning is an exclusion list authored elsewhere. |
| AI-SOC (the 2025–26 cohort) | "Can a model triage this for me?" | An LLM-written triage narrative | Accepts or rejects a summary. The model is retrained by the vendor, not by you. |
| **Perch** | **"Do I authorize this, and what does my answer change?"** | **A typed verdict, recorded against a case** | **Enters the concentration arithmetic and the detector fitness function, in this deployment, immediately.** |

That last cell is the whole product, and it is not marketing. Trace it, with the
caller, the process and the effect named at every hop:

```
operator presses D (Dismiss)
  → POST /v1/operator/findings/{id}/feedback           THE ROUTE WE ARE ADDING — does not exist
  → same handler body the Providence HMAC webhook runs  providence_handlers.rs:140-190
      · in swarm_detect --serve, the sole writer
      · REQUIRES an existing incident: load_by_incident_id → 404      providence_handlers.rs:131-139
  → a suppression-marker deposit lands in the substrate  providence_handlers.rs:486-501
  → concentration_for() skips every deposit at or before
    that marker for that key                             substrate.rs:1286, 1367-1380
      · effect: total_strength drops for that (threat_class, key)
  → SwarmFeedbackSignal routes into Kitten's population
    store with a penalty                                 kitten_agent.rs:287-315
  → FalsePositiveMeasurement is upserted ON THE INCIDENT  providence_handlers.rs:169-175
      · struct at swarm-spine/src/incident.rs:46-61; false_positive = (action == Dismiss)
  → build_alert_tuning_report(&[IncidentRecord]) ranks
    HostExclusionReview / DetectorThresholdReview /
    DetectorRuleReview against 0.75 / 0.50 / 0.34         alert_tuning.rs:6-15, :85
```

Eight hops from a keypress to a threshold recommendation, and all eight already
exist in shipped Rust. The only missing link is the first one. The operator
surface registers 49 routes (`crates/swarm-runtime-http/src/http/state.rs:294-485`,
counted by `grep -cE '\.route\('`) and `grep -n feedback` over that file returns
nothing.

So the honest statement of the category is not "Ambush needs a UI." It is:

> Ambush's detection quality is a function of analyst verdicts, and the product
> has no way to receive one except by an external SOAR posting an HMAC-signed
> webhook.

`SwarmFeedbackSignal` (`crates/swarm-core/src/types.rs:209-223`) has a field
called `analyst_id: String`. There is no analyst. The struct has been waiting
for a person since it was written.

### 1.1 The constraint the chain puts on the product

Read the chain again and one field does load-bearing work: `incident_id` is
required on `SwarmFeedbackSignal` (`types.rs:212`) while `finding_id` is
`Option`, and the handler opens with
`current_incident_store().load_by_incident_id(&request.incident_id)` returning
a 404 when it misses (`providence_handlers.rs:131-139`). Downstream,
`build_alert_tuning_report` takes `&[IncidentRecord]` (`alert_tuning.rs:85`) and
the measurements it counts are upserted onto an incident
(`providence_handlers.rs:169-175`).

**A verdict has nowhere to live until a finding belongs to an incident.** That
is not a defect the console can route around; it is the shape of the store. It
has one large consequence for positioning, and it is a favourable one:

> The case is not a UI convenience layered on top of findings. Promoting a
> finding to a case is the act that mints the record a verdict can attach to.
> The case model is load-bearing on the *tuning loop*, not just on the
> conversation.

That reframes the case-promotion bar from a product-taste question into a
correctness question, and it means the brief's open question 2 (where the bar
sits) is on the critical path of the thesis, not adjacent to it. It also gives
the new feedback route a precise obligation: it must resolve or mint an
`IncidentRecord` for the finding before it can write a measurement. That
obligation belongs on the backend bill in `03-DOMAIN-EVENT-MAPPING.md §11`; this
document's job is to say that the loop does not close without it.

**Rejected alternative — position Perch as "a SOC console for Ambush."** That
framing invites a feature-parity comparison Perch loses on day one: no query
language, no case management, no reporting, no integrations directory. It also
teaches the buyer that the verdict is a ticket disposition, which is exactly the
mental model that makes the tuning loop invisible. We name the category by what
the verdict *does*, and let the missing features be non-goals we state out loud
(§5, and the brief's closed fourteen-surface list).

---

## 2. The two holes, and why they fit

Two repos independently built complementary halves of one human-in-the-loop
approval loop, and each half is dead on its own.

| The loop | Ambush has | Buzz has | State |
| --- | --- | --- | --- |
| A policy that decides a human must be asked | `PolicyVerdict::RequireHuman` (`swarm-policy/src/lib.rs:87`) | — | Ambush: computed, then discarded |
| A durable hold for the pending action | — | `workflow_approvals`, hard FKs to `workflows`/`workflow_runs` | Neither: the hold does not exist |
| A notification that reaches a person | — | needs-action feed: `kind IN (46010, 40007)` (`buzz-db/src/store/feed.rs:190-193`) | Buzz: query written, nothing emits 46010 |
| A card the human reads | — | `WorkflowApprovalCard.tsx` — 31 lines ending in `"Approval actions are not yet available in Desktop."` (`:27`) | Buzz: literally a stub |
| A signed grant/deny from the human | — | 46030/46031 with a client half that composes and signs (`desktop/src-tauri/src/commands/workflows.rs:350-370`, registered `lib.rs:773-774`) | Buzz: **client half reusable, relay half not** — see §2.2 |
| Re-evaluation of policy before dispatch | dispatcher revalidates the governance artifact (`dispatcher.rs:1276-1292`) | SEC-006 re-auth at every run-creation door | Both: built |
| The verdict changing the engine | the eight-hop chain in §1 | — | Ambush: built, unreachable |
| A record naming *which human* decided | — | — | **Neither: see §2.4** |

### 2.1 Ambush's gate denies rather than holds

In `LiveResponse` mode, `RequireHuman` returns `ApprovalError::Denied`
(`crates/swarm-runtime/src/lib.rs:979-982`). The human-approved execution path
exists — `audit_authorize_and_execute_human_approved_instrumented` at `:1085` —
and its only callers outside `swarm-runtime` itself are two demo sites
(`crates/swarm-ingest-runtime/src/ingest/demo.rs:725`, `:1369`). The instrumented
internal it delegates to takes `allow_human_approved_execution: bool`
(`lib.rs:1133-1136`), and that bool is the *entire* difference between the
autonomous path and the human-approved path. The README's promise, "human approval applies
above the configured severity," is today implemented as a refusal. That is not a
bug in the safety argument (denying is fail-closed and correct), but it means the
product's headline governance mode is a mode nobody can operate.

### 2.2 Buzz's approval producer is a TODO, and its consumer is workflow-bound

`buzz-workflow/src/executor.rs:726-729` generates a token, returns `Suspended`,
and leaves `// TODO (WF-08): create approval record in DB, emit kind:46010`.
Kind 46010 is defined (`buzz-core/src/kind.rs:578`), is in `ALL_KINDS` (`:745`),
is queried by the desktop feed, and hits the default reject arm at ingest
(`crates/buzz-relay/src/handlers/ingest.rs:545`). Buzz built the receiving end of
a doorbell nobody wired.

**Correction to the earlier draft of this document, found while re-verifying:**
the answering half is *not* "fully built and reusable." 46030/46031 are
**command kinds** (`buzz-core/src/kind.rs:815-826`), so ingest routes them into
`command_executor::handle_command` (`ingest.rs:2277-2280`) rather than storing
them. `handle_approval_grant` (`command_executor.rs:1020`) then requires a `d`
or `e` tag carrying an approval token hash, looks the row up with
`get_approval_by_stored_hash`, and rejects with `"invalid: approval not found"`
when it misses (`:1029-1046`); on success it flips a `workflow_approvals` row
and resumes a workflow run (`:1076-1110`).

Consequence, stated here because it lands on the wedge's enforcement mechanism
in §4: **a Perch-published 46030 with no synthetic `workflow_approvals` row will
be rejected by an unforked relay.** Leg 1 of the two-legged write cannot be a
bare 46030 unless we either forge a workflow and run per hold — which
`03-DOMAIN-EVENT-MAPPING.md` already rejects for the hold itself — or spend fork
budget the brief's C1 constraint reserves. The cheap answer is the one the wire
format already provides: the human's intent record rides the marker path as a
`kind:9` card, at zero additional match arms. The arithmetic is
`03-DOMAIN-EVENT-MAPPING.md`'s to settle; the positioning consequence is that
"the console publishes a signed intent record" stays true either way, and this
document does not depend on the kind integer.

What is genuinely reusable is the **client** half: composing, signing and
submitting a grant/deny event through the Tauri seam, plus the desktop card
shell. That is real, and it is the part Perch needs.

### 2.3 The third hole: what is actually signed today

The brand's whole register is "no receipt, no action," so the word *signed* has
to be earned artifact by artifact. It is not, yet. Verified this session by
reading each struct:

| Artifact | Ed25519 signature? | Where | Verifier, and who calls it |
| --- | --- | --- | --- |
| `PheromoneDeposit` | **Yes** — `signature: Vec<u8>`, `agent_key: Vec<u8>` | `swarm-core/src/pheromone.rs:231-233` | Verified inside the substrate. **Never published to the relay** (`03 §4.1`), so no card carries it. |
| `ConsensusGovernanceReceipt` | **Yes** — `{ payload, signature: DetachedSignature }` | `swarm-consensus/src/lib.rs:379-383` | `receipt.verify()`; called by `verified_governance_receipt` (`swarm-runtime/src/lib.rs:778-807`) and `verify_release_attestation` (`swarm-runtime/src/containment.rs:235-269`) |
| Rollback receipt's attestation | **Yes** — `governance_attestation: Option<Value>` over this receipt's canonical form with the field cleared | `swarm-response/src/rollback.rs:263-264` | `verify_release_attestation` — signature **plus** subject binding against `release_subject_id` (`containment.rs:255-267`); surfaced as `attestation_verified` at `http/containment.rs:219-222`. `None` means UNATTESTED and the verifier refuses it. |
| Approval-ledger vote envelope | **Yes** — spine envelope | `swarm-runtime/src/approval.rs:1810` | `verify_envelope` in the same function. This is the **only** non-test caller of `build_signed_envelope` in the workspace. |
| `EvidenceBundle` (evolution) | **Yes** — canonical payload + sha256 + signature | `swarm-evolution/src/evidence.rs:1162`, `:1759` | `swarmctl evidence-verify` (`swarm-cli/src/core.inc:319`, `:3547`). **Evolution artifacts only — it does not take a response receipt.** |
| `DetectionFinding` | **No** — seven fields, none a signature | `swarm-whisker/src/detector.rs:50-59` | — |
| `SwarmFindingEnvelope` (the payload of `RuntimeEvent::Finding`) | **No** — eight fields | `swarm-response/src/siem.rs:17-27` | — |
| `ResponseReceipt` | **No.** The receipt body is unsigned; `audit.governance.receipt` is an untyped `Option<Value>` that *may* hold a signed consensus receipt | `swarm-response/src/lib.rs:99-116`, `:135-142` | — for the body |
| `AuditTrail` | **No** — trail_id, hunt_id, receipt ids, detection, policy, response, created_at_ms | `swarm-spine/src/lib.rs:113-122` | — |
| The hold, and the human's decision | **Does not exist** | — | — |

Two further facts that a citation alone would hide.
`build_signed_envelope` (`swarm-spine/src/envelope.rs:71`) is real, but its only
non-test caller in the workspace is `approval.rs:1810`; `chain.rs:185` is inside
`#[cfg(test)] mod tests` (`chain.rs:176`). And `verify_chain_link` /
`ChainLinkVerdict` (`swarm-spine/src/chain.rs:20`, `:75`) have **zero** consumers
outside their own module — the only other mention is the re-export at
`swarm-spine/src/lib.rs:67`. The chain machinery exists and is exercised by one
feature.

**The positioning position.** We take option (a): *wrap the fact in
`build_signed_envelope` before it leaves the daemon*, as a sixth item on the
Ambush backend bill. It is the same one-call pattern `approval.rs:1810` already
uses, against a verifier that already exists, and it converts four unsigned card
types into chain links. Option (b) — drop the claim and say "signed by the
bridge's Nostr key, the daemon is the record" — collapses the differentiator to
"the daemon will tell you if you ask it," which is a weaker version of every
SIEM's audit log. Until (a) lands, **no Perch surface, badge, export bundle or
exit criterion may claim an Ed25519 check over a finding, escalation, hold or
receipt body.** The containment-release attestation is the one receipt-side
signature that verifies today, with subject binding, and it should be shown
loudly *because* it is the exception.

### 2.4 The record does not name the human

Worse than unsigned: absent. Perch's spine sentence is "every human decision is
a typed act that becomes the quarter's audit artifact." Today no Ambush type has
a field for the operator who decided:

- `ActionRequest` has five fields — `hunt_id`, `requested_by: AgentId`, `action`,
  `severity`, `evidence` (`swarm-policy/src/lib.rs:46-58`). `requested_by` is the
  requesting *agent*.
- `ApprovalContext` has four — `live_mode`, `receipt_chain`, `correlation_id`,
  `now_ms` (`:60-72`). No operator.
- `ResponseReceiptAudit` carries `ResponsePolicyAudit { verdict, rule_name,
  reason }` and `ResponseGovernanceAudit { governing_agent_id, reason, receipt }`
  (`swarm-response/src/lib.rs:118-142`). `governing_agent_id` is Tom, not a
  person.
- `audit_authorize_and_execute_human_approved_instrumented` takes no approver
  argument (`swarm-runtime/src/lib.rs:1085-1092`), and the flag it forwards is a
  bare bool (`:1133-1136`).

So a granted destructive action is **byte-indistinguishable in the chain from an
autonomous one**, except that `policy.verdict` reads `require_human`. The
`operator_id` would live only in the new daemon-side `HeldActionStore`, which is
neither hash-linked nor signed.

The fix is one threaded field — `approved_by: Option<OperatorApproval>` carrying
operator id, decided-at, hold id and the signature from §2.3 — and it belongs on
the backend bill next to the hold store; `03-DOMAIN-EVENT-MAPPING.md §11` owns
the ordering. **Positioning constraint until it lands:** the audit artifact
answers *"a human was asked, and the action ran on the human-approved path."* It does not
answer *"who approved this."* No pitch, demo beat, adoption row or sales
sentence in this document claims otherwise, and §7 and §8 are written to that
line.

### 2.5 Why the holes fit anyway

The fork cost of joining the two halves is two match arms in one relay file
(details in `02-ARCHITECTURE-INTEGRATION.md`). That is the cheapest structural
graft in this plan. The three items above are each small, local, and inside
Ambush's own daemon — a store, a threaded field, an envelope call. None of them
argues against the graft; they argue against shipping the sentence before the
code. Which is exactly the discipline the brand already applies to itself
(`docs/EVOLUTION.md:161`, "Read this before filing 'promotion is broken'").

---

## 3. Who the operator is, and what a shift looks like

Ambush's own command surface tells you who the user is. There are 126 `swarmctl`
subcommands (counted over `enum Command` in `crates/swarm-cli/src/core.inc:299`),
and roughly ninety of them are evidence, approval, review, and evolution artifact
management rather than detection. The product's center of gravity is not "find
the bad thing." It is **governed change management for detection logic, with
cryptographic provenance.** That is a collaboration product wearing a detection
engine's clothes, which is precisely why a collaboration app is the right body.

The operator has four scopes — read, rehearse, approve, maintenance
(`crates/swarm-core/src/config/operator.rs:82-90`) — and today `Read` is
enforced on no `/v1/operator/*` handler, so role-gated UI is a claim we may not
make until that changes (a stated non-goal in the brief; the settings page says
so out loud). They have five named failure-mode playbooks
(`docs/DR-RUNBOOK.md:190-318`, §7.1–7.5). They run one colony; internet-exposed
and multi-tenant operator governance is a declared non-goal
(`docs/CONSENSUS.md:309-315`).

A shift, today versus in Perch:

| Hour | Today | In Perch | Grounded in |
| --- | --- | --- | --- |
| Start of shift | `swarmctl status`, read a wall of JSON, guess what changed since the last person | The Watch (`/`) opens on four queues and three read frontiers restored from the outgoing analyst's handoff | Buzz `AppShellContext.tsx:33-48` (channel, thread and per-message frontiers); Ambush `ReviewSession` |
| A held destructive action | Does not happen. `RequireHuman` denies. | Row in `needs_action`; fixed field order ACTION → BLAST RADIUS → IF YOU UNDO → WHY WE ARE ASKING → WHAT GRANTING OPENS; **`G`** records the grant, **`R`** refuses | `swarm-runtime/src/lib.rs:979-982`; brief render law 1; keymap settled in `04 §0.4` |
| A finding that is obviously benign | Nothing to press. Open a ticket in a different product, or post to the SOAR that holds the HMAC key | **`C`/`D`/`I`** in the row, and the row shows what will be suppressed — but only once the finding belongs to a case (§1.1) | `types.rs:110-116`; `substrate.rs:1367-1380`; `providence_handlers.rs:131-139` |
| Correlating two hits | Read `swarmctl incident --id …` output, keep notes in a text file | One TTL case channel per promoted incident; correlation is a NIP-10 reply thread; notes are the case canvas | Buzz channel `ttlSeconds`/`ttlDeadline`; kind 40100 canvas |
| Checking a containment | `swarmctl quarantine list` (one of only three call sites in the CLI that speak HTTP at all — 3 `reqwest` references in 5,750 lines of `core.inc`) | `/leases`, with `remaining_ms` and `expired` as two separate loud facts | `swarm-runtime-http/src/http/containment.rs:70-88` — the doc comment says `remaining_ms` saturates at zero |
| "Why did it fire?" | `swarmctl playbook-preview`, then read `rulesets/default.yaml` in an editor | `/policy` renders rules in file order with shadowing dimmed and "no human will be asked" on every allow rule outranking the gate | shipped `command-and-control-emergency-block` vs `human_gate_severity` |
| End of shift | Nothing. There is no handoff object. | `/handoff`: one button composing a `ReviewSession` from every case touched, plus open leases, snoozes, and the three read frontiers | `ReviewSessionCreateRequest` has exactly `title`, `notes`, `artifact_refs` (`swarm-runtime-workbench/src/workbench/types.rs:123-127`) |

That last row is the sharpest. Ambush's entire narrative capacity for a review
session is one `Option<String>` set at creation time. A shift is a story, and
the product has one text field for it.

The **second user is the swarm**, with one honest qualification. Eight typed
agents post as channel members and their actions are timeline rows. Their
liveness is **not** Nostr presence: kind 20001 is a TTL-decayed status set on
connect and refreshed on a 60-second heartbeat with a 180-second expiry
(`crates/buzz-pubsub/src/presence.rs:16`, `lib.rs:331`), so "online" can be up to
three minutes stale. A three-minute lie-window is fine for a colleague's avatar
and wrong for "is Whisker still hunting." Agent liveness reads the ephemeral
`AgentHealth` stream instead (`03 §4.2`, `07 §2`). *(The earlier draft of this
document said "their health is presence," and an earlier draft of the reason said
presence has no Redis `PUBLISH`. Both were wrong: presence falls through to the
shared channel-less ephemeral path and does `publish_event(EventTopic::Global)`
— `crates/buzz-relay/src/handlers/event.rs:843-847`, publish at `:877-891`. The
decision is unchanged; the reason is the TTL, not the transport.)*

---

## 4. The wedge, stated precisely

"Agents and humans in one workspace" is the wedge, and it is also the most
over-claimed phrase in this market. The cheap version — pipe alerts into Slack,
add a bot, call it agentic — fails for a reason that is structural, not
aesthetic: **a chat integration gives an agent a voice without giving it an
identity, and gives a human a button without giving the button authority.**

Buzz's version is different in a way that is checkable in source. Humans and
agents get the same keypair, the same NIP-05 handle, the same channel membership
gate; the only difference is which auth NIP they use (`VISION.md:87-92`). The
relay learns an agent's owner from a self-proving NIP-OA attestation, and a ban
on the owner cascades to every agent key
(`crates/buzz-relay/src/handlers/auth.rs:106-184`). Membership is re-authorized
on every single delivery, not at subscribe time (`handlers/event.rs:116-217`).
Buzz's own tagline is "where humans and agents are just colleagues"
(`VISION.md:244`).

Ambush's version is the mirror image, and it is stronger, because it is where
the symmetry deliberately stops:

- Every agent holds an admitted Ed25519 key and a stable `swarm:ed25519:<hex>`
  identity (README §Security and trust).
- The strongest action any agent can take is `SwarmAction::RequestResponse`
  (`crates/swarm-core/src/types.rs:349`). Only Tom issues receipts, in
  deterministic Rust.
- A confident hallucination is held back by the same distinct-source rule that
  holds back a noisy detector (README §Bring your own agent).

### The claim, and both of its asymmetries

> **One record, two asymmetries.** Agents and humans write to the same durable
> record — same identity primitive, same room, same per-delivery authorization,
> same audit trail — and they differ deliberately on two axes.
> **Authority:** only the daemon dispatches; the console publishes intent.
> **Attention:** agents write to the case and do not read it.

The second asymmetry is new to this revision and it is a correction, not a
flourish. In the specified system the bridge subscribes **in-process** to
`RuntimeEvent` and publishes over `buzz-ws-client`
(`03 §1`, `02 §4`); its "read side" is HTTP GETs to the daemon to hydrate
objects. Nothing anywhere in `02`, `03` or `07` opens a relay `REQ` on the
Ambush side, and `02` settles that the Tauri process links no Ambush crate. So:

- A human message posted into a case channel reaches no agent.
- A NIP-10 reply to a finding card reaches no agent.
- `@`-mentioning Whisker reaches no agent.

Saying so is not a retreat. It is the difference between this document's claim
and the chatops claim it rejects, and stating it prevents building the affordance
that implies a response. Three consequences we accept in v1, each of which
belongs to a named surface doc:

1. Agent identities are excluded from mention autocomplete in a case, or the
   members list renders "agents do not read this channel." (`04 §2.3`)
2. "A case member `@`-ing you" is a **human-to-human** queue source only, and it
   is empty in a single-operator deployment — which is the same fact objection 4
   in §9 raises, arriving from the other direction.
3. A human message in a case is an annotation for the next shift and for the
   export bundle. That is its whole job, and it is a real job: it is the thing
   Ambush's one `Option<String>` cannot hold.

If a read path is ever wanted, it is a costed backend item (a relay subscriber
inside the daemon, subject to ADR 0010's single-writer argument), not a
configuration flag. It is not in v1 and nothing in this document assumes it.

```
        ┌──────────────────────── one case channel ────────────────────────┐
        │                                                                  │
  Whisker ──deposit──▶ substrate ──concentration──▶ Escalation             │
        │                  ▲                            │                  │
        │                  │                            ▼                  │
   Pouncer ──RequestResponse──────────────▶ policy: RequireHuman           │
        │                  │                            │                  │
        │        (agents publish into the case;         ▼                  │
        │         no agent subscribes to it)     HeldActionStore  (daemon) │
        │                  │                            │                  │
        │                  │                    kind 46010 hold card       │
        │                  │                            ▼                  │
        │                  │              ┌──── OPERATOR reads the row ────┐
        │                  │              │  G grant · R refuse            │
        │                  │              │  C confirm · D dismiss · I inv.│
        │                  │              └────────────┬───────────────────┘
        │                  │                           │
        │        leg 1: signed INTENT card ────────────┤ (relay: the record of
        │                  │                           │  what a human meant)
        │                  │                           │
        │        leg 2: POST /holds/{id}/decide ───────┘ (daemon: re-evaluates
        │                  │                              policy + governance
        │                  │                              from scratch, mints
        │                  │                              the lease at DECISION
        │                  ▼                              time, then dispatches)
        └──── Dismiss deposits a suppression marker ──▶ concentration drops
                                                        Kitten penalizes the
                                                        strategy; the tuning
                                                        report re-ranks
```

The two-legged write is the enforcement mechanism. Perch publishes a signed
human *intent* record onto the relay and separately posts a decision to the
daemon, which re-derives authority from scratch. **The console cannot
authorize.** That is guaranteed by a process boundary, not by convention, which
is why the grant control says "record my decision and send it to the daemon"
rather than "approve" (brief render law 6), and why the verdict key is `G` and
not `A` (`04 §0.4`).

One correction carried in from §2.2: leg 1's carrier is settled in
`03-DOMAIN-EVENT-MAPPING.md`, and it has since been settled there: it is **not**
46030. 46030 is a Buzz *command* kind that dies on a missing `workflow_approvals`
row, so leg 1 rides a `kind:9` card carrying the `ambush:verdict:v1` marker
(`03` §5.5). The wedge does not depend on the integer. It depends on the two legs going
to two processes.

What no SIEM console can structurally do here: their approval buttons *are* the
authorization. The button and the authority live in the same process, behind the
same session cookie. Ambush's design puts the authority in a separate binary
that holds the lease store, the receipt counter and the governance keyring
(ADR 0010, `crates/swarm-runtime-http/src/http/containment.rs:1-39`), and Perch
is downstream of it by construction. That is a stronger safety property than any
console-side RBAC, and it is a property we get for free by *not* rewriting
Ambush's topology.

---

## 5. Against the incumbents, specifically

> **Verification note.** The characterizations of CrowdStrike, Splunk, Elastic,
> Panther and Google SecOps below come from general product knowledge, not from
> source I read. They are **unverified** and must be re-checked against current
> vendor documentation before appearing in any external-facing material. The
> Ambush and Buzz claims in the same table are cited and verified.

| Console | What it does well and we will not attempt | What it structurally cannot do, and why |
| --- | --- | --- |
| **CrowdStrike Falcon** | Sensor telemetry at fleet scale; one-click network containment; a mature detections queue with assignment and SLA. | Containment is a vendor state, not a leased capability with a declared blast radius, a typed inverse and an expiry that releases without a human. Ambush expresses mandatory expiry as a type: `ContainmentTtl` is a `NonZeroI64` newtype and "there is no `ContainmentTtl` that means 'no expiry'" (`crates/swarm-response/src/containment.rs:74-81`). The timer is a type invariant, not a policy setting. |
| **Splunk ES + SOAR** | SPL; unlimited retention; a playbook editor with a large integrations catalog; enterprise reporting. | A human's disposition on a notable is metadata. It does not enter a detector's fitness function. Splunk's tuning path is a human editing a correlation search in a separate tool, on a separate cadence. Ambush's is `is_suppressed_by_feedback` on the next concentration evaluation. |
| **Elastic Security** | Open-ish, cheap at volume, strong detection-as-code with rules in Git. | Detection-as-code without evolution-as-code: a rule change is a PR, not an artifact chained back to the pressure that produced it through replay-validate → rank → proof → canary → promote (README §The swarm evolves too). |
| **Panther** | Detections as Python, CI-tested, security-data-lake economics. | Same as Elastic on the loop, plus: no response authority at all, so no gate to render. Panther's console has nothing to hold. |
| **Google SecOps (Chronicle)** | Petabyte search at flat cost; UDM normalization; curated detections. | Curated detections are the vendor's, shipped to you. Ambush's promotion path deliberately refuses every candidate under the shipped ruleset ("no proof, no promotion", `docs/EVOLUTION.md:161`) and the curated bundle is sha256-pinned in a signed attestation whose key is absent from the repo (`:274`). The direction of trust is inverted. |
| **The AI-SOC cohort** | Genuinely good alert narratives; fast triage of high-volume noise. | The model is theirs and improves for everyone; your verdict is training data you do not own. In Perch the verdict is a local artifact that changes *your* colony's arithmetic and nothing else. |

Three claims we can make that none of them can, each with its citation and its
current limit:

1. **Your verdict is arithmetic, not metadata.**
   `crates/swarm-pheromone/src/substrate.rs:1286`, `:1367-1380`. *Limit:* the
   verdict must attach to an incident (§1.1).
2. **The action you approve carries its own inverse and its own expiry, and the
   product tells you when it has neither.** Twelve destructive actions
   (`swarm-policy/src/static_gate.rs:37-53`, identical to
   `swarm-runtime/src/dispatcher.rs:1276-1292`), three executable inverses
   (`swarm-response/src/rollback.rs:66-78` — `ReleaseQuarantinedFile`,
   `ResumeProcess`, `RestoreHostConnectivity`), and
   `RollbackReceipt::fully_reversed()` is deliberately strict so Simulated and
   Irreversible cannot masquerade as success. *Limit:* the one receipt-side
   signature that verifies today is the release attestation
   (`swarm-runtime/src/containment.rs:235-269`), which checks signature **and**
   subject binding. `swarmctl evidence-verify` does **not** verify a response
   receipt — it verifies an evolution `EvidenceBundle`
   (`swarm-evolution/src/evidence.rs:1759`). Do not point at it from a receipt
   row.
3. **The console cannot authorize.** Two-legged writes across a process
   boundary; ADR 0010's single-writer argument. *Limit:* none — this one is
   structural and true today.

Three things we explicitly will not build, and the reason:

- **No query language and no hunting IDE.** `/ledger` is one NIP-50 search bar
  with Slack-style operators over findings, receipts, leases, canvases and human
  verdicts. Ambush's operator surface has *zero* free-text search today, so a
  single bar is a category jump; an SPL competitor is a decade of work we would
  lose.
- **No case management with SLAs, assignment and ticketing sync.** The case is a
  TTL channel that archives itself on silence. Snooze and handoff cover the real
  workflow; queue-management theater does not.
- **No executive dashboards.** The brand's own instinct — README's benchmark
  section says "Rerun them on your own host before making a capacity claim" — is
  incompatible with a screen designed to be screenshotted into a board deck.

---

## 6. The pitch and the demo

### Ten seconds

**To the operator:**
> Ambush already ranks which of your detectors is lying to you. It has no way to
> ask you. Perch is the ask.

**To the security leader:**
> A SIEM tells you what happened. An XDR tells you what it blocked. Ambush
> proves what it saw and why it was allowed to act — Perch is where your team
> does the allowing, and every allow is timed, reversible where reversal exists,
> and feeds next week's tuning.

**To the engineer:**
> Twelve destructive actions require a signed governance receipt. Three have an
> executable inverse. Perch is the screen that will not let you confuse the two
> at 02:41.

The leader pitch deliberately reuses the README's own stanza
(`README.md:51-53`) and extends it by one clause. Perch is a continuation of
that sentence, not a new one. Note what it does **not** say: it does not say the
allow is signed, and it does not say the ledger names who allowed it. Both are
true only after §2.3 and §2.4 land, and the sentence is written so that landing
them is an upgrade rather than a correction.

### Two minutes

Beat-by-beat, with the surface, the thing that must be true, and the phase in
which the beat becomes showable. That last column exists because three beats sit
on surfaces `09-ROADMAP-AND-RISKS.md` schedules after Phase 1 — the full
two-minute demo is a Phase-3 artifact, and pretending otherwise would put a
mocked screen in a sales meeting.

| t | Beat | Surface | Must be true | Phase |
| --- | --- | --- | --- | --- |
| 0:00 | "This is one shift." Perch opens on The Watch. Four queues; two rows in `needs_action`. No dashboards. | `/` | Home inbox remapped from `FeedItemCategory` | 1 |
| 0:15 | "The swarm found something without a correlation rule." Click the case. Three deposits from three detectors on one host, a NIP-10 reply thread, `2.41 / 3 sources / 2 agents` — never a bare source count. | `/cases/$id` | Render law 2; `strategy_scoped_agent_id` (`swarm-whisker/src/stream.rs:19-22`) makes bare counts a lie | 2 |
| 0:35 | Back to the queue. The held row. Read the five fields in fixed order: **IsolateHost** → blast radius → *no executable inverse; irreversible* → *rule `command-and-control-emergency-block` did not match; static gate at HIGH* → *a 60-second capability lease*. | `/` detail | Hold store exists; `lease_ttl_ms: 60000` (`rulesets/default.yaml:94`) | 1 |
| 0:55 | Press **G**. The button says "record my decision and send it to the daemon." Governance strip shows *committee of 1 (solo transport)* — never a quorum fraction. | `/` detail + chrome | `SoloGovernorTransport` refuses larger committees (`docs/CONSENSUS.md:87-89`) | 1 |
| 1:10 | `/leases` — the containment is open, `remaining_ms` counting down, `expired` a separate field. "If nobody comes back, it lapses on its own." | `/leases` | `http/containment.rs:70-88`: `remaining_ms` SATURATES AT ZERO | 2 |
| 1:25 | Second row: a finding **on this case**. Press **D** for Dismiss. The row shows *what will be suppressed*, and the suppression appears as an explicit timeline row in the case. | `/` detail | `is_suppressed_by_feedback`; and the finding belongs to an incident, or the feedback route 404s (§1.1) | 1 |
| 1:40 | `/watch-floor` — the concentration curve for that threat class visibly drops. Labelled as interpolation; the header shows the runtime's `total_strength`. | `/watch-floor` | Render law 4; deposits route returns the post-suppression slice | 3 |
| 1:50 | `/tuning` — a `DetectorThresholdReview` card that was not there ninety seconds ago, with reviewed / false-positive / rate and `supporting_signals`. | `/tuning` | `build_alert_tuning_report`, thresholds 0.75/0.50/0.34 | 2 |
| 2:00 | "That is the loop. Nothing here is a status field." | — | — | — |

**The demo constraint, stated as a rule:** the hold at 0:35 is real or the demo
does not happen. Ambush's brand is built on pairing every claim with the command
that falsifies it; a mocked gate would be the exact failure the docs mock
elsewhere ("A stub is not a proof"). If the hold store slips, the v0 demo is
`/watch-floor` + `/ledger` + `/gaps` with the queue visibly labelled *not yet
wired* — which is still a category jump over 1,523 lines of string-concatenated
HTML, and still honest.

**The Phase-1 demo, which is the one that actually ships first,** is beats 0:00,
0:35, 0:55, 1:25 plus the C9 counter strip on `/`: forty-five seconds, one
screen, one hold, one dismiss, and a number that says how many measurements this
week produced. That is a smaller demo and a truer one.

---

## 7. What the UI changes, commercially and philosophically

### An engine with a CLI is a tool

Today Ambush is distributed as a `cargo install` one-liner and operated through
126 subcommands, of which ~124 are not HTTP clients at all — they open `data/*`
directories directly. The measurement behind that: `core.inc` is 5,750 lines and
contains exactly **3** `reqwest` references. That is a *tool*: something one
person runs on a box. It is bought by an individual engineer, evaluated in an
afternoon, and defended in a review by that engineer's credibility.

There is one existing programmatic consumer that should not be quietly forgotten
in a positioning document: `clients/python/swarm-platform-client/` is a
generated OpenAPI client (`client.py`, `types.py`, ~20 model modules, plus
`smoke_platform_client.py`) against the read-only `/v2/api` surface. Perch does
not use it and does not poll `/v2/api`. Whether that surface is frozen,
deprecated, or must keep working is a compatibility question with a real cost,
and it belongs in `02-ARCHITECTURE-INTEGRATION.md`'s verdict tables rather than
here. The positioning point is narrower: Ambush already has an external contract,
and "Perch is the console" must not be heard as "Perch is the only client."

An engine with Perch is a *place*. It has a shift, a handoff, a queue with your
name on rows, a room per incident, and a search bar over the whole record. That
is bought by a team, evaluated over a week, and defended by the artifact it
produces at quarter end.

The commercial shift is not "add a GUI to sell it." It is a change in **what is
being sold**:

| | Ambush today | Ambush with Perch |
| --- | --- | --- |
| Unit sold | A runtime | A shift |
| Buyer | The engineer who will run it | The team who will staff it |
| Evaluation | "Does it detect?" — `swarmctl first-run` | "Would I let it act, and can I prove I decided?" |
| Renewal artifact | Benchmarks | The quarter's decision ledger and tuning history |
| Failure mode of the sale | "Impressive, but who operates it?" | "We need one more seat" |

One row of that table is a promise with a dependency. **"Can I prove I
decided?"** is answerable today only as *"can I prove a human was asked, and
that the action ran on the human-approved path"* — §2.4. The stronger sentence unlocks
when `approved_by` reaches the receipt. Sales material must use the weaker
sentence until then; it is still a sentence no SIEM's disposition field can say,
because the weaker sentence is about an *authorization path*, not a status
column.

### An app that shows its work

Philosophically the UI has to inherit a voice that is unusual and load-bearing.
Ambush's docs argue with themselves in public: the README has a section titled
"What we do not catch, and why" backed by a checked-in file listing exactly 18
intentionally-uncovered ATT&CK techniques across 11 detectors with per-technique
rationale (`rulesets/evasion/attack-technique-catalog.yaml` — 18 `technique:`
keys, 11 distinct `detector:` values, both counted this session). ADR 0009 is
subtitled as negative space. `docs/EVOLUTION.md` opens a section with "Read this
before filing 'promotion is broken'."

The console must be the same personality. That is why `/gaps` is a v1 surface
and not a nice-to-have: **every empty state in the app links there instead of
saying "no data."** A quiet queue that says which techniques would not have made
noise is the opposite of "Everything looks good!" — and it is the single
cheapest way to make the app feel like the docs.

### The uncomfortable one

The README says: "Fifteen typed response actions are available to the playbook.
**Three are destructive** — `BlockEgress`, `IsolateHost`, `RevokeCredential` —
and none can execute without a signed governance receipt" (`README.md:216-220`).

The code says twelve.
`response_action_requires_governance_receipt`
(`crates/swarm-runtime/src/dispatcher.rs:1276-1292`) and
`StaticApprovalGate::destructive_action`
(`crates/swarm-policy/src/static_gate.rs:37-53`) enumerate the identical twelve
variants — the three above plus `SinkholeDns`, `TerminateUserSession`,
`InjectFirewallRule`, `QuarantineFile`, `KillProcess`, `SuspendProcess`,
`DisableUserAccount`, `ForcePasswordReset`, `RemoveScheduledTask`. The README's
own headline safety claim undercounts its own safety property by a factor of
four.

This is worth saying out loud in a positioning document because it is the
argument for the UI in miniature. Prose drifts from code; a console rendered
from the code does not. A screen that shows twelve badges when the marketing
page shows three is the product correcting its own documentation, in public, at
02:41. That is on-brand in a way no competitor's console can be, because no
competitor's brand is built on falsifiability.

(The correction propagates: **two badge families, not one** — twelve
destructive/human-gated/receipt-required, three reversible — with "which rule
decided" as a third, orthogonal axis. See `08-TRUST-AND-GOVERNANCE-UX.md`. Three
of this plan's own reviewers asserted "three receipt-gated actions" and two
claimed to have verified it; the error is durable, which is the point.)

---

## 8. Adoption: hour, week, quarter

| Horizon | What happens | What it requires | The number that proves it |
| --- | --- | --- | --- |
| **First hour** | `swarmctl first-run` still works exactly as it does today. Perch connects to the running daemon and The Watch shows the office-dropper correlation as a case with three deposits and a thread. Nothing is held yet — detect-only is still the default. | Perch reads: the deposits route, the ephemeral telemetry stream, the case channel. Zero writes. | Time from `cargo install` to a rendered case. Target: under the ten minutes `first-run` already takes. |
| **First day** | The operator turns on `mode: live_response` with `human_gate_severity: HIGH` — three lines of YAML the README already documents — and the first hold appears in `needs_action`. They press `D` on a benign finding on a promoted case and watch the curve move. | The daemon-side `HeldActionStore` and `POST /holds/{id}/decide`; and the feedback route resolving an incident for the finding (§1.1). | First verdict recorded. |
| **First week** | Two operators on alternating shifts. `/handoff` composes a `ReviewSession` from every case touched; the incoming analyst resumes at three read frontiers. Cases archive themselves on silence via channel TTL. Snoozes come back. | Handoff, snooze, TTL channels, read frontiers — all Buzz machinery, no Ambush backend work. | Verdicts per week, and how many cases were resumed rather than re-read. |
| **First month** | `/tuning` has ranked recommendations sourced from real verdicts, not from a webhook. The first `DetectorThresholdReview` crosses 0.50 and someone hand-writes a profile change. `/policy` has already caught one allow rule shadowing the human gate. | Nothing new; the loop is running. | Fraction of tuning recommendations traceable to in-app verdicts. This is *the* metric. |
| **First quarter** | The decision ledger is the audit artifact. `/ledger` answers "show me every destructive action that ran on the human-approved path last quarter, and the rule that sent it there" in one query. Detector false-positive rate has moved, and the movement is attributable. | NIP-50 FTS over the case record; a verify affordance that re-reads the daemon. | Median seconds page-to-verdict; FP rate delta with verdict attribution. |

Two corrections to the first-quarter row, carried from §2.3 and §2.4, because
this is the row a buyer will quote back at us. **The query** is *"which
destructive actions ran on the human-approved path, and under which rule"* — not *"who
authorized what"* — until `approved_by` reaches `ResponseReceiptAudit`;
`policy.verdict == require_human` is the only signal in the chain today that a
person was involved at all. **The verify affordance** re-reads the daemon; it is
not `swarmctl evidence-verify`, which takes an evolution `EvidenceBundle`
(`swarm-evolution/src/evidence.rs:1759`), not a response receipt. The one thing
it can check cryptographically today is a containment release's governance
attestation (`swarm-runtime/src/containment.rs:235-269`); every other row gets a
re-fetch and "the daemon is the record" until §2.3 lands.

### The falsification instrument has one home

The brief's C9 instrumentation — **median seconds page-to-verdict**,
**measurements written per week**, and **what fraction of Friday's tuning
recommendations came from this week's verdicts** — ships in Phase 1 and lives on
**The Watch (`/`)**, in the queue-1 header strip. Not on the Watchfloor: under
`04`'s route table the Watchfloor is `/watch-floor` and it is a Phase-3 surface,
so putting the thesis's own falsification instrument there would defer it by two
phases, which is the same as not shipping it.

`/tuning` and `/handoff` restate these numbers where they are locally useful and
**link back to `/`**; they do not compute their own. One producer, three readers.
`09-ROADMAP-AND-RISKS.md`'s Phase-1 exit criterion names `/` accordingly.

If the third number is near zero after a month of real use, the thesis of this
document is wrong and we should know it from our own telemetry before a customer
tells us.

---

## 9. The honest counter-case

Six objections in their strongest form, our answer, and what would actually
falsify the thesis.

**1. "Nobody wants another chat app in their SOC."** The strongest form: analysts
already drown in Slack; a channel-per-incident is where context goes to die; the
last decade of chatops produced alert fatigue, not better decisions.

*Answer:* the objection is right about chat and wrong about the shape. Perch is
not a chat app with security data in it; it is a queue with a conversation
attached to each row. The homepage is a verdict queue, not a message list. The
brief deletes DMs, pulse-as-social, likes, GIFs, custom emoji, confetti and
huddle precisely so the chat affordances that survive are the ones that carry
evidence. And exactly four notification classes may wake someone at 03:00, with
the explicit instruction to refuse a fifth at least four times. §4's attention
asymmetry is the sharpest version of this answer: the room is a record, not a
conversation with a robot.

*What would falsify it:* operators keep the app open but make verdicts somewhere
else — in the CLI, in a ticket. If the terminal panel's `swarmctl` usage
outgrows the verdict rate by 10:1 after a month, the queue is not the workflow.

**2. "The operational bill is absurd for a two-container product."** Postgres,
Redis, 40 migrations, `pgschema` desired-state with a reconcile script, plus a
NATS JetStream substrate already in Ambush — two message buses, two durability
stories.

*Answer:* it is absurd, it is real, and every deployment document states it
plainly (brief constraint C2). The counter-argument is that the alternative —
the contrarian's proposal to delete the relay and rebuild — is roughly 6k LOC
(figure carried from the master brief, **unverified**) of event store,
subscription fan-out, per-delivery re-authorization, keyset pagination and FTS,
all of it security-critical. We are trading operational weight for correctness we
did not write. Also: the relay must sit inside the operator's network boundary
and never on the internet, which is consistent with Ambush's own declared
non-goal of internet-exposed operator governance.

*What would falsify it:* a design partner refuses the deployment. If the first
two evaluations stall on "we are not running Postgres and Redis for a console,"
the packaging is the product problem, not the UI.

**3. "The verdict volume is too low for the loop to matter."** The thresholds
need real N: `HOST_EXCLUSION_MIN_REVIEWED: 2`,
`DETECTOR_THRESHOLD_MIN_REVIEWED: 4`, `DETECTOR_RULE_MIN_REVIEWED: 3`
(`alert_tuning.rs:7-15`). A well-tuned colony that escalates twice a week
produces a tuning report in a month, maybe.

*Answer:* this is the most serious objection in the list, and §1.1 makes it
sharper rather than softer: a verdict only counts if the finding is on an
incident, so the *effective* denominator is promoted cases, not findings seen. If
the case-promotion bar is set high, the loop starves quietly. The honest answer
is that the thresholds are low *because* the designer expected low volume — four
reviewed findings on one detector is a deliberately small bar — and that the
promoted/suppressed counter belongs on `/` from day one alongside the C9
numbers, so a starving loop is visible in week one rather than quarter two.

*What would falsify it:* fewer than ~10 verdicts per operator-week in a real
deployment. Below that, the console is a governance surface (still valuable) but
not a tuning loop, and the pitch must change to match.

**4. "This is a single-operator product wearing a team product's clothes."**
Governance is `SoloGovernorTransport`, a committee of one
(`docs/CONSENSUS.md:87-89`). Multi-tenant operator governance is a non-goal.
`validate_and_append_vote` hardcodes `vote: ApprovalVote::Approve`
(`crates/swarm-runtime/src/approval.rs:1341-1345`), so there is not even a signed
reject path. Who is the second seat?

*Answer:* the second seat is the next shift, not a second voter. Handoff,
read frontiers, snooze and the case canvas are all *asynchronous* collaboration
between people who are never online together — which is the actual shape of SOC
work and the one Buzz's model happens to fit. We do not ship an approval-ledger
voting surface in v1 (brief default), and the governance strip renders
"committee of 1 (solo transport)" rather than a fraction. The cost is admitted in
§4: the mention queue is empty in a solo deployment, and we do not pretend
otherwise by counting agent posts as mentions.

*What would falsify it:* a single operator with no handoff finds `/handoff` and
the case model to be pure overhead. If solo users turn off case promotion, the
team framing is aspirational and the product is a personal tool.

**5. "The fork tax will eat the team."** Buzz moves fast — `AppShell.tsx` is at
**997** of a hard 1000-line cap, `MessageRow.tsx` at **998**, `e2eBridge.ts` is
**14,620** lines that must mirror every backend change, and three kind registries
are hand-synced. *(All three line counts re-measured this session with `wc -l`;
they are no longer inherited numbers.)*

*Answer:* the wire-format decision is the mitigation. Marker-prefixed kind:9
cards mean **zero** additions to the three kind registries, and the relay fork
is two match arms with a written-justification requirement on any third. The
first two housekeeping items (split both files, lift the renderer registry) are
immediate, not deferred. And the 46010 fix is upstreamable to `block/buzz` as a
genuine bug fix, which converts a fork cost into a contribution.

*What would falsify it:* the first upstream merge takes more than a day. Track
it; it is the cheapest early signal of fork drift.

**6. "You are selling a signed record you have not built."** New in this
revision, and it is the objection this document should be least comfortable
with. Four of the seven card types are unsigned (§2.3); no artifact names the deciding
human (§2.4); the chain machinery has one feature using it; and the two-legged
write's leg 1 cannot ride the kind we assumed it would (§2.2).

*Answer:* every one of those is a small, local change inside Ambush's own
daemon, against verifiers that already exist and are already tested — one
`build_signed_envelope` call, one threaded struct field, one carrier decision.
None of them requires new cryptography, a new trust anchor, or a change to the
process topology. But they are on the critical path of the *sentence*, not just
the code, and the correct response is to make the sentence match the build
state at every horizon (§6's ten-second pitches and §8's quarter row are both
written to the weaker, true version) and to put the stronger version behind a
dated item on the backend bill.

*What would falsify it:* the `approved_by` field and the envelope wrap do not
land within one milestone of the hold store. If the record still cannot name a
human two quarters in, the product is a very good queue on top of an audit trail
that does not know we exist, and the "quarter's audit artifact" claim must be
retired rather than deferred.

### Falsification table

| Claim | Measurement | Kill threshold |
| --- | --- | --- |
| Verdicts drive tuning | Fraction of weekly recommendations traceable to in-app verdicts | < 20% after one month of real use |
| The queue is the workflow | Verdicts per operator-week | < 10 |
| The console is fast enough to be the shift | Median seconds page-to-verdict | > 120s sustained |
| The graft is cheap | Days to land the 46010 upstream PR; count of stored kinds added | > 1 day; > 0 additional stored kinds without written justification |
| Handoff is real | Cases resumed via handoff vs re-read from scratch | < 50% resumed |
| The loop has a denominator | Promoted cases per week vs findings seen | Promotions ≈ 0 while findings > 0 for two consecutive weeks |
| The record is real | Weeks until a receipt names the deciding operator | > 1 milestone after the hold store ships |

---

## 10. Brand continuity: a body, not a rebrand

Perch must read as the same product as the README. Four continuity rules, each
sourced from something that already exists.

**The palette is already decided, and it is three colors.** Green `#4ade80` =
swarm, detection, deposits, trails. Amber `#f59e0b` = authority, the gate,
destructive, thresholds. Cyan `#22d3ee` = proof, receipts, audit, evolution.
Background gradient `#070a09` → `#0d1512`. Verified by frequency count across
`docs/assets/pillars.svg` (8 green, 7 cyan, 3 amber, re-counted this session) and
consistent across all 19 hand-authored SVGs. The semantic assignment is the
identity: amber *is* authority, so an amber badge on a hold is not decoration, it
is the same statement `colony.svg` makes. Details in `05-DESIGN-SYSTEM.md`.

**The only UI Ambush ships today contradicts that identity.** The operator
workbench renders `color-scheme:light` on a cream `#f4efe5` ground
(`crates/swarm-runtime-http/src/http/render.rs:38`) with a blue `#0f4f8a` accent
(`:46`). None of those hexes appear in any brand asset. That is not a criticism
of the workbench — it is a plainly-labeled internal review tool — but it does
mean **Perch is the first UI that will look like Ambush**, and there is no
incumbent look to preserve. That removes a whole class of "but it doesn't match
the existing console" objections.

**The voice is falsifiable declaratives.** Short sentences. Every claim followed
by the command or file that would disprove it. Negative space as a rhetorical
device. In-flight work fenced and shouted, never hidden. Existing lines Perch
should be able to sit next to without embarrassment: *"no agent commands another
· coordination is the substrate"*, *"no receipt, no action"*, *"Detection may be
permissive. Action may not."*, *"A stub is not a proof."*, *"Gaps here are
declared rather than discovered during an incident."* `06-COPY-AND-VOICE.md`
turns these into copy laws; the positioning consequence is simply that generic
console copy is off-brand and will read as a downgrade. It also means §2.3's
table belongs in the product, not only in the plan: a console whose brand is
falsifiability should render "UNATTESTED" more often than it renders a check.

**Naming.** *Perch* is where the cat waits before the ambush. It resolves a live
tension in the brand: the stigmergy math is ant-colony, the agent cast is
feline, and the two metaphors currently coexist without a referee. Perch settles
it for the UI layer — **the spatial metaphor is the cat's**: the operator is
above the colony, still, watching, and the moment of decision is the pounce. The
substrate view on `/watch-floor` keeps the ant physics (decay curves, trails,
thresholds) because that is what the math is; the operator's own surfaces take
the feline framing. One further housekeeping note that belongs in positioning:
the legacy codename "Swarm Team Six" still ships in the Helm chart name, the
OpenAPI title, `QUICKSTART.md`, `DEPLOYMENT.md` and `pillars.svg`. Perch must
never render it. Pick "Ambush" everywhere the console can see.

---

## 11. How the citations in this document were checked

A reviewer of the whole plan observed that the set "verifies that names exist and
stops there" — every blocking finding had the shape *the `path:line` is real, and
the inference drawn from it is not*. That is the failure mode a citation-dense
document is most prone to and least able to self-detect, so this revision applies
a three-question test to every load-bearing citation and writes the answer in the
same sentence as the citation:

1. **Who calls this?** `build_signed_envelope` has one non-test caller (§2.3).
   `verify_chain_link` has none outside its module (§2.3).
   `audit_authorize_and_execute_human_approved_instrumented` has two, both in
   `demo.rs` (§2.1).
2. **What process is it in?** The 49 operator routes run in
   `swarm_detect --serve`; the bridge subscribes in-process to the same binary
   (§4). Buzz's `handle_approval_grant` runs in the relay, against the relay's
   own tables (§2.2).
3. **What does it do to the data?** `providence_feedback_handler` writes a
   `FalsePositiveMeasurement` *onto an incident* and 404s without one (§1.1).
   `handle_approval_grant` flips a `workflow_approvals` row and resumes a
   workflow run (§2.2). `verify_release_attestation` checks a signature *and* a
   subject binding (§2.3).

Where the answer is "nothing / a different one / less than claimed," this
document says so beside the citation rather than in a footnote. Two claims from
the earlier draft were retracted outright by this pass (presence as the liveness
source, and 46030 as leg 1's carrier), and one — the eight-hop chain in §1 — was
found to have a precondition nobody had written down. That is the test working,
and it should be run again by whoever edits this document next.

**Still unverified in this document, deliberately:** the entire incumbent
comparison in §5; the "~90 of 126 subcommands are artifact management" split (the
126 is counted, the taxonomy is not); the ~6k LOC rebuild figure in §9 objection
2; the §3 "Today" column, which is a reasoned reconstruction from the CLI and
route surfaces rather than observed behavior; and every target number in §8 and
the falsification table, which are proposals rather than baselines.

---

## What this document does not decide

| Question | Owner |
| --- | --- |
| The relay fork, the bridge crate, process topology, module-by-module plan, and the disposition of `clients/python/` + `/v2/api` | `02-ARCHITECTURE-INTEGRATION.md` |
| Which Ambush object becomes which event, the carrier for leg 1 (§2.2), the backend bill order including the §2.3 envelope wrap and the §2.4 `approved_by` field | `03-DOMAIN-EVENT-MAPPING.md` |
| Every surface's layout, fields, keys and empty states; the route table; the case-promotion bar | `04-SURFACES-AND-UX.md` |
| Palette derivation, tokens, the accent pin, the SVG substrate view | `05-DESIGN-SYSTEM.md` |
| The word list (including "queue" vs "lane"), the badge vocabulary, error and empty-state copy | `06-COPY-AND-VOICE.md` |
| Coalescing, spooling, sequence gaps, render budgets | `07-REALTIME-AND-DATA.md` |
| The warrant pane's fixed field order, badge families, honest attestation, and what a verify affordance may claim | `08-TRUST-AND-GOVERNANCE-UX.md` |
| Build order, sizing, the hold-store dependency, risk register, and the Phase-1 exit criterion naming `/` as the C9 home | `09-ROADMAP-AND-RISKS.md` |
