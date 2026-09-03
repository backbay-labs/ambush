# Copy, naming, and the product vocabulary

Perch inherits two vocabularies that disagree: Ambush's typed Rust nouns (`RequireHuman`,
`distinct_sources`, `lease_closed`) and Buzz's chat-app nouns (channel, thread, inbox).
This document settles which word wins at every collision, fixes the biological metaphor
term by term, and writes the strings out in full — including the destructive-approval
pane, which is a safety control and is specified here like one. Every string below is
meant to be lifted into the codebase verbatim.

**Revision note (red-team pass).** Nine findings landed against this document or against
strings it owns. Six changed the copy: the verdict keymap (§5.5), the notification bodies
(§5.7), the evidence and attestation strings (§5.10), the dismiss arithmetic (§5.5), the
word *lane* (§2.4), and the scope of the ban list (§7.2). One finding was correct about a
claim this document had inherited without checking — the Ed25519 chain does not cover four
of the seven card types (finding, escalation, hold, lease) — and §5.10 now states which cards carry a verifiable signature and
which do not. Two errors this document found in its own strings while re-reading the
source are corrected here and flagged in §8.3: the dismiss suppression key is
`(threat_class, event_id)`, not `(strategy_id, host_id)`, and `swarmctl evidence-verify`
verifies **evolution** evidence bundles, not response receipts.

---

## Decisions made here

1. **Product name is Perch.** The deployment is a **colony**. "Clowder" is dead — it
   survives only in two stale roadmap SVGs (`docs/assets/roadmap.svg:54`) and never
   appears in `README.md` or any `docs/*.md`.
2. **The eight agent names stay**, because `AgentRole` serializes to `whisker`,
   `tom`, `calico` on the wire (`crates/swarm-core/src/agent.rs:17-34`) and those strings
   are already in every log line and receipt. But **a governance actor is never rendered
   bare**: it is always `Tom · governance`.
3. **"Pheromone" is kept as the compound, "deposit" is the working noun.** First mention
   on a surface is "pheromone deposit"; every subsequent mention is "deposit".
4. **"Substrate" is kept only where it names the configured component** (Settings shows
   `backend.kind`: `in_memory` / `local_journal` / `jet_stream`). Everywhere else the
   noun is "the trails".
5. **"Hunt" is dropped as a navigational noun.** `HuntId` is literally the telemetry
   event id (`crates/swarm-runtime/src/service/runtime_service.rs:391`), so a "Hunts"
   nav item would promise an object that does not exist. `hunt_id` renders verbatim as a
   field label on evidence surfaces because it is the join key operators paste into
   `swarmctl`.
6. **The `/leases` nav label is "Containments", not "Leases."** Two unrelated objects are
   both called a lease in the code — `CapabilityLease` (the 60-second authorization,
   `crates/swarm-policy/src/lib.rs:133`) and `ContainmentLease`
   (`crates/swarm-response/src/containment.rs`). See §2.2. **The ban is scoped** to
   rendered labels, headings, nav and badge text; identifiers and mid-sentence prose after
   the compound is established are exempt (§7.2).
7. **"Three destructive actions" is wrong and Perch must not repeat it.** `README.md:217-218`
   says three. The code says twelve, twice
   (`crates/swarm-policy/src/static_gate.rs:37-53`,
   `crates/swarm-runtime/src/dispatcher.rs:1276-1292`). Perch renders twelve and files a
   README fix.
8. **Two badge families, never one word "destructive."** Family A: twelve
   human-gated / receipt-required actions. Family B: three actions with an executable
   inverse. A third axis, "which rule decided," is a sentence, not a badge.
9. **The `IF YOU UNDO` copy is already written in the Rust and is rendered verbatim.**
   `InverseGap::Irreversible { reason }` at `crates/swarm-response/src/rollback.rs:186-188`
   carries an English sentence. Perch prints it; it does not paraphrase it.
10. **The grant control's label is a sentence about recording, never "Approve."**
11. **Confirm / Dismiss / Investigate are the finding labels**, unchanged from
    `ProvidenceFeedbackAction` (`crates/swarm-core/src/types.rs:110-116`), and each one
    states its distinct arithmetic effect, because only `Dismiss` sets
    `false_positive: true`
    (`crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:493`).
12. **The operator *refuses*; policy *denies*; Tom *vetoes*.** Three actors, three typed
    words, never interchanged (§4.1). "Deny" is retired as an operator control label.
13. **Verdict keys are `C`/`D`/`I` for findings and `G`/`R` for holds.** `A` is banned as
    a verdict key, in the ban list, for the same reason the word "Approve" is
    (§5.5, §7.2). This adopts 04-SURFACES-AND-UX.md §3.0 and replaces the
    `A`/`D`/`E`/`S` map this document previously carried.
14. **No empty state says "everything looks good."** Every empty state names a number.
    The `/gaps` link is **scoped**, not universal: only *swarm-produced-nothing* states link
    there (`04` §2.12 — an empty `/leases` means nothing is contained, which is not a coverage
    question). The phrase ban is universal; the link is not.
15. **Never a bare source count.** The string is always `N sources / M agents`.
16. **Never a quorum fraction.** The string is `committee of 1 (solo transport)`.
17. **Never a shield glyph on an attestation**, and never an unqualified "signed" badge.
    §5.10 carries a per-card signature-provenance table because four of the seven card
    types — finding, escalation, hold, lease — carry no signature of their own.
18. **A wake-class notification body contains typed values only** — no host, no path, no
    process name, no free text (§5.7). It is the one surface an `<AdversaryString>`
    component cannot reach.
19. **Evolution vocabulary (canary, promotion, proof) ships no v1 surface** but is
    glossed here so the tuning bench's forward-pointing copy is written once and
    correctly.
20. **"Lane" means exactly one thing in Perch:** one of the twelve standing threat-class
    channels. The inbox groupings are **queues**, the hue taxonomy is **pillars**, the
    bridge transport classes are **streams**, and README's agent grouping is not rendered
    at all (§2.4).
21. **Strings live in one module per surface under `desktop/src/features/<surface>/copy.ts`**,
    plus one shared `shared/copy/domain.ts` for the glossary terms, and a CI guard bans
    the banned words, the banned key, and free text in notification bodies (§7).

---

## 1. Voice: six laws

Ambush's docs already have a voice, and it is unusually good: every claim is followed by
the command that falsifies it, the README contains a section called *"What we do not
catch, and why"*, and `docs/EVOLUTION.md:187` contains the line **"A stub is not a
proof."** The existing operator workbench inherits it — every page description states
what the page is *not*: *"Promotion evidence packets stay advisory. This review flow is
for operator understanding, not approval or deployment."*
(`crates/swarm-runtime-http/src/http/pages.rs:1409`).

Perch's job is to keep that voice while going from ~40 server-rendered pages to fourteen
interactive surfaces. Six laws.

**L1 — State the limit in the same breath as the capability.** This is the house style
already, and it is what makes the product credible. Every surface that could be
mistaken for authority says it is not. Not in a tooltip; in the body copy, at the same
type size as the claim.

> ✅ "Release reads `lease_closed` from the daemon's response body. A 200 is not a
> release."
> ❌ "Release the containment."

**L2 — Use the domain's typed word, always, and never a friendlier synonym.** The moment
`Dismiss` becomes a thumbs-down, the tuning loop
(`crates/swarm-runtime/src/alert_tuning.rs:84`) is being fed by an emoji. `RequireHuman`,
`Confirm`, `Dismiss`, `Investigate`, `distinct_sources`, `lease_closed`,
`total_strength`, `attestation_verified` all appear on screen as themselves. Where the
typed word is unreadable alone, it gets a plain-English apposition — never a replacement.

> ✅ "RequireHuman — policy stopped this and asked for a person."
> ❌ "Needs your OK"

L2 has a corollary that is easy to get backwards: **a typed word belongs to the actor
that owns the type.** `PolicyVerdict::Deny` is policy's word and `GovernanceVeto` is Tom's
word, so neither may be borrowed for the operator's own act. That is §4.1.

**L3 — Calm under load. No exclamation marks, ever. No urgency adjectives.** The severity
is `CRITICAL` because `Severity` serializes SCREAMING_SNAKE_CASE
(`crates/swarm-core/src/types.rs:407-414`); that is the whole urgency signal. Copy that
adds "urgent!" on top of a CRITICAL badge is telling the operator the badge cannot be
trusted. The single permitted intensifier in the product is the word **still** —
"a host is still contained."

**L4 — Never cute about a destructive action.** No verbs like "zap", "nuke", "kill it
with fire", no emoji, no animation on the grant path. Buzz ships a confetti layer
(`EmojiBurstProvider`/`PoofBurstProvider` wrapping the tree at
`desktop/src/main.tsx:93-94`); the brief deletes it, and this document is the reason
why. A product whose defining sentence is *"If the swarm is wrong at 3am and nobody is
watching, the containment lapses on its own"* cannot also throw confetti.

**L5 — Numbers carry their denominator and their unit.** `2 sources / 1 agent`.
`58s remaining`. `0 of 6 recommendations acted on this week`. Never `2 sources`, never
`58`, never `100%`. This is the render law about `distinct_sources` generalized: a bare
number invites the operator to supply the missing half from memory, and at 02:41 they
supply it wrong.

**L6 — Say the thing that is absent.** An empty queue is not good news; it is a claim
about coverage. `rulesets/evasion/attack-technique-catalog.yaml` declares **18 ATT&CK
techniques across 11 detectors** deliberately uncovered (re-verified this pass: 18
`technique:` keys, 11 distinct `detector:` values). Every empty state routes there.

**Register:** sentence case for prose and buttons. `SCREAMING_SNAKE` only for `Severity`
values, because that is the serialization. `lower_snake_case` in mono for anything that
is a literal config key, action kind, strategy id, or wire field. Uppercase + tracking
for section eyebrows only, matching the existing brand SVGs' 4.2–5.2 letter-spacing
labels and Buzz's `Badge` cva (`desktop/src/shared/ui/badge.tsx:6-25`). No title case
anywhere.

---

## 2. Naming

### 2.1 The product name

**Perch.** Verified free this pass: no case-insensitive match for "perch" anywhere in the
Ambush tree outside `docs/plans/`, and none anywhere in Buzz's `desktop/src` or `crates`.
The word does the two jobs the brief needs — it is where a predator waits and watches,
which is on-metaphor for a feline swarm; and it is a *place*, not an action, which is
right for a console that explicitly never authorizes.

Rejected: **Clowder** (the collective noun) — it is already spent as the name of the
*community*, and it survives only in stale SVGs. Rejected: **Ambush Console** — generic,
and it makes the console sound like part of the runtime it is deliberately outside of.
Rejected: **Den**, **Nest** — both imply the thing lives inside; Perch's whole safety
argument is that it is external and reads over a process boundary.

Full name on first run and in the about box: **Perch — the Ambush operator console.**
Never "Ambush Perch". Never "Perch by Backbay Labs" in-product.

One naming defect must be fixed on the way in: `README.md`, `docs/QUICKSTART.md`,
`docs/DEPLOYMENT.md`, the Helm chart and the OpenAPI title still carry the legacy
codename "Swarm Team Six". Perch's window title, deep-link scheme and about box use
**Ambush** exclusively. `ambush://` is the scheme.

### 2.2 Surface names

| Route | Nav label | Page title (H1) | Rejected, and why |
|---|---|---|---|
| `/` | The Watch | The Watch | "Inbox" (Buzz's word) — an inbox is mail you may ignore; a watch is a shift you are accountable for. "Queue" as a *surface* name — implies FIFO across the whole screen; the four groupings inside it are queues (§2.4). |
| `/cases/$caseId` | (in sidebar, by case name) | `<case name>` | "Incident" — `CorrelatedIncident` is a real recomputed artifact (`crates/swarm-spine/src/incident.rs:135-146`); reusing the word for a channel would mean two things named incident. |
| `/lanes/$laneId` (12 channels) | Lanes | `<threat class>` | "Channels" — Buzz's word, and it tells an operator nothing. |
| `/leases` | **Containments** | Open containments | "Leases" — see below. |
| `/policy` | Policy | Policy rules | "Rules" — collides with `DetectorRule` in the tuning bench. |
| `/watch-floor` | Watchfloor | Watchfloor | "Dashboard" — a dashboard implies you act from it; this is a wall screen. |
| `/ledger` | Ledger | Ledger | "Search" — undersells it; this is the only enumeration surface in the product. |
| `/tuning` | Tuning | Tuning bench | "Feedback" — describes the input, not the output. |
| `/handoff` | Handoff | End watch | — |
| `/gaps` | Gaps | Declared gaps | "Coverage" — a coverage page implies a percentage; this page is a list of named absences. |
| `/settings` | Settings | Settings | — |

Route paths follow 04-SURFACES-AND-UX.md's table, including its rename of the brief's
`/watch` to `/watch-floor` (it collided with The Watch at `/`). Labels are this
document's.

**On `/leases` → "Containments".** The code uses "lease" for two unrelated objects.
`CapabilityLease { capability_id, expires_at_ms, action, scope }` is the authorization to
dispatch, minted by an `ApprovalGate`, and `lease_ttl_ms` is `60000` in
`rulesets/default.yaml:94` — sixty seconds. `ContainmentLease` is the bounded enforcement
window with a blast radius and an inverse, and its TTL is hours. Rendering "Leases: 3" in
the sidebar next to a verdict pane whose last field says "grants a lease" is a
conflation with a physical consequence: an operator could read "3 leases" as "3 pending
authorizations" and go looking for something to expire.

There is in fact a *third* lease in the tree — the governance partition path's
**contingency lease**, with its own 60-second TTL (`contingency_lease_ttl_ms: 60_000`,
`crates/swarm-runtime/src/dispatcher.rs:1592`) and its own count on the governance report
(`active_contingency_leases`, `crates/swarm-policy/src/governance.rs:68`). Three unrelated
objects, one word, is not a nuance; it is the reason the bare word cannot ship.

Resolution: route stays `/leases` (URLs are not operator-facing). Nav label and H1 say
**Containments**. The object noun on the page is **containment lease**, spelled out. In
the verdict pane, `CapabilityLease` renders as **capability lease** with its TTL, and the
partition path's is a **contingency lease**. Those three compounds are the whole allowed
set. The bare word is banned **in rendered labels, headings, nav and badge text** — not in
identifiers, not in route or query strings, not in code fences, and not mid-paragraph once
a compound has been established in the same block. That scoping is deliberate: a ban that its own author's strings fail is a ban
that gets weakened on contact (§7.2 carries the exact grep contract, and §8.2 names the
two peer documents that still ship "Leases" as a heading).

### 2.3 The agent names

Keep all eight: **Whisker, Stalker, Weaver, Pouncer, Tom, Kitten, Sphinx, Calico**
(`crates/swarm-core/src/agent.rs:17-34`).

The argument for renaming them to roles is real: a new analyst reading "Tom vetoed this"
learns nothing, and "Kitten" reads harmless while being the component that mutates
detectors. The argument against is stronger and decides it: `AgentRole` serializes
`snake_case` to the wire, into every `PheromoneDeposit.agent_role`, into every
`RuntimeEvent::AgentAction`, into `swarmctl` output and into the log format
`[Whisker-7a3f]`. A UI that renders "Detection agent" where the receipt says `whisker`
forces the operator to hold a translation table, and they will hold it wrong at 03:00.

**The rule instead: pair, do not replace.** Every agent identity renders as
`Name · role word` on first appearance in any row, list, or timeline group.

| Wire value | Rendered | README's grouping column (**not rendered**) |
|---|---|---|
| `whisker` | Whisker · detection | Critical |
| `pouncer` | Pouncer · response | Critical |
| `tom` | **Tom · governance** (mandatory, always) | Governance |
| `stalker` | Stalker · investigation | Async |
| `weaver` | Weaver · correlation | Async |
| `sphinx` | Sphinx · memory | Memory |
| `calico` | Calico · deception | Deception |
| `kitten` | Kitten · evolution | Evolution |

The third column is `README.md:143-152`'s own header, and that header is the word **Lane**.
Perch does not render it, for the reason in §2.4: it is a scheduling tier
(hot-path / async / governance), it is not one of the twelve threat-class lanes, and
shipping both would put two different "lanes" on the same row. The rendered role word is
the agent's function, taken from the same table's *"What it owns"* column.

Tom is special-cased as mandatory-always because "Tom denied this" is the single string
in the product most likely to be read as a person's name, and it is exactly the string
that appears next to a refused destructive action. (It is also the string that must say
*vetoed*, not *denied* — §4.1.)

Agent *instances* are `Whisker-7a3f` (role, hyphen, short id) matching the log format,
with the full 64-hex `swarm:ed25519:…` identity available on hover and rendered untruncated
on any surface where the operator is making a trust decision — the same doctrine Buzz
already enforces for Nostr keys with `<PubKey variant="full">` and the
`check-pubkey-truncation.mjs` guard (`desktop/src/shared/ui/PubKey.tsx:17-31` states the
rationale: "a truncated key is forgeable by vanity grinding"). Extend that guard to
Ed25519 identities.

### 2.4 The word "lane", ruled

"Lane" arrived in this plan set from four directions at once and ended up meaning four
things, one of which is a nav label an operator reads. That is the exact defect this
document bans for "lease" in §2.2, and the rule has to apply to our own coinage or it is
not a rule.

| Sense | Where it came from | Perch's word | Note |
|---|---|---|---|
| One of the twelve standing threat-class channels | `standard_threat_classes()`, the `LANES` sidebar heading | **lane** — keeps the word | The only operator-visible sense. |
| One of the four inbox groupings on `/` | Buzz's `FeedItemCategory` | **queue** | Type name `FeedItemCategory` is unchanged; `LANE_LABELS` becomes `QUEUE_LABELS`. |
| The three-hue semantic taxonomy (substrate / authority / evidence) | 05-DESIGN-SYSTEM.md | **pillar** | Tokens are `--pillar-substrate` etc., after `docs/assets/pillars.svg`. *Family* was this document's first proposal and 05 §2.1 overrode it, correctly: "two badge families" already spends that word on a different axis. |
| One of the four bridge transport classes with spool budgets | 07-REALTIME-AND-DATA.md | **stream** | "the alarm stream", "256 MiB per stream". Never operator-visible. |
| README's agent grouping (Critical / Async / Governance / …) | `README.md:143` | not rendered | §2.3. |

Without this ruling, "the evidence lane" is simultaneously a colour token and a disk
spool, and "lane 1" is a queue on one screen and a threat class on another. Bare `lane`
outside the nav sense joins the ban list (§7.2).

---

## 3. The noun glossary

The user-facing name, one sentence a new hire understands, what it is not, and the
metaphor verdict. **Kept** = the biological word ships to users. **Softened** = the word
ships but never alone. **Dropped** = the word does not appear in Perch.

| Term | UI name | One sentence | It is NOT | Metaphor |
|---|---|---|---|---|
| pheromone | pheromone deposit → deposit | A signed observation one detector left on one host, carrying a half-life so it fades on its own. | An alert. Nothing pages on a deposit. | **Softened** — compound on first mention, "deposit" after. |
| deposit | deposit | See above; the working noun. | A log line — the substrate refuses a deposit whose Ed25519 signature does not verify and whose `agent_id` does not derive from the signing key (`crates/swarm-pheromone/src/substrate.rs:210-250`). | **Kept** |
| substrate | the trails (prose) / substrate (Settings only) | The shared store the deposits accumulate in. | A message bus. Agents do not send each other anything. | **Softened** — `substrate` survives only where it labels `backend.kind`. |
| concentration | concentration | The sum of every still-live deposit's decayed strength for one threat class. | A count of alerts. It is a float that shrinks over time. | **Kept** |
| decay / half-life | half-life | How long a deposit takes to lose half its strength: `strength(t) = confidence · 0.5^((t − timestamp) / half_life)` (`crates/swarm-core/src/pheromone.rs:281`). | A retention window. Nothing is deleted; strength approaches zero. | **Kept** |
| evaporation | (prose: "decayed below the floor") / `evaporation_threshold` in Settings | The strength floor under which a deposit stops counting. | Deletion. | **Softened** — the config key renders verbatim; the prose word is dropped. |
| distinct_sources | `N sources / M agents` | How many separate depositors agree — but a "source" is a detector strategy, not an agent. | The number of agents. `strategy_scoped_agent_id` sets `agent_id = "{agent}:{strategy}"` (`crates/swarm-whisker/src/stream.rs:20-22`) and `concentration_for` inserts that string (`crates/swarm-pheromone/src/substrate.rs:1295`), so one Whisker with four detectors reads as four sources. | **Kept**, never bare. |
| lane | lane | One of twelve standing threat-class channels. | A queue, a colour family, or a bridge stream — see §2.4. | **Kept**, single sense. |
| escalation | escalation | The moment concentration crossed a threshold *and* enough distinct sources agreed. | A page. Escalation changes the swarm's mode; it does not wake anyone. | **Kept** |
| mode / posture | mode | `Normal` / `Alert` / `Incident` — the swarm's current stance (`crates/swarm-core/src/agent.rs:110-120`). | A severity. Severity describes one finding; mode describes the whole runtime. | "Posture" **dropped** — not a code word. |
| incident | correlated incident | A durable artifact Weaver produced by correlating investigations, with named included *and rejected* members (`crates/swarm-spine/src/incident.rs:135-146`). | The channel you are reading. That is a **case**. | **Kept**, always the compound. |
| case | case | One private, TTL-renewing channel per promoted incident or held action; the case id is the channel UUID. | An Ambush artifact — it exists only in Perch and the relay. | n/a — invented, and labelled as Perch's own noun on `/gaps` and in Settings. |
| hold | held action | A destructive action policy stopped, parked in the daemon's hold store with an expiry, waiting for a person. | An approval request in Buzz's sense. Buzz's `workflow_approvals` table is not its home. | **Kept** — Perch's noun for `RequireHuman` made durable. |
| investigation | investigation bundle (artifact) / Investigate (verb) | The bundle is Stalker's replay-backed reconstruction; the verb is analyst feedback that keeps a finding open. | The verb does **not** create the bundle. Say "keeps this open and records that it needs work." | **Kept**, disambiguated by grammar. |
| finding | finding | What one detector concluded from one telemetry event, before anything accumulated. | An incident, an alert, or a reason to act. `DetectionFinding` has seven fields and no signature (`crates/swarm-whisker/src/detector.rs:50-59`). | **Kept** |
| receipt | governance receipt / response receipt / release receipt | The record that a specific decision was authorized. Only the *governance* receipt carries its own signature (§5.10). | Proof that someone you trust authorized it — there is no trust anchor (`docs/decisions/0010-…:125-139`). | **Kept**, always with its qualifier. |
| veto | veto | Tom's typed refusal of a destructive action, carrying a reason string (`crates/swarm-core/src/types.rs:377-384`). | An error, and not the operator's refusal. A veto is the system working. | **Kept** |
| capability lease | capability lease | The 60-second authorization minted at decision time that lets one action reach one adapter. | The containment. It is gone long before the containment ends. | **Kept**, never "lease" alone in a label. |
| containment lease | containment lease | An enforced containment with a hard expiry, a declared blast radius, and a named inverse. | Permanent. When it expires, the sweep releases it. | **Kept**, never "lease" alone in a label. |
| blast radius | blast radius | The typed preview of exactly what this action touches: scope kind, scope value, impact, and the count of affected scopes (`crates/swarm-core/src/types.rs:505-513`). | An estimate. It is a typed struct, not a guess — but `scope_value` is adversary-influenced (§5.7, §7.3). | **Kept** |
| rehearsal | rehearsal | A dry run that produced the blast radius and rollback plan without touching a real target (`simulated_only: true`). | A test of whether the action would succeed. | **Kept** |
| quorum | `committee of 1 (solo transport)` | How many governors must agree. Today: one, because `SoloGovernorTransport` is the only transport and it refuses larger committees (`docs/CONSENSUS.md:87-89`). | A fraction. Never render `1/1` or `3/5`. | **Kept**, as a fixed phrase. |
| governance health | governance | One of `healthy` / `degraded` / `partitioned` / `healing` (`docs/CONSENSUS.md:214-223`; `crates/swarm-policy/src/governance.rs:49-54`). | A connection status. `healing` is a first-class state, not "recovering." | **Kept** |
| colony | colony | One Ambush deployment: one runtime, one substrate, one governance chain. | A tenant. Internet-exposed or multi-tenant operator governance is a declared non-goal (`docs/CONSENSUS.md:312`). | **Kept** |
| swarm | the swarm | The eight agents plus the substrate, taken together. | A cluster. Nothing commands anything. | **Kept** |
| hunt | `hunt_id` (field label only) | The id that joins a finding to its replay bundle — in practice the telemetry event id. | A saved search, an investigation, or a thing you can list. | **Dropped** as a noun; kept as a field. |
| decoy | decoy | A deliberately fake asset Calico plants so that touching it is itself the signal. | A honeypot product. `decoy_type` is a free string (`canary_token`, `honeypot`) and renders verbatim in mono. | **Kept** |
| canary (evolution) | canary lane | The bounded live lane a candidate detector runs in before promotion. | A canary *token*. Never render bare "canary". | **Kept**, always "canary lane". Not rendered in v1. |
| promotion | promotion | Making a candidate detector the production subject under a bounded observation window. | Deployment. Zero promotions with the shipped ruleset is correct by design (`docs/EVOLUTION.md:161`). | **Kept**. Not rendered in v1. |
| evolution | evolution | Selection pressure applied to the detector population itself. | Self-modifying response behavior — only detection artifacts evolve (`docs/EVOLUTION.md:52`). | **Kept**. Not rendered in v1. |
| tuning recommendation | recommendation | A ranked suggestion — host exclusion, detector threshold, or detector rule — computed from analyst verdicts. | An action. The next step is a config diff a human signs. | n/a |

Two glossary entries earn their own note.

**Concentration and the four solver states are not the same kind of "empty".** A
concentration of `0.00` means every deposit decayed. Zero promotions means the gate
refused, correctly. Both are legitimate zeros with completely different meanings, and
neither is "no data". Copy for each is in §5.2.

**"Attested" is the most dangerous word in the product.** `attestation_verified: true`
means "this attestation matches this body," not "a governor we trust authorized this" —
`ConsensusGovernanceReceipt::verify` checks the signature against the public key carried
*inside the receipt*, and ADR 0010 names the absent third check itself
(`docs/decisions/0010-containment-release-goes-through-the-daemon.md:125-139`: "there is
no trust anchor … A full re-attestation is not caught"). `None` means **UNATTESTED**, not
"fine". The strings are fixed in §5.10 and no synonym is permitted.

---

## 4. The verb glossary

### 4.1 Three actors, three refusal words

This is the single highest-value distinction in the vocabulary, and it is the reason
"Deny" is retired as an operator control label.

| Actor | Typed word | Where it comes from | Rendered as | Never used for |
|---|---|---|---|---|
| The operator | **refuse / refusal** | Perch's own noun; the wire form is a `kind:9` card carrying `<!-- ambush:verdict:v1 -->` with `decision: "refuse"` (`03` §5.5 — **not** `KIND_APPROVAL_DENY = 46031`, which the relay routes to a command executor that rejects it) | "Refuse", "Refused by {operator}" | Policy's verdict or Tom's veto |
| Policy | **deny / denied** | `PolicyVerdict::Deny`, `ApprovalError::Denied` | "Denied by policy rule `{ruleName}`" | The operator's act |
| Tom · governance | **veto / vetoed** | `SwarmAction::GovernanceVeto` (`crates/swarm-core/src/types.rs:377-384`) | "Vetoed by Tom · governance" | Either of the above |

Conflating them produces the worst timeline in the product: three rows that all read
"Denied" and hide which of three independent mechanisms stopped the action. The wire form is
the `ambush:verdict:v1` card and the Tauri command is `perch_record_verdict` (`08` §7.6);
Buzz's legacy `deny_approval` command name survives only where it is re-pointed at the daemon.
Identifiers are exempt from the ban (§7.2).

### 4.2 The verbs

| Verb | Key | Where | What it does | What it does NOT do |
|---|---|---|---|---|
| **Record my decision** (grant) | `G` | verdict pane, held action | Publishes a signed `kind:9` `ambush:verdict:v1` intent card and POSTs the decision to the daemon. | Authorize. The daemon re-evaluates policy and governance from scratch. |
| **Refuse** | `R` | verdict pane, held action | Same two legs, same card, `decision: "refuse"`. | Stop an already-dispatched action. |
| **Confirm** | `C` | finding row | Writes a `FalsePositiveMeasurement` with `false_positive: false` — a *reviewed* finding that was real. | Escalate. It raises the reviewed denominator on `/tuning`. |
| **Dismiss** | `D` | finding row | Writes `false_positive: true` (the only verb that does — `providence_handlers.rs:493`) **and** retroactively drops every deposit sharing this finding's `(threat_class, event_id)` at or before the marker from the concentration sum (`substrate.rs:1286`, predicate at `:1367-1380`, key at `:1412-1421`). | Hide the row. It changes the math, across detectors you did not review. |
| **Investigate** | `I` | finding row | Writes a reviewed measurement with `false_positive: false` and keeps the finding open. | Create an `InvestigationBundle`. |
| **Promote to a case** | `E` | watch, lane, finding, hold | Creates the private TTL channel, seeds the canvas, and mints the incident record a verdict needs (`03` §4.3, bill item B3i). One meaning, always (`04` §3.0). | Route the item to another operator — no operator directory exists. Change any Ambush state beyond the incident record. |
| **Snooze** | `S` | finding, case row | Removes the row until a chosen time, then returns it to "Waiting on you". | Suppress the underlying deposits, or extend a hold — see the disabled-state copy in §5.5. |
| **Release** | — | containments | Asks the daemon to run the inverse and close the containment lease. | Guarantee the containment ended. Read `lease_closed`. |
| **Escalate** (the *action*, not a key) | — | rendered on receipts | The typed `Escalate { summary, urgency }` response action — the one whose entire blast radius is `OperatorEscalationOnly`. Perch renders it; no Perch control emits it. | Page anyone by itself; see §5.7. |
| **End watch** | — | handoff | Composes a `ReviewSession` from everything touched and hands over three read frontiers. | Close anything. |

**One limit that belongs in this table rather than in a footnote.** The shipped analyst
feedback path is incident-scoped: `providence_feedback_handler` loads the incident by
`request.incident_id` and returns not-found if there is none
(`crates/swarm-ingest-runtime/src/ingest/providence_handlers.rs:130-139`), and
`build_alert_tuning_report` takes `&[IncidentRecord]`
(`crates/swarm-runtime/src/alert_tuning.rs:84`), because the measurement is upserted onto
an incident (`:170-176`). So a verdict on a finding that has never been correlated has
nowhere to land today. The copy consequence is one string, and it must not be omitted:

```ts
uncorrelatedFinding:
  "This finding is not part of a correlated incident. Confirm, Dismiss and Investigate " +
  "write a FalsePositiveMeasurement onto an incident record, and this finding has none " +
  "yet. Promote it to a case first, or record the verdict on the incident once Weaver " +
  "correlates it.",
```

Whether the new `POST /v1/operator/findings/{id}/feedback` synthesizes an incident record
or refuses is 03-DOMAIN-EVENT-MAPPING.md §11's call. Either way one of these two strings
ships, and the second one is written here so the choice is visible:

```ts
uncorrelatedFindingSynthesized:
  "Recorded. This finding was not correlated, so the verdict was attached to a " +
  "single-member incident record created for it. It counts toward the reviewed " +
  "denominator on /tuning like any other.",
```

---

## 5. The microcopy library

Paste-ready. `{braces}` are interpolations. Strings are exact, including punctuation.

### 5.1 Navigation and chrome

```ts
// desktop/src/shared/copy/nav.ts
export const NAV = {
  watch:        "The Watch",
  lanes:        "Lanes",
  cases:        "Cases",
  containments: "Containments",
  policy:       "Policy",
  watchfloor:   "Watchfloor",
  ledger:       "Ledger",
  tuning:       "Tuning",
  handoff:      "End watch",
  gaps:         "Gaps",
  settings:     "Settings",
} as const;

// The four groupings inside The Watch. Buzz's type is still FeedItemCategory;
// only the operator-facing word changes, because "lane" is spent (§2.4).
export const QUEUE_LABELS = {          // needs_action | mention | activity | agent_activity
  needs_action:   "Waiting on you",
  mention:        "Named you",
  activity:       "Your cases",
  agent_activity: "Swarm",
} as const;
```

The governance strip (persistent chrome, four values,
`crates/swarm-policy/src/governance.rs:49-54`):

```ts
export const GOVERNANCE_STRIP = {
  healthy:     { label: "Governance healthy",     detail: "committee of 1 (solo transport)" },
  degraded:    { label: "Governance degraded",    detail: "quorum available, one or more governors unhealthy" },
  partitioned: { label: "Governance partitioned", detail: "destructive response fails closed unless a staged contingency lease authorizes the exact action" },
  healing:     { label: "Governance healing",     detail: "quorum is back; partition-era activity is still being reconciled" },
} as const;
```

`healing` deliberately does not say "recovered". `docs/CONSENSUS.md:237` requires the
reconciliation output to be reviewed *before the incident is treated as closed* — the
detail line says so.

**The C9 counters have one home and it is The Watch.** The three instrumentation numbers
the brief makes the thesis's own falsification instrument live in the header of queue 1 on
`/`, because `/` is the only Phase-1 surface. `/tuning`, `/handoff` and the Watchfloor
restate them read-only and link back; they do not own them.

```ts
export const INSTRUMENTATION = {
  strip: "{medianSeconds}s median page-to-verdict · {measurements} measurements written this week · {fraction} of this week's recommendations came from this week's verdicts",
  stripEmpty: "No verdicts recorded yet this week. These three numbers are how we find out whether the loop is real.",
  promotedSuppressed: "{promoted} promoted / {suppressed} did not clear the bar",
  restated: "Measured on The Watch.",
} as const;
```

### 5.2 Empty states

Buzz's shape is icon + title + one-sentence description
(`desktop/src/features/home/ui/InboxDetailPane.tsx:441-447`). Perch keeps the shape and
replaces the reassurance with a fact and a link.

```ts
// desktop/src/features/watch/copy.ts
export const EMPTY = {
  // Per 04 §2.12 this is NOT a /gaps state: an empty hold queue is a gate question, not a
  // coverage question. It names what ran without being held instead.
  watchNeedsAction: {
    title: "Nothing is waiting on you",
    body: "No held actions, no due snoozes. {n} destructive actions ran in this window without a hold — below human_gate_severity, or matched by an allow rule.",
    action: { label: "See which rule decided", href: "/policy" },
  },
  // This one IS a /gaps state: the swarm produced nothing.
  watchNoFindings: {
    title: "No findings this shift",
    body: "{n} techniques across {d} detectors are declared uncovered — a quiet queue is partly a statement about coverage.",
    action: { label: "See declared gaps", href: "/gaps" },
  },
  watchAll: {
    title: "The watch is clear",
    body: "Last deposit landed {relative}. Mode is {mode}. Nothing here means nothing crossed a threshold, not that nothing happened.",
    action: { label: "Open the Watchfloor", href: "/watch-floor" },
  },
  laneQuiet: {
    title: "No live deposits in {threatClass}",
    body: "Concentration is {strength} against an alert threshold of {alertThreshold}, from {sources} sources / {agents} agents. Deposits decay on a {halfLife}s half-life, so this can go quiet without anything being resolved.",
    action: { label: "See what this lane cannot see", href: "/gaps?threat_class={threatClass}" },
  },
  containmentsNone: {
    title: "No open containments",
    body: "Nothing is currently isolated, quarantined or suspended. Expired containment leases are released by the sweep and appear in the Ledger.",
    action: { label: "Search released containments", href: "/ledger?q=ambush:lease" },
  },
  casesNone: {
    title: "No open cases",
    body: "A case opens when a destructive action is held, when a correlated incident includes 2 or more members, or when you promote a finding by hand. {suppressed} findings did not clear that bar this shift.",
    action: { label: "Review the promotion bar", href: "/settings#case-promotion" },
  },
  tuningNone: {
    title: "No recommendations yet",
    body: "A detector-rule review needs 3 reviewed findings and 2 false positives on one detector; a threshold review needs 4 and 2; a host exclusion needs 2 and 2 on one host. You have recorded {actual} reviewed, {fp} false positive. Confirm, Dismiss and Investigate all count toward the denominator; only Dismiss counts as a false positive.",
    action: { label: "Open the watch", href: "/" },
  },
  ledgerNoResults: {
    title: "No matches for {query}",
    body: "The Ledger searches finding, escalation, hold, receipt, containment-lease and rollback cards, plus case canvases and human verdicts. Fields inside a card body — strategy_id, host_id, receipt_id — are full-text only and cannot be filtered as operators.",
    action: { label: "Query syntax", href: "/settings#ledger-syntax" },
  },
  policyNoRules: {
    title: "policy.rules is empty",
    body: "Every request falls through to the static gate, which asks a human for any destructive action at {humanGateSeverity} or above.",
  },
} as const;
```

The `tuningNone` numbers are the shipped constants, not placeholders:
`DETECTOR_RULE_MIN_REVIEWED = 3` / `MIN_FALSE_POSITIVE = 2` / `MIN_RATE = 0.34`,
`DETECTOR_THRESHOLD_* = 4 / 2 / 0.50`, `HOST_EXCLUSION_* = 2 / 2 / 0.75`
(`crates/swarm-runtime/src/alert_tuning.rs:6-15`). An operator who has recorded two
verdicts should be able to read how many more are needed and for which recommendation
kind, not "not enough data".

With the shipped ruleset the pheromone interpolations read: `default_half_life_secs: 3600.0`,
`alert_threshold: 2.0`, `evaporation_threshold: 0.01`, `min_sources_for_escalation: 2`
(`rulesets/default.yaml:55-58`). So `laneQuiet` renders as *"Concentration is 0.34 against
an alert threshold of 2.0, from 1 source / 1 agent…"* — a sentence that tells an operator
how far from escalation the lane actually is, and on which of the two axes, which a bare
"no activity" never does.

Two special zeros, each of which is correct and must not read as a fault:

```ts
export const CORRECT_ZEROS = {
  promotions: {
    title: "0 promotions",
    body: "Correct by design. The shipped ruleset carries no custom_z3 invariant, so the solver status is null and the production gate refuses every candidate. A stub is not a proof.",
  },
  concentrationZero: {
    title: "Concentration 0.00",
    body: "Every deposit in this class has decayed below the evaporation floor of {evaporationThreshold}. Nothing was deleted; strength approached zero.",
  },
} as const;
```

### 5.3 Loading and degraded states

```ts
export const LOADING = {
  watch:        "Loading the watch…",
  case:         "Loading case {caseId}…",
  deposits:     "Reading the trails…",
  verdictPane:  "Loading the held action…",
  ledger:       "Searching…",
} as const;

export const DEGRADED = {
  relayReconnecting: {
    label: "Reconnecting to the relay",
    body:  "Live evidence is paused. Held actions are still held — the daemon does not depend on this connection.",
  },
  daemonUnreachable: {
    label: "Daemon unreachable",
    body:  "Perch cannot reach swarm_detect at {daemonUrl}. You can read history; you cannot record a decision or release a containment. An open containment lease's own TTL is the only backstop while this lasts.",
  },
  bridgeGap: {
    label: "Gap in the evidence stream",
    body:  "Sequence {expected} did not arrive; the next envelope was {received}. {n} events are missing from this view. This is a gap in what Perch received, not a gap in what the daemon recorded.",
    action: { label: "Reconcile against the daemon", href: "/ledger?verify={caseId}" },
  },
  telemetryStale: {
    label: "Telemetry stale",
    body:  "No concentration snapshot for {seconds}s. Curves below are the last received values, not current ones.",
  },
  derivedDisagrees: {
    label: "Client curve disagrees with the runtime",
    body:  "Perch computed {clientValue} from {n} deposits; the runtime's snapshot says {serverValue}. The runtime is authoritative. Likely cause: {reason}.",
  },
} as const;
```

`bridgeGap` is the copy that mechanizes the brief's first risk. Its second sentence is
the whole point: the relay is not the record.

### 5.4 Errors, by class

Six classes. Each has a fixed shape: **what failed · what is still true · what to do.**

```ts
export const ERRORS = {
  // 1. Auth — the daemon's own strings are already precise; surface them, prefixed.
  auth401: "Daemon rejected the token: {daemonMessage}. Perch reads and writes nothing to Ambush without it. Update it in Settings → Daemon.",
  auth403: "Your operator token does not carry the {scope} scope. This refusal is real and narrow: it applies to this write only. Read access is not enforced on any /v1/operator/* handler — see Settings → Operator scopes.",
  schemaVersion: "Daemon speaks operator API schema {found}; Perch expects {expected}. Nothing was sent. Upgrade whichever is older.",

  // 2. Write conflict
  holdAlreadyDecided: "This hold was already decided by {operatorId} at {time} — {decision}. Your decision was not recorded. Reload to see theirs.",
  leaseAlreadyClosed: "Containment {leaseId} was already released at {time}. Releasing twice would write two rollback receipts for one containment lease and break the audit trail, so this was refused.",

  // 3. Policy / governance refusals — NOT errors in the failure sense.
  vetoed: "Vetoed by Tom · governance. Reason: {reason}",
  deniedByRule: "Denied by policy rule `{ruleName}`. Reason: {reason}",
  deniedPartitioned: "Governance is partitioned and no staged contingency lease authorizes {actionKind} on this scope. Destructive response fails closed here by design.",
  deniedNoGovernor: "No governor key is registered, so no receipt can be minted, so this action cannot execute. Detection is unaffected.",
  refusedLate: "The daemon re-evaluated after you recorded your decision and refused it: {reason}. Your decision is recorded; nothing dispatched. This is the gate working, not a client error.",

  // 4. Transport
  daemonTimeout: "No response from the daemon in {ms}ms. Perch does not know whether the decision was recorded. Reload the hold before deciding again — deciding twice is refused, but reading first is safer.",
  relayPublishFailed: "Could not publish your signed intent record to the relay ({reason}). The daemon was not contacted; nothing was decided.",

  // 5. Input
  reasonRequired: "A reason is required and cannot be whitespace. Every maintenance request is audit-recorded with its reason, including the ones that get blocked.",
  ledgerBadOperator: "`{token}` is not a search operator. Perch supports from:, in:, after:, before:. Everything else is full text.",

  // 6. Integrity — these are loud on purpose.
  attestationMismatch: "The governance attestation on receipt {receiptId} does not match its body. Do not treat this receipt as evidence. Re-read it from the daemon and compare.",
  chainBreak: "Envelope chain broken for issuer {issuer}: expected prev {expected}, found {found}. This view is not a complete record of that issuer's activity.",
} as const;
```

Three deliberate choices here. Class 3 is not styled as an error — a veto is the product
working, and painting it red teaches operators that governance is a malfunction; and
`refusedLate` is in class 3 rather than class 4 for the same reason. The `daemonTimeout`
string admits it does not know, rather than guessing. And `auth403` volunteers the
enforcement gap rather than letting an operator infer a read-only role that does not
exist — the precise version is in §5.9.

### 5.5 The verdict pane — this copy is a safety control

Five fields, **fixed order, identical for all twelve destructive actions**, never
reordered by severity or action type. At 02:41 an operator reads by position.

```
ACTION              {typed variant, mono} — {plain sentence}
BLAST RADIUS        {impact} · {scope_kind} {scope_value} · up to {max_affected_scopes} scope(s)
IF YOU UNDO         {one of four verdicts, below}
WHY WE ARE ASKING   {named rule, or the static-gate sentence}
WHAT GRANTING OPENS capability lease · {action_kind} · scope {scope} · {ttl}s
```

**ACTION.** The typed variant in mono, then one sentence with the real target. Every
`{braced}` value in this table originates in telemetry and renders through
`<AdversaryString>` (§7.3) — `scope_for_response_action`
(`crates/swarm-policy/src/static_gate.rs:231-263`) builds the scope from `host_id`,
`file_path`, `domain`, `credential_id`, `user_id`, `process_name` and `task_name`, and an
attacker wrote all seven.

| Action kind | Sentence |
|---|---|
| `block_egress` | Block all network egress to `{target}`. |
| `isolate_host` | Cut `{host_id}` off from the network. |
| `revoke_credential` | Revoke credential `{credential_id}`. |
| `sinkhole_dns` | Redirect `{domain}` to the defensive sinkhole. |
| `terminate_user_session` | End session `{session_id}` on `{host_id}`. |
| `inject_firewall_rule` | Add firewall rule `{rule_name}` on `{host_id}`: {direction} {cidr}{port}. |
| `quarantine_file` | Quarantine `{file_path}` on `{host_id}`. |
| `kill_process` | Terminate `{process_name}` on `{host_id}`. |
| `suspend_process` | Suspend `{process_name}` on `{host_id}`. |
| `disable_user_account` | Disable account `{user_id}`. |
| `force_password_reset` | Force a password reset for `{user_id}`. |
| `remove_scheduled_task` | Remove scheduled task `{task_name}` on `{host_id}`. |

**IF YOU UNDO.** Four verdicts, resolved from `resolve_inverse`
(`crates/swarm-response/src/rollback.rs:151-192`). Only three actions have an executable
inverse, and the mapping is not guessable — `SuspendProcess` is reversible and
`KillProcess` is not.

| Verdict | When | String |
|---|---|---|
| Executable inverse | `quarantine_file`, `suspend_process`, `isolate_host` | `Reversible — {inverse_kind} on {target}. Release runs it and the receipt reports whether it worked.` |
| Irreversible, with a written reason | `terminate_user_session` | `Irreversible — {reason verbatim}` → *"a terminated session cannot be resumed; the principal can only establish a fresh session"* |
| Unmapped | the other eight | `No executable inverse — no inverse operation is defined for step {step} of {action_kind}; the containment stays in effect. Undoing this is a manual operation on your side.` |
| Simulated only | rehearsal, no real target touched | `Rehearsed only — no real target was touched, so nothing has been reversed and nothing needs to be.` |

Note the second row: Ambush already wrote that sentence, in Rust, at
`rollback.rs:186-188`, and the arm exists precisely to say so on the receipt
("Re-permitting login is not the inverse of ending a session"). Perch prints it verbatim.
Any paraphrase drifts from the receipt.

**WHY WE ARE ASKING.** Two shapes only, and the distinction is load-bearing because an
`allow` rule silently outranks the human gate:

```ts
byRule:      "Rule `{ruleName}` matched first and its decision is {decision}. Reason: {reason}",
byStaticGate:"No policy rule matched. The static gate asks a human for any destructive action at {humanGateSeverity} or above. This finding is {severity}.",
```

**WHAT GRANTING OPENS.**

```ts
grantOpens: "capability lease · {actionKind} · scope {scope} · {ttlSeconds}s",
grantOpensNote: "Minted when you decide, not when the hold opened. It expires {ttlSeconds}s after your decision whether or not the action has dispatched.",
```

**The controls, and the keys.**

```ts
export const VERDICT_CONTROLS = {
  // Held action. G and R. There is no `A`, and the ban list enforces that (§7.2).
  grant: {
    label: "Record my decision and send it to the daemon",
    hint:  "Perch does not authorize. The daemon re-evaluates policy and governance from scratch before anything dispatches.",
    key:   "G",
  },
  refuse: {
    label: "Refuse",
    hint:  "Recorded as a signed refusal in this case, and posted to the daemon. Nothing dispatches.",
    key:   "R",
  },
  promote: { label: "Promote to a case", hint: "Opens a case channel and the incident record a verdict needs. Does not route this to anyone — there is no operator directory.", key: "E" },
  snooze: {
    label: "Snooze",
    hint:  "Returns to “Waiting on you” at the time you pick.",
    key:   "S",
    disabledOnHold: "A held action cannot be snoozed. It expires on its own in {remaining} and nothing runs. Refuse it (R) if you do not want it to run.",
  },
} as const;

export const FINDING_CONTROLS = {
  confirm:     { label: "Confirm",     hint: "Records a reviewed finding that was real. Raises the reviewed denominator on /tuning.", key: "C" },
  dismiss:     { label: "Dismiss",     hint: "Records a false positive and suppresses deposits. Read the dialog.", key: "D" },
  investigate: { label: "Investigate", hint: "Reviewed, not resolved. Keeps the finding open.", key: "I" },
} as const;
```

Three things about this block are load-bearing.

*The grant label is a sentence and the refusal is one word.* That asymmetry is
deliberate, and it is not the friction asymmetry (which is about dialogs, not words). The
long label exists to prevent a *claim* the architecture cannot back: `POST /v1/operator/…`
is the only authorization path and Perch is on the wrong side of a process boundary from
it. Refusing claims nothing, so it needs no disclaimer.

*`A` is not a key here and must never become one.* The map is `C`/`D`/`I` for findings and
`G`/`R` for holds, per 04-SURFACES-AND-UX.md §3.0. Holds and findings interleave in the
same queues and the same detail pane, so a shared `D` would mean "refuse a destructive
action" on one row and "retroactively delete deposits from the concentration sum" on the
row below it. `A` for "approve" is additionally the word render law 6 forbids; banning
the label while binding the key is a distinction no operator's muscle memory respects.
The ban list in §7.2 greps for both.

*The snooze disabled string is not decoration.* Snooze is disabled on **every** hold, and the
reason is `08` §3.5's safety argument rather than arithmetic: a hold is a live gate with its own
clock, the queue *is* the reminder, and a snoozed hold that expires while hidden is a fail-closed
action nobody chose. With `hold_ttl_ms` settled at 3_600_000 (60 minutes, `08` §3.6) Buzz's
shortest preset — "In 30 minutes" (`desktop/src/features/reminders/lib/timePresets.ts:31-44`) —
no longer outlives every hold, so the disabled string must name the *rule*, not the clock. Snooze
remains live on findings and case rows.

**The dismiss confirmation** — the only place Perch interrupts a non-destructive verb,
because Dismiss rewrites the concentration sum, and it does so on a wider key than it
looks:

```
Title:   Dismiss this finding and suppress {n} deposits?
Body:    Dismissing records false_positive: true and drops every deposit that carries this
         finding's telemetry event id {eventId} in threat class {threatClass}, from every
         detector, with a timestamp at or before this marker — {n} deposits, {sources}
         sources / {agents} agents. Concentration for {threatClass} goes {before} → {after}
         against an alert threshold of {alertThreshold}.
         Suppression is keyed on (threat class, event id), not on the detector, so
         detectors you have not reviewed are suppressed too.
         This appears as an explicit suppression row on the lane timeline.
Confirm: Dismiss and suppress
Cancel:  Cancel
```

The key is `FeedbackSuppressionKey { threat_class, event_id }`
(`crates/swarm-pheromone/src/substrate.rs:345-348`, built at `:1412-1421` from
`deposit.indicator["event_id"]`), and the predicate suppresses when the marker's state is
`Dismiss` and its timestamp is `>=` the deposit's (`:1367-1380`). Since
`findings_to_deposits` copies `finding.event_id` into every deposit's indicator
(`crates/swarm-whisker/src/stream.rs:35-37`), one Dismiss reaches every detector that
fired on that telemetry event. An earlier draft of this document said the key was
`(strategy_id, host_id)` and understated the blast radius; the corrected string is above,
and §8.3 records the correction.

### 5.6 Veto, containment expiry, and rollback

```ts
export const CONTAINMENT = {
  open:        "Open · {remaining} remaining",
  expiringSoon:"Open · {remaining} remaining · releases automatically",
  expired:     "EXPIRED — {host} may still be contained",
  expiredBody: "This containment lease passed its expiry {ago} ago and is still listed as open. remaining_ms saturates at zero, so “0s” and “expired” are two separate facts and this is the second one. The sweep should have released it.",

  releaseConfirmTitle: "Release containment on {host}?",
  releaseConfirmBody:  "The daemon runs {inverseKind} against {target} and co-signs the release on the governance chain. If the inverse fails, the containment lease stays open and the response reports lease_closed: false.",
  releaseConfirmCta:   "Ask the daemon to release",

  releasedClosed:      "Released. lease_closed: true · fully_reversed: {fullyReversed}",
  releasedNotClosed:   "NOT RELEASED. The daemon returned 200 but lease_closed: false — the inverse failed and the containment is still in effect. The next sweep will retry.",
  releasedUnattested:  "Released, UNATTESTED. No governor was available to co-sign. The release proceeded because refusing to undo a containment over a bookkeeping failure inverts the safety argument. The receipt says so plainly.",
  daemonDownRelease:   "Release is only available against a running daemon. With the daemon stopped, the containment lease’s own TTL is the backstop.",
} as const;

export const ROLLBACK_STATUS = {                      // five variants, rendered as five
  reversed:     { label: "Reversed",     body: "The inverse ran against the real target and succeeded." },
  simulated:    { label: "Simulated",    body: "The inverse was rehearsed. No real target was touched, so nothing was restored." },
  irreversible: { label: "Irreversible", body: "No inverse exists for this step. The world was not restored and no adapter can restore it." },
  unsupported:  { label: "Unsupported",  body: "The configured adapter cannot execute this inverse." },
  failed:       { label: "Failed",       body: "The inverse was attempted against a real target and failed." },
} as const;

export const ROLLBACK_SUMMARY = {
  fullyReversed:    "Fully reversed — every step reported Reversed.",
  notFullyReversed: "Not fully reversed. {n} of {total} steps: {breakdown}. fully_reversed() requires every step to be Reversed; Simulated and Irreversible do not count.",
} as const;

export const VETO = {
  banner: "Vetoed by Tom · governance",
  body:   "{reason}",
  note:   "A veto is the gate working. The action was never dispatched and no containment was opened.",
} as const;
```

`releasedUnattested` and `releasedNotClosed` are both lifted from ADR 0010's own prose
(`docs/decisions/0010-…:181-189`), which already says a release without a governor
proceeds and *"the receipt says plainly which it was"*, and that
`lease_closed: false` exists **"so a 200 cannot read as 'released'"**.
`ROLLBACK_STATUS` preserves all five variants rather than collapsing to success/failure,
and `fully_reversed()` is *"deliberately stricter than 'nothing errored'"* in its own doc
comment (`crates/swarm-response/src/rollback.rs:288-296`) — copy that reads "rollback
succeeded" off a non-error contradicts the type.

`CONTAINMENT.expiredBody` and `daemonDownRelease` now say **containment lease** in full.
They previously said bare "lease" — strings the §7.2 ban would have failed. That is the
correction the scoping rule exists to make visible rather than to excuse.

### 5.7 Notifications and paging

Exactly four classes may wake someone. The brief settles the list; this settles the
strings, and the strings are written to survive being read on a lock screen with no
context.

**The binding rule: a wake-class body is composed of typed values only.** No `{target}`,
no `{host}`, no `{file_path}`, no `{process_name}`, no `{summary}`, no free text of any
kind. The reason is specific, not general caution: OS notification bodies are rendered
outside React, outside `<AdversaryString>`, and outside every CI guard §7.3 proposes;
macOS honours newlines in them; and every one of the seven fields
`scope_for_response_action` can put in a scope
(`crates/swarm-policy/src/static_gate.rs:231-263`) originates in `ProcessStartEvent`,
CloudTrail or K8s telemetry an attacker wrote. A quarantine on a path containing
`\n\nGranted by Tom · safe` would land verbatim on a lock screen at 03:00. Buzz's
`truncateNotificationBody` (`desktop/src/features/notifications/lib/notificationFormat.ts:26-33`)
caps at 140 characters but strips no newline and no bidi codepoint, so inheriting it is
not the control. Typed-only is the control.

| Class | Title | Body | Every field typed |
|---|---|---|---|
| Held destructive action naming you | `Ambush · action held for you` | `{actionKind} · {severity} · {threatClass} · expires in {relative} · hold {holdIdShort}` | `ResponseAction` kind literal, `Severity` enum, threat-class slug, relative time, opaque 8-char id |
| Mode transition to Incident | `Ambush · mode is now Incident` | `{threatClass} · {n} sources / {m} agents · strength {strength} over {incidentThreshold}` | slug, two integers, two floats |
| Containment failed to release | `Ambush · containment did not release` | `lease_closed: false · {inverseKind} {rollbackStatus} · containment {leaseIdShort}` | `ContainmentInverse` kind, `RollbackStepStatus` variant, opaque 8-char id |
| Due snooze | `Ambush · snoozed item is back` | `{cardKind} in {perchLabel} · snoozed {relative} ago` | marker slug, Perch-generated case/lane label, relative time |

`{perchLabel}` is Perch's own string — `Case 0042 · credential_access` or a threat-class
lane name — never a name derived from telemetry.

Rules that go in the code review checklist:

- The **3am push never contains a verb the operator can act on from the notification.**
  There is no "Approve" and no "Grant" action on the push. Tapping opens the verdict row.
- The mode-transition push carries the source/agent split, because that is the one number
  most likely to change the reader's mind about getting out of bed.
- **A quiet night is not notified.** There is no "all clear" push, ever.
- The refusal string for the inevitable fifth class, kept where reviewers can find it:
  *"Four classes may wake someone. Adding a fifth means removing one — which one?"*
- The notification copy module is the one place `<AdversaryString>` cannot reach, so it
  gets its own CI check (§7.2, `check-perch-notification-fields.sh`) that fails on any
  interpolation not on the typed-field allowlist.

### 5.8 Onboarding and first run

```
Screen 1 — What Perch is
  Title: Perch is where you decide.
  Body:  Ambush computes what it saw and what it was allowed to do. It cannot compute
         whether an alert was real. That is the only thing it needs from you, and this
         is where you give it.
  Cta:   Connect a colony

Screen 2 — Connect
  Title: Point Perch at a colony.
  Body:  Perch reads from a relay and writes decisions to the daemon. Two addresses,
         two credentials. Neither one lets Perch change Ambush state on its own.
  Field: Relay URL          placeholder "wss://relay.internal.example"
  Field: Daemon URL         placeholder "https://127.0.0.1:9090"
  Field: Operator token     help "Stored in the OS keyring. Never held in the webview."
  Note:  Both must sit inside your network boundary. The relay carries evidence and is
         not built to face the internet.

Screen 3 — What Perch cannot do
  Title: Three things Perch will never do.
  Body:  • It never authorizes. It records your decision and sends it; the daemon
           re-evaluates policy and governance from scratch.
         • It never writes to an Ambush store. swarm_detect --serve is the only writer.
         • It never edits rulesets. Those are a signed, sha256-pinned bundle.
  Cta:   Understood

Screen 4 — First watch
  Title: You are on watch.
  Body:  Four queues. Waiting on you is the only one with a deadline. When you finish,
         End watch composes the handoff.
  Cta:   Open the watch
```

Screen 3 is not a legal disclaimer; it is the product's actual differentiator stated
before anything else, in the same voice as the README's own boundaries section.

**Not-yet-wired banner** (the brief's fallback if the daemon-side hold store slips):

```
Label: Verdict queue not yet wired
Body:  The hold store is not live in this build. Nothing here is a real held action, and
       recording a decision does nothing. Watchfloor, Ledger and Gaps read live data.
```

### 5.9 Settings and config validation

```ts
export const SETTINGS = {
  scopesTitle: "Operator scopes",
  scopesBody:  "Ambush defines four scopes: read, rehearse, approve, maintenance. Three of them are enforced on the daemon's operator API: maintenance (containment release, control routes), approve (the approval ledger) and rehearse (review). `read` is enforced on the /v2/api platform surface and on no /v1/operator/* handler, so any valid token reads everything here. Perch does not hide surfaces based on scope, because that would imply an enforcement that does not exist.",

  platformApiTitle: "The /v2/api platform surface",
  platformApiBody:  "Ambush also ships a read-only /v2/api surface and a generated Python client. Perch does not use it and does not poll it. If you have automation on that client, it keeps working; Perch is not a replacement for it and does not change it.",

  substrateTitle: "Substrate",
  substrateBody:  "backend.kind = {kind}. in_memory does not survive a restart, and the runtime refuses to enable live response on a substrate that cannot.",

  rulesetTitle: "Ruleset",
  rulesetBody:  "{path} · sha256 {hash} · pinned by a signed attestation. Perch is read-only here. Editing the curated bundle changes its hash and startup verification will reject it.",

  daemonTokenTitle: "Daemon token",
  daemonTokenBody:  "Held in the OS keyring and injected by the native layer. It is never present in the webview. Rotating it requires restarting the daemon, because startup fails on a missing token env var.",

  costsTitle: "What this console costs you",
  costsBody:  "Perch adds a Postgres, a Redis and a relay to a product that otherwise ships two containers and a data directory. That relay carries evidence and must sit inside your network boundary.",
} as const;

export const CONFIG_ERRORS = {
  relayUnreachable: "Cannot reach {url}. Perch cannot show evidence without it; held actions are unaffected.",
  relayNotAmbush:   "{url} answered, but it is not carrying an Ambush colony — no ambush:finding:v1 cards in the last {n} events. Check you have the right relay.",
  daemonMismatch:   "The relay says colony `{relayColony}`; the daemon says `{daemonColony}`. Perch will not join two colonies in one window.",
  tokenNoScopes:    "This token carries no scopes. It will still read everything — see Operator scopes above — but every write will be refused.",
  urlNotWss:        "Use wss://. Perch refuses ws:// for a relay carrying finding and receipt evidence.",
} as const;
```

The scopes string is now precise rather than merely alarming.
`require_operator_api_scope` and `require_operator_review_scope`
(`crates/swarm-runtime-http/src/http/auth.rs:154-180`) are called with `Maintenance`
(`containment.rs:197`, `control.rs:82,117,154`, `maintenance.rs:28`), `Approve`
(`approval.rs:73,137`) and `Rehearse` (`review.rs:166`) — and never with `Read`.
`OperatorScope::Read` is checked in exactly one runtime place,
`crates/swarm-ingest-runtime/src/ingest/platform_api.rs:974`, which is the `/v2/api`
surface, plus a config-load assertion that at least one principal has it
(`crates/swarm-core/src/config/validation.rs:716`). Saying "read is enforced nowhere"
would have been wrong in a way a reviewer inherits, which is why `platformApiBody` exists
next to it.

`urlNotWss` is a deliberate hard refusal with copy that names the reason, rather than a
warning the operator learns to click through.

### 5.10 Evidence, signatures, and export

This section changed the most in the red-team pass, because the claim it previously
carried — "the Ed25519 signature is the record and is what verification runs against" —
is true of one card type and false of four.

**What is actually signed, per card type.** Read this table before writing any badge.

| Card | Marker | Signature on the artifact itself | Verifiable by whom |
|---|---|---|---|
| Finding | `ambush:finding:v1` | **None.** `DetectionFinding` has seven fields and no signature (`crates/swarm-whisker/src/detector.rs:50-59`); `SwarmFindingEnvelope` has eight and none (`crates/swarm-response/src/siem.rs:17-27`). | Nobody. Re-read it from the daemon. |
| Escalation | `ambush:escalation:v1` | **None.** `EscalationRecord` (`crates/swarm-core/src/pheromone.rs:238-…`) carries no signature. | Nobody. Re-read it from the daemon. |
| Hold | `ambush:hold:v1` | **None** — the hold store does not exist yet, and nothing before bill item `B6` (`09` §3.1) signs its record. | Nobody. Re-read it from the daemon. |
| Response receipt | `ambush:receipt:v1` | **None on the receipt.** `ResponseReceipt` has no signature (`crates/swarm-response/src/lib.rs:99-116`); its `audit.governance.receipt` is an untyped `Option<serde_json::Value>` (`:135-142`) that *may* hold a signed `ConsensusGovernanceReceipt`. | The embedded governance receipt, if present, verifies. The response receipt around it does not. |
| Containment lease | `ambush:lease:v1` | **None.** | Nobody. |
| Rollback / release receipt | `ambush:rollback:v1` | **The receipt has no signature of its own**, but it carries `governance_attestation: Option<Value>` — a serialized `ConsensusGovernanceReceipt` over this receipt's canonical form with the field cleared (`crates/swarm-response/src/rollback.rs:264-286`). | Verifiable: `verify_release_attestation`, surfaced as `attestation_verified` / `attestation_error` on the release response (`crates/swarm-runtime-http/src/http/containment.rs:140-145, 219`). |
| Pheromone deposit | not published (03 §4.1) | **Ed25519, verified on ingest** (`crates/swarm-core/src/pheromone.rs:231-232`; verification and `agent_id` derivation check at `crates/swarm-pheromone/src/substrate.rs:210-250`). | The substrate, on every deposit. Perch never sees one individually. |

Two further facts, because the plan set has been treating a chain that mostly does not
run as if it did. `build_signed_envelope` (`crates/swarm-spine/src/envelope.rs:71`) has
exactly **one** non-test caller in the workspace — `crates/swarm-runtime/src/approval.rs:1810`,
the approval ledger — and `verify_chain_link` / `ChainLinkVerdict`
(`crates/swarm-spine/src/chain.rs:20,75`) have no consumers outside swarm-spine's own
module and its re-export at `lib.rs:61`. So there is no hash-linked Ed25519 chain over
findings, holds, or response receipts to verify against, and no copy may imply one.

**The strings.**

```ts
export const EVIDENCE = {
  // Governance attestation — the one badge that reports a real check.
  attestedTrue:  "Attestation matches this body",
  attestedTrueTip: "Checked: the governance receipt re-canonicalizes and its ed25519 signature verifies against the public key carried inside the receipt, and its proposal_id equals the hash of this body with the attestation cleared. NOT checked: whether that key belongs to a governor you trust. There is no trust anchor, and a full re-attestation would pass this check.",
  attestedNone:  "UNATTESTED",
  attestedNoneTip: "No governance attestation is present. That is not the same as “fine”.",
  attestedFalse: "ATTESTATION MISMATCH",

  // The four card types that carry no signature of their own. This is a fact, not a warning.
  unsignedCard: "No signature of its own",
  unsignedCardTip: "This card is a copy. {cardKind} carries no signature in Ambush today, so nothing here can be verified offline. The daemon holds the record; use “Verify against the daemon”.",
  bridgeSigned: "Bridge-signed transport · secp256k1 {npubShort}",
  bridgeSignedTip: "The Nostr envelope proves this card reached the relay from the bridge’s key and was not altered in transit. It says nothing about whether the daemon produced it.",

  // Sequence, not chain: the bridge's own per-issuer counter (07 §…), not a hash chain.
  seqOk:    "Sequence intact · issuer {issuer} · seq {seq}",
  seqGap:   "Sequence gap · expected {expected}, received {received} · {n} envelopes missing from this view",

  signedByEd25519: "Signed Ed25519 by {agentIdentity}",   // deposits and governance receipts ONLY; never truncated
  envelope:        "Nostr envelope signed secp256k1 by {npub}",
  bothChainsNote:  "Two keys, two jobs. The secp256k1 envelope is transport: it proves the bridge published this and nobody rewrote it on the way. Where an Ed25519 signature exists — a governance attestation, a pheromone deposit — it is the record, and verification runs against it. For everything else the daemon is the record and this card is a copy.",

  operatorAttribution: "Recorded by {operatorId} in Perch at {time}.",
  operatorAttributionTip: "Perch’s hold record and the signed ambush:verdict:v1 card on the relay name you. The daemon’s own receipt does not: ResponseReceiptAudit carries a policy verdict and a governing agent id and has no approver field (crates/swarm-response/src/lib.rs:120-142), and audit_authorize_and_execute_human_approved_instrumented takes no approver argument. Today the daemon’s record shows that a human was asked, not which one answered.",

  verifyLocalCta:  "Verify against the daemon",
  verifyLocalBody: "Re-reads this artifact from swarm_detect and compares it byte for byte with the copy on the relay. This is the only verification available for a finding, escalation, hold or response receipt.",

  exportCta:  "Export for the record",
  exportBody: "Writes the cards, their envelopes, and a DERIVED.json listing every value Perch computed rather than received. Governance attestations in the bundle can be re-verified; the other cards can only be compared against the daemon. There is no shipped offline verifier for a response receipt — `swarmctl evidence-verify --bundle-id` verifies evolution evidence bundles (crates/swarm-evolution/src/evidence.rs:1162, 1759), not these.",
} as const;
```

**Where the fix lands, and the one string that would change it.** The finding against this
document offered two ways out: make the chain real, or stop claiming it. This document
takes the second — the strings above are honest against the tree as it stands today, and
they ship whether or not the backend changes. But the first is one call at one site, the
same `build_signed_envelope` pattern `approval.rs:1810` already uses, and if
03-DOMAIN-EVENT-MAPPING.md §11 adds it as a sixth backend item, exactly one string flips:

```ts
// Only if the daemon wraps the fact in build_signed_envelope before it leaves.
signedFact: "Signed Ed25519 by the daemon · envelope seq {seq} · prev {prevShort}",
signedFactTip: "The daemon signed this fact and linked it to the previous one it issued. Verification re-canonicalizes the envelope and checks the signature and the prev hash locally, with no access to the runtime.",
```

Until that string is true, `unsignedCard` is what renders, and no badge on a finding,
escalation, hold or response receipt may use the words *signed*, *verified* or *proof*.
A lock-free glyph, no shield, no green check, and the tooltip is mandatory rather than
optional.

---

## 6. Copy anti-patterns, before → after

| # | Before (wrong) | After (ship this) | Why |
|---|---|---|---|
| 1 | "Everything looks good! ✅" | "The watch is clear. Last deposit landed 6m ago. Mode is Normal. 18 techniques across 11 detectors are declared uncovered." | A quiet queue is a coverage claim. `attack-technique-catalog.yaml` exists precisely so this can be said. |
| 2 | "Approve" | "Record my decision and send it to the daemon" | Perch is not an authorization path. The button must not claim otherwise. |
| 3 | "3 sources agree" | "3 sources / 1 agent" | `strategy_scoped_agent_id` makes ids strategy-scoped (`stream.rs:20-22`), so one Whisker with three detectors reads as three sources and defeats `min_sources_for_escalation`. |
| 4 | "✔ Verified by governor" | "Attestation matches this body" + the mandatory tooltip | There is no trust anchor. A shield is a lie with an icon. |
| 5 | "2 of 3 governors approved" | "committee of 1 (solo transport)" | `SoloGovernorTransport` refuses larger committees. A fraction is fiction. |
| 6 | "Undo" (uniform button) | Four distinct verdicts: Reversible / Irreversible / No executable inverse / Rehearsed only | Only 3 of 12 destructive actions have an executable inverse (`rollback.rs:151-192`). |
| 7 | "Rollback succeeded" | "Not fully reversed. 1 of 3 steps: Reversed 1, Irreversible 1, Unsupported 1." | `fully_reversed()` requires *every* step Reversed and is "deliberately stricter than 'nothing errored'" (`rollback.rs:288-296`). |
| 8 | "Released ✔" (from HTTP 200) | Read `lease_closed`; if false: "NOT RELEASED … still in effect." | ADR 0010:186-189 says the field exists so a 200 cannot read as released. |
| 9 | "0 promotions ⚠" | "0 promotions — correct by design. A stub is not a proof." | The shipped ruleset refuses every candidate deliberately (`EVOLUTION.md:161-187`). |
| 10 | "3 destructive actions require approval" | "12 destructive actions are human-gated and receipt-required. 3 of them have an executable inverse." | Both code lists enumerate twelve; `README.md:217-218` is stale. |
| 11 | 👍 / 👎 on a finding | Confirm / Dismiss / Investigate | These are typed verbs with different arithmetic; only Dismiss sets `false_positive: true`. |
| 12 | "Tom denied this" | "Vetoed by Tom · governance. Reason: {reason}" | "Tom" alone reads as a colleague; and *veto* is Tom's typed word, *deny* is policy's, *refuse* is yours (§4.1). |
| 13 | "Lease expires in 0s" | "EXPIRED — {host} may still be contained" | `remaining_ms` saturates at zero (`crates/swarm-response/src/containment.rs:275-277`); the list view carries `expired` as a second field for exactly this reason (`http/containment.rs:71-87`). |
| 14 | "Connection lost. Retrying…" | "Reconnecting to the relay. Live evidence is paused. Held actions are still held." | The operator's real question is whether the gate is still working. |
| 15 | "No data" | "Concentration 0.00 — every deposit decayed below the floor of {t}." | Zero has a mechanism and the mechanism is the interesting part. |
| 16 | "Are you sure?" | Five-field verdict pane, fixed order | A yes/no dialog before a destructive action is a speed bump, not a control. |
| 17 | "Incident #42" for the channel | "Case 0042" | `CorrelatedIncident` is a distinct artifact; two things must not be called incident. |
| 18 | "Search" | "Ledger" | It is the only surface in the product that can enumerate anything. |
| 19 | "Approved by you" on a receipt | "Recorded by {you} in Perch" + the attribution tooltip | The daemon's receipt names no approver (`swarm-response/src/lib.rs:120-142`). Perch may claim its own record; it may not claim the chain's. |
| 20 | `Ambush · quarantine /tmp/x on prod-db-01` (push body) | `Ambush · action held for you` / `quarantine_file · HIGH · defense_evasion · expires in 12m · hold 8f2a1c04` | Push bodies render outside every guard and honour newlines; `file_path` is attacker-written (§5.7). |
| 21 | "Dismiss this alert" | "Dismiss this finding and suppress {n} deposits?" with the arithmetic | Suppression is keyed on `(threat_class, event_id)` and reaches detectors you did not review (`substrate.rs:345-348, 1412-1421`). |
| 22 | "Signed and verified" on a finding card | "No signature of its own" + "Verify against the daemon" | `DetectionFinding` has no signature and there is no chain over it (§5.10). |

Anti-pattern 16 deserves the explicit note. Buzz's house dialog is *"Delete message?"* +
one sentence (`desktop/src/features/messages/ui/DeleteMessageConfirmDialog.tsx:33-36`),
and it is a good pattern for a message. Perch deliberately breaks it for held actions.
A confirmation dialog asks *are you sure*; the verdict pane answers *what happens, what
it touches, whether you can take it back, who decided to ask you, and what you are
handing out*. Those are not the same control and they must not look alike.

---

## 7. Where the strings live, and the guards that keep them honest

### 7.1 Layout

One `copy.ts` per feature under `desktop/src/features/<surface>/copy.ts`, exporting
`as const` objects; one `desktop/src/shared/copy/domain.ts` holding the glossary terms
(agent names + role words, the four governance states, the five rollback statuses, the
twelve action sentences, the four undo verdicts, the signature-provenance strings); and
one `desktop/src/features/notifications/copy.ts` that is the *only* module allowed to
produce an OS notification body. Rationale: the domain strings are the ones that must not
drift from Rust, and putting them in one file makes a single review diff catch the drift.
Feature strings stay local so a surface can be deleted cleanly — which matters, because
the surface list is closed at fourteen and adding one requires deleting one.

### 7.2 Ban list, enforced, and scoped

`tools/check-copy-banned-terms.sh` sits beside the existing gates and must land with a
real workflow `run:` step in the same PR (`tools/check-gates-wired.sh` fails on an
unwired check script). **Scope, stated so the guard survives contact:** it scans rendered
strings — the `label`, `title`, `body`, `hint`, `detail` and `tip` values in `copy.ts`
modules, plus JSX text nodes, `aria-label`, `title`, `placeholder` and `alt` — and it does
not scan identifiers, imports, type names, `href`/route/query values, code fences,
comments, or test fixtures. A guard that fails on `href="/ledger?q=ambush:lease"` gets
switched off in a week.

| Banned in rendered strings | Because | Use instead |
|---|---|---|
| `Approve` / `Approved` as a control label or heading | Perch does not authorize | "Record my decision…" |
| `key: "A"` / `"a"` bound to any verdict control | the key survives the label; §5.5 | `G` (grant), `R` (refuse) |
| `Deny` / `Denied` as an *operator* control label | policy's typed word, not the operator's | "Refuse" |
| bare `lease` in a label, heading, nav item or badge | two objects, one word (§2.2) | `capability lease` / `containment lease` |
| bare `lane` in a label or heading outside the twelve threat-class channels | four senses, one word (§2.4) | `queue` / `family` / `stream` |
| `verified by`, `trusted`, `proof`, shield or lock glyph beside an attestation | no trust anchor | "attestation matches this body" |
| `signed` / `verified` on a finding, escalation, hold or response receipt card | no signature exists on those (§5.10) | "No signature of its own" |
| `quorum` followed by `/` or a fraction | committee of one | "committee of 1 (solo transport)" |
| `sources` not immediately followed by `/ … agents` | strategy-scoped ids | "N sources / M agents" |
| `Everything looks good`, `All clear`, `You're all caught up` | off-brand and false | the §5.2 empty states |
| `hunt` as a nav item or heading | `HuntId` is an event id | "case" |
| `clowder` | dead term | "colony" |
| `Swarm Team Six` | legacy codename | "Ambush" |
| `!` in a rendered string longer than three characters | L3 | — |

A second, narrower guard — `check-perch-notification-fields.sh` — scans
`features/notifications/copy.ts` and fails on any interpolation whose name is not on the
typed-field allowlist (`actionKind`, `severity`, `threatClass`, `inverseKind`,
`rollbackStatus`, `cardKind`, `perchLabel`, `holdIdShort`, `leaseIdShort`, `relative`,
`n`, `m`, `strength`, `incidentThreshold`). §5.7 is the reason; that module is outside
every runtime guard the app has.

Two existing Buzz guards come along and are extended:
`check-pubkey-truncation.mjs` (extend to `swarm:ed25519:` identities, per the rationale in
`PubKey.tsx:17-31`) and `check-px-text.mjs` (needed because the hand-authored SVG
substrate view on `/watch-floor` will otherwise reintroduce px labels).

### 7.3 Adversary-controlled interpolation

Every `{token}` in §5.5's ACTION and BLAST RADIUS tables, and every `{host}`, `{target}`,
`{file_path}`, `{process_name}`, `{user_id}`, `{domain}`, `{task_name}`, `{session_id}`
and `{rule_name}` anywhere in this document, is attacker-written data reaching an
operator's screen. In-app they render through `<AdversaryString>` (08-TRUST-AND-GOVERNANCE-UX.md
§7.7). In an OS notification they do not render at all (§5.7). Those are the only two
dispositions; there is no third.

### 7.4 Citation discipline for every string that cites Rust

A string that quotes the code is a claim about behavior, and existence is not behavior.
Before a `path:line` citation ships beside a user-facing string, the copy must be able to
answer three questions, and where an answer is "nothing", "a different one", or "less than
that", the string says so in the same sentence:

1. **Who calls it?** `build_signed_envelope` exists and has one caller, which is why
   §5.10 no longer promises a chain.
2. **Which process is it in?** The 49 operator routes exist in `swarmctl serve`'s process,
   not the daemon's, which is why no Settings string promises Perch reads them.
3. **What does it do to the data?** `providence_feedback_handler` exists and requires an
   `incident_id`, which is why §4.2 ships an uncorrelated-finding string.

This pass applied that test to every citation in this document. Two failed and are
corrected in §8.3.

---

## 8. Cross-references and propagation

### 8.1 Owned elsewhere

- Field order, keyboard bindings and the layout of the verdict pane: **04-SURFACES-AND-UX.md**.
- Badge shape, severity colour, and the two badge families' visual treatment: **05-DESIGN-SYSTEM.md**.
- The wire markers (`ambush:finding:v1` …) whose human-fallback lines use the strings in
  §5.5, §5.6 and §5.10: **03-DOMAIN-EVENT-MAPPING.md**.
- Sequence gaps and the spool that produces `DEGRADED.bridgeGap`: **07-REALTIME-AND-DATA.md**.
- The trust argument the §5.10 strings encode, and `<AdversaryString>`: **08-TRUST-AND-GOVERNANCE-UX.md**.
- Fixing `README.md:217-218` and the "Swarm Team Six" rename as scoped work: **09-ROADMAP-AND-RISKS.md**.

### 8.2 Propagation this revision requires

These are vocabulary and copy changes this document owns, landing in files it does not.
They are listed so the cross-document pass is mechanical rather than archaeological.

| Change | Lands in |
|---|---|
| `A` → `G` on the grant control; `D`(deny) → `R`; the CI guard and INV-11 rewritten against `G` | 08 §3.5 and INV-11; 09's Phase-1 exit criteria; 01's shift table and demo script; 07's perf-spec name |
| Nav label "Leases" → "Containments"; component name `Lease board` → `Containment board`; `LeaseTimer` unchanged (identifier) | 04 §1.2 and §2.6; 05 §7.1(g) and §8 |
| `--lane-*` colour tokens → `--pillar-*`; "hue = lane" → "hue = pillar" | 05 §1, §7 — **done**, 05 §2.1 |
| Bridge "lanes" → "streams"; "256 MiB per lane" → "per stream" | 07 §2, §5 |
| `LANE_LABELS` → `QUEUE_LABELS`; "lane 1" → "queue 1"; "lane headers" → "queue headers" | 04 §2.1; this document, done |
| C9 counters' single home is The Watch (`/`); other surfaces restate read-only | 01 §8; 04 §2.10; 08 §3.6, §7.1; 09 exit criterion 6 |
| Wake-class notification bodies carry typed values only | 08's invariant list gains the CI check named in §7.2 |
| No card badge says "signed" or "verified" except a governance attestation or a deposit | 08 §6; 09's Phase-0 exit criterion; 02 §13's contract test |
| `/v2/api` and `clients/python/` disposition stated once | 02 §5 or a new §15; the Settings string in §5.9 is written against "frozen, not a Perch dependency" |

### 8.3 Corrections to this document's own earlier claims

- **The dismiss suppression key.** Previously stated as `(strategy_id, host_id)`. It is
  `FeedbackSuppressionKey { threat_class, event_id }`
  (`crates/swarm-pheromone/src/substrate.rs:345-348`, built at `:1412-1421`). The
  confirmation string in §5.5 now names the real blast radius: every detector that fired
  on the same telemetry event, not just the one you reviewed.
- **`swarmctl evidence-verify`.** Previously offered as the offline verifier for an
  exported governance receipt. It verifies **evolution** evidence bundles out of a
  `FileEvidenceBundleStore` (`crates/swarm-evolution/src/evidence.rs:1162, 1759`), not
  response or governance receipts. §5.10's export copy says so.
- **The Ed25519 chain.** Previously asserted, in `bothChainsNote`, that "the Ed25519
  signature is the record and is what verification runs against" for every card.
  Corrected in §5.10 with a per-card table. Four of the seven card types carry no signature.
- **`OperatorScope::Read`.** Previously "enforced on no handler". It is enforced on the
  `/v2/api` platform surface (`platform_api.rs:974`) and on no `/v1/operator/*` handler.
  §5.9 now says both halves.

---

## 9. Not verified

- The exact serialized field names on `GET /v1/operator/containment/leases` were read this
  pass from `ContainmentLeaseView` (`crates/swarm-runtime-http/src/http/containment.rs:71-87`:
  `lease`, `remaining_ms`, `expired`) — that part is now verified. What is **not** verified
  is the shape of the *proposed* `POST /v1/response/holds/{id}/decide` response, which does
  not exist; every hold string interpolating `{decision}` or `{operatorId}` is written
  against 03-DOMAIN-EVENT-MAPPING.md's proposal.
- Whether the mobile Flutter app carries any user-facing string this document contradicts.
  Mobile is out of scope for v1 by the brief and I did not read `mobile/lib`.
- The claim that no string in Buzz's shipped desktop uses the word "Approve" as a
  control label other than the workflow stub; I read the stub
  (`WorkflowApprovalCard.tsx:26-27`, which renders "Approval actions are not yet available
  in Desktop") and the Tauri command names (`grant_approval`, `deny_approval`) but did not
  exhaustively grep all `.tsx` files.
- The `Case 0042` id format is invented for this document; no in-tree case-numbering
  scheme exists, since the case object is Perch's own noun.
- `hold_ttl_ms = 3_600_000` is 08-TRUST-AND-GOVERNANCE-UX.md §3.6's settled default and does
  not exist in the tree. The snooze disabled-state string in §5.5 is deliberately written
  against the *rule* rather than the clock, so a re-tuned TTL does not change the copy.
- The claim that Ambush's existing docs contain no exclamation marks or urgency
  adjectives. I read `README.md`, `docs/CONSENSUS.md`, `docs/EVOLUTION.md` and ADR 0010 and
  observed the register, but did not grep the full `docs/` tree to prove the absence.
- `tools/check-copy-banned-terms.sh` and `check-perch-notification-fields.sh` do not
  exist; they are proposals patterned on the repo's existing gate scripts and on
  `tools/check-gates-wired.sh`'s requirement that every check be wired into a workflow.
