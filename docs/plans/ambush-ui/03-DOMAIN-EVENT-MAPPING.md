# Domain mapping: Ambush objects onto the Buzz event model

Every Ambush domain object that reaches an operator's eye has to arrive as one of three
things: a stored `kind:9` card carrying a versioned marker comment, one stored `kind:46010`
hold, or a live-only ephemeral frame in the `26000` block. Everything else — enumeration,
computed reports, and every write that authorizes — stays on the daemon's HTTP surface and is
never mirrored into the relay. This document is the complete table, the tag schemas, the
per-surface subscription filters, the identity bridge between two disjoint signature
algorithms, and the exact list of routes the Ambush runtime must grow.

Sibling docs: `02-ARCHITECTURE-INTEGRATION.md` owns process topology and the bridge crate;
`07-REALTIME-AND-DATA.md` owns spooling, backpressure, and query performance;
`08-TRUST-AND-GOVERNANCE-UX.md` owns what a badge is allowed to say. This doc owns the wire.

### How to read a citation in this document

A `path:line` proves a name exists. It does not prove the name does what a plan wants. Review
found four places in the first draft where the citation was real and the inference was not, so
every load-bearing citation below now answers three questions in the same paragraph:

| Question | Why it bites |
|---|---|
| **Who calls this?** | `build_signed_envelope` (`swarm-spine/src/envelope.rs:71`) has exactly one non-test caller in the workspace. A chain nothing writes is not a chain. |
| **Which process is it in?** | The 49 operator routes (`swarm-runtime-http/src/http/state.rs`) run in `swarm_detect --serve`; `swarmctl serve` builds its own control plane in another process. |
| **What does it do to the data?** | Buzz's `topic` tag exists — and each write emits a durable relay-signed `kind:40099` (`buzz-relay/src/handlers/side_effects.rs:1549-1563`, `:771-804`). A "cheap metadata poke" is two stored rows plus three addressable replacements. |

Where the honest answer is "nothing", "a different one", or "less than claimed", it is written
in the same sentence as the citation. Terminology is likewise constrained: in this document
**lane** means one of the twelve threat-class channels and nothing else. Transport classes are
**streams**, inbox categories are **queues**, and the D/A/E/H column below is a **carrier**.

---

## Decisions made here

1. **The hold is one stored event: `kind:46010`.** It carries the `ambush:hold:v1` marker body
   in its `content`, a `p` tag naming every operator who may decide, and an `h` tag naming the
   case channel. The `p` tag feeds the needs-action **backfill**; the `h` tag makes it visible
   in the case. It does **not** feed a live global subscription — §5.4 explains why, and what
   does.
2. **Seven markers, and the seventh is argued.** `ambush:finding:v1`, `ambush:escalation:v1`,
   `ambush:hold:v1`, `ambush:verdict:v1`, `ambush:receipt:v1`, `ambush:lease:v1`,
   `ambush:rollback:v1`. `verdict` replaces the first draft's use of `kind:46030`/`46031`,
   which cannot work (§5.5). `incident` is deliberately *not* a marker.
3. **Ephemeral telemetry is community-global, not channel-scoped**, so it carries no host id,
   no indicator, and no finding id — only aggregates and opaque ids. Kinds `26000`–`26006`,
   with a stated **issuer** rule as well as a payload rule (§6).
4. **The single-letter tag budget is spent, permanently**: `h` (channel), `e`/`p` (NIP-10 +
   mentions), `t` (threat-class slug), `l` (severity), `k` (card kind), `d` (addressable).
   Only `h`, `p` (single), `e` and `d` (on NIP-33 kinds) are pushed into SQL; `t`, `l` and `k`
   are **post-filters**, not indexed selection (§3).
5. **Per-issuer monotonic sequence on every published envelope**, so a gap renders as a gap
   rather than as silence.
6. **The relay is never the record.** Every card carries the daemon-side locator that
   re-fetches the authoritative object, and a verify affordance reads the daemon, not the card.
7. **Ambush grows six new backend surfaces**, listed in build order in §11. The sixth is new
   in this revision and is the reason the audit chain can answer "who approved this".

---

## 1. What the runtime emits versus what the console needs

Ambush has one live push surface and one pull surface, and they answer different questions.

`RuntimeEvent` (`crates/swarm-runtime/src/runtime_events.rs:212-305`) is an **eleven**-variant
serde-tagged enum — `Ingest`, `Finding`, `Replay`, `AgentAction`, `TamperAlert`,
`EvolutionStatus`, `ResponseExecution`, `AgentHealth`, `ConcentrationSnapshot`, `Escalation`,
`ModeTransition` — broadcast over a `tokio::sync::broadcast` channel with
`DEFAULT_RUNTIME_EVENT_CAPACITY = 1_024` (`runtime_events.rs:13`). It is a **notification**
stream: `Finding` carries a `SwarmFindingEnvelope` and an `Option<String>` host id but no
policy verdict; `ResponseExecution` carries `receipt_id: Option<String>` but not the receipt;
`Escalation` carries `threat_class`, `level`, `total_strength`, `distinct_sources`,
`peak_confidence`, `mode_changed`, `current_mode` — and **not** the `ThreatClassPolicy` it
crossed, so that is a bridge hydration, marked as such in §4.1. Nothing in the enum carries a
`ReplayBundle`, an `AuditTrail`, a `ContainmentLease`, a `CorrelatedIncident`, or a
`RollbackReceipt` — those live in file-backed stores behind the operator surface's 49 routes
(`crates/swarm-runtime-http/src/http/state.rs`, `grep -c '\.route('` = 49).

That split dictates the shape of the mapping. **The event stream tells the console that
something happened and gives it a stable id; the console then fetches the durable object
once and publishes it as a card.** The bridge is a translator with a read side, not a tee.

```
swarm_detect --serve  (sole writer, :9090)
  │
  ├─ IngestState::subscribe_runtime_events()   ingest/mod.rs:1874-1880
  │        │  returns Option<Receiver> — None when no broadcaster is wired.
  │        │  A None here is a startup failure the bridge must refuse to swallow.
  │        │  (in-process; broadcast cap 1024, lagged receivers drop SILENTLY)
  │        ▼
  │   swarm-perch-bridge
  │        ├─ disk spool  (drain-before-IO; a dropped frame is a correctness bug)
  │        ├─ hydrate: GET /v1/operator/{replay,incident,containment/leases,...}
  │        └─ publish over buzz-ws-client (NIP-42, kind:22242)
  │                 │
  └─────────────────┼──── (the console's writes go BACK here, never to the relay)
                    ▼
              buzz-relay  ──►  Perch (Tauri)
```

Two properties of the source data force design choices that show up everywhere below.

**Unit mismatch.** The pheromone path is unix **seconds** (`PheromoneDeposit::timestamp`,
`decay_half_life` — `crates/swarm-core/src/pheromone.rs:203-232`, decay at `:281`); everything
else is unix **milliseconds** (`*_at_ms`). Nostr `created_at` is seconds. Rule: the Nostr
`created_at` is always `emitted_at_ms / 1000`, and **every** numeric time inside a card body
keeps its source suffix (`_ms` or bare seconds for pheromone fields) so no consumer has to
guess. A shared TypeScript "timestamp" helper that normalizes both is forbidden; it produces
1000×-wrong decay curves silently.

**Severity casing.** `Severity` serializes `SCREAMING_SNAKE_CASE` while roughly forty sibling
enums serialize `snake_case`. The `l` tag therefore carries `CRITICAL`/`HIGH`/`MEDIUM`/`LOW`
verbatim. Any codegen that lowercases enum variants uniformly breaks exactly this one field.

---

## 2. Identity: two chains, and what each one actually signs

This is a real cryptographic mismatch, not a formatting difference.

| | Ambush | Buzz |
|---|---|---|
| Algorithm | Ed25519 (`ed25519-dalek`, `swarm-crypto/src/lib.rs:59`) | secp256k1 BIP-340 Schnorr |
| Identity string | `swarm:ed25519:<64 hex>` (`swarm-core/src/types.rs:16`) | 32-byte x-only pubkey hex |
| Chain machinery | `issuer` + `seq` + `prev_envelope_hash`, `verify_chain_link` (`swarm-spine/src/chain.rs:75-147`) | none — each event stands alone |

An Ed25519 key cannot be a Nostr pubkey. There is no encoding that makes it one.

### 2.1 The signature inventory, stated plainly

The first draft of this document, and four of its siblings, asserted that the Ed25519-signed
Ambush artifact "rides verbatim in the body" and that verification "runs against the Ed25519
chain". **That is false for most card types today, and no plan may build acceptance criteria
on it.** Verified by reading the structs:

| Card | Underlying type | Carries a verifiable signature today? |
|---|---|---|
| `ambush:finding:v1` | `DetectionFinding` (`swarm-whisker/src/detector.rs:50-59`, seven fields) / `SwarmFindingEnvelope` (`swarm-response/src/siem.rs:17-27`, eight fields) | **No.** Neither struct has a signature field. |
| `ambush:escalation:v1` | `RuntimeEvent::Escalation` (`runtime_events.rs:286-295`) | **No.** Plain data on a broadcast channel. |
| `ambush:hold:v1` | `ActionRequest` (`swarm-policy/src/lib.rs:47-58`) + `PolicyDecision` (`:75-84`) | **No.** |
| `ambush:verdict:v1` | the operator's decision | **Yes, after backend item 1.5** (§11.1b) — and only then. |
| `ambush:receipt:v1` | `ResponseReceipt` (`swarm-response/src/lib.rs:100-116`), `AuditTrail` (`swarm-spine/src/lib.rs:113-122`) | **No** on the receipt itself. `audit.governance.receipt` is an untyped `Option<serde_json::Value>` (`:136-142`) that *may* hold a `ConsensusGovernanceReceipt`. |
| `ambush:lease:v1` | `ContainmentLeaseView` (`swarm-runtime-http/src/http/containment.rs:70-90`) | **No.** |
| `ambush:rollback:v1` | `RollbackReceipt` (`swarm-response/src/rollback.rs:242-286`) | **Yes, conditionally.** `governance_attestation: Option<serde_json::Value>` holds a serialized `ConsensusGovernanceReceipt` over the receipt with that field cleared, and `verify_release_attestation` (`swarm-runtime/src/containment.rs:235-268`) verifies it, checks subject binding against `release_subject_id`, and is actually called at `http/containment.rs:219`. `None` means UNATTESTED and the verifier **refuses** it (`rollback.rs:277-281`). |
| pheromone deposits | `PheromoneDeposit.signature` (`swarm-core/src/pheromone.rs:231-232`) | **Yes** — and §4.1 rules that deposits are never individually published. |

And the chain machinery the plan leaned on is near-dead: `build_signed_envelope`
(`envelope.rs:71`) has **one** non-test caller in the workspace — `swarm-runtime/src/approval.rs:1810` —
and `verify_chain_link` / `ChainLinkVerdict` have **zero** consumers outside `swarm-spine`'s own
module beyond the re-export at `swarm-spine/src/lib.rs:61`. Worse, that one caller signs with
`Keypair::from_seed(sha256("approval-ledger-envelope:{ledger_id}"))` (`approval.rs:1804-1806`) —
a deterministic keypair derivable by anyone who knows the ledger id. Its envelope hash is a
tamper-evidence chain, not an authenticity proof. The authenticity in the approval ledger is
somewhere else entirely, and §11.1b uses it.

**Consequence, binding on every sibling document.** Two options existed: (a) delete the
Ed25519-verification claim everywhere, or (b) make it true. This document takes **(b), but
scoped**: backend item 1.5 wraps *the human decision* in `build_signed_envelope` before it
leaves the daemon, because that is the artifact the product is named after and it is the same
one-call pattern `approval.rs:1810` already uses. Findings, escalations, holds and response
receipts stay unsigned in v1, and every surface that renders them says so:

- Findings / escalations / holds / receipts / leases: **"signed by the bridge's Nostr key.
  The daemon is the record."** Plus a verify affordance that re-fetches from the daemon.
- Rollback receipts: the existing tri-state — attested (with the ADR 0010 caveat that a full
  re-attestation passes), `None` → **UNATTESTED**, or verification error.
- Verdicts: **"Ed25519 chain: envelope N continues issuer `swarm:ed25519:9f3c…`"**, checked
  locally against the daemon-served envelope.

`09`'s Phase-0 exit criterion and `02` §13's contract test must be rewritten against this: the
Phase-0 criterion is *byte-identical round-trip of the finding JSON*, not signature
verification; the signature contract test belongs to Phase 1 and covers the verdict envelope.

### 2.2 What NIP-OA actually buys

Each agent instance gets a second, Nostr-only secp256k1 keypair, bound to its Ambush identity
by a NIP-OA owner attestation (`crates/buzz-sdk/src/nip_oa.rs:1-19`):

```
["auth", "<owner-pubkey-hex>", "<conditions>", "<sig-hex>"]
message = SHA256("nostr:agent-auth:" || agent_pubkey_hex || ":" || conditions)
sig     = BIP-340 Schnorr(message, owner_secret_key)
```

The owner is the **colony operator key**, one per deployment. What this buys, verified:
**a self-proving agent→owner binding with no DB round-trip, so a ban on the operator cascades
to every agent key at authentication time.** `handlers/auth.rs:106-184` reads the ban state of
the authenticating pubkey, and if clear, calls `extract_nip_oa_owner` and checks the owner's
ban state too, failing closed on a DB error. That path does **not** require configuration.

**What it does not buy, corrected from the first draft:** per-kind authorization.
`verify_auth_tag` (`nip_oa.rs:195-236`) calls `validate_conditions` for **syntax only**
(`:214`) and returns the owner pubkey — it never sees the event being published. Its only
relay consumers are `check_relay_membership` (`buzz-relay/src/api/mod.rs:88`),
`extract_nip_oa_owner` (`:156-170`) and the HTTP bridge (`api/bridge.rs:902`), all of which use
the return value for membership and the ban cascade. Two further facts: `validate_conditions`
splits on `&` and requires **every** clause to hold (`nip_oa.rs:145-158`), so
`kind=9&kind=26000` would be unsatisfiable under any future enforcement rather than a two-kind
grant; and the membership path that reads conditions at all sits behind `allow_nip_oa_auth`,
which **defaults to false** (`buzz-relay/src/config.rs:1367-1368`) and must be set explicitly
for the closed-relay path. Delete "the bridge cannot publish a hold under a sensor's key" —
today it can. Per-kind narrowing is out of scope: it would be a third relay change against C1's
two-arm budget. The compensating control is outside the relay — **the sensor identities are
simply not given the ability to publish `46010`, because only the bridge's alarm identity
publishes holds** (§7 assigns identities), and `08`'s INV-15 refuses to render a hold card
whose pubkey is not an admitted bridge identity.

The binding in the other direction — Nostr key → Ambush identity — goes in the agent's
`kind:0` profile and, more importantly, **in every card body**:

```jsonc
"issuer": {
  "swarm_agent_id": "swarm:ed25519:9f3c…64hex",     // the Ed25519 identity, verbatim
  "nostr_pubkey":   "a71b…64hex",                    // the envelope signer
  "role": "whisker"                                  // AgentRole, snake_case
}
```

**Verification-surface rule (binding).** Every place the UI says something is verified must
name the chain it checked and, per §2.1, must not claim a chain that does not exist. If the
console ever renders a single green check meaning "verified", the transport signature has
silently replaced the evidence signature and "Ambush proves what it saw" becomes "trust the
bridge."

**The operator's key, revised.** A human's Nostr keypair is a Buzz identity: it signs the
`ambush:verdict:v1` card. It is **not** the only key the human holds. Ambush already ships a
signature-bound human-decision primitive, and §11.1b makes the decide route use it, so the
operator also holds an **Ed25519 signing key in the Tauri process**, beside the Nostr key —
the same key `demo.rs:685-693` reads from `voter_signing_key_env` today.

---

## 3. The wire format: marker-prefixed `kind:9` cards

Durable Ambush evidence rides `kind:9` stream messages (`KIND_STREAM_MESSAGE`) whose `content`
begins with an HTML comment marker, exactly the pattern Buzz already ships for wave messages:
`WAVE_MESSAGE_MARKER = "<!-- buzz:wave:v1 -->"`
(`desktop/src/features/messages/lib/waveMessage.ts:1`), sniffed in `MessageRow.renderBody`'s
**default** arm (`desktop/src/features/messages/ui/MessageRow.tsx:414-427`) via
`parseWaveMessageContent`, before falling through to markdown.

Content anatomy, three parts, in this order:

```
<!-- ambush:finding:v1 -->
{"schema":"ambush.perch.finding.v1","seq":41,"issuer":{…},"finding":{…},"locator":{…}}
whisker-7a3f · dns_exfiltration · HIGH · conf 0.82 · host web-04 · finding f2c9…
```

1. **Marker.** Version is in the marker, not only in the JSON, so a renderer can route before
   it parses. A `v2` marker is a new renderer; a `v1` renderer that meets `v2` falls through to
   the fallback line rather than rendering a half-understood card.
2. **JSON body.** One line, so the fallback line is trivially separable by the first newline.
3. **Human fallback line.** This is what a Flutter client, `buzz messages thread`, a NIP-50
   search snippet, and a plain markdown renderer show. It is the degradation contract, and it
   must contain the identifiers a human would need to go find the real thing.

### Why markers and not new stored kinds

| Cost of a new stored kind | Evidence |
|---|---|
| Fork `required_scope_for_kind`; default arm rejects unknown kinds outright | `buzz-relay/src/handlers/ingest.rs:545` — `_ => Err("restricted: unknown event kind")` |
| Fork `requires_h_channel_scope` or the event is admitted global with no compartment | `ingest.rs:703-732`; `is_global_only_kind` at `:621-625` |
| Register in **four** client places, not one: `CHANNEL_TIMELINE_CONTENT_KINDS`, `CHANNEL_EVENT_KINDS` (`desktop/src/shared/constants/kinds.ts:100-113, 137-149`), `isTimelineContentEvent` (`formatTimelineMessages.ts:52-66`), and a `MessageRow` renderer arm | measured while sizing §5.2 |
| Hand-sync three kind registries: `buzz-core/src/kind.rs`, `desktop/src/shared/constants/kinds.ts`, `mobile/lib/shared/relay/nostr_models.dart` | drift is unenforced |
| Degrades to nothing in Flutter/web/CLI/search — an unknown kind renders as an empty row | — |

Against that, the marker path costs two things, both permanent and both named.

**Cost 1: body fields are FTS-reachable only.** NIP-01 indexes single-letter tags.
`strategy_id`, `host_id`, `receipt_id`, `lease_id`, `hunt_id` are reachable through NIP-50 FTS
(Postgres `search_tsv`, `schema/schema.sql:223-227`) and nowhere else. The events are signed,
so they cannot be re-tagged later.

**Cost 2 — corrected in this revision: `t`, `l` and `k` are post-filters, not selection.**
`filter_fully_pushable` (`buzz-relay/src/handlers/req.rs:851-895`) pushes only `kinds`,
`authors`, `ids`, `since`/`until`, `#h`, a **single** `#p`, `#d` on NIP-33-only kind filters,
and `#e`; its default arm returns `false` for every other generic tag, naming `#t` and `#a`
explicitly. `EventQuery` has no generic tag field beyond `custom_tag: Option<(String,String)>`
— one pair (`buzz-db/src/store/event.rs:81-83`). So a REQ of `{kinds:[9], #h:[case],
#k:["receipt"]}` fetches a page of *all* `kind:9` in the case and drops non-matching rows
afterwards. Two consequences, binding on §8: **paging depth must be sized for the dilution**
(a `limit:200` on a busy case can return a handful of receipts), and such a filter
**disqualifies the fast COUNT path**. Where per-card-type selection actually matters — the case
timeline's receipt and lease sub-views — Perch fetches one page of `{kinds:[9], #h:[case]}` and
**partitions it client-side on the parsed marker**, rather than asking the relay for a
selection it cannot push down. `k` remains worth its letter as a *display and post-filter* hint
(it lets a renderer route without parsing the body, and it lets a wide Ledger query be narrowed
without a second round trip), but it is not an index and no document may describe it as one.

Verified enabling fact: `kind:9` is already in `required_scope_for_kind` as `MessagesWrite`
and already in `requires_h_channel_scope` (`ingest.rs:707`). Zero relay change for the entire
evidence stream.

### The tag schema, common to all seven cards

| Tag | Value | Notes |
|---|---|---|
| `h` | case or lane channel UUID | mandatory; `extract_channel_id` parses it as a `Uuid` (`ingest.rs:549-561`) |
| `t` | threat-class slug — `ThreatClass` snake_case (`swarm-core/src/pheromone.rs:16`) | post-filter only; `custom` findings carry `t=custom` **and** a body `threat_class_custom` string |
| `l` | `Severity`, SCREAMING_SNAKE_CASE | post-filter only |
| `k` | card kind slug: `finding`\|`escalation`\|`hold`\|`verdict`\|`receipt`\|`lease`\|`rollback` | renderer routing + post-filter; **not** indexed selection |
| `e`/`p` | NIP-10 threading and mentions | `#p` (single) is the one generic tag that *is* pushed, via the `event_mentions` join |
| `broadcast` | `"1"` on mode-transition-to-Incident escalation cards only | Buzz's existing notification predicate keys off it |

---

## 4. The complete object mapping

Carrier legend: **D** = durable `kind:9` card; **A** = actionable stored kind (`46010`);
**E** = ephemeral `26xxx`; **H** = daemon HTTP only, never on the relay;
**C** = channel/addressable state.

### 4.1 Hot path

| Ambush type (cite) | Carrier | Vehicle | Channel | Body highlights |
|---|---|---|---|---|
| `TelemetryEvent` (`swarm-core/src/telemetry.rs:8`, 13 payload kinds) | H | — | — | Never published. Raw telemetry is the highest-volume, highest-sensitivity object in the system; it reaches the console only inside a `ReplayBundle` fetched on demand. |
| `DetectionFinding` (`swarm-whisker/src/detector.rs:50-59`) / `SwarmFindingEnvelope` (`swarm-response/src/siem.rs:17-27`) | D | `kind:9` + `ambush:finding:v1` | lane channel | `finding_id`, `event_id`, `strategy_id`, `threat_class`, `severity`, `confidence`, `evidence`, plus `host_id` **from the `RuntimeEvent::Finding` wrapper, not the envelope** (`runtime_events.rs:224-228`). Unsigned; see §2.1. |
| `PheromoneDeposit` (`swarm-core/src/pheromone.rs:203-234`) | H | — | — | Not individually published, despite being one of only two routinely Ed25519-signed objects. Deposits are queried as a slice through the new `/v1/operator/pheromone/deposits` route (§11.5). |
| `PheromoneConcentration` / `RuntimeThreatConcentration` (`runtime_events.rs:186-210`) | E | `26001` | global | `threat_class`, `total_strength`, `distinct_sources`, `peak_confidence`, `current_mode`. **It does NOT rewrite any channel topic** — see §7.1. |
| `EscalationRecord` / `RuntimeEvent::Escalation` (`runtime_events.rs:286-295`) | D | `kind:9` + `ambush:escalation:v1` | lane channel | `threat_class`, `level`, `total_strength`, `distinct_sources`, `peak_confidence`, `mode_changed`, `current_mode` — all served. The resolved `ThreatClassPolicy` thresholds are **hydrated by the bridge** from the daemon, not carried by the event; the card marks them `"source":"hydrated"`. |
| `SwarmMode` / `RuntimeEvent::ModeTransition` | E + D | `26003`, and an `ambush:escalation:v1` card with `broadcast=1` when `to == Incident` | global / lane | `from`, `to`, `triggering_threat_class`, `reason` |
| `ActionRequest` (`swarm-policy/src/lib.rs:47-58`) + `PolicyDecision` (`:75-84`) when the verdict is `RequireHuman` | A + E | `kind:46010` + `ambush:hold:v1`, plus a `26006` alarm frame | case channel / global | §5 |
| `CapabilityLease` (`swarm-policy/src/lib.rs:134-144`) | inside cards | — | — | Never its own card. It appears inside the hold card as "what granting opens" and inside the receipt card as what was consumed. **Minted at decision time, not hold time** — `lease_ttl_ms: 60000` (`rulesets/default.yaml:94`) is dead before a human reads the page. |
| `ResponseReceipt` (`swarm-response/src/lib.rs:100-116`) + `AuditTrail` (`swarm-spine/src/lib.rs:113-122`) | D | `kind:9` + `ambush:receipt:v1` | case channel | `receipt_id`, `action`, `mode` (`dry_run`\|`enforced`), `status`, `audit.policy` (`verdict`/`rule_name`/`reason`), `audit.governance` (`governing_agent_id` — **an agent, not the human**), `trail_id`, `related_receipt_ids`. Unsigned until §11.1b lands the approver thread. |
| `ReplayBundle` (`swarm-spine/src/lib.rs:125-134`) | H | — | — | Too large and too nested to inline (it embeds the whole `TelemetryEvent`, all findings, all deposits, the request, the rehearsal, the trail). Every receipt card carries `locator.bundle_id`; the console fetches it. |
| `ContainmentLeaseView` (`swarm-runtime-http/src/http/containment.rs:70-90`) | D + H | `kind:9` + `ambush:lease:v1` on open; `/leases` reads HTTP | case channel | typed `action`, `blast_radius`, `rollback` preview, `issued_at_ms`, `expires_at_ms`. **`remaining_ms` and `expired` are never baked into the card** — they are clock-derived and the card is immutable. |
| `RollbackReceipt` (`swarm-response/src/rollback.rs:242-286`) | D | `kind:9` + `ambush:rollback:v1` | case channel, NIP-10 reply to the lease card | `trigger`, `steps[]` with `RollbackStepStatus`, `fully_reversed()`, `lease_closed`, and `governance_attestation` **as a tri-state** — the one card whose signature the console can actually check (§2.1). |

### 4.2 Async paths and governance

| Ambush type | Carrier | Vehicle | Rationale |
|---|---|---|---|
| `InvestigationBundle` (`swarm-spine/src/investigation.rs:78`, 30 fields, vote lineage in basis points) | H | — | Renders in the case detail pane from a fetch. Its `candidate_interpretations` / `vote_lineage` / `decision` are exactly the shape that would rot if frozen into a card at one instant. |
| `CorrelatedIncident` (`swarm-spine/src/incident.rs:136`) | C + H | **is** the case channel; seeds the canvas | Deliberately **not** a marker card. The incident is a *recomputed snapshot* — `included_members` and `rejected_members` change as the correlation engine re-runs. A frozen card would create a second record that drifts from the daemon's, violating decision 6. The channel's `kind:39000` metadata carries `incident_id`; the `kind:40100` canvas is seeded from the incident's `summary`, `graph_dimensions`, and the member table as markdown a human can then edit. **This decision has a cost §4.3 now names.** |
| `GovernanceStatusReport` (`swarm-policy/src/governance.rs:65`) incl. `PartitionState` (`:50`) | E | `26004` | Feeds the persistent governance strip. `total_governors: 1` renders "committee of 1 (solo transport)", never a fraction. |
| `ConsensusGovernanceReceipt` (`swarm-consensus/src/lib.rs:380`) | inside cards | — | Rides inside the receipt card's `audit.governance.receipt`, an untyped `Option<Value>` (`swarm-response/src/lib.rs:136-142`). Rendering it as its own card would imply a committee ledger Perch does not ship in v1. |
| `AgentHealth` / `RuntimeEvent::AgentHealth` (`runtime_events.rs:276-282`) | E | `26002` | `agent_id`, `role`, `from`, `to`. **Not** Nostr presence (`kind:20001`) — for a corrected reason: presence *does* fan out cluster-wide. A `20001` update writes Redis presence state and then falls through to the shared channel-less ephemeral path, which does `publish_event(&conn.tenant, EventTopic::Global, &event)` before local fan-out; the code comment says so explicitly (`buzz-relay/src/handlers/event.rs:843-847`, publish at `:884-891`). The real disqualifier is that presence is a **TTL-decayed status with a lie window**: `SET … EX 180` on a 60 s heartbeat (`buzz-pubsub/src/presence.rs:3,16`), so a dead sensor reads "online" for up to three minutes. Liveness for a security product cannot be three minutes stale. |
| `RuntimeEvent::TamperAlert` | E + D | `26005`, plus an `ambush:escalation:v1` card with `broadcast=1` when `fail_closed` | `unexpected_library_loads` is a path list — sensitive. The ephemeral form carries counts only; the card carries the paths and lands in a private ops channel. |
| `RuntimeEvent::Ingest` | E | `26000` | Rate gauge only, coalesced. Per-event ingest frames at line rate are the single largest volume source in the enum. |
| `RuntimeEvent::Replay`, `RuntimeEvent::EvolutionStatus`, `RuntimeEvent::AgentAction` | H | — | Replay runs, the evolution path and per-turn agent actions are `/watch-floor` and `/tuning` reads, not conversation. |

### 4.3 Feedback and tuning — and the constraint that governs it

| Ambush type | Carrier | Vehicle |
|---|---|---|
| `ProvidenceFeedbackAction = Confirm \| Dismiss \| Investigate` (`swarm-core/src/types.rs:112`) | D | `kind:9` + `ambush:verdict:v1`, `h` = case or lane channel, `e` = the finding card. The body names the verb literally. |
| `FalsePositiveMeasurement` (`swarm-spine/src/incident.rs:46`) | H | Written by the daemon at `POST /v1/operator/findings/{id}/feedback` (§11.4), the same record the Providence webhook writes at `providence_handlers.rs:170-179` |
| `AlertTuningRecommendation` / `AlertTuningReport` (`swarm-runtime/src/alert_tuning.rs:50-77`) | H | Computed by `build_alert_tuning_report` (`:85`) against thresholds 0.75 / 0.50 / 0.34 (`:6-15`). A report, not an event. |

**The constraint, stated where the product thesis can see it.** The shipped write path is
**incident-keyed, not finding-keyed**, and the plan must not pretend otherwise.
`SwarmProvidenceFeedbackRequest` carries a **required** `incident_id: String` and an *optional*
`finding_id` (`swarm-core/src/types.rs:144-152`). `providence_feedback_handler` does
`.load_by_incident_id(&request.incident_id)` and returns 404 when it misses
(`providence_handlers.rs:130-138`); `resolve_feedback_target` then selects a member from
`incident.included_members` and errors if the finding is not one of them
(`swarm-runtime/src/providence.rs:799-815`); the measurement is upserted **onto the incident**
and the incident is persisted (`providence_handlers.rs:167-179`). And
`build_alert_tuning_report(records: &[IncidentRecord])` (`alert_tuning.rs:85-92`) reads
measurements only off incidents.

So a verdict is recordable **only against a finding that belongs to an incident record**. The
common case — one finding in a lane, no incident — has nowhere for a Dismiss to land. Combined
with §4.2's ruling that `CorrelatedIncident` is not promoted for its own sake, this is a real
hole in the loop the product is named after. **Settled: render Confirm/Dismiss/Investigate
disabled on an uncorrelated finding, with the reason on the control** — "this finding is not
part of an incident record yet; promote it to a case to record a verdict" — and make
*promote-to-case* create the incident record, which is the same act as the brief's manual
promotion bar. Extending the store to attach a measurement to a bare finding is a larger,
separately-argued change; implicitly promoting on Dismiss is rejected because it makes a
one-keypress dismissal silently create durable state.

Two further honesty requirements. `06`'s copy must not say "every human decision is a signed
act" about the *arithmetic*: the suppression deposit that a Dismiss produces is signed with the
**daemon's** key (`providence_handlers.rs:536-558` — `state.signing_key.sign(&payload_bytes)`,
`agent_id: AgentId::from_verifying_key(&state.signing_key.verifying_key())`), not the
analyst's. The signed human act is the `ambush:verdict:v1` card and the §11.1b envelope; the
deposit is the daemon acting on it. And **the verb set is the wire format** — `Dismiss` must be
the word on the button and the string on the wire, because only Dismiss sets
`false_positive: true`. The moment the console sends `{"reaction":"👎"}` the tuning loop is fed
by an emoji and `build_alert_tuning_report` sees nothing.

### 4.4 Why `escalation` earned a marker, and why `verdict` earns the seventh

`RuntimeEvent::Escalation` is the only variant that records a threshold crossing — the exact
moment the swarm's coordination substrate said "this is real enough to change posture." It is
the anchor for case promotion, one of the four notification classes allowed to wake someone,
and the one thing a shift-handover reader needs to reconstruct *why* a lane went hot after the
concentration curve has decayed back down. An ephemeral-only escalation is unreadable at 07:00.

`ambush:verdict:v1` is the seventh, and it is not a preference: §5.5 shows that `kind:46030`
**cannot carry it**. Beyond that necessity, it meets the same bar — the human decision is the
one artifact in this product that must be legible in the case timeline forever, must survive
into a quarter's audit bundle, and must be findable by free text ("who dismissed the DNS
alerts on web-04 last Tuesday"). An eighth marker needs this shape of argument: what an
operator cannot reconstruct without it after the ephemeral has decayed.

---

## 5. The actionable kind: `46010`, and how a hold reaches one human

### 5.1 The hold event and the two relay match arms

`KIND_WORKFLOW_APPROVAL_REQUESTED = 46010` is defined (`buzz-core/src/kind.rs:578`), is in
`ALL_KINDS` (`:745`), and is one of exactly two kinds the desktop needs-action feed queries:

```rust
// crates/buzz-db/src/store/feed.rs:191-193
qb.push(format!(
    " AND e.kind IN ({KIND_WORKFLOW_APPROVAL_REQUESTED}, {KIND_STREAM_REMINDER})"
));
```

Nothing can emit it. `required_scope_for_kind` has no arm for it, so it falls to
`_ => Err("restricted: unknown event kind")` (`ingest.rs:545`), and its only would-be producer
is a stub (`buzz-workflow/src/executor.rs:727`). The desktop card literally reads "Approval
actions are not yet available in Desktop" (`WorkflowApprovalCard.tsx:27`).

**The relay fork is exactly two match arms, both for `46010`:**

```rust
// crates/buzz-relay/src/handlers/ingest.rs — before the default arm at :545
KIND_WORKFLOW_APPROVAL_REQUESTED => Ok(Scope::MessagesWrite),

// crates/buzz-relay/src/handlers/ingest.rs:703-732 — requires_h_channel_scope
| KIND_WORKFLOW_APPROVAL_REQUESTED
```

The second arm is **mandatory**, not cosmetic. Verified: `46010` appears in neither
`requires_h_channel_scope` (`:703-732`) nor `is_global_only_kind` (`:621-625`). Without it the
scope arm alone admits a hold as a community-global event with no `h` tag,
`filter_fanout_by_access` (`handlers/event.rs:116-217`) has no channel to check membership
against, and the compartment is defeated.

Three things checked that do **not** need to change: `search_tsv` (the privacy CASE nulls the
tsvector for kinds `1059, 30179, 30300, 30350, 30622, 44100, 44101, 44200` at
`schema/schema.sql:223-227`; `46010` is not among them, so hold bodies are FTS-searchable —
what the Ledger wants); `P_GATED_KINDS` (`buzz-core/src/kind.rs:159-169`, which does not
contain `46010`, so the `p` tag is a *routing* hint, not a read gate — channel membership is
the read gate); and `AUTHOR_ONLY_KINDS`.

### 5.2 `46010` is invisible client-side until it is registered in four places

This was listed as a decision in the first draft and flagged as unverified in the same
document. It is now checked, and it is a **work item, not a decision**. The needs-action half
verifies: `build_needs_action_query` INNER JOINs `event_mentions` and filters
`kind IN (46010, 40007)` (`buzz-db/src/store/feed.rs:171-200`), and `p` tags populate
`event_mentions` for **every** kind (`buzz-db/src/runtime/mod.rs:10-45`, insert at `:88-110`).
The case-timeline half does not. `46010` is absent from:

| Registration point | File |
|---|---|
| `CHANNEL_TIMELINE_CONTENT_KINDS` | `desktop/src/shared/constants/kinds.ts:137-149` |
| `CHANNEL_EVENT_KINDS` | `kinds.ts:100-113` |
| `isTimelineContentEvent` | `desktop/src/features/messages/lib/formatTimelineMessages.ts:52-66` |
| a `MessageRow` renderer arm | `MessageRow.tsx` switch |

The history fetch requests only the content-kind set, so a `46010` in a case channel is fetched
by nothing, renders no row, and triggers no unread — invisible regardless of its `h` tag. Four
client registrations, sized in `09` Phase 1 as its own line, not folded into "the verdict row".
Note what this does to C1's framing: the fork is still **two relay match arms**, but the kind
must be registered in **six** places total across the two trees. Say "two relay arms, six
registration points" rather than "two arms and nothing else".

Do **not** add `46010` to `NON_CONVERSATIONAL_UNREAD_KINDS` (`kinds.ts:155-168`): a hold must
count toward unread, which is the entire point.

One more verified consequence: `build_needs_action_query` has no status join, so a **decided**
hold stays in `query_needs_action` forever. Perch reconciles the queue against the daemon's
hold list on every fetch and removes decided holds client-side. This is true of Buzz's own
approvals too; it is not an Ambush regression, but it must be built deliberately rather than
discovered.

### 5.3 The `p` tag is load-bearing, and so is channel membership

`query_needs_action` is an `INNER JOIN event_mentions m … AND m.pubkey_hex = $reader`
(`feed.rs:180-190`), and it additionally scopes to visible channels:
`push_visible_channel_filter` emits `AND (e.channel_id IS NULL OR e.channel_id IN (…))`
(`feed.rs:61-73`). So a hold reaches an operator's queue only if **both** hold: the operator is
`p`-tagged, and the operator is a member of the case channel.

Rule, both halves: the bridge `p`-tags the recipients **and** adds them to the case channel via
`kind:9000` at case creation. A hold that satisfies one and not the other reaches nobody, and
the failure is silent.

### 5.4 Who gets the `p` tag, and how the queue updates live

Three sibling documents proposed three incompatible mechanisms — a daemon shift assignment
(which does not exist), a relay-published watch claim (which the bridge cannot read: it runs
inside `swarm_detect --serve` and subscribes in-process at `ingest/mod.rs:1874-1880`, with no
relay read path), and re-publishing open holds with the incoming analyst's pubkey (which
requires a **new signed event**, because `event_mentions` rows come from the p tags on the
stored event — so it duplicates the hold and is signed by the wrong key). **One survives, and
this document settles it.**

**Settled for v1: `p`-tag every operator principal holding `OperatorScope::Approve`.** This
needs no new backend surface, no relay read from the bridge, and no shift concept. The daemon
already builds that list: `OperatorAuthConfig::effective_principals()`
(`swarm-core/src/config/operator.rs:153-168`) returns the configured `principals`, or a single
default principal granted `Read | Rehearse | Approve | Maintenance`. In the shipped default
configuration that is **exactly one operator**, so the "noisy queue" objection is empty by
default and only appears in a deployment that has deliberately configured several approvers. A
noisy queue is recoverable; an empty one is not.

Per-shift routing is a **named, priced v2 item**, not an assumption: add
`on_shift_operator_pubkeys: Vec<String>` to the daemon, set by a small
`POST /v1/operator/watch/claim` beside the decide route, read by the bridge at publish time,
with `/handoff` updating the daemon rather than the relay. `07`'s re-publish is rejected above
with reasons.

**`04` §2.11's watch claim is not rejected — it is a different mechanism at a different layer,
and the two coexist.** The `p` tag decides whose *queue* the row enters, and that is settled
above as every Approve-scoped operator. The watch claim decides whose *phone rings*: it is a
client-side filter on wake classes 1–3 (`04` §3.2), read from the `#watch` ops channel's topic,
requiring no bridge read of the relay and no daemon field. With no claim held, or a stale one,
everyone pages. Only the *daemon-side* `on_shift_operator_pubkeys` field can narrow the `p` tag
itself, and that is the v2 item above. Note the schema cost when it is built:
`OperatorPrincipalConfig` carries `#[serde(deny_unknown_fields)]`
(`config/operator.rs:116-129`), so the operator→Nostr-pubkey mapping is a typed field addition,
not a free config key.

**The live path, and the defect it fixes.** `03` §8 and `07` §6 both specified The Watch's
needs-action subscription as a REQ with **no `#h`** — and that filter cannot work, because of
the fork this very document mandates. Adding `46010` to `requires_h_channel_scope` sets
`channel_id` on the stored event; `fan_out_scoped` then routes an event with
`channel_id = Some(..)` through `channel_kind_index` / `channel_wildcard_index` **only**
(`buzz-relay/src/subscription.rs:387-423`), and a REQ with no `#h` is registered as a *global*
subscription in the global indexes (`subscription.rs:158-218`). The code states the invariant
outright at `:486-491`: "Global subscriptions (channel_id = None) do NOT receive channel-scoped
events." The HTTP backfill still works, so this is invisible in a cold-load test and shows only
as "the queue never updates live" — while `07` budgets 400 ms and `04` promises a realtime
queue increment.

**Settled: a `26006` alarm frame is the live path; the durable `46010` is the record.**

```
hold created (daemon)
  ├─ RuntimeEvent::ResponseHeld ──► bridge
  │      ├─ publish kind:46010 into the case channel   (durable; the record)
  │      └─ publish ephemeral 26006, global, no `h`,   (live; the nudge)
  │             p = each Approve-scoped operator
  │             body = { hold_id, action_kind, severity, case_channel, expires_at_ms }
  ▼
Perch: 26006 arrives on the always-open global REQ → increments the queue,
       fires the wake class, and re-runs query_needs_action for the authoritative row.
```

Why this and not the alternatives: polling `query_needs_action` alone cannot meet a 400 ms
budget and would have to delete it; subscribing per-case with `#h` makes a hold in a case the
operator has not opened invisible until backfill. The ephemeral path is verified to reach a
global REQ (`event.rs:877-903`: channel-less ephemerals publish to `EventTopic::Global` and fan
out through the global index) and `07`'s alarm stream already specifies never-coalesced,
never-dropped delivery for exactly this frame.

Its loss policy must be stated because ephemerals are not stored: **a Perch that is
disconnected when the alarm fires misses it.** Therefore `query_needs_action` runs on connect,
on every reconnect, and on every alarm; the queue's authority is the HTTP feed plus relay
backfill, and the alarm is only a nudge. `07`'s ≤400 ms budget is a budget on the *alarm*, and
must be relabelled as such.

Its payload obeys §6's global-ephemeral constraint, which forces one change to the id format below.

### 5.5 The verdict cannot ride `kind:46030` — and why

The first draft specified leg 1 of the write as a signed `kind:46030` grant / `46031` deny,
citing the fact that both are already allowlisted in `required_scope_for_kind`
(`ingest.rs:541`). The scope arm is real. **The inference was wrong, and this is a defect no
reviewer caught.**

`is_command_kind` (`buzz-core/src/kind.rs:815-826`) includes `KIND_APPROVAL_GRANT` (46030) and
`KIND_APPROVAL_DENY` (46031). At `ingest.rs:2278`, after signature, timestamp, auth and scope
checks, a command kind is routed to `command_executor::handle_command` **instead of ordinary
storage**. `handle_approval_grant` (`command_executor.rs:1020-1061`) then:

1. requires a `d` or `e` tag whose value is a **token hash hex** (`:1031-1038`);
2. calls `get_approval_by_stored_hash` and rejects with `"invalid: approval not found"` when
   there is no matching `workflow_approvals` row (`:1041-1045`);
3. requires `status == Pending`, a non-expired `expires_at`, and a passing
   `check_approver_spec` (`:1048-1061`).

An Ambush hold has no `workflow_approvals` row — and §5.6 rejects creating one, because the
table has hard foreign keys to `workflows` and `workflow_runs`. So a Perch-published `46030`
is **rejected at ingest and never stored**. The event does not exist; the case timeline shows
nothing; the Ledger cannot find it.

**Settled: the human verdict is a `kind:9` card with the `ambush:verdict:v1` marker.** `kind:9`
is not a command kind, is already scoped and `h`-scoped, renders in the timeline for free, is
FTS-searchable, and degrades honestly. This also *shrinks* the plan: `46030`/`46031` leave the
design entirely, so the relay fork is `46010` and nothing else, and `08`'s analysis of whether
`46030` needs an `h` tag is moot.

### 5.6 Hold card body

```jsonc
{
  "schema": "ambush.perch.hold.v1",
  "seq": 88,
  "issuer": { "swarm_agent_id": "swarm:ed25519:…", "nostr_pubkey": "…", "role": "pouncer" },
  "hold_id": "hold:01JQ8Z3K9V7M2R4T",             // OPAQUE — see below
  "held_at_ms": 1772300000000,
  "expires_at_ms": 1772303600000,                  // hold_ttl_ms default 3_600_000 (08 §3.6)
  "action": { "type": "isolate_host", "host_id": "web-04" },   // ResponseAction, verbatim
  "action_kind": "isolate_host",
  "request": { "hunt_id": "…", "requested_by": "swarm:ed25519:…", "severity": "HIGH" },
  "policy": { "verdict": "require_human", "rule_name": "…", "reason": "…" },
  "rehearsal": {
    "blast_radius": { "scope_kind": "host", "scope_value": "web-04",
                      "impact": "host_connectivity_isolated",
                      "max_affected_scopes": 1, "affected_capabilities": ["…"],
                      "summary": "…" },
    "rollback": { "required": true, "summary": "…",
                  "steps": [{ "kind": "restore_host_connectivity", "summary": "…" }] }
  },
  "inverse": { "executable": true, "kind": "restore_host_connectivity" },
  "receipt_required": true,        // response_action_requires_governance_receipt
  "human_gated": true,             // StaticApprovalGate::destructive_action
  "governance_receipt_present": true,   // see §11.3 — the check the dispatcher runs
  "lease_on_grant": { "ttl_ms": 60000, "action": "isolate_host", "scope": "web-04" },
  "locator": { "daemon": "https://…:9090", "hold": "/v1/response/holds/hold:01JQ8Z3K9V7M2R4T" }
}
```

The field order in that body is the **fixed verdict-pane order** from render law 1:
`action` → `rehearsal.blast_radius` → `inverse` → `policy` → `lease_on_grant`. Keeping the
serialization order and the render order identical means a reviewer diffing a card against a
screenshot is checking one thing, not two.

**`hold_id` is opaque, revised.** The first draft proposed `hold:{hunt_id}:{held_at_ms}`. That
cannot be used, because §5.4 puts `hold_id` in a community-global ephemeral and `HuntId` is
the telemetry event id (`swarm-runtime/src/service/runtime_service.rs:391`) — a join key into
detection data. `hold_id` is therefore a random opaque token; the `hunt_id` lives in the hold
**body**, which is channel-compartmented.

**The two badge families are two fields, computed by the daemon, never by the console.**
`receipt_required` mirrors `response_action_requires_governance_receipt`
(`swarm-runtime/src/dispatcher.rs:1276-1292`); `human_gated` mirrors
`StaticApprovalGate::destructive_action` (`swarm-policy/src/static_gate.rs:37-53`). Both were
read line by line in this revision: they enumerate the **same twelve** variants —
`BlockEgress`, `IsolateHost`, `RevokeCredential`, `SinkholeDns`, `TerminateUserSession`,
`InjectFirewallRule`, `QuarantineFile`, `KillProcess`, `SuspendProcess`, `DisableUserAccount`,
`ForcePasswordReset`, `RemoveScheduledTask`. `inverse.executable` is the genuinely different
axis: `ContainmentInverse` has exactly three variants — `ReleaseQuarantinedFile`,
`ResumeProcess`, `RestoreHostConnectivity` (`swarm-response/src/rollback.rs:66-78`) — and the
mapping is non-obvious (`SuspendProcess` reversible, `KillProcess` not). Two badge families,
twelve and three; the third axis is `policy.rule_name`, which answers "which rule decided".

### 5.7 The write path: two legs, never conflated

```
Operator presses "Record my decision and send it to the daemon"
    │
    ├─ LEG 1 (relay): sign kind:9 + <!-- ambush:verdict:v1 -->
    │     h = case channel, e = the 46010 event id, p = requesting agent, k = verdict
    │     body = {hold_id, decision, rationale, decided_at_ms, operator}
    │     → a HUMAN INTENT RECORD. Not an authorization. Zero relay change.
    │
    └─ LEG 2 (daemon): POST /v1/response/holds/{hold_id}/decide  via invokeTauri
          body = {decision, rationale, nostr_intent_event_id,
                  signature: DetachedSignature}        ← §11.1b
          → daemon verifies the operator's Ed25519 signature, re-evaluates
            partition authorization, the governance receipt, and policy from
            scratch (§11.3), mints the CapabilityLease at DECISION time,
            then dispatches.
```

Leg 1 is idempotent and can be replayed; leg 2 is the only thing that can act. If leg 1
succeeds and leg 2 fails, the case timeline shows a signed human intent with no receipt after
it — the honest picture, rendered as "decision recorded, not yet dispatched", never
optimistically. If leg 2 succeeds and leg 1 fails, the daemon's record still holds the
decision; the console republishes leg 1 on reconnect from its spool.

`nostr_intent_event_id` is client-supplied and the daemon does not verify it. It is a
convenience cross-reference for the console, and no surface may present it as proof of
anything. The proof is the Ed25519 signature in the same body.

### 5.8 What we are not reusing

Buzz's `workflow_approvals` table has hard foreign keys to `workflows` and `workflow_runs`.
Storing an Ambush hold there needs a synthetic workflow and a synthetic run per held action.
The hold's durable home is the daemon's new `HeldActionStore` (§11.1), where the authority
already lives — the same single-writer argument ADR 0010 makes for containment release
(`crates/swarm-runtime-http/src/http/containment.rs:1-39`). The relay carries the conversation
and the notification; it does not carry the state machine.

The consumer half of Buzz's approval path is production-grade — token-hash lookup, expiry,
approver-spec authz, race-safe status flip, resume-from-step
(`buzz-relay/src/handlers/command_executor.rs:1020+`), plus Tauri
`grant_approval`/`deny_approval` (`desktop/src-tauri/src/lib.rs:773-774`). Perch keeps
`WorkflowRunTrace`, `StepProgress` and the approval card **as presentation** over Ambush's own
state machine, and runs none of `buzz-workflow`'s executor.

---

## 6. Ephemeral telemetry: the `26000` block

Ephemeral kinds `20000`–`29999` (`kind.rs:457-459`) take a separate ingest path with only a
`MessagesWrite` scope check and no per-kind allowlist
(`buzz-relay/src/handlers/event.rs:694-707`). Zero relay change.

Every ephemeral kind currently in use was enumerated: `20001`, `20002`, `22242`, `24134`,
`24200`, `24242`, `24243`, `24810`, `27235`, `28936`. The `26000` block is free.

| Kind | Source | Cadence | Scope | Payload |
|---|---|---|---|---|
| `26000` | `RuntimeEvent::Ingest` | 1 Hz aggregate | global | `{accepted, rejected, sources: {…}}` — counts only |
| `26001` | `RuntimeEvent::ConcentrationSnapshot` | **coalesced to 1 Hz** | global | `{current_mode, concentrations: [{threat_class, total_strength, distinct_sources, peak_confidence}]}` |
| `26002` | `RuntimeEvent::AgentHealth` | on change | global | `{agent_id, role, from, to}` |
| `26003` | `RuntimeEvent::ModeTransition` | on change | global | `{from, to, triggering_threat_class, reason}` |
| `26004` | `GovernanceStatusReport` | 1 Hz or on change | global | `{partition_state, total_governors, healthy_governors, quorum_threshold, active_contingency_leases, unauthorized_partition_actions}` |
| `26005` | `RuntimeEvent::TamperAlert` | on event | global | `{debugger_attached, tracer_pid, unexpected_library_count, fail_closed}` — **counts, not paths** |
| `26006` | `RuntimeEvent::ResponseHeld` | on event, never coalesced, never dropped | global, `p` = each Approve-scoped operator | `{hold_id (opaque), action_kind, severity, case_channel, expires_at_ms}` — §5.4 |

**Global, not channel-scoped — and why.** An ephemeral with an `h` tag gets a membership check
and channel-scoped fan-out (`event.rs:848-874`); one without goes down a `Uuid::nil()` sentinel
global path (`event.rs:877-903`) that reaches every subscribed member. Channel scoping would
mean the Watchfloor holds twelve subscriptions and still misses a Custom threat class, and
would collide with the symmetric scoping invariant (`subscription.rs:486-491`). One global REQ
is simpler and correct.

**Two rules govern this block, not one.**

*The payload rule.* Telemetry is visible to every member of the colony's Buzz community,
including members on no case. That is acceptable **only because** these payloads carry no host
id, no indicator, no finding id, no library path, and no non-opaque join key — just
threat-class aggregates, agent roles, governance counts, and the opaque hold token. Any field
added to a `26xxx` payload has to pass that test.

*The issuer rule — new in this revision.* Aggregate-only payloads bound the **disclosure**
risk; nothing in the relay bounds the **authorship** risk. The ephemeral gate is a single scope
test — `if !scopes.is_empty() && !scopes.contains(&Scope::MessagesWrite)`
(`event.rs:698-707`) — which every chat-capable member passes, and which passes outright when
`scopes` is empty. So any member, or any single compromised agent key, can publish a fabricated
`26003` mode transition to Incident and page the whole rotation, or a fabricated `26001` /
`26002` that paints the Watchfloor and the liveness roster, or a fabricated `26006` that puts a
phantom row in every queue. Binding controls:

1. A `26xxx` frame is **rendered only if its pubkey resolves to an admitted bridge identity**
   from the colony roster — the same admission check `08`'s INV-15 applies to marker cards.
   Frames from any other pubkey are counted and dropped, and the count is visible.
2. **Wake class 1 (mode transition to Incident) reconciles against the daemon before paging.**
   The ephemeral opens the fetch; the daemon's `current_mode` decides whether a phone rings.
3. `26006` is a nudge with no authority: it triggers `query_needs_action`, and a row appears
   only if the daemon-backed hold list confirms it (§5.2).

These belong on the INV list next to INV-15.

**Coalescing is mandatory for `26001`.** The runtime publishes a twelve-class
`ConcentrationSnapshot` every `CONCENTRATION_MONITOR_INTERVAL_MS = 100`
(`swarm-runtime-http/src/bin/swarm_detect.rs:40`) — 10 Hz, forever, at rest. Coalesce in the
bridge, before the IPC boundary, holding only the latest per threat class per second. React
`memo` is all-or-nothing and a fresh `concentrations` array every 100 ms defeats every
downstream memo in the Watchfloor.

---

## 7. Channel topology

| Concept | Buzz object | Identity | Lifecycle |
|---|---|---|---|
| **Lane** (12) | open NIP-29 channel | one per `standard_threat_classes()` entry (`swarm-runtime/src/escalation.rs:315-330`) | permanent; **topic rewritten only on an escalation-level transition** — §7.1 |
| **Case** | private NIP-29 channel | **the case id IS the channel UUID** | created on promotion; TTL-renewing |
| Case membership | `kind:39002` addressable, `d` = channel UUID | | re-authorized on every single delivery (`handlers/event.rs:116-217`) |
| Case metadata | `kind:39000`, `d` = channel UUID | carries `incident_id`, `hunt_id` in `about` | |
| Case notes | `kind:40100` canvas | one per channel | seeded from the incident on open |
| Correlation | NIP-10 reply thread | `e` tags | `thread_metadata` materializes `reply_count` / `descendant_count` / `last_reply_at` at ingest (`schema/schema.sql:513-530`) |

### 7.1 The lane topic is not a live gauge

The first draft said `PheromoneConcentration` "**also** rewrites the lane channel's `39000`
topic", and `04` restated it as "rewritten on each `ConcentrationSnapshot`, coalesced to 1 Hz".
**Withdrawn.** A NIP-29 topic change is not a cheap metadata poke. Traced end to end:

1. The client publishes `kind:9002` (`KIND_NIP29_EDIT_METADATA`), which has a real scope arm
   (`ingest.rs:506-517`) and is in `requires_h_channel_scope` (`:722`) — so it is stored.
2. `handle_edit_metadata`'s `"topic"` arm calls `set_topic` and then `emit_system_message`
   (`side_effects.rs:1549-1563`). `set_topic` has **no no-op guard** — it `UPDATE`s
   unconditionally (`buzz-db/src/store/channel.rs:557-578`).
3. `emit_system_message` signs a relay-keyed `kind:40099` and performs a **durable
   `insert_event` as its explicit "completion boundary"** (`side_effects.rs:771-804`), then
   fans out.
4. `handle_edit_metadata` ends with `emit_group_discovery_events`
   (`side_effects.rs:1731-1733`), which re-emits `39000`/`39001`/`39002` through
   `emit_addressable_discovery_event` → `replace_addressable_event`
   (`side_effects.rs:998-1046`) — each of which does a **read query plus an addressable
   replacement write**.
5. `40099` is in `CHANNEL_TIMELINE_CONTENT_KINDS` and `CHANNEL_EVENT_KINDS`
   (`kinds.ts:141, 108`), so it renders **its own timeline row**.

So one topic rewrite is: one stored `9002`, one stored `40099`, three addressable replacements
with a read apiece, one `refresh_channel_ttl_after_event_insert` per insert
(`schema/schema.sql:960-998`), and a Redis fan-out. Twelve lanes at 1 Hz is on the order of
24 durable inserts per second — roughly 2 million rows a day — plus a lane timeline that is an
unbroken scroll of "topic changed" rows burying the finding and escalation cards the lane
exists to show. Decay is continuous, so a change-detection guard does not save it. It also
blows the rate limit: `enforce_ws_admission` applies `agent_standard_messages_per_min` (120,
i.e. 2/s) per-pubkey to every EVENT frame with **no kind dispatch** —
`let is_event = matches!(msg, ClientMessage::Event(_))` (`buzz-relay/src/connection.rs:652-708`).

One correction to the objection as filed: `40099` is in `NON_CONVERSATIONAL_UNREAD_KINDS`
(`kinds.ts:155-168`), so it does **not** drive unread badges. It renders a row and costs a
write; it does not falsely mark channels unread. The write cost alone is disqualifying.

**Settled.** The lane's `strength / sources / threshold` readout renders from the ephemeral
`26001` frame the lane view is already subscribed to — **zero stored events**. The persisted
`39000` topic is rewritten only on an escalation-level transition (a `RuntimeEvent::Escalation`,
which is already a durable card and is rare and event-driven). `04` §2.5, the brief's surface 4
and `09`'s Lanes sizing note all follow this, and `07` §3's identity/rate table gains an
explicit line for lane topic writes with the escalation-driven number.

**TTL is a shipped channel property, not something to build.** `channels.ttl_seconds` and
`ttl_deadline` exist (`schema/schema.sql:102-103`), with a partial index on expiry
(`:116-117`) and a constraint trigger `refresh_channel_ttl_after_event_insert` (`:960-998`)
that pushes `ttl_deadline` forward on every event insert. That is exactly the semantics a case
wants: activity renews it, silence archives it. Set `ttl_seconds` at case creation from the
incident's severity; do not build a sweeper.

Channel creation goes through `KIND_NIP29_CREATE_GROUP = 9007`; membership through
`9000`/`9001`; metadata edits through `9002`. All are already allowlisted
(`ingest.rs:506-518`). Identities, since §2.2 leans on them: the bridge publishes under a small
fixed set — one per agent role for evidence, one telemetry identity, one **alarm** identity
that is the only key permitted to publish `46010` and `26006`, and one channel-admin identity
holding `ChannelsWrite` / `AdminChannels`.

**`ThreatClass::Custom(String)`** has no lane. Custom findings land in the nearest standard
lane and the card's fallback line says so verbatim: `custom:sphinx_memory → filed under
discovery`. Twelve fixed lanes; revisit only if a deployment ships custom classes in production.

---

## 8. Subscription filters, per surface

Buzz filters AND within a filter and OR across filters; `kinds: []` matches nothing, absent
matches everything; `#h` falls back to the stored `channel_id` **only** when the event carries
no `h` tag at all. Limits: 10 filters per REQ, `max_limit` 1000. **Every filter must name
`kinds` explicitly** or it trips the p-gate. And per §3, `#t`/`#l`/`#k` are post-filters: they
narrow what is *returned* from a fetched page, never what is *selected* by SQL, so every filter
below that uses one is annotated with its dilution risk.

| Surface | REQ filters | Notes |
|---|---|---|
| The Watch (`/`) — needs_action **live** | `{"kinds":[26006],"#p":["<me>"]}` | ephemeral; global sub. The **only** live path — §5.4. A channel-scoped `46010` cannot reach a filter-less-of-`#h` REQ (`subscription.rs:387-423, 486-491`). |
| The Watch — needs_action **authority** | `GET` the needs-action feed (`query_needs_action`) on connect, reconnect, and every `26006` | the row that renders; reconciled against the daemon hold list |
| The Watch — mention | `{"kinds":[9],"#p":["<me>"],"limit":100}`, partitioned client-side on `k` | an Escalate naming you. `#k` post-filters, so ask for depth and partition. |
| The Watch — activity | one channel-scoped filter per case you took: `{"kinds":[9,46010],"#h":["<case>"]}` | ≤10 filters per REQ ⇒ batch cases into REQs of ten |
| Case timeline | `POST /query` with `top_level: true`, one `#h` (`buzz-relay/src/api/bridge.rs:481-540`) | server-authoritative `has_more` via the `39006` bounds overlay; `39005` thread summaries appended free |
| Case live | `{"kinds":[9,46010,40100,40099],"#h":["<case>"],"since":<now>}` | no `#k` — receipt/lease sub-views partition the fetched page client-side |
| Lane | `{"kinds":[9],"#h":["<lane>"],"limit":200}` + `{"kinds":[26001]}` | the header readout comes from `26001`, not the topic (§7.1) |
| Watchfloor | `{"kinds":[26000,26001,26002,26003,26004,26005,26006]}` — **no `#h`** | global sub; the symmetric invariant means it receives nothing channel-scoped, which is the point |
| Governance strip | shares the Watchfloor REQ, reads `26004` only | 2 s debounce on degraded (`shared/api/useRelayConnection.ts`) |
| Leases | HTTP `GET /v1/operator/containment/leases` (poll 5 s) + `{"kinds":[9],"#h":["<case>"]}` partitioned on `k` | `remaining_ms`/`expired` are clock-derived and must come from the daemon's `observed_at_ms`, not from the card |
| Ledger | NIP-50: `{"kinds":[9,46010],"search":"<query>","limit":100}` | Buzz routes `search` filters to `buzz-search` Postgres FTS automatically; the row insert **is** the index update, so there is no consistency window. A `search` filter also disqualifies the fast COUNT path (`req.rs:892-895`). |
| Tuning bench | HTTP only — `/v1/operator/status` `alert_tuning` | |
| Gaps | static — `rulesets/evasion/attack-technique-catalog.yaml` | 18 techniques across 11 detectors (counted in the file) |

Two operational cautions inherited wholesale. A subscription can be evicted with a `CLOSED`
carrying a specific reason string; only `"channel access revoked"` is in the desktop client's
drop-set, so a naive client that treats every `CLOSED` as fatal will reconnect-storm during
case churn. And group-discovery events (`39000`/`39001`/`39002`) are channel-scoped in storage,
so case discovery is a historical REQ, never a live global subscription.

---

## 9. Derived versus served

The console computes things the runtime does not. Render law 4 says anything derived carries a
marker naming the function, the runtime's own snapshot is authoritative, and disagreement snaps
visibly with a reason row. Here is the exhaustive list for v1.

| Value | Source | Marking |
|---|---|---|
| Decay curve between snapshots | client interpolation of `strength(t) = confidence × 0.5^((t−timestamp)/half_life)` (`pheromone.rs:281-287`) | axis label reads **"interpolated between snapshots"**; the header number is the runtime's `total_strength` from the latest `26001` |
| Deposit slice for a threat class | `GET /v1/operator/pheromone/deposits` — **must** be post-suppression, post-evaporation, plus the resolved `ThreatClassPolicy` | if the client's summed curve and the served `total_strength` disagree by >2% (an invented tolerance, not an in-tree constant), render a reason row |
| Lane threshold headline | `26001` + the hydrated `ThreatClassPolicy` | marked `hydrated` — the escalation event does not carry it (§4.1) |
| `distinct_sources` | served | **never rendered bare.** `findings_to_deposits` sets `agent_id = "{agent}:{strategy}"` (`swarm-whisker/src/stream.rs:20-22`, used at `:46`) and `concentration_for` does `sources.insert(deposit.agent_id.0.clone())` (`swarm-pheromone/src/substrate.rs:1295`). One Whisker with four detectors reports four sources. Render **"4 sources / 1 agent"**, expandable to the ids grouped by real agent. |
| Suppression | server-side `is_suppressed_by_feedback` (`substrate.rs:1367-1380`) | the predicate is `state == Dismiss && marker_timestamp >= deposit.timestamp`, so a Dismiss retroactively removes **every deposit at or before the marker**. The verdict row previews what will be suppressed; the suppression then appears as an explicit timeline row. Dismiss is never a gesture. |
| `remaining_ms` | `ContainmentLease::remaining_ms` **saturates at zero** (`swarm-response/src/containment.rs:70-88`) | `expired` is a separate served boolean (`http/containment.rs:82-90`). Two facts, two rows. `expired: true` on a *listed* lease means the sweep tried and failed — a host is still contained. That is a loud state. |
| `lease_closed` / `fully_reversed` | served in the release response body (`http/containment.rs:129-145`) | read from the body, never from the HTTP status. A 200 with `lease_closed: false` means the inverse failed and the lease is deliberately still open. |
| `attestation_verified` | served, from `verify_release_attestation` (`swarm-runtime/src/containment.rs:235-268`) | means **"this attestation matches this body and names this subject"**, not "a governor we trust authorized this" — the function's own doc comment says a full re-attestation is not caught and "do not read `attestation_verified: true` as 'a governor we trust authorized this'" (`containment.rs:225-234`). `None` renders **UNATTESTED**. |
| Thread counters | materialized by the relay in `thread_metadata` at ingest | free; do not recompute client-side |
| Unread / read frontiers | Buzz `AppShellContext` (channel, thread, per-message) | reused as-is; feeds `/handoff` |

**Reconciliation rule.** Every derived value has a served counterpart or it is not rendered.
There is no third category of "the console's opinion."

---

## 10. History, backfill, replay

### 10.1 Sequence and gaps

Every envelope the bridge publishes carries `"seq": <u64>` in its body, monotonic per issuer.
Note precisely what this is and is not: it is the bridge's **own** counter, mirroring the shape
of `swarm-spine`'s chain discipline (`chain.rs:75-147`: first is `seq == 1`, continuation is
`head.seq + 1`) — it is **not** the spine chain, which §2.1 shows has one writer in the whole
workspace. The console tracks a head per issuer. A jump from 41 to 43 renders as an explicit
gap row — "1 envelope missing from `whisker-7a3f` between 14:02:11 and 14:02:19" — with a
button that re-fetches the interval from the daemon.

This is the mechanization of the brief's risk 1. Without it, the relay silently becomes the
record: a dropped frame is indistinguishable from a quiet minute, which in a threat-hunting
product is the worst possible failure mode.

### 10.2 The spool

`subscribe_runtime_events()` (`ingest/mod.rs:1874-1880`) hands back an
`Option<broadcast::Receiver<RuntimeEvent>>` over a channel of capacity 1024
(`runtime_events.rs:13`). Two loss modes, both handled: a `None` return means no broadcaster is
wired and the bridge must **fail loudly at startup**, not degrade to silence; and a lagged
receiver **drops silently**. The bridge's receive loop therefore does exactly one thing —
append to a disk spool — before any Nostr I/O, hydration fetch, or serialization. Spool entries
carry the issuer sequence, so a bridge restart resumes at the last acknowledged `OK` rather
than at the socket.

### 10.3 Cold start and backfill

A console opening a case does **not** replay the relay from the beginning. It does:

1. `POST /query` with `top_level: true, #h: [case], limit: 100` — one page, with the `39006`
   bounds overlay giving server-authoritative `has_more` and a composite `(created_at, id)`
   keyset cursor. A timestamp-only cursor cannot escape a second denser than one page; the
   composite one can.
2. Open the live REQ with `since: <now>`.
3. Hydrate the detail pane from the daemon on selection, not on load.

The Ledger's backfill is the same `POST /query` path with a NIP-50 `search` filter. The Watch's
queue backfill is `query_needs_action`, not a REQ (§5.4).

### 10.4 Replay of an Ambush replay

`ReplayBundle` is Ambush's own replay primitive and has nothing to do with relay backfill. The
receipt card's `locator.bundle_id` deep-links to `GET /v1/operator/replay?bundle_id=…`, which
returns the event, findings, deposits, request, rehearsal and trail as one object. The console
renders it in the auxiliary panel. It is never published; publishing it would inline a
`TelemetryEvent` plus every deposit into a signed relay event for no read anyone performs from
the timeline.

---

## 11. What the Ambush runtime must grow

Six surfaces, in build order. Item 1 gates everything else.

### 11.1 `HeldActionStore` + `RuntimeEvent::ResponseHeld` — the largest item

Today `PolicyVerdict::RequireHuman` in `RuntimeMode::LiveResponse` returns
`ApprovalError::Denied` (`crates/swarm-runtime/src/lib.rs:978-981`) and the instrumented path
records `AuditResponseRecord::Skipped { reason }` (`:1134-1145`). The human-approved path
`audit_authorize_and_execute_human_approved_instrumented` (`:1085-1092`) is reachable only from
two demo-gated call sites. **There is no hold.** Every other item on this list is a thin route;
this one is a new durable state machine.

```rust
pub struct HeldAction {
    pub hold_id: String,              // opaque token — NOT hunt-id-derived (§5.6)
    pub action_request: ActionRequest,
    pub rehearsal: Option<ResponseRehearsalPreview>,
    pub policy_decision: PolicyDecision,
    pub held_at_ms: i64,
    pub expires_at_ms: i64,
    pub decision: Option<HoldDecision>,
}
```

Persist a hold instead of `Skipped`. Emit `RuntimeEvent::ResponseHeld { emitted_at_ms, hold_id,
hunt_id, action_kind, severity, expires_at_ms }` — a **twelfth** `RuntimeEvent` variant, with a
matching `RuntimeEventKind` arm so the existing `?types=` filter grammar keeps working.

Until this lands, develop Perch against the E2E mock bridge with Ambush fixtures and **never
ship a demo that implies a working gate**.

### 11.1b Thread the operator into the audit chain — new, and not optional

The product's spine is "every human decision is a typed, signed act that becomes the quarter's
audit artifact". **No such record exists, and the brief's original five-item bill did not add one**
(it is `B2o` in `09` §3.1's reconciled eleven-item bill).
`ActionRequest` has five fields, none an operator (`swarm-policy/src/lib.rs:47-58`);
`ApprovalContext` has four (`:60-72`); `ResponseGovernanceAudit` carries
`governing_agent_id: AgentId` — Tom, not the human (`swarm-response/src/lib.rs:135-142`);
`AuditTrail` carries trail/hunt/receipt ids, detection, policy, response, timestamp
(`swarm-spine/src/lib.rs:113-122`);
`audit_authorize_and_execute_human_approved_instrumented` takes **no approver argument**, and
`allow_human_approved_execution` is a bare `bool` that only flips the `RequireHuman` arm
(`swarm-runtime/src/lib.rs:1085-1092`, `:1133-1136`). A granted destructive action is therefore
byte-indistinguishable in the durable record from an autonomous one, except that
`policy.verdict` reads `require_human`. An `operator_id` sitting only in the `HeldActionStore`
is not the chain.

Two changes, and both reuse machinery Ambush already ships.

**(a) The decide route takes a signature, not just a bearer token.** Ambush already has a
signature-bound human-decision primitive and the plan was about to replace it with a shared
env-var secret. `approval_vote_append_handler` (`swarm-runtime-http/src/http/approval.rs:130-141`)
requires `OperatorScope::Approve` and refuses `voter_id != principal.operator_id`;
`validate_and_append_vote` (`swarm-runtime/src/approval.rs:1296-1349`) verifies a
`DetachedSignature` over `vote_payload_bytes(set_id, ledger_id, voter_id)` and then requires
`voter_id == voter_id_from_public_key(&signature.public_key_hex)` (`:1331-1339`, with
`voter_id_from_public_key` at `:1783-1785` formatting `swarm:ed25519:{hex}`) — a cryptographic
binding between the human and the act. By contrast the bearer path is an opaque token read from
process env and compared with `!=` (`http/auth.rs:91-93`), shared per principal, rotatable only
by restart (`:63-79`). The decide body therefore carries
`signature: DetachedSignature` over canonical JSON of `{hold_id, decision, decided_at_ms}`, and
the handler runs the same two checks `approval.rs:1323-1339` already runs. Zero new crypto. The
Tauri process holds the operator's Ed25519 key beside the Nostr key, in the OS keyring.

**(b) The approver reaches the receipt and the chain.** Thread
`approved_by: Option<OperatorApproval>` — `{operator_id, decided_at_ms, hold_id, signature}` —
through `audit_authorize_and_execute_human_approved_instrumented` into `ResponseReceiptAudit`,
and wrap the fact in `build_signed_envelope` before it leaves the daemon, which is the same
one-call pattern `approval.rs:1810` uses and is what makes the chain real for this artifact.

Until (b) lands, `08` §6.4's export bundle and `01`'s positioning must not claim the audit
artifact answers *who approved this*. It answers *a human was asked*.

### 11.2 `POST /v1/response/holds/{hold_id}/decide`

`OperatorScope::Approve`. Body `{decision: "grant"|"deny", rationale, nostr_intent_event_id,
signature}`. Mints the `CapabilityLease` at **decision time** — `lease_ttl_ms` is 60000
(`rulesets/default.yaml:94`) and `ensure_active_lease` runs immediately before execution
(`swarm-runtime/src/lib.rs:1003`), so a hold-time lease is dead before a human reads the page.
Response mirrors the containment release response's honesty: the receipt, plus separate
`dispatched: bool` and `receipt_id: Option<String>` so a 200 never reads as "it happened".

Also add `GET /v1/response/holds` (list, for reconciliation after a bridge restart) and
`GET /v1/response/holds/{id}`.

### 11.3 What "re-evaluates from scratch" must actually mean

"The daemon" is not one authority, and the first draft treated it as one. Traced through the
real call graph, the **autonomous** path applies three checks in this order, and the first two
live in the `AgentDispatcher`, one layer *above* the runtime:

| # | Check | Where | What it does |
|---|---|---|---|
| 1 | `authorize_partition_request(&request)` | `swarm-runtime/src/dispatcher.rs:559-573` | refuses or flags the request under a governance partition; a failure `continue`s, dropping the action |
| 2 | `missing_governance_receipt_reason(&request)` | `dispatcher.rs:575-587`, defined `:1294-1310` | for the twelve receipt-required actions, pulls `evidence["governance_receipt"]`, deserializes a `ConsensusGovernanceReceipt`, and calls `.verify()`. Missing, malformed or bad-signature ⇒ the action never reaches the runtime. |
| 3 | `router.route_request(request)` → `SwarmRuntime::audit_authorize_and_execute_*` | `dispatcher.rs:588`, runtime at `lib.rs:1097+` | policy evaluate → guard → prepare containment → issue lease → execute |

A `POST /decide` that calls straight into the runtime enters at **step 3**, below governance
and beside the human. It would skip partition authorization and the governance-receipt
verification entirely — turning a human grant into the one path in the system that bypasses
the committee. **Binding: the decide handler runs steps 1 and 2 itself, by line number, against
the stored `HeldAction.action_request`, before it calls step 3, and renders each result
separately.** The hold card's `governance_receipt_present` field (§5.6) is the daemon's answer
to step 2 at hold time; the decide route re-runs it at decision time, and a grant that fails it
returns a `RefusedLate` naming the check — a normal outcome, never a client error.

### 11.4 `POST /v1/operator/findings/{finding_id}/feedback` — the loop

Body `{action: "confirm"|"dismiss"|"investigate", analyst_id, reason?, incident_id}`. Writes
the **same** `FalsePositiveMeasurement` (`swarm-spine/src/incident.rs:46`) that the Providence
webhook writes via `incident.upsert_false_positive_measurement(…)`
(`providence_handlers.rs:167-179`), and appends the same `AnalystFeedbackAuditEntry`.

`incident_id` is **required**, mirroring `SwarmProvidenceFeedbackRequest`
(`swarm-core/src/types.rs:144-152`), and the constraint that follows from it is stated in §4.3
and must be stated in `01` §1, `04`'s Verdict Row and the copy on the control: a verdict is
recordable only against a finding that belongs to an incident record.

This remains the whole argument. `build_alert_tuning_report` (`alert_tuning.rs:85`) ranks
`HostExclusionReview` / `DetectorThresholdReview` / `DetectorRuleReview` from those
measurements against thresholds 0.75 / 0.50 / 0.34 (`:6-15`). The only writers today are two
HMAC webhooks. The operator surface registers 49 routes and none accepts analyst feedback.
Ambush computes the answer to "was that alert real?" and has no door for a human to tell it.

### 11.5 `GET /v1/operator/pheromone/deposits`

A pass-through of `query_deposits(DepositQuery)` — the query struct already exists with
`{threat_class, since_timestamp, host_id, limit}` (`swarm-pheromone/src/substrate.rs:314-319`).
The response **must** return the post-suppression, post-evaporation slice plus the resolved
`ThreatClassPolicy`, or the console's curve disagrees with `swarmctl` and the operator learns
to distrust the screen. Include `total_strength` and `distinct_sources` computed by the same
`concentration_for` the runtime uses, so the client has a served number to reconcile against.
The path prefix is already established by `/v1/operator/pheromone/threat-class-configs`
(`http/state.rs:296`).

### 11.6 Gate `GET /v1/events/stream`

Unauthenticated today: `resolve_demo_scope` returns the caller's requested scope when no
`context_token` is present. It leaks tamper alerts with library paths, response executions with
receipt ids and policy verdicts, every finding, and arbitrary agent `details` JSON. Perch does
not use it — the bridge subscribes in-process — but fix it regardless. The shipped
server-rendered dashboard depends on it being open, so the fix and the dashboard's replacement
are one change.

### 11.7 What we are explicitly not adding — and the surface nobody has scoped

No JSON list endpoints for findings, cases, or leases beyond the above. Enumeration is what the
relay is for: `POST /query` with `top_level` windows, composite keyset cursors, and NIP-50 FTS
replaces the operator surface's missing pagination — where `limit_*` helpers truncate in memory
and **overwrite `total_count` with the truncated length**, so "50 of 4000" is unimplementable
today. Building that twice would be the mistake.

**`/v2/api` and `clients/python/` get a disposition here because no other document gives them
one.** `/v2/api` is a real six-path read surface mounted at
`swarm-ingest-runtime/src/ingest/mod.rs:2574` with a generated OpenAPI spec
(`src/bin/generate_platform_openapi.rs:82-170`) and a shipped generated Python client
(`clients/python/swarm-platform-client/`, ~20 model modules plus `smoke_platform_client.py`).
It is an **external contract that already polls**, and `load_platform_findings`
(`ingest/platform_api.rs:720`) calls `store.recent(usize::MAX)`. Perch does not use it and must
never be wired to it. Settled disposition: **frozen at its current shape — no new fields, no
new paths, not a Perch dependency, and not deprecated in v1** — because deprecating an external
contract is a separate decision with its own consumers. `02` restates this row in its
crate-verdict table; the wire-format consequence is only that no `ambush:*` marker, kind or tag
defined here is ever mirrored into `/v2/api`'s schema.

---

## 12. Rejected alternatives

| Rejected | Why |
|---|---|
| **A `47xxx` stored-kind family for Ambush artifacts** | Three kind registries plus four client registration points per kind (§3, §5.2), two relay forks per kind, zero degradation in Flutter/web/CLI, permanent merge pain against upstream `block/buzz`. Buys `#`-filterable fields the Ledger's FTS already covers. |
| **`kind:46030`/`46031` as the human verdict record** | `is_command_kind` (`kind.rs:815-826`) routes them to `command_executor::handle_command` (`ingest.rs:2278`), and `handle_approval_grant` rejects with `"invalid: approval not found"` when there is no `workflow_approvals` row (`command_executor.rs:1041-1045`). The event would never be stored. `ambush:verdict:v1` on `kind:9` instead. |
| **A REQ of `{kinds:[46010],"#p":[me]}` as the live queue** | The fork this document mandates makes `46010` channel-scoped, and global subscriptions never receive channel-scoped events (`subscription.rs:387-423, 486-491`). Ephemeral `26006` drives the live queue; `query_needs_action` is the authority. |
| **Rewriting the lane `39000` topic on each `ConcentrationSnapshot`** | Two durable inserts plus three addressable replacements per rewrite (§7.1), ~2M rows/day at twelve lanes × 1 Hz, 6–12× over the 120/min per-pubkey quota, and a lane timeline of "topic changed" rows. Render from `26001`; rewrite the topic on escalation transitions only. |
| **Publishing every `PheromoneDeposit`** | Estimated to double the volume of the busiest lane channel (from the one-finding-to-N-deposits shape of `findings_to_deposits`, not measured). The console never reads a single deposit; it reads slices and aggregates. |
| **`CorrelatedIncident` as a signed card** | A recomputed snapshot with mutable `included_members`/`rejected_members`. A frozen copy becomes a second record that drifts. The channel + canvas carries it — at the cost §4.3 now names. |
| **Nostr presence (`kind:20001`) for agent liveness** | Not for the reason first given: presence *does* PUBLISH cluster-wide (`event.rs:843-847, 884-891`). The disqualifier is the 180 s TTL lie window on a 60 s heartbeat (`buzz-pubsub/src/presence.rs:3,16`). `26002` from the health stream instead. |
| **NIP-OA `conditions` as per-kind authorization** | `verify_auth_tag` validates conditions for syntax and never sees the published event (`nip_oa.rs:214`); its relay consumers use only the returned owner. Clause syntax is AND-joined, so `kind=9&kind=26000` is unsatisfiable. Narrow by not giving sensor identities the ability to publish `46010` instead. |
| **Reusing `kind:7` reactions for Confirm/Dismiss/Investigate** | The tuning loop is fed by `ProvidenceFeedbackAction` string variants, and only `Dismiss` sets `false_positive: true`. A reaction is an emoji; `build_alert_tuning_report` would see nothing. |
| **Channel-scoping the telemetry ephemerals** | Twelve subscriptions, misses `Custom`, collides with the symmetric scoping invariant. Global with an aggregates-only payload rule **and an issuer rule** is simpler and safe. |
| **Storing holds in Buzz's `workflow_approvals` table** | Hard FKs to `workflows` and `workflow_runs` force a synthetic workflow per action. The authority is in the daemon; the state belongs with it. |
| **A decide route authenticated by bearer token alone** | `http/auth.rs:91-93` compares an env-var secret with `!=`; it is shared per principal and rotatable only by restart. Ambush already ships signature-bound human decisions (`approval.rs:1296-1349`). Use them. |
| **A `POST /decide` that enters at the runtime** | It would skip `authorize_partition_request` and `missing_governance_receipt_reason`, both of which live in the dispatcher (`dispatcher.rs:559-587`) — making a human grant the one path that bypasses governance. §11.3. |
| **`POST /events` (HTTP) as the bridge's write path** | Ephemerals and gift wraps are rejected on the HTTP bridge (`ingest.rs:2193`). The bridge needs the WebSocket anyway. |
| **A single "verified" badge** | Two chains, and per §2.1 most cards carry no Ambush signature at all. One badge means the transport signature has silently replaced an evidence signature that does not exist. |

---

## 13. The registry, and how it changes

| Slot | Value | Change control |
|---|---|---|
| Stored kinds forked into the relay | `46010` only — **two relay match arms, six registration points** (2 relay + 4 client, §5.2) | A third stored kind requires a written argument against the marker path, in this file, with the FTS and degradation costs priced. |
| Markers | `ambush:{finding,escalation,hold,verdict,receipt,lease,rollback}:v1` | An eighth needs the §4.4 justification shape: what an operator cannot reconstruct without it after the ephemeral has decayed. |
| Ephemeral kinds | `26000`–`26006` | New ones must satisfy **both** the aggregates-only payload rule and the admitted-issuer rule in §6. |
| Single-letter tags | `h`, `e`, `p`, `t`, `l`, `k`, `d` — of which only `h`, single `#p`, `#e` and `#d`-on-NIP-33 are pushed to SQL | Closed. Signed events cannot be re-tagged. No document may describe `t`/`l`/`k` as indexed selection. |
| New `RuntimeEvent` variants | `ResponseHeld` (twelfth) | Each needs a `RuntimeEventKind` arm so `?types=` keeps parsing. |
| New daemon routes | the six in §11 | Every write route goes to `swarm_detect --serve`. A second writer forks the audit chain (ADR 0010). |
| Frozen external contract | `/v2/api` + `clients/python/` | Frozen at current shape; not a Perch dependency; §11.7. |

Two housekeeping items block the first evidence card and are not deferrable: `MessageRow.tsx`
is at 998 lines against a hard CI cap and `AppShell.tsx` at 997/1000. The renderer registry has
to come out of `MessageRow` **before** the first `ambush:*` marker lands, because the marker
sniff goes in the default arm that is already there — and because `46010` needs a renderer arm
of its own (§5.2), which is a second entry into the same switch.

---

## 14. Still unverified, and what would settle it

| Claim | Status |
|---|---|
| Kinds `26000`–`26006` remain free | Every ephemeral kind currently in use was enumerated (`20001, 20002, 22242, 24134, 24200, 24242, 24243, 24810, 27235, 28936`), but nothing enforces the reservation against future upstream `block/buzz` allocations. |
| The 2% reconciliation tolerance between the client curve and the served `total_strength` | An invented default, not derived from any in-tree constant. Settle by measuring drift over one shift against `swarmctl`. |
| `hold_ttl_ms: 3_600_000` | `08` §3.6's settled default (60 minutes). No hold TTL exists in the tree; `HeldActionStore` does not exist. |
| The opaque `hold_id` format | Patterned on existing conventions (`bundle:`, `trail:`, `lease:`, `rollback:`) but no such format exists in tree. |
| "Publishing every deposit would double the busiest channel's volume" | An estimate from the one-finding-to-N-deposits shape of `findings_to_deposits`, not a measurement. |
| The relay `CLOSED` reason strings and the desktop drop-set | Carried from the buzz-protocol recon notes; not read directly this session. |
| The NATS JetStream `PheromoneSubstrate` backend's `query_deposits` behaviour | `07` read the in-memory and file-backed implementations (both route through `filter_deposits`); the JetStream one was not read. If it diverges on suppression or ordering, §11.5's contract needs re-checking. |
| Per-shift routing (`on_shift_operator_pubkeys`, `POST /v1/operator/watch/claim`) | Explicitly a **v2 proposal**, not a fact. Nothing in `OperatorPrincipal` or the config tree carries a shift concept today; §5.4's v1 answer needs none. |
