# ADR 0014: A Human Decision Is Two Legs, And The Console Cannot Authorize Because Of A Process Boundary

## Status

Proposed on 2026-08-30. **Revision 2** — two clauses changed; see *Revision history*.
Perch, Phase 1 (`B2`, `B2g`, `B2o`, `F3`).

Depends on ADR 0012 (the daemon is the only writer) and ADR 0013 (leg 1's carrier).
Constrains ADR 0016 (which chain a signature is on).

### Revision history

| Rev | What changed | Why |
|---|---|---|
| 1 | C1 gated `sign_event`; no clause covered two operators deciding one hold | — |
| **2** | **C1 is rewritten from one command to a property enforced across every signing command, with a CI rule that enumerates them.** **C4 is new**: concurrent decision is legitimate, the daemon arbitrates, and the losing console publishes a `superseded` update card. Fact 3 is expanded and Fact 5 is added | `grep 'signing_keys()'` over `desktop/src-tauri/src/commands/` returns 33 sites in 17 files, and `send_channel_message` takes a renderer-supplied `kind` **and** `content` — so revision 1's gate could be walked around two files over without touching the command it gated. Separately, `APPENDIX-NORMATIVE.md` §4 layer 1 `p`-tags every `Approve` principal, so two consoles can hold one open hold, and `kind:9` is immutable with no relay compare-and-set |

Path prefix convention as in ADR 0011: `BUZZ ` is `block/buzz` at `eed74bde2`.

## Context

The product's whole claim is that a human decision on a destructive action becomes a typed,
signed, auditable act. There are two obvious ways to build that and both are wrong.

The first is to let the console authorize: the operator presses a key, the console mints
the authorization, the daemon executes it. That makes a compromised renderer process — a
webview running ~100k LOC of inherited React — an authorization path for host isolation.

The second is to let the console *only* post to the daemon and record nothing itself. That
loses the human's own signature over their own intent, which is the artifact the auditor
actually wants, and it makes the record of deliberation identical to the record of
execution.

### Fact 1: the console holds no handle on anything that can authorize

`prepare_containment` (`crates/swarm-runtime/src/lib.rs:823-864`) is called before
`execute` on both response paths, in `swarm_detect --serve`. It reads
`self.containment` — a field on `SwarmRuntime` — and returns
`RuntimeError::ContainmentRefused` when it is `None` (`:836-844`).
`StaticApprovalGate::issue_lease` (`crates/swarm-policy/src/static_gate.rs:307-324`) sets
`expires_at_ms = context.now_ms + self.lease_ttl_ms` and
`capability_id = "lease:{hunt}:{action}:{now_ms}"`. `ensure_active_lease`
(`lib.rs:1369-1379`) then refuses a stale capability lease with
`ApprovalError::Denied("capability lease expired")` and a synthetic `lease-denied:…`
receipt.

Every one of those is an in-memory field of an object the console process does not have
and cannot obtain. There is no IPC, no route and no file that hands it out. That is the
boundary — not a rule someone might forget, and not a review convention.

### Fact 2: minting at hold time would break the gate arithmetically

`policy.lease_ttl_ms` is 60,000 (`rulesets/default.yaml:94`). A `CapabilityLease` minted
when the hold is *created* is expired roughly a minute later, long before a human opens
the page — so every grant would fail `ensure_active_lease` and the queue would be
unusable. The capability lease must be minted from the decision instant.
`demo_approval_resume_handler`
(`crates/swarm-ingest-runtime/src/ingest/demo.rs:1279-1425`) already does exactly this: it
builds an `ApprovalContext` with `now_ms` at the decision instant at `:1360-1365`, calls
`audit_authorize_and_execute_human_approved_instrumented` at `:1369`, and publishes
`RuntimeEvent::ResponseExecution` at `:1392`. It is B2's working prototype, minus
persistence and operator authentication, and it is gated by `state.demo_mode_enabled()` at
`:1284`.

Note the object an operator watches count down is a **different** object — the containment
lease, not the capability lease. The
`ContainmentLease`'s TTL is `runtime.containment.lease_ttl_ms`, default 900,000 ms
(`crates/swarm-core/src/config/defaults.rs:23-27`), and `rulesets/default.yaml` cannot set
it — that file is digest-signed and the block is absent by design
(`crates/swarm-core/src/config/runtime.rs:88-95`). Sixty seconds beside a
`ContainmentLeaseView` is wrong by 15×.

### Fact 3: the renderer holds **thirty-three** signing sites, not one, and an open egress

This fact is **expanded in revision 2.** Revision 1 named one command and built clause C1 on
it. Measured, that is a small fraction of the surface.

`sign_event` (`BUZZ desktop/src-tauri/src/commands/identity.rs:107-130`) is a
`#[tauri::command]` taking `(kind: u16, content: String, created_at: Option<u64>,
tags: Vec<Vec<String>>)`, resolving the operator's key inside the Tauri host process and
returning the signed event JSON to the webview. It is exposed as `signRelayEvent`
(`BUZZ desktop/src/shared/api/tauri.ts:597-605`). Any code in the React tree can ask it to
sign any kind with any content.

**It is not the only such command.** `grep -rn 'signing_keys()' desktop/src-tauri/src/commands/`
excluding `*_tests.rs` returns **33 call sites across 17 files** — every one a path on which
the operator's secp256k1 key signs something inside the host process at the renderer's
request. Three of those commands take the **kind itself** from the renderer:

| Command | Renderer-supplied | Why it defeats a `sign_event`-only gate |
|---|---|---|
| `sign_event` (`identity.rs:107-130`) | `kind: u16`, `content`, `tags` | the one revision 1 gated |
| `send_channel_message` (`messages.rs:409-424`) | `kind: Option<u32>` (`:420`), `content: String` (`:411`), plus six tag vectors | resolves `state.signing_keys()` at `:445` and signs. A renderer calling it with `kind: Some(9)` and a `content` whose first line is `<!-- ambush:verdict:v1 -->` produces a **signed, published, structurally valid verdict card without touching `sign_event` at all** |
| the project-owner announcement path (`project_git_workflow.rs:82-91`) | `ProjectOwnerAnnouncementInput { kind: u16, content, created_at, tags }` | a third generic `(kind, content, tags)` oracle. Whether it survives the deletion programme is ADR 0011's; while it exists it is the same hole |

The shipped CSP (`BUZZ desktop/src-tauri/tauri.conf.json:39`) ends its `connect-src` with bare
`https: http: wss: ws:` and carries a remote `script-src` host,
`https://cdn.jsdelivr.net/npm/@mediapipe/`, which exists for the animated-avatar capture
feature.

Together: a compromised renderer could forge an `ambush:verdict:v1` card for any hold —
manufacturing the evidence that a human deliberated — and post the whole verdict queue anywhere
on the internet. Neither is a new hole this project opens; both are holes this project's threat
model can no longer tolerate. **And the gate has to be drawn around the property, not around a
command name**, which is what revision 1 got wrong.

### Fact 4: the daemon does not currently re-derive governance on the human path

This is the fact that makes the second half of "the daemon re-evaluates from scratch" false
today. `AgentDispatcher`'s tick loop applies two gates before routing an action:
`authorize_partition_request` (`crates/swarm-runtime/src/dispatcher.rs:560`, defined at
`:1014`) and then, at `:575-587`,
`if !partition_authorized && let Some(reason) = missing_governance_receipt_reason(&request)`
— which logs a `warn!` and `continue`s, dropping the action with **no audit trail, no receipt
and no runtime event**. Only after both does it call `router.route_request` (`:589`), which is
`IngestRuntimeRequestResponseRouter::route_request`
(`crates/swarm-ingest-runtime/src/ingest/mod.rs:140-150`), the sole production entry into
`audit_authorize_and_execute`.

A `/decide` route entering at the last step skips both. And all three functions are private:
`missing_governance_receipt_reason` (`:1294`) and `response_action_requires_governance_receipt`
(`:1276`) are private free functions and `authorize_partition_request` is a private inherent
method, so no other crate can call them. The public surfaces are
`GovernanceAuthority::authorize_partition_request`
(`crates/swarm-policy/src/governance.rs:159-163`, already held on `IngestState` as
`Option<Arc<dyn GovernanceAuthority>>` at `ingest/mod.rs:1375`) or re-verifying
`request.evidence["governance_receipt"]` as a `ConsensusGovernanceReceipt` by hand.

### Fact 5: more than one console may legitimately hold the same open hold

`APPENDIX-NORMATIVE.md` §4 layer 1 `p`-tags **every** principal holding
`OperatorScope::Approve`, and §13's declined-amendment note confirms the watch claim does not
narrow that set. So two operators can be looking at the same open hold, and both can press the
second stroke.

The two legs behave differently under that race, and the asymmetry is the whole problem:

| | Leg 1 (relay) | Leg 2 (daemon) |
|---|---|---|
| Ordering | published **first** (`13-WIRE-SCHEMAS.md` §3.2's publish order — the `card` tag needs the leg-1 event id) | posted second |
| Concurrency control | **none.** The relay has no compare-and-set, and a `kind:9` event is immutable once accepted | `HeldActionStore::begin_decision` is a compare-and-set into `deciding` (`12-BACKEND-BILL-API.md` §3, D3) |
| Result of two operators | **two signed verdict cards, both permanent, both by real operators, in the same case channel** | exactly one winner; every other request gets `409` |

Left alone, the case channel — and the Ledger export's `holds/` directory — contains two
unqualified human-decision records for one hold, with nothing marking which one executed. The
losing console is also the **only** party that knows both which card it published and which
`409` it received, so no other component can repair it.

## Decision

**Every human decision is two legs, published separately, never conflated, and the console
is structurally incapable of performing the second one's job.**

**Leg 1 — the intent record.** A `kind:9` card carrying `<!-- ambush:verdict:v1 -->`,
signed with the operator's own secp256k1 key, published into the case channel with an `h`
tag equal to that channel's UUID. It records **what a named human decided, when, and on
what they were looking at**. It is not an authorization, is never described as one, and its
presence on the relay changes nothing about what the daemon will do.

**Leg 2 — the decision.** `POST /v1/response/holds/{hold_id}/decide`, `OperatorScope::Approve`,
over HTTP to `swarm_detect --serve`, carrying a bearer token that lives in the OS keyring
and is injected by a Tauri command. **The token never crosses the IPC boundary into the
webview** (`08` INV-22). The daemon re-evaluates policy from scratch, mints the
`CapabilityLease` at the decision instant, and dispatches or refuses.

**Four clauses make the boundary real rather than declared.**

**C1. No renderer-supplied content may be signed as a governance marker — on any command,
enumerated mechanically.** This clause is **rewritten in revision 2**; revision 1 gated
`sign_event` alone and Fact 3 shows that leaves at least two other paths to a signed verdict
card.

The gate is a pure function, `perch_sign_gate(kind, &content) -> Result<(), String>`
(`16-INVARIANT-TESTS.md` INV-29), which refuses `kind:46010` outright and refuses any `kind:9`
whose content's **line 0** (`trimEnd`, never `trimStart`) matches `^<!-- ambush:[a-z]+:v\d+ -->$`.
Three obligations, and the third is what makes it an invariant rather than a patch:

1. It is called on the **first line** of `sign_event`, before `state.signing_keys()`.
2. It is called on the same line of **every other command that signs renderer-supplied
   content**, which today means at minimum `send_channel_message` (`messages.rs:409-424`)
   and the project-owner announcement path (`project_git_workflow.rs:82-91`). A command
   that constructs its own content from typed arguments — a reaction, a profile update — does
   not need it and must not get it, because a gate on a path that cannot carry a marker is a
   gate nobody maintains.
3. **The enumeration is asserted, not remembered.** `check-perch-write-allowlist.sh` gains a
   rule: every `#[tauri::command]` in `desktop/src-tauri/src/commands/` that reaches
   `state.signing_keys()` **and** takes a parameter named `content` must call
   `perch_sign_gate` in the same function. The baseline is the 33 sites Fact 3 measured; a
   thirty-fourth that takes `content` and does not call the gate fails the build. Without
   this rule C1 is a claim about three files that a fourth file silently falsifies — which is
   precisely the defect the wave-2 red team found in revision 1.

The only producer of an `ambush:verdict:v1` card is a new, narrow Tauri command,
`perch_record_verdict`, which builds the card body from **daemon-fetched hold state** — not
from renderer-supplied JSON — and is therefore the one caller whose content never reaches the
gate as an argument. A kind allowlist alone is insufficient, because the verdict rides `kind:9`,
which is also every ordinary case message.

**C2. The CSP is a pinned string.** A string-equality assertion against
`tauri.conf.json`'s `security.csp`; bare `https:`/`http:`/`wss:`/`ws:` in `connect-src`,
and any remote `script-src` host, fail the build (`08` INV-30). **The animated-avatar
feature is deleted before the pin lands** — pinning the CSP with the remote `script-src`
host still present pins the hole. That ordering is a hard serialization in Phase 0.

**C3. `B2g` is what makes "re-derives authority from scratch" true, and cutting it has a
rendered consequence.** Either `/decide` routes through `route_request` beneath the two
dispatcher gates, or the two private functions move into a shared
`swarm_runtime::governance_gate` module that both the dispatcher and the decide path call.
Until one of those lands, **the verdict pane may not display `RECEIPT REQUIRED` as an
enforced fact** (`08` §0.2(a)). B2g is the only newly-added Rust item that is cuttable, and
this is the sentence that makes the cut visible on screen rather than silent.

**C4. Concurrent decision is legitimate, and the loser publishes an update card that says so.
New in revision 2.** Fact 5 makes two signed verdict cards for one hold reachable on shipped
semantics, so the design must name the state rather than assume it away.

- **The daemon arbitrates.** `POST /decide`'s compare-and-set is the single winner-selection
  mechanism; the relay is never asked to arbitrate anything (ADR 0012 clause 3). A console
  losing the race receives `409 hold_already_deciding` (with `Retry-After: 1`, because it will
  resolve) or `409 hold_already_decided`.
- **The losing console publishes an update card.** It publishes a second `ambush:verdict:v1`
  replying to its own first, with `leg2.state = "superseded"` carrying the winning
  `nostr_intent_event_id`. It is the only party that can: `ErrorResponse` is `{error, message}`
  and cannot carry the winner's id, so the console re-reads the hold to learn it
  (`12-BACKEND-BILL-API.md` §4.8's `deciding_intent_event_id`).
- **A verdict card with no matching daemon decision record is not the decision**, and any
  reconciler — the Ledger, the case timeline, the export bundle — renders it as a human intent
  record that did not execute, never as a decision. This is a rendering rule with teeth: without
  it the export's `holds/` directory answers "who decided this" with two names.
- **The window where this is unrepairable is real and bounded.** If the losing console is closed
  before it publishes the update, its card stands unqualified. The mitigation is the
  reconciliation rule above, not a promise that the update always lands.

`12-BACKEND-BILL-API.md` §4.4 and §4.8 own the daemon side and the `409` taxonomy;
`13-WIRE-SCHEMAS.md`'s `card-ambush-verdict-v1.schema.json` owns `superseded`, `superseded_by`
and `superseded_at_ms` (peer amendment PA-1); `16-INVARIANT-TESTS.md` owns the two-console P0
invariant. **This ADR owns only the rule that the loser must say so and that a card without a
daemon record is not a decision.**

**Two further properties follow and are binding.**

- **No optimistic UI on a governance path.** Grant, refuse, containment release and finding
  verdict each render three distinct states: *sending*, *recorded*, and
  *daemon-acknowledged-or-refused*. None of them has an undo affordance (`08` INV-33). A
  daemon `RefusedLate` after a grant renders as a normal outcome naming the rule, not as a
  client error (`08` INV-28). `superseded` (C4) is a fifth rendered state and is subject to the
  same rule: it is a distinct thing on screen, and it offers no retry.
- **The grant is two-stroke and structurally non-primary.** `G` arms and is ignored on
  `event.repeat`; a second stroke records it, disabled until the BLAST RADIUS block has been
  fully visible and the pane has held this `hold_id` for ≥ 1500 ms; arming resets when
  `hold_id` changes (`08` INV-11). The control never resolves to the default
  `buttonVariants()` (`BUZZ desktop/src/shared/ui/button.tsx:12-13`), which
  `AlertDialogAction` would otherwise give it by forwarding
  `cn(buttonVariants(), className)` (`BUZZ desktop/src/shared/ui/alert-dialog.tsx:149`).
  `event.repeat` guarding is already house practice — `useAppShellKeyboardShortcuts.ts:58-63`
  bails on it for all six existing chords.

## Alternatives Considered

**One leg: post to the daemon and let the daemon publish the record.** Simpler, one
network call, no divergence to reconcile, **and it dissolves Fact 5's race** — a real
advantage this revision has to weigh rather than ignore. Rejected anyway, because the artifact
the auditor wants is a signature **by the human**, over **their own intent**, made **before**
the outcome was known. A daemon-published record of a human decision is the daemon's word for
it. The two legs are also two failure domains: leg 1 succeeding and leg 2 failing is a real,
renderable state ("recorded, not yet acknowledged"), and it is more honest than either half
alone. C4 is the price of keeping that, and it is one enum value and a reconciliation rule.

**One leg: publish the card and let the bridge post it to the daemon.** Rejected: it makes
the relay an authorization path, which is exactly ADR 0012 clause 3 inverted, and it gives
the bridge — a write-only publisher — a reason to read.

**Publish leg 1 only after leg 2 succeeds, so a loser never publishes a card.** Tempting and
wrong. It destroys the property that makes leg 1 worth having: a signature made *before* the
outcome was known. It also loses the "recorded, daemon unreachable" state entirely, which is
the state a partitioned console must be able to show.

**Have the console mint the capability lease and the daemon merely honour it.** Rejected on
Fact 1 and
Fact 3 together. It is the design that makes a webview compromise a host-isolation capability.

## Consequences

### Positive

- "Perch never authorizes" is a property of process topology. It survives a renderer
  compromise, a malicious dependency, and a future contributor who has not read this file.
- A stalled or refused leg 2 is visible rather than silent, because leg 1 already exists
  and says what was intended.
- Minting at decision time makes the capability lease's own TTL provable from the receipt:
  `expires_at_ms − issued_at_ms` equals the configured TTL measured from the decision.
- C1's third obligation turns "we gated the signing command" into a property CI re-measures on
  every commit, which is the only form in which it survives the deletion programme.

### Negative

- Two writes means a divergence state, and the console must render all three cases
  (`07` §5.6). It also means leg 1 can exist for a decision the daemon refused — which is
  correct and must read as "recorded, refused by the daemon, here is the rule", never as an
  error.
- **Two operators means a fourth divergence state** (C4), a fifth `leg2.state` value, and a
  reconciliation rule every consumer of the case timeline has to implement. This is a real cost
  of the two-leg design and it was missed in revision 1.
- **A grant on a containment action fails on the shipped configuration.**
  `ContainmentSettings.lease_store_path` defaults to `None`
  (`crates/swarm-core/src/config/runtime.rs:94-95`), whose own doc says a restart "FORGETS
  every open containment and no sweep will ever release it". With no store,
  `prepare_containment` returns `ContainmentRefused` for all four containment actions
  (`is_containment_action`, `crates/swarm-runtime/src/containment.rs:54-63`:
  `QuarantineFile | SuspendProcess | IsolateHost | TerminateUserSession`). So a granted
  `isolate_host` fails **at the decide route** unless a deployment sets the path. `/decide`
  must return a typed refusal for this, not a 500, and `/leases` must render
  "no containment lease store configured" as a first-class state. This is a deployment
  prerequisite nobody budgeted and it belongs in the demo checklist.
- Deleting animated avatars becomes a prerequisite of a security control rather than a
  cleanup task, which moves it into the blocking deletion track.

## Verification

- `08` INV-11, INV-22, INV-28, INV-29, INV-30, INV-33 are the executable form of this ADR.
  `16-INVARIANT-TESTS.md` owns their implementations.
- **PROPOSED** a Rust test over the Tauri command surface asserting `perch_sign_gate` rejects
  `kind:46010` and any `kind:9` whose first line matches `^<!-- ambush:[a-z]+:v\d+ -->$`, and
  that it agrees with the renderer's `parseAmbushMarker` in **both** directions.
- **PROPOSED, and it is the one that closes revision 1's hole:** an inventory test in the shape
  of `egress_guard_tests.rs` asserting that every `#[tauri::command]` reaching
  `state.signing_keys()` with a `content` parameter calls `perch_sign_gate`. The negative
  control is a fixture command that signs `content` without the call and must fail. A test that
  only checks the three known commands would pass on the day a fourth is added, which is the
  day it matters.
- **PROPOSED** an integration test that grants a hold whose capability lease was minted at hold
  time and asserts `ApprovalError::Denied("capability lease expired")` — the fixture that proves
  Fact 2 rather than asserting it.
- **PROPOSED** an integration test that grants `isolate_host` with
  `lease_store_path: None` and asserts a typed refusal, not a 500.
- **PROPOSED (P0), two consoles, one hold** — `16-INVARIANT-TESTS.md`'s: both publish leg 1;
  both `POST /decide`; assert exactly one daemon decision record; assert the loser received
  `409 hold_already_deciding` or `409 hold_already_decided`; assert the loser's re-read names the
  winner; assert the loser publishes `superseded` carrying the winner's
  `nostr_intent_event_id`; and assert the case timeline renders the loser's first card as an
  intent record that did not execute.

## Follow-On Work

- `12-BACKEND-BILL-API.md` §4–§6 owns `/decide`, its `409` taxonomy, B2g's shape and B2o's
  `approved_by` threading. This ADR owns only the boundary and C4's rule.
- B2o is uncuttable for a reason worth restating here: today a granted destructive action
  is byte-indistinguishable in the chain from an autonomous one, except that
  `policy.verdict` reads `require_human`. `ResponseReceiptAudit`
  (`crates/swarm-response/src/lib.rs:118-142`) has exactly two fields, `policy` and
  `governance`, and `ResponseGovernanceAudit.governing_agent_id` is Tom — the governance
  agent, not the human. Nothing on the receipt names a person.
- Decide where the operator's leg-1 signing key comes from and whether it is the same key
  the relay knows them by. ADR 0016 owns the chain question; the provisioning question is
  open.
- C1's third obligation needs `check-perch-write-allowlist.sh` to gain a rule it does not have
  today. That script is PROPOSED in both repositories, and per `tools/check-gates-wired.sh` it
  must land with its workflow `run:` step in the same commit.
