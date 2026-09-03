# Trust, governance, and the UX of letting software act

Ambush can isolate a production host, kill a process, and revoke a credential. Perch is where
a human says yes. This document specifies that moment end to end — what evidence is shown, in
what order, with what timer, with what friction, and what happens when nobody answers — and
then argues the other direction: the enumerated ways a console can *weaken* a fail-closed
system, with a named control for each. It ends with the backend work this document's claims
depend on, and an invariant list written so each line can become a test.

The premise every section returns to: **Perch is never an authorization path.** It publishes a
signed human intent record and posts a decision. `swarm_detect --serve` re-evaluates and
dispatches. Everything below is about making the human's half of that exchange honest, not
about making the console powerful.

**Two corrections to the earlier draft of this document, stated before anything else, because
every claim downstream inherits them.** Red-team review was right on both and the citations
below are all re-read at the line.

1. **The daemon does not re-evaluate governance on any path a decide route can reach.** The
   earlier draft said it did, in the preamble and in the §3.2 state machine. It does not.
   Governance-receipt enforcement and partition authorization live one layer *above* the
   runtime, in `AgentDispatcher`'s agent-turn loop, and are unreachable from
   `audit_authorize_and_execute_human_approved_instrumented`. See §0.
2. **Four of the seven marker card types — finding, escalation, hold, lease — carry no Ed25519
   signature at all.** The earlier draft's
   §6.3 "offline verification runs three separately-reported checks" and §6.4's byte-identical
   bundle assumed a signed-fact chain that has exactly one producer in the workspace, and it is
   the approval ledger. See §0 and §6.

Both are now stated in the sections that made the wrong claim, both have a named backend item
in §8, and both gate specific UI claims until that item lands. A console that asserts a check
the daemon does not perform is worse than a console with no badge.

---

## Decisions made here

1. **The enforcement trace is published, per check, with call sites.** §0 answers three
   questions for every load-bearing citation in this document: who calls it, what process it
   runs in, and what it does to the data. Where the answer is "nothing", that is stated in the
   same sentence as the citation.
2. **The mode indicator is derived, not served**, and renders with a derived-marker naming the
   three runtime facts it is computed from. `docs/CONSENSUS.md:27` says "four governance modes"
   and then tables five (`:31-35`); no Rust enum carries them. See §1.
3. **Two badge families, not one, and a third axis that is a sentence, not a badge.**
   Human-gated/receipt-required is the *same* set of twelve (`static_gate.rs:37-53` ≡
   `dispatcher.rs:1276-1292`); reversibility is a *different* set of three
   (`rollback.rs:66-78`, resolved at `:151-192`). The third axis — which rule decided — renders
   as the rule's own `rule_name`. See §2.
4. **`RECEIPT REQUIRED` is not rendered as an enforced fact until B1.5 lands.** Today the
   twelve-action receipt requirement is enforced only on the autonomous dispatcher path. The
   verdict pane renders the honest interim string naming both call sites. See §0 and §3.3.
5. **The verdict pane has a fixed field order that never varies by action type**, and every
   field has a defined "we could not compute this" rendering. See §3.3.
6. **The `CapabilityLease` is minted at decision time by the daemon**, never at hold time
   (`rulesets/default.yaml:94` sets `lease_ttl_ms: 60000`). See §3.4.
7. **`hold_ttl_ms` is settled at `3_600_000` (60 minutes)**, and `03-DOMAIN-EVENT-MAPPING.md`
   §5.6's worked hold body and `04-SURFACES-AND-UX.md` §3.0's constant table are amended to match.
   The earlier 15-minute default is withdrawn everywhere. See §3.6.
8. **Snooze does not apply to a hold.** Buzz's five presets start at 30 minutes
   (`timePresets.ts:31-43`, verified) and a hold is a live gate with its own clock. The queue
   *is* the reminder. The cheap escape from a hold is `R` (Refuse), which is one keypress and
   the safe direction. See §3.5.
9. **The verdict keymap is `C`/`D`/`I` for findings and `G`/`R` for holds**, adopting
   `04-SURFACES-AND-UX.md` §3.0 wholesale. `A` is forbidden by render law 6 and is added to the
   copy ban list. This document's earlier `A`/`D` map is withdrawn: under it `D` meant Refuse on
   a hold row and Dismiss on the finding row directly below it, and Dismiss retroactively
   removes deposits from the concentration sum. See §3.5.
10. **The grant is two-stroke and blast-radius-gated, in the row — not a modal.** This replaces
    the earlier scroll-gated modal, which contradicted 04's row wireframe and the brief's
    "approval-as-a-row". The friction survives; the separate surface does not. See §3.5.
11. **Deny has no undo toast.** `07-REALTIME-AND-DATA.md` decision 8 forbids optimistic UI on
    governance paths, and an undo window on the *safe* direction is the exact habituation shape
    §7.1 exists to prevent. Refuse renders sending → recorded → daemon-acknowledged. See §3.5.
12. **A hold that reaches its TTL undecided expires as a typed outcome and is not executed.**
    Nobody-is-watching is fail-closed and is a *rendered* state, not a silent drop. See §3.6.
13. **Release reads `lease_closed` and `fully_reversed` from the body, never the HTTP status**
    (`http/containment.rs:192-210`, computed at `:224-228`). `remaining_ms` and `expired` render
    as two separate facts (`ContainmentLeaseView` at `http/containment.rs:73-88`; saturation at
    `swarm-response/src/containment.rs:275-278`). There is no "extend". See §4.
14. **Verification renders a tier, not a checkmark.** Three tiers: envelope-only (no Ed25519
    over the body — today's state for finding, escalation, hold and rollback cards), detached
    Ed25519 over the body (governance receipts, pheromone deposits), and spine-chained (exists
    only after B1.7). Every badge names its chain *and* its tier. See §6.2–§6.3.
15. **Attacker-controlled strings render in a hardened frame, and the allowlist is inverted.**
    A dangerous-field list fails open on the next field added; Perch keeps a *trusted-string*
    allowlist instead and requires `<AdversaryString>` for everything else. The threat is the
    remark autolinking pipeline, not emphasis. See §7.7.
16. **The CSP is not tight today and Perch must tighten it in Phase 0.** The shipped
    `connect-src` ends `https: http: wss: ws:` (`tauri.conf.json:39`, read verbatim). The
    earlier draft claimed the opposite. See §7.4.
17. **Governance kinds never go through the generic `sign_event` oracle.**
    `sign_event(kind, content, created_at, tags)` (`commands/identity.rs:107-135`) signs
    anything the webview asks for with the operator's key, and is exposed as `signRelayEvent`
    (`tauri.ts:596-604`). A compromised renderer can therefore forge the deliberation record.
    See §7.6.
18. **Exactly four notification classes may wake someone at 03:00**, and the admission rule that
    protects them extends to `kind:46010`, not only to marker cards. See §7.2 and §7.7.
19. **No role-based UI gating claims.** `OperatorScope::Read` is checked on zero handlers.
    `review_session_create_handler` (`http/review.rs:204-221`) has no scope check at all. See §7.5.

---

## 0. What is actually enforced, and by whom

This section exists because the review's sharpest observation was structural: the citations in
this plan are real and the inferences drawn from them were not. `envelope.rs:71` exists — it has
one caller. `dispatcher.rs:1276` exists — it runs in a different loop than the decide route
enters. So, for every check this document leans on: **who calls it, what process it is in, and
what it does to the data.**

### 0.1 The enforcement trace

| Check | Function | Non-test call sites | Runs in | Reachable from `POST /decide`? |
|---|---|---|---|---|
| Policy verdict | `ApprovalGate::evaluate` via `audit_authorize_and_execute_instrumented_internal` (`swarm-runtime/src/lib.rs:1097`) | every runtime execution lane | daemon runtime | **yes** |
| Guard rejection | `evaluate_guard_rejection` (`lib.rs:1150` region, called on the Allow/RequireHuman arm) | internal | daemon runtime | **yes** |
| Containment preflight | `prepare_containment`, then `ensure_active_lease(&lease, context.now_ms)` (`lib.rs:1003`) | internal | daemon runtime | **yes** |
| Scope rate limit | `ConfigurableApprovalGate` window (`static_gate.rs`, `max_actions_per_scope_per_minute: 5`, `rulesets/default.yaml:96`) | inside `evaluate` | daemon runtime | **yes** |
| **Governance receipt required** | `missing_governance_receipt_reason` (`dispatcher.rs:1294-1310`) | `dispatcher.rs:576`, `dispatcher.rs:671` — **two, both inside `AgentDispatcher`'s agent-turn routing loop** | dispatcher | **NO** |
| **Partition authorization** | `authorize_partition_request` (`dispatcher.rs:1014`, delegating to `GovernancePolicy`) | `dispatcher.rs:560` — **one** | dispatcher | **NO** |
| Governance *decoration* | `decorate_receipt_with_governance` (`lib.rs:935-949`) → `verified_governance_receipt` (`lib.rs:777-806`) | `lib.rs:1014`, `:1208`, `:1253`, `:1309` | daemon runtime | yes — **but it never refuses**: absent, malformed, or `verify()`-failing receipts return `None` with a `tracing::warn!` and execution proceeds |
| **Operator identity in the audit chain** | — | none | — | **does not exist** |
| **Ed25519 signature over a published fact** | `build_signed_envelope` (`swarm-spine/src/envelope.rs:71`) | `swarm-runtime/src/approval.rs:1810` — **one**, the approval ledger | approval ledger | **NO** |
| **Chain-link verification** | `verify_chain_link` / `ChainLinkVerdict` (`swarm-spine/src/chain.rs:75`, `:20`) | **zero** outside `swarm-spine`; only the re-export at `swarm-spine/src/lib.rs:61` | — | **NO** |

Grep basis for the four bolded zeros/ones: `grep -rn "missing_governance_receipt_reason\|
authorize_partition_request\|build_signed_envelope\|verify_chain_link" --include="*.rs" crates/`,
excluding `vendor/reference/clawdstrike/` (a reference tree, not a build input, per
`docs/VENDOR-REFERENCES.md`).

### 0.2 What follows, stated as three UI consequences

**(a) A granted hold dispatches whether or not a governance receipt is present.** The only
runtime entry point a decide route can call is
`audit_authorize_and_execute_human_approved_instrumented` (`lib.rs:1085-1092`) →
`audit_authorize_and_execute_instrumented_internal` (`:1093`), which never calls
`missing_governance_receipt_reason`. The existing demo path proves the shape:
`ingest/demo.rs:1370-1381` calls it directly with a `pending.request` and no receipt check.
**Until B1.5 lands, the verdict pane may not render `RECEIPT REQUIRED` as an enforced fact.**
It renders instead:

```
WHY WE ARE     receipt-required on the autonomous path (dispatcher.rs:576, :671)
ASKING         NOT ENFORCED on the human-decision path — see §8, B1.5
```

That is ugly on purpose. A badge that claims a check nobody runs is the single most dangerous
string this console can print.

**(b) A granted destructive action is byte-indistinguishable in the audit record from an
autonomous one.** `ActionRequest` has five fields — `hunt_id`, `requested_by: AgentId`,
`action`, `severity`, `evidence` (`swarm-policy/src/lib.rs:47-58`). `ApprovalContext` has four,
none an operator (`:61-72`). `ResponseReceiptAudit` carries `ResponsePolicyAudit`
(verdict/rule_name/reason) and `ResponseGovernanceAudit` (`governing_agent_id: AgentId` — Tom,
not the human) at `swarm-response/src/lib.rs:118-142`. `AuditTrail`
(`swarm-spine/src/lib.rs:113-122`) carries trail id, hunt id, receipt ids, detection, policy,
response, timestamp. `audit_authorize_and_execute_human_approved_instrumented` takes no
approver argument; `allow_human_approved_execution` is a bare `bool` that only flips the
`RequireHuman` arm (`lib.rs:1133-1145`). The *only* thing distinguishing a granted action in the
chain is that `policy.verdict` reads `require_human`. **Until B1.6 lands, §6.4's export bundle
and any positioning copy must say the chain answers "a human was asked", never "who approved
this".** The operator id lives in the new `HeldActionStore` (`03` §11), which is not the chain,
is not hash-linked, and whose `nostr_intent_event_id` is a client-supplied string.

**(c) Four of the seven marker card types carry no signature to verify.** Measured against the
types. Note which four: `finding`, `escalation`, `hold` and `lease` can carry none under any
condition today. `receipt` and `rollback` carry one *conditionally*, and `verdict` carries one
only after B1.6 — an earlier draft of this table put `rollback` in the unconditional four, which
contradicted `04` §6.3's accepted rebuttal and §6.2's own tier table.

| Marker card | Underlying type | Signature over the body? |
|---|---|---|
| `ambush:finding:v1` | `DetectionFinding` — 7 fields (`swarm-whisker/src/detector.rs:50-59`); `SwarmFindingEnvelope` — 8 fields (`swarm-response/src/siem.rs:17-27`) | **none** |
| `ambush:escalation:v1` | `EscalationRecord` (`swarm-core/src/pheromone.rs:237+`) | **none** |
| `ambush:hold:v1` | `HeldActionStore` record (proposed, `03` §11) | **none as specified** |
| `ambush:rollback:v1` | `RollbackReceipt` (`swarm-response/src/rollback.rs:243-263`) — carries `origin_receipt_id`, `governance_receipt_id: Option<String>` **and** `governance_attestation: Option<Value>`, which when present is a serialized `ConsensusGovernanceReceipt` over this receipt's canonical form with the field cleared | **none of its own, but tier 1 when attested** — `verify_release_attestation` (`swarm-runtime/src/containment.rs:235-268`) checks the signature *and* the subject binding and is actually called at `http/containment.rs:219`. `04` §6.3 rebutted the earlier draft here and the rebuttal is accepted. |
| `ambush:receipt:v1` | `ResponseReceipt` (`swarm-response/src/lib.rs:99-116`) — no signature; `audit.governance.receipt` is an untyped `Option<serde_json::Value>` (`:136-142`) whose payload *is* a `ConsensusGovernanceReceipt` | **only when a governance receipt is attached** |
| `ambush:lease:v1` | `ContainmentLeaseView` (`swarm-runtime-http/src/http/containment.rs:70-90`) | **none.** The attestation lives on the release/rollback receipt, not on the lease card. |
| `ambush:verdict:v1` | the operator's decision (`03` §5.5) | **none until B1.6**, then a detached Ed25519 signature over canonical `{hold_id, decision, decided_at_ms}` |

The two objects that *are* routinely Ed25519-signed are `PheromoneDeposit.signature`
(`swarm-core/src/pheromone.rs:231-232`) — which `03` §4.1 rules is never individually published
— and `swarm-consensus` receipts (`ConsensusGovernanceReceipt::verify` at
`swarm-consensus/src/lib.rs:428-446`). ADR 0010 says the rest out loud, at `:140-144`: the
`verify()` semantics are shared with the dispatcher and **"nothing checks chain linkage"**.

So §6.3's three-check verification is not a description of today; it is a description of what
B1.7 makes possible. Until then Perch renders **tier 0** on those four card types and its
"verify" affordance re-fetches from the daemon rather than checking a signature that is not
there. §6.2 specifies the three tiers and their exact copy.

### 0.3 Terminology ruling: "queue", not "lane"

`06-COPY-AND-VOICE.md` bans the bare word "lease" because `CapabilityLease` and
`ContainmentLease` are unrelated objects sharing one word (`06` §2). The set then applied its
own rule to the domain's vocabulary and not to its own: "lane" currently means a threat-class
channel (`04`, `03`), an inbox category (`04`, `06`), a colour family (`05`), and a bridge
transport class (`07`).

This document adopts the narrow sense and uses no other:

- **lane** — one of the twelve standing threat-class channels from `standard_threat_classes()`
  (`escalation.rs:315-330`). This is the operator-visible nav label and it keeps the word.
- **queue** — one of The Watch's four categories (`needs_action`, `mention`, `activity`,
  `agent_activity`). Everywhere this document previously wrote "the `needs_action` lane" it now
  writes "the needs-action queue".
- 05's hue taxonomy and 07's transport classes need their own words; naming them is those
  documents' call, not this one's.

`tools/check-copy-banned-terms.sh` gains bare `lane` outside the twelve-channel nav sense,
alongside bare `lease` and the banned control label `Approve`.

---

## 1. The five governance modes as UI states

The modes are a documentation contract, not a type. `docs/CONSENSUS.md:27` reads "The active
runtime uses four governance modes" and the table immediately below it (`:29-35`) has five
rows. There is no `GovernanceMode` enum in the workspace. What *does* exist as typed runtime
state is narrower and more useful:

| Typed fact | Source | Values |
|---|---|---|
| `RuntimeMode` | `swarm-runtime/src/lib.rs` (matched at `:979`, `:1133`) | `DetectOnly` \| `LiveResponse` |
| `PartitionState` | `swarm-policy/src/governance.rs:49-54` | `Healthy` \| `Degraded` \| `Partitioned` \| `Healing` |
| `SwarmMode` | `swarm-core/src/agent.rs` (carried on `RuntimeEvent::ModeTransition`) | `Normal` \| `Alert` \| `Incident` |
| `GovernanceStatusReport` | `governance.rs:62-71` | 8 fields incl. `active_contingency_leases`, `unauthorized_partition_actions` |

So the five-row table is a *projection* over three independent facts plus a static config
value (`operator_surface.enabled`). Perch renders that projection — and, under render law 4,
marks it as derived and names the function. The mode chip reads `guarded response` with a
small caret; the caret opens a three-row panel showing `RuntimeMode`, `PartitionState`, and
`SwarmMode` verbatim with their own timestamps, plus the sentence *"Mode is computed by
`derivePerchGovernanceMode()`; the runtime does not serve this value."*

The projection:

| Mode chip | Derived when | Verdict queue | Grant control | Lease board | Watchfloor |
|---|---|---|---|---|---|
| **Observation** | no destructive action has ever been held, or `RuntimeMode != LiveResponse` | empty, links `/gaps` | absent | empty state naming zero open leases | full |
| **Guarded response** | `LiveResponse` + `PartitionState::Healthy` + no receipt-required action pending | live | live | live | full |
| **Receipt-backed response** | as above, and the selected hold's action is one of the twelve at `dispatcher.rs:1276-1292` | live | live, with the governance strip pinned in the pane and the B1.5 caveat from §0.2(a) | live | full |
| **Partition contingency** | `PartitionState::Partitioned` or `Healing` | live, banner: destructive dispatch fails closed unless a **contingency lease** covers it — and if one does, **no governance receipt is required or expected** (`dispatcher.rs:575-577`) | live but relabelled — see §5.3 | live, contingency leases visually distinct, `UNATTESTED` rendered in its *designed* sense (§6.2) | full |
| **Maintenance-only** | operator principal holds `Maintenance` and the shift is flagged for maintenance | live, read-only | **absent** | release enabled | full |

Two things this table is careful *not* to say. It never claims maintenance mode widens
authority — `docs/EVOLUTION.md:127` is explicit that no review action bypasses a gate, and the
maintenance chip's tooltip quotes it. And **Partition contingency does not disable the grant
button.** The daemon decides; Perch's job is to tell the operator that their grant is likely
to be refused and why, not to pre-refuse it. A console that guesses the daemon's answer and
hides the control teaches operators that the console's model is authoritative — which is the
exact belief that later gets someone killed by a stale cache.

**The partition row carries a correction.** The earlier draft treated `UNATTESTED` as an
anomaly everywhere. It is not: `dispatcher.rs:575-577` reads

```rust
if !partition_authorized
    && let Some(reason) = missing_governance_receipt_reason(&request)
```

so an action redeemed against a contingency lease routes **with no governance receipt, by
construction**. Every receipt and lease it produces will be `UNATTESTED`, and that is the design
working. §6.2 gives `UNATTESTED` two renderings so an operator who has learned "unattested means
somebody misconfigured governance" does not misread the one state where it means "governance was
partitioned and a contingency lease was spent".

---

## 2. The taxonomies, and correcting the record

**The panel error.** Three judges asserted "3 receipt-gated actions". It is false, and the
falsification is a two-file diff, re-read at the line for this revision:

- `swarm-policy/src/static_gate.rs:37-53` — `destructive_action()` matches twelve variants
  (`:40-51`).
- `swarm-runtime/src/dispatcher.rs:1276-1292` — `response_action_requires_governance_receipt()`
  matches **the same twelve**, in the same order.

`docs/CONSENSUS.md:44-48` lists only `BlockEgress`, `IsolateHost`, `RevokeCredential`. The doc
is behind the code. Perch renders from the code.

The genuinely different set is reversibility. `ContainmentInverse` has exactly three variants
(`rollback.rs:66-78`) and `resolve_inverse()` (`:151-192`) has four arms: three yielding a
`ContainmentInverse`, one yielding `InverseGap::Irreversible` (`:186-189`), and a `_` fallthrough
to `InverseGap::Unmapped` (`:190`). The mapping is not intuitive — `SuspendProcess` is
reversible, `KillProcess` is not.

### 2.1 The action matrix Perch renders from

| # | `ResponseAction` | `kind()` | Human-gated (12) | Receipt-required (12) | Inverse | Blast-radius impact |
|---|---|---|---|---|---|---|
| 1 | `BlockEgress{target}` | `block_egress` | ✓ | ✓ | **Unmapped** | `NetworkEgressBlocked` |
| 2 | `IsolateHost{host_id}` | `isolate_host` | ✓ | ✓ | **`RestoreHostConnectivity`** | `HostConnectivityIsolated` |
| 3 | `RevokeCredential{credential_id}` | `revoke_credential` | ✓ | ✓ | **Unmapped** | `CredentialAccessRevoked` |
| 4 | `SinkholeDns{domain}` | `sinkhole_dns` | ✓ | ✓ | Unmapped | `DnsResolutionSinkholed` |
| 5 | `TerminateUserSession{host,session}` | `terminate_user_session` | ✓ | ✓ | **Irreversible** | `UserSessionTerminated` |
| 6 | `TriggerEdrScan{host,profile}` | `trigger_edr_scan` | ✗ | ✗ | Unmapped | `HostScanTriggered` |
| 7 | `InjectFirewallRule{…}` | `inject_firewall_rule` | ✓ | ✓ | Unmapped | `HostFirewallPolicyChanged` |
| 8 | `QuarantineFile{host,path}` | `quarantine_file` | ✓ | ✓ | **`ReleaseQuarantinedFile`** | `FileQuarantined` |
| 9 | `KillProcess{host,proc}` | `kill_process` | ✓ | ✓ | Unmapped | `ProcessTerminated` |
| 10 | `SuspendProcess{host,proc}` | `suspend_process` | ✓ | ✓ | **`ResumeProcess`** | `ProcessSuspended` |
| 11 | `DisableUserAccount{user}` | `disable_user_account` | ✓ | ✓ | Unmapped | `UserAccountDisabled` |
| 12 | `ForcePasswordReset{user}` | `force_password_reset` | ✓ | ✓ | Unmapped | `PasswordResetEnforced` |
| 13 | `RemoveScheduledTask{host,task}` | `remove_scheduled_task` | ✓ | ✓ | Unmapped | `ScheduledTaskRemoved` |
| 14 | `DeployDecoy{type,zone}` | `deploy_decoy` | ✗ (min-severity rule only) | ✗ | Unmapped | `DeceptionCoverageChanged` |
| 15 | `Escalate{summary,urgency}` | `escalate` | ✗ | ✗ | Unmapped | `OperatorEscalationOnly` |

Sources: variants and impacts at `swarm-core/src/types.rs:419-500`; `kind()` labels mirrored in
`static_gate.rs:188-205`; inverse arms at `rollback.rs:155-190`.

**The "receipt-required" column is a property of the action, not a promise about enforcement.**
Per §0.2(a) it is enforced only on the dispatcher path. The column header in the rendered UI
therefore reads `RECEIPT-REQUIRED (autonomous path)` until B1.5 lands, and the tooltip names both
call sites.

Note row 14: `DeployDecoy` is not in `destructive_action()` but *does* get its own minimum-
severity denial (`static_gate.rs:279-286`, rule `static.deploy_decoy_min_severity`). A UI that
buckets actions into "destructive / not destructive" will get this row wrong in a way that only
shows up as a confusing deny. Perch has no bucket; it renders the rule name.

### 2.2 Badge spec

Two families, visually unrelated so they cannot be misread as intensities of one thing:

```
HUMAN GATE + RECEIPT      →  amber pill, uppercase, "GATED · RECEIPT"     (Badge variant="warning")
NO GATE                   →  outline pill,          "UNGATED"              (Badge variant="outline")

REVERSIBLE                →  cyan text + inverse kind, "UNDO: resume_process"
IRREVERSIBLE              →  red-on-surface text,      "NO UNDO — session cannot be resumed"
UNMAPPED                  →  neutral text,             "NO UNDO MAPPED — containment stays in effect"
```

The `Badge` component ships `default`, `secondary`, `outline`, `destructive`, `warning`,
`success`, `info` (`badge.tsx:10-21`, read this revision). `destructive` in Buzz means *this
control deletes things*; Perch must not reuse it for severity or the affordance and the priority
collide on the same row. Severity gets its own token ramp (see `05-DESIGN-SYSTEM.md`).

The `Unmapped` copy is lifted almost verbatim from the source's own error text
(`rollback.rs:129-131`: *"no inverse operation is defined for step … the containment stays in
effect"*). Using the domain's own sentence is cheaper than inventing one and cannot drift.

---

## 3. The human-approval flow, end to end

### 3.1 What actually happens today (the bill, restated)

`PolicyVerdict::RequireHuman` in `RuntimeMode::LiveResponse` returns
`ApprovalError::Denied` (`swarm-runtime/src/lib.rs:979-981`) and, on the instrumented path,
records `AuditResponseRecord::Skipped` (`:1133-1145`). The human-approved lane —
`audit_authorize_and_execute_human_approved_instrumented` (`:1085`) — sets
`allow_human_approved_execution: true` and is reachable from exactly two demo-gated call sites
(`ingest/demo.rs:725`, `:1370`). **There is no hold today**, and per §0 there is no governance
re-check and no operator field on the path that would execute one.

Everything in this section presumes the backend items in §8. Perch develops against the E2E mock
bridge with Ambush fixtures until they land, and the queue is labelled `not yet wired` if they
slip (see `09-ROADMAP-AND-RISKS.md`).

### 3.2 The state machine

```mermaid
stateDiagram-v2
    [*] --> Evaluated: ConfigurableApprovalGate.evaluate()
    Evaluated --> Denied: PolicyVerdict::Deny
    Evaluated --> Dispatched: PolicyVerdict::Allow (no human asked)
    Evaluated --> Held: PolicyVerdict::RequireHuman
    Held --> Granted: POST /v1/response/holds/{id}/decide {grant}
    Held --> Refused: POST .../decide {deny}
    Held --> Expired: hold_ttl_ms elapsed, no decision
    Granted --> Reevaluated: daemon re-runs policy (B1.5 adds governance + partition)
    Reevaluated --> RefusedLate: policy changed its mind
    Reevaluated --> RefusedLateGovernance: governance.missing_receipt (B1.5)
    Reevaluated --> Dispatched: lease minted NOW, ensure_active_lease passes
    Dispatched --> Leased: ContainmentLease::open (containment actions only)
    Denied --> [*]
    Refused --> [*]
    Expired --> [*]
    RefusedLate --> [*]
    RefusedLateGovernance --> [*]
```

`RefusedLate` is not a defensive flourish. Between hold and grant the operator may have banned
the requesting agent, a governor may have gone unhealthy, the scope rate limit
(`max_actions_per_scope_per_minute: 5`, `rulesets/default.yaml:96`) may have filled, or
`PartitionState` may have flipped. **A grant can be followed by a refusal, and the UI must render
that as a normal, expected outcome — not an error.** Copy: *"You recorded a grant. The daemon
re-evaluated and refused: `static.scope_rate_limit` — scope `web-07` exceeded 5 actions per
minute. Nothing ran."*

`RefusedLateGovernance` is a **separate arm** and it is drawn dashed in the UI's own legend
until B1.5 exists, because today it cannot fire: the decide route reaches only the runtime, and
the runtime never calls `missing_governance_receipt_reason`. Drawing the arm and marking it
unbuilt is the honest rendering; omitting it would let a reader infer the check exists.

### 3.3 The fixed field order

Render law 1, restated as a component contract. Five slots, always present, always in this
order, never conditional on action type. An action that cannot fill a slot fills it with an
explicit absence, never by collapsing the layout.

```
┌─ HOLD hold:9f2c…  ── QuarantineFile ─────────────── expires in 47m 12s ─┐
│                                                                          │
│  ACTION          quarantine_file                                         │
│                  host_id    "web-07.prod.internal"        ADVERSARY      │
│                  file_path  "/var/tmp/.cache/ld.so.helper" ADVERSARY     │
│                                                                          │
│  BLAST RADIUS    File quarantined · scope kind: file                     │
│                  scope: "web-07.prod.internal:/var/tmp/…"  ADVERSARY     │
│                  max affected scopes: 1                                  │
│                  capabilities: [edr.quarantine]                          │
│                  ⓘ served by the runtime's rehearsal preview             │
│                                                                          │
│  IF YOU UNDO     release_quarantined_file  (executable inverse)          │
│                  → web-07.prod.internal:/var/tmp/.cache/ld.so.helper     │
│                                                                          │
│  WHY WE ARE      no rule matched → static gate                           │
│  ASKING          static.human_gate · "authorized but held for human      │
│                  approval" · severity HIGH ≥ human_gate_severity HIGH    │
│                  receipt-required on the autonomous path                 │
│                  (dispatcher.rs:576, :671) — NOT ENFORCED here, see §8   │
│                                                                          │
│  WHAT GRANTING   CapabilityLease, minted at your decision, TTL 60s       │
│  OPENS           action quarantine_file · scope web-07:/var/tmp/…        │
│                  then a ContainmentLease, TTL 3600s, on the lease board  │
│                                                                          │
│  [ R  Refuse ]        [ G  Record my decision → daemon ]  ← blast-radius │
│                                                              gate: read  │
└──────────────────────────────────────────────────────────────────────────┘
```

Field-by-field sourcing and absence rendering:

| Slot | Source | When absent |
|---|---|---|
| ACTION | the typed `ResponseAction` from the hold, rendered as `kind()` + each named field on its own line, **every value field through `<AdversaryString>`** | never absent; a hold without a typed action is a corrupt hold and renders as a red error row |
| BLAST RADIUS | `ResponseRehearsalPreview.blast_radius` — `scope_kind`, `scope_value`, `impact`, `max_affected_scopes`, `affected_capabilities`, `summary` (`types.rs:506-513`) | `NO REHEARSAL — the runtime did not derive a blast radius for this request` |
| IF YOU UNDO | `resolve_inverse(action, step)` per step of `rollback.steps` (`rollback.rs:151-192`) | the three `InverseGap` renderings from §2.2 |
| WHY WE ARE ASKING | `PolicyDecision.rule_name` + `.reason` verbatim (`swarm-policy/src/lib.rs:74-83`), **plus the receipt-enforcement caveat from §0.2(a) while it applies** | impossible — every decision carries a rule name, defaulting to `policy.unknown`, which renders as itself and is a bug signal |
| WHAT GRANTING OPENS | `lease_ttl_ms` from resolved `PolicyConfig`, plus `runtime.containment.lease_ttl` when the action opens a `ContainmentLease` | `NO LEASE — this action does not open a capability lease` |

The reason the order is fixed and not "most relevant first": at 02:41 an operator reads by
position, not by reading. A pane that reorders itself per action type means the third block is
sometimes the undo and sometimes the rule, and the muscle memory that makes a 9-second verdict
possible never forms. This is also why *WHY WE ARE ASKING* sits fourth rather than first —
it is the field an experienced operator skips, and putting a skippable field first trains the
eye to start below the fold.

### 3.4 The three flagship actions, worked

**BlockEgress.** `IF YOU UNDO` reads `NO UNDO MAPPED — containment stays in effect`. This is
the honest answer: `resolve_inverse` has no `BlockEgress` arm (it falls to `_` at
`rollback.rs:190`), so a release produces a receipt whose step status is `Unsupported`
(`RollbackStepStatus` at `rollback.rs:211-223`) and whose `fully_reversed()` is false. A UI that
shows an Undo button here lies. `WHAT GRANTING OPENS` must additionally warn: this action opens a
`ContainmentLease` whose expiry will fire a rollback that cannot roll back — the lease closing is
bookkeeping, not restoration.

**IsolateHost.** The one flagship with a real inverse. `IF YOU UNDO` reads
`restore_host_connectivity → web-07.prod.internal` (`rollback.rs:174-178`), and the lease board's
Release button on this lease is the only Release in the product that can honestly promise a
restored world — and only if the release response comes back `fully_reversed: true`.

**RevokeCredential.** `Unmapped`, and worse than `BlockEgress` because the blast radius is a
principal rather than a flow. `affected_capabilities` is the field that carries the real cost
here and it must not be truncated: if the preview lists eleven capabilities, eleven render.
Perch has no "+8 more" affordance in the blast-radius slot.

**Lease timing is the load-bearing detail.** `lease_ttl_ms` is `60000`
(`rulesets/default.yaml:95`) and `ensure_active_lease(&lease, context.now_ms)` is checked
immediately before `response.execute()` (`swarm-runtime/src/lib.rs:1003`). A lease minted
when the hold was *created* is dead long before a human reads the page. So: the daemon mints at
decision time, inside `POST /v1/response/holds/{id}/decide`, and Perch's copy says so. The
observable consequence Perch must instrument is the decision→dispatch window: if it approaches
60 s the operator sees a `RefusedLate` with an expired-lease reason, and that is a daemon
performance bug the console should surface, not absorb.

### 3.5 Friction, asymmetric and deliberate

**The keymap, settled.** This document adopts `04-SURFACES-AND-UX.md` §3.0 without amendment.
The earlier `A`/`D`/`E`/`S` map is withdrawn and `A` joins the copy ban list. Two reasons, both
mechanical rather than aesthetic:

1. `A` for "approve" is the word render law 6 forbids on the control label; binding it to the
   key reintroduces the word through the operator's fingers and through every training doc.
2. Holds and findings interleave in one list (`04` §2.1 — the needs-action queue carries both),
   so `D` cannot mean Refuse on one row and Dismiss on the next. **Dismiss is the verb that
   retroactively removes every deposit at or before the marker from the concentration sum**
   (`is_suppressed_by_feedback` at `swarm-pheromone/src/substrate.rs:1367`, applied in the sum at
   `:1286` and in the source set at `:1325`). A mis-keyed `D` under the old map silently blinds a
   detector. That is not a typo, it is a detection outage with no error message.

| Control | Row type | Key | Friction | Rationale |
|---|---|---|---|---|
| Confirm | finding | `C` | one keypress | records a true positive; feeds `FalsePositiveMeasurement` with `false_positive: false` |
| Dismiss | finding | `D` | confirmation showing the suppression arithmetic (deposits removed, `total_strength` before/after vs `alert_threshold`) before it commits | render law 5: Dismiss is never a gesture |
| Investigate | finding | `I` | one keypress | neither confirms nor suppresses |
| **Refuse** | hold | `R` | one keypress, **no dialog, no undo**, three-state send | refusing is the safe direction; making it expensive produces grants-by-exhaustion |
| Promote to a case | either | `E` | one keypress | opens the case (and, per `04` A10, the incident record a verdict needs). **Not** "route to another operator": `04` §3.0 settles `E` as promote-to-case with one meaning, and no operator directory exists in either tree to route to. |
| Snooze | **finding only** | `S` | preset menu (`timePresets.ts:31-43`) | **disabled on holds**, with the reason in the row — see below |
| **Grant** | hold | `G`, then `Enter`/click | two-stroke, blast-radius-gated, confirm is *secondary*-styled | the only irreversible direction |

**Why Refuse has no undo toast.** The earlier draft specified "one keypress, no dialog, undo
toast for 5 s". That is optimistic UI on a governance path, which
`07-REALTIME-AND-DATA.md` decision 8 forbids in terms. It is also wrong in both of its possible
implementations: buffered client-side, the row reads REFUSED for five seconds while the hold is
still live and a crash loses the decision silently; sent immediately, "undo" is a false promise —
the verdict card is a signed, immutable relay event and the daemon has already acted. Worse, it is the
one place in the plan where the *safe* direction is made reversible-looking, which is precisely
the habituation shape §7.1 exists to prevent. Refuse is immediate and irrevocable and renders
07's three states like every other governance write. An operator who changes their mind requests
the action again, which produces a new hold and a second, separately recorded decision — the
honest artifact.

**Why a hold cannot be snoozed.** Buzz's presets are 30 min / 1 h / 3 h / tomorrow 9am / next
Monday 9am (`desktop/src/features/reminders/lib/timePresets.ts:31-43`, read verbatim). The
earlier draft ruled "a hold cannot be snoozed past its own TTL; the menu disables presets beyond
`expires_at_ms`" **and** set `hold_ttl_ms` to 15 minutes — which disabled all five presets on
every hold, always, while §7.1 simultaneously named snooze the primary anti-habituation control.
The valve did not exist for the object it was prescribed on.

The fix is not shorter presets. A hold is a live gate with its own clock; the queue *is* the
reminder, and a snoozed hold that expires while hidden is a fail-closed action nobody chose. So:
**`S` is disabled on hold rows**, rendered (not omitted, so nobody hunts for it) with the string

> *A hold cannot be snoozed. It expires on its own in 47m and nothing runs. Refuse (`R`) if you
> do not want it to run.*

`S` keeps working on finding rows, where nothing expires and a snooze is genuinely a scheduling
decision. §7.1's anti-habituation valve is Refuse, and Refuse is one keypress in the safe
direction. This ruling requires `04` §2.1/§3.0 to drop `S` from the hold affordance list and `06`
to move its snooze control string off the verdict pane; both are recorded in the dependency list
at the end of this document, and **both are done** as of the cross-document reconciliation pass.

**The grant control: two-stroke, blast-radius-gated, in the row.** The earlier draft specified a
scroll-to-end-gated **modal**. That contradicted `04` §2.2's row wireframe and the brief's
"approval and disposition in the row, never a separate screen". The friction survives; the modal
does not.

`G` *arms* the control; a second, distinct keystroke (`Enter`) or a click *records* it. The
confirm is disabled until both of:

- the **BLAST RADIUS** block has been fully visible — `IntersectionObserver` at `threshold: 1.0`
  on its last child, which for a long capability list means the operator actually scrolled it;
- the pane has been mounted for **this** `hold_id` for at least 1500 ms.

Arming is ignored when `event.repeat` is true and resets whenever the selected `hold_id` changes,
so a held-down key and a stale selection are both structurally impossible. Both conditions are
observable in a Playwright test, which is why they are written this way rather than as "the
operator should read it".

The control's label is `Record my decision and send it to the daemon`. Not "Approve".
Render law 6, and it is enforceable: `AlertDialogAction` renders `cn(buttonVariants(), className)`
(`alert-dialog.tsx:149`), i.e. the default primary variant. A CI check
(`tools/check-perch-grant-affordance.sh`, patterned on `tools/check-gates-wired.sh`) fails the
build if any element carrying `data-perch-role="grant"` resolves to `buttonVariants()` with no
explicit non-primary variant, if its accessible name matches `/^\s*approve\b/i`, or **if the
string `"a"`/`"A"` appears as a `key` binding on a verdict control** — the last clause is what
keeps the withdrawn keymap from creeping back through a merge.

**Rejected alternative: type-the-hostname-to-confirm.** It is the standard destructive-action
pattern and Buzz has no precedent for it (grep of the desktop features found no typed-confirm
dialog; `DeleteMessageConfirmDialog.tsx` is a plain `AlertDialog`). We rejected it because the
hostname is *attacker-influenced data* — see §7.7 — and asking a human to retype an
adversary-supplied string as a safety ritual is the wrong shape. The blast-radius gate reads the
same amount of time, forces the eye across the impact rather than across a text field, and
cannot be trained into a reflex on a string the attacker chose.

### 3.6 Timeout, and nobody-is-watching

A hold has its own TTL, independent of any lease. **Default `hold_ttl_ms: 3_600_000` (60
minutes), configurable per threat class.** This replaces the earlier 15-minute default and is
now the one number the set uses. `03-DOMAIN-EVENT-MAPPING.md` §5.6's worked hold body and
`04-SURFACES-AND-UX.md` §3.0's `PERCH_HOLD_TTL_MS` were both carrying 900,000 and are amended to
3,600,000 in the same editorial pass. The number lives in `APPENDIX-NORMATIVE.md`; this document
is its author, not its owner.

The argument for 60 rather than 15: the drift cost is real but it is *rendered*, as
`RefusedLate`, and a refusal an operator can read is a better outcome than an expiry nobody
chose. Fifteen minutes is shorter than the walk `01-POSITIONING.md`'s own two-minute demo takes
through `/leases`, `/watch-floor` and `/tuning` mid-hold. The constraint that actually matters is
the *lease* TTL — 60 s, minted at decision time — and that is unaffected by the hold window.

On expiry:

- The hold transitions to `Expired`. **The action does not run.** Fail-closed, matching the
  existing `AuditResponseRecord::Skipped` posture (`swarm-runtime/src/lib.rs:1133-1145`).
- A `kind:9` `ambush:hold:v1` card is appended to the case channel recording the expiry with
  the elapsed time and the last operator who viewed it (Perch knows this; the daemon does not,
  so the "viewed by" line carries a derived marker).
- The Watch's needs-action queue keeps the row for the rest of the shift, greyed, with the
  copy *"Expired undecided after 60m. Nothing ran. The finding is still open."*
- The handoff bundle (§6.4) lists every hold that expired undecided during the shift. This is
  the number that tells a SOC lead their staffing is wrong, and it is the number a console
  that silently drops expired holds destroys.

**Nobody-is-watching is not a UI state, it is a measured one.** Perch emits a per-shift counter —
holds created, holds decided, holds expired undecided, median seconds page-to-verdict — onto the
ephemeral telemetry stream. **Its home is The Watch (`/`)**, not `/handoff`: `/` is the only
Phase-1 surface (`09-ROADMAP-AND-RISKS.md`), and `09` D14 makes the C9 counters a Phase-1
non-negotiable, so any other home is a counter that ships after the phase that requires it. The
counters render in the needs-action queue header. `/handoff` and `/tuning` restate them read-only
and link back to `/`; neither owns them. Render law: if the expired-undecided count is non-zero,
`/handoff` cannot be completed without acknowledging it. No blocking modal; an unignorable row.

---

## 4. Containment lease UX

### 4.1 The two facts that must never merge

```rust
pub struct ContainmentLeaseView {
    pub lease: ContainmentLease,
    pub remaining_ms: i64,   // SATURATES AT ZERO
    pub expired: bool,
}
```

`http/containment.rs:73-88` carries the reason in its own doc comment (`:75-80`): `remaining_ms`
alone "cannot distinguish 'expires in an instant' from 'expired an hour ago and the sweep has not
managed to release it'". The saturation itself is at
`swarm-response/src/containment.rs:275-278` — `self.expires_at_ms.saturating_sub(now_ms).max(0)`.
So the lease row renders a countdown **and** a separate expiry flag, and `expired: true` on a
*listed* lease is the loudest state on the board:

```
web-07.prod.internal   isolate_host        EXPIRED · SWEEP FAILING     00:00
   ↳ this host is still contained. The TTL sweep has tried and could not release it.
   ↳ last attempt: —   (the runtime does not report attempt counts)
```

That second `↳` line is a deliberate admission: `ContainmentSweep` exposes no attempt counter
through the list route, so Perch says so rather than inventing a retry count.

### 4.2 Early release

`POST /v1/operator/containment/leases/{lease_id}/release`, `OperatorScope::Maintenance`
(`http/containment.rs:197`). Three rules:

1. **Read the body, not the status.** `lease_closed` is computed by re-reading `open_leases()`
   after the release (`containment.rs:224-228`), and its own doc comment (`:196-200`) says it is
   `false` when the inverse failed — the lease is deliberately kept open for the next sweep. A
   200 with `lease_closed: false` renders as **RELEASE FAILED — the host is still contained**, in
   the same visual register as an error, because it is one.
2. **`fully_reversed` is a separate claim from `lease_closed`.** A lease can close with
   `fully_reversed: false` (every step `Unsupported` or `Irreversible`). Copy:
   *"Lease closed. Nothing was restored — `block_egress` has no mapped inverse."*
3. **Per-step outcomes render, always.** `RollbackStepStatus` has five values
   (`rollback.rs:211-223`) and each renders as its own word: Reversed / Simulated /
   Irreversible / Unsupported / Failed. Collapsing them to a checkmark destroys the distinction
   `fully_reversed()` exists to preserve.

### 4.3 There is no extend

`ContainmentLease` has private fields, one constructor, and derives its expiry from a
`ContainmentTtl` newtype that cannot represent "no expiry" — `NonZeroI64` with a `> 0` guard
(`swarm-response/src/containment.rs:74-95`). The persisted form re-checks
`expires_at_ms > issued_at_ms` on deserialize (`:157-172`). Extending means minting a new lease
over the same containment — and the store contract warns that closing twice produces two rollback
receipts for one containment, which breaks the audit trail.

So Perch ships **no extend affordance.** The lease board's only verbs are Release and Verify.
An operator who needs a longer containment re-requests the action, which produces a new hold, a
new decision, and a new receipt — the full chain, which is the point. The copy on the absent
control (rendered as a disabled row-menu item with a tooltip, not omitted, so nobody hunts for
it) is: *"A containment lease cannot be extended. Request the action again to open a new lease
with its own receipt."*

### 4.4 Reconciliation after a partition

`GovernanceStatusReport` carries `active_contingency_leases`, `unauthorized_partition_actions`
and `last_reconciliation_report_id` (`governance.rs:62-71`). `PartitionState::Healing` is a
first-class value, not an implicit return to `Healthy` (`:49-54`; transition logic in
`tom_agent.rs`).

The lease board grows a **Partition** section while `PartitionState != Healthy`, and a
**Reconciliation** banner while `Healing`:

```
HEALING — governance is reconciling partition-era activity
  contingency leases redeemed during the partition   3
     ↳ these carry no governance receipt by design (dispatcher.rs:575) — UNATTESTED here
       is expected, not a fault
  unauthorized partition actions recorded            1     ← loud
  reconciliation report                              recon:… (open)
```

`unauthorized_partition_actions > 0` is the single most important number the governance strip
can show and it is a raw count from the runtime, not derived. It means something acted during a
partition without a valid contingency lease. Perch renders it in the destructive register with
no rounding, no sparkline, and a link into the audit trail.

---

## 5. Veto, override, and quorum degradation

### 5.1 There is no override

Say it in the product. Ambush has no operator affordance that converts a `Deny` into an
execution, and `docs/EVOLUTION.md:127` states the general form: *"no browser or review action
bypasses canary, promotion, governance, or policy gates."* When the daemon returns `Deny`,
Perch renders the rule name and the reason and offers exactly two next steps: change the
configuration (out of band, with the ruleset-attestation caveat from `docs/EVOLUTION.md:274`),
or escalate to a human decision that is recorded and does nothing mechanical.

The rejected alternative was a "break glass" control gated on `OperatorScope::Maintenance`. We
rejected it because `Maintenance` "widens nothing" by contract (`CONSENSUS.md:35`), because the
scope is checked on only nine handlers today (§7.5), and because a break-glass path in a console
that is explicitly not an authorization path would have to reach past the daemon — which is the
second-writer hazard ADR 0010 exists to prevent.

### 5.2 Veto rendering

`SwarmAction::GovernanceVeto` carries `governing_agent_id` and a typed `reason` string
(`swarm-core/src/types.rs:378-385`), and is one of the two sites where
`missing_governance_receipt_reason` actually runs (`dispatcher.rs:671`). A veto is rendered as a
*timeline row in the case*, not a toast: it is a durable governance fact and belongs in the
record. The row names the governing agent with the full 64-hex Ed25519 identity — never
truncated, per the `<PubKey variant="full">` doctrine (`PubKey.tsx:20-31`, whose own comment says
"a truncated key is forgeable by vanity grinding") extended to the Ed25519 chain by the check in
§7.8.

### 5.3 Quorum degradation

The honest facts, in order of how much they hurt:

- The only transport is `SoloGovernorTransport`, which serves a committee of one and refuses a
  larger one (`CONSENSUS.md:87-96`).
- A deployment that admits peer governors **without** a networked transport fails closed on
  every destructive action, with a veto naming the transport.
- Round state is not persisted; a restart mid-round loses the round (`CONSENSUS.md:113-119`).
  Fail-closed but not recoverable.
- There is no trust anchor on the signer of a governance receipt, and nothing checks chain
  linkage (ADR 0010:125-131, `:140-144`). A "quorum met" reading is doing more work than the
  cryptography supports.

The governance strip therefore renders **`committee of 1 (solo transport)`** and never a
fraction. Rendering `1/1` invites the reading "quorum met", which is true and useless; the
operator needs to know there is no second opinion in the system. When `total_governors > 1` in
`GovernanceStatusReport` the strip switches to the *fail-closed* register, not a healthier one:

```
GOVERNANCE   committee of 3 · no networked transport · destructive response FAILS CLOSED
             every destructive action will be vetoed until a transport is installed
```

This is the one place Perch's copy is more alarming than the raw numbers, and it is correct:
`total_governors: 3, healthy_governors: 3` looks *better* than `1` and behaves strictly worse.

**Recovery path, rendered inline.** When destructive response is blocked, the queue does not go
empty — every held action still lists, with a per-row banner naming the blocking condition and
the one thing that clears it (install a transport / restore quorum / wait for `Healing` to
settle). The operator's available actions in that state are Refuse and promote to a case (`E`).
This matters: a blocked-but-visible queue is a work list; a hidden queue is an outage with no
evidence.

**No approval-ledger voting surface in v1**, per the brief. When it arrives it carries the
constraint that `validate_and_append_vote` hardcodes `ApprovalVote::Approve`
(`swarm-runtime/src/approval.rs:1343`, read this revision — the `ledger.entries.push` sets
`vote: ApprovalVote::Approve` unconditionally), so there is no signed reject path to render. That
surface must show abstain-by-silence or budget the signed reject path, not paint a Deny button
over a vote the type cannot carry.

---

## 6. Receipts, evidence, and handing a bundle to someone with no runtime access

### 6.1 Which chain, said out loud

Two signature chains, never conflated:

| | Ambush | Nostr envelope |
|---|---|---|
| Curve | Ed25519 (`swarm-crypto/src/lib.rs:57-63`, `Ed25519Signer`) | secp256k1 BIP-340 Schnorr |
| Signs | the governance receipt / pheromone deposit / approval-ledger envelope | the transport event |
| Verified by | `ConsensusGovernanceReceipt::verify` (`swarm-consensus/src/lib.rs:428-446`), `verify_envelope`, `verify_detached_signature` | `buzz-core/src/verification.rs` |
| Renders as | `Ed25519 · <64 hex>` | `secp256k1 · npub1…` (full) |

Every verification surface names the chain it checked **and the tier it reached** (§6.2). The
failure mode this prevents is subtle and fatal: a green check that means "the relay accepted this
event" reading as "a governor authorized this action". `03-DOMAIN-EVENT-MAPPING.md` owns the wire
shapes; this document owns the badge text.

A related correction the set should carry, because it is a trust claim: agent liveness is read
from the ephemeral `26002 AgentHealth` stream and **not** from Nostr presence. The reason is not
"presence is single-node with no `PUBLISH`" — a `kind:20001` update writes Redis presence state
and then falls through to the shared channel-less ephemeral path, which does
`publish_event(&conn.tenant, EventTopic::Global, &event)` before local fan-out
(`buzz-relay/src/handlers/event.rs:843-847` says so in a comment; the publish is at `:877-891`).
The real reason is the **lie window**: presence is a TTL-decayed status with
`PRESENCE_TTL_SECS = 180` (`buzz-pubsub/src/presence.rs:16`, three 60-second heartbeat windows),
so a dead agent reads as online for up to three minutes. In a security console that is a false
"a Whisker is watching that host". The decision is unchanged; the justification is.

### 6.2 Verification tiers, and the attestation badge

Per §0.2(c), most Ambush facts carry no signature. A single "verified / not verified" badge over
a set of artifacts with three different cryptographic properties is exactly the green check this
document exists to prevent. So verification renders a **tier**, always named, never implied:

| Tier | What exists | Applies to today | Badge text | Verify affordance |
|---|---|---|---|---|
| **0 — envelope only** | a secp256k1 Nostr signature over the transport event, and nothing over the body | `ambush:finding:v1`, `ambush:escalation:v1`, `ambush:hold:v1`, `ambush:lease:v1` — always; `ambush:receipt:v1` and `ambush:rollback:v1` when no governance receipt / attestation is nested; `ambush:verdict:v1` until B1.6 | `TRANSPORT-SIGNED ONLY · secp256k1 · the daemon is the record` | **re-fetches from the daemon** and diffs; there is no local check to run |
| **1 — detached Ed25519 over the body** | `ConsensusGovernanceReceipt` (`verify()` at `swarm-consensus/src/lib.rs:428-446`) or `PheromoneDeposit.signature` (`swarm-core/src/pheromone.rs:231-232`) | governance receipts, release attestations (so an attested `ambush:rollback:v1`, which `04` §6.3 correctly rebutted this document about), and `ambush:verdict:v1` once B1.6 puts the operator's detached signature in the body | `Ed25519 · attestation matches this body` + the ADR 0010 caveat | signature + subject binding, reported separately |
| **2 — spine-chained** | a `build_signed_envelope` wrapper with `seq` and `prev_envelope_hash` (`swarm-spine/src/envelope.rs:71-100`) | **nothing today** — exists only after B1.7 | `Ed25519 · chained · seq N` | signature + subject binding + `verify_chain_link` |

**The attestation badge, honestly.** ADR 0010:125-131 names the missing check outright:
`ConsensusGovernanceReceipt::verify` checks the signature against `signature.public_key_hex`
*carried inside the receipt itself*. There is no trust anchor; nothing compares the signer to a
configured governor set, and — the ADR's own words at `:140-144` — nothing checks chain linkage.
A full re-attestation (mint a keypair, recompute `proposal_id` over the rewritten subject, sign)
passes. What the two implemented checks buy is that a *partial* rewrite fails (ADR 0010:133-138).

So there are three renderings, and none of them is a shield:

| `attestation_verified` | `governance_attestation` | Render |
|---|---|---|
| `true` | present | `attestation matches this body` + the signer's full 64-hex key + *"no trust anchor: this does not prove a governor you trust authorized it, and no chain linkage was checked (ADR 0010:125-131, :140-144)"* |
| `false` | present | `ATTESTATION MISMATCH` + `attestation_error` verbatim (`http/containment.rs:206-209`) |
| `false` | `None`, **`PartitionState::Healthy` at execution** | **`UNATTESTED`** + *"no governance authority was wired, or none could sign"* |
| `false` | `None`, **partition contingency at execution** | **`UNATTESTED — BY DESIGN`** + *"redeemed under a contingency lease during a partition. No governance receipt is required or expected on this path (`dispatcher.rs:575`)."* |

The last row is new in this revision and it is the fix for a real misreading: an operator who
learns `UNATTESTED` means "somebody misconfigured governance" will get the one state that matters
exactly backwards. `verify_release_attestation` refuses a missing attestation with
`ReleaseAttestationError::Unattested` (`http/containment.rs:219`; the variant is exercised at
`http/tests.rs:3462-3464`) — the refusal is correct in both cases; only the *explanation* differs,
and the explanation is what the operator acts on.

### 6.3 Verifying offline, in the UI

Verification runs against the Ed25519 chain, locally, in the Tauri process — not in the
webview, and not by asking the relay. **How many checks run depends on the tier**, and the pane
says which tier it is before it says anything else:

1. **Signature** (tiers 1 and 2) — `verify_detached_signature` over the canonical bytes.
   Result: pass/fail plus the 64-hex signer.
2. **Subject binding** (tiers 1 and 2) — `sha256(canonical(receipt with attestation cleared))`
   vs `attestation.payload.proposal_id`. This is the check that catches a partial rewrite.
3. **Chain linkage** (tier 2 only) — `verify_chain_link` over `prev_envelope_hash` / `seq`
   continuity per issuer (`swarm-spine/src/chain.rs:75-147`, four `ChainLinkVerdict` failure
   variants). **A gap renders as a gap**, never as a smooth chain: risk (1) from the brief.

**On a tier-0 card, none of the three runs**, and the pane says so in those words rather than
showing three greyed rows that read as "pending". What it offers instead is the daemon re-fetch:
`GET` the artifact by id from `swarm_detect --serve`, diff it byte-for-byte against the relay
copy, and render agreement or disagreement as an explicit row. That is a weaker property than a
signature and the copy says which one you have.

Before any check, per constraint C5, the pane shows the **literal RFC 8785 canonical bytes** in a
monospace, selectable, copyable block, and the **untruncated 64-hex voter/signer id**. The reason
is that every one of these checks is a computation the console performed; the bytes are the thing
a reviewer can take somewhere else.

### 6.4 The export bundle

The requirement is a person with no runtime access, no relay credentials, and no Perch install
reproducing the console's verdict. Perch's `Export` on a case produces a single directory:

```
case-0042/
  MANIFEST.json          sha256 of every file below, plus the exporting operator's
                         Ed25519 identity, a detached signature over the manifest, and
                         a per-file `verification_tier` (0 | 1 | 2) from §6.2
  receipts/*.json        verbatim ResponseReceipt / RollbackReceipt bodies, byte-identical
                         to what the daemon stored — no reserialization, no pretty-printing
  envelopes/*.json       spine envelopes, with seq gaps present and annotated.
                         EMPTY until B1.7 lands, and VERIFY.md says why rather than
                         omitting the directory
  holds/*.json           every hold, its policy decision, its outcome, and the human intent
                         record (`kind:9` + `ambush:verdict:v1`) with its secp256k1 signature
  canvas.md              the case canvas as written
  VERIFY.md              the checks of §6.3 written as commands a reader can run with
                         swarmctl and nothing else, PER TIER — including the sentence
                         "these files carry no Ed25519 signature; re-fetch them from the
                         daemon to verify" for every tier-0 artifact
  DERIVED.json           everything Perch computed that the runtime did not, each entry
                         naming the function that produced it
```

`DERIVED.json` is the discipline that makes the bundle honest. Render law 4 says derived values
carry a marker; the export makes the marker machine-readable, so a reviewer can delete every
derived value and still have a complete record. **Nothing in `receipts/` or `envelopes/` is
reserialized** — a bundle that pretty-prints canonical JSON destroys the hashes it exists to
prove.

**What this bundle does not answer, until B1.6.** It does not answer *who approved this*. Per
§0.2(b) the receipt records that the verdict was `require_human` and that a `ResponseReceipt` was
produced; the operator id exists only in the `HeldActionStore` and in the relay's
`ambush:verdict:v1` card, neither of which is the Ed25519 chain. `MANIFEST.json` therefore carries an explicit
`"answers_who_approved": false` field and `VERIFY.md` states it in prose. When B1.6 lands, the
field flips and the `approved_by` block appears inside the receipt where an auditor expects it.

Rejected alternative: exporting a PDF report. It reads better and cannot be verified. If a
human-readable artifact is wanted it is generated *from* the bundle, alongside it, never
instead of it.

---

## 7. How a UI weakens a fail-closed system

This is the section that justifies the document. Every row below is a way Perch could make
Ambush less safe than Ambush is without it.

| # | Weakening | Control | Enforced where |
|---|---|---|---|
| 1 | Approval fatigue / habituation | queue-depth cap, no bulk grant, asymmetric friction, hold-rate telemetry on `/` | §7.1 |
| 2 | One-click path outrunning comprehension | blast-radius gate, two-stroke grant, fixed field order, no key-repeat | §3.5 |
| 3 | Misleading severity encoding | pinned accent, `destructive` reserved for affordance, severity on its own ramp | §7.3 |
| 4 | Compromised client | daemon re-evaluates policy; **CSP must be tightened in Phase 0**; token in OS keyring | §7.4 |
| 5 | Session and auth model | bearer in keyring, injected by a Tauri command, never in the webview | §7.5 |
| 6 | **Insider misuse and renderer-forged consent** | governance kinds leave the generic signing oracle; `perch_record_verdict` builds the body from daemon state | §7.6 |
| 7 | **Prompt injection through rendered attacker strings** | hardened frame, trusted-string allowlist, no remark pipeline, no marker sniffing | §7.7 |
| 8 | Log / PII exposure in rendered telemetry | field allowlist per payload kind, reveal-on-demand, no default full dump | §7.8 |
| 9 | Notification storm training people to ignore alerts | four wake classes, lanes muted by default, 2 s debounce, **issuer admission on 46010** | §7.2 |
| 10 | Cross-tenant leak on colony switch | typed reset registry with an exhaustiveness check | §7.9 |

### 7.1 Approval fatigue

The mechanism: an operator who sees forty holds an hour stops reading the blast radius. The
console then functions as a rubber stamp with cryptographic receipts, which is strictly worse
than no gate at all — it manufactures evidence of deliberation that did not happen.

Controls, in order of strength:

- **No bulk anything.** No select-all, no shift-click range, no "grant remaining", no
  keyboard-repeat on `G` (arming ignores `event.repeat`, and arming resets on `hold_id` change).
- **Queue-depth alarm.** If the needs-action queue exceeds a configured depth (default 12), the
  Watch renders a banner naming it as a *tuning problem, not a work problem*, and links
  `/tuning`. The banner's copy points at `build_alert_tuning_report`'s thresholds
  (`alert_tuning.rs:6-15`: reviewed ≥ 2/4/3, FP ≥ 2, rate ≥ 0.75/0.50/0.34) as the loop that
  is supposed to drain it.
- **The instrumented claim (C9), on `/`.** Median seconds page-to-verdict, measurements written
  per week, and the fraction of this week's `AlertTuningRecommendation`s that came from this
  week's verdicts. Home is The Watch (§3.6). If median-to-verdict falls below ~15 seconds while
  the queue is deep, that is the signature of habituation and the queue header says so.
- **Refuse is the cheap escape, and it is the safe direction.** The earlier draft named snooze
  here; per §3.5 snooze does not exist on a hold and could not have. An operator who cannot decide
  refuses, which stops the action, records the decision, and leaves the finding open for the
  detector-tuning loop. That is a better default than any parking affordance, because the
  parked-and-forgotten hold is exactly the fail-closed-by-neglect case §3.6 measures.

### 7.2 Notification storms

Buzz's `shouldNotifyForEvent` returns `true` for **every top-level post in an unmuted channel**
(`shouldNotify.ts:55-57` — `if (parentId === null) return true;`), and the desktop toast master
switch plus 7 of 8 sound slots default ON (`notifications/hooks.ts:56-63`). The twelve standing
lane channels (`escalation.rs:315-330`) receive an escalation card per crossing. Left alone, Perch
pages on every escalation on day one and the operator turns notifications off on day two.

Control: **lanes ship muted by default**, and exactly four classes may produce an OS
notification —

1. `ModeTransition` to `SwarmMode::Incident` (broadcast),
2. a held destructive action naming this operator (mention),
3. a lease that failed to release (`lease_closed: false`, or `expired: true` on a listed lease),
4. a due snooze (findings only, per §3.5).

Refuse the request for a fifth at least four times. The governance strip additionally inherits
Buzz's 2 s debounce on degraded states (`useRelayConnection.ts:15-26` — the comment names the
flap problem explicitly) because governance flaps on a tick and a strobing strip teaches
operators to ignore the strip.

**Wake class 2 needs an admission rule, and it is not the one INV-15 gave.** After the two-arm
fork, `kind:46010` resolves to `Scope::MessagesWrite` — the arm lands directly beside
`KIND_APPROVAL_GRANT | KIND_APPROVAL_DENY => Ok(Scope::MessagesWrite)`
(`buzz-relay/src/handlers/ingest.rs:544`), which is the same scope every chat-capable member
already holds. The relay performs no issuer-authority check. So **any member of the colony
community can publish a `46010` with a `p` tag naming the on-shift operator** — and `03`'s own
decision makes that `p` tag load-bearing, since `query_needs_action` INNER JOINs `event_mentions`.
That is a 03:00 page with attacker-chosen `ACTION` and `BLAST RADIUS` text, plus a forged hold row
in the case timeline and, per §6.4, in the export bundle a reviewer with no runtime access is
supposed to trust. The daemon's 404 on decide bounds the *execution* risk; it bounds neither the
attention risk nor the evidence risk.

Two controls, both required:

- **INV-15's admission rule extends to every Ambush-authored stored kind, `46010` included.** A
  `46010` whose signer does not resolve to an admitted bridge identity renders as an untrusted
  prose event, never enters the needs-action queue, and never reaches a wake class.
- **`GET /v1/response/holds` on the daemon is the authoritative queue source** (already proposed
  in `03` §11.2). The relay copy is a notification and a conversation anchor, nothing more. Perch
  reconciles on open; a hold present on the relay and absent from the daemon renders as
  **FORGED — no such hold on the daemon**, in the destructive register, and is reported.

### 7.3 Misleading severity encoding

Buzz's accent picker overwrites `--primary` from a 10-swatch palette including Green, Orange
and Red (`ThemeProvider.tsx:44-55, 198-237`). A red `--primary` makes a red CRITICAL badge
meaningless and makes the grant control — which must never look primary — look like the most
important control on screen. **The accent picker is deleted, not hidden.** `--destructive` stays
bound to "this control changes the world" and never carries severity; severity gets its own
tokens. `05-DESIGN-SYSTEM.md` owns the ramp.

### 7.4 A compromised client

Threat: an attacker with code execution in the Perch renderer wants a host isolated.

What saves the system is architectural: **the daemon re-evaluates policy from scratch on every
decision.** (Not governance — §0. B1.5 is what makes the sentence in this paragraph true for the
whole gate rather than for policy alone.) A compromised renderer can post a grant for a hold that
exists; it cannot invent a hold, cannot mint a lease, and cannot make `PolicyVerdict::Deny` into
`Allow`.

**The earlier draft then said the blast radius is "the same as a compromised operator, and is the
correct answer". That is wrong and §7.6 corrects it**: the renderer also holds a generic signing
oracle, so it can grant *and* manufacture the evidence that a human deliberated. A compromised
renderer is strictly worse than a compromised operator until §7.6's control lands.

**The CSP is not tight today, and the earlier draft claimed it was.** Read verbatim from
`desktop/src-tauri/tauri.conf.json:39`:

```
script-src  'self' 'wasm-unsafe-eval' https://cdn.jsdelivr.net/npm/@mediapipe/
connect-src 'self' ipc: http://ipc.localhost buzz-media: http://buzz-media.localhost
            https: http: wss: ws:
img-src     'self' buzz-media: http://buzz-media.localhost data: blob: https: http:
media-src   'self' buzz-media: http://buzz-media.localhost data: blob: https: http:
```

`connect-src ... https: http: wss: ws:` means any code in a ~100k-LOC React tree can POST the
entire verdict queue, host inventory, receipts and case canvases to any host on the internet —
from a workstation this plan says sits inside the security product's trust boundary. The
`@mediapipe` script source is huddle's, and huddle is on the delete list.

**Phase 0 task, with a CI assertion on the literal CSP string:**

```
connect-src 'self' ipc: http://ipc.localhost buzz-media: http://buzz-media.localhost
            <relay wss origin> http://127.0.0.1:9090
```

— dropping `https: http: wss: ws:`; dropping the jsdelivr `script-src` entry with huddle; dropping
`https: http:` from `img-src` and `media-src` (GIFs and remote link previews are already deleted).
The assertion is a string equality against the checked-in config, not a regex, so a widening is a
one-line diff a reviewer cannot miss. `02-ARCHITECTURE-INTEGRATION.md` currently uses the wide
`connect-src` only to justify a lint banning the literal `9090`; that lint is fine and
insufficient, and the tightening is budgeted here rather than nowhere.

Only after that lands may §7's control column read "no remote fetch". Today it may not.

Buzz's `egress_guard.rs` — a fail-closed inventory test pairing every relay-bound egress site with
a guard call (`egress_guard_tests.rs:264-301`) — is the model for a Perch equivalent covering
outbound requests from the console process.

### 7.5 Session and auth

Ambush operator auth is an opaque bearer token read from process env on **every** request and
compared with `!=` — not constant-time (`http/auth.rs:84-96`; the comparison is
`expected_token.as_str() != token` at `:95`). Expired-token 401s disclose the operator id and
expiry timestamp (`:210-215`). Rotation requires a restart because startup fails on a missing
token env. There are no accounts, sessions, cookies, or logout.

Perch's posture:

- The token lives in the OS keyring via the existing `secret_store` and is injected into the Rust
  side by a Tauri command. **It never crosses into the webview.** A browser-hosted Perch would
  turn this into a same-origin gateway problem, which is the contrarian's design and is out of
  scope. (Note the limit honestly: keyring storage does not stop a confused-deputy call — see
  §7.6.)
- `/settings` renders the honest facts: which operator id this token maps to, which scopes it
  claims, and the sentence *"`read` scope is not enforced by the runtime. Any valid token can
  read every operator surface and create review sessions, exports, capsules, imports and
  delegations."* Grep basis, re-run this revision over
  `crates/swarm-runtime-http/src/`: `require_operator_api_scope` /
  `require_operator_review_scope` are called for `Maintenance` at `maintenance.rs:28`,
  `containment.rs:197`, `control.rs:82`, `:117`, `:154`, `review.rs:419` (6); `Approve` at
  `approval.rs:73`, `:137` (2); `Rehearse` at `review.rs:166` (1); and **`Read` nowhere**.
- **`review_session_create_handler` has no scope check at all** (`http/review.rs:204-221`): it
  takes a `Form<ReviewSessionCreateForm>` and no `AuthenticatedOperatorPrincipal`. It sits behind
  the router-level `require_bearer_auth` layer (`http/state.rs:472-479`), so it is
  authenticated — but any valid token creates review sessions. This matters because `/handoff`
  needs exactly that call (§8, B5).
- **No role-based UI gating claims until that changes.** Hiding a control the backend will
  happily serve is theatre that the next operator will discover and distrust.

### 7.6 Insider misuse, and the renderer-forged consent record

The console cannot prevent an authorized operator from granting a destructive action they
should not. What it can do is make the act attributable and permanent:

- **Two legs, never conflated.** Leg 1 is a signed `kind:9` card carrying the
  `ambush:verdict:v1` marker — a Nostr event the operator's own key signed, which the relay stores
  immutably. (Not `46030`/`46031`: `is_command_kind` routes those to `command_executor`, which
  rejects them without a `workflow_approvals` row — `03` §5.5.) Leg 2
  is the decision POSTed to the daemon. The intent record exists whether or not the daemon
  dispatches.
- **Full-key attribution everywhere a decision is displayed.** `<PubKey variant="full">` is
  required on security-decision surfaces because truncated prefixes are forgeable by vanity
  grinding (`PubKey.tsx:20-31`). Perch adds grant/refuse/release/verify to that required list.

**The correction.** The earlier draft concluded from leg 1 that *"'I granted it but it didn't run'
and 'I never granted it' are distinguishable after the fact"*. They are not, because the webview
holds a generic signing oracle:

```rust
#[tauri::command]
pub async fn sign_event(
    kind: u16, content: String, created_at: Option<u64>, tags: Vec<Vec<String>>,
    state: State<'_, AppState>,
) -> Result<String, String> { let keys = state.signing_keys()?; … }
```

`desktop/src-tauri/src/commands/identity.rs:107-135`, exposed to JS as `signRelayEvent`
(`desktop/src/shared/api/tauri.ts:596-604`). Arbitrary kind, arbitrary content, arbitrary tags,
the operator's own key. A compromised renderer forges an `ambush:verdict:v1` grant card for any
hold at any time —
so it can grant *and* manufacture the evidence that a human deliberated. Keeping the daemon bearer
token in the keyring does not help either: the decide call goes through a Tauri command that
applies the token on the renderer's behalf, which is a textbook confused deputy.

**Control, required before any grant path ships:**

1. **A dedicated Rust command, `perch_record_verdict(hold_id, decision, rationale)`**, which
   (a) fetches the hold from the daemon itself, (b) constructs the `ambush:verdict:v1` card body
   **from that fetched state**, so the renderer chooses nothing but the verdict enum and free-text
   rationale, (c) requires an OS user-presence confirmation the webview cannot drive, and
   (d) signs the Ed25519 decide payload (B1.6) alongside the Nostr envelope.
2. **A content and kind gate on `sign_event`**: it refuses `kind:46010` outright, and refuses any
   `kind:9` whose content's first line is an `ambush:*:v1` marker. Since the verdict now rides
   `kind:9` (`03` §5.5) a kind allowlist alone is not enough — `kind:9` is also every ordinary
   case message. Enforced by a Rust test over the command surface. This is INV-29.
3. Rationale text is the *only* renderer-supplied field in the intent record, and it is stored
   and rendered as adversary-class text (§7.7) on the receiving side, because a compromised
   renderer authors it.

**A caveat the carrier change removes, recorded so nobody re-adds it.** The earlier draft carried a
warning that `KIND_APPROVAL_GRANT | KIND_APPROVAL_DENY` are in `required_scope_for_kind`
(`ingest.rs:544`) but in **neither** `requires_h_channel_scope` (`:703-732`) nor
`is_global_only_kind` (`:621-700`), so an intent record could land global with no `h`. That hazard
is gone: `03` §5.5 moves the verdict onto `kind:9`, which **is** in `requires_h_channel_scope`
(`ingest.rs:707`), so the relay itself requires the `h` tag and the compartment is enforced rather
than asserted. INV-12 and INV-13 survive as belt-and-braces on Perch's own publish and render
paths, and the daemon still reads none of this, so a mis-scoped intent record is inert with respect
to authorization.

### 7.7 Prompt injection through rendered attacker-controlled strings

**This is real, and it is the highest-severity item in this document.**

The telemetry Ambush ingests is written by the adversary. `ProcessStartEvent` carries
`parent_process`, `process_name`, `command_line: String`, `executable_path` and `signer`
(`swarm-core/src/telemetry.rs:88-96`). `CloudTrailEvent` carries `user_agent`, `error_message`,
and `request_parameters` / `response_elements` as `serde_json::Value` — arbitrary JSON
(`telemetry.rs:84-102`). `KubernetesAuditEvent` carries `annotations` and `request_object`, also
arbitrary (`telemetry.rs:107-127`). `RuntimeEvent::AgentAction.details` is `serde_json::Value`
(`swarm-runtime/src/runtime_events.rs:248`) and `TamperAlert.unexpected_library_loads` is a
`Vec<String>` of host paths (`:254`).

And — this is what makes an allowlist the wrong shape — the worst carriers are not declared in
`telemetry.rs` at all:

- `DetectionFinding.evidence` is `serde_json::Value` (`swarm-whisker/src/detector.rs:57`) and
  flows **verbatim** into `PheromoneDeposit.indicator`: `findings_to_deposits` builds
  `json!({ "event_id": …, "host_id": …, "source": …, "evidence": finding.evidence.clone() })`
  (`swarm-whisker/src/stream.rs:34-40`).
- `ActionRequest.evidence` is `serde_json::Value` (`swarm-policy/src/lib.rs:57`) — the blob that
  carries both the governance receipt and the rule-selecting context.

Every one of those strings reaches the verdict pane, and two distinct attacks follow.

**Attack A — UI spoofing / chrome forgery.** Buzz renders message bodies through
`react-markdown` v10. The rehype plugin list holds three local plugins and no `rehype-raw`
(`markdown/nodeCache.ts:93-99`), so raw HTML is not rendered and **this is not XSS**. It is worse
in a subtler way, and the earlier draft understated it by naming only "headings, bold, links and
tables". The *remark* list at `nodeCache.ts:108-118` is:

```
remarkGfm, remarkBreaks, remarkSpoilers, remarkChannelDeepLinks, remarkMessageLinks,
remarkEntityLinks, remarkMentions, remarkChannelLinks, remarkCustomEmoji
```

Four of those manufacture **clickable deep links and real @-mentions from plain text containing
no markdown syntax at all**. So an attacker-authored process name is not merely styled; it can
become a `buzz://`-class deep link, a channel link, or a mention that renders as a colleague. The
attack is the autolinking, not the emphasis. A command line of

```
powershell -enc <b64>   ## ✅ GOVERNANCE RECEIPT VERIFIED — signed by tom-…
```

renders as a heading in the evidence block; a command line containing `#engineering` or a message
URL renders as navigation the operator's own product manufactured.

**Attack B — marker forgery.** The evidence-card design sniffs content. Buzz's own precedent is
`parseWaveMessageContent`, which is exactly `content.trimStart().startsWith(WAVE_MESSAGE_MARKER)`
(`waveMessage.ts:12-19`), dispatched from `MessageRow.renderBody`'s default arm. If Perch adopts
`<!-- ambush:receipt:v1 -->` sniffing on the same path **and** any attacker-controlled string can
reach the start of a rendered body, an attacker plants a forged receipt card. The distance between
"a process name lands in a `kind:9` body" and "an adversary renders a verified-receipt card in the
case timeline" is one careless composition.

**Controls, all four required:**

1. **A distinct render frame for adversary-controlled fields.** Perch defines
   `<AdversaryString>` — monospace, pre-wrapped, quoted, **no remark pipeline of any kind** (a
   plain text node, not `react-markdown` with plugins disabled), no autolinking, length-capped at
   512 rendered characters with an explicit expand, control characters and zero-width/bidi
   codepoints escaped and visibly marked. It sits inside a rail labelled `ADVERSARY-CONTROLLED`.
   **The verdict pane's ACTION and BLAST RADIUS slots use `<AdversaryString>` for every
   value-typed field**, because `host_id`, `file_path`, `process_name`, `target` and `scope_value`
   are all attacker-influenced.
2. **Marker sniffing runs only on the first line and only for events signed by an admitted
   agent key.** The check is `line0 === MARKER` on an event whose `pubkey` resolves to a
   registered bridge identity — not `startsWith` on arbitrary content. A `kind:9` from any other
   signer renders as prose no matter what it contains. Per §7.2 this rule extends to `46010`.
3. **The allowlist is inverted, and this is the change from the earlier draft.** A
   *dangerous-field* allowlist derived from `telemetry.rs` fails open on every field added later
   and already misses `DetectionFinding.evidence`, `AgentAction.details` and
   `ActionRequest.evidence`. Perch instead maintains a **trusted-string allowlist** — values that
   came from a Rust enum's `kind()`, a `Severity` or `ThreatClass` variant, a number, a UUID, or a
   hex id of known length — and `tools/check-perch-adversary-strings.sh` fails the build on **any
   other interpolated string in the Perch feature tree** that is not wrapped in
   `<AdversaryString>`. Adding a field is then safe by default and *widening trust* is the thing
   that needs review. Same shape as Buzz's `check-pubkey-truncation.mjs`, which exists for exactly
   this class of "one careless render undoes the doctrine" problem.
4. **Never feed a rendered string to an agent as instruction.** Perch has an in-case agent
   surface. Any adversary-controlled text passed into an agent prompt is prompt injection with
   a shell attached. Adversary fields cross that boundary only as explicitly delimited, labelled
   data, and the case-scoped PTY is the operator's tool, not an agent's.

### 7.8 Log and PII exposure

`/watch-floor` is an ambient wall screen, potentially on a monitor visible to people who are not
on shift. It reads ephemeral telemetry, which includes `TamperAlert.unexpected_library_loads`
(host filesystem paths, `runtime_events.rs:254`), `Ingest.host_id`, `AgentAction.details`
(arbitrary, `:248`), and — through CloudTrail — `principal_arn`, `principal_name`,
`source_ip_address` and `user_agent` (`telemetry.rs:88-95`).

Controls: a **per-payload-kind field allowlist** for the Watchfloor (counts, threat classes,
concentrations, agent health, mode — no free strings), with everything else reachable only from
a case, on demand, one field at a time. `TamperAlert` renders on the wall as *"tamper alert —
1 unexpected library load"* with the paths behind a click that is attributed in the audit log.

And `/v1/events/stream` gets gated regardless (brief item 5, constraint C7): today
`resolve_demo_scope` returns the caller's requested scope whenever no `context_token` query
param is present (`ingest/mod.rs:636-647`), so the entire runtime event stream — tamper alerts
with library paths, response executions with receipt ids and policy verdicts, arbitrary agent
details — is unauthenticated. Perch does not consume it (ingress is in-process via
`IngestState::subscribe_runtime_events()`, `ingest/mod.rs:1875`), which means fixing it costs
Perch nothing and must happen anyway.

The `<PubKey>` truncation guard (`desktop/scripts/check-pubkey-truncation.mjs`) is extended to
Ed25519 64-hex identities and lands in Ambush as `tools/check-key-truncation.sh` per
`02-ARCHITECTURE-INTEGRATION.md`.

### 7.9 Cross-tenant leak on colony switch

`resetCommunityState()` (`useCommunityInit.ts:54-83`, 22 reset calls read this revision) is an
inventory maintained by discipline. React key-remount clears React state only; module-level Maps
and class instances survive. In a security console a missed reset is not a stale cache, it is
**one colony's findings rendered under another colony's name**. Control: in the same change that
adds the first Ambush singleton, `resetCommunityState` becomes a typed registry with an
exhaustiveness check — a `Record<ColonyScopedSingleton, () => void>` over a union the compiler
forces to be total. This is risk (4) from the brief, and it is a P0, not a hygiene item.

---

## 8. The backend Ambush must build before Perch may claim what it claims

**The reconciled bill lives in `09-ROADMAP-AND-RISKS.md` §3.1** — eleven items under one label
set (`B1`, `B2`, `B2r`, `B2g`, `B2o`, `B3`, `B3i`, `B3r`, `B4`, `B5`, `B6`), each carrying who
calls it, what process it runs in and what it does to the data. `03-DOMAIN-EVENT-MAPPING.md` §11
owns the wire-level rationale for six of them. This document adds three and extends one, because
§0 showed that three of this document's central claims are not true of the code as it stands.
They are numbered locally to slot into `03`'s list; the mapping to `09`'s labels is
**B1.5 = B2g**, **B1.6 = B2o**, **B1.7 = B6**, **B5+ = B5**. Cite `09` §3.1's labels in new work.

| Item | What | Why this document needs it | Perch claim gated on it |
|---|---|---|---|
| **B1.5** | **Governance and partition re-evaluation on the decide path.** Either lift `missing_governance_receipt_reason` (`dispatcher.rs:1294-1310`) and `authorize_partition_request` (`:1014`) out of the dispatcher into a shared pre-routing check, or have `POST /decide` call `route_request` rather than the runtime directly. On failure the route returns a typed `RefusedLate { rule: "governance.missing_receipt" }` **before** dispatch. | §0.2(a): the human path today calls only `decorate_receipt_with_governance`, which warns and proceeds. | The verdict pane may not render `RECEIPT REQUIRED` as an enforced fact; §3.2's `RefusedLateGovernance` arm is drawn dashed; §1's "Receipt-backed response" row carries the caveat. |
| **B1.6** | **The operator in the receipt.** Thread `approved_by: Option<OperatorApproval>` — `{ operator_id, decided_at_ms, hold_id, ed25519_signature }` — through `audit_authorize_and_execute_human_approved_instrumented` (`lib.rs:1085-1092`) into `ResponseReceiptAudit` (`swarm-response/src/lib.rs:118-125`) and the spine envelope. | §0.2(b): a granted destructive action is byte-indistinguishable from an autonomous one except that `policy.verdict` reads `require_human`. | `MANIFEST.json` carries `"answers_who_approved": false`; §6.4 and all positioning copy say the chain answers "a human was asked", not "who approved this". |
| **B1.7** | **Sign the facts.** Wrap every fact the bridge publishes in `build_signed_envelope` (`swarm-spine/src/envelope.rs:71`) before it leaves the daemon — the same one-call pattern `approval.rs:1810` already uses, with a per-issuer `seq` and `prev_envelope_hash`. This is what makes `verify_chain_link` (`chain.rs:75`, currently zero consumers) real. | §0.2(c): `DetectionFinding`, `SwarmFindingEnvelope`, `ResponseReceipt`, `AuditTrail` and `RollbackReceipt` carry no signature; ADR 0010:140-144 says nothing checks chain linkage. | Verification renders **tier 0** on finding, escalation, hold and rollback cards (§6.2); §6.3's three checks collapse to a daemon re-fetch; `envelopes/` in the export bundle is empty and `VERIFY.md` says why. |
| **B5+** | **Gate the unauthenticated and unscoped surfaces**, extending `03`'s item 5. `/v1/events/stream` (`ingest/mod.rs:636-647`) is unauthenticated. `review_session_create_handler` (`http/review.rs:204-221`) is authenticated but takes no `AuthenticatedOperatorPrincipal` and performs no scope check; it needs `require_operator_api_scope(&principal, OperatorScope::Approve, …)`. | §7.5, §7.8, and INV-01: `/handoff` must call the review-session create, and INV-01 as originally written would have failed the build on it. | `/settings` states both defects verbatim until they are fixed; INV-01's allowlist names the review-session create explicitly. |

**Ordering.** B1.5 and B1.6 are the same edit to the same function signature and should land
together, immediately after `03`'s B1 (`HeldActionStore` + `RuntimeEvent::ResponseHeld`) and
before B2 (`POST /decide`) ships to a user — otherwise the first decide route in existence is one
that skips the gate. B1.7 is separable and can follow, because tier 0 is a *rendered* honest state
rather than a broken one. B5+ is independent of all of them and should not wait.

**Sizing note for `09-ROADMAP-AND-RISKS.md`:** B1.5 and B1.6 are Rust work on the critical path
and are not in the current 11 ew Rust estimate. This document does not size them; it names them so
they can be sized.

---

## 9. Invariants, written as tests

Each line is an assertion. `[UI]` = a Playwright/unit test in the Perch tree. `[CI]` = a
`tools/check-*.sh` or `scripts/check-*.mjs` gate. `[E2E]` = a relay-backed integration test.

| ID | Invariant | Kind |
|---|---|---|
| INV-01 | Perch issues no write to any Ambush store beyond a named allowlist. The only Ambush-bound mutations from the console process are `POST /v1/response/holds/{id}/decide` (B2), `POST /v1/operator/findings/{id}/feedback` (B3), **the incident-minting write behind promote-to-case (B3i)**, `POST /v1/operator/containment/leases/{id}/release`, and `POST /v1/operator/review/sessions` (the `/handoff` composition, `04` §2.11). Any other Ambush-bound non-GET fails the gate. The B3i entry was missing from the first draft of this list, which would have failed the build on the first promote-to-case. | CI |
| INV-02 | The verdict pane renders its five slots in the fixed order for all 15 `ResponseAction` variants, with no slot omitted. Snapshot per variant. | UI |
| INV-03 | No `ResponseAction` renders an enabled Undo affordance unless `resolve_inverse(action, step)` returns `Ok` for **every** step of the plan. | UI |
| INV-04 | `RollbackStepStatus` renders as five distinct strings. No two of Reversed / Simulated / Irreversible / Unsupported / Failed produce identical DOM text. | UI |
| INV-05 | A release response with `lease_closed: false` renders in the error register regardless of HTTP status. Test drives a 200 with `lease_closed: false`. | UI |
| INV-06 | `remaining_ms` and `expired` render as two separate elements. A lease with `remaining_ms: 0, expired: false` and one with `remaining_ms: 0, expired: true` produce different DOM. | UI |
| INV-07 | No element in the Perch tree offers extending a containment lease. Grep for `extend` on lease surfaces fails the build. | CI |
| INV-08 | `governance_attestation: None` renders the literal token `UNATTESTED`, with no success-register styling — and renders the **`UNATTESTED — BY DESIGN`** variant iff `PartitionState` at execution was `Partitioned` or `Healing`. Both cases asserted. | UI |
| INV-09 | No governance surface renders a quorum fraction. Grep for `/\d+\s*\/\s*\d+\s*governors?/i` in Perch source fails the build. | CI |
| INV-10 | The grant control never resolves to the default `buttonVariants()` and its accessible name never matches `/^\s*approve\b/i`. | CI |
| INV-11 | The grant is two-stroke and gated: `G` arms and is ignored when `event.repeat` is true; the confirm is disabled until the BLAST RADIUS block has been fully visible and the pane has held this `hold_id` ≥ 1500 ms; arming resets on `hold_id` change. No `data-perch-role="grant"` element is reachable from a multi-select context. | UI |
| INV-12 | Every `ambush:verdict:v1` card Perch publishes carries an `h` tag equal to the open case's channel UUID. (The relay also requires it — `kind:9` is in `requires_h_channel_scope` — so this asserts Perch's own publish path, not the relay's.) | E2E |
| INV-13 | The case timeline refuses to render an `ambush:verdict:v1` card whose `h` tag does not match the case channel. | UI |
| INV-14 | **Trusted-string allowlist, not a dangerous-field one.** Every interpolated string in the Perch feature tree that is not on the trusted-value allowlist (enum `kind()`, `Severity`/`ThreatClass` variant, number, UUID, fixed-length hex) is wrapped in `<AdversaryString>`. Unwrapped interpolation fails the build. | CI |
| INV-15 | Marker sniffing (`ambush:*:v1`) fires only when the marker is the entire first line **and** the event's `pubkey` resolves to an admitted bridge identity. **The same admission rule applies to `kind:46010`:** a hold from an unadmitted signer renders as untrusted prose, never enters the needs-action queue, and never reaches a wake class. | UI + E2E |
| INV-16 | No source count renders alone. Every `distinct_sources` render is accompanied by an agent count, per render law 2 (`stream.rs:20-22` scopes ids by strategy; `substrate.rs:1295` counts them). | UI |
| INV-17 | Every value the console computes that the runtime does not carries a derived marker naming the producing function. Export's `DERIVED.json` is non-empty iff any derived value is rendered. | UI |
| INV-18 | A hold that reaches `hold_ttl_ms` (3,600,000 ms default) undecided transitions to `Expired`, dispatches nothing, and renders in the queue for the rest of the shift. | E2E |
| INV-19 | `/handoff` cannot be completed while `expired_undecided > 0` without an explicit acknowledgement. | UI |
| INV-20 | Exactly four notification classes can produce an OS notification. A fifth registered class fails the gate. | CI |
| INV-21 | The twelve lane channels are muted by default on first run. | E2E |
| INV-22 | The daemon bearer token never appears in any value crossing the Tauri IPC boundary into the webview. Runtime assertion in dev + a Rust test over the command surface. | CI |
| INV-23 | `resetCommunityState` is exhaustive over the `ColonyScopedSingleton` union. Adding a member without a reset fails `tsc`. | CI |
| INV-24 | No empty state contains the string "looks good", "all clear", "no data" or "nothing to see" — **universal**. Every *swarm-produced-nothing* empty state links `/gaps`; other empty states name their own governing number instead and must not link it (`04` §2.12, `09` §4.2 criterion 4). | CI |
| INV-25 | Every verification result names the chain it checked (`Ed25519` or `secp256k1`) **and its tier (0/1/2)**. A verification badge with no chain label or no tier label fails the test. | UI |
| INV-26 | Receipts and envelopes in an export bundle are byte-identical to the daemon's stored bodies. Round-trip hash comparison. | E2E |
| INV-27 | No Perch surface offers an override, break-glass, or force path for a `PolicyVerdict::Deny`. | CI |
| INV-28 | A grant followed by a daemon `RefusedLate` (including `RefusedLateGovernance` once B1.5 lands) renders as a normal outcome with the rule name, not as a client error. | UI |
| INV-29 | **`sign_event` cannot sign a governance artifact.** A Rust test over the command surface asserts that `sign_event` rejects `kind:46010` and rejects any `kind:9` whose content's first line is an `ambush:*:v1` marker, and that the only producer of an `ambush:verdict:v1` card is `perch_record_verdict`, which builds its body from daemon-fetched hold state. | CI |
| INV-30 | **The CSP is the pinned string.** A string-equality assertion against `tauri.conf.json`'s `security.csp`; `https:`, `http:`, `wss:`, `ws:` as bare `connect-src` sources, and any remote `script-src` host, fail the build. | CI |
| INV-31 | **No verdict control binds `A`.** The keymap is `C`/`D`/`I` for findings and `G`/`R` for holds. A `key` binding of `a`/`A` on any verdict control, or the label `Approve` anywhere in the Perch tree, fails `tools/check-copy-banned-terms.sh`. | CI |
| INV-32 | **No single key is bound to two different verdict verbs across row types in the same list.** Asserted as a table test over the keymap registry, since holds and findings interleave in the needs-action queue. | UI |
| INV-33 | **No optimistic UI on a governance path.** Grant, Refuse, release and finding verdict each render three distinct states (sending / recorded / daemon-acknowledged-or-refused). No undo affordance exists on any of them. | UI |
| INV-34 | A hold row's snooze control is disabled and renders the stated reason; a finding row's is enabled. Asserted on both row types in one list. | UI |
| INV-35 | A `kind:46010` present on the relay and absent from `GET /v1/response/holds` renders as **FORGED**, in the destructive register, and is excluded from the export bundle's `holds/`. | E2E |

---

## Cross-references and dependencies

**This document depends on:**

- `02-ARCHITECTURE-INTEGRATION.md` — the `swarm-perch-bridge` crate, the two-arm relay fork, the
  `9090` lint, and the CI-gate adoption path (`tools/check-*.sh` + a wired workflow step).
- `03-DOMAIN-EVENT-MAPPING.md` — marker-comment card shapes, the tag budget, the two identity
  chains, and the wire-level rationale for six of the eleven bill items (`09` §3.1 is the
  normative label set; this document extends it in §8).
- `04-SURFACES-AND-UX.md` — the Watch, the Verdict Row, `/leases`, `/policy`, `/handoff` as
  surfaces; **and the keymap, which this document now adopts verbatim.**
- `05-DESIGN-SYSTEM.md` — the severity ramp, the pinned accent, and the badge tokens §2.2 uses.
- `06-COPY-AND-VOICE.md` — owns the exact strings; this document owns which claims they may make,
  and contributes three ban-list entries (`Approve`, bare `lane`, `A` as a verdict key).
- `07-REALTIME-AND-DATA.md` — the disk spool, per-issuer sequence, the 1 Hz coalescing that make
  §6.3's gap-rendering possible, and **decision 8 (no optimistic UI on governance paths)**, which
  this revision now honours.
- `09-ROADMAP-AND-RISKS.md` — sequencing if `HeldActionStore` slips, and the sizing of §8's B1.5,
  B1.6 and B1.7, which are not in its current Rust estimate.

**Changes this document requires of its neighbours** (each is a consequence of a finding this
revision accepted, not a preference):

| Doc | Change |
|---|---|
| `00-BRIEF` | Amend the keymap to `C`/`D`/`I` + `G`/`R`; settle `hold_ttl_ms: 3_600_000`; add B1.5/B1.6/B1.7 to the Ambush backend bill; name The Watch (`/`) as the C9 counters' home. |
| `01-POSITIONING` | Replace "Press **A**" at `:167` and `:349`; the two-minute demo's mid-hold walk is now consistent with a 60-minute TTL. |
| `03` | §2's "verification runs against the Ed25519 chain" becomes the three-tier statement of §6.2; §11.2's "re-evaluates policy and governance" becomes "re-evaluates policy; governance only after B1.5"; §4.2's presence justification becomes the 180 s lie-window. |
| `04` | Drop `S` from the hold affordance list (§2.1, §3.1); the Verdict Row wireframe adopts the two-stroke blast-radius gate rather than a plain outline button; `⏱ 47m` is now correct against a settled 60-minute TTL. |
| `05`, `07` | Rename their own uses of "lane" (hue family / transport class) per §0.3. |
| `06` | Move the snooze control string off the verdict pane; add `Approve`, bare `lane`, and `A`-as-verdict-key to `tools/check-copy-banned-terms.sh`. |
| `09` | Exit criterion 6 names `/` rather than `/watch`; Phase-0 gains the CSP tightening (INV-30) and the `sign_event` allowlist (INV-29); F3's `invokeTauri` seam size takes 02's measured figure, not the brief's inherited one. |
