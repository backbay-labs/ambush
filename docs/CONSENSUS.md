# Governance And Consensus Contract

This document is part of the active contract set defined in
`docs/REFERENCE-STATUS.md`.

It describes the bounded governance model that ships today: local policy,
receipt-backed destructive response, registry-backed identity admission, and
fail-closed partition handling.

## Executive Summary

Ambush now ships a real governance lane, but it is deliberately narrow.

The runtime does not require consensus for every action. Most roles observe,
investigate, correlate, remember, or evolve without entering the governance
path. Governance applies when the runtime crosses a trust boundary:

- a destructive response action is about to execute
- a runtime identity must be trusted to participate
- partition-era emergency authority must be staged or redeemed

Everything else should remain outside the governance path unless a later
milestone explicitly promotes it.

## Governance Modes

The active runtime uses four governance modes.

| Mode | What it covers | What is required |
| --- | --- | --- |
| Observation | Detection, investigation, correlation, memory, deception, status publication | No governance receipt; standard signed deposits and audit only |
| Guarded response | Non-destructive response actions such as escalation or decoy deployment | Policy validation and ordinary audit trail |
| Receipt-backed response | Governed response actions listed below | One-time request-bound governance authorization, one policy preflight, and human approval when that preflight returns `RequireHuman` |
| Partition contingency | Destructive response while quorum is partitioned | Valid staged contingency lease plus partition authorization and later reconciliation |
| Maintenance-only | Local operator review, export, replay, and bounded maintenance actions | Authenticated operator access and maintenance audit, but no widened destructive authority |

This is the shipped contract. It is not a general-purpose distributed control
plane.

## What Requires A Governance Receipt

`ResponseAction::requires_governance_receipt()` is the single classification
source. It currently classifies these actions as governed:

- `BlockEgress`
- `IsolateHost`
- `RevokeCredential`
- `SinkholeDns`
- `TerminateUserSession`
- `InjectFirewallRule`
- `QuarantineFile`
- `KillProcess`
- `SuspendProcess`
- `DisableUserAccount`
- `ForcePasswordReset`
- `RemoveScheduledTask`

`TriggerEdrScan`, `DeployDecoy`, and `Escalate` are not governed by this
receipt boundary. They remain subject to normal policy and audit controls.

For those actions:

1. `Pouncer` constructs the complete `ActionRequest`, then asks `Tom` policy
   whether that exact request can proceed.
2. `Tom` runs one consensus round through the `ConsensusTransport` its policy
   holds and persists an issued authorization in the pending ledger before
   returning its receipt. An approval, veto, and partition contingency are
   distinct typed outcomes.
3. The dispatcher preflights ordinary policy once without consuming governance.
   `Deny` stops there. `RequireHuman` durably holds the exact request, policy
   decision, and still-pending governance receipt, then binds a persisted
   approval set; it creates no admission and invokes no executor.
4. An `Allow`, or the dedicated resume path after an exact persisted human pack
   is verified, atomically consumes the governance authorization immediately
   before routing. Only then does the dispatcher create one opaque, non-cloneable
   admission and move it to one router invocation.
5. The runtime consumes that admission by value without parsing the receipts or
   evaluating mutable policy a second time. Lease, containment, guard, adapter,
   and audit checks still apply. If routing or execution fails after durable
   consumption, the authorization is burned rather than made replayable.

Non-destructive actions remain guarded and audited, but they do not require a
governance receipt in the current runtime.

### Request Binding And One-Time Admission

Normal action authorization uses the domain-separated
`GovernanceActionRequestSubjectV1`. Its canonical JSON binds the domain and
schema version plus `hunt_id`, `requested_by`, the complete response action and
target, derived scope, severity, and the remaining evidence. Only the bearer
fields `governance_receipt` and `contingency_lease` are excluded. The proposal
identifier is the hash of that canonical subject.

A receipt is not authority merely because its signature verifies. The installed
`GovernanceAuthority` separately verifies and consumes an `Approve` for a
`RequestResponse` route or a `Veto` for a `GovernanceVeto` route. It requires:

- the supported receipt schema and a signer in the configured governor set
- the exact expected decision and exact canonical subject/proposal digest
- bounded age and future clock skew
- committee, threshold, tally, commit-hash, and receipt-id consistency that can
  be derived from the local receipt data
- a matching entry in the persisted pending-authorization ledger
- durable movement to the bounded consumed ledger before routing

Missing legacy pending state, a replayed receipt, or any issuance/consumption
persistence failure refuses the route. These checks prove local consistency
and one-time policy issuance. They do **not** prove that a distributed quorum
actually exchanged votes; that depends on the transport described below.

### How The Round Is Actually Run (BFT-03, phase 321)

This is the part that is easy to overstate, so it is stated exactly.

- `GovernancePolicy` holds AT MOST ONE governor signing key
  (`LocalGovernorKey`), and `register_governor` returns
  `Err(GovernanceKeyError::SecondSigningKey)` for a second, different key. The
  type exposes no accessor returning a `SigningKey`. Until phase 321 this was a
  `BTreeMap<AgentId, SigningKey>` and the round was simulated by building one
  in-process node per key -- a shape in which one process could cast every
  committee member's vote.
- Peer governors are admitted by identity alone
  (`register_peer_governor(&VerifyingKey)`); no peer key is ever held. The
  admitted set IS persisted, because forgetting it across a restart is a
  fail-open: a policy that knows about a peer refuses every destructive action,
  and one that has forgotten it is back to a committee of one and starts
  authorizing again.
- The round is driven by `swarm_consensus::drive_round`, which publishes signed
  envelopes to a `ConsensusTransport` and consumes what the transport delivers.
  Its deadline is `round_timeout_ms * (max_faulty + 1)`.
- A round that does not commit inside that deadline returns an error, and
  `can_act` turns it into a `Veto` carrying the consensus error verbatim. It
  never falls through to `Allow`.

WHAT DOES NOT SHIP YET. The only transport in the tree is
`SoloGovernorTransport`, which serves a committee of ONE and REFUSES any larger
committee. So:

- a deployment registering one governor (the only shape
  `crates/swarm-runtime-http/src/bin/swarm_detect.rs` builds today) runs a real
  one-member round: `threshold() == 1`, the member is its own proposer, and the
  receipt names a committee of one;
- a deployment that admits peer governors WITHOUT installing a networked
  transport fails closed on every destructive action, with a veto naming the
  transport as the cause.

A networked transport -- pheromone-substrate or JetStream backed -- is not here.
It cannot be at the current signature: `ConsensusTransport` is synchronous (a
mailbox: publish to an outbox, drain an inbox), and a transport that must wait
for peers has to be `async`, which makes `GovernancePolicy::can_act` async. That
is the open half of BFT-04. Two consequences worth naming:

- contingency-lease issuance also runs a governance round, from the SYNCHRONOUS
  `observe_health` on every `TomAgent` tick, once per each of twelve destructive
  action kinds. Making the round networked changes that path's character
  completely, and it is deliberately not attempted here.
- BFT-03's requirement text also asks that governors exchange
  `ConsensusSignedEnvelope` **over the pheromone substrate**. That clause is NOT
  satisfied; the seam exists and the substrate transport does not.

### Restart Safety Of A Round

`PersistedGovernanceState` persists `previous_commit_hash`, the receipt counter,
the display-to-consensus governor identity mapping, exact unhealthy-agent
observations, the last healthy/quorum counts, partition state, active leases,
bounded pending and consumed authorization ledgers, and bounded exact-request
human holds. It persists NO round state and NOT the governor key. A restart
mid-round therefore loses the round. A receipt issued before restart remains
usable only if its pending entry was durably written; a consumed receipt remains
refused after restart. A held request can resume only from its bound persisted
approval set and pack while both approvals remain fresh. Governance LIVENESS is not restart-safe, and any claim of
"restart-safe recovery" should be read as covering the persisted fields above
and not the round.

The signed state rename is the commit point. A checkpoint failure after that
rename never rolls the in-memory authority state back. The policy records the
lag, withholds newly issued receipts and external consume/redeem/attest effects,
and repairs the signed checkpoint before another governed effect can proceed.
Health, peer, and human-staging callers retain committed state rather than
reporting that it was discarded. Initial creation has no older checkpoint to
anchor recovery, so an incomplete first checkpoint rolls the new state file
back and fails bootstrap.

One persisted governance stream has exactly one live process owner. Startup,
initialization, and explicit reinitialization acquire an exclusive OS advisory
lock beside the stream and retain its file handle for the full policy lifetime;
the existence of the lock file is not ownership and no stale-lockfile timeout is
used. The lock inode is permanent stream metadata: its `0600` record contains a
random 256-bit generation ID, and both the signed state and signed checkpoint
bind that generation together with the lock's filesystem device and inode. A
second process receives a typed startup refusal. Every mutation also
compares the caller's verified predecessor sequence and signed-statement digest
with durable state under that lock before writing. This CAS is defense in depth
against a stale in-process snapshot: it cannot borrow the latest sequence and
overwrite newer authorization state. Writers outside this lock protocol are not
a supported coordination model.

On the shipped Linux path and the macOS development path, the lock must be a
regular, non-symlink file. The policy binds the held handle to its filesystem
device, inode, and held-file generation record and rechecks all three before and
after state loads, transaction checks, state commits, and checkpoint commits.
Ordinary load and explicit reinitialization open the permanent lock without
`create`; a missing lock never becomes a fresh authority epoch implicitly. A
copied or replacement lock has a different signed binding and therefore cannot
load the existing stream. If a displaced owner crosses its final pre-write check,
its post-write check refuses the effect and the envelope remains bound to the
dead inode, so it cannot restart under the replacement path.
Persisted governance-stream startup is intentionally supported only on the
shipped Linux and macOS Unix path until an equivalent Windows file-identity
binding exists; persisted configuration on any other platform fails closed at
startup. The non-persisted in-memory policy is unaffected.
An active privileged host adversary can still make the stream unavailable by
deleting or replacing its files. The binding prevents that availability attack
from creating a second valid writer; it does not claim to make a path check and
rename one kernel-atomic operation.

Fresh initialization creates, fsyncs, and parent-directory-syncs the lock record
before signing either anchor. A retry after a parent-sync failure re-fsyncs the
same valid generation rather than minting another stream. Moving, restoring, or
snapshotting the files onto a different device/inode fails with a typed binding
mismatch. Recovery is explicit and offline with every process stopped.
State-preserving recovery is the explicit offline migration described
below. It authenticates both existing anchors with the externally admitted
Tom/primary key, creates or reuses durable lock metadata, changes only the lock
binding, and advances the state/checkpoint sequence. Signed payloads from the
immediately preceding schema that omit only the binding fail closed at ordinary
startup and are accepted only by that migration. Earlier signed schemas that
omit health, identity, committee, or authorization inputs remain unsupported
because defaulting those fields could fail open. Ordinary startup never performs
this migration.

A missing permanent lock cannot be repaired by `with_persistence` or
`reinitialize_persistence`. Stop every process first and run the explicit
state-preserving command with the same config, stable key root, identity
registry, and state volume:

```bash
swarmctl --config /etc/swarm/config.yaml identity migrate-governance-lock \
  --confirm-offline \
  --state-path /var/lib/swarm/governance-partition-state.json
```

The command loads an existing key without creating one, requires an exact active
Tom/primary registry record, verifies both signed anchors before creating the
lock, acquires the advisory lock, re-verifies unchanged bytes under the lock,
then signs state at `N+1` before signing checkpoint `N+1`. A lock-only failure is
retryable. A crash after the state commit leaves an older checkpoint; retry
recognizes the state already bound to the held lock and advances only the
checkpoint. A fully migrated retry is idempotent. Unsigned, corrupt,
wrong-signer, checkpoint-ahead, or incompatible-schema input creates no trusted
authority and fails closed. The command detects an active owner that implements
the permanent-lock protocol; `--confirm-offline` is still mandatory because a
pre-lock release has no advisory owner to detect.

If authenticated anchors are unavailable, archive the entire state root and
follow the destructive identity-root reset procedure; do not fabricate an empty
lock. Destructive reset discards membership, health, leases, holds,
authorization ledgers, and chain position. Rolling back both valid signed
anchors together remains outside local detection and requires an external
monotonic or independently authenticated anchor.

## Approval And Receipt Lineage

The active receipt chain is:

1. An admitted runtime agent proposes or routes a response.
2. `Tom` governance either approves, vetoes, or stages partition-time fallback
   evidence.
3. The dispatcher evaluates ordinary policy once without consuming governance.
4. `Allow` proceeds to atomic governance consumption. `RequireHuman` persists
   an exact hold and approval-set binding while leaving governance pending.
5. The dedicated resume path verifies the exact persisted human pack, rechecks
   governance freshness and pending state, then atomically consumes governance
   and creates the one-shot admission without a second policy evaluation.
6. Final execution and audit artifacts persist the request, decision, and
   outcome lineage.

This contract keeps one vocabulary across demo approval, live response, and
operator review: request, receipt, approval, audit, and evidence.

## Human Approval Boundary

Human approval is a separate boundary layered on top of receipt-backed
governance.

`policy.human_gate_severity` defines the severity at or above which destructive
actions are held for human confirmation even when receipt-backed governance has
otherwise authorized the request.

It governs the *fallback* leg of response authorization, not every leg.
`ConfigurableApprovalGate` evaluates `policy.rules` in file order; the first rule
whose threat class, severity band, action selector, time window, and per-agent
rate limit all match decides the request outright. Only when no configured rule
matches does evaluation reach `StaticApprovalGate`, which is the sole producer of
`RequireHuman` (`static.human_gate`). The precedence is therefore:

1. first matching `policy.rules` entry -> policy-layer `allow` or `deny`, immediately
2. no rule matched -> static gate -> `static.human_gate` for destructive actions
   at or above `policy.human_gate_severity`, otherwise `static.default_allow`

This is deliberate, and the shipped `rulesets/default.yaml` depends on it: the
`command-and-control-emergency-block` rule allows `block_egress` at CRITICAL
while `human_gate_severity` is HIGH, so its own stated purpose ("critical C2
traffic can trigger immediate containment and escalation") is only reachable
because a matching rule outranks the human gate. An operator who wants a
destructive action human-gated must not write a matching `allow` rule for it.
`configurable_gate_allow_rule_outranks_static_human_gate` and
`configurable_gate_human_gates_destructive_action_when_no_rule_matches` in
`crates/swarm-policy/src/configurable_gate.rs` pin both halves of this.

Current implications:

- a destructive request can be governance-authorized and still stop at the human
  gate, when no configured rule matches it; stopping persists a hold but consumes
  neither approval and executes nothing
- a matching configured `allow` rule passes the policy layer without a human
  hold; it still cannot replace dispatcher governance admission
- only the dedicated dispatcher resume route can compose the exact persisted
  human pack with the exact still-pending governance authorization
- serve mode opens all four durable approval stores (sets, ledgers, verdicts,
  and receipt packs). A governance-prefixed operator vote exports the pack,
  then calls the authenticated internal runtime endpoint
  `/v1/governance/approvals/{approval_set_id}/resume` with only its persisted
  pack ID. The runtime reloads the pack and samples its own clock immediately
  before freshness validation and consumption; neither the operator request nor
  the callback body can supply a timestamp
- that endpoint is an internal operator-to-runtime callback, not part of the
  public read-only platform API/OpenAPI surface. Missing stores or a missing pack
  fail closed; ordinary demo approval sets keep the existing demo-resume route
- forged, denied, stale, future-dated, or cross-request human packs consume
  neither approval; direct raw human-approved runtime entry points remain refused
- after atomic consumption, the admission is non-cloneable and any routing or
  execution failure burns both approvals
- human approval does not replace the governance receipt
- demo approval and live operator approval reuse the same bounded approval
  vocabulary rather than defining a second governance model

## Identity Admission Contract

Every runtime-owned agent identity follows the same admission path:

- keys persist under `identity.agent_key_dir`
- on the shipped Linux release path and macOS development path, a newly created
  key-root chain is recorded up to its nearest existing directory anchor, only
  the parents that anchor newly created entries are synced, and an existing root
  triggers no ancestor sync; sync failure aborts startup and best-effort removes
  only empty directories created by that attempt so retry repeats the durability
  sequence; each new key is still synced with the key root before creation is
  reported, and existing key bytes are loaded rather than creating another identity
- stable identities are derived from the Ed25519 public key
- registry snapshots and continuity proofs persist under
  `identity.registry_dir`
- unadmitted identities do not join the dispatcher or deposit trusted
  pheromones

Rotation is continuity-preserving rather than anonymous replacement. The active
contract is:

- identities are durable
- admission is explicit
- rotation preserves trust lineage
- retired keys remain available for historical verification

This is stronger than an in-memory allowlist and narrower than a full external
PKI or multi-tenant operator system.

## Identity Rotation And Verification

Rotation is part of the active contract for non-governor roles. Tom/primary is
the signer of persisted governance authority and therefore has a stricter
offline rekey boundary.

- `swarmctl identity rotate` preserves continuity from the retired key to the
  new key for non-Tom roles
- `swarmctl identity rotate --role tom` refuses before changing either the key
  store or registry; see `docs/CONFIGURATION.md` for the required offline rekey
  properties
- registry state retains enough historical material to verify older receipts and
  deposits
- governance and deposit validation fail closed for identities that are not
  admitted through the current registry state
- runtime registration and substrate admission both consume the same admitted
  identity set

## Governance Health States

The governance policy persists and reports four runtime states:

| State | Meaning |
| --- | --- |
| `healthy` | Quorum is available and partition-era activity is not active |
| `degraded` | Enough governors remain for quorum, but one or more are unhealthy |
| `partitioned` | Quorum is unavailable; destructive actions fail closed unless a valid contingency lease exists |
| `healing` | Quorum has returned and the runtime is reconciling partition-era activity |

These states are not abstract theory. They are persisted, emitted as runtime
events, and surfaced through `/healthz` and `/readyz`.

## Partition And Recovery Rules

The active partition contract is:

| State | Destructive response | Observability | Recovery expectation |
| --- | --- | --- | --- |
| `healthy` | Allowed through normal receipt-backed governance | Full health and runtime visibility | Stage bounded contingency leases for later emergency use |
| `degraded` | Denied with a signed governance veto while any unhealthy agent remains | Full visibility, degraded state reported | Repair unhealthy agents and confirm a healthy signed state before retrying |
| `partitioned` | Denied unless a valid staged contingency lease authorizes the exact action | Full visibility remains available | Persist every authorized and unauthorized partition-era attempt |
| `healing` | Normal quorum is back, but partition-era activity is being reconciled | Full visibility plus reconciliation markers | Review reconciliation output before treating the incident as closed |

This rule is intentional:

- destructive authority fails closed while any agent is unhealthy or quorum is unavailable
- health, metrics, and operator visibility remain available
- contingency leases are narrow emergency exceptions
- healing is a first-class state, not an implicit return to healthy

## Contingency Lease Contract

Contingency leases are staged while the system is healthy and redeemed only
under partition.

The active contract is intentionally narrow:

- leases authorize only a specific destructive action kind
- leases may be scoped to one host or other action scope
- leases carry a blast-radius cap
- leases expire after a bounded TTL
- operator status counts a lease only before its exact expiry boundary; the
  read does not mutate signed history, and later governed persistence performs
  ordinary expiry pruning
- each lease is bound to the exact canonical governor committee recorded in its
  signed receipt; admitting a new committee member atomically invalidates every
  lease staged by the prior committee
- each exact request and each covered scope is redeemable only once
- redemption is persisted before routing and retained for later reconciliation

Contingency leases are an emergency exception inside the existing governance
model. They are not an alternate control plane.

## Reconciliation Markers

When the runtime transitions from `partitioned` back toward quorum, it persists
and emits reconciliation artifacts that distinguish:

- partition-authorized actions
- unauthorized partition-era attempts
- the last reconciliation report identifier
- the latest partition-state transition time

Operators should treat these markers as part of the auditable response chain,
not as optional debug output.

## Observability And Operator Surfaces

Operators should expect governance state in these surfaces:

- `/healthz` and `/readyz` governance component details
- runtime events for partition transitions and reconciliation
- audit evidence attached to response execution
- persisted governance state on disk for restart-safe recovery
- reconciliation report identifiers and active contingency-lease counts in the
  serve-mode governance component

The platform and operator surfaces consume this governance data, but they do not
change the underlying authorization semantics.

Persisted governance authority is one Tom/primary-signed state envelope plus an
adjacent Tom/primary-signed sequence checkpoint. The externally preloaded and
admitted Tom key is the signer expectation; persisted peer governors are
committee membership, not receipt-signing trust anchors. The shipped issuance
path remains local-only. On load, a signed contingency lease whose receipt names
a different canonical committee is discarded rather than migrated into the
current committee's authority.
The shipped Helm profile uses a single `Recreate` deployment and
`ReadWriteOncePod` storage. Rendering fails when shared persistence is enabled
with more than one replica; rolling pod overlap is not a supported authority
topology.
Rollback of only the envelope is detected against the checkpoint. Rolling back
both local files together is outside the protection of this design and requires
an external monotonic or independently authenticated anchor.

## Pre-1.0 Rust API Migration

The security boundary intentionally breaks several public Rust source APIs.
There is no compatibility shim because each old shape omitted information now
required to fail closed:

- `GovernancePolicy::with_persistence(config, path) -> std::io::Result<_>` is
  now `GovernancePolicy::with_persistence(config, path,
  admitted_tom_agent_id, tom_signing_key) ->
  Result<_, GovernancePersistenceError>`. Callers must load or create the stable
  Tom/primary key, admit that externally derived identity through the registry,
  and pass that exact identity and key. Legacy unsigned state must be explicitly
  reinitialized offline; persisted envelope fields never supply the trust
  anchor.
- `GovernancePolicy::migrate_persistence_lock(path, admitted_tom_agent_id,
  tom_signing_key)` is the only state-preserving missing/rebound-lock path. It
  accepts the exact immediately preceding signed payload schema or the current
  schema, advances the signed sequence, and requires an externally admitted
  signer. There is no overload that trusts an envelope signer or creates a key.
- `ContingencyLease::verify()` is now
  `verify(&trusted_governor_identities)`. Callers must pass identities from the
  admitted authority, normally `GovernanceAuthority::governor_public_keys()`;
  the signer embedded in the lease is not its own trust anchor.
- `GovernanceDecision::Allow { receipt: Option<_>, ... }` is split into
  `NotRequired` for actions outside receipt-backed governance and `Authorize {
  receipt, contingency_lease }` for governed approval. Match both explicitly;
  do not convert a missing receipt into authorization.
- the sealed `GovernanceAuthority` gained one-shot approval/veto consumption
  and the human hold, binding, lookup, and atomic human-consumption methods.
  Runtime callers must retain the same authority object through issuance and
  consumption. The trait remains sealed, so downstream crates should consume a
  supplied `dyn GovernanceAuthority` rather than attempting an external
  implementation.

## Ingest, Bridge, Demo, And Raw Runtime Boundaries

Live HTTP ingest and bridge ingest still detect, deposit, publish findings, and
forward telemetry to the agent lane. Their synchronous playbook selector does
not return a governed action. `Pouncer` constructs and governs the later request
once; ingest does not start a duplicate round.

All raw `SwarmRuntime` entry points refuse governed actions in enforced mode
before policy, lease issuance, guards, containment, or executor invocation.
This is keyed to the actual execution mode, not the caller's `live_mode` flag.
Detect-only rehearsal and non-governed action behavior is unchanged.

The guided `swarmctl first-run` path is a detect-only governed-action and policy
rehearsal. It mints neither a human-approval receipt nor a governance
authorization. A live demo step that names a governed action records
`governance_deferred`; it does not create a human-resume path that could bypass
`Pouncer` and the dispatcher. The hidden, deprecated
`--voter-signing-key-env` option remains parseable for one compatibility release
but is ignored; quickstart retains `receipt_pack_id: null` in JSON for the same
compatibility window.

The governed-resume callback is a bearer-bearing internal hop. Its configured
`operator_surface.runtime_base_url` is fully validated even when callers use a
public `LocalOperatorSurface` config constructor, and its dedicated client
ignores process proxies, refuses redirects, and applies a bounded timeout.
The surface stores the trimmed URL that validation accepted. A non-success
callback diagnostic contains only the HTTP status; the upstream response body
is never read or echoed.
A refused redirect never contacts its target and leaves the exact
governance/human hold pending. Other transport failures can be ambiguous after
delivery, so operators inspect the persisted hold before retrying; durable
one-time consumption prevents an already consumed approval from executing again.

Source compatibility note for this release: downstream implementations of the
public `RequestResponseRouter` trait must remove the former `now_ms` parameter
from `restore_human_preflight`. The dispatcher now owns the clock and samples it
after the awaited, side-effect-free restoration step; external implementations
cannot select the pack-validation or governance-consumption time.

## Config Keys That Define The Contract

The active governance contract is anchored by these repo-owned settings:

- `policy.human_gate_severity`
- `policy.lease_ttl_ms`
- `runtime.governance_degraded_tick_threshold`
- `runtime.partition_contingency_lease_ttl_ms`
- `runtime.partition_contingency_blast_radius_cap`
- `identity.agent_key_dir`
- `identity.registry_dir`
- `tls.*` and `platform_api.keys[*]` for the authenticated serve surfaces that
  expose governance state
- `operator_surface.*` for the bounded local operator and maintenance surface
  that inspects, but does not replace, governance evidence

Use `docs/CONFIGURATION.md` for field-level examples and endpoint notes.

## Explicit Boundaries

The active governance contract explicitly does not include:

- automatic governance over every swarm action
- internet-exposed or multi-tenant operator governance
- independent external consensus clusters beyond the bounded shipped runtime
- unrestricted partition-time destructive authority
- a second trust vocabulary separate from persisted identities, receipts, and
  approval artifacts

Use `docs/ARCHITECTURE.md` for the lane map and `docs/AGENTS.md` for current
Tom and Pouncer role boundaries.
