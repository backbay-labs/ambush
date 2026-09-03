# ADR 0016: Two Identity Chains, Named On Every Surface, Never Conflated

## Status

Proposed on 2026-08-30. **Revision 2** — Fact 4 gains a fourth absent check and C6a is new;
the rollback badge now renders the attestation's own `decision`. Perch, Phase 0 (bridge identities) and Phase 1 (every badge).

Depends on ADR 0012 (the relay is transport, the daemon is the record) and ADR 0015 (the
bridge holds the Nostr keys). Constrains every verification badge Perch renders.

Path prefix convention as in ADR 0011: `BUZZ ` is `block/buzz` at `eed74bde2`.

## Context

Ambush signs with Ed25519. Nostr requires secp256k1 BIP-340 Schnorr. They are different
curves, different key material, and different claims — and every card Perch renders travels
inside one and carries facts from the other.

### Fact 1: the two chains, measured

- **Ambush is Ed25519 throughout.** `crates/swarm-crypto/Cargo.toml:9` declares
  `ed25519-dalek`; `Ed25519Signer::from_secret_material` (`swarm-crypto/src/lib.rs:67`) and
  `verify_detached_signature` (`:130`) are the whole signing surface. `rg secp256k1` over
  `crates/` returns **nothing**. An identity is `swarm:ed25519:<64 hex>` —
  `AgentId::from_public_key_hex` (`crates/swarm-core/src/types.rs:15-17`) constructs exactly
  that string, and `from_verifying_key` (`:19-21`) hexes the Ed25519 public key into it.
- **Nostr is secp256k1.** The relay's `AUTH` challenge is a signed `kind:22242`; every event
  id is a Schnorr signature over a canonical serialization.

Nothing converts one into the other. A signature on one curve says nothing about the other.

### Fact 2: NIP-OA binds a Nostr key to a Nostr owner — not to a swarm identity

`BUZZ crates/buzz-sdk/src/nip_oa.rs:1-18` documents the tag as
`["auth", "<owner-pubkey-hex>", "<conditions>", "<sig-hex>"]` over the preimage
`"nostr:agent-auth:" || agent_pubkey_hex || ":" || conditions`, hashed with SHA-256 and
signed BIP-340 Schnorr by the **owner's secret key**. It is verified with
`nostr::secp256k1::schnorr::Signature` against a `nostr::PublicKey`.

So NIP-OA proves: *this Nostr agent key was authorized by that Nostr owner key.* It buys
two real things in the relay — the ban cascade
(`BUZZ crates/buzz-relay/src/handlers/auth.rs:100-130`: a ban on the cryptographically
proven owner cascades to the agent, extracted from the self-proving tag with no database
round-trip) and a rate tier (`BUZZ crates/buzz-relay/src/connection.rs:690-695` selects
`agent_standard_messages_per_min` = 120 when `ctx.agent_owner_pubkey.is_some()`, else
`human_messages_per_min` = 60).

It does **not** prove that a Nostr key corresponds to `swarm:ed25519:<hex>`.
`00-BRIEF.md` §4.7 says each agent's Nostr keypair is "bound to its `swarm:ed25519:<hex>`
identity by a NIP-OA owner attestation". That is not what the mechanism does, and the
difference is load-bearing: the actual `swarm_agent_id → nostr_pubkey` mapping is
established by the bridge's own deterministic key derivation from a configured secret root
(`11-BRIDGE-CRATE.md` §7.2, PROPOSED) and honoured by the console's admitted-identity list.
That mapping is an **unsigned trust root**, and this ADR says so rather than inheriting a
sentence that implies otherwise.

### Fact 3: four of the seven card types carry no Ed25519 signature at all

Verified by reading the structs:
`DetectionFinding` (`crates/swarm-whisker/src/detector.rs:51-59`, 7 fields),
`SwarmFindingEnvelope` (`crates/swarm-response/src/siem.rs:18-27`, 8 fields),
`ResponseReceipt` (`crates/swarm-response/src/lib.rs:100-116`),
`AuditTrail` (`crates/swarm-spine/src/lib.rs:114-122`, 7 fields) — none has a signature
field. The proposed `HeldAction` record will not either.

And the chain machinery the plan set cites is nearly dead code:
`build_signed_envelope` (`crates/swarm-spine/src/envelope.rs:71`) has exactly **one**
non-test caller, `crates/swarm-runtime/src/approval.rs:1810`, which derives its keypair as
`Keypair::from_seed(sha256("approval-ledger-envelope:{ledger_id}"))` (`:1807-1809`) — a seed
anyone who knows the ledger id can reproduce — signs, verifies its own signature, then
**discards the signature and keeps only `envelope_hash`** (`:1836-1840`). `verify_chain_link`
has **zero** consumers outside its own module. The workspace's single production envelope
signature is a chaining checksum, not provenance.

### Fact 4: there is exactly one real signature check the console can surface today

`verify_release_attestation` (`crates/swarm-runtime/src/containment.rs:235-269`), called
from `crates/swarm-runtime-http/src/http/containment.rs:219-222`, runs over
`RollbackReceipt.governance_attestation` and performs two independent checks: the detached
Ed25519 signature on the `ConsensusGovernanceReceipt`, and the binding of the attestation's
`proposal_id` to `sha256(canonical(receipt-with-attestation-cleared))`.

ADR 0010 names the third check that is **absent**: nothing compares the signer to the
configured governor set, so a full re-attestation by an attacker-minted keypair passes. Its
words are `attestation_verified: true` means "this attestation matches this body", **not**
"a governor we trust authorized this". `swarmctl` already renders that honestly as
`VERIFIED` / `NOT VERIFIED: {reason}` (`crates/swarm-cli/src/core.inc:3169-3173`).

**A fourth absent check, measured in revision 2 and not previously written down anywhere in
the plan set: the verifier never reads the receipt's own verdict.**
`ConsensusGovernanceReceipt::verify` (`crates/swarm-consensus/src/lib.rs:425-448`) does
exactly three things — re-canonicalizes `self.payload`, checks the detached Ed25519 signature
against `self.signature.public_key_hex`, and asserts that `payload.issued_by` derives from that
same key (`:441-447`). It does **not** look at `payload.decision`, whose type is
`GovernanceReceiptDecision { Approve, Veto }` (`:353-358`). Neither does
`verify_release_attestation`, whose only additional check is the `proposal_id` subject binding.

So a `ConsensusGovernanceReceipt` carrying `decision: Veto`, self-signed by any keypair, whose
`proposal_id` equals `release_subject_id(receipt)`, yields `attestation_verified: true`. This
is not a bug in the daemon — the field is a governance artifact whose consumer is expected to
read it — but it is a hard limit on what the badge may claim. **The console must render the
`decision` value beside the badge**, or a `Veto` receipt renders identically to an `Approve`
one on the one card in the product that has a real signature.

## Decision

**Perch tracks two identity chains, labels which one every claim is about, and never lets a
signature on one stand in for the other.**

**C1. Every verification result names the chain and the tier.** A badge reads
`Ed25519 · tier 1` or `secp256k1 · tier 0`, never a bare word. A verification badge with no
chain label or no tier label fails the test (`08` INV-25). Tier `0` renders as
`UNATTESTED`, and as `UNATTESTED — BY DESIGN` when `PartitionState` at execution was
`Partitioned` or `Healing` (`08` INV-08) — that state is exactly four values,
`Healthy | Degraded | Partitioned | Healing`
(`crates/swarm-policy/src/governance.rs:49-54`).

**C2. Verification runs against the Ed25519 chain, locally, and never against the Nostr
envelope the fact travelled in.** The envelope's `sig` proves *the bridge published this
body* — a transport claim. If a surface ever verified the envelope and rendered the result
as verification of the fact, "trust the bridge" would silently have replaced "trust the
receipt". The envelope's signature is visible to any reader who looks at the raw event and
needs no help from a badge.

**C3. Four words are banned outright beside an attestation**, per
`APPENDIX-NORMATIVE.md` §7: `verified by`, `trusted`, `proof`, and any shield or lock glyph.
`signed` and `verified` may not appear on a finding, escalation, hold, containment-lease or
bare response-receipt card at all, because those four types carry no signature (Fact 3).
The shield ban is not free: `block/buzz` renders a lucide `Shield`/`ShieldAlert` in nine
surviving files, two of them on Perch's explicit reuse path —
`BUZZ desktop/src/features/settings/ui/ModerationQueueCard.tsx:317` and
`BUZZ desktop/src/features/channels/ui/MembersSidebarMemberCard.tsx:409`.

**C4. The bridge must never put a `signature`, `signed_by` or `verified` field in a card
body it constructs.** Not "should not". The bridge holds a secp256k1 key and no Ed25519
key; anything signature-shaped it emits would be a transport claim wearing a provenance
word. Where an Ambush artifact genuinely carries an attestation — `RollbackReceipt` — the
attestation rides verbatim as the daemon produced it and the console verifies it by calling
the daemon, not by re-implementing the check.

**C5. Keys render in full on every security-decision surface, with the chain labelled.**
`BUZZ desktop/src/shared/ui/PubKey.tsx:21-31` already states the doctrine and the reason in
its own prop documentation: `full` is "required on security-decision surfaces … a truncated
key is forgeable by vanity grinding, so decisions must be made against the whole key."
Perch extends the component to two chains — a `npub`/64-hex secp256k1 key and a
`swarm:ed25519:<64 hex>` identity — and labels which is shown. The doctrine is unchanged;
only the arity is.

**C6a. The rollback receipt's badge renders three things, never one.** Tier and chain
(`Ed25519 · tier 1`), the **limit** (`attestation matches this body` — never `verified by`,
`trusted` or `proof`, and never a shield or lock glyph), and the attestation's own
`payload.decision`. Fact 4's fourth absent check makes the third mandatory: a badge that omits
`decision` reports `Veto` and `Approve` identically. The two checks that *did* run are named;
the two that did not — trust anchor, and the decision itself — are the reason the other two
words on the badge exist.

**C6. Where a fact's provenance is a config mapping rather than a signature, the surface
says so.** The `swarm_agent_id → nostr_pubkey` mapping (Fact 2) is exactly this case. The
colony roster names an agent by its Ed25519 identity; the card that carried its finding was
signed by a secp256k1 key admitted by configuration. Rendering the first as if the second
proved it is the conflation this ADR exists to prevent.

## Alternatives Considered

**Give each Ambush agent a real secp256k1 key and a NIP-OA attestation chained to a swarm
identity.** Attractive, and it is what `00-BRIEF.md` §4.7 reads as if it says. Rejected as
unavailable rather than undesirable: NIP-OA's preimage takes a Nostr agent pubkey and a
Nostr owner pubkey and nothing else (Fact 2), so binding an Ed25519 identity into it would
require a NIP change in `block/buzz`. What is achievable today — and what C6 requires the
UI to say — is that the mapping is configured, not proven. Revisit if a NIP-OA `conditions`
extension carrying a foreign-chain identity becomes upstreamable.

**Render one badge that means "this is genuine", computed over whichever signature is
available.** Rejected. It is the single most dangerous simplification available here: it
would render tier 0 and tier 1 identically for six of the seven card types, and the one
type that is genuinely tier 1 would then look like the six that are not.

**Verify the Nostr envelope and call it verification.** Rejected on C2. It is technically a
real signature check, which is what makes it tempting and what makes it worse than no badge.

## Consequences

### Positive

- The badge taxonomy degrades honestly: before B6 every finding, escalation, hold and
  containment-lease card is tier 0 and says so, which is a *rendered honest state* rather
  than an absence.
- The one genuine attestation the system has — the rollback receipt's — gets rendered with
  the limit ADR 0010 already wrote down **plus the decision the verifier does not read**,
  instead of being oversold twice over.
- A ban on an operator's Nostr key cascades to every agent key the bridge derives, through
  a mechanism the relay already implements and this project does not have to build.

### Negative

- Two chains means two mental models on screen. C1's label is the mitigation and it costs
  horizontal space on every card.
- **B6 is not "one call per fact".** `09` §3.1 sizes it that way; Fact 3 shows the existing
  call proves the API compiles, not that a signing identity exists on any publish path. B6
  additionally needs a configured daemon key (the
  `Ed25519Signer::from_secret_material(env)` pattern at
  `crates/swarm-runtime/src/providence.rs:129`, `:169`) and a per-issuer `seq` plus
  `prev_envelope_hash` store. Proposed brief amendment **AD-A5** below.
- The `swarm_agent_id → nostr_pubkey` mapping is an unsigned trust root that the whole
  card-attribution path depends on. C6 makes it visible; it does not make it signed.
  Closing it is a follow-on, not a v1 deliverable.

## Verification

- `08` INV-25 (chain **and** tier on every verification result) and INV-08 (`UNATTESTED`
  and its by-design variant) are the executable form of C1.
- **PROPOSED** a CI grep for `verified`, `signed`, `trusted` and `proof` in the Perch
  feature tree that fails unless the occurrence is within a component that also renders a
  chain label and a tier — the `tools/check-copy-banned-terms.sh` that does not yet exist
  (ADR 0015 follow-on).
- **PROPOSED** extend `BUZZ desktop/scripts/check-pubkey-truncation.mjs` to
  `swarm:ed25519:` identities, so C5 is mechanical on both chains rather than on one.
- **PROPOSED** a bridge unit test asserting no constructed card body contains a key named
  `signature`, `signed_by` or `verified` (C4).

## Follow-On Work

- Proposed brief amendment **AD-A5**: `APPENDIX-NORMATIVE.md` §5's B6 row and `09` §3.1's
  "B6 is one call per fact" should read "one call per fact **plus** a configured signing
  identity and a per-issuer `seq` / `prev_envelope_hash` store". The existing caller's
  publicly derivable seed (Fact 3) is the evidence.
- Proposed brief amendment **AD-A6**: `00-BRIEF.md` §4.7's "bound to its
  `swarm:ed25519:<hex>` identity by a NIP-OA owner attestation" overstates what NIP-OA
  proves (Fact 2). The sentence should say the attestation binds an agent Nostr key to an
  **owner Nostr key**, buying the ban cascade and the rate tier, and that the mapping to the
  swarm identity is configured and unsigned.
- Decide whether the operator's leg-1 signing key (ADR 0014) is the same secp256k1 key the
  relay knows them by, or a distinct one. It is currently assumed to be the same; nothing
  has verified that assumption.
