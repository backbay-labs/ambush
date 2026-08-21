# ADR 0011: A Governance Receipt Is Checked Against The Governor Set, Not Against Itself

## Status

Accepted on 2026-08-14. Task #27.

Supersedes nothing. Closes the hole ADR 0010 named and left open under "There is
a THIRD check that is absent". It originally extended the policy trait by one
method; the 2026-08-15 amendment below removes that trait and places the method
on the concrete lower-level handle.

Authorization follow-up, also 2026-08-14: the action-routing parts of this ADR
are superseded by the request-bound, one-time admission contract in
[`docs/CONSENSUS.md`](../CONSENSUS.md#request-binding-and-one-time-admission).
The old `missing_governance_receipt_reason` and runtime-side receipt parser no
longer exist. The dispatcher now asks the governance authority to verify and durably
consume an exact `Approve` or `Veto`, then passes an opaque admission to the
runtime. Contingency receipts are likewise anchored and redeemed once. The
release-attestation trust-anchor decision in this ADR remains current.

Human-approval composition was hardened in the same follow-up. Ordinary policy
is preflighted once before governance consumption. `RequireHuman` persists an
exact-request hold and approval-set binding while leaving governance pending;
the dedicated resume route verifies the exact locally persisted approval pack,
atomically consumes governance, and moves one non-cloneable admission to one
router call without a second mutable policy evaluation. Once consumed, a later
routing or execution failure burns both approvals. Raw human-approved runtime
entry points do not bypass this route.

Capability-boundary amendment, 2026-08-15: the public backend trait and its public
`#[doc(hidden)]` marker were forgeable by downstream crates and are removed. The
current `swarm_governance::GovernanceAuthority` is a concrete opaque handle with a
private `Arc<GovernancePolicy>`. Only an authenticated persisted policy can mint it;
runtime, ingest, containment, human resume, and release verification accept that
exact handle rather than a trait object or generic implementation. Historical trait
widening language below describes the API that first shipped this decision, not the
current capability boundary.

## Context

`ConsensusGovernanceReceipt::verify` performed two checks, and both were closed
over the receipt:

- the detached ed25519 signature, verified against
  `signature.public_key_hex` — **a field of the receipt**;
- `payload.issued_by`, required to derive from that same key.

So the function answered "is this receipt internally consistent?" while three
call sites read it as "did a governor authorize this?":

| Call site | Read the answer as |
| --- | --- |
| `swarm_runtime::containment::verify_release_attestation` (QRT-04 release path) | `attestation_verified: true` on the operator API |
| `swarm_runtime::dispatcher::missing_governance_receipt_reason` | permission to route a destructive action |
| `swarm_runtime::SwarmRuntime::verified_governance_receipt` | which receipt id to stamp into the audit |

Anyone able to write where those receipts live — a stored rollback receipt, or
the `evidence` map of an action request — could mint a keypair, sign, and pass.
Both call sites in the first two rows are now anchored; the third is discussed
under Consequences.

### What was measured, before anything was changed

`crates/swarm-runtime-http/src/http/tests.rs`,
`qrt_04::a_fully_re_attested_receipt_is_refused`. A genuine containment release
was performed through the daemon's operator path, then its receipt was rewritten
(`steps[0].status` `Reversed` -> `Failed`, i.e. "the host was restored" rewritten
to "it was not", plus a replaced `summary`) and re-attested end to end by
`SigningKey::from_bytes(&[251; 32])`, a key no governor holds. Recomputing
`proposal_id` over the rewritten subject is eight lines and needs no secret:
every input is public.

Written first in the form that asserts the forgery is ACCEPTED, it passed:

```
test http::tests::qrt_04::a_fully_re_attested_receipt_is_refused ... ok
```

Flipped to assert refusal, it failed, printing the receipt that had just been
accepted — signed by `swarm:ed25519:ee692b43...`, chained onto
`previous_commit_hash: "forged-previous-commit-hash"`, a value no chain in this
repository has ever contained.

The subject check was re-measured against the anchored verifier rather than
assumed to still matter: short-circuiting check 3 with the anchor active,
`a_tampered_rollback_receipt_fails_verification` fails at its first case with
`called Result::unwrap_err() on an Ok value` — the `Reversed` -> `Failed`
rewrite verifying against the genuine governor's signature. All three checks
remain load bearing.

`crates/swarm-runtime/tests/dispatch_integration.rs`,
`destructive_request_response_is_refused_when_the_signer_is_not_a_governor`
measures the same defect on the dispatcher path, and it is worse there because
the request is not merely believed, it is executed. With the anchor check
reverted to the old `verify()`, a `BlockEgress` request carrying a receipt
signed by `SigningKey::from_bytes(&[201; 32])` produced
`(audits, executor calls, gate evaluations) = (1, 1, 1)` where the test requires
`(0, 0, 0)`.

### Why this is not a small edit

The check needs the governor public keys where the verification happens, and it
happens in `swarm-runtime`:

- `swarm-agents` depends on `swarm-runtime`, so the runtime cannot name
  `GovernancePolicy` — the same wall ADR 0010 hit;
- `GovernanceStatusReport` carries `total_governors` and `healthy_governors`,
  counts rather than identities, so the existing read-only surface cannot answer
  it;
- `swarm-policy` does not depend on `swarm-consensus` and must not start to (ADR
  0009), so the original trait could not carry a
  `ConsensusGovernanceReceipt` in either direction.

## Decision

**The governance authority surface gains one method**, originally the third
widening of the now-removed backend trait and currently an inherent method on the
opaque handle:

```rust
fn governor_public_keys(&self) -> BTreeSet<AgentId>;
```

`GovernancePolicy::governor_public_keys` returns exactly the membership
`GovernanceState::committee` builds a round over: the admitted peer governors
plus the local one. That is the set that can legitimately have signed a receipt
on this chain.

**Only public halves cross, and structurally so.** A governor's `AgentId` is
`swarm:ed25519:<public-key-hex>` — `AgentId::from_verifying_key` hex-encodes the
32 public key bytes, untruncated and unhashed. Peer governors were never held as
keys at all (`peer_governors: BTreeSet<AgentId>`), and the local governor's
private half stays inside `LocalGovernorKey`, which by construction exposes no
accessor returning a `SigningKey` (BFT-03,
`tools/check-single-governor-key.sh`). The values this method returns are
already published in plaintext inside every receipt the authority signs, as
`payload.issued_by` and `signature.public_key_hex`, so a caller learns nothing
it could not read off an artifact it already holds. Returning
`ed25519_dalek::VerifyingKey` instead would have added a dependency to a TCB
crate to say the same thing less precisely.

**The check lives on the receipt type**, beside the one it replaces, so nobody
has to know to look elsewhere:

```rust
pub fn verify_signed_by(&self, governor_public_keys: &BTreeSet<AgentId>)
    -> Result<VerifyingKey, ConsensusError>;
```

It recovers the verifying key FROM THE SIGNATURE — not from `payload.issued_by`,
which is attacker-written — derives its identity, and requires membership.
`verify` keeps its old behavior and its doc now states plainly that it is not
authentication.

**It fails closed on an empty anchor.** No governance authority installed, or an
authority naming no governor, is refused with `ConsensusError::NoTrustAnchor`
rather than falling back to the key the receipt carries. This is the posture
b4bf119 established for `GovernancePolicy::can_act` with an empty keyring: a
verifier with nothing to check against knows nothing, and the honest answer is
to say so. It has a real cost, stated under Consequences.

**Both authorization call sites take the anchor from the object that signs.**
The release path passes `ContainmentSweep::governance()` — the one authority the
sweep attests with — so anchor and signer come from the same object rather than
from two configurations that could drift. The dispatcher passes its own concrete
governance authority handle.

## Why this authority surface is acceptable here

The original trait widening was deliberately narrow. The 2026-08-15 amendment
preserves that surface on the concrete handle while removing substitutable
implementations:

- **The dependency is explicit.** The concrete policy and handle now live together
  in `swarm-governance`; runtime consumers depend on that lower-level crate rather
  than on an agent-role crate or forgeable policy trait.
- **No verdict, and no argument.** `authorize_partition_request` returning
  `Ok(true)` lets a destructive action proceed. This method reports a set and
  takes nothing; every decision made from it is made by the caller, in the open.
- **It reports only the wrapped policy's trust set.** Downstream code cannot
  substitute a backend that returns attacker-selected keys.
- **The current handle is not substitutable.** Only an authenticated persisted
  `GovernancePolicy` can mint it. A source inventory gate rejects trait or generic
  installer reintroduction, and compile-fail fixtures reject implementation,
  construction, and fake-handle installation.

## Consequences

- **A dispatcher with no governance authority now refuses every action in
  `ResponseAction::requires_governance_receipt()`.** That is a real behavior
  change and it broke two integration tests, which were not adjusted to pass:
  they were fixtures minting an unrelated keypair and relying on a self-signed
  receipt being believed. They now install a governance policy that registers
  the key their receipts are signed with — which is what a deployment must also
  do. The follow-up additionally requires pending-ledger membership, exact
  request binding, the route-specific decision, freshness, and durable
  one-time consumption.
- **`attestation_verified: true` on the containment release route now means
  what it says**: a governor this process recognizes signed this exact body.
  ADR 0010's warning against reading it as "a governor we trust authorized
  this" no longer applies to that field.
- **Chain linkage is still unchecked**, and this ADR does not close it.
  Nothing follows `previous_commit_hash` back to a known head, so a receipt
  re-attested by a GOVERNOR'S OWN key over a rewritten body is still accepted —
  an insider holding the signing key, not an attacker holding write access to
  the store. Closing it needs a durable, verifiable chain head, which this
  repository does not have. The `previous_commit_hash` equality the QRT-04 test
  asserts is a property of one process's in-memory chain, not an anchor.
- **`SwarmRuntime` no longer parses or verifies bearer governance receipts.**
  Governed execution in enforced mode requires the dispatcher's opaque typed
  admission; raw runtime entry points refuse before policy or execution. Audit
  decoration reuses the receipt already verified by the dispatcher.
- **`ContingencyLease::verify` is now anchored to the configured governor set**
  and checks its locally derivable proposal and commit consistency. Redemption
  is persisted before routing and is one-time for the exact request and scope.
