# ADR 0010: A Containment Release Is Signed By The Daemon, And Reached Over HTTP

## Status

Accepted on 2026-08-13. Phase 320, QRT-04.

Supersedes nothing. Extends ADR 0009 by adding one method to a trait in the
trusted computing base; the allow-listed dependency set that ADR 0009 states
is unchanged and `tools/check-workspace-layering.sh` needed no new exemption.

Amended 2026-08-14 by ADR 0011, which closes the missing THIRD check this ADR
names below. `verify_release_attestation` now also requires the signer to be a
configured governor, so the paragraph reading "`attestation_verified: true`
therefore means 'this attestation matches this body', NOT 'a governor we trust
authorized this'" is no longer true of the shipped code. It is left in place
unedited because it is the record of what shipped in phase 320.

Amended again on 2026-08-15 by ADR 0011's capability-boundary amendment. The
public governance backend trait and marker described below were forgeable and
are removed. The same release-signing and trust-set methods are now inherent on
the concrete opaque `swarm_governance::GovernanceAuthority` handle, minted only
from an authenticated persisted `GovernancePolicy`.

## Context

QRT-04 asks for three things at once:

1. an operator can end a containment before its lease expires,
2. the early release goes "through the same governance signing path" as the
   rest of the audit chain, and
3. an integration test contains, verifies the effect, releases both manually
   and by TTL, and verifies both receipts, with a tampered receipt refused.

The requirement writes (1) as `swarmctl quarantine release <lease_id>`. The
phase-320 blocker note in `.planning/REQUIREMENTS.md` already recorded why a
local subcommand cannot have it, and this ADR records the two further facts
measured while implementing the alternative.

### Fact 1: a second process cannot release a lease, whatever it does with the audit chain

`swarmctl quarantine release` as a local harness would open
`data/governance-partition-state.json` alongside a running
`swarm_detect --serve`. `GovernancePersistence::save`
(`crates/swarm-agents/src/tom_agent.rs`) is tmp-write plus rename with no lock
and the daemon holds `previous_commit_hash` and `receipt_counter` in memory, so
the two writers would each advance a hash chain the other cannot see. That is
the recorded blocker.

Routing through `LocalOperatorSurface` — the authenticated operator surface
served by `swarmctl serve` — does not fix it, and the reason is one layer
below governance. `LocalOperatorSurface::from_config` builds its own
`DefaultControlPlane`, which builds its own `ConfiguredRuntimeStack`, which
calls `containment_binding_from_config`. With
`runtime.containment.lease_store_path` unset — which is the shipped default,
and `rulesets/default.yaml` cannot set it because its sha256 is inside the
signed attestation — that is a `MemoryContainmentLeaseStore`, and a second
instance is a different map. A release route on that surface would answer
"no open containment lease `x`" for every lease the daemon is actually
holding: a check reporting over a region it never inspected, which is the
exact defect shape `.planning/STATE.md` catalogues eleven times.

With a path configured it is worse rather than better: `FileContainmentLeaseStore`
guards its read-modify-write with a `std::sync::Mutex`, which is per process.
Two processes closing leases against the same document lose each other's
closed receipts silently.

So the writer has to be the process that opens the leases, sweeps them, and
holds the governance authority. That is `swarm_detect --serve`.

### Fact 2: signing the release needs the governance keyring, which only the governance agent has

The signing path is the governor keyring plus the `previous_commit_hash` chain,
both inside `GovernancePolicy`'s `Mutex<GovernanceState>`. At the time this ADR
shipped, the policy lived in `swarm-agents`, which depended on `swarm-runtime`,
so `swarm_runtime::containment` could not name it. The only interface runtime
had was the then-current policy trait, and it did not carry a signing request.
The policy and concrete handle now live below runtime in `swarm-governance`.

## Decision

**The release endpoint lives in `swarm-runtime-http` and is mounted on the
daemon's listener.** `crates/swarm-runtime-http/src/http/containment.rs`
defines two authenticated routes:

```
GET  /v1/operator/containment/leases
POST /v1/operator/containment/leases/{lease_id}/release
```

They use the operator surface's own `OperatorAuthState`, `require_bearer_auth`
and `require_supported_operator_api_schema_version`, and the release requires
`OperatorScope::Maintenance`. `swarm_detect` — which is a binary of the same
crate — merges the router into `detect_http_router`'s output, handing it the
`Arc<ContainmentSweep>` it already spawned the TTL task with. They are NOT
merged into `LocalOperatorSurface::router()`, for the reason in Fact 1.

**One `ContainmentSweep` per process serves both triggers.** `ContainmentSweep`
now carries the governance authority as a field rather than taking it per call,
so `ContainmentSweep::release` (manual) and `ContainmentSweep::sweep`
(automatic) read the same store, executor, execution mode and authority.
Both call `swarm_runtime::containment::release_lease`, which is the single
shared function; manual and automatic differ in exactly one argument, the
`RollbackTrigger`.

**`swarmctl quarantine list` / `release` are HTTP clients**, resolving the
daemon base URL from `operator_surface.runtime_base_url` (or `--daemon-url`)
and the bearer token from the env of a configured principal that grants
`maintenance`. They are the first `swarmctl` subcommands that talk to a running
daemon rather than to repo-owned artifacts on disk.

**The then-current `GovernanceAuthority` trait gained one method**,
`attest_release`; the method is now inherent on the concrete handle:

```rust
fn attest_release(&self, subject: &serde_json::Value, now_ms: i64)
    -> Option<serde_json::Value>;
```

`GovernancePolicy::attest_release` holds the same mutex, reads the same
`governors` keyring, calls the same `simulate_governance_commit`, advances the
same `previous_commit_hash` and `receipt_counter`, issues through the same
`ConsensusGovernanceReceipt::issue`, and persists through the same
`persist_locked` as `issue_governance_receipt` and `issue_contingency_lease`.
That is what makes "the same governance signing path" a fact rather than a
phrase: the test asserts that a TTL release's attestation names the manual
release's commit as its `previous_commit_hash`, which no second signer and no
second chain could produce.

**The attestation binds to the receipt, not merely to a commit.**
`RollbackReceipt` gains an opaque `governance_attestation: Option<Value>`, and
`swarm_runtime::containment::verify_release_attestation` performs two
independent checks:

- `ConsensusGovernanceReceipt::verify` — re-canonicalizes the governance
  payload and checks the detached ed25519 signature;
- the attestation's `proposal_id` must equal
  `sha256(canonical(receipt-with-attestation-cleared))`.

There is a THIRD check that is absent, and this ADR names it rather than leaving
it to be inferred from the two that are present. `ConsensusGovernanceReceipt::verify`
checks the signature against `signature.public_key_hex` carried inside the
receipt itself, so there is no trust anchor: nothing compares the signer to the
configured governor set and nothing checks chain linkage. An attacker able to
rewrite a stored receipt can also mint a keypair, recompute `proposal_id` over
the rewritten subject, sign, and pass verification.

What the two implemented checks buy is that a PARTIAL rewrite fails — body
edited with the attestation left alone, or a valid attestation lifted from a
different release. That is the realistic at-rest tampering case and it is what
the tests exercise. A full re-attestation is not caught. `attestation_verified:
true` therefore means "this attestation matches this body", NOT "a governor we
trust authorized this".

This is pre-existing `verify()` semantics shared with the dispatcher's
`missing_governance_receipt_reason`, not a regression introduced here. Closing
it required the governor public keys to be reachable from the runtime, and
`GovernanceStatusReport` did not carry them. ADR 0011 added that surface and its
2026-08-15 amendment moved it onto the concrete handle.

Neither implies the other. Measured: with the second check disabled, a receipt
whose `steps[0].status` had been rewritten from `Reversed` to `Failed`
verified against a genuine, unmodified signature.

## Why the original trait widening was accepted, and what replaced it

The original trait's doc comment set the bar: widening beyond what a named
consumer already called re-imported the coupling the trait existed to remove.
The historical widening was narrowed on three axes:

- **No new TCB dependency.** The method takes and returns
  `serde_json::Value`, not `swarm_consensus::ConsensusGovernanceReceipt`.
  `swarm-policy` is trusted computing base and ADR 0009 allow-lists its
  declared workspace dependencies down to `{swarm-core}`; naming a consensus
  type would have added an edge for a type this crate never inspects.
  `GovernanceRuntimeEventRecord::details` already carries governance receipts
  across this boundary as a `Value`, and `swarm_runtime::dispatcher` already
  deserializes one back out of a `Value`, so the shape is precedent rather than
  invention.
- **No authorization verdict.** `authorize_partition_request` returning
  `Ok(true)` is what lets a destructive action proceed during a partition. The
  worst `attest_release` can do is decline to attest. It cannot cause a
  containment and it cannot prevent one being undone.
- **Current replacement.** The public trait and marker did not form a cross-crate
  seal and are gone. `ContainmentSweep` accepts only the concrete opaque handle;
  external compile-fail fixtures pin implementation, construction, installation,
  and removal of the original policy-trait path.

## Consequences

- Manual early release is available on a running daemon and nowhere else. An
  operator with a stopped daemon cannot release a lease; the lease's own TTL is
  the backstop, which is the property QRT-01..03 shipped.
- `LocalOperatorSurface` gained no containment routes. If a future phase wants
  them there, it needs a lease store that two processes can safely share — a
  real durability boundary, not a JSON file — and this ADR should be revisited
  then rather than the routes quietly added.
- An unattested release is recorded as unattested and refused by the verifier.
  Releasing still proceeds without a governor: refusing to undo a containment
  because the audit trail was unavailable would leave a host contained for a
  bookkeeping reason, which inverts the safety argument. The receipt says
  plainly which it was.
- A release whose inverse failed is neither attested nor closed. It keeps the
  lease open for the next sweep, and the HTTP response reports
  `lease_closed: false` so a 200 cannot read as "released". `swarmctl
  quarantine release` exits non-zero in that case.
