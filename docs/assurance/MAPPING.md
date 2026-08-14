# Invariant map: what fails closed, where, and what proves it

Phase 285. Requirements MAPPING-01..05 and FALSIFY-01..04.

`CLAUDE.md` says "live response must fail closed on malformed or weak requests".
Until this phase that was a sentence. This file is the table it turns into: one
row per fail-closed invariant, each naming the exact function that enforces it,
the assumption it rests on, and — through
[`negative-registry.toml`](negative-registry.toml) — a test that proves the
guard actually fires.

## How to read a row, and what a row is worth

A row is worth exactly the negative test behind it. `.planning/STATE.md`
catalogues twelve shipped defects of one shape: a check reporting success over a
region it never inspected. A table of invariants is a perfect vehicle for a
thirteenth, so every row here carries a `crates/*/tests/negative_*.rs` test that:

1. drives the **real** function and asserts it refuses;
2. drives an **unmutated mirror** of that function and asserts it reproduces the
   real outcome — the anti-vacuity control, without which a difference under
   mutation could be a sloppy rewrite rather than the guard;
3. drives the **mirror with exactly one guard removed** and asserts it
   **permits** what the real function refused.

Step 3 is FALSIFY-02. Step 2 is the part that is easy to leave out and is what
makes step 3 mean anything.

Every mutation in this table was run, observed failing, and its output recorded
in the phase-285 commit message. A row whose negative test cannot fail is worse
than no row.

## The source marker convention (MAPPING-03)

Every function named below carries a `// INVARIANT: <NAME>` comment on the
enforcing statement itself — the `if`, the match arm, the `else` — not on the
function. `tools/check-mapping.sh` requires the marker to be in the same file the
row's path resolves to, and fails on a marker with no row (grep for
`// INVARIANT:` to enumerate them).

## Enforcement

| Gate | What it fails on |
| --- | --- |
| `tools/check-mapping.sh` | a `// INVARIANT:` marker with no row; a row naming a Rust path that does not exist; a row naming an undeclared assumption; `assumptions.toml` disagreeing with the table in either direction; fewer than 12 rows; fewer than 4 crates covered; fewer than 8 assumptions |
| `tools/check-negative-registry.sh` | a row with no registry entry; a registry entry for no row; a registry entry naming a test file or test function that does not exist; a registry entry whose `production_fn` disagrees with the table |

Both run in the `panic-contract` job of `.github/workflows/ci.yml` and both run a
fixture on every invocation that proves they catch each of those cases. The
scripts live in `tools/`, not `scripts/`; MAPPING-04/05 and FALSIFY-03/04 say
`scripts/check-*.sh`, and that wording is stale — every gate in this repository
is `tools/check-*.sh` and `tools/check-gates-wired.sh` enumerates that directory.
Phase 283 hit the same stale path and recorded the same deviation.

## The table

21 rows across four crates: 5 in `swarm-policy`, 4 in `swarm-response`, 6 in
`swarm-runtime`, 6 in `swarm-spine`.

| Invariant | Enforcing function | Assumption | What it refuses |
| --- | --- | --- | --- |
| `POLICY-EMPTY-RULESET-DENIES` | `swarm_policy::configurable_gate::ConfigurableApprovalGate::evaluate` | `ASSUME-CONFIG-INTEGRITY` | With no configurable rules loaded — the shipped default — every request is denied by `configurable.fail_closed.empty_ruleset` rather than falling through to the permissive static default. |
| `POLICY-NULL-EVIDENCE-REFUSED` | `swarm_policy::static_gate::StaticApprovalGate::validate_request` | `ASSUME-DETERMINISTIC-GATE` | A request whose evidence bundle is JSON `null` is refused as malformed before any verdict is rendered. |
| `POLICY-DESTRUCTIVE-MIN-SEVERITY` | `swarm_policy::static_gate::StaticApprovalGate::evaluate` | `ASSUME-DETERMINISTIC-GATE` | A destructive action at `Severity::Low` is denied by `static.minimum_severity`, whatever else about the request is well formed. |
| `POLICY-DESTRUCTIVE-HUMAN-GATE` | `swarm_policy::static_gate::StaticApprovalGate::evaluate` | `ASSUME-DETERMINISTIC-GATE` | A destructive action at or above `human_gate_severity` returns `RequireHuman`, never `Allow` — which in `LiveResponse` mode is a refusal at the runtime. |
| `POLICY-SCOPE-RATE-LIMIT` | `swarm_policy::static_gate::StaticApprovalGate::scope_rate_limit_decision` | `ASSUME-OS-CLOCK` | The `max_actions_per_scope_per_minute + 1`-th action against one scope inside one minute is denied by `static.scope_rate_limit`. |
| `RESPONSE-LEASE-BOUNDED` | `swarm_response::containment::ContainmentLease::open` | `ASSUME-OS-CLOCK` | A lease whose derived expiry is not strictly after its issue instant is refused, including the case where the saturating add is a no-op at `i64::MAX`. |
| `RESPONSE-STORED-LEASE-BOUNDED` | `swarm_response::containment::ContainmentLease::try_from` | `ASSUME-KEYSTORE-ATOMICITY` | A lease deserialized from the store is re-checked against the same bound, so an edited at-rest record cannot reintroduce an unbounded containment. |
| `RESPONSE-ENFORCED-SIMULATION-NOT-SUCCESS` | `swarm_response::rollback::RollbackReceipt::derive_status` | `ASSUME-NETWORK-TRANSPORT` | An all-`Simulated` rollback in `Enforced` mode is `Failed`, not `Simulated` — `indicates_success()` is false, because the host is still contained. |
| `RESPONSE-SANDBOX-NEVER-REVERSES` | `swarm_response::rollback::SandboxRollbackExecutor::rollback` | `ASSUME-NETWORK-TRANSPORT` | An executor that holds no transport never emits `Reversed`, in any mode, so no receipt claims a restoration performed by code that cannot reach a host. |
| `RUNTIME-DENY-BLOCKS-EXECUTION` | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `ASSUME-DETERMINISTIC-GATE` | A `Deny` verdict returns before `ResponseExecutor::execute`, so the response adapter is never reached. |
| `RUNTIME-HUMAN-GATE-BLOCKS-LIVE` | `swarm_runtime::SwarmRuntime::authorize_and_execute` | `ASSUME-DETERMINISTIC-GATE` | In `LiveResponse` mode a `RequireHuman` verdict is a refusal, so an action awaiting human confirmation is not executed. |
| `RUNTIME-EXPIRED-LEASE-REFUSED` | `swarm_runtime::ensure_active_lease` | `ASSUME-OS-CLOCK` | A capability lease whose expiry is at or before `now_ms` refuses the request between lease issue and execution. |
| `RUNTIME-CONTAINMENT-NEEDS-STORE` | `swarm_runtime::SwarmRuntime::prepare_containment` | `ASSUME-KEYSTORE-ATOMICITY` | An enforced containment on a runtime with no lease store is refused BEFORE execution, because a containment that cannot be bounded cannot be undone. |
| `RUNTIME-RELEASE-SUBJECT-BOUND` | `swarm_runtime::containment::verify_release_attestation` | `ASSUME-CANONICAL-JSON` | An attestation whose `proposal_id` is not the digest of this receipt-minus-attestation is refused, so a rewritten body cannot ride a genuine signature. |
| `RUNTIME-FAILED-ROLLBACK-KEEPS-LEASE` | `swarm_runtime::containment::release_lease` | `ASSUME-NETWORK-TRANSPORT` | A rollback receipt carrying a `Failed` step keeps the lease OPEN, so a transport blip at sweep time cannot end the lease and abandon a still-contained host. |
| `SPINE-ENVELOPE-HASH-BOUND` | `swarm_spine::envelope::verify_envelope` | `ASSUME-SHA256` | An envelope whose claimed `envelope_hash` is not the digest of its own body is refused, even though the signature — taken over the body MINUS hash and signature — still verifies. |
| `SPINE-ENVELOPE-SIGNATURE-REQUIRED` | `swarm_spine::envelope::verify_envelope` | `ASSUME-ED25519` | An envelope re-attributed to another issuer, with its hash recomputed so the hash binding is satisfied, fails the signature check. |
| `SPINE-CHAIN-PREV-HASH-BOUND` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | A correctly signed envelope that continues some other history is not a valid continuation of the head we hold. |
| `SPINE-CHAIN-SEQ-MONOTONIC` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | An envelope whose `seq` is not exactly `head.seq + 1` is refused, which is what stops a byte-identical replay of an already-accepted record. |
| `SPINE-CHAIN-ISSUER-BOUND` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | Another keyholder's correctly signed envelope, crafted to name our head, cannot extend our issuer's chain. |
| `SPINE-CHAIN-FIRST-LINK-SHAPE` | `swarm_spine::chain::verify_chain_link` | `ASSUME-CHAIN-HEAD-DURABILITY` | An issuer met for the first time must start at `seq=1` with a null `prev_envelope_hash`, so a chain cannot silently join at height 99 with 98 unaudited records behind it. |

## Row notes

These are the places where the table is less simple than it looks. Read them
before trusting a row.

### Five rows name a function that is not public API

`validate_request` is `pub(crate)`; `scope_rate_limit_decision`, `derive_status`,
`prepare_containment` and `ensure_active_lease` are private. The row names
the function that ENFORCES; `negative-registry.toml`'s `entry_point` field names
the public function the test drives to reach it. Naming the public entry point in
the table instead would be less precise and would hide which of several guards
inside one function a row is about.

### Two rows name the same function

`RUNTIME-DENY-BLOCKS-EXECUTION` and `RUNTIME-HUMAN-GATE-BLOCKS-LIVE` are two
match arms of `authorize_and_execute`; `SPINE-ENVELOPE-HASH-BOUND` and
`SPINE-ENVELOPE-SIGNATURE-REQUIRED` are two checks inside `verify_envelope`;
four rows are four guards inside `verify_chain_link`. They are separate rows
because neither implies the other, and each negative test mutates only the guard
its row is about. The `verify_envelope` pair is the clearest case: the signature
is taken over the envelope with `envelope_hash` and `signature` REMOVED, so
rewriting the hash alone leaves the signature verifying, and rewriting the issuer
and recomputing the hash leaves the hash comparison satisfied. Each check is the
only thing standing in the way of one of those two attacks.

### The `swarm-spine` chain rows have no production call site

Measured, and it is the most important caveat on this page:

```
$ grep -rn 'verify_chain_link' crates/ | grep -v swarm-spine/src/chain.rs | grep -v tests/negative_
crates/swarm-spine/src/lib.rs:61:pub use chain::{ChainLinkVerdict, IssuerChainHead, chain_head_from_envelope, verify_chain_link};
```

Nothing in the critical lane calls it. The four rows are invariants of a public,
tested primitive of a trusted-computing-base crate that the runtime does not yet
use — mapped ahead of the caller on purpose, because the guard has to be right
before something depends on it.

There is a concrete gap behind that: `swarm_runtime::approval::build_vote_envelope_hash`
BUILDS an envelope chain — it passes `entries.last().envelope_hash` as
`prev_envelope_hash` — and no code path ever verifies those links. The approval
ledger's chain is constructed and never checked. See
`docs/decisions/0011-invariant-mapping-and-negative-registry.md`.

`verify_envelope`, by contrast, IS called in production, from the same function.

### `RUNTIME-RELEASE-SUBJECT-BOUND` is not a trust anchor

`verify_release_attestation` proves that the attestation covers THIS receipt
body. It does not prove that a governor you trust signed it:
`ConsensusGovernanceReceipt::verify` checks the signature against the public key
CARRIED INSIDE the receipt. An attacker who can rewrite a stored receipt can
also mint a keypair and re-attest. What the row buys is that a PARTIAL rewrite —
edit the body, leave the attestation — is refused, which is the realistic
at-rest tampering case. Tracked as open work (`.planning` task #27); do not read
`attestation_verified: true` as "a governor we trust authorized this".

### What the mirrors do not cover

The `swarm-runtime` mirror of `authorize_and_execute` reproduces the sequence
down to `execute` and omits the guard pipeline and the governance decoration.
Both are inert for these probes — the runtimes under test are built with no
guard pipeline and the probe requests carry no `governance_receipt` — and the
unmutated control asserts the mirror and the real function agree on both the
result AND the executor call count, which is what makes that claim checkable
rather than a promise in a comment.

## Evidence boundary

Every row here is proved by a single-process, in-memory test. Nothing in this
table is evidence about concurrency, crash recovery, or a real host. Phase 286
(deterministic simulation) and phase 287 (fuzz and loom) are where those come
from, and their rows will say which boundary they extend.
