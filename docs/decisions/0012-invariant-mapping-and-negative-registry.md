# ADR 0012: Fail-Closed Is A Table With Mutation Tests Behind It, Not A Sentence

## Status

Accepted on 2026-08-14 for the repository-local Phase 285 implementation.
MAPPING-05 and FALSIFY-04 remain open until a provenance-distinct external
required check protects the local gate result. The current organization is on
GitHub Free, where an organization-owned pinned required workflow is
unavailable. A dedicated external GitHub App check with its own integration ID
is the viable Free-plan anchor; the existing Actions App plus `panic-contract`
check name is not provenance and can be spoofed by another workflow.

Supersedes nothing. Names invariants of the trusted computing base ADR 0009
draws; adds no dependency edge to any TCB crate, so
`tools/check-workspace-layering.sh` needed no new `TCB_ALLOWED_WORKSPACE_DEPS`
entry. The five new test targets live in `crates/*/tests/` and use only
dependencies those crates already declare.

## Context

`CLAUDE.md` says "live response must fail closed on malformed or weak
requests". Until this phase, checking that claim meant reading the code.
Several fixes this session — b4bf119, cc5b169, 99733a0, ce1ddd1 — each found a
place where it was false, and each was found by a human reading a diff.

The failure mode this repository actually has is narrower and worse than "a
guard is missing". `.planning/STATE.md` catalogues twelve shipped defects of one
shape: **a check reporting success over a region it never inspected**. A layering
gate whose deny-list was derived from the edges it policed. A solver status
unreachable because its classifier matched a string the real solver never emits.
A rollback test driven by an `Err`-returning fake, when production returns `Ok`
with a `Failed` step.

An invariant table is a perfect vehicle for a thirteenth. A markdown row saying
"`SwarmRuntime::authorize_and_execute` refuses a Deny verdict" keeps reading
correctly after the function is renamed, after the arm is deleted, and after the
test that covered it was quietly weakened. So the decision this ADR records is
not "write the table" — it is **what has to sit behind a row before the row is
allowed to exist**.

## Decision

### 1. A row names the enforcing function, and a gate resolves it

`docs/assurance/MAPPING.md` carries one row per fail-closed invariant in the
requirement-defined universe. Each row names an exact
`crate::module::function` path and one or more assumption IDs. Assumption
dependencies are many-to-many; forcing a one-assumption partition produced an
incomplete blast radius and was removed in assurance review.

`tools/check-mapping.sh` obtains the four crates' compiled Rust source inventory
from Cargo's rustc dep-info, lexically removes Rust comments and literals, and
resolves each path through the crate-root module graph — including inline and
`#[path]` modules, but excluding orphan source files — to the exact impl type and
function body. It requires one
`// INVARIANT: <NAME>` marker immediately before an executable decision inside
that exact function, and fails on any production marker with no row.

The checked-in `docs/assurance/universe.toml` ratchet records the exact required
invariant and omission IDs/counts, requires the sets to be disjoint, partitions
each ID onto exactly one named surface, and requires production paths to match
that surface. Deleting a row, marker, assumption dependency, or registry entry
without updating the ratchet fails locally. The ratchet and checker are
co-located, however: a coherent edit of both can change the universe. The same
checker resolves `docs/assurance/omissions.toml`. An excluded surface
must name a real function plus an owner, reason, and clearing condition. The
adversarial fixtures prove that comments, strings, wrong-function markers and
markers parked above non-guard statements cannot satisfy it.

### 2. A row is not allowed to exist without a mutation test

This is the substantive decision and the expensive one.

`docs/assurance/negative-registry.toml` maps each row to a
`crates/*/tests/negative_*.rs` test, and `tools/check-negative-registry.sh` fails
on a row with no entry, an entry with no row, an entry naming a test file or test
function that does not exist, a test function carrying anything other than the
compiler's built-in `#[test]` attribute, an ignored or conditionally disabled
test, or a body that does not invoke exactly one shared typed differential
protocol. The shared macro owns the real production invocation and a
source-digested entry/completion sentinel around its synchronous future driver.
A focused `syn` checker requires the canonical fully-qualified macro path,
parses each distinct registered source once, and locally digests the complete
source file: imports and crate bindings, case identity, setup, mutation roles,
production path and arguments, result normalization, mirror operations, and
denial/permission predicates. Mapped markers and adapters name the same public production entry;
the only indirect entries are two Serde conversions explicitly classified as
reviewed boundaries. Comments, strings, locally shadowed macros,
decorative tokens, nonexistent modules/types, and production-shaped
`.evaluate`/`black_box`/unrelated-assertion spoofs are adversarial self-test
cases. The gate binds relevant workspace/crate manifest fields and the exact
Cargo.lock/metadata identities of the runtime, serialization, and proc-macro
dependencies, then compiles every target with `--locked`. It invokes each emitted
test binary directly for exact `--list` set equality and exact passed counts with
zero failed or ignored, so a Cargo runner cannot fabricate execution evidence.
An executable fixture also proves a local fake `tokio-macros` can erase an async
test body and that the dependency boundary rejects the substituted resolution.

The protocol itself has a separate compiled five-test contract target. Its
success case uses typed counters and role capture to prove exactly one real,
one mirror(None), and one mirror(BrokenVariant) call. Four `#[should_panic]`
cases prove real/control mismatch, a permitting real operation, a denying
broken operation, and swapped role identities are rejected. The gate copies
the actual `tests/negative_protocol.rs`, contract, and registered sources into
temporary crates and mutates them. No-op/conditional execution, omitted or
swapped roles, identity-selective returns, forced mirror mutations, and
constant/ignored/swapped/vacuous predicates must all make the gate fail.

The Rust-syntax checker rejects caller control flow around the invocation, dead
closures, renamed production methods, aliases, globs, re-exports, local shadows,
and normalizers that ignore or replace the production result. It also digests
the complete shared protocol implementation, so identity-conditional early
returns and skipped roles are caught by the local check. The expected-binding
file and protocol digests are embedded in checker code; that makes ordinary
source or baseline drift visible, including coordinated edits that do not also
change the checker. It does not authenticate the checker: a coherent change to
the checker plus all inputs can pass. The broader fidelity of each handwritten
mirror remains a reviewed limitation.

The shared typed protocol makes each test do three things over one probe input:

1. drives the **real** function and asserts it refuses;
2. drives an **unmutated mirror** of that function and asserts it reproduces the
   real outcome;
3. drives the **mirror with exactly one guard removed** and asserts it
   **permits** what the real function refused.

Step 3 is what FALSIFY-02 asks for. **Step 2 is the decision worth arguing
about.** Without it, a difference under mutation is not attributable to the
mutation: a mirror that was rewritten sloppily also "permits", and the test would
pass for the wrong reason — this repository's own defect class, reintroduced
inside the mechanism built to prevent it. Every mirror therefore carries a
control, and for the `swarm-runtime` rows the control asserts agreement on the
executor **call count** as well as on the result.

### 3. The mirror lives in the test binary, never behind a build flag

The obvious alternative — a `#[cfg(feature = "mutation")]` hole in the real
function — was rejected. `swarm-policy`, `swarm-crypto` and `swarm-spine` are the
trusted computing base (ADR 0009). A build flag that can open a hole in them is a
hole in them. A mirror in a test target cannot be linked into anything that
ships.

The cost is real and is stated rather than hidden: **nothing mechanical proves a
handwritten mirror is faithful beyond the registered probe and operations.**
The typed control in step 2 and review are what stand in for that broader proof,
and the protocol plus both check scripts say so in their headers rather than
implying a guarantee they do not provide.

### 4. Neutralization evidence is row-local and reproducible

The removed guard can be restored by selecting the mirror's `None` mutation on
the same probe. The resulting differential failure is recorded per row in
`negative-registry.toml`'s `observed_when_neutralized`, and the field is required
non-empty. The prose in `permits` and `observed_when_neutralized` is not
mechanically interpreted or compared to stdout; the executable assertions are
authoritative and review checks that the prose describes them. This ADR does
not claim those outputs are in a commit message; exact
commands and outputs belong in the execution handoff that reproduced them.

A negative test that has never been seen failing is not evidence. That is the
eleventh entry in `.planning/STATE.md` wearing a different hat.

### 5. `tools/`, not `scripts/`

MAPPING-04, MAPPING-05, FALSIFY-03 and FALSIFY-04 all say `scripts/check-*.sh`.
There is no `scripts/` directory in this repository and never has been. Every
gate is `tools/check-*.sh`, and `tools/check-gates-wired.sh` enumerates that
directory — a gate placed in `scripts/` would be invisible to the gate that
checks gates are wired. The requirement wording is stale; phase 283 hit the same
thing and recorded the same deviation.

Workflow wiring is not branch protection or provenance. Both scripts are
invoked by `.github/workflows/ci.yml`, but another workflow can present the same
Actions App identity and `panic-contract` check name. MAPPING-05 and FALSIFY-04
remain open until a dedicated external GitHub App check with a distinct
integration ID is protected (or the organization upgrades and an admin-owned
required workflow is pinned).

## What this buys, stated narrowly

57 rows across `swarm-policy` (10), `swarm-response` (15), `swarm-runtime` (15)
and `swarm-spine` (17), each with a same-probe differential mutation test, plus
five enforced omissions for named surfaces that render no pre-dispatch refusal.

It does NOT buy:

- **whole-tree completeness.** The declared universe is the four surfaces named
  by MAPPING-02, not every crate. `swarm-agents::GovernancePolicy::can_act` is
  outside that declared universe; expanding the requirement must expand the
  scope registry rather than silently pretending it was already covered.
- **evidence about concurrency or crash recovery.** Every row is proved by a
  single-process, in-memory test. Phases 286 and 287 are where those come from.
- **a trust anchor for release attestation.** `RUNTIME-RELEASE-SUBJECT-BOUND`
  proves the attestation covers *this* receipt body. It does not prove a governor
  you trust signed it; `ConsensusGovernanceReceipt::verify` checks the signature
  against the public key carried inside the receipt. Open as task #27.

## Two findings the table surfaced

Writing an honest "enforced by" column forced two measurements that were not
being made.

### `swarm_spine::chain::verify_chain_link` has no production caller

```
$ grep -rn 'verify_chain_link' crates/ | grep -v swarm-spine/src/chain.rs | grep -v tests/negative_
crates/swarm-spine/src/lib.rs:61:pub use chain::{ChainLinkVerdict, IssuerChainHead, chain_head_from_envelope, verify_chain_link};
```

Ten chain rows are invariants of a public, tested primitive of a TCB crate
that the critical lane does not call. They are mapped anyway, and the table says
so in the row notes: the guard has to be right before something depends on it,
and a row that states its own reachability is worth more than an absent row. The
alternative — quietly listing them as if the system enforced them — is the defect
this ADR exists to prevent.

### The approval ledger builds a chain nobody verifies

`swarm_runtime::approval::build_vote_envelope_hash` passes
`entries.last().envelope_hash` as the next envelope's `prev_envelope_hash`. It
calls `verify_envelope` on what it just built — a self-check — and no code path
anywhere calls `verify_chain_link` on the result. The ledger's links are
constructed and never checked, so a rewritten or reordered ledger would not be
detected by anything.

This is a gap, not a regression, and it is not fixed here: fixing it means
deciding where the `IssuerChainHead` for the ledger lives and what a verification
failure should do to an in-flight approval, which is design work rather than a
line change. `ASSUME-CHAIN-HEAD-DURABILITY` in `assumptions.toml` records it with
the measurement, and it is reported as follow-up.

## Alternatives rejected

**Derive one file from the other.** `assumptions.toml`'s `invariants` lists could
be generated from MAPPING.md at read time. Then they would always agree and the
agreement would mean nothing. They are maintained separately and
`check-mapping.sh` requires set equality in both directions, so a drift is a red
build rather than an invisible no-op.

**Let a row cite a positive test.** Every one of these invariants already had
passing positive tests before this phase, and several of the defects listed above
shipped underneath passing positive tests. A positive test proves the system
denies; it does not prove the named guard is what denied.

**Coverage floors as completeness.** The criterion's minimum of twelve is a
floor, not permission to stop counting. The first implementation did that and
missed real guards. The revised decision enumerates the named surfaces, freezes
their exact IDs in `universe.toml`, and uses explicit enforced omissions for
exclusions.
