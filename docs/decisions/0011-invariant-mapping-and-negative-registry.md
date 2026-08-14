# ADR 0011: Fail-Closed Is A Table With Mutation Tests Behind It, Not A Sentence

## Status

Accepted on 2026-08-14. Phase 285, MAPPING-01..05 and FALSIFY-01..04.

Supersedes nothing. Names invariants of the trusted computing base ADR 0009
draws; adds no dependency edge to any TCB crate, so
`tools/check-workspace-layering.sh` needed no new `TCB_ALLOWED_WORKSPACE_DEPS`
entry. The four new test targets live in `crates/*/tests/` and use only
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

`docs/assurance/MAPPING.md` carries one row per fail-closed invariant. Each row
names an exact `crate::module::function` path and one assumption ID.

`tools/check-mapping.sh` resolves each path against the tree — crate directory,
module file, declared type, declared `fn` — and fails when it does not exist.
It also requires a `// INVARIANT: <NAME>` marker on the enforcing statement, **in
the file the row resolves to**, and fails on any marker in production code that
has no row.

Production text is everything above the first column-0 `#[cfg(test)]` in a file,
so a function that exists only inside a test module does not satisfy a row. The
self-test exercises that direction explicitly (`function_only_under_cfg_test`),
because a truncation rule with no fixture is itself an uninspected region.

### 2. A row is not allowed to exist without a mutation test

This is the substantive decision and the expensive one.

`docs/assurance/negative-registry.toml` maps each row to a
`crates/*/tests/negative_*.rs` test, and `tools/check-negative-registry.sh` fails
on a row with no entry, an entry with no row, an entry naming a test file or test
function that does not exist, a test function carrying no `#[test]` attribute, or
a `broken_variant` that is not both defined in the file and named inside the test
body.

Each such test does three things over one probe input:

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
mirror is faithful.** The control in step 2 and review are what stand in for it,
and both check scripts say so in their headers rather than implying a guarantee
they do not provide.

### 4. Every mutation was neutralized and watched to fail

For each of the 21 rows, the removed guard was put back — making the "broken"
variant no longer broken — and the test was run and observed failing. The
observed text is recorded per row in `negative-registry.toml`'s
`observed_when_neutralized`, and the field is required to be non-empty.

A negative test that has never been seen failing is not evidence. That is the
eleventh entry in `.planning/STATE.md` wearing a different hat.

### 5. `tools/`, not `scripts/`

MAPPING-04, MAPPING-05, FALSIFY-03 and FALSIFY-04 all say `scripts/check-*.sh`.
There is no `scripts/` directory in this repository and never has been. Every
gate is `tools/check-*.sh`, and `tools/check-gates-wired.sh` enumerates that
directory — a gate placed in `scripts/` would be invisible to the gate that
checks gates are wired. The requirement wording is stale; phase 283 hit the same
thing and recorded the same deviation.

## What this buys, stated narrowly

21 rows across `swarm-policy` (5), `swarm-response` (4), `swarm-runtime` (6) and
`swarm-spine` (6), each with a mutation test that has been observed failing.

It does NOT buy:

- **completeness.** Nobody has enumerated every fail-closed guard in the tree.
  The table is the set of invariants that are real, already enforced, and
  falsifiable today. `swarm-agents`' `GovernancePolicy::can_act` — the fix in
  b4bf119, and a genuine fail-closed guard — has no row, because the phase's
  criterion names four crates and holding the diff to four crates mattered more
  than a twenty-second row.
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

Four of the 21 rows are invariants of a public, tested primitive of a TCB crate
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

**Thirty rows.** The criterion asks for twelve. Twenty-one is what could be
backed by a mutation test that was actually observed failing, without inventing
an invariant to fill a row.
