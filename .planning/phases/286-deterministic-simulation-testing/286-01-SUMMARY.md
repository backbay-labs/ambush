# Phase 286 Plan 01 Summary — Rejected Candidate

**Status: SUPERSEDED / REJECTED 2026-09-07. Phase 286 is reopened and in progress.**
The closure recorded by `1a5c9003b` is withdrawn. Its test results do not establish
DST-01..06. The replacement work is [286-02-PLAN.md](286-02-PLAN.md); the recovery
and blocking review are [286-REVIEW.md](286-REVIEW.md). No replacement implementation
or gate is declared passed in this record.

## Preserved candidate identity

The interrupted Claude session built eight commits on `feat/dst-286`, based on
`5ad9b6850`, with candidate head `1a5c9003b`, in the sibling checkout
`/Users/connor/Medica/backbay/standalone/swarm-team-six-dst-286`:

- `3cc4525fc`: original implementation plan.
- `761a65bdc`, `0b8b8f45b`: harness foundation and comment correction.
- `bd9f5b251`: the three named fault classes.
- `d7d03b868`, `9925a7e2e`: oracles, corpus and task-review fixes.
- `fb80d8a90`: nightly workflow and former MAPPING evidence-boundary section.
- `1a5c9003b`: the premature planning closure.

These objects preserve the original work and its claims for comparison. The
original plan remains historical evidence; its permission to weaken an oracle
to match existing behavior is superseded by the repair plan.

## Why the closure was rejected

The purported receipt-before-action oracle checked the reverse subset: persisted
receipt identities had to appear among observed actions. It accepted an action
with no durable prior authorization record and no completion receipt. The exact
policy-disposition oracle also accepted a dropped episode without checking for
forbidden effects. At-most-once counts covered one invocation without restarting
and redelivering the same request. Repeated seeds exercised only four effective
schedules, and substrate reopen substituted a fresh empty in-memory instance.

A passing counter-based corpus with those properties cannot establish durable
ordering, policy safety through cancellation, or duplicate suppression after a
crash. The former reports of a green 64/5,000-seed corpus and clean task reviews
are historical reports about this rejected candidate, not acceptance evidence.
The final whole-branch review was interrupted before a verdict.

## Repair contract

Before a live effect, both production runtime entry paths must durably reserve
the request identity and its immutable authorized content in a dispatch-intent
journal. A post-effect completion receipt records an observed result. An intent
is not a claim that an action completed, and a missing completion after a crash
must remain unresolved and must not authorize another effect. The local journal
is unsigned and depends on OS/filesystem protections; signed audit artifacts are
a separate evidence surface.

The replacement proof must exercise real sandbox effects, persistent substrate
reopen, request redelivery, varied deterministic fault schedules and production
mutations that expose each safety failure. Phase 286 remains open until its
immutable repaired tree passes that proof and the existing required gates.
