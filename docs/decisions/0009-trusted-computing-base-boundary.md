# ADR 0009: The Trusted Computing Base, Stated As Negative Space

## Status

Accepted on 2026-08-13. Phase 283 (TCBOUND-01..04).

### A note on this file's path and number

TCBOUND-01 names `docs/adr/ADR-0001-trusted-computing-base.md`. There is no
`docs/adr/` directory in this repository and there never has been; ADRs live in
`docs/decisions/` and are numbered `0001`-`0008`. Landing this at the
requirement's path would have started a second, competing ADR tree whose first
entry collided in number with `0001-rust-first-runtime.md` — a documentation
split with two files both called "ADR 0001". The existing location and the next
free number are used instead, and the deviation is recorded here and in
`.planning/REQUIREMENTS.md` rather than applied silently.

The same reasoning applies to TCBOUND-03's `scripts/check-workspace-layering.sh`.
There is no `scripts/` directory; gates live in `tools/`, and
`tools/check-gates-wired.sh` enumerates `tools/check-*.sh` to prove each one is
invoked by a workflow. A gate landed outside `tools/` would be invisible to the
gate that exists to catch unrun gates. The script is
`tools/check-workspace-layering.sh`.

## Context

`swarm-policy` decides whether a destructive action is permitted. `swarm-crypto`
decides what a signature is taken over. `swarm-spine` decides what "this
happened and has not been altered" means. If any of those three is wrong, every
other assurance in this system is decoration — the detection can be perfect and
the receipt still worthless.

Measured at the phase-283 baseline, that trio is dependency-clean in the way
that matters most:

```
$ cargo metadata --format-version 1 --all-features --locked   # via the gate
swarm-policy   declared normal: serde, serde_json, swarm-core, thiserror, tracing
swarm-crypto   declared normal: ed25519-dalek, hex, rand_core, ryu, serde,
                                serde_json, sha2, thiserror
swarm-policy   resolved-normal transports reachable: (none)
swarm-crypto   resolved-normal transports reachable: (none)
```

Nothing enforced that, and six milestones of capability (v1.79 through v1.87)
are queued to be built around these crates. The property was true by luck and
by review attention, and review attention is the thing that does not survive
contributor turnover.

Phase 282 also just finished cutting `swarm-runtime` into seven crates. The
product-crate list TCBOUND-03 was written against — `swarm-cli`,
`swarm-runtime`, `swarm-runtime-http` — predates `swarm-agents`,
`swarm-evolution`, `swarm-ingest-runtime` and `swarm-runtime-workbench`, so a
gate typed against those three names would have let the same inversion in
through a door that did not exist when the requirement was written.

## Decision

### The trusted computing base is three crates

`swarm-policy`, `swarm-crypto`, `swarm-spine`.

- **`swarm-crypto`** — Ed25519, SHA-256, Merkle trees, canonical JSON. The
  deepest member: everything above it inherits whatever it links.
- **`swarm-policy`** — the deterministic response gate, capability leases, and
  the governance authority the dispatcher authorizes through.
- **`swarm-spine`** — signed envelopes, the issuer chain, witnessed
  checkpoints, and the audit record shapes for one handled event.

### Stated as negative space: what the TCB must never depend on

Positive statements of scope rot quietly, because nobody notices a missing
sentence. These are stated as prohibitions so that violating one is an event.

1. **Never a transport or a command line.** No TCB crate may name `axum`,
   `clap`, `hyper` or `reqwest` in any dependency section, in **any** dependency
   kind — normal, dev, or build. A transport client is a parser for
   attacker-controlled bytes plus a connection pool plus a TLS stack; a
   command-line parser is an argument surface. Neither belongs in a crate whose
   output is a yes-or-no answer about destroying something. Dev-dependencies are
   included on purpose: ADR 0008 is a whole ADR about an `axum` edge that is
   "only" a dev-dependency and still compiles a transport stack into five
   targets of the crate that declares it.

2. **Never anything above it.** No TCB crate may name a crate that sits above
   the TCB, in any dependency kind. "Above" is derived, not listed: the TCB
   closure is the three crates plus everything they reach on the resolved normal
   graph (measured today: `swarm-core`, `swarm-crypto`, `swarm-policy`,
   `swarm-response`, `swarm-spine`, `swarm-whisker`), and everything else in the
   workspace that reaches the TCB is above it — 14 crates today, including all
   three TCBOUND-03 names. Deriving it means a crate added tomorrow is
   classified by its edges rather than by somebody remembering to update a list.

3. **Never the advisory lane.** Neither `swarm-policy` nor `swarm-response` may
   depend on the crate hosting the memory or correlation modules
   (`crates/swarm-runtime/src/sphinx_agent.rs` and
   `crates/swarm-runtime/src/correlation.rs`, both in `swarm-runtime` today).
   A policy verdict must not vary with how much optional context happened to be
   available, or an attacker who starves the correlation lane has changed what
   the gate decides. XHUNT-03 asserts this at runtime with both lanes disabled;
   this makes it a build-time property instead, and it covers `swarm-response`,
   which is not in the TCB.

4. **Never a widening of `pub`.** Out of scope for this ADR and already
   enforced: `tools/check-visibility-baseline.sh`.

### What is trust-sensitive but deliberately outside the TCB

TCBOUND-02 names six crates, all six of which exist and now carry an
"Owns / does not own" section in their crate-level doc comment:
`swarm-policy`, `swarm-pheromone`, `swarm-response`, `swarm-guard`,
`swarm-crypto`, `swarm-spine`. Three are the TCB. The other three are trust-
sensitive and outside it, each for a stated reason:

- **`swarm-response`** links `reqwest`, because a live-response adapter has to
  talk to an EDR. That is exactly why the *decision* lives one crate down in
  `swarm-policy`, where no transport is reachable.
- **`swarm-pheromone`** links `async-nats` under its default `nats` feature. A
  forged or flooded deposit changes what the detection lane concludes, so it is
  trust-sensitive; it links a network client, so it is not TCB.
- **`swarm-guard`** is a consumer of the boundary, not part of it. Passing every
  guard authorizes nothing; only `swarm-policy` does.

Two further crates were considered and are not in either list.
`swarm-consensus` is trust-sensitive by any reading — it sizes the Byzantine
threshold that gates destructive response — and its manifest is already clean
(`swarm-core`, `swarm-crypto`, and eight leaf libraries: `async-trait`,
`ed25519-dalek`, `hex`, `serde`, `serde_json`, `thiserror`, `tokio`,
`tracing`). It is left out only
because phase 321 is actively changing it (`recommended_max_faulty`, committee
resizing, BFT-03's removal of the co-located-key path), and adding a boundary
doc section to a crate mid-repair invites the section and the code to disagree.
`swarm-core` is inside the TCB *closure* and is enforced as such by rule 1 —
a transport added to `swarm-core` fails this gate — but it is not itself named
TCB, because it is the workspace's shared type vocabulary and every crate
depends on it. Both are follow-ups, not omissions.

### The one accepted deviation

Rule 1 is stated over declared edges. On the **resolved** normal graph the TCB
is not transport-free today, and pretending otherwise would be the exact defect
this repository keeps catching:

```
$ cargo tree -p swarm-spine -i reqwest -e normal
reqwest v0.12.28
└── swarm-response v0.1.0
    └── swarm-spine v0.1.0

$ cargo tree -p swarm-spine -i hyper -e normal
hyper v1.9.0
├── hyper-rustls v0.27.9
│   └── reqwest v0.12.28
│       └── swarm-response v0.1.0
│           └── swarm-spine v0.1.0
...
```

`swarm-spine` declares `swarm-response` because its envelopes embed
`ResponseReceipt` and `ResponseFailure`; `swarm-response` declares `reqwest` for
the HTTP EDR adapter. So the audit crate reaches an HTTP client, and no rule
written inside `swarm-spine`'s manifest can change that.

Those two edges — and only those two — are recorded as
`RESOLVED_TRANSPORT_BASELINE` in `tools/check-workspace-layering.sh`, in the
same shape `tools/check-visibility-baseline.sh` records its three accepted
`pub` widenings. A **third** resolved transport edge into the TCB fails the
build, and a baseline entry that stops holding **also** fails the build, so the
exemption cannot quietly outlive its reason. Both fixture-proved (cases 6 and 7
below).

What deletes them: inverting `swarm-spine`'s dependency on `swarm-response`
behind a trait, so the receipt types stop pulling the EDR HTTP client into the
TCB. That is a crate-shape change of the same class as ADR 0003's executor
inversion and belongs to a phase that owns crate shape, not to this one.

### Declared edges or the resolved graph — the rule-by-rule ruling

Phase 282 shipped a wrong claim by conflating these, so each rule states which
reading it uses and why.

| Rule | Reading | Why |
| --- | --- | --- |
| 1. TCB × transport | **Declared**, all three kinds | What a manifest owner controls and a reviewer can be held to. TCBOUND-03's own word is "direct". |
| 2. TCB × above-the-TCB | **Declared**, all three kinds | Same, and it is the only reading that catches dev cycles — which cargo permits outright, so nothing else rejects them. |
| 3. TCB × transport | **Resolved normal**, against a baseline | Catches a transport smuggled in through `swarm-core`, which rule 1 cannot see. Cannot be enforced at zero; see the deviation above. |
| 4. Advisory lane | **Both** | The declared form is the reviewable one; the resolved form catches an indirect route. |

Target-specific edges are **not** filtered out of the resolved reading, so the
gate's answer does not depend on the host it runs on. Renames do not evade any
rule: `cargo metadata` reports the real package name, so
`wire = { package = "reqwest" }` is matched as `reqwest`.

## Consequences

### Positive

- The boundary is a build failure rather than a review catch, on every PR.
- The "above the TCB" set is derived from `cargo metadata`, so it covers the
  seven crates phase 282 created and every crate created after this ADR.
- The one real deviation is written down with the command that reproduces it and
  the change that closes it, instead of being narrowed away.
- `swarm-response` — the crate that actually executes destructive actions — is
  covered by the advisory-lane rule despite being outside the TCB.

### Negative

- Rule 1 is a declared-edge rule, so a transport reaching the TCB through a
  crate the TCB depends on is caught by rule 3's baseline comparison rather than
  by rule 1, and only once the resolved set grows. There is no reading under
  which the TCB is transport-free on the resolved graph today.
- The advisory-lane rule is stated over the *crate* that hosts the memory and
  correlation modules. It is strictly stronger than a module-level rule while
  those modules stay in `swarm-runtime` (with `swarm-runtime` out of the
  manifest, `use swarm_runtime::correlation::CorrelationEngine` is a compile
  error), but it is aimed by a two-line registry. If a module moves, the gate
  fails loudly with `LAYERING-VACUITY[guard]` and the registry must be
  re-pointed — fixture case 10 proves that, and it is the deliberate cost of
  expressing a module rule through a crate-level tool.
- `swarm-consensus` and `swarm-core` carry no "Owns / does not own" section, for
  the reasons given above.

## Verification

The gate proves it can fail before it is trusted to pass. Every invocation
generates a miniature cargo workspace — real crate names, stub crates literally
named `axum`/`clap`/`hyper`/`reqwest` as path dependencies so nothing is
fetched — runs real `cargo metadata` over it, and runs the **same rule engine
with the same policy and the same baseline**, unmodified. One control case plus
nine deliberately-broken variants. Observed 2026-08-13, exit 0 overall:

```
$ bash tools/check-workspace-layering.sh
fixture: proving this gate can fail before trusting it to pass
  ok  clean fixture passes  (exit 0)
  ok  swarm-policy declaring clap is caught  (exit 1)
  ok  swarm-crypto taking axum as a DEV dependency is caught  (exit 1)
  ok  swarm-policy taking swarm-runtime as a DEV dependency is caught  (exit 1)
  ok  swarm-spine taking swarm-pheromone as a BUILD dependency is caught  (exit 1)
  ok  a transport smuggled in through swarm-core is caught  (exit 1)
  ok  a baseline edge that no longer holds is caught  (exit 1)
  ok  swarm-response reaching the advisory lane is caught  (exit 1)
  ok  a trust-sensitive crate losing its Owns section is caught  (exit 1)
  ok  the correlation module moving fails the gate loudly  (exit 2)
fixture: 10 case(s) passed (1 control, 9 deliberately broken)

workspace layering holds: 3 TCB crates (swarm-crypto, swarm-policy,
swarm-spine); 6 crates in the TCB closure; 14 crates derived as downstream of
it, including all 3 named by TCBOUND-03; 4 transport names checked against
declared edges of all three kinds; 2 resolved-normal transport edge(s), all on
the accepted baseline; 1 advisory-lane host crate(s) (swarm-runtime) held out of
2 critical-path crate(s); 6 crate(s) carrying Owns / Does not own
```

The control case is load-bearing: without a clean fixture that exits 0, the nine
broken variants would "catch" every violation while catching none. Every number
in the success line is derived from the sets the engine computed, never typed —
the defect corrected in `tools/check-gates-wired.sh` and
`tools/check-visibility-baseline.sh` was a success line printing hand-typed
counts.

Four of the nine variants exercise cases **cargo itself accepts**: dev- and
build-dependency cycles are legal, and a transitive transport edge is not
cargo's concern. A TCB crate taking a *normal* dependency on a crate above it is
a cycle that `cargo metadata` refuses to resolve; that failure is real and this
script propagates it under `set -e`, but it is cargo speaking, not this gate.

The check is wired as an unconditional step of the `panic-contract` job in
`.github/workflows/ci.yml`, and `tools/check-gates-wired.sh` fails the build if
that ever stops being true.

## Follow-On Work

- Invert `swarm-spine -> swarm-response` behind a trait, then delete both
  `RESOLVED_TRANSPORT_BASELINE` entries; the gate will demand the deletion.
- Give `swarm-consensus` an "Owns / does not own" section once phase 321's BFT
  repair lands, and consider adding it to `TRUST_SENSITIVE`.
- Decide whether `swarm-core` should be named TCB rather than merely enforced as
  part of its closure.
- Reconcile the requirement paths: TCBOUND-01's `docs/adr/` and TCBOUND-03's
  `scripts/` do not exist and should be corrected in `.planning/REQUIREMENTS.md`
  rather than created.
