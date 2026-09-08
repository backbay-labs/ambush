# ADR 0012: The Decision-Core Dependency Boundary

## Status

Accepted on 2026-09-08. Phase 292 (v1.81 Machine-Checked Decision Core), Task 3
(DCORE-03, DCORE-04).

### A note on this file's path and the gate's path

The phase-292 plan names `docs/adr/0012-decision-core-boundary.md` and
`scripts/check-decision-core-boundary.sh`. There is no `docs/adr/` directory in
this repository and never has been — ADRs live in `docs/decisions/`, numbered
`0001` through `0011`, and this is `0012`. There is no `scripts/` directory
either; every gate lives in `tools/`, and `tools/check-gates-wired.sh`
enumerates `tools/check-*.sh` to prove each one is invoked by a workflow.
Landing this gate outside `tools/` would have made it invisible to the gate
that exists to catch unrun gates. This is the same deviation ADR 0009 recorded
for TCBOUND-01 and TCBOUND-03, recorded again here for the same reason: the
script is `tools/check-decision-core-boundary.sh`.

## Context

Phases 288 through 291 (v1.80, the red-swarm work) and phase 292's first two
tasks carved `swarm-policy`'s rate-limit and governance predicates out of the
crate's IO- and clock-touching code into a pure, injected-clock module,
`crates/swarm-policy/src/formal_core.rs`. That module is the intended proof
surface for two phases still to come:

- **Phase 293** — Kani, a bounded model checker, exhaustively proving
  properties of `formal_core.rs`'s functions over their input space.
- **Phase 294** — named safety properties stated over the same functions.

Both depend on `formal_core.rs`, and therefore on everything `swarm-policy`
itself pulls in, staying reasoned-about-able: no network IO, no wall-clock
reads, no ambient non-determinism a model checker cannot enumerate. A
transport client, a telemetry exporter, or a command-line parser arriving in
that dependency graph would not change what `formal_core.rs`'s source text
says, but it would change what compiles into the crate carrying it, and an
`unsafe`, `async`, or FFI-touching transitive dependency is exactly the kind of
thing that makes "prove properties of this module" a claim about a much larger
and less tractable surface than the module itself.

Measured at this phase's baseline, `swarm-policy` is already clean:

```
$ cargo metadata --format-version 1 --all-features --locked   # via the gate
swarm-policy declares (normal): serde, serde_json, swarm-core, thiserror, tracing
swarm-policy resolved-normal forbidden crates reachable: (none)
```

Nothing enforced that. `swarm-policy`'s own manifest names only `swarm-core`
and four leaf libraries, but ADR 0009's own history is a lesson that a
manifest reading nothing does not mean the resolved graph reaches nothing:
ADR 0008 records `swarm-runtime` reaching `axum` on its normal resolved
profile through a dev-dependency's own transitive edge, invisible to anyone
reading `swarm-runtime`'s `[dependencies]` section. `swarm-core` — the one
thing `swarm-policy` depends on — is workspace-wide shared vocabulary that
every crate touches; a future change to it is exactly the kind of edge that
would arrive without a single line of `swarm-policy`'s own `Cargo.toml`
changing.

## Decision

### The decision core's dependency graph must never reach seven names

`swarm-policy` — the crate hosting `formal_core.rs` — may never reach, on its
**resolved NORMAL dependency graph**, any of:

`axum`, `hyper`, `tokio-rustls`, `reqwest`, any `opentelemetry*` crate, `clap`,
`x509-parser`.

Four of these — `axum`, `hyper`, `reqwest`, `clap` — are ADR 0009's own
TCBOUND-03 list, restated here because the decision core is where the
Kani/named-property proof obligation actually lives, not merely where trust
concentrates the way the TCB does. `tokio-rustls`, `opentelemetry*` and
`x509-parser` are added because they are the other three shapes a proof
surface must not carry:

- **`tokio-rustls`** is a TLS stack. A model checker reasoning about
  `formal_core.rs` must not also be reasoning, even transitively, about
  certificate validation and an async IO runtime's scheduling.
- **`opentelemetry*`** (the whole family — `opentelemetry`,
  `opentelemetry_sdk`, `opentelemetry-otlp`, and anything else sharing the
  prefix) is a telemetry exporter: background export tasks, batching timers,
  and network calls are exactly the ambient non-determinism a bounded model
  checker cannot enumerate and a named safety property should not have to
  account for.
- **`x509-parser`** is a parser for attacker-controlled bytes (a certificate).
  The same reasoning ADR 0009 gives for banning a transport from the TCB
  applies to a byte parser in the decision core's own graph: it is an attack
  surface with nothing to do with "should this response be authorized."

### This is enforce-only

Unlike ADR 0009's TCB boundary, which records one accepted deviation on the
resolved graph (`swarm-spine -> swarm-response -> reqwest -> hyper`), this
boundary starts, and today remains, at zero. There is nothing to remove and no
baseline to record — `swarm-policy` has never named any of these seven, and
the gate exists to keep that true as phases 293 and 294, and everything
queued after them, are built on top of `formal_core.rs`.

### Mechanism: the resolved graph, not the manifest

`tools/check-decision-core-boundary.sh` reads `cargo metadata`'s resolved
graph (`resolve.nodes[...].deps[...].dep_kinds`), not `swarm-policy`'s
`Cargo.toml`. `cargo metadata` resolves the full dependency graph — feature
flags, version selection, everything — without compiling anything, so this is
one fast call, not a build. The gate walks every edge whose `dep_kinds`
includes `kind: null` (cargo's spelling of "normal") reachable from
`swarm-policy`, over every workspace feature (`--all-features`), and fails if
any node's package name is one of the six exact forbidden names or starts
with `opentelemetry`. Dev- and build-dependency edges are out of scope: a
Kani harness or a named-property test never compiles `swarm-policy`'s dev or
build profile, so a `[dev-dependencies]` edge is not part of the proof
surface those phases will build.

### The self-test

A gate never observed to fail is not a gate. The forbidden-name walk is one
function, `scan_forbidden(graph, name_of, root)`, generic over any
node-to-children mapping. The real check builds that mapping from `cargo
metadata`'s resolved edges and calls it once; a self-test that runs on **every
invocation**, before the real check, builds a small synthetic mapping in
memory and calls the identical function against four cases: a clean control
shaped like `swarm-policy`'s real tree, a forbidden crate planted as a direct
dependency, a forbidden crate planted two hops behind a stand-in for
`swarm-core` (the ADR 0008 smuggling shape a manifest read cannot see), and an
`opentelemetry*` family member planted under a different suffix than the
exact strings the exact-match rules use, proving the ban is a prefix rule.
None of this touches a real `Cargo.toml`, `Cargo.lock`, or spawns a second
`cargo` invocation — the synthetic graphs are plain in-process data, so there
is no fixture to build or tear down and no risk of mutating the tree the gate
is supposed to be checking.

## Consequences

### Positive

- The boundary is a build failure on every PR, not a review catch, before
  phase 293 spends effort proving anything about a surface this gate has not
  yet protected.
- The rule reads the resolved graph, so a forbidden crate arriving through
  `swarm-core` — the one thing `swarm-policy` depends on, and shared by every
  crate in the workspace — is caught the same way a direct dependency is.
- The self-test runs on every invocation rather than living in a separate,
  possibly-stale test file, so a change to the scan logic that breaks its own
  claimed behavior fails the gate immediately rather than only showing up as
  a false "clean" on the real graph.

### Negative

- The rule is scoped to `swarm-policy` alone, not the wider TCB ADR 0009
  already covers. If `formal_core.rs`, or an equivalent proof surface, is ever
  split into its own crate, this gate's `CRATE` constant needs to move with
  it — nothing here derives that automatically the way ADR 0009's TCB closure
  is derived.
- `opentelemetry*` is matched by prefix rather than an exhaustive enumerated
  list. That is deliberate (new family members should not need a gate
  update), but it means a crate that merely happens to start with
  `opentelemetry` for an unrelated reason would also be caught; no such crate
  exists in this workspace's dependency graph today.

## Verification

```
$ bash tools/check-decision-core-boundary.sh
self-test: proving the scan can both pass and catch a plant before trusting it
  ok  clean synthetic graph reports nothing  (found: none)
  ok  a direct forbidden dependency is caught  (found: reqwest via swarm-policy -> reqwest)
  ok  a forbidden dependency smuggled two hops behind swarm-core is caught  (found: hyper via swarm-policy -> swarm-core -> telemetry-shim -> hyper)
  ok  an opentelemetry* family member is caught by the prefix rule  (found: opentelemetry-otlp via swarm-policy -> opentelemetry-otlp)
self-test: 4 case(s) passed (1 control, 3 deliberately planted)

decision-core boundary holds: none of 7 forbidden crate name(s) (axum, hyper, tokio-rustls, reqwest, clap, x509-parser, opentelemetry*) are reachable from 'swarm-policy' on the resolved NORMAL dependency graph
```

The self-test's own mechanism was additionally cross-checked against the REAL
resolved graph, not just synthetic data, by pointing the same engine's root at
`swarm-cli` (which does declare `clap` and does reach `reqwest`, `axum`,
`opentelemetry*` and the rest transitively): it correctly reported all eleven
forbidden packages actually present in that crate's resolved graph, each with
the real dependency path, and exited non-zero.

The check is wired as an unconditional step of the `panic-contract` job in
`.github/workflows/ci.yml`, immediately after the trusted-computing-base
layering check, and `tools/check-gates-wired.sh` fails the build if that ever
stops being true.

## Follow-On Work

- If `formal_core.rs` moves into its own crate ahead of, or during, phase 293,
  re-point `CRATE` in `tools/check-decision-core-boundary.sh` at the new crate
  name in the same commit that moves it.
- Phase 293 (Kani) and 294 (named safety properties) are the reason this
  boundary exists; this task adds no proof of its own, only the dependency
  floor those phases will build on.
