# ADR 0003: SPLIT-02 Delivers `swarm-runtime-workbench`; `swarm-runtime-replay` Is Blocked By A Composition-Root Cycle

## Status

Accepted on 2026-08-12. Amended on 2026-08-13 after review, on the Verification
block only. The decision stands, the cycle is unchanged, and the Context
measurements are left exactly as taken on 12 August. Two of the four commands
there had drifted out of agreement with the tree:

- "Forward edge: production consumers inside the root. Currently 20." returns 15
  at cc5b169. **Nothing addressed the cycle.** Five consumers left the CRATE in
  two later extractions: `evidence.rs`, `governance_prep.rs` and `portfolio.rs`
  to `swarm-evolution` (SPLIT-04, 1db4191/e870ecd/0431315), and `ingest/mod.rs`
  and `ingest/demo.rs` to `swarm-ingest-runtime` (SPLIT-05, d5ae8bd). A consumer
  in another crate does not stop being a consumer; it stops being counted by a
  command scoped to `crates/swarm-runtime/src/`.
- The prose-audit command's single expected hit is now
  `swarm-runtime-workbench/src/lib.rs:27`, not `:24`.

The other two commands -- the return edge and the identifier-form cycle probe --
still print what this ADR says they print.

## Context

SPLIT-02 (phase 282) undertook two extractions in one requirement:
`swarm-runtime-replay` from `crates/swarm-runtime/src/replay/`, and
`swarm-runtime-workbench` from `crates/swarm-runtime/src/workbench/` plus
`review_workbench.rs`.

The workbench half is delivered. The replay half cannot be done as code motion.

### The cycle the requirement predicted was real, and is fixed

SPLIT-02's text names one cycle: `http` imports `crate::review_workbench` types
while `workbench` imports `crate::operator_http::OperatorSurfacePaths`, so
extracting both as-is would not build. It prescribed relocating
`OperatorSurfacePaths` first. That landed in 754567d, and it holds:

```
$ grep -rn "pub struct OperatorSurfacePaths" crates/
crates/swarm-core/src/config/operator.rs:318:pub struct OperatorSurfacePaths {

$ grep -rn "swarm_runtime_http\|crate::http" crates/swarm-runtime-workbench/src/ --include='*.rs'
$ echo "rc=$?"
rc=1

$ grep -rn "swarm.runtime.http" crates/swarm-runtime-workbench/src/ --include='*.rs'
crates/swarm-runtime-workbench/src/lib.rs:24://! and in `swarm-runtime-http`, which inherited it the same way in SPLIT-01:
```

The workbench crate references the HTTP crate **not at all** in code: no import,
no path, no `use`. The identifier-form pattern returns nothing (rc=1). Widening
the pattern to the hyphenated crate name -- which is how a doc comment would
spell it, and which the identifier pattern therefore cannot match -- turns up one
line, and it is prose. The edge is one-way, `swarm-runtime-http` ->
`swarm-runtime-workbench` -> `swarm-runtime`, and the workbench extraction went
through on that basis.

### A second cycle the requirement does not mention

`replay` and the composition root depend on each other, in non-test code, in
both directions.

**Root -> replay.** Comment out `pub mod replay;` at
`crates/swarm-runtime/src/lib.rs:41` and run:

```
$ cargo check -p swarm-runtime --lib --message-format=short
rc=101
error: could not compile `swarm-runtime` (lib) due to 36 previous errors
```

The 36 are spread over 20 files. `--lib` does not compile `#[cfg(test)]`
modules, so every one of them is production code:

```
   4 ingest/mod.rs          2 selection.rs            1 promotion.rs
   3 strategy.rs            2 portfolio.rs            1 mutation.rs
   3 mutation/fitness.rs    2 kitten_agent.rs         1 ingest/demo.rs
   3 lib.rs                 2 evolution/helpers.rs    1 governance_prep.rs
   3 drafting.rs            2 evolution/formal_safety.rs
                            1 red_swarm.rs            1 evolution.rs
                            1 evidence.rs             1 evasion_coverage.rs
                            1 detector_factory.rs     1 canary.rs
```

Thirty-three of them are `E0432`/`E0433` on `crate::replay` directly. The
remaining three, all in `mutation/fitness.rs`, are `E0689` -- "can't call method
clamp on ambiguous numeric type {float}" -- which is inference fallout from the
replay types disappearing out from under those expressions, not a pre-existing
defect. Restore the commented line afterwards; the probe leaves nothing behind.

Three of those errors are in `lib.rs` itself, because the crate's own top-level
error enum structurally contains replay's error types:

```rust
// crates/swarm-runtime/src/lib.rs:118,121,124
Replay(#[from] crate::replay::ReplayHarnessError),
VerificationStore(#[from] crate::replay::VerificationStoreError),
ShadowStore(#[from] crate::replay::ShadowStoreError),
```

**Replay -> root.** Three of the nine non-test files under `replay/` import five
distinct `crate::` modules plus the crate root:

```
replay/types.rs:5-7        crate::config, crate::correlation, crate::service
replay/harness.rs:32-42    crate::config, crate::correlation,
                           crate::detector_factory, crate::investigation,
                           crate::service, crate::{RuntimeMode, SwarmRuntime}
replay/verification.rs:8   crate::detector_factory::RuntimeDetector
```

A fourth file, `replay/detect_stall.rs:23`, imports `crate::detector_factory`
as well, but its module declaration is `#[cfg(test)]` (`replay/mod.rs:25-26`),
so it is test-only and carries no weight in this argument. It is excluded above,
and from the file count, for that reason.

This is not path convenience. `replay/harness.rs:853-862` builds the composition
root to run a replay against it:

```rust
    ) -> Result<RuntimeService<ConfigurableApprovalGate, SandboxExecutor>, ReplayHarnessError> {
        let mut offline_config = self.config.clone();
        offline_config.runtime.mode = RuntimeMode::DetectOnly;
        offline_config.runtime.require_durable_live_response = false;
        let runtime = SwarmRuntime::new(
            RuntimeMode::DetectOnly,
            ConfigurableApprovalGate::from_config(&offline_config.policy),
            SandboxExecutor,
        );
        Ok(RuntimeService::new(offline_config, runtime).with_configured_sequence_detector()?)
```

(`sed -n '853,862p' crates/swarm-runtime/src/replay/harness.rs`, verbatim.)

`service/` stays in `swarm-runtime` — that is ADR-adjacent settled ground from
SPLIT-01 (a43df1c), and it is settled *because* replay imports it.

**Cargo's verdict.** The cycle lives in the package graph, so it is rejected
before compilation begins. This is **not** observable at HEAD: no
`swarm-runtime-replay` exists, and `cargo metadata --format-version 1` exits 0
with an empty stderr. Reproducing it takes a transient probe -- create a skeleton
`crates/swarm-runtime-replay` whose only dependency is `swarm-runtime`, add it to
`members` and `[workspace.dependencies]`, then give `swarm-runtime` the
`swarm-runtime-replay` edge its 20 consumers would require:

```
$ cargo metadata --format-version 1
rc=101
error: cyclic package dependency: package `swarm-runtime v0.1.0 (/…/crates/swarm-runtime)` depends on itself. Cycle:
package `swarm-runtime v0.1.0 (/…/crates/swarm-runtime)`
    ... which satisfies path dependency `swarm-runtime` (locked to 0.1.0) of package `swarm-runtime-replay v0.1.0 (/…/crates/swarm-runtime-replay)`
    ... which satisfies path dependency `swarm-runtime-replay` (locked to 0.1.0) of package `swarm-runtime v0.1.0 (/…/crates/swarm-runtime)`
    ... which satisfies path dependency `swarm-runtime` (locked to 0.1.0) of package `swarm-cli v0.1.0 (/…/crates/swarm-cli)`
```

(Verbatim except that the absolute checkout prefix is elided to `/…/`.) The probe
is not committed; revert `Cargo.toml`, `Cargo.lock`, `crates/swarm-runtime/Cargo.toml`
and delete the skeleton directory afterwards.

### No sub-boundary rescues it

The obvious retreat — extract only replay's leaf types and leave the harness
behind — does not exist. `replay/types.rs` is both the file that defines what
the 20 consumers import and a file that reaches back into the root:

```
types.rs:22   pub enum ReplayHarnessError          types.rs:5  use crate::config::{...}
types.rs:630  pub struct ExperimentLineage         types.rs:6  use crate::correlation::CorrelationError
types.rs:684  pub enum DetectorCandidateManifest   types.rs:7  use crate::service::{RuntimeMetricsSnapshot, ServiceError}
types.rs:772  pub struct DetectorExperimentManifest
```

`stores.rs`, which defines the other two error types `lib.rs` embeds, opens with
`use super::types::{...}` and is therefore downstream of `types.rs`, not a leaf
beside it. There is no subset of `replay/` that is simultaneously what the root
needs and free of what the root provides.

## Decision

**The replay half of SPLIT-02 is not attempted in phase 282, and SPLIT-02 stays
open.**

- `swarm-runtime-workbench` **is** extracted, and that half is complete and green.
- `swarm-runtime-replay` is **not** created. An empty or partial crate is not
  left in the tree as a placeholder.
- SPLIT-02's checkbox stays unchecked; it names two crates and one exists.
- The requirement text is **not** amended. Its account of the cycle is
  incomplete rather than wrong, and correcting requirement scope belongs to the
  phase owner, not the implementer.

### Escalation: this is a scope decision, not an implementation defect

The gap between "SPLIT-02 names two crates" and "one crate exists" cannot be
closed from inside phase 282. Both available closures are barred:

- **Force the extraction.** Requires the trait inversion described under
  Alternatives -- new trait definitions and changed signatures. Phase 282 is pure
  code motion; a design change is out of contract.
- **Land a placeholder `swarm-runtime-replay`.** An empty or partial crate that
  ticks a checkbox while `replay/` stays in the root is worse than the honest
  gap, because it makes the boundary look enforced when it is not.

So the requirement stays open and this ADR is the escalation. **The phase owner
must decide** between:

1. Splitting SPLIT-02 so the delivered workbench half can close, and re-scoping
   the replay half into its own requirement whose text budgets for the trait
   inversion on `replay/harness.rs`'s `SwarmRuntime` dependency; or
2. Leaving SPLIT-02 whole and open, and accepting that it blocks SPLIT-06's
   under-25,000-LOC target for `swarm-runtime` by the 8,142 lines of replay
   machinery that do not move.

Until one of those happens, SPLIT-02 must not be reported as delivered, and no
phase-282 artifact does so.

## Alternatives Considered

**Move the 20 consumers out with replay.** They are `ingest/`, `evolution/`,
`mutation/`, `canary`, `drafting`, `evidence`, `promotion`, `portfolio`,
`selection`, `strategy`, `governance_prep`, `kitten_agent`, `red_swarm`,
`detector_factory`, `evasion_coverage` — substantially the whole evolution lane
plus the detector factory. That is not extracting replay; it is relocating
`swarm-runtime` and leaving the name behind.

**Invert the return edge with a trait**, the way SPLIT-03 did for the policy
dispatcher (36b2f67, f8d3cc6, b708d3b). This is the real answer and it is
tractable: `replay/harness.rs` needs "something that executes an event", not
`SwarmRuntime` specifically. It is also a design change with new trait
definitions and changed signatures, which is exactly what this phase's code
motion is forbidden to contain, and it is large enough to deserve its own
requirement rather than riding inside SPLIT-02's diff.

**Rejected outright:** moving `replay/` out and having `swarm-runtime` reach its
own error variants back through a `swarm-runtime-replay` re-export. Cargo
rejects the manifest edge regardless of how the paths are spelled; the cycle is
in the package graph, not the module graph.

## Consequences

### Positive

- `workbench/` and `review_workbench.rs` are out of the composition root, and
  `swarm-runtime-http` reaches them across a crate line through a `pub(crate)`
  re-export rather than through widened internals.
- The blocker is now a measured number (36 errors, 20 production files) instead
  of an implementer's impression, and the trait inversion that would clear it
  has a named precedent in SPLIT-03.

### Negative

- `swarm-runtime` keeps 8,142 lines of replay machinery (`wc -l
  crates/swarm-runtime/src/replay/*.rs`; 4,857 of them outside the two
  `#[cfg(test)]` files), so the composition root is larger than SPLIT-02
  intended.
- Phase 282 cannot report SPLIT-02 as delivered.
- The requirement's stated premise — that relocating `OperatorSurfacePaths` is
  what unblocks *both* extractions — reads as sufficient and is not. Anyone
  planning from the text alone will budget for one cycle and meet two.

## Verification

```sh
# Return edge: replay's non-test dependence on the composition root.
# Requirement remains blocked while this prints lines. detect_stall.rs is
# deliberately absent -- it is #[cfg(test)] at replay/mod.rs:25-26.
grep -n "use crate::" crates/swarm-runtime/src/replay/{types,harness,verification}.rs

# Forward edge: production consumers inside the root. 20 on 2026-08-12; 15 at
# cc5b169, and the drop is five consumers LEAVING THE CRATE (SPLIT-04, SPLIT-05),
# not the cycle being addressed. See Status.
grep -rl "crate::replay" --include="*.rs" crates/swarm-runtime/src/ \
  | grep -v "/src/replay/" | grep -vE "test" | wc -l

# Cycle 1 (the one SPLIT-02 predicted) stays fixed. The identifier-form pattern
# expects NO output and rc=1 -- the workbench has no code edge to the HTTP crate.
grep -rn "swarm_runtime_http\|crate::http" crates/swarm-runtime-workbench/src/ --include='*.rs'

# Widened to the hyphenated spelling, for the prose audit: expects exactly one
# hit, the doc comment at lib.rs:27 (lib.rs:24 when this ADR was written).
grep -rn "swarm.runtime.http" crates/swarm-runtime-workbench/src/ --include='*.rs'
```
