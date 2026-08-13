# ADR 0006: SPLIT-05 Extracts `ingest/` Whole, At The Price Of Three Widenings, And Unpins The Four Agents

## Status

Accepted on 2026-08-12. Amended on 2026-08-13 after review, on two points, both
of them disclosure rather than substance: the `[dev-dependencies]` reverse edge
is now measured instead of estimated, and the no-widening invariant this ADR
breaks is escalated below as **OPEN, pending phase-owner sign-off** rather than
being treated as settled by the reviewer who checked the justifications.

## Context

SPLIT-05 (phase 282) asked for one extraction: `swarm-ingest-runtime`, holding
`ingest/` and `bridge_runtime.rs` in `crates/swarm-runtime/src/`. ADR 0004 named
it the keystone of the phase -- `ingest/` is what pinned four of the eight agent
roles in the composition root, and ADR 0002 holds SPLIT-01 open over the `axum`
edge that `ingest/` carried.

It delivered in full, and then some: the extraction had to take two more files
with it.

### The move set is four modules, not two, and Cargo chose the extra two

The brief named `ingest/` and `bridge_runtime.rs`. `control.rs` and
`anti_tamper.rs` came too, because they name `ingest/` from non-test code and
`ingest/` names them back:

```
$ git show fbe195d:crates/swarm-runtime/src/control.rs | sed -n '8,11p'
use crate::ingest::{
    FirstRunWizardError, FirstRunWizardReport, FirstRunWizardRequest, IngestBuildError,
    IngestState, run_first_run_wizard,
};
$ git show fbe195d:crates/swarm-runtime/src/anti_tamper.rs | sed -n 1p
use crate::ingest::IngestState;
```

Those are the only two back-edges in the crate. Nothing else in
`crates/swarm-runtime/src/` named `ingest/` at all, which is what made the
extraction possible; the check is mechanical and holds today:

```
$ grep -rn --include='*.rs' 'crate::ingest\|crate::control\|crate::anti_tamper\|crate::bridge_runtime' \
    crates/swarm-runtime/src/
(no output)
```

`ingest`, `control` and `anti_tamper` are therefore one strongly connected
component. Moving any one of them alone leaves another naming
`swarm_ingest_runtime::` from inside `swarm-runtime`, which Cargo rejects before
compilation:

```
error: cyclic package dependency: package `swarm-ingest-runtime` depends on itself.
```

`bridge_runtime.rs` is not in the component -- it names nothing in the move set
-- but it could not go first either, because four `ingest/` files named it. The
general rule, which is the reusable part of this ADR: **a module may leave the
root only once every module that names it has already left, or leaves with it.**
That rule fixed the commit order (bin, then the SCC, then `bridge_runtime`), and
it is what the previous attempt at this extraction did not apply.

### The `[[bin]]` that had to move first

`src/bin/generate_platform_openapi.rs` read `control`'s two schema-version
constants. Every other `swarm_runtime::control` consumer inside `swarm-runtime`
is a test, an example or a bench, and those targets reach this crate through the
`[dev-dependencies]` edge. A `[[bin]]` cannot: bins link `[dependencies]` only.
So the bin moved one commit ahead of `control.rs`, reading it across the forward
edge in the interval. Its two callers in `tools/` were repointed, and the spec it
emits is unchanged byte for byte.

## Decision

Extract `swarm-ingest-runtime` with `ingest/` (7 files), `control.rs`,
`anti_tamper.rs`, `bridge_runtime.rs` and the OpenAPI generator bin. Accept three
widenings on `swarm-runtime` as the price, and record them here rather than
burying them.

The edge direction is `swarm-ingest-runtime -> swarm-runtime`, enforced by Cargo:

```
$ cargo tree -p swarm-runtime -e normal --prefix none | grep -c swarm-ingest-runtime
0
```

### `swarm-runtime` does depend on `swarm-ingest-runtime`, as a dev-dependency

That reverse entry is real and it is stated here rather than left to be found.
Cargo permits a dev cycle where it rejects a normal one, so the forward-edge rule
holds for everything that ships and is broken for nothing at all only in the
sense that test targets are not part of the library graph:

```
$ cargo metadata --format-version 1 | (extract dependency kinds)
swarm-ingest-runtime  -> swarm-runtime         kind=normal
swarm-runtime         -> swarm-ingest-runtime  kind=dev

$ cargo tree -p swarm-runtime -e normal --prefix none | grep -c swarm-ingest-runtime
0
$ cargo tree -p swarm-runtime -e dev --prefix none | grep -c swarm-ingest-runtime
1
```

It follows the precedent `swarm-agents` set on this branch, which carries the
same shape for the same reason and predates this phase (`swarm-runtime ->
swarm-agents kind=dev`, present at `b86576d`). This is now the second one.

Thirteen dev targets need it -- twelve integration tests and one example. No
bench does; the earlier draft of this ADR said "one bench" and that was wrong:

```
$ for d in tests examples benches; do
    printf '%s %s\n' "$(grep -rl swarm_ingest_runtime crates/swarm-runtime/$d | wc -l)" "$d"; done
12 tests
1 examples
0 benches
```

Ten of the thirteen reach for a single free function and never touch the router:

```
$ grep -rho 'use swarm_ingest_runtime::.*' crates/swarm-runtime/{tests,examples} | sort | uniq -c
  10 use swarm_ingest_runtime::control::build_composite_detector;
   3 use swarm_ingest_runtime::ingest::IngestState;
   2 use swarm_ingest_runtime::bridge_runtime::{BridgeRuntimeRegistry, bridge_health_report};
   1 use swarm_ingest_runtime::ingest::{IngestResponse, IngestState, detect_http_router};
   1 use swarm_ingest_runtime::ingest::detect_http_router;
```

The alternative is to let those thirteen files follow the code into
`swarm-ingest-runtime`, which would delete the edge outright. It is NOT taken
here, and the reason is that it would misfile ten of the thirteen: files named
`recruitment_integration.rs`, `multi_agent_pipeline_integration.rs`,
`multi_strategy_integration.rs` and so on are `swarm-runtime` integration tests
that happen to build their detector with `control::build_composite_detector`.
Moving them to assert against `swarm-runtime` from inside `swarm-ingest-runtime`
trades a dev edge Cargo sanctions for a test suite filed under the wrong crate,
and a partial move -- taking only the three that drive the router or the bridge
registry -- leaves the edge in place and buys nothing. Both lanes are serial, so
either move is gate-neutral: the sum stays 1126 and no name changes.

This is recorded as a decision to revisit, not as an invariant. The edge is the
right shape to delete when `build_composite_detector` finds a home that is not
`control.rs`, which is a refactor and not this phase's business.

### Three items were widened. This is the first widening on the branch.

Until this ADR, phase 282 had converted no restricted visibility to `pub`. Three
conversions land here, all in `swarm-runtime`, all pure functions over types that
were already `pub`:

| Item | Was | Needed by | Why it cannot follow its caller |
| --- | --- | --- | --- |
| `config::kill_chain_sequence_profile` | `pub(crate)` | `control.rs:1559` | Still called at `config.rs:1037`, `service/mod.rs:39`, `service/runtime_service.rs:69` |
| `config::validate_all_detector_profiles` | `pub(crate)` | `control.rs:716` | Sole caller, but its body dispatches to 14 per-profile validators in `config.rs`, 13 of them still `pub(crate)`, and every one of the 13 has callers elsewhere in the root; moving it widens 13 items instead of 1 |
| `escalation::standard_threat_classes` | `pub(crate)` | `ingest/demo.rs`, `ingest/platform_api.rs` | Still called at `escalation.rs:110` and `:271`; duplicating the 12-variant list in the new crate creates two orderings that can silently diverge |

A fourth candidate did NOT need widening and is recorded because it is the shape
to reach for first. `dispatcher::approval_context_now` was `pub(crate)`, its only
callers were the two ingest routes, so it followed them and is now a private
`fn` in `ingest/mod.rs`. `dead_code` proved it had no other consumer. Its one
substitution is the clock: the original called `dispatcher`'s private
`unix_timestamp_millis`, and `runtime_events::now_ms` has a byte-identical body.

### The alternative to the three widenings, weighed and declined

Leave `control.rs` in the root and invert `control -> ingest` behind a trait, as
SPLIT-03's `swarm_core::agent` seal and this phase's `GovernanceAuthority`
inversion both did. Two of the three widenings are `control.rs`'s and would go
away.

It was declined because the coupling is not one method. `GovernanceAuthority`
inverted a single call, `policy.status_report()`. `control -> ingest` is:

- two variants of the public `ControlError` enum -- `IngestBuild(Box<IngestBuildError>)`
  and `FirstRunWizard(#[from] FirstRunWizardError)`;
- a public struct field, `FirstRunWizardOptions::walkthrough:
  Option<FirstRunWizardReport>`, plus `FirstRunWizardPaths` beside it;
- `IngestState::from_config(...)` followed by `run_first_run_wizard(...)` inside
  `DefaultControlPlane::first_run`;
- a free function returning `Result<SwarmConfig, FirstRunWizardError>`.

Inverting that means associated types on a trait, or relocating the wizard's
types, and it changes a public error enum. That is a refactor, and SPLIT-05 was
scoped as code motion. Doing both at once is precisely what stalled the previous
attempt.

The third widening, `standard_threat_classes`, is `ingest`'s and survives the
inversion either way.

All three are reversible in one keyword each when `config` and `escalation`
themselves leave the root, and none of them adds a type to the public surface.

### The branch's no-widening invariant is broken, and that needs sign-off

Phase 282 was briefed with an invariant stated as a command, and the command was
required to keep exiting 1. It does not:

```
$ git diff 742206d..HEAD | grep -E '^-.*(pub\(crate\)|pub\(super\)|pub\(in )'
-    pub(super) bridge_health: Option<crate::bridge_runtime::BridgeStatusReport>,
-pub(crate) fn kill_chain_sequence_profile(
-pub(crate) fn validate_all_detector_profiles(
-pub(crate) fn approval_context_now(live_mode: bool) -> ApprovalContext {
-pub(crate) fn standard_threat_classes() -> Vec<ThreatClass> {
$ echo $?
0
```

Five lines, exit 0. Three of the five are the widenings this ADR is named for.
The other two are not widenings, and are itemised so the count is not read as
five regressions:

- `pub(super) bridge_health` is a type-path edit. The field is `pub(super)` on
  both sides; only its type moved down to `swarm-core`:

  ```
  $ git diff 742206d..HEAD -M | grep -E '^[-+].*bridge_health: Option<'
  -    pub(super) bridge_health: Option<crate::bridge_runtime::BridgeStatusReport>,
  +    pub(super) bridge_health: Option<swarm_core::BridgeStatusReport>,
  ```

- `approval_context_now` is a narrowing: `pub(crate)` in `dispatcher.rs` before,
  a private `fn` in `ingest/mod.rs` now.

Nothing else was promoted. Scanning the extraction for silent private-to-`pub`
changes returns the three and two lines of doc-comment prose:

```
$ git diff b86576d..HEAD -M -- crates/swarm-runtime/src | grep -E '^\+.*\bpub\b'
+pub fn kill_chain_sequence_profile(
+pub fn validate_all_detector_profiles(
+pub fn standard_threat_classes() -> Vec<ThreatClass> {
+//! with no widening -- the nine `pub(crate)` `calico_agent` items ADR 0004
+//! costed stay `pub(crate)` once `calico` and `sphinx` are in the same crate
```

**A narrow facade is not an escape hatch here, and this is worth stating because
it is the first thing to reach for.** A re-export cannot widen the item behind
it, so the item has to be `pub` before any facade can name it:

```
$ echo 'pub use crate::config::suspicious_process_tree_profile;' >> crates/swarm-runtime/src/lib.rs
$ cargo check -p swarm-runtime --lib
error[E0364]: `suspicious_process_tree_profile` is only public within the crate,
              and cannot be re-exported outside
```

**What is being asked of the phase owner.** The brief said to keep the invariant
true and it is not true. Three `pub` items on a crate are public API until
something takes them away, and a reviewer agreeing that each one is individually
unavoidable is not the same act as granting the exception. This ADR records the
break rather than absorbing it. The two live options:

1. **Accept, and restate the invariant.** SPLIT-05 stands as committed. The rule
   for the rest of phase 282 becomes "no widening beyond the three named here",
   checked by the same command against a known baseline of five hits. Each of
   the three is deleted by one keyword when `config` and `escalation` leave the
   root, which the remaining SPLITs already intend.
2. **Reverse the shape.** `control.rs` stays in the composition root and
   `control -> ingest` is inverted behind a trait, which removes two of the
   three. That is the option costed above and declined: it changes two public
   `ControlError` variants and a public struct field, so it is a refactor, and
   refactor-plus-extraction in one task is precisely what stalled the previous
   attempt at SPLIT-05. `escalation::standard_threat_classes` is `ingest`'s and
   survives the inversion either way, so option 2 buys two of three, not three.

### The serial test lane had to follow `ingest::tests`

`ingest/tests.rs` is `#[cfg(test)] mod tests` inside `ingest/mod.rs`, so its 115
unit tests moved with the module and could not be left behind. CI ran
`swarm-runtime` serially for one stated reason, quoted from the workflow before
this phase touched it:

```
# swarm-runtime's `ingest::tests` module mutates shared `SWARM_*_TEST_TOKEN`
# environment variables across its platform_api tests; the env race is
# cargo-test-thread-scoped, so this single crate runs serially.
```

The module that comment is about is now in `swarm-ingest-runtime`, so the serial
step names both crates. This is not a relaxation: it restores the execution
semantics those 115 tests had at every prior commit.

The lane change ships **in the same commit as the move**, not as a follow-up.
Those 115 tests are `#[cfg(test)] mod tests` inside `ingest/mod.rs` and are not a
separable target, so a commit that moves the module while the lane definition
still names `swarm-runtime` puts them in the parallel step and is red under its
own gate; a commit that changes the lane first describes a tree that does not
exist yet. Either ordering leaves a bad bisect point, so the two are one atom.
Left in the parallel step they fail about three runs in five:

```
$ for i in 1 2 3 4 5; do cargo test -p swarm-ingest-runtime --lib; done
test result: FAILED. 113 passed; 2 failed
test result: ok.     115 passed; 0 failed
test result: FAILED. 114 passed; 1 failed
test result: ok.     115 passed; 0 failed
test result: FAILED. 114 passed; 1 failed

$ for i in 1 2 3 4 5; do cargo test -p swarm-ingest-runtime --lib -- --test-threads=1; done
test result: ok. 115 passed; 0 failed   (five times)
```

The underlying defect is a test-isolation one and is NOT fixed here:
`enable_platform_api` sets `SWARM_PLATFORM_API_TEST_TOKEN` for every
platform_api test while
`platform_api_routes_reload_rotated_bearer_token_without_restart` overwrites it
mid-test. The fix is a lock scoped to those tests, or per-test variable names as
the file's other four `SWARM_*_TEST_TOKEN` sites already use.

## Consequences

- 17,797 lines leave the composition root, measured across the last code commit
  of the phase:

  ```
  $ for rev in b86576d 163282b; do for c in swarm-runtime swarm-ingest-runtime; do
      git ls-tree -r --name-only $rev crates/$c/src | grep '\.rs$' \
        | while read f; do git show $rev:"$f"; done | wc -l; done; done
  97264   # swarm-runtime/src before
     78   # swarm-ingest-runtime/src before (crate doc only)
  79467   # swarm-runtime/src after
  17905   # swarm-ingest-runtime/src after
  ```

  The 108 lines the new crate gained beyond the move are its crate doc and the
  relocated `approval_context_now`.
- **ADR 0004's blocker is discharged.** `calico`, `kitten`, `sphinx` and `tom`
  are no longer pinned. The one non-test back-edge ADR 0004 named is now a
  forward edge from another crate, and the four are a closed group that nothing
  else in the root reads from non-test code:

  ```
  $ grep -rn --include='*.rs' 'crate::\(calico\|kitten\|sphinx\|tom\)_agent' \
      crates/swarm-runtime/src/ | grep -v '_agent.rs:' | grep -v '//!'
  crates/swarm-runtime/src/dispatcher.rs:1400: use crate::tom_agent::{...};
  ```

  and that hit is inside the `#[cfg(test)] mod tests` opening at
  `dispatcher.rs:1390`. All four can move to `swarm-agents` in one commit, and
  the nine `pub(crate)` `calico_agent` items ADR 0004 costed stay `pub(crate)`,
  because `calico` and `sphinx` land in the same crate. `ls
  crates/swarm-runtime/src/*_agent.rs | wc -l` still prints 4; it is now a
  matter of doing the move rather than of unblocking it.
- **ADR 0002's blocker is discharged, and SPLIT-01 is not yet closed.** No
  non-test code in `swarm-runtime` names `axum`. Deleting the manifest line and
  running `cargo check -p swarm-runtime --lib` yields 0 errors, down from 52
  before this phase; `--all-targets` still fails, in `tests/`, `examples/` and
  two `#[cfg(test)]` modules, which is what makes the line a dev-dependency
  rather than a normal one. The line is deliberately left in `[dependencies]`:
  moving it is a manifest change to be made and proved on a tree where nothing
  else is moving, and deleting it as a side effect of a file move is the version
  that cannot be checked.
- SPLIT-04 does not unblock. ADR 0005 already said the crate root alone pins the
  seven evolution modules, and the root outlives every extraction in the phase.
  Its progress measure drops from 58 to 38 only because 20 of the hits were
  `ingest/`'s and left the crate.
- `swarm-cli`, `swarm-evolution` and `swarm-runtime-http` gain a normal
  `swarm-ingest-runtime` dependency. All three sit above it, so nothing closes.
  `swarm-runtime` cannot re-export `control` at its old path: a re-export needs a
  normal dependency, and that is the cycle. Consumers were repointed instead,
  following the precedent set by the rate-limiter move.
- `swarm-runtime-http/src/lib.rs` held `control` inside a braced
  `pub(crate) use swarm_runtime::{...}` group -- the exact shape ADR 0004 flagged
  as the way a name silently stops resolving. `cargo check --workspace` stayed
  green; `--all-targets` failed. That remains the check that matters during a
  large move.

### Test accounting

The gate is unchanged across all four commits of the extraction. Sum of passed
tests is 1126 at every step, and the sorted union of test names is byte-identical
to the pre-SPLIT-05 baseline.

| Step | G1 passed | G2 passed | Sum | Registered names |
| --- | --- | --- | --- | --- |
| baseline (b86576d) | 558 | 568 | 1126 | 1152 |
| + openapi bin (fbe195d) | 558 | 568 | 1126 | 1152 |
| + ingest, control, anti_tamper, and the serial lane (d5ae8bd) | 558 | 568 | 1126 | 1152 |
| + bridge_runtime (163282b) | 558 | 568 | 1126 | 1152 |

The split never leaves 558/568, and that is the point: no test changed the lane
it runs in, only the crate it lives in. The one way to make those numbers move is
to let the lane definition lag the code, which is the bisect point the
serial-lane section above explains away by keeping the lane change inside the
move commit. Registered names exceed passed by the 26 pre-existing `ignored`
tests.
