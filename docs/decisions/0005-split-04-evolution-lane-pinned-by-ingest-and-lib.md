# ADR 0005: SPLIT-04 Extracts Three Of Ten Evolution Modules Plus One The Brief Did Not Name; The Other Seven Are Pinned By `lib.rs`, `ingest/`, `kitten_agent`, `sphinx_agent` And `evolution_status`

## Status

Accepted on 2026-08-12.

## Context

SPLIT-04 (phase 282) asked for one extraction: give `crates/swarm-evolution` --
an 8-line facade over `swarm_runtime` -- real source, by moving the evolution
lane back out of the composition root. The named set was `evolution/`,
`mutation/`, and the top-level `evolution.rs`, `mutation.rs`, `drafting.rs`,
`promotion.rs`, `canary.rs`, `portfolio.rs`, `selection.rs`, `strategy.rs`,
`governance_prep.rs`, `evidence.rs`. That is 36,700 lines, measured at the
pre-split commit:

```
$ { for f in evolution.rs mutation.rs drafting.rs promotion.rs canary.rs \
             portfolio.rs selection.rs strategy.rs governance_prep.rs evidence.rs; do \
      git show be497d7:crates/swarm-runtime/src/$f; done; \
    for f in $(git ls-tree -r --name-only be497d7 \
                 -- crates/swarm-runtime/src/evolution crates/swarm-runtime/src/mutation); do \
      git show be497d7:$f; done; } | wc -l
   36700
```

Three of the named modules moved -- `evidence` (2,388), `governance_prep`
(1,728), `portfolio` (1,960) -- plus `operator_maintenance` (944), which the
brief did not name. Seven did not move: `canary`, `drafting`, `evolution`,
`mutation`, `promotion`, `selection`, `strategy`. This ADR records why those
seven cannot move as code motion, why a module outside the brief had to move,
and what the extraction did and did not buy for SPLIT-05.

### The crate edge can only run one way, and replay decides which way

`swarm-evolution` already depended on `swarm-runtime`, and it has to keep doing
so. The lane's largest outward coupling is the replay harness, which the brief
pins in the composition root for this part -- of the 52 non-test `crate::replay`
references in the crate before the split, 36 were in the named set. So the edge
stays `swarm-evolution -> swarm-runtime`.

That direction has a price, and it is the whole of this ADR: **nothing left in
`swarm-runtime` may name a module that moves.** Adding the reverse edge is not
a style question; it is rejected by Cargo before a single file is compiled:

```
$ # with `swarm-evolution.workspace = true` added to crates/swarm-runtime/Cargo.toml
$ cargo check -p swarm-runtime
error: cyclic package dependency: package `swarm-runtime v0.1.0 (crates/swarm-runtime)` depends on itself. Cycle:
package `swarm-runtime v0.1.0 (crates/swarm-runtime)`
    ... which satisfies path dependency `swarm-runtime` of package `swarm-evolution v0.1.0 (crates/swarm-evolution)`
    ... which satisfies path dependency `swarm-evolution` of package `swarm-runtime v0.1.0 (crates/swarm-runtime)`
```

### Six files in the remainder name the lane in non-test code

The seven modules that stayed are named from five modules of the remainder plus
the crate root:

```
$ cd crates/swarm-runtime/src
$ grep -rcE 'crate::(canary|drafting|evolution|mutation|promotion|selection|strategy)::' \
       --include='*.rs' . | grep -v ':0$' | sort -t: -k2 -rn
...
evolution_status.rs:18
kitten_agent.rs:12
ingest/mod.rs:12
ingest/tests.rs:8
lib.rs:7
sphinx_agent.rs:1
```

(The other hits are the lane naming itself, which is not a constraint.) All but
`ingest/tests.rs` are production code -- top-of-file imports and `#[from]`
variants, not test scaffolding.

Each of the six is pinned in the composition root by a decision that is already
recorded, so none can simply ride along:

- **`lib.rs:125-152`** -- `StrategyProposalRouteError` wraps
  `drafting::EvolutionDraftingError`, `mutation::EvolutionMutationError`,
  `selection::EvolutionSelectionError`, `evolution::FormalSafetyGateError`,
  `evolution::EvolutionQueueError`, `evolution::EvolutionProposalStoreError`
  and `canary::CanaryError` by `#[from]`. It is the crate root; it cannot move,
  and `ingest/mod.rs:62` names it (`use crate::{RuntimeError,
  StrategyProposalRouteError, SwarmRuntime}`), so it cannot be hollowed out
  either.
- **`ingest/`** -- SPLIT-05's file set, per ADR 0002. It is also what keeps
  `axum` in this manifest.
- **`kitten_agent.rs`, `sphinx_agent.rs`** -- two of the four agent roles ADR
  0004 pins in the root until `ingest/` leaves.
- **`evolution_status.rs`** -- reachable from `control.rs:7`, `service/`,
  `runtime_events.rs:4`, `ingest/mod.rs:42` and `kitten_agent.rs:8`. `service/`
  is documented as staying in the remainder; `control` and `runtime_events` are
  in no extraction's file set.

Closing the seven under "everything that names them must move too" therefore
does not terminate at a boundary any part of phase 282 owns. It reaches
`lib.rs`, `ingest/`, `control`, `service`, `replay` and 25 further modules --
30 of the crate's 40 modules plus the crate root -- which is not an extraction,
it is a rewrite.

### Four modules are closed under that rule, and one of them was not in the brief

Exactly one non-empty subset of the crate satisfies "no module outside it names
a module inside it", and it is these four:

| module | named from, before the split |
| --- | --- |
| `evidence` | `operator_maintenance` only |
| `governance_prep` | `operator_maintenance` only |
| `portfolio` | `governance_prep`, `operator_maintenance` only |
| `operator_maintenance` | `evidence` only |

`operator_maintenance.rs` is **not** in SPLIT-04's named file set. It moved
anyway, because `evidence` and `operator_maintenance` are a two-module cycle --
`be497d7:evidence.rs:8` imports `crate::operator_maintenance`,
`be497d7:operator_maintenance.rs:1` imports `crate::evidence` -- so leaving it
behind would have put the Cargo cycle above into the manifest. Leaving `evidence`
behind instead would have left the movable set empty: `governance_prep` and
`portfolio` are both named from `operator_maintenance`.

It is a fair addition on ownership grounds as well as mechanical ones. The
module is the operator-facing maintenance lane over evidence bundles,
governance packets and portfolio decisions; it names those three and nothing
else, which is why it crossed the crate line with **zero edits** -- all three of
its `crate::` imports were still `crate::` imports on the far side:

```
$ git diff --stat -M be497d7..HEAD -- crates/swarm-runtime/src/operator_maintenance.rs \
                                      crates/swarm-evolution/src/operator_maintenance.rs
 crates/{swarm-runtime => swarm-evolution}/src/operator_maintenance.rs | 0
 1 file changed, 0 insertions(+), 0 deletions(-)
```

## Decision

SPLIT-04 lands the four-module subset and stays open.

- `swarm-evolution` gains real source: `evidence.rs`, `governance_prep.rs`,
  `operator_maintenance.rs`, `portfolio.rs`. That is 6,076 of the brief's
  36,700 named lines (17%), plus 944 lines the brief did not name, for 7,020
  moved in total.
- The crate keeps re-exporting the seven modules that stayed
  (`swarm_evolution::canary` and friends still resolve), so the facade's
  existing surface is unchanged for consumers.
- **No item gained visibility.** The moved code compiles against
  `swarm-runtime`'s existing `pub` surface exactly as it stood; no `pub(crate)`
  became `pub`, in either crate, and no new `pub` item was introduced. This
  matters more here than elsewhere in the phase -- `portfolio` and
  `governance_prep` are the governance-review lane, and `promotion` reads out of
  both -- so it is stated as a checkable command rather than a claim:

```
$ git diff be497d7..HEAD | grep -E '^[+-].*\bpub(\(crate\))?\b' | grep -vE '^[+-] *(//|///|//!)'
+pub(crate) use swarm_evolution::{evidence, governance_prep, operator_maintenance, portfolio};
+pub mod evidence;
+pub mod governance_prep;
+pub mod operator_maintenance;
+pub mod portfolio;
+    pub use swarm_evolution::evidence::*;
+    pub use swarm_evolution::governance_prep::*;
+    pub use swarm_evolution::operator_maintenance::*;
+    pub use swarm_evolution::portfolio::*;
-pub mod evidence;
-pub mod governance_prep;
-pub mod operator_maintenance;
-pub mod portfolio;
-    pub use swarm_runtime::evidence::*;
-    pub use swarm_runtime::governance_prep::*;
-    pub use swarm_runtime::operator_maintenance::*;
-    pub use swarm_runtime::portfolio::*;
```

  Every line is the same four modules changing address: four `pub mod`
  declarations moving `lib.rs`, four `swarm-cli` facade re-exports and one
  `swarm-runtime-http` alias following them. Nothing else in the workspace
  changed visibility.

- SPLIT-04 is **not satisfied** while the other seven modules are in
  `swarm-runtime`. Its checkbox stays unchecked. It is unblocked by the same
  event as SPLIT-01: `ingest/` leaving, which also releases `kitten_agent`,
  `sphinx_agent` and (through `control` and `service`) `evolution_status`.

## Consequences

### What this bought SPLIT-05, measured

The brief predicted that after SPLIT-04 the non-test `crate::replay`
back-references would "collapse to roughly four, in lib.rs and
detector_factory.rs". They did not. The measurement, using the file-level
definition of "non-test" that reproduces the brief's own starting number of 52:

```
$ for rev in be497d7 HEAD; do
    total=0; testn=0
    for f in $(git ls-tree -r --name-only $rev -- crates/swarm-runtime/src | grep '\.rs$'); do
      n=$(git show $rev:$f | grep -cE 'crate::replay\b'); [ "$n" -eq 0 ] && continue
      total=$((total+n))
      case "$(basename $f)" in tests.rs|tests_*.rs|test_support.rs) testn=$((testn+n));; esac
    done
    echo "$rev: TOTAL=$total IN_TEST_FILES=$testn NON_TEST=$((total-testn))"
  done
be497d7: TOTAL=87 IN_TEST_FILES=35 NON_TEST=52
HEAD:    TOTAL=80 IN_TEST_FILES=35 NON_TEST=45
```

52 to 45. The seven that left are `portfolio`'s 3, `governance_prep`'s 2 and
`evidence`'s 2.

Four was not reachable by any version of SPLIT-04, because it counts modules
SPLIT-04 does not own. Moving all seven remaining named modules as well would
remove 29 more and leave 16, not 4:

```
       3  ./lib.rs                   1  ./detector_factory.rs
       4  ./ingest/mod.rs            1  ./ingest/demo.rs
       3  ./kitten_agent.rs          1  ./evolution_status.rs
       1  ./red_swarm.rs             1  ./evasion_coverage.rs
       1  ./replay/mod.rs
```

Only 4 of those 16 are the `lib.rs` and `detector_factory.rs` sites the brief
names. The other 12 are `ingest/` (5), `kitten_agent` (3), `evolution_status`,
`evasion_coverage`, `red_swarm`, and replay's own module doc. **Replay is
therefore not unblocked by finishing SPLIT-04; it is unblocked by SPLIT-05.**
Whoever takes replay next should treat `ingest/` as the precondition, not the
evolution lane. This is a correction to the ordering argument in
`docs/decisions/0003-split-02-replay-blocked-by-composition-root-cycle.md`, not
a contradiction of it: SPLIT-04 was necessary, it was simply not sufficient.

### The seven modules that stayed still cost every consumer

Anything linking `swarm-runtime` still compiles `canary`, `drafting`,
`evolution/`, `mutation/`, `promotion`, `selection` and `strategy` -- 30,624
lines of offline evolution workflow -- whether or not it ever drafts a
detector. That is the cost SPLIT-04 existed to remove, and 83% of it is still
there.

### The new crate edges

`swarm-runtime-workbench`, `swarm-runtime-http` and `swarm-cli` each gained a
`swarm-evolution` dependency and now reach the four modules as
`swarm_evolution::<module>`. `swarm-runtime-http`'s `pub(crate) use` aliases --
the ones that make `swarm-cli`'s shared `core.inc` resolve `crate::evidence`
and `crate::portfolio` -- were split across the two crates the same way SPLIT-02
split `review_workbench`. No consumer's public API changed.
