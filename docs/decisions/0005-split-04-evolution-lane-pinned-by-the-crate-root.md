# ADR 0005: SPLIT-04 Extracts Three Of The Ten Evolution Modules It Named Plus One It Did Not; The Other Seven Are Pinned By The Crate Root Alone, Which No Extraction Ordering Releases

## Status

Accepted on 2026-08-12. Revised on 2026-08-12 in response to review, and again
on 2026-08-13; see [Revision history](#revision-history) for what changed and
why. The first revision strengthens the pin and withdraws one false uniqueness
claim; the second repoints a verification command that had stopped running.
Neither changes what shipped.

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

### The crate root alone pins all seven, in three steps

Six files in the remainder name the seven -- five of them in production code,
the sixth being `ingest/tests.rs` -- and an earlier draft of this ADR argued the
pin from all six at once. That argument was true but weaker than the facts.
**`lib.rs` on its own is sufficient.** It is the crate
root: it is not in any extraction's file set, it cannot be moved by definition,
and it closes over all seven modules without help from `ingest/`, the agents or
`evolution_status`.

Step 1 -- the root names five of the seven directly, by `#[from]` on
`StrategyProposalRouteError`:

```
$ cd crates/swarm-runtime/src
$ grep -nE 'crate::(canary|drafting|evolution|mutation|selection)::' lib.rs
160:    Drafting(#[from] crate::drafting::EvolutionDraftingError),
163:    Mutation(#[from] crate::mutation::EvolutionMutationError),
166:    Selection(#[from] crate::selection::EvolutionSelectionError),
169:    FormalSafety(#[from] crate::evolution::FormalSafetyGateError),
172:    Queue(#[from] crate::evolution::EvolutionQueueError),
175:    ProposalStore(#[from] crate::evolution::EvolutionProposalStoreError),
187:    Canary(#[from] crate::canary::CanaryError),
```

Step 2 -- `strategy` is named by four of the five just pinned, so it is pinned
too:

```
$ grep -rcE 'crate::strategy::' --include='*.rs' . | grep -v ':0$' | grep -vE '^\./strategy\.rs:' | sort -t: -k2 -rn
drafting.rs:6
selection.rs:5
kitten_agent.rs:3
sphinx_agent.rs:1
mutation/test_support.rs:1
mutation.rs:1
ingest/tests.rs:1
evolution/tests.rs:1
evolution.rs:1
```

Step 3 -- `promotion` is named by exactly one file in the whole crate, and that
file is `strategy.rs`, pinned in step 2:

```
$ grep -rcE 'crate::promotion::' --include='*.rs' . | grep -v ':0$'
strategy.rs:3
```

`canary, drafting, evolution, mutation, selection -> strategy -> promotion`
closes on the crate root and stops. `kitten_agent`, `sphinx_agent`, `ingest/`
and `evolution_status` appear in step 2's output and are pinned by ADR 0004 and
ADR 0002 respectively, but they are **corroborating, not load-bearing**: delete
every one of them from the crate and the three steps above still run to the same
conclusion.

### The root's enum is itself pinned, which is why no ordering fixes this

The natural response is to move `StrategyProposalRouteError` out of the root so
the `#[from]` variants go with it. That is blocked one level down, by a file no
extraction owns. Outside `lib.rs` (the definition) and `ingest/` (SPLIT-05's, and
the only caller), exactly one file names the type -- and `dispatcher.rs`'s own
`mod tests` opens at line 1401, so only the first two hits below are production
code:

```
$ grep -n 'StrategyProposalRouteError' crates/swarm-runtime/src/dispatcher.rs
4:    RuntimeError, StrategyProposalRouteError, agent_tick_error_boundary, agent_tick_panic_error,
167:    ) -> Result<StrategyProposalRouteReport, StrategyProposalRouteError>;
1411:        StrategyProposalRouteError, agent_tick_error_boundary, agent_tick_error_role,
1529:            Option<Result<StrategyProposalRouteReport, StrategyProposalRouteError>>,
1538:        ) -> Result<StrategyProposalRouteReport, StrategyProposalRouteError> {
```

`dispatcher.rs:162-168` is a trait definition, not a call site:

```rust
#[async_trait]
pub trait StrategyProposalRouter: Send + Sync {
    async fn route_proposal(
        &self,
        proposal: StrategyProposalRoute,
    ) -> Result<StrategyProposalRouteReport, StrategyProposalRouteError>;
}
```

`dispatcher` is the composition root's agent-dispatch layer. It is in no
extraction's file set, and `swarm-runtime-http`'s `swarm_detect` binary consumes
it as `swarm_runtime::dispatcher::{AgentDispatcher, ...}`. So the enum cannot
follow the lane into `swarm-evolution` either -- `dispatcher` would then name
`swarm_evolution::StrategyProposalRouteError`, which is the same Cargo cycle.
Nor can the enum sink into `swarm-core`: its seven `#[from]` variants name
concrete lane error types, so `swarm-core` would have to depend on
`swarm-evolution`, which depends on `swarm-runtime`, which depends on
`swarm-core`.

This is the shape SPLIT-03 already hit and solved once, for the agent trait:
the boundary type moved to `swarm_core::agent` with its concrete variants
erased behind a sealed trait (`swarm_core::agent::sealed::SealedAgentTickError`).
The same inversion is what SPLIT-04's remaining seven need. It is a design
change to a public error boundary, not code motion, and phase 282's mandate is
code motion.

### Four modules were closed under that rule, and one of them was not in the brief

The rule "no module outside the moved set may name a module inside it" selects,
among SPLIT-04's ten named modules, exactly three -- `evidence`,
`governance_prep`, `portfolio` -- and drags in a fourth from outside the brief:

| module | named from, before the split |
| --- | --- |
| `evidence` | `operator_maintenance` only |
| `governance_prep` | `operator_maintenance` only |
| `portfolio` | `governance_prep`, `operator_maintenance` only |
| `operator_maintenance` | `evidence` only |

```
$ for m in evidence operator_maintenance governance_prep portfolio; do
    echo "--- files naming crate::$m at be497d7 ---"
    for f in $(git ls-tree -r --name-only be497d7 -- crates/swarm-runtime/src | grep '\.rs$'); do
      b=${f#crates/swarm-runtime/src/}
      case "$b" in $m.rs|$m/*) continue;; esac
      git show be497d7:$f | grep -qE "crate::$m\b" && echo "    $b"
    done
  done
--- files naming crate::evidence at be497d7 ---
    operator_maintenance.rs
--- files naming crate::operator_maintenance at be497d7 ---
    evidence.rs
--- files naming crate::governance_prep at be497d7 ---
    operator_maintenance.rs
--- files naming crate::portfolio at be497d7 ---
    governance_prep.rs
    operator_maintenance.rs
```

This set is **maximal within SPLIT-04's scope** -- the other seven named modules
all close on the crate root, per the three steps above -- and it is the whole of
what the brief's file set could give up.

It is **not** the crate's only closed set, and an earlier draft of this ADR
claimed it was. That claim was false, and the table above disproves it on its
own: nothing outside `evidence` and `operator_maintenance` names either of them,
so `{evidence, operator_maintenance}` is a strictly smaller closed set, as is
`{evidence, governance_prep, operator_maintenance}`. Several more exist outside
the evolution lane -- the `ingest`/agent family closes at
`{anti_tamper, control, evidence, ingest, operator_maintenance}` and grows from
there. Those belong to SPLIT-03 and SPLIT-05, not here. What is true, and is all
this ADR needs, is the scoped statement: **of SPLIT-04's ten named modules, the
movable closure is exactly these four, and every other one of the ten reaches
`lib.rs`.**

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
$ git diff --stat -M be497d7..0431315 -- crates/swarm-runtime/src/operator_maintenance.rs \
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
$ git diff be497d7..0431315 | grep -E '^[+-].*\bpub(\(crate\))?\b' | grep -vE '^[+-] *(//|///|//!)'
-    pub use swarm_runtime::evidence::*;
+    pub use swarm_evolution::evidence::*;
-    pub use swarm_runtime::governance_prep::*;
+    pub use swarm_evolution::governance_prep::*;
-    pub use swarm_runtime::operator_maintenance::*;
+    pub use swarm_evolution::operator_maintenance::*;
-    pub use swarm_runtime::portfolio::*;
+    pub use swarm_evolution::portfolio::*;
+pub mod evidence;
+pub mod governance_prep;
+pub mod operator_maintenance;
+pub mod portfolio;
+pub(crate) use swarm_evolution::{evidence, governance_prep, operator_maintenance, portfolio};
-pub mod evidence;
-pub mod governance_prep;
-pub mod operator_maintenance;
-pub mod portfolio;
```

  Every line is the same four modules changing address: four `pub mod`
  declarations moving `lib.rs`, four `swarm-cli` facade re-exports and one
  `swarm-runtime-http` alias following them. Nothing else in the workspace
  changed visibility.

- SPLIT-04 is **not satisfied** while the other seven modules are in
  `swarm-runtime`. Its checkbox stays unchecked.
- **SPLIT-04 is not unblocked by any later extraction.** Unlike SPLIT-01 and
  SPLIT-03, which wait on `ingest/`, this one waits on a design change:
  `StrategyProposalRouteError` must stop naming the lane's concrete error types,
  by the same sealed-boundary inversion SPLIT-03 applied to
  `swarm_core::agent::AgentTickError`. `ingest/` leaving is necessary -- it is
  one of the six namers -- and nowhere near sufficient. An earlier draft of this
  ADR said `ingest/` was the unblock event. That was wrong; the crate root
  outlives every extraction in the phase.

## Consequences

### What this bought SPLIT-05, measured

The brief predicted that after SPLIT-04 the non-test `crate::replay`
back-references would "collapse to roughly four, in lib.rs and
detector_factory.rs". They did not. The measurement, using the file-level
definition of "non-test" that reproduces the brief's own starting number of 52:

```
$ for rev in be497d7 0431315; do
    total=0; testn=0
    for f in $(git ls-tree -r --name-only $rev -- crates/swarm-runtime/src | grep '\.rs$'); do
      n=$(git show $rev:$f | grep -cE 'crate::replay\b'); [ "$n" -eq 0 ] && continue
      total=$((total+n))
      case "$(basename $f)" in tests.rs|tests_*.rs|test_support.rs) testn=$((testn+n));; esac
    done
    echo "$rev: TOTAL=$total IN_TEST_FILES=$testn NON_TEST=$((total-testn))"
  done
be497d7: TOTAL=87 IN_TEST_FILES=35 NON_TEST=52
0431315: TOTAL=80 IN_TEST_FILES=35 NON_TEST=45
```

52 to 45. The seven that left are `portfolio`'s 3, `governance_prep`'s 2 and
`evidence`'s 2.

Four was not reachable by any version of SPLIT-04, because it counts modules
SPLIT-04 does not own. Moving all seven remaining named modules as well would
remove 28 more and leave 17, not 4:

```
$ cd crates/swarm-runtime/src
$ grep -rc 'crate::replay\b' --include='*.rs' . | grep -v ':0$' \
   | grep -vE '^(canary|drafting|evolution|mutation|promotion|selection|strategy)(\.rs|/)' \
   | grep -vE '(^|/)(tests|tests_[a-z_]+|test_support)\.rs:' \
   | sort -t: -k2 -rn | awk -F: '{s+=$2; printf "%3d  %s\n",$2,$1} END {print "TOTAL="s}'
  4  lib.rs
  4  ingest/mod.rs
  3  kitten_agent.rs
  1  replay/mod.rs
  1  red_swarm.rs
  1  ingest/demo.rs
  1  evolution_status.rs
  1  evasion_coverage.rs
  1  detector_factory.rs
TOTAL=17
```

Two of the 17 are module-doc prose rather than code (`lib.rs:46` and
`replay/mod.rs`), leaving 15 real references. Only 4 of those 15 are the sites
the brief names: `lib.rs`'s three `#[from]` variants (`ReplayHarnessError`,
`VerificationStoreError`, `ShadowStoreError`) and `detector_factory.rs`. The
other 11 are `ingest/` (5), `kitten_agent` (3), `evolution_status`,
`evasion_coverage` and `red_swarm`. **Replay is therefore not unblocked by
finishing SPLIT-04; it is unblocked by SPLIT-05.**
Whoever takes replay next should treat `ingest/` as the precondition, not the
evolution lane. This is a correction to the ordering argument in
`docs/decisions/0003-split-02-replay-blocked-by-composition-root-cycle.md`, not
a contradiction of it: SPLIT-04 was necessary, it was simply not sufficient.

### The seven modules that stayed still cost every consumer

Anything linking `swarm-runtime` still compiles `canary`, `drafting`,
`evolution/`, `mutation/`, `promotion`, `selection` and `strategy` -- 30,624
lines of offline evolution workflow -- whether or not it ever drafts a
detector. That is the cost SPLIT-04 existed to remove, and 83% of it is still
there. Because the pin is the crate root and not an extraction ordering, that
83% does not shrink on its own as phase 282 proceeds; it needs the
`StrategyProposalRouteError` inversion booked as its own work.

### The new crate edges

`swarm-runtime-workbench`, `swarm-runtime-http` and `swarm-cli` each gained a
`swarm-evolution` dependency and now reach the four modules as
`swarm_evolution::<module>`. `swarm-runtime-http`'s `pub(crate) use` aliases --
the ones that make `swarm-cli`'s shared `core.inc` resolve `crate::evidence`
and `crate::portfolio` -- were split across the two crates the same way SPLIT-02
split `review_workbench`. No consumer's public API changed.

## Verification

```sh
# The pin, in one command: while this prints lines, the seven cannot move,
# whatever else has been extracted. It is the crate root naming the lane.
grep -nE 'crate::(canary|drafting|evolution|mutation|selection)::' \
  crates/swarm-runtime/src/lib.rs

# Progress measure for the seven. Summed to 58 on 2026-08-12 and has to reach 0;
# the lib.rs term is the one that no extraction can retire.
#
# REPOINTED 2026-08-13. It used to name crates/swarm-runtime/src/ingest, which
# SPLIT-05 (d5ae8bd) moved to swarm-ingest-runtime, so the command exited 2 on a
# missing path -- a progress measure that had stopped measuring. `ingest/`'s 20
# is retired rather than relocated: an extracted consumer spells the lane
# `swarm_runtime::<module>` and would re-spell it again if the seven moved, so it
# no longer pins anything. That is exactly the distinction the "no extraction can
# retire" clause draws around lib.rs. Sums to 39 at cc5b169 (7 + 12 + 1 + 19).
grep -rcE 'crate::(canary|drafting|evolution|mutation|promotion|selection|strategy)::' \
  crates/swarm-runtime/src/lib.rs crates/swarm-runtime/src/kitten_agent.rs \
  crates/swarm-runtime/src/sphinx_agent.rs crates/swarm-runtime/src/evolution_status.rs
```

## Revision history

- **2026-08-12, original.** Argued the pin from all six naming files jointly,
  titled it "pinned by ingest and lib", claimed the four-module set was the
  crate's only closed subset, and recorded `ingest/` leaving as SPLIT-04's
  unblock event.
- **2026-08-12, revised after review.** Three corrections, no change to shipped
  code:
  1. The pin is stronger than recorded. `lib.rs` alone closes over all seven in
     three steps; the `ingest/`, `kitten_agent`, `sphinx_agent` and
     `evolution_status` arguments are corroborating, not load-bearing. Retitled
     and renamed from
     `0005-split-04-evolution-lane-pinned-by-ingest-and-lib.md` accordingly.
  2. "Exactly one non-empty subset of the crate satisfies the rule" was false --
     `{evidence, operator_maintenance}` is a smaller one, and the `ingest`
     family gives more. Replaced with the scoped claim the decision actually
     rests on.
  3. The residual `crate::replay` table read 16 with 3 in `lib.rs`; it is 17
     with 4, because the same measurement counts `replay/mod.rs`'s module doc
     but skipped `lib.rs:46`'s. Rewritten as a reproducible command. The
     conclusion it supports -- replay waits on `ingest/`, not on this lane --
     is unchanged.
  4. Consequently, "SPLIT-04 is unblocked by `ingest/` leaving" was false. The
     crate root outlives every extraction in phase 282, so SPLIT-04 needs the
     `StrategyProposalRouteError` boundary inverted the way SPLIT-03 inverted
     `AgentTickError`. Recorded in the Decision section and re-pointed in the
     phase's open-task list.
- **2026-08-13, verification repointed after review.** No change to the argument
  or to shipped code. The progress-measure command named
  `crates/swarm-runtime/src/ingest`, a path SPLIT-05 deleted on the same branch,
  so it exited 2 instead of measuring. The `ingest` term is dropped rather than
  redirected at the new crate -- see the comment on the command for why an
  extracted consumer stops being part of the pin. Measured 58 -> 39, of which
  -20 is `ingest/` leaving and +1 is a `crate::evolution::` import added to
  `evolution_status.rs`'s test module.
