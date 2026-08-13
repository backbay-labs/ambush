# ADR 0004: SPLIT-03 Extracts Four Of Eight Agents; `calico`, `kitten`, `sphinx` And `tom` Are Pinned By `ingest/`

## Status

**Partially superseded on 2026-08-13 by
[`0007-split-03-kitten-pinned-by-a-private-method-not-by-ingest.md`](0007-split-03-kitten-pinned-by-a-private-method-not-by-ingest.md).**
ADR 0007 supersedes the pin recorded here for `tom`, which was real and is now
discharged -- `tom` moved once `ingest/` left -- and REPLACES the pin recorded
for `calico`, `kitten` and `sphinx` with a different one: a private method on the
composition root, not `ingest/`. It does not change this ADR's account of why the
four could not move before SPLIT-05, which is why the Context below stands.

The exit criterion in the Consequences section has moved with that. It shows
`ls crates/swarm-runtime/src/*_agent.rs | wc -l` printing 4; at cc5b169 it prints
3, because `tom` left. It still has to reach 0, and ADR 0007 is where the
remaining three are argued.

Accepted on 2026-08-12. Amended on 2026-08-12 after review, on two points in the
Decision section: it named `kitten`'s inline test module as a consumer of the
dev-dependency edge, which is false, and it did not record the alternative to
that edge. The decision itself is unchanged.

## Context

SPLIT-03 (phase 282) asked for one extraction: `swarm-agents`, holding the eight
`*_agent.rs` role implementations in `crates/swarm-runtime/src/`. That is 12,215
lines, measured at the pre-split commit:

```
$ for f in calico kitten pounce sphinx stalker tom weaver whisker; do \
    git show bf23a4f:crates/swarm-runtime/src/${f}_agent.rs; done | wc -l
   12215
```

It satisfies v1.74's undelivered EXTRACT-01..03.

Four roles moved: `pounce`, `stalker`, `weaver`, `whisker`. Four did not:
`calico`, `kitten`, `sphinx`, `tom`. This ADR records why the other four cannot
move until SPLIT-05, and what it would have cost to force them.

### The precondition SPLIT-03 depends on holds

Part A sealed the `swarm_core::agent` trait boundary so the composition root
stops naming concrete agent types. The check the brief prescribes returns one
line, and it is inside `#[cfg(test)] mod tests` (the module opens at
`dispatcher.rs:1401`):

```
$ grep -rn "use crate::[a-z_]*_agent" crates/swarm-runtime/src/dispatcher.rs crates/swarm-runtime/src/lib.rs
crates/swarm-runtime/src/dispatcher.rs:1409:    use crate::tom_agent::{GovernancePolicy, GovernancePolicyConfig, TomAgent};
```

Non-test composition code names no agent. The seal itself survived a crate
crossing untouched, which is the property it was built for:

```
$ grep -rn SealedAgentTickError crates --include='*.rs' | grep -v swarm-core/src/agent.rs
crates/swarm-runtime/src/sphinx_agent.rs:64:impl swarm_core::agent::sealed::SealedAgentTickError for SphinxAgentTickError {}
crates/swarm-agents/src/stalker_agent.rs:53:impl swarm_core::agent::sealed::SealedAgentTickError for StalkerAgentTickError {}
```

Two hits, one per crate, same count as before the split. The boundary-label
domain stays enumerable.

### The blocker: `ingest/` calls into two agents from non-test code

`ingest/` is the runtime's HTTP ingest surface. It stays in `swarm-runtime` until
SPLIT-05 (`swarm-ingest-runtime`), and it reaches **into** two agents:

```
$ grep -rn "crate::\(tom\|kitten\)_agent" crates/swarm-runtime/src/ingest/mod.rs crates/swarm-runtime/src/ingest/providence_handlers.rs
crates/swarm-runtime/src/ingest/providence_handlers.rs:2:use crate::kitten_agent::route_feedback_signal;
crates/swarm-runtime/src/ingest/mod.rs:61:use crate::tom_agent::GovernancePolicy;
```

Neither is test scaffolding. `ingest/mod.rs` stores
`Option<Arc<GovernancePolicy>>` as state (line 1329) and reads it in
`current_governance_status()` (line 1746); `providence_handlers.rs` calls
`route_feedback_signal` on the Providence dismiss path (line 368).

These are back-edges. Moving `tom` or `kitten` puts a normal `swarm-agents` entry
in `swarm-runtime`'s `[dependencies]`, and Cargo rejects that outright. Verified
on this tree by adding the entry and resolving (absolute paths elided from the
output below; everything else is verbatim):

```
$ cargo metadata --format-version 1
error: cyclic package dependency: package `swarm-agents v0.1.0` depends on itself. Cycle:
package `swarm-agents v0.1.0`
    ... which satisfies path dependency `swarm-agents` of package `swarm-runtime v0.1.0`
    ... which satisfies path dependency `swarm-runtime` (locked to 0.1.0) of package `swarm-agents v0.1.0`
```

`calico` is pinned transitively. `kitten_agent` stays, and its second line is:

```
$ sed -n 2p crates/swarm-runtime/src/kitten_agent.rs
use crate::calico_agent::parse_calico_deception_interaction;
```

So `calico` must stay wherever `kitten` stays.

### Why `sphinx` did not move either, though it could have

`sphinx` is the largest of the four remaining (3,044 lines) and has no back-edge
of its own. It is pinned by `calico`, which it reads from in non-test code. Nine
`calico_agent` items are `pub(crate)` today, and every one would have to become
`pub` -- permanent public API on the root -- for `sphinx` to compile from another
crate:

```
$ grep -n 'pub(crate) \(const CALICO\|enum Calico\|struct Calico\|fn parse_calico\)' crates/swarm-runtime/src/calico_agent.rs
22:pub(crate) const CALICO_DECEPTION_INVENTORY_SCHEMA: &str = "calico_deception_inventory";
23:pub(crate) const CALICO_DECEPTION_INTERACTION_SCHEMA: &str = "calico_deception_interaction";
24:pub(crate) const CALICO_DECEPTION_INVENTORY_THREAT_CLASS: &str = "deception_inventory";
48:pub(crate) enum CalicoLifecycleStage {
56:pub(crate) struct CalicoMonitoringPayload {
63:pub(crate) struct CalicoDeceptionInventoryPayload {
79:pub(crate) struct CalicoDeceptionInteractionPayload {
625:pub(crate) fn parse_calico_deception_inventory(
635:pub(crate) fn parse_calico_deception_interaction(
```

Five are needed by `sphinx`'s production code; four
(`CALICO_DECEPTION_*_SCHEMA`, `CALICO_DECEPTION_INVENTORY_THREAT_CLASS`,
`CalicoMonitoringPayload`) are needed **only** by its test module. Widening
production API to satisfy a test module is not a trade worth making, and the
whole widening would be undone the moment SPLIT-05 lets `calico` and `sphinx`
rejoin in the same crate -- where they would want to be `pub(crate)` again. The
churn buys nothing that waiting does not.

Recorded so the next reader does not re-derive it: `sphinx` is not blocked by a
cycle, it is blocked by a price. The price drops to zero after SPLIT-05.

## Decision

Extract `swarm-agents` with `pounce`, `stalker`, `weaver` and `whisker`. Leave
`calico`, `kitten`, `sphinx` and `tom` in `swarm-runtime`, to move with or after
SPLIT-05 once `ingest/` is no longer in the root.

The edge direction is `swarm-agents -> swarm-runtime`, enforced by Cargo rather
than by review:

```
$ cargo tree -p swarm-runtime -e normal --prefix none | grep -c swarm-agents
0
```

`swarm-runtime` carries `swarm-agents` under `[dev-dependencies]` only. Cargo
permits a cycle closed by a dev-dependency edge, because dev-dependencies do not
participate in the build-order graph of the lib target; the same experiment that
fails above exits 0 with the entry under `[dev-dependencies]`.

That edge has exactly four consumers, and every one of them is a whole file
under `tests/`. This is the complete reference set from this crate into the new
one:

```
$ grep -rn --include='*.rs' swarm_agents crates/swarm-runtime/ | sort
crates/swarm-runtime/tests/bridge_registry_integration.rs:10:use swarm_agents::whisker_agent::WhiskerAgent;
crates/swarm-runtime/tests/dispatch_integration.rs:15:use swarm_agents::pounce_agent::PounceAgent;
crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs:7:use swarm_agents::stalker_agent::StalkerAgent;
crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs:8:use swarm_agents::weaver_agent::WeaverAgent;
crates/swarm-runtime/tests/multi_agent_pipeline_integration.rs:9:use swarm_agents::whisker_agent::WhiskerAgent;
crates/swarm-runtime/tests/pounceagent_integration.rs:6:use swarm_agents::pounce_agent::PounceAgent;
```

Six lines, four files, nothing under `src/`:

```
$ grep -rln --include='*.rs' swarm_agents crates/swarm-runtime/src | wc -l
       0
```

So no inline `#[cfg(test)] mod tests` in the root depends on the edge --
`kitten`'s included. An earlier revision of this ADR said otherwise; that was
wrong, and the correction matters because it is what makes the alternative below
cheap enough to have to argue against. `kitten`'s test module reaches for
`calico`, which never left this crate:

```
$ grep -n 'use crate::calico_agent' crates/swarm-runtime/src/kitten_agent.rs
2:use crate::calico_agent::parse_calico_deception_interaction;
2556:    use crate::calico_agent::{CalicoDeceptionInteractionPayload, CalicoLifecycleStage};
```

### The alternative to the dev-dependency edge, weighed and declined

Because the edge's consumers are four whole files, the cycle is not forced by
the code -- it is chosen. Moving `dispatch_integration.rs`,
`bridge_registry_integration.rs`, `pounceagent_integration.rs` and
`multi_agent_pipeline_integration.rs` to `crates/swarm-agents/tests/` would let
the `[dev-dependencies]` entry be deleted, leaving no edge at all from
`swarm-runtime` to `swarm-agents` in either dependency table.

Test accounting does not object to that. The contract is the sum and the sorted
union of test names, not the per-lane split; an integration test is reported
under its function path in a binary named after its file, and neither changes
when the file changes crate. The union would be preserved exactly and only the
G1/G2 split would move -- the same thing that already happened to the nine unit
tests in the table below.

Two costs decided it the other way.

**1. The transport stack would follow the tests into the agents crate.** The
four files use five crates `swarm-agents` does not depend on, so each would have
to be added to its `[dev-dependencies]`:

```
$ for c in arc_swap axum swarm_consensus swarm_crypto swarm_guard; do
    for f in dispatch bridge_registry pounceagent multi_agent_pipeline; do
      grep -qE "\b$c\b" crates/swarm-runtime/tests/${f}_integration.rs && echo "$c ${f}_integration.rs"
    done
  done
arc_swap dispatch_integration.rs
arc_swap multi_agent_pipeline_integration.rs
axum dispatch_integration.rs
axum bridge_registry_integration.rs
swarm_consensus dispatch_integration.rs
swarm_crypto dispatch_integration.rs
swarm_guard dispatch_integration.rs
```

```
$ grep -cE '^(arc-swap|axum|swarm-consensus|swarm-crypto|swarm-guard)' crates/swarm-agents/Cargo.toml
0
```

`axum` is the dependency SPLIT-01 undertook to remove from this side of the tree
and that ADR 0002 holds SPLIT-01 open over. Putting it into a crate that does
not have it, to buy a manifest cleanup, moves the wrong way.

**2. Two of the four are not agent tests, and two straddle the split.**
`dispatch_integration.rs` (1,899 lines) exercises the dispatcher through a
nine-line `use swarm_runtime::{...}` group opened at `:49`, and
`bridge_registry_integration.rs` exercises `bridge_runtime`, `control` and
`detection::metrics`. Each names exactly one agent type, as a fixture. Filing
them under `swarm-agents` puts a crate's integration tests in a crate that is
not under test. And two of the four name agents from *both* crates, so
relocating them does not make them local to either:

```
$ sed -n '15p;56p' crates/swarm-runtime/tests/dispatch_integration.rs
use swarm_agents::pounce_agent::PounceAgent;
    tom_agent::{ContingencyLease, GovernanceDecision, GovernancePolicy, GovernancePolicyConfig},
$ sed -n '6p;17p' crates/swarm-runtime/tests/pounceagent_integration.rs
use swarm_agents::pounce_agent::PounceAgent;
use swarm_runtime::tom_agent::{GovernancePolicy, GovernancePolicyConfig};
```

Against that, the cost of keeping the edge is bounded and known:
`cargo test -p swarm-runtime` has to build `swarm-agents` first, and the two
crates could not be published to a registry independently of each other. Neither
binds this repo today.

The choice costs nothing to revisit. At SPLIT-05, once `ingest/` leaves and the
other four roles follow it, `pounceagent_integration.rs` and
`multi_agent_pipeline_integration.rs` become tests of `swarm-agents` alone and
can move without dragging `axum` anywhere.

### Nothing was widened

No `pub(crate)` became `pub` in SPLIT-03. Every item the four moved roles reach
for was already `pub` in a `pub mod`:

| Item | Declared | Used by |
| --- | --- | --- |
| `correlation::CorrelationEngine` | correlation.rs:29 | weaver |
| `detection::pipeline::detect_and_deposit_with_role` | pipeline.rs:60 | whisker |
| `investigation::InvestigationError` | investigation.rs:21 | stalker |
| `investigation::SummaryInvestigator` | investigation.rs:174 | stalker |
| `investigation::InvestigationCoordinator` | investigation.rs:258 | stalker |
| `tom_agent::GovernanceDecision` | tom_agent.rs:207 | pounce |
| `tom_agent::GovernancePolicy` | tom_agent.rs:348 | pounce |
| `swarm_policy::static_gate::scope_for_response_action` | static_gate.rs:231 | pounce |

## Consequences

- Four roles, 1,593 lines, leave the composition root. The remaining four are
  10,622 lines and remain blocked on SPLIT-05, not on SPLIT-03.
- `swarm-runtime-http` gains a normal `swarm-agents` dependency for
  `swarm_detect.rs`, which sits above both crates and closes nothing.
- The public path of four modules changed from `swarm_runtime::<role>_agent` to
  `swarm_agents::<role>_agent`. `swarm-runtime` cannot re-export them, because a
  re-export needs a normal dependency and that is the cycle.
- SPLIT-03 stays open, in the sense ADR 0002 uses for SPLIT-01: the requirement is
  not fully delivered until the other four roles follow `ingest/` out. It is
  4-of-8 by role and 1,593-of-12,215 by line. The exit criterion is mechanical,
  so the open item cannot be lost to a reading of this prose:

  ```
  $ ls crates/swarm-runtime/src/*_agent.rs | wc -l
         4
  ```

  It has to reach 0. The composition root carries the same note in code, at the
  top of `crates/swarm-runtime/src/lib.rs` and on each of the four `pub mod`
  declarations, so a reader who never opens `docs/decisions/` still finds it.

### Test accounting

The gate is unchanged across all four commits. Sum of passed tests is 1126 at
every step, and the sorted union of test names is byte-identical to the
pre-SPLIT-03 baseline:

| Step | G1 passed | G2 passed | Sum | Registered names |
| --- | --- | --- | --- | --- |
| baseline (bf23a4f) | 533 | 593 | 1126 | 1152 |
| skeleton | 533 | 593 | 1126 | 1152 |
| + whisker, weaver | 539 | 587 | 1126 | 1152 |
| + stalker | 542 | 584 | 1126 | 1152 |
| + pounce | 542 | 584 | 1126 | 1152 |

Nine unit tests crossed G2 -> G1 (weaver 2, whisker 4, stalker 3) and kept their
names, because each role's module path inside `swarm-agents` is the one it had
inside `swarm-runtime`. Registered names exceed passed by the 26 pre-existing
`ignored` tests (7 in swarm-pheromone, 13 in `tests/jetstream.rs`, 6 in
`tests/multi_instance.rs`); both columns are tracked because a passed-count alone
cannot see an ignored test stop being registered.

### One near-miss worth keeping

`tests/dispatch_integration.rs` imported `pounce_agent::PounceAgent` inside a
braced `use swarm_runtime::{...}` group, where the module name is not adjacent to
the crate name and a name-based grep for `swarm_runtime::pounce_agent` does not
find it. `cargo build --workspace` does not compile test targets and stayed
green. `cargo clippy --workspace --all-targets` failed:

```
error[E0432]: unresolved import `swarm_runtime::pounce_agent`
  --> crates/swarm-runtime/tests/dispatch_integration.rs:55:5
```

A grouped import is how a test silently stops being compiled during a large move.
`--all-targets`, not the build, is what makes it visible.
