# ADR 0004: SPLIT-03 Extracts Four Of Eight Agents; `calico`, `kitten`, `sphinx` And `tom` Are Pinned By `ingest/`

## Status

Accepted on 2026-08-12.

## Context

SPLIT-03 (phase 282) asked for one extraction: `swarm-agents`, holding the eight
`*_agent.rs` role implementations in `crates/swarm-runtime/src/`, roughly 12,137
lines. It satisfies v1.74's undelivered EXTRACT-01..03.

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
fails above exits 0 with the entry under `[dev-dependencies]`. That allowance is
what lets the root's four integration tests and `kitten`'s test module keep
constructing concrete agents without any test being moved or renamed.

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
  not fully delivered until the other four roles follow `ingest/` out.

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
