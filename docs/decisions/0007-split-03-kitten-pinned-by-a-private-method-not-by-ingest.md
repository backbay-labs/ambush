# ADR 0007: SPLIT-03 Moves `tom`; `calico`, `kitten` And `sphinx` Are Still Pinned, By A Private Method Rather Than By `ingest/`

## Status

Accepted on 2026-08-13.

Supersedes the pin ADR 0004 recorded for `tom`, and replaces the pin it recorded
for `calico`, `kitten` and `sphinx` with a different one. It does not change ADR
0004's account of why the four could not move before SPLIT-05.

## Context

ADR 0004 recorded four of the eight roles -- `calico`, `kitten`, `sphinx`, `tom`
-- as pinned inside `swarm-runtime` by `ingest/`, which called into two of them
from non-test code. SPLIT-05 moved `ingest/` out to `swarm-ingest-runtime` (ADR
0006), which turns those calls into forward edges. The phase-282 assessment
concluded from this that all four were free at zero cost: one commit, no
widening, no design change.

That is true for `tom` and false for the other three. This ADR records what the
brief asked to be verified before it was relied on.

### `tom` was free, and moved

`tom_agent.rs` named nothing in the composition root:

```
$ grep -oE '(crate|super)::[A-Za-z_:]+' crates/swarm-runtime/src/tom_agent.rs | sort -u
super::now_ms
```

`super::now_ms` is the file's own helper at `tom_agent.rs:1266`, reached from its
`#[cfg(test)]` module. The one reference to `tom` elsewhere in the crate was
`dispatcher.rs:1400`, inside the `#[cfg(test)] mod tests` that opens at 1390, so
it now reaches `swarm_agents::tom_agent` over the dev-dependency edge the root
already carried.

At the time of the crossing, both then-existing sealed boundaries survived
untouched because both impls named the defining crate rather than the
composition root:

```
$ grep -rn "SealedAgentTickError\|SealedGovernanceAuthority" crates --include='*.rs' \
    | grep -vE 'swarm-core/src/agent.rs|swarm-policy/src/governance.rs' | grep -E ':impl '
crates/swarm-runtime/src/sphinx_agent.rs:64:impl swarm_core::agent::sealed::SealedAgentTickError for SphinxAgentTickError {}
crates/swarm-agents/src/tom_agent.rs:1285:impl swarm_policy::governance::sealed::SealedGovernanceAuthority for GovernancePolicy {}
crates/swarm-agents/src/stalker_agent.rs:53:impl swarm_core::agent::sealed::SealedAgentTickError for StalkerAgentTickError {}
```

Those were the same three impls as before that move. This is historical evidence,
not the current authority boundary: ADR 0011's 2026-08-15 amendment removed the
public governance trait and marker, moved the whole Tom/governance implementation
to `swarm-governance`, and replaced injection with a concrete opaque handle minted
only by an authenticated persisted `GovernancePolicy`.

### The other three are one indivisible commit

Nothing in `swarm-runtime` names them any more:

```
$ grep -rn --include='*.rs' 'crate::\(calico\|kitten\|sphinx\)_agent' \
    crates/swarm-runtime/src/ | grep -v '_agent.rs:' | grep -v '//!'
$
```

But they name each other, through nine `pub(crate)` items that `calico_agent.rs`
declares -- `sphinx` reads all nine, `kitten` reads four of them, and `kitten`'s
test module reads `sphinx_agent::SphinxAgent`. So they cannot be moved one per
commit:

- moving `calico` first leaves `swarm_agents::calico_agent` named from the
  root's NON-TEST code (`kitten_agent.rs:2`), which needs a normal
  `swarm-agents` entry in the root's manifest, which is
  `error: cyclic package dependency: package 'swarm-agents' depends on itself`;
- moving either reader first leaves it naming `swarm_runtime::calico_agent::*`
  across the crate line, and a re-export cannot launder a `pub(crate)` item
  (`error[E0364]`), so all nine become permanent public API to buy an ordering.

Moving the three together keeps all nine `pub(crate)` inside `swarm-agents`.
That much of the assessment holds: the group costs nothing *among themselves*.

### The pin: one `pub(crate)` method, reached by method-call syntax

The group was moved, and the workspace does not build:

```
error[E0624]: method `strategy` is private
   --> crates/swarm-agents/src/kitten_agent.rs:828:61
    |
828 |                     serde_json::Value::from(detector_genome.strategy()),
    |                                                             ^^^^^^^^ private method
    |
   ::: crates/swarm-runtime/src/mutation/types.rs:137:5
    |
137 |     pub(crate) fn strategy(&self) -> &'static str {
    |     --------------------------------------------- private method defined here
```

`kitten_agent.rs:828` is inside `fn build_population_proposal`, which opens at
line 758. `kitten_agent.rs`'s `#[cfg(test)]` module opens at 2525, so this is
production code, not a test.

**This is why the assessment missed it.** The check ADR 0004 used, and the check
the brief prescribes, is a grep for `crate::<module>` paths. `strategy()` is
called as a METHOD on a value whose type (`EvolutionDetectorGenome`) is already
`pub` and is obtained from an already-`pub` accessor
(`drafting.rs:345 pub fn detector_genome`). No `crate::` path appears at the call
site, and none appears in `kitten_agent.rs`'s import block either. A path grep
cannot see this class of pin at all; only the compiler can.

It is the only one. After the move, with `serde_yaml` added to `swarm-agents`'
dev-dependencies for `kitten`'s test module,
`cargo check -p swarm-agents --all-targets` reports exactly this one error and
nothing else -- no other private item, in any of the three files, in test code or
production code.

### What forcing it would cost

`EvolutionDetectorGenome::strategy` cannot follow its caller. It has 13 call
sites and 12 of them stay:

```
$ grep -roc '\.strategy()' crates/swarm-runtime/src --include='*.rs' | grep -v ':0$'
crates/swarm-runtime/src/kitten_agent.rs:1
crates/swarm-runtime/src/drafting.rs:1
crates/swarm-runtime/src/mutation/harness.rs:2
crates/swarm-runtime/src/mutation/render.rs:1
crates/swarm-runtime/src/mutation/autonomous.rs:2
crates/swarm-runtime/src/mutation/helpers.rs:6
```

So the only mechanical way to move `kitten` is to widen it to `pub`. That is a
FOURTH widening against a baseline of three, which `tools/check-visibility-baseline.sh`
fails by construction, and which CI's own comment on that step calls
"worth a review rather than a commit message".

Two further reasons not to take it as a side effect of a file move:

1. `strategy()` lives in `mutation/`, which SPLIT-04 intends to move out of this
   crate to `swarm-evolution`. Widening it makes public API, forever, out of a
   method in a module the phase is actively trying to relocate. ADR 0006's three
   accepted widenings each came with a keyword that deletes them when their
   module leaves; this one would be created in the module that is leaving.
2. The behaviour-preserving alternative -- deriving the string from serde, since
   `EvolutionDetectorGenome` carries `#[serde(tag = "strategy", rename_all = "snake_case")]`
   and the method returns exactly those tags -- is a rewrite of a call site, not
   code motion. SPLIT-03's mandate is motion.

## Decision

Move `tom` to `swarm-agents`. Leave `calico`, `kitten` and `sphinx` in
`swarm-runtime`, as one group, pinned by
`EvolutionDetectorGenome::strategy`.

Do NOT widen `strategy()` to close SPLIT-03. A fourth widening is a decision
about permanent public API and belongs to the phase re-plan, alongside SPLIT-04
-- which is where `mutation/` is decided anyway.

## Consequences

- SPLIT-03 is 5 of 8 roles, not 8 of 8. `ls crates/swarm-runtime/src/*_agent.rs | wc -l`
  prints 3; it printed 4 before this change and has to reach 0.
- 1,661 lines left the composition root with `tom`. 8,932 remain in the three
  (`calico` 1,394, `kitten` 4,494, `sphinx` 3,044).
- The visibility baseline still reads three accepted widenings since 742206d.
- The unblock is one of: SPLIT-04 moving `mutation/` to `swarm-evolution`, after
  which `strategy()` and its 12 remaining callers are on the far side of the same
  line and `kitten` reads it as ordinary public API of a leaf crate; or a
  recorded decision to widen it, with an allowlist line in
  `tools/check-visibility-baseline.sh` naming `kitten_agent.rs:828` as the caller
  and the SPLIT-04 move as what deletes it.
- The progress measure for this ADR is the compiler, not a grep. `git mv` the
  three files into `crates/swarm-agents/src/`, repoint the `crate::` paths, and
  run `cargo check -p swarm-agents --all-targets`: it is unblocked when that
  reports zero privacy errors.
