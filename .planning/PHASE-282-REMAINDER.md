# Phase 282 Remainder, Re-Derived Against The Merged Tree

**Written 2026-08-13. Task #14.**
**Measured at `cc5b169` (main), the tip at the time of writing.** Phase 282 merged
as `0a09358`; the tree has moved since (phase 320 added
`crates/swarm-runtime/src/containment.rs`, and `swarm-response` grew), so every
number below is re-measured at `cc5b169` rather than inherited. Where a figure
recorded in `ROADMAP.md` / `STATE.md` disagrees with the re-measurement, both are
shown and the recorded one is marked superseded with the command that superseded
it.

This document contains **no code changes and proposes none for itself**. It is
the re-derivation the phase-282 ADRs escalated to the phase owner and that nobody
had done against the merged tree.

## 0. Method

Every number in this document is the output of a command that is printed next to
it. Three conventions, stated once:

- **"LOC"** means `wc -l` over `*.rs` under a crate's `src/`. It is the same
  measure `ROADMAP.md` criterion 4 uses, so the numbers are comparable to the
  recorded ones. **It does not see `crates/swarm-cli/src/core.inc`** — 5,413
  lines compiled into two crates and counted in neither. Section 5 quantifies
  that.
- **"non-test"** means: the file is not declared under `#[cfg(test)]`, and the
  reference occurs before the file's first top-level inline `mod <name> {`
  block (this crate's `#[cfg(test)] mod tests` shape). This distinction decides
  whether an edge is a NORMAL dependency (which Cargo rejects in a cycle) or a
  DEV dependency (which it permits), so it is load-bearing everywhere below.
  The script is reproduced in Appendix A.
- **"pin"** means: module X cannot leave `swarm-runtime` because module Y, which
  stays, names it from non-test code. The crate edge runs
  `<new crate> -> swarm-runtime`, so a stayer naming a leaver is
  `error: cyclic package dependency`. This is ADR 0006's rule, restated: *a
  module may leave the root only once every module that names it has already
  left, or leaves with it.*

## 1. Re-measured LOC, per crate

```sh
find crates -path '*/src/*' -name '*.rs' -exec wc -l {} + | grep -v ' total$' \
  | awk '{split($2,a,"/"); s[a[2]]+=$1} END {for (k in s) printf "%8d  %s\n", s[k], k}' \
  | sort -rn
```

| crate | at `0a09358` (merge) | at `cc5b169` (now) | delta |
| --- | ---: | ---: | ---: |
| swarm-runtime | 77,868 | **80,615** | +2,747 |
| swarm-ingest-runtime | 17,956 | **18,177** | +221 |
| swarm-whisker | 11,655 | **11,664** | +9 |
| swarm-runtime-http | 10,391 | **10,450** | +59 |
| swarm-core | 9,717 | **9,899** | +182 |
| swarm-response | 6,141 | **7,843** | +1,702 |
| swarm-evolution | 7,066 | **7,067** | +1 |
| swarm-pheromone | 5,289 | **5,289** | 0 |
| swarm-runtime-workbench | 4,064 | **4,064** | 0 |
| swarm-spine | 3,739 | **3,739** | 0 |
| swarm-agents | 3,366 | **3,507** | +141 |
| swarm-ingest-json | 3,236 | **3,236** | 0 |
| swarm-consensus | 1,912 | **1,912** | 0 |
| swarm-guard | 1,671 | **1,671** | 0 |
| swarm-crypto | 1,405 | **1,405** | 0 |
| swarm-policy | 1,233 | **1,233** | 0 |
| swarm-ingest-tetragon | 774 | **774** | 0 |
| swarm-ingest-sentinel | 721 | **721** | 0 |
| swarm-ingest-taxii | 406 | **406** | 0 |
| swarm-cli | 177 | **177** | 0 (+5,413 `.inc`, §5) |
| **workspace total** | | **173,849** | |

The merge-commit column is the same command run over an extracted tree:

```sh
git archive 0a09358 crates | tar -x -C <scratch> && find <scratch>/crates ...
```

### 1a. One recorded number is wrong

`ROADMAP.md:993` and `STATE.md:60` both record `swarm-runtime-http` at **10,381**
at the merge. It was **10,391**:

```sh
$ git archive 0a09358 crates/swarm-runtime-http/src | tar -xO -f - '*.rs' | wc -l
   10391
```

Every other figure in that list reproduces exactly (77,868 / 17,956 / 7,066 /
4,064 / 3,366). This is a digit transposition, not a measurement dispute, and it
is corrected in place in both files.

### 1b. Two recorded counts are inverted

`ROADMAP.md:946` and `:993` both say **"5 of 8 agents ... did NOT move"**. Five
of eight DID move; three did not.

```sh
$ ls crates/swarm-runtime/src/*_agent.rs
crates/swarm-runtime/src/calico_agent.rs
crates/swarm-runtime/src/kitten_agent.rs
crates/swarm-runtime/src/sphinx_agent.rs
$ ls crates/swarm-runtime/src/*_agent.rs | wc -l
       3
$ ls crates/swarm-agents/src/*_agent.rs | wc -l
       5
```

ADR 0004 left four behind; ADR 0007 (2026-08-13) moved `tom`, leaving three. The
roadmap line was written from ADR 0004's era and inverted while being restated.
Corrected in place.

`ROADMAP.md` also says "7 of 10 evolution modules". That one is right as an
account of SPLIT-04's *named* set, and it is worth keeping in that form — but the
seven are not ten-sevenths of the work. They are **31,860 of the brief's 36,700
named lines, 87%**; see §2.

### 1c. Verified still true at `cc5b169`

The three cycle breaks phase 282 shipped all survive the phase-320 changes:

```sh
$ grep -rn "pub struct OperatorSurfacePaths" crates --include='*.rs'
crates/swarm-core/src/config/operator.rs:318:pub struct OperatorSurfacePaths {

$ grep -rn "SealedAgentTickError\|SealedGovernanceAuthority" crates --include='*.rs' \
    | grep -v 'swarm-core/src/agent.rs' | grep -v 'swarm-policy/src/governance.rs' | grep ':impl '
crates/swarm-runtime/src/sphinx_agent.rs:64:impl swarm_core::agent::sealed::SealedAgentTickError for SphinxAgentTickError {}
crates/swarm-agents/src/stalker_agent.rs:53:impl swarm_core::agent::sealed::SealedAgentTickError for StalkerAgentTickError {}
crates/swarm-agents/src/tom_agent.rs:1302:impl swarm_policy::governance::sealed::SealedGovernanceAuthority for GovernancePolicy {}
```

Three impls, two crates, same as ADR 0007 recorded. The seals are the mechanism
the two remaining seams should copy; §3 says so specifically.

## 2. What each unlanded extraction would actually remove

| requirement | file set | total LOC | of which `#[cfg(test)]` | ships |
| --- | --- | ---: | ---: | ---: |
| SPLIT-02 (replay half) | `replay/` (11 files) | **8,142** | 3,285 | 4,857 |
| SPLIT-03 (3 of 8 roles) | `calico_agent.rs`, `kitten_agent.rs`, `sphinx_agent.rs` | **8,932** | 3,377 | 5,555 |
| SPLIT-04 (7 of 10 modules) | `canary.rs`, `drafting.rs`, `promotion.rs`, `selection.rs`, `strategy.rs`, `evolution.rs`+`evolution/`, `mutation.rs`+`mutation/` | **31,860** | 11,149 | 20,711 |
| **all three** | | **48,934** | 17,811 | 31,123 |

```sh
$ find crates/swarm-runtime/src/replay -name '*.rs' | xargs wc -l | tail -1
    8142 total
$ wc -l crates/swarm-runtime/src/*_agent.rs | tail -1
    8932 total
$ find crates/swarm-runtime/src -name 'canary.rs' -o -name 'drafting.rs' \
    -o -name 'promotion.rs' -o -name 'selection.rs' -o -name 'strategy.rs' \
    -o -name 'evolution.rs' -o -name 'mutation.rs' \
    -o -path '*/src/evolution/*' -o -path '*/src/mutation/*' | xargs wc -l | tail -1
   31860 total
```

`80,615 - 48,934 = 31,681`. **That is the floor for `swarm-runtime` if every
extraction SPLIT-01..05 names lands in full.** It is 6,681 over SPLIT-06's 25,000
target, and §4 shows what the residue is made of. The recorded projection at
`ROADMAP.md` criterion 4 was 37,338 measured on `.inc`-inclusive LOC at `0018e6a`;
the shape of the conclusion is unchanged, the number is not.

### 2a. Numbers the ADRs recorded that have since moved

| ADR | recorded | now | command |
| --- | ---: | ---: | --- |
| 0003: replay `wc -l` | 8,142 (4,857 non-test) | 8,142 (4,857) | unchanged |
| 0003: production files naming `crate::replay` | 20 | **15** | `grep -rl 'crate::replay' --include='*.rs' crates/swarm-runtime/src/ \| grep -v '/src/replay/' \| grep -vE 'test' \| wc -l` |
| 0005: "the seven still cost every consumer" | 30,624 | **31,860** | above |
| 0005/0006 progress measure | 58 → 38 | **39** | see below |
| 0007: `.strategy()` call sites | 13 (12 staying) | **12** | `grep -rc '\.strategy()' crates/swarm-runtime/src --include='*.rs' \| grep -v ':0$'` |

The ADR 0005 progress measure, with its `ingest/` term dropped because that
directory no longer exists in this crate:

```sh
$ grep -rc 'crate::\(canary\|drafting\|evolution\|mutation\|promotion\|selection\|strategy\)::' \
    crates/swarm-runtime/src/lib.rs crates/swarm-runtime/src/evolution_status.rs \
    crates/swarm-runtime/src/kitten_agent.rs crates/swarm-runtime/src/sphinx_agent.rs
crates/swarm-runtime/src/evolution_status.rs:19
crates/swarm-runtime/src/kitten_agent.rs:12
crates/swarm-runtime/src/lib.rs:7
crates/swarm-runtime/src/sphinx_agent.rs:1
```

39, not 38. **The largest term is no longer `lib.rs`.** That is the finding §3
turns on.

## 3. The seams. There are three, not two.

The brief asked for two trait inversions — "the replay executor seam and the
evolution error seam". The measured coupling says the split is different:

- the **evolution error seam** is real and it is one enum;
- the **replay executor seam is not the blocker**, and inverting it would not
  unblock the extraction — §3c;
- there is a **third pin, `EvolutionStatusReport`,** which the ADRs list only as
  "corroborating" and which is now the biggest single term in the measure above.

Here is the whole non-test coupling picture for the modules in question. Each row
is what that module names from non-test code (Appendix A):

```
canary            -> config detector_factory evolution replay
drafting          -> config evolution mutation replay strategy
evolution         -> canary config evasion_coverage replay strategy
mutation          -> detector_factory drafting evolution replay strategy
promotion         -> canary config detector_factory evolution replay
selection         -> drafting evolution mutation replay strategy
strategy          -> canary config promotion replay

lib               -> canary containment drafting evolution mutation replay selection service
evolution_status  -> canary config evolution mutation selection
kitten_agent      -> agent_identity calico_agent drafting evasion_coverage evolution
                     evolution_status mutation red_swarm replay strategy
sphinx_agent      -> calico_agent strategy
detector_factory  -> config replay
evasion_coverage  -> config detection detector_factory replay
red_swarm         -> replay
replay            -> config correlation detector_factory investigation service

runtime_events    -> evolution_status
service           -> alert_tuning config containment correlation detection
                     evolution_status investigation providence runtime_events sequence_detector
startup_attestation -> evasion_coverage
detection         -> detector_factory
dispatcher        -> detection runtime_events
```

Read it as: everything below the blank line is composition root and stays. Every
arrow from below the line to above it is a pin.

### SEAM-01 — `StrategyProposalRouteError` (the evolution error seam)

**Where.** `crates/swarm-runtime/src/lib.rs:214`, a 15-variant public enum, ten
of whose variants are `#[from]` over concrete lane types:

```
$ grep -nE 'crate::(canary|drafting|evolution|mutation|selection|replay)::' crates/swarm-runtime/src/lib.rs
223:    Drafting(#[from] crate::drafting::EvolutionDraftingError),
226:    Mutation(#[from] crate::mutation::EvolutionMutationError),
229:    Selection(#[from] crate::selection::EvolutionSelectionError),
232:    FormalSafety(#[from] crate::evolution::FormalSafetyGateError),
235:    Queue(#[from] crate::evolution::EvolutionQueueError),
238:    ProposalStore(#[from] crate::evolution::EvolutionProposalStoreError),
240:    Replay(#[from] crate::replay::ReplayHarnessError),
243:    VerificationStore(#[from] crate::replay::VerificationStoreError),
246:    ShadowStore(#[from] crate::replay::ShadowStoreError),
249:    Canary(#[from] crate::canary::CanaryError),
```

**This one enum pins both lanes.** ADR 0003 and ADR 0005 treat the replay
`#[from]`s and the evolution `#[from]`s as two separate problems in two separate
requirements. They are ten variants of one type. Verify: `lib.rs`'s only
`crate::replay` references outside a doc comment are lines 240, 243 and 246, all
inside this enum —

```
$ grep -n "crate::replay" crates/swarm-runtime/src/lib.rs
82://! `swarm-evolution -> swarm-runtime` (the lane reads `crate::replay`, which
240:    Replay(#[from] crate::replay::ReplayHarnessError),
243:    VerificationStore(#[from] crate::replay::VerificationStoreError),
246:    ShadowStore(#[from] crate::replay::ShadowStoreError),
```

ADR 0003 cites these at `lib.rs:118,121,124` and calls them "the crate's own
top-level error enum". They are not in `RuntimeError` (`lib.rs:176`); they are in
`StrategyProposalRouteError` (`lib.rs:214`). Same enum as the evolution
`#[from]`s. The two ADRs never noticed they were describing the same object.

**Why it cannot sink or move.** Not into `swarm-evolution`: `dispatcher.rs:167`
uses the type in a trait signature, `dispatcher` is the root's agent-dispatch
layer, and `swarm-runtime-http`'s `swarm_detect` binary consumes
`swarm_runtime::dispatcher`, so the enum would be named from the root — the
cycle. Not into `swarm-core`: its ten `#[from]` variants name concrete lane
types, so `swarm-core` would need `swarm-evolution`, which needs `swarm-runtime`,
which needs `swarm-core`. Both re-verified at `cc5b169`:

```
$ grep -n 'StrategyProposalRouteError' crates/swarm-runtime/src/dispatcher.rs
4:    RuntimeError, StrategyProposalRouteError, agent_tick_error_boundary, agent_tick_panic_error,
167:    ) -> Result<StrategyProposalRouteReport, StrategyProposalRouteError>;
1401:        StrategyProposalRouteError, agent_tick_error_boundary, agent_tick_error_role,
1520:            Option<Result<StrategyProposalRouteReport, StrategyProposalRouteError>>,
1529:        ) -> Result<StrategyProposalRouteReport, StrategyProposalRouteError> {
```

`dispatcher.rs`'s own `mod tests` opens at 1390, so lines 4 and 167 are the only
production hits — the same two ADR 0005 found.

**The shape of the fix, and it is not new.** `swarm_core::agent::AgentTickError`
already solves exactly this problem for the agent boundary: the boundary type
lives in `swarm-core`, its concrete variants are erased behind
`swarm_core::agent::sealed::SealedAgentTickError`, and the sealed impls name the
DEFINING crate rather than the composition root — which is why they survived two
crate crossings untouched (§1c). `swarm_policy::governance::GovernanceAuthority`
is the second instance, and `tom_agent` carried its impl across a crate line with
no edit. Do the same thing a third time.

**Cost, in API.** `StrategyProposalRouteError` is `pub`. Its consumers outside
`swarm-runtime`:

```
$ grep -rn "StrategyProposalRouteError" crates --include='*.rs' | grep -v 'swarm-runtime/src/lib.rs' | grep -vc dispatcher
```
- `swarm-ingest-runtime/src/ingest/mod.rs` — 11 sites, 8 of them constructing
  the six *non*-`#[from]` variants (`InvalidPayload`, `UnsupportedSource`,
  `ValidationStrategyMismatch`, `ValidationMaterializationMismatch`,
  `RankingPacketNotFound`, `MissingArtifact`, `MissingQueueProposalId`), which
  the inversion does not touch;
- `swarm-ingest-runtime/src/ingest/tests.rs:1128` and
  `swarm-runtime/tests/critical_path_integration.rs:823` — both match on
  `StrategyProposalRouteError::InvalidPayload(_)`, also untouched.

So the blast radius of erasing the ten `#[from]` variants is: `impl
StrategyProposalRouteError::boundary()` (`lib.rs:289`) has to derive its
`&'static str` label from the sealed trait instead of a `match` over concrete
types, and every `?` in the lane that relied on `From` has to go through the
seal. **No external consumer constructs or matches any of the ten.** That is the
measurement that makes this tractable, and it is the reason this seam is cheaper
than it looks.

**What it unblocks.** By itself: nothing — SEAM-02 still pins four of the seven
modules. Together with SEAM-02 it releases the whole evolution lane (31,860) and
removes 3 of the 4 remaining root→replay references.

### SEAM-02 — `EvolutionStatusReport` (the pin the ADRs called "corroborating")

**Where.** The composition root reaches the evolution lane through
`evolution_status`, and it does so from two files that are unambiguously the root:

```
$ grep -n "crate::evolution_status" crates/swarm-runtime/src/runtime_events.rs crates/swarm-runtime/src/service/mod.rs
crates/swarm-runtime/src/runtime_events.rs:4:use crate::evolution_status::EvolutionStatusReport;
crates/swarm-runtime/src/service/mod.rs:46:use crate::evolution_status::EvolutionStatusReport;
```

`runtime_events.rs`'s `#[cfg(test)]` opens at 366 and `service/mod.rs`'s inline
`mod tests {` opens at 111, so both imports (lines 4 and 46) are production. And
`evolution_status.rs` names four of the seven from production code — its
`#[cfg(test)]` opens at 1327, so every line below is above the test boundary:

```
$ grep -nE 'crate::(canary|drafting|evolution|mutation|promotion|selection|strategy)::' \
    crates/swarm-runtime/src/evolution_status.rs | head -11
1:use crate::canary::{CanaryRunRecord, CanaryRunStatus};
3:use crate::evolution::{
9:use crate::mutation::{
14:use crate::selection::EvolutionRankedCandidateSelectionRecord;
276:    BenchmarkStore(#[from] crate::mutation::EvolutionBenchmarkStoreError),
760:    latest_episode_report: Option<&crate::mutation::EvolutionEpisodeReport>,
1020:    latest_solver_proof: Option<&crate::evolution::EvolutionProofLookup>,
1061:    latest_proposal: Option<&crate::evolution::EvolutionProposalLookup>,
1137:    reasons: &[crate::evolution::EvolutionProposalBlockingReason],
1172:) -> Result<Option<crate::evolution::EvolutionProofLookup>, EvolutionStatusError> {
1190:) -> Result<Option<crate::evolution::EvolutionProposalLookup>, EvolutionStatusError> {
```

**Why this matters and why it was missed.** `evolution_status.rs` is not in
SPLIT-04's named file set, so it stays. It names `canary`, `evolution`,
`mutation` and `selection` in production. `runtime_events` and `service` name
it. Therefore `canary`, `evolution`, `mutation` and `selection` are pinned by a
chain that has nothing to do with `StrategyProposalRouteError` — and `strategy`
and `promotion` follow by ADR 0005's own steps 2 and 3. **Landing SEAM-01 alone
moves zero lines.** ADR 0005's claim that `lib.rs` "alone is sufficient" to
explain the pin is true; its downgrade of `evolution_status` to "corroborating,
not load-bearing" is the part that misleads a planner, because sufficiency of one
pin says nothing about how many pins have to be cut.

**Cost, in API.** Much smaller than SEAM-01. The root names exactly **one type**,
`EvolutionStatusReport`, at exactly three sites:

```
$ grep -n "EvolutionStatusReport" crates/swarm-runtime/src/runtime_events.rs crates/swarm-runtime/src/service/*.rs
crates/swarm-runtime/src/runtime_events.rs:4:use crate::evolution_status::EvolutionStatusReport;
crates/swarm-runtime/src/runtime_events.rs:261:        status: EvolutionStatusReport,
crates/swarm-runtime/src/service/mod.rs:46:use crate::evolution_status::EvolutionStatusReport;
crates/swarm-runtime/src/service/types.rs:226:    pub evolution: Option<EvolutionStatusReport>,
crates/swarm-runtime/src/service/types.rs:349:    pub fn with_evolution(mut self, evolution: EvolutionStatusReport) -> Self {
```

One enum variant payload (`RuntimeEvent::EvolutionStatus`), one optional struct
field and one builder method. `EvolutionStatusReport` is a serialisable report,
not a behaviour: the natural fix is to **sink the type into `swarm-core`** rather
than to invert a trait. That is the same move `OperatorSurfacePaths` got in
SPLIT-02 (`swarm-core/src/config/operator.rs:318`), and unlike SEAM-01 it does
not require a seal at all — it requires `EvolutionStatusReport`'s own field types
to be `swarm-core`-reachable, which is the thing to prove before committing to
this route.

**What it unblocks.** With SEAM-01: the entire evolution lane, 31,860 LOC. Note
the ordering consequence — `evolution_status.rs` itself (2,251 LOC) **stays** in
the root; it becomes a consumer of `swarm-evolution`, which is a legal forward
edge.

### SEAM-03 — the replay manifest types. NOT the executor.

**The executor inversion is not the blocker, and ADR 0003's own evidence shows
it.** ADR 0003 frames the fix as giving `replay/harness.rs` "something that
executes an event" instead of `SwarmRuntime`. That inverts the
`replay -> root` edge. But once `swarm-runtime-replay` exists and depends on
`swarm-runtime`, `replay -> root` is a **forward** edge and Cargo is content with
it. `harness.rs:853-862` may keep constructing `SwarmRuntime` verbatim:

```
$ grep -n "SwarmRuntime\|RuntimeService\|RuntimeMode" crates/swarm-runtime/src/replay/harness.rs
41:use crate::service::{EventExecutionContext, RuntimeService};
42:use crate::{RuntimeMode, SwarmRuntime};
853:    ) -> Result<RuntimeService<ConfigurableApprovalGate, SandboxExecutor>, ReplayHarnessError> {
855:        offline_config.runtime.mode = RuntimeMode::DetectOnly;
857:        let runtime = SwarmRuntime::new(
858:            RuntimeMode::DetectOnly,
862:        Ok(RuntimeService::new(offline_config, runtime).with_configured_sequence_detector()?)
```

The cycle is closed by the OTHER direction, and that is the direction to cut. The
corrected sequence at `ROADMAP.md` criterion 1 already says exactly this
("... -> decouple those four references -> replay -> workbench"); ADR 0003's
Alternatives section then re-proposes the executor inversion as "the real
answer", and that is the sentence a planner will read. **Inverting the executor
is an architecture improvement — it would let `swarm-runtime-replay` stop
depending on the composition root entirely — but it is not what unblocks
SPLIT-02, and pricing SPLIT-02 against it overstates the requirement by a large
margin.**

**What actually pins replay.** 15 production files name `crate::replay`. Eleven
of them leave with SPLIT-03 and SPLIT-04:

```
$ grep -rl "crate::replay" --include="*.rs" crates/swarm-runtime/src/ | grep -v "/src/replay/" | grep -vE "test" | sort
crates/swarm-runtime/src/canary.rs             <- SPLIT-04
crates/swarm-runtime/src/detector_factory.rs   <- STAYS
crates/swarm-runtime/src/drafting.rs           <- SPLIT-04
crates/swarm-runtime/src/evasion_coverage.rs   <- STAYS
crates/swarm-runtime/src/evolution_status.rs   <- STAYS (test-only ref, see below)
crates/swarm-runtime/src/evolution.rs          <- SPLIT-04
crates/swarm-runtime/src/evolution/formal_safety.rs  <- SPLIT-04
crates/swarm-runtime/src/evolution/helpers.rs        <- SPLIT-04
crates/swarm-runtime/src/kitten_agent.rs       <- SPLIT-03
crates/swarm-runtime/src/lib.rs                <- SEAM-01
crates/swarm-runtime/src/mutation.rs           <- SPLIT-04
crates/swarm-runtime/src/promotion.rs          <- SPLIT-04
crates/swarm-runtime/src/red_swarm.rs          <- moves with the lane (see below)
crates/swarm-runtime/src/selection.rs          <- SPLIT-04
crates/swarm-runtime/src/strategy.rs           <- SPLIT-04
```

`evolution_status.rs`'s only `crate::replay` is at line 1359, inside its
`#[cfg(test)]` module (opens 1327), so it is a dev edge, not a pin.
`red_swarm.rs` is named by `kitten_agent` and by nothing else, so it travels with
SPLIT-03/04 rather than staying.

**That leaves exactly three pins**, and this is the number to plan against:

| pin | site | what it names |
| --- | --- | --- |
| `lib.rs` | 240, 243, 246 | 3 `#[from]` variants — **SEAM-01 removes these** |
| `detector_factory.rs` | `:8` | `use crate::replay::DetectorCandidateManifest;` |
| `evasion_coverage.rs` | `:7-10` | `ReplayHarnessError, ReplayScenarioClass, ReplayScenarioInput, load_replay_suite_manifest, load_scenario_manifest, resolve_manifest_relative_path` |

Neither of the two survivors can simply follow replay out:

```
$ grep -n "crate::detector_factory" crates/swarm-runtime/src/detection/pipeline.rs
1:use crate::detector_factory::RuntimeDetector;
$ grep -n "crate::evasion_coverage" crates/swarm-runtime/src/startup_attestation.rs
11:use crate::evasion_coverage::resolve_repo_root;
```

`detection` is named by `dispatcher` and `service` — composition root — so
`detector_factory` is pinned to the root. `evasion_coverage` is pinned by one
function, `resolve_repo_root` (`evasion_coverage.rs:432`, a `pub fn` returning a
`PathBuf` from a `&Path`), which is a relocation candidate for `swarm-core`, not
a design problem.

**So SEAM-03 is: split `replay/types.rs` along the data/behaviour line.** The
manifest and scenario DATA types — `ReplayScenarioClass` (`:173`),
`ReplayScenarioInput` (`:305`), `DetectorCandidateManifest` (`:684`),
`ReplaySuiteManifest` (`:231`), `ExperimentLineage` (`:630`) and the three
`load_*`/`resolve_manifest_relative_path` loaders — go DOWN into `swarm-core`.
The harness/error types go UP into `swarm-runtime-replay`. The dividing line is
already visible in the file's own import block: `ReplayHarnessError`
(`types.rs:22`) is the thing that structurally contains the composition root —

```
$ sed -n '1,10p' crates/swarm-runtime/src/replay/types.rs
use super::stores::{ ... };
use crate::config::{DetectorProfileError, RuntimeConfigError};
use crate::correlation::CorrelationError;
use crate::service::{RuntimeMetricsSnapshot, ServiceError};
```

— and it is the only one of the six `evasion_coverage` imports that does. So the
concrete question SEAM-03 has to answer, and it is answerable by compiler and not
by argument, is: **can `evasion_coverage` and `detector_factory` be re-expressed
against a `swarm-core`-hosted manifest module plus their own local error type,
with no reference to `ReplayHarnessError`?** If yes, replay leaves as pure code
motion behind SEAM-01. If no, `evasion_coverage` moves out with replay and
`resolve_repo_root` sinks to `swarm-core`, and only `detector_factory` remains.

**Cost, in API.**

```
$ grep -c '^pub ' crates/swarm-runtime/src/replay/types.rs
      61
$ grep -rc 'crate::replay' crates/swarm-runtime/src/{canary,drafting,promotion,selection,strategy,evolution,mutation}.rs \
    crates/swarm-runtime/src/evolution/{helpers,formal_safety}.rs \
    | grep -v ':0$' | awk -F: '{s+=$2} END {print "TOTAL="s}'
TOTAL=29
```

Moving a subset of `replay/types.rs`'s 61 public items to `swarm-core` changes
their public path from `swarm_runtime::replay::X` to `swarm_core::X` for every
consumer: 29 references across the evolution lane's non-test files, 3 in
`kitten_agent.rs`, 1 `pub(crate) use` alias in `swarm-runtime-http`, and one
`crate::replay` in `swarm-cli`'s `core.inc`. This is the largest *mechanical*
cost of the three seams and the smallest *design* cost: no trait, no seal, no
behaviour change.

### 3a. The seams are ordered, and SPLIT-03 and SPLIT-04 are mutually blocking

One consequence nobody has recorded, and it changes the commit plan.

ADR 0007 pins `calico`/`kitten`/`sphinx` on `EvolutionDetectorGenome::strategy`,
which is `pub(crate)` in `mutation/types.rs:137` — a module SPLIT-04 intends to
move. And `kitten_agent` names `crate::mutation`, `crate::drafting` and
`crate::evolution` from production code. So:

- move `mutation` to `swarm-evolution` while `kitten` stays →
  `swarm-runtime` names `swarm_evolution::mutation` → cycle;
- move `kitten` to `swarm-agents` while `mutation` stays →
  `error[E0624]: method 'strategy' is private` (ADR 0007's measured error).

**ADR 0007's stated unblock does not work as written.** It says the fix is
"SPLIT-04 moving `mutation/` to `swarm-evolution`, after which `strategy()` and
its 12 remaining callers are on the far side of the same line and `kitten` reads
it as ordinary public API of a leaf crate". `kitten` lands in `swarm-agents`, not
in `swarm-evolution`; `pub(crate)` inside `swarm-evolution` is exactly as
invisible from `swarm-agents` as it is today. The item still has to become `pub`,
and `tools/check-visibility-baseline.sh` covers `crates/*/src` at **any depth in
every crate** — its own header says so — so it is still the fourth widening
against a baseline of three, just wearing a different crate name.

The three real options, all of which belong to the re-plan and not to an
implementer:

1. **Widen `EvolutionDetectorGenome::strategy` to `pub`** with an allowlist entry
   in `tools/check-visibility-baseline.sh`. One keyword. Makes permanent public
   API out of a method whose 12 call sites are all inside `mutation/` and
   `drafting.rs` (11) plus `kitten_agent.rs` (1).
2. **Land SPLIT-03's three roles and SPLIT-04's `mutation`+`drafting` block in
   one commit**, with `swarm-agents` gaining a `swarm-evolution` dependency. Then
   `strategy()` still has to be `pub` in `swarm-evolution` for `kitten` to call
   it — so this does not avoid the widening either. It only relocates it.
3. **Delete the call.** `EvolutionDetectorGenome` carries
   `#[serde(tag = "strategy", rename_all = "snake_case")]` and `strategy()`
   returns exactly those tags, so `kitten_agent.rs:828`'s one use can be derived
   from serde. ADR 0007 costed this and declined it as a rewrite rather than
   motion — correct for a code-motion phase, and it is the only option of the
   three that leaves the visibility baseline at three.

Option 3 is the recommendation, and it is one call site.

### 3b. Proposed requirements

Each seam gets its own requirement, per ADR 0003's and ADR 0005's escalations, and
because ADR 0006 records that refactor-plus-extraction in one task is what stalled
the first SPLIT-05 attempt at 26 clippy errors.

---

**SEAM-01** — `StrategyProposalRouteError` stops naming concrete lane types.

*Success criteria, all mechanical:*
1. `grep -nE 'crate::(canary|drafting|evolution|mutation|selection|replay)::' crates/swarm-runtime/src/lib.rs`
   prints nothing (rc=1).
2. The boundary-label domain stays enumerable: `StrategyProposalRouteError::boundary()`
   returns the same ten strings for the same ten conditions, proved by a test that
   fails if a label is added or renamed.
3. The seal is `swarm_core`- or `swarm_policy`-hosted, with `sealed::Sealed*`
   impls that name the DEFINING crate, so they survive a later crate crossing
   untouched — the property §1c measures for the two existing seals.
4. `swarm-ingest-runtime`'s 11 construction sites and the two `InvalidPayload`
   matches compile unchanged.
5. `bash tools/check-visibility-baseline.sh` still reports three accepted
   widenings, not four.
6. Test-name set byte-identical in both directions, the check that caught b86576d.

*Unblocks:* 3 of the 4 residual root→replay references; 5 of the 7 evolution
modules at the `lib.rs` pin. *Costs:* one public enum's internal representation;
no external consumer constructs or matches an affected variant (§3, measured).

---

**SEAM-02** — the composition root stops naming `crate::evolution_status`.

*Success criteria:*
1. `grep -rn 'crate::evolution_status' crates/swarm-runtime/src/runtime_events.rs crates/swarm-runtime/src/service/`
   prints nothing (rc=1).
2. `EvolutionStatusReport` resolves from `swarm-core` (or is reached through a
   sealed report trait), and `RuntimeEvent::EvolutionStatus`'s serialized form is
   byte-identical before and after — asserted by a fixture, not by inspection,
   because this type crosses the operator HTTP surface.
3. `crates/swarm-runtime/src/evolution_status.rs` stays in `swarm-runtime` and
   becomes a consumer of the extracted lane.

*Unblocks:* `canary`, `evolution`, `mutation`, `selection` at the second pin, and
with them `strategy` and `promotion` by ADR 0005's steps 2–3. Nothing moves
without both SEAM-01 and SEAM-02. *Costs:* one report type's crate address, one
enum payload, one struct field, one builder method.

---

**SEAM-03** — the replay manifest/scenario types stop being replay's.

*Success criteria:*
1. `grep -rn 'crate::replay' crates/swarm-runtime/src/ --include='*.rs' | grep -v '/src/replay/'`
   prints only lines inside `#[cfg(test)]` modules, after SPLIT-03, SPLIT-04 and
   SEAM-01 have landed.
2. A transient probe reproduces the closure: create a skeleton
   `crates/swarm-runtime-replay` depending on `swarm-runtime`, give
   `swarm-runtime` the reverse edge, and `cargo metadata --format-version 1`
   exits 0 where ADR 0003 measured `error: cyclic package dependency`. Revert the
   probe.
3. No item is widened: `bash tools/check-visibility-baseline.sh` reports three.

*Unblocks:* SPLIT-02's replay half, 8,142 LOC, as pure code motion.
*Costs:* the public path of a subset of `replay/types.rs`'s 59 public items.
*Explicitly NOT in scope:* the `SwarmRuntime` executor inversion. It is an
architecture improvement, it is not on the critical path (§3c), and bundling it
is the refactor-plus-extraction combination ADR 0006 records as the cause of the
26-error stall.

---

### 3c. Why the executor inversion is worth doing later, separately

Once SPLIT-02 lands via SEAM-03, `swarm-runtime-replay` depends on
`swarm-runtime` — the whole composition root, including `service/`, `config`,
`correlation`, `investigation` and `SwarmRuntime` itself. That means every replay
consumer transitively links the composition root, which is most of what SPLIT-06
exists to avoid. Inverting `harness.rs`'s `SwarmRuntime` construction behind an
"executes an event" trait is what would let `swarm-runtime-replay` become a leaf,
and it is what makes `service/` (5,663 LOC) movable — see §4b. Book it, but book
it after the extraction, not inside it.

## 4. SPLIT-06, re-derived from coupling

### 4a. The two recorded defects, both confirmed at `cc5b169`

**Unreachable.** SPLIT-06 asks for `swarm-runtime` under 25,000 LOC. With every
extraction SPLIT-01..05 names landed in full, `swarm-runtime` is **31,681**
(§2). What remains is the composition root and nothing else:

| module | LOC | | module | LOC |
| --- | ---: | --- | --- | ---: |
| `service/` | 5,663 | | `evasion_coverage.rs` | 1,304 |
| `config.rs` | 2,692 | | `containment.rs` | 913 |
| `dispatcher.rs` | 2,616 | | `correlation.rs` | 858 |
| `approval.rs` | 2,450 | | `sequence_detector.rs` | 801 |
| `evolution_status.rs` | 2,251 | | `agent_identity.rs` | 793 |
| `lib.rs` | 2,211 | | `startup_attestation.rs` | 737 |
| `detection/` | 2,165 | | `escalation.rs` | 617 |
| `providence.rs` | 1,675 | | `detector_factory.rs` | 576 |
| `investigation.rs` | 1,426 | | `alert_tuning.rs` | 517 |
| | | | `threat_intel_runtime.rs` | 450 |
| | | | `runtime_events.rs` | 398 |
| | | | `red_swarm.rs` | 385 |
| | | | `http/` | 105 |
| | | | `bin/` | 78 |
| | | | **total** | **31,681** |

`service/` alone is 5,663 and SPLIT-01's own text requires it to stay. There is
no arrangement of SPLIT-01..05 that reaches 25,000.

**Self-contradictory.** SPLIT-06 also asks that no workspace crate exceed 20,000.
Landing SPLIT-04's seven in `swarm-evolution` gives
`7,067 + 31,860 = ` **38,927** — the same requirement breached by satisfying
another clause of itself. Not a near miss: nearly double.

### 4b. The coupling-driven answer

The seven modules are not one blob. Their non-test condensation is a three-node
DAG, derived from the matrix in §3 (confirm by reading the seven rows: nothing in
block A names anything in B or C; nothing in B names C):

```
   C  selection                          1,929   depends on A and B
   |
   B  drafting, mutation                14,627   depends on A
   |
   A  canary, evolution, promotion, strategy    15,304   base
```

```sh
$ find crates/swarm-runtime/src -name 'canary.rs' -o -name 'promotion.rs' \
    -o -name 'strategy.rs' -o -name 'evolution.rs' -o -path '*/src/evolution/*' \
    | xargs wc -l | tail -1
   15304 total
$ find crates/swarm-runtime/src -name 'drafting.rs' -o -name 'mutation.rs' \
    -o -path '*/src/mutation/*' | xargs wc -l | tail -1
   14627 total
$ wc -l crates/swarm-runtime/src/selection.rs
    1929
```

`15,304 + 14,627 + 1,929 = 31,860`. ✓

The blocks are SCCs — A is genuinely cyclic (`canary -> evolution -> strategy ->
promotion -> canary`) and B is genuinely cyclic (`drafting -> mutation ->
drafting`), so neither can be subdivided further without a design change. **The
DAG holds for test code too**: running the same matrix without the non-test
filter changes no arrow between A, B and C, so this split needs no
dev-dependency edge in either direction.

**The plan note's two claims, checked.**

- *"`mutation/` ~10,631 and `evolution/` ~6,862 each stand alone."* The two
  figures are correct as of `0a09358` and are **directory-only** — they exclude
  the module roots `mutation.rs` (74) and `evolution.rs` (78), which is where the
  `#[path]` declarations and the `use crate::replay` / `use crate::strategy`
  imports actually live. At `cc5b169` the movable units are `mutation.rs` +
  `mutation/` = **10,814** and `evolution.rs` + `evolution/` = **7,707**.
  *"Each stands alone" is FALSE as stated*: `mutation` names `drafting` and
  `drafting` names `mutation` (a two-module SCC), and `evolution` names `canary`
  and `strategy` which name it back. Neither is a standalone crate. The
  defensible units are the three SCC blocks above, not the two directories.
- *"`service/` (~5,643) can follow replay out once replay stops importing it."*
  The size is right (5,643 at `0a09358`, **5,663** at `cc5b169`). The claim is
  **backwards**. `service/` is not held in place by replay importing it. Outside
  `service/` itself and `replay/`, exactly one file in the crate names it, and
  it is the crate root:

  ```
  $ grep -rn 'crate::service' crates/swarm-runtime/src --include='*.rs' \
      | grep -v '/src/service/' | grep -v '/src/replay/'
  crates/swarm-runtime/src/lib.rs:848:        let preview = crate::service::preview::build_rehearsal_preview(
  ```

  So removing replay's import would leave `service/` named only from `lib.rs`.
  What holds it is the other direction: `service -> alert_tuning config
  containment correlation detection evolution_status investigation providence
  runtime_events sequence_detector` — ten root modules, including
  `containment.rs`, which phase 320 added *after* this note was written. Moving
  `service/` out means every one of those ten becomes a cross-crate edge, and
  `service/` would then be a crate that depends on the composition root while the
  composition root's `lib.rs` calls into it. `service/` **is** the composition
  root's service layer. Replay stopping its import removes a *reason for
  `service/` to share a crate with replay*; it does not make `service/` movable.
  Do not plan on it. What would make it movable is §3c's executor inversion plus
  a decision about those ten edges — a phase, not a rider.

**Recommended re-derivation of SPLIT-06.** Replace the two numeric clauses with
coupling clauses plus one measured record:

1. The evolution lane lands as **three crates along its own condensation**, not
   one:
   - `swarm-evolution` keeps the governance/review lane it already has
     (`evidence` 2,389, `governance_prep` 1,728, `operator_maintenance` 944,
     `portfolio` 1,966, `lib.rs` 40 = **7,067**) and gains block A
     (**15,304**) → **22,371**;
   - or, if the 20,000 ceiling is kept as a hard clause, block A becomes its own
     crate at **15,304** and `swarm-evolution` stays at **7,067**;
   - block B + C (`drafting`, `mutation`, `selection`) is one crate at
     **16,556**.
   Every one of those is under 20,000; the single-crate arrangement (38,927) is
   not, and the "swarm-evolution + A" arrangement (22,371) is not.
2. `swarm-runtime` is recorded at its measured floor of **31,681** with the
   composition-root inventory above attached, and the 25,000 clause is either
   dropped or moved to a follow-on phase that names which of `service/` (5,663),
   `providence.rs` (1,675) or `detection/` (2,165) is next — a decision that
   needs §3c's executor inversion first, not a budget.
3. The per-crate ceiling clause is amended to say **what is measured**: `*.rs`
   under `src/` PLUS any `#[path]`-included non-`.rs` source, because today the
   clause is unfalsifiable for two crates (§5).

## 5. INCFIX-02 / `crates/swarm-cli/src/core.inc`

Still present, still one file, still included by two crates:

```
$ find crates -name '*.inc'
crates/swarm-cli/src/core.inc
$ wc -l crates/swarm-cli/src/core.inc
    5413 crates/swarm-cli/src/core.inc
$ grep -rn 'core.inc' crates --include='*.rs'
crates/swarm-cli/src/lib.rs:79:#[path = "core.inc"]
crates/swarm-runtime-http/src/lib.rs:52:// `cli::core` is `crates/swarm-cli/src/core.inc`, pulled in by `#[path]` rather
crates/swarm-runtime-http/src/cli/mod.rs:1:#[path = "../../../swarm-cli/src/core.inc"]
```

### 5a. It is a decomposition, not code motion, and here is the mechanism

`core.inc` resolves its runtime dependencies as `crate::<module>` — 19 distinct
modules:

```
$ grep -ohE 'crate::[a-z_]+' crates/swarm-cli/src/core.inc | sort -u | wc -l
      19
```

Both including crates satisfy all 19 by different means. `swarm-cli/src/lib.rs`
declares 23 `pub mod`s — 19 facade re-exports
(`pub mod canary { pub use swarm_runtime::canary::*; }` and so on) plus `args`,
`dispatch`, `format`, `tracing`. `swarm-runtime-http/src/lib.rs:59-71` supplies
18 `pub(crate) use` aliases and declares the nineteenth, `operator_http`, itself
at `:75`:

```
$ grep -n "pub(crate) use\|^pub mod" crates/swarm-runtime-http/src/lib.rs
59:pub(crate) use swarm_ingest_runtime::control;
60:pub(crate) use swarm_runtime::{
70:pub(crate) use swarm_evolution::{evidence, governance_prep, operator_maintenance, portfolio};
71:pub(crate) use swarm_runtime_workbench::review_workbench;
73:pub mod cli;
74:pub mod http;
75:pub mod operator_http;
76:pub mod serve;
```

The same 5,413 lines therefore compile twice against two different resolutions of
the same 19 names. **That is why this cannot be `git mv`**: any split of the file
into modules has to preserve that dual resolution, and any change to which
modules it names changes both crates' manifests.

### 5b. Phase 320's constraint, confirmed

`swarm-cli`'s manifest does not depend on `swarm-agents`, `swarm-response` or
`swarm-policy`:

```
$ grep -n "swarm-agents\|swarm-response\|swarm-policy" crates/swarm-cli/Cargo.toml; echo "rc=$?"
rc=1
$ grep -n '^swarm-' crates/swarm-runtime-http/Cargo.toml
24:swarm-agents.workspace = true
25:swarm-core.workspace = true
26:swarm-crypto.workspace = true
27:swarm-evolution.workspace = true
28:swarm-pheromone.workspace = true
29:swarm-policy.workspace = true
30:swarm-response.workspace = true
31:swarm-ingest-runtime.workspace = true
32:swarm-runtime.workspace = true
33:swarm-runtime-workbench.workspace = true
34:swarm-spine.workspace = true
```

The shared file compiles under the **intersection** of the two manifests, which
is `swarm-cli`'s. So `core.inc` — and any CLI surface descended from it — can
never name a `swarm-agents`, `swarm-response` or `swarm-policy` type directly,
whatever `swarm-runtime-http` can reach. Any INCFIX-02 plan that decomposes the
file by command domain has to hold that line, and any new CLI command touching
containment, response adapters or the policy gate has to reach them through
`swarm-runtime`'s re-exports or add the dependency deliberately.

### 5c. It corrupts SPLIT-06's own measurement

A `*.rs` glob — the measure SPLIT-06 and `ROADMAP.md` criterion 4 both use — sees
none of those 5,413 lines, and they are compiled into **both** crates:

| crate | `*.rs` LOC | compiled LOC |
| --- | ---: | ---: |
| swarm-cli | 177 | **5,590** |
| swarm-runtime-http | 10,450 | **15,863** |

`swarm-runtime-http`'s true size is 52% larger than recorded. It is still under
20,000, so no clause is currently violated — but the clause "no workspace crate
exceeds 20,000 LOC, measured and recorded" is being checked by an instrument that
cannot see 5,413 lines of two crates. That is this project's catalogued failure
mode (a check reporting success over a region it never inspected), applied to a
LOC gate rather than to a test. §4b clause 3 fixes the wording; INCFIX-02 fixes
the cause.

### 5d. Recommended scoping

INCFIX-02 stays its own phase and does not ride inside any SPLIT. Its exit
criterion is already mechanical and already correct:
`find crates -name '*.inc'` returns 0, no resulting file exceeds 800 lines, and
`tools/check-no-include-files.sh` (wired at `ci.yml:panic-contract`) keeps it
that way. Phase 281's note about repointing the cross-crate include at
`#[path = "../../../swarm-cli/src/cli/mod.rs"]` remains the cheapest route — it
removes the `.inc` without deciding ownership, and INCFIX-03 forbids
`#[path = "*.inc"]`, not `#[path]`. Add one criterion phase 281 could not have
known: **the decomposition must not add a `swarm-agents`, `swarm-response` or
`swarm-policy` dependency to `swarm-cli`**, per §5b.

## 6. Recommended sequence

Nothing below is a code change made by this document; it is the order the
measurements support.

| # | work | unblocks | LOC moved |
| --- | --- | --- | ---: |
| 1 | **SEAM-01** `StrategyProposalRouteError` sealed | the `lib.rs` pin on both lanes | 0 |
| 2 | **SEAM-02** `EvolutionStatusReport` out of the root | the `evolution_status` pin | 0 |
| 3 | **SPLIT-04'** evolution lane → 2–3 crates along the A/B/C condensation, plus §3a option 3 (delete `kitten_agent.rs:828`'s `.strategy()` call) | SPLIT-03 | 31,860 |
| 4 | **SPLIT-03'** `calico`, `kitten`, `sphinx` → `swarm-agents` | — | 8,932 |
| 5 | **SEAM-03** replay manifest types → `swarm-core`; `resolve_repo_root` → `swarm-core` | SPLIT-02's replay half | 0 |
| 6 | **SPLIT-02'** `swarm-runtime-replay` | — | 8,142 |
| 7 | **INCFIX-02** `core.inc` decomposition | honest LOC for 2 crates | 0 (+5,413 becomes visible) |
| 8 | **SPLIT-06'** measure and record; decide the next boundary from coupling | — | — |
| 9 | *(later, separate)* replay executor inversion | `swarm-runtime-replay` as a leaf; `service/` as a candidate | — |

Steps 1 and 2 move zero lines and are the entire reason steps 3–6 are possible.
That is the fact the phase-282 plan did not have and this one does.

## Appendix A — the non-test cross-reference matrix

`/private/tmp/.../xref2.sh`, reproduced so the §3 matrix is checkable:

```bash
#!/bin/bash
# Non-test cross-reference matrix over crates/swarm-runtime/src top-level modules.
# Excludes (a) files whose `mod` declaration is #[cfg(test)], (b) everything at
# or after a top-level inline `mod <name> {` block (the #[cfg(test)] mod tests
# convention this crate uses). A bare "first #[cfg(test)]" cut is WRONG for
# module roots that declare `#[cfg(test)] #[path=...] mod tests;` near the top --
# it truncates `service/mod.rs` at line 4 and reports `service -> containment`
# when the real answer is ten modules.
cd "$1" || exit 1
SRC=crates/swarm-runtime/src
TESTFILES='(/tests\.rs|/tests_[a-z_]+\.rs|/test_support\.rs|/tests_support\.rs|/detect_stall\.rs)$'
MODS=$(ls $SRC | sed 's/\.rs$//' | sort -u | grep -v '^bin$')
for m in $MODS; do
  files=""
  [ -f "$SRC/$m.rs" ] && files="$files $SRC/$m.rs"
  [ -d "$SRC/$m" ] && files="$files $(find $SRC/$m -name '*.rs' | grep -vE "$TESTFILES")"
  [ -z "$files" ] && continue
  out=""
  for f in $files; do
    cut=$(grep -nE '^mod [a-z_]+ \{' "$f" | head -1 | cut -d: -f1)
    if [ -n "$cut" ]; then cut=$((cut-1)); else cut=$(wc -l < "$f"); fi
    hits=$(head -n "$cut" "$f" | grep -ohE "crate::[a-z_]+" | sed 's/crate:://')
    out="$out $hits"
  done
  echo "$out" | tr ' ' '\n' | grep -v '^$' | sort -u | grep -vx "$m" | tr '\n' ' ' \
    | sed "s/^/$m -> /"; echo
done
```

**Known limits, stated because this document's conclusions rest on it.** It sees
`crate::` paths only. It cannot see a pin expressed as a method call on an
already-public type — which is precisely the class of pin ADR 0007 found with the
compiler (`EvolutionDetectorGenome::strategy`, called as `.strategy()` with no
`crate::` anywhere at the call site). **Any plan built on this matrix must be
confirmed by `cargo check -p <crate> --all-targets` before it is believed**, the
way ADR 0007 confirmed SPLIT-03. The matrix bounds the problem; it does not close
it.
