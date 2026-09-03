# Phase 287: Adversarial Co-evolution Arena - Research

**Researched:** 2026-08-21
**Domain:** Rust-first bounded red/blue adversarial evaluation, deterministic campaign generation, real Ambush runtime integration, and fail-closed evidence
**Confidence:** HIGH for existing code and safety seams; MEDIUM for the Phase 286 graph API, which is not present in this checkout

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

CONTEXT.md has no Decisions subsection. Its complete objective, required shape, measurement contract, and safety boundary are binding:

# Phase 287 Context: Adversarial Co-evolution Arena

## Objective

Build a bounded Red/Blue Co-evolution Arena that exercises the real Ambush investigation and containment-planning path. Red campaigns should adapt from observed blue behavior; blue should learn from escapes and falsified hypotheses. A larger agent count is not evidence of intelligence—the arena must show measurable improvement and generalization.

## Required shape

- Red agents compose multi-stage campaigns from the catalogued tactic/technique corpus using deterministic seeds, virtual time, event budgets, and isolated fixtures or sandbox targets. They cannot invent unbounded capabilities or access live targets.
- Blue agents investigate generated campaigns through real ingest, graph, detector, policy, and containment-planning boundaries. Red code has no response-adapter or policy-authority capability.
- Red mutation records the blue outcome that caused each surviving change in timing, ordering, or tactic composition. Campaigns terminate on generation, budget, plateau, or coverage bounds.
- Blue emits detector and response candidates from escapes and falsified hypotheses with evidence lineage, affected telemetry sources, expected coverage, safety constraints, and reproducible candidate IDs.
- Candidates compete on historical attacks, benign controls, counterexamples, and withheld campaigns. False positives, latency/resource cost, containment safety, and withheld generalization are separate dimensions.

## Measurement contract

Report time to containment, containment blast radius, previously unseen evasions, improvement over the single-agent baseline, and withheld-campaign generalization. Acceptance requires at least 15% median containment-time improvement, no increase in median blast radius, at least one previously unseen evasion in three consecutive seeded runs, at least 10% improvement over the single-agent baseline, and withheld performance no worse than 5% relative to in-sample score.

## Safety boundary

Static and runtime isolation controls must fail closed if red code imports response execution, a blue simulation bypasses policy, or a generated action lacks the receipt/approval boundary. Include a negative fixture that proves the isolation check can fail. Arena results are evidence for synthesis, not permission to deploy a candidate.

### Claude's Discretion

CONTEXT.md has no Claude's Discretion subsection. Recommendations below are implementation choices that preserve the binding shape above.

### Deferred Ideas (OUT OF SCOPE)

CONTEXT.md has no Deferred Ideas subsection. No additional scope is inferred.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research support |
|---|---|---|
| ARENA-01 | Bounded multi-stage catalogued campaigns with deterministic seeds, virtual time, event budgets, and no invented capabilities/live targets | Red-only crate, typed fixture grammar, corpus digest, hash-derived choices, virtual scheduler, fixture namespace, and hard bounds |
| ARENA-02 | Blue runs through real ingest, graph, detector, policy, and containment planning; Red has no response/policy authority | Dedicated arena composition crate using real runtime/ingest seams, Phase 286 adapter, GraphAuthorityHandoff/GraphSignerBinding, dry-run policy, configured DispatchingExecutor, and rehearsal preview |
| ARENA-03 | Red mutates from measured Blue evidence and records causal lineage; all declared stop conditions apply | Authority-free RedOutcomeProjection derived from persisted BlueOutcome, outcome/escape/falsification IDs, changed dimensions, and deterministic stop reasons |
| ARENA-04 | Blue emits evidence-linked detector and response candidates with reproducible IDs | Candidate records hash canonical parent/outcome/corpus inputs and carry graph/event/telemetry/safety lineage |
| ARENA-05 | Historical, benign, counterexample, and withheld competition dimensions stay separate | Immutable partition manifest and digest; separate catch, FP, work/latency, containment-safety, and withheld gates |
| ARENA-06 | Structural and runtime isolation fail closed, including a negative fixture | Forbidden dependency inventory, compile-fail import fixture, live/policy/receipt negative tests, and wired gate |
| ARENA-07 | Reports metrics and meets the five stated thresholds | Paired identical-stream single-agent control, virtual containment time, rehearsal blast radius, unseen fingerprints, improvement, and withheld score |
| ARENA-08 | Fixed inputs produce byte-identical decisions/lineage; runs are bounded and clean | Canonical digests, BTree ordering, injected clock, deterministic signer/sequence, wall guard only, and teardown assertions |
</phase_requirements>

## Summary

The executable no-action contract is not an optional replay ambiguity. Phase
286 Plan 06B owns `FindingReplayOutcome::{NoFinding,NoAction,Actionable}` and
`Phase286StackResult` with the same cases. `NoActionFindingReplay` retains
normalized event/finding/deposit evidence without an `ActionRequest` and proves
zero policy, response, receipt, dispatcher, response-adapter, and generic
investigation calls. Only `Actionable` carries the mandatory `ReplayBundle` and
can produce `ArenaIngestResult.phase286_capture`; the separate
`ArenaIngestResult.no_action` field retains the legal no-action outcome. The
normalizer contract is always `FixtureTarget::normalize_event(&FixtureEvent,
GraphLogicalTime) -> Result<TelemetryEvent, FixtureError>`, while the injected
runtime stack is concrete over `ConfiguredRuntimeStack<P,E,
Phase286StrategyBridge>` and never generic over an arbitrary `S` strategy.

The current red seam is static. crates/swarm-runtime/src/red_swarm.rs contains SuiteRedSwarmAdapter, which concatenates event-backed replay scenarios, and MockRedSwarm, which returns a cloned vector. DefaultReplayHarness::run_loaded_scenario is also offline event replay. These are useful immutable fixture loaders and regression references, but they cannot satisfy adaptive mutation, measured Blue feedback, real graph/planning integration, or causal lineage. The arena must not call them as its co-evolution loop, and it must not claim intelligence from a larger agent count.

Use two new workspace seams. swarm-arena-red should be a capability-minimal crate that emits only typed fixture telemetry and campaign decisions. It must not depend on swarm-runtime, swarm-ingest-runtime, swarm-policy, swarm-response, or swarm-agents. swarm-arena should own orchestration and may depend on both the red crate and existing runtime/ingest crates without creating the existing swarm-runtime to swarm-ingest-runtime cycle. Keeping Red in the existing runtime crate is weaker because that crate already links policy and response.

The Blue side must call `SwarmConfig::arena.require_enabled()` before constructing a runner, target, detector, configured stack, or ingest state. It then processes generated events through the exact `FixtureTarget::normalize_event(&FixtureEvent, GraphLogicalTime) -> Result<TelemetryEvent, FixtureError>` normalizer, wraps the injected detector in the owned sized `ArenaDetectionStrategyAdapter::new(detector)`, and calls the exact `IngestState::process_bridge_event_at<D,P,E>(&self, TelemetryEvent, &dyn GraphClock, &ArenaDetectionStrategyAdapter<D>, &ConfiguredRuntimeStack<P,E,Phase286StrategyBridge>) -> Result<ArenaIngestResult, String>` seam, `build_composite_detector`, and the specialized `ConfiguredRuntimeStack::process_event_with_phase286_capture`. `ArenaIngestResult` is exactly `swarm_ingest_runtime::ingest::{normalized_event, normalized_event_digest, findings, phase286_capture: Option<Phase286InvestigationCapture>, no_action: Option<NoActionFindingReplay>, safety}` and is constructed only by `ArenaIngestResult::from_injected_runtime`; `Phase286InvestigationCapture.replay` is the sole replay carrier, so no side channel or rerun is valid. Its safety trace rejects disabled arena config, non-DetectOnly mode, graph-disabled state, fixed-stack substitution, and external effects. The injected detector and stack are mandatory arguments; the arena branch may not let an `IngestState` field silently substitute its fixed production stack. The graph-enabled stack is constructed only through Phase 286's six-argument `ConfiguredRuntimeStack::from_graph_components(config, policy, response, bridge, authority, signer_binding)` contract with `GraphAuthorityHandoff`, `GraphSignerBinding`, `investigation.enabled=true`, and bounded concrete worker/queue/time settings. An actionable finding enters the existing coordinator via exactly one `submit(&ReplayBundle)`, and the concrete worker invokes `Phase286StrategyBridge::investigate`/one-shot capture once; Arena creates no second queue and never bypasses `submit`. That one capture supplies the public Phase 286 graph result, existing investigation outcome, typed decision, and `ContainmentSimulation`, after which the real policy/rehearsal traversal runs. A no-finding event returns `Phase286StackResult::NoFinding`; a no-action finding returns `Phase286StackResult::NoAction` with zero policy/response/adapter calls; only an actionable finding returns a Phase 286 capture. Phase 286 Plan 06B owns the exact compile contract and counter proof at `crates/swarm-runtime/tests/collective_hypothesis_graph_contract.rs` and `phase286_bridge_handoff.rs`; it rejects `SummaryInvestigator` fallback. Policy must run in DetectOnly/dry-run mode and containment must be a rehearsal preview with a simulated receipt. For one finding, the exact `request_builder` is invoked once, an `ArenaActionContext` is built once, the selected option/action is converted through Phase 286's content-derived `BoundContainmentRequest`, and `RuntimeService::rehearse_selected_simulation(binding, &finding, &approval_context)` is called at most once through the injected authority handoff; `audit_authorize_and_execute` and its instrumented duplicate are forbidden. Current ingest and async investigation code use wall-clock scheduling, so the arena needs the injected runtime `GraphClock` bridge owned by Blue; Red consumes only `GraphLogicalTime`. It must not score wall-clock or async completion order.

**Primary recommendation:** implement one deterministic arena evaluator around a catalog-bounded Red campaign interpreter and the real Blue runtime, with causal Red mutation from persisted Blue outcomes, paired identical-stream single-agent control, immutable partitions, and signed fail-closed artifacts.

The arena's configuration owner is `swarm_core::config::arena::ArenaConfig`,
added by Plan 00 and embedded as `SwarmConfig::arena`. It is
`#[serde(default, deny_unknown_fields)]`, disabled by default, validates a
relative owned `run_root` and every independent bound, and is the only source
for `ArenaRunConfig` defaults. The checked-in signed ruleset intentionally
omits `arena`; a core config test must prove serde omission leaves its raw
signed bytes unchanged. Plan 00 owns the three core config paths, Plans 00C
and 00D migrate the remaining live sites, and Plan 00E runs the independent
AST-aware final oracle; it rejects any missing path, omitted arena field,
duplicate owner, alternate arena default, or non-construction lexical false
positive.

## Standard Stack

### Core

| Library/crate | Version | Purpose | Why standard |
|---|---:|---|---|
| swarm-arena-red | 0.1.0 workspace | Red grammar, campaign materialization, bounded mutation | Compile-time absence of response/policy authority |
| swarm-arena | 0.1.0 workspace | Blue adapter, partitions, evaluation, candidate lineage, stores | Can depend on runtime and ingest without a cycle |
| swarm-core | 0.1.0 workspace | TelemetryEvent, TelemetryPayload, RuntimeMode, AgentId, signed envelope | Canonical domain and safety types |
| swarm-runtime | 0.1.0 workspace | ConfiguredRuntimeStack, RuntimeService, policy/response/replay composition | Existing real critical path |
| swarm-ingest-runtime | 0.1.0 workspace | Input validation, normalization, composite detector factory | Existing ingest boundary; requires virtual clock seam |
| swarm-policy | 0.1.0 workspace | Blue-side approval and lease evaluation | Only policy authority |
| swarm-response | 0.1.0 workspace | Phase 286-configured DispatchingExecutor/recording response path and simulated receipts | No external effects |
| swarm-whisker | 0.1.0 workspace | DetectionStrategy and finding implementations | Existing detector interface |
| swarm-crypto | 0.1.0 workspace | Canonical JSON, SHA-256, signatures | Existing evidence/ID primitives |

### Supporting

| Library/crate | Version | Purpose | When to use |
|---|---:|---|---|
| serde / serde_json | 1 | Typed artifact serialization | All campaign/outcome/candidate/report payloads |
| serde_yaml | 0.9 | Repository-owned catalog and fixture manifests | Immutable input loading only |
| sha2 | 0.10 | Content and lineage digests | Stable IDs and corpus partitions |
| ed25519-dalek | 2 | Configured artifact signer | Fixed test key; admitted role key in production |
| tokio | 1 | Existing async runtime calls | Service invocation only; deterministic decisions stay synchronous |
| trybuild | 1.0 dev | Compile-fail Red isolation fixtures | Prove forbidden imports do not compile |
| proptest | 1 workspace dev | Grammar/property tests | Generate valid/invalid bounded stages |

No network client, shell/process executor, or new agent framework is appropriate. Verify versions with cargo metadata --format-version 1 --locked --offline; internal packages are workspace version 0.1.0. Do not add registry dependencies or use cargo update.

### Alternatives Considered

| Instead of | Could use | Tradeoff |
|---|---|---|
| Separate Red and arena crates | Red module under swarm-runtime/src/red_swarm.rs | Existing crate already has policy/response capabilities, so compile-time absence is impossible |
| Real stack and ingest boundary | MockRedSwarm or replay harness | Proves static fixture loading only, not adaptive Red or real Blue safety |
| Identical single-agent control | More agents/workers | Adds scheduler confounds; count is not evidence |
| Hash-derived choices | rand, OS entropy, UUIDs | Breaks byte-identical decisions |
| Virtual work/time | Instant latency as fitness | Existing project evidence shows machine-dependent ranking |

## Architecture Patterns

### Recommended project structure

~~~text
crates/swarm-arena-red/
  src/lib.rs          # Red-only public capability surface
  src/catalog.rs      # versioned tactic/technique -> fixture map
  src/grammar.rs      # typed stages and fail-closed validation
  src/campaign.rs     # immutable campaign/event materialization
  src/scheduler.rs    # virtual clock, deterministic queue, budgets
  src/mutation.rs     # RedOutcomeProjection-driven bounded mutation

crates/swarm-arena/
  src/lib.rs          # composition root
  src/blue.rs         # ingest/runtime/graph/planning adapter
  src/clock.rs        # virtual clock and deterministic work counters
  src/partitions.rs   # immutable corpus partitions and digests
  src/synthesis.rs    # detector/response candidate lineage
  src/evaluation.rs   # dimensions, pairing, thresholds
  src/artifacts.rs    # signed stores and sequence checks
  src/isolation.rs    # runtime assertions

tests/
  adversarial_coevolution_arena.rs
  arena_isolation_compile_fail.rs
  ui/arena_red_forbidden_import.rs
~~~

Keep red_swarm.rs only as a historical/Kitten compatibility facade. Arena code must not call SuiteRedSwarmAdapter, MockRedSwarm, DefaultReplayHarness::run_loaded_scenario, or evaluate_suite_selection.

### Pattern 1: Typed, catalog-bounded grammar

Represent campaigns as immutable data:

~~~rust
pub struct Campaign {
    pub seed: u64,
    pub corpus_digest: String,
    pub fixture_namespace: String,
    pub generation: u32,
    pub virtual_start_ms: i64,
    pub stages: Vec<CampaignStage>,
    pub budget: CampaignBudget,
}

pub struct CampaignStage {
    pub ordinal: u16,
    pub tactic_id: String,
    pub technique_id: String,
    pub primitive: FixturePrimitive,
    pub offset_ms: u32,
    pub ordering_key: u16,
}
~~~

FixturePrimitive must use fixture IDs or bounded enum values, not arbitrary commands, URLs, IPs, paths, process callbacks, sockets, or file writes. Materialization maps primitives to swarm_core::TelemetryEvent with source arena-fixture and deterministic event IDs. Validate stage/depth/event/duration limits, catalog membership, fixture namespace, non-negative offsets, no path traversal/external target, deny unknown fields, and no ReplayScenarioClass::Mixed.

The current rulesets/evasion/attack-technique-catalog.yaml describes detector gaps, while scenario metadata carries techniques; it is not a complete tactic-to-fixture grammar. Add an explicit versioned mapping schema and digest it. Do not treat arbitrary suite strings as capabilities.

### Pattern 2: Deterministic scheduler and bounded budgets

Sort ready events by virtual timestamp, ordering key, stage ordinal, then event ID. Use BTreeMap/BTreeSet for serialized/iterated collections. Derive every mutation choice from seed, parent digest, generation, persisted Blue outcome digest, Red projection digest, and mutation ordinal; Red consumes only the projection. Record seed, corpus `oracle-registry`/fingerprint digests, the sole execution-registry digest, scheduler version, virtual start, and all limits.

Use separate max_generations, max_events, max_stages, max_virtual_ms, max_mutations, plateau_window, and coverage limits. Stop precedence is hard safety/authority refusal, partition/withheld boundary, generation, event, work, virtual time, mutation, plateau, coverage, then completed; the first reason is terminal. A wall-clock watchdog may abort a hung process, but is guard_only and never scores or selects. Require a config-level run root, await/abort owned tasks, remove only the exact owned root after an ownership-token check, and assert no leaked files, sockets, child tasks, mutable withheld handles, or dirty run root.

### Pattern 3: Blue-outcome-driven Red loop

~~~text
immutable seed campaign
    -> real Blue run
    -> Arena-owned BlueOutcome (escapes, falsified hypotheses, policy/preview, work)
    -> RedOutcomeProjection (authority-free)
    -> RedMutationDecision(parent_digest, projection_digest, cause, dimensions)
    -> validated bounded child campaign
    -> next generation or explicit stop
~~~

Each surviving mutation records parent campaign digest, exact persisted BlueOutcome digest plus its narrow RedOutcomeProjection digest, escape event IDs, falsified-hypothesis IDs, selected dimension, old/new canonical values, mutation ordinal, and stop/budget state. Only timing offsets, ordering, and catalogued tactic composition may change. A test must vary measured Blue outcomes and prove the child changes; a static replay loop must fail. Red never receives policy, response, receipt, lease, dispatcher, governance, or raw telemetry fields.

Stop on generation, event/work, virtual duration, plateau, required coverage, or partition boundary and record the first stop reason.

### Pattern 4: Real Blue runtime with virtual clock

The existing runtime method is `from_components`, but it is forbidden for the
graph-enabled arena because it does not install the Phase 286 graph bridge
contract. The graph path uses the Phase 286-owned six-argument
`ConfiguredRuntimeStack::from_graph_components` constructor plus the
specialized `process_event_with_phase286_capture`, as used by the real runtime
integration path:

~~~rust
config.runtime.mode = RuntimeMode::DetectOnly;
config.hypothesis_graph.enabled = true;
config.investigation.enabled = true;
config.investigation.worker_count = 1;
config.runtime.require_durable_live_response = false;
let detector = swarm_ingest_runtime::control::build_composite_detector(&config.detection)?;
let policy = ConfigurableApprovalGate::from_config(&config.policy);
let response = phase_286_configured_recording_executor;
let bridge = phase_286_graph_strategy;
let authority = phase_286_graph_authority;
let signer_binding = phase_286_signer_binding;
let stack = ConfiguredRuntimeStack::from_graph_components(
    config,
    policy,
    response,
    bridge,
    authority,
    signer_binding,
)?;
let capture = stack.process_event_with_phase286_capture(
    &detector,
    &event,
    EventExecutionContext {
        agent_id: &agent_id,
        approval: &approval_with_virtual_now,
        signing_key: &signing_key,
    },
    blue_action_selector,
    observe_findings,
).await?;
~~~

This reaches substrate readiness, detector evaluation, deposits, enrichment,
policy, dry-run response, replay persistence, and the one-shot Phase 286 bridge
capture. An actionable replay enters the existing Phase 286 coordinator queue
through exactly one `submit(&ReplayBundle)` and one concrete worker capture;
Arena must not create a second queue or bypass that worker path. Do not call a
detector directly as the only Blue proof.

The `investigate_once` wording in the next contract denotes the bridge's
worker-owned one-shot capture, not an Arena-side direct call: the configured
graph stack owns the real `InvestigationCoordinator` worker/queue, submits the
`ReplayBundle` once, and the worker invokes the async
`InvestigationStrategy::investigate` method once before the stack returns the
captured result.

`IngestState::process_bridge_event` currently obtains `now_ms` from the wall clock and its detect-only request builder emits no action. Add exactly `IngestState::process_bridge_event_at<D,P,E>(&self, TelemetryEvent, &dyn GraphClock, &ArenaDetectionStrategyAdapter<D>, &ConfiguredRuntimeStack<P,E,Phase286StrategyBridge>) -> Result<ArenaIngestResult, String>`; its first operation is the configured `ArenaConfig::require_enabled()` guard, and it constructs `ArenaIngestResult::from_injected_runtime` only after supplied detector/stack calls. The constructor carries `phase286_capture: Option<Phase286InvestigationCapture>` directly; `Phase286InvestigationCapture.replay` is the sole replay carrier and no side channel or bridge rerun exists. Keep the existing method as a live wrapper that supplies the production detector/stack. The graph-enabled stack must use Phase 286's six-argument constructor with `GraphAuthorityHandoff`, `GraphSignerBinding`, `investigation.enabled = true`, and bounded concrete worker/queue/time settings. After the closed `FixtureTarget::normalize_event` step, use the specialized configured stack and its one-shot `Phase286StrategyBridge::investigate_once` capture when `SwarmConfig::hypothesis_graph.enabled` is true; an actionable finding enters the existing coordinator queue once via `submit`, while no-finding/no-action paths make zero worker/authority calls. Never invoke the coordinator/planner a second time, never use `SummaryInvestigator`, and do not loop through HTTP or use production wall time. One finding invokes one request builder and at most one `RuntimeService::rehearse_selected_simulation` call with the Phase 286 `BoundContainmentRequest`; no `audit_authorize_and_execute` duplicate is legal.

For containment candidates use the Phase 286-owned public async `RuntimeService::rehearse_selected_simulation(binding: BoundContainmentRequest, finding: &DetectionFinding, context: &ApprovalContext) -> Result<swarm_runtime::service::DryRunTraversalReceipt, RuntimeError>`, with `BoundContainmentRequest` and `GraphAuthorityHandoff` at their Phase 286 public paths. `DryRunTraversalReceipt` remains at `swarm_runtime::service::DryRunTraversalReceipt` with exact fields `{ policy_verdict: PolicyVerdict, pouncer_selection_id: String, tom_governance_receipt_id: String, operator_approval_id: String, dispatcher_admission_id: String, simulated_receipt_id: String, response_status: swarm_response::ResponseStatus }`. Its constructor rejects empty IDs and any response status other than `Simulated`. The method must validate the selected option/request/simulation/target binding and delegate through the real policy -> Pouncer -> Tom/governance -> operator approval -> bound receipt -> dispatcher admission traversal, then force `ExecutionMode::DryRun`/`ResponseStatus::Simulated`; the Phase 286 compile contract constructs the DTO, authority handoff, signer binding, bound request, and async method call. Negative spies attach to this method and require zero recording-adapter calls for every missing stage. Never create an enforced executor or call an external adapter. The valid Arena fixture is single-finding: one `request_builder` invocation yields either `Some(action)`, one Phase 286-bound request, and one rehearsal/receipt, or `None` and retained no-action evidence with no policy/receipt traversal; no multi-finding fan-out or duplicate investigation is legal.

### Pattern 5: Identical single-agent control

For every seed, persist one campaign decision digest and run both the learning Blue evaluator and the single-agent control on identical campaign bytes, virtual clock, detector/config, graph input/store, policy config, signer, scheduler, fixture-target mapping, partition, corpus `oracle-registry` digest, and the sole execution-registry digest. The control has one fixed investigator/strategy and an empty/frozen learned state; it is not a simplified mock. The learning lane may differ only by the bounded signed learned-state projection. Reject a comparison when any frozen common-input digest differs before scoring. Do not use agent count as a metric.

### Pattern 6: Immutable evaluation partitions

Create a content-addressed manifest with historical_attacks, benign_controls, counterexamples, and withheld_campaigns. Each entry has canonical ID, class, source, content digest, corpus version, and partition digest, while the index carries detached signature-envelope metadata verified at admission. Do not claim that static YAML is itself cryptographically signed. Load immutable in-memory data or a read-only copy below the configured run root; reject duplicates/path aliases/mutation. Withheld runs only after candidate/learned-state lineage is frozen and emit no Red feedback. Historical suites can be inputs, but the static replay harness remains out of the arena loop.

### Pattern 7: Evidence-only candidate synthesis

Candidate records require candidate kind, canonical ID, parent/campaign/outcome digests, source event IDs, graph edge/hypothesis IDs, telemetry families, expected coverage, policy verdict, approval requirement, rehearsal preview, rollback, blast-radius constraints, and all partition scores. Current EvolutionDetectorGenome supports four families: suspicious process tree, behavioral anomaly, fileless execution, and DNS exfiltration; do not claim arbitrary genome support. Response candidates use only existing ResponseAction and policy/playbook vocabulary. When detector escape and containment/planning-gap applicability are both true, both candidate kinds are required. Accepted candidates enter only a bounded, signed BlueLearnedState CAS projection for later Phase 288 evaluation; Arena output never invokes promotion/canary.

### Pattern 8: Signed artifacts

Use SignedStateEnvelope for campaign decisions, full Blue outcomes, Red projections, mutation decisions, candidates, pair records, and final reports. Phase 287 owns `ArenaArtifactStore::compare_and_append` with expected generation, predecessor digest, and fencing token; Phase 286 owns graph/task/memory stores only and does not provide an arena artifact store. Existing FileEvolutionEpisodeStore::open_signed and signed population stores are patterns, but avoid their wall-clock created_at fields. Supply a configured signer; tests use a fixed SigningKey seed. Use fixed stream IDs and explicit monotonic sequences. Verify state kind, stream, signer, schema, signature, payload, accepted sequence, CAS generation, predecessor, fence, and run-root ownership. Verify detached partition/withheld digests and signature metadata; fail closed on changed indexes or replayed sequences.

### Anti-patterns

- Static suite materialization presented as adaptive co-evolution.
- Direct detector evaluation without ingest, substrate, policy, graph, planning, or receipt.
- Enforced/live response, external adapter, network target, or action execution from Red.
- Red carrying ActionRequest, ResponseAction, ApprovalContext, ApprovalGate, or ResponseExecutor.
- Aggregate catch rate deciding survival before FP, counterexample, work, safety, and withheld gates.
- Withheld outcomes feeding mutation.
- SystemTime, Instant, async completion order, HashMap iteration, random IDs, or random signer data in decisions/IDs.

## Don't Hand-Roll

| Problem | Do not build | Use instead | Why |
|---|---|---|---|
| Canonical IDs/digests | Ad hoc strings/non-canonical JSON | swarm_crypto::canonical_json_bytes and sha256_hex | Existing deterministic evidence primitive |
| Signatures/replay checks | New wrapper/unsigned index | swarm_core::SignedStateEnvelope and SignedStateExpectation | Binds signer, stream, sequence, payload, and signature |
| Detection/ingest | Second detector/direct helper | build_composite_detector and ConfiguredRuntimeStack | Required real path |
| Policy/approval | Red allowlist or arena verdict | ConfigurableApprovalGate/StaticApprovalGate and SwarmRuntime | One authority, existing fail-closed behavior |
| Response simulation | Fake receipt/blast arithmetic | Phase 286 GraphAuthorityHandoff, BoundContainmentRequest, configured DispatchingExecutor, and rehearsal execution | Typed receipt, policy attribution, rollback, blast radius |
| Investigation | Summary-only arena graph | Phase 286 graph/planning adapter | Required causal evidence and containment path |
| Corpus class | Neutral missing/mixed class | Existing replay validation contract | Prevents vacuous known-bad/FP gates |

## Common Pitfalls

### Static replay mistaken for adaptation

Timestamp shifting and sorting a suite is not mutation. Require outcome digest, causal evidence IDs, changed dimensions, and a test where a different Blue escape changes the child.

### Fake or incomplete Blue path

Direct detector calls omit ingest, substrate, policy, graph, planning, and receipts. Integration must assert replay/finding evidence, policy result, simulated receipt/guard rejection, graph IDs, and rehearsal preview.

### Non-identical baseline

Different event order, clock, detector, or campaign makes the improvement claim invalid. Pair and verify all digests before calculating a percentage.

### Withheld leakage

Do not allow mutation feedback, shared mutable files, aliases, or candidate selection before withheld evaluation. Verify the detached partition signature envelope and digest; do not claim that static YAML bytes are themselves signatures.

### Wall-clock fitness

Instant and async worker completion vary by machine. Gate on virtual containment time and deterministic work counters; wall time is a diagnostic or guard only.

### Same-crate authority leakage

Red inside swarm-runtime can reach sibling policy/response modules. Separate crates plus metadata and compile-fail fixtures are required.

### Receipt-less or preview-less actions

An action without policy verdict, approval boundary, simulated receipt, and containment preview is invalid and excluded from every score. Enforced governed calls without dispatcher admission must return GovernedActionRequiresAdmission.

### Unbounded/leaky run

Enforce generation/event/work/plateau/coverage limits, record first stop reason, clean run-owned state, and assert task/file/socket cleanup.

### Fake unseen evasion

Generation-scoped event IDs are not novel evasions. Fingerprint normalized tactic, technique, primitive, order relation, and timing bucket; require a measured Blue escape/falsification.

### Phase 286 silently replaced

No SummaryInvestigator/static replay fallback if it bypasses the graph/planning contract. Fail construction until the deterministic adapter exists.

## Code Examples

### Red dependency boundary

Source: workspace Cargo manifests.

~~~toml
[package]
name = "swarm-arena-red"
version.workspace = true
edition.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
serde_yaml.workspace = true
sha2.workspace = true
swarm-core.workspace = true
swarm-crypto.workspace = true
thiserror.workspace = true
~~~

No swarm-runtime, swarm-ingest-runtime, swarm-policy, swarm-response, swarm-agents, reqwest, or process-execution dependency is allowed.

### Canonical campaign digest

Source: crates/swarm-crypto/src/lib.rs.

~~~rust
fn digest(campaign: &Campaign) -> Result<String, ArenaError> {
    let bytes = swarm_crypto::canonical_json_bytes(campaign)
        .map_err(ArenaError::CanonicalEncoding)?;
    Ok(swarm_crypto::sha256_hex(&bytes))
}
~~~

Do not include wall time, filesystem paths, random IDs, or unordered maps in the input.

### Signed artifact

Source: crates/swarm-core/src/signed_state.rs.

~~~rust
let signer = AgentId::from_verifying_key(&signing_key.verifying_key());
let envelope = SignedStateEnvelope::sign(
    "arena_episode",
    stream_id,
    signer.clone(),
    sequence,
    report,
    &signing_key,
)?;
let verified = envelope.verify(SignedStateExpectation {
    state_kind: "arena_episode",
    stream_id,
    expected_signer_agent_id: Some(&signer),
    accepted_sequence: Some(sequence),
})?;
~~~

### Blue dry-run boundary

Source: service stack, runtime service, policy, and response adapter modules.

~~~rust
// `binding` is produced by the Phase 286 service only after it finds the
// content-derived option_id, recomputes the simulation/option/request digests,
// and verifies the exact ActionRequest-to-target-node mapping.
let trace = runtime.rehearse_selected_simulation(
    binding,
    &finding,
    &approval_with_virtual_now,
)
    .await?;
assert_eq!(trace.response_status, ResponseStatus::Simulated);
assert!(matches!(trace.policy_verdict,
    PolicyVerdict::Allow | PolicyVerdict::RequireHuman));
assert!(!trace.pouncer_selection_id.is_empty());
assert!(!trace.tom_governance_receipt_id.is_empty());
assert!(!trace.operator_approval_id.is_empty());
assert!(!trace.dispatcher_admission_id.is_empty());
assert!(!trace.simulated_receipt_id.is_empty());
// Every value is emitted by the real traversal. A hand-built boolean,
// direct graph-to-adapter call, or missing-stage fallback is rejected.
~~~

## State of the Art

| Old approach | Current phase approach | Impact |
|---|---|---|
| SuiteRedSwarmAdapter concatenates replay events | Typed grammar composes catalogued fixture primitives | Bounded timing/order/tactic mutation |
| MockRedSwarm static vector | BlueOutcome-driven Red mutation | Causal adaptive evidence |
| Offline DefaultReplayHarness | Ingest + ConfiguredRuntimeStack + graph/planning + rehearsal | Real Blue boundary coverage |
| Catch-rate-only/static pressure | Separate catch, FP, work/time, safety, and withheld dimensions | No unsafe aggregate survivor |
| Unsigned/wall-clock artifacts | Signed canonical virtual-time envelopes | Byte-identical and tamper/replay-resistant |
| More-agent claims | Identical single-agent paired control | Improvement attributable to learning |

Deprecated for this phase: static replay as the arena loop; MockRedSwarm as adaptive Red; current EvolutionAdversarialPressureRequest as sufficient co-evolution (it scores supplied static events); and any promotion/canary call from arena results.

## Open Questions

1. **Phase 286 graph API:** consume the exact post-Plan-06B `GraphInvestigationInput`/`GraphInvestigationResult`/`GraphInvestigationStrategy` DTOs, `Phase286StrategyBridge`, `Phase286InvestigationCapture`, and specialized stack method at their public paths, with the compile-contract and counter tests as the authority. Do not duplicate or bypass the coordinator, planner, or existing `InvestigationStrategy` trait, and do not run generic and one-shot investigation for the same replay.
2. **Ingest clock:** current process_bridge_event uses wall-clock now_ms and detect-only suppresses action selection. Expose an injected-clock arena entry point that preserves parse/normalization and real runtime processing; never use an HTTP loopback.
3. **Tactic grammar:** current attack-technique-catalog.yaml describes detector gaps, not stage primitives. Add a deny-unknown-fields, versioned technique-to-fixture mapping and digest.
4. **Signer:** require a caller-supplied admitted role key; fixed seed only for reproducibility tests. Generated keys invalidate byte equality.
5. **Resource units:** exact Phase 286 graph counters are unknown. Define versioned deterministic counters for events, detector evaluations, graph work, policy evaluations, persistence bytes, and queue operations; wall-clock is non-gating.

## Plan-Sized Work Decomposition

### Preflight bundle (Plans 00J, 00, 00A, 00B, 00C, 00D, 00E, 00F, 00G, 00H, and 00I; `wave_0_complete` records only this bundle)

1. Consume the exact public Phase 286 DTO/clock seams after Plan 06B's symbols and counter proof exist; construction fails if absent. `GraphLogicalTime` is core-only for Red; runtime `GraphClock` is Blue-only.
2. Add swarm-arena-red and swarm-arena manifests with explicit offline dev dependencies; enforce the full Red forbidden-dependency/symbol inventory, including authority reachable through `swarm-core`.
3. Define tactic-to-fixture/closed FixtureTarget grammar, immutable partition manifest, historical/benign/counterexample/withheld fixtures, baseline formulas, known-fingerprint set, and independent corpus-only oracle-registry digests; Plan 00F owns the eight truth files and Plan 00I owns their strict authoring-time verifier. Positive execution names/counts remain solely in `tools/arena-test-registry.json` owned by Plan 00J.
4. Add clean and deliberately broken isolation fixtures plus exact named-test/ignored==0 self-tests before trusting a passing scan; Plan 00B remains the independent runtime corpus oracle.
5. After both config migrations, run Plan 00E's independent Rust-token-aware
   direct-literal classifier and golden/mutation suite; it is the only oracle
   for exactly 24 constructions in 23 paths.

`wave_0_complete` is the logical preflight marker for this eleven-plan bundle,
not a GSD execution-wave number. Plan 00J runs in wave 1, Plan 00 in wave 2,
00A in wave 3, 00C/00D/00F in wave 4, 00G/00H/00I in wave 5, 00B in wave 6,
and 00E is the final scanner in wave 7. `preflight_complete` remains false
until every preflight command passes on the combined tree.

### Wave 8: Red grammar and adaptive scheduler (Plan 01)

1. Implement typed fixture primitives, catalog validation, deterministic IDs, target namespace checks, virtual clock, and all budgets.
2. Implement hash-derived choices and canonical campaign/decision digests.
3. Implement BlueOutcome input and RedMutationDecision provenance; only timing/order/catalogue dimensions may change.
4. Add property tests for determinism, bounds, no live capability, plateau, and stop reasons.

### Wave 9: Red projection-causal mutation (Plan 01B)

1. Require every mutation to be caused by persisted Blue escape/falsification evidence and a bounded learned-state projection.
2. Reject static replay, agent-count-only, authority-bearing, or unpersisted mutation inputs with exact negative tests.

### Wave 10: Blue runtime and safety evidence (Plan 02)

1. Build Blue with build_composite_detector, ingest normalization, the six-argument Phase 286 ConfiguredRuntimeStack, GraphAuthorityHandoff/GraphSignerBinding, policy, and the configured recording DispatchingExecutor in DetectOnly with the real bounded worker queue.
2. Route replay/finding evidence through Phase 286 graph and containment planning; collect falsifications, policy, simulated receipt, rehearsal preview, and deterministic work.
3. Add fail-closed tests for live governed execution, policy bypass, invalid targets/evidence, missing receipt, and missing preview.
4. Keep Red unable to name action, approval, policy, response, ingest, or runtime capabilities.

### Wave 11: injected-clock virtual ingest proof (Plan 02B)

1. Prove deterministic injected-clock ingest, one-shot Phase 286 worker handoff, and disabled-first construction refusal.
2. Preserve the exact six-argument stack and real bounded worker/queue contract in the integration tests.

### Wave 12: candidates, partitions, and control (Plan 03)

1. Emit typed detector/response candidates with event/graph/falsification lineage, telemetry sources, expected coverage, safety constraints, and canonical IDs.
2. Evaluate historical, benign, counterexample, and frozen withheld partitions separately.
3. Run identical-stream single-agent control and persist paired digests; define virtual containment time, preview-derived blast radius, unseen fingerprints, deterministic resource score, and withheld relative score.
4. Persist signed campaign/outcome/mutation/candidate/pair/report envelopes with virtual timestamps and sequences.

### Wave 13: bounded runner and single-capture handoff (Plan 04)

1. Wire the bounded arena runner to the real ingest/Phase 286 capture path and prove single-source capture, adaptive causality, and safety.
2. Keep deterministic work, policy rehearsal, cleanup, and no-action behavior fail closed.

### Wave 14: acceptance and CI (Plan 05)

1. Add unit/property, real-runtime integration, compile-fail/static isolation, tamper/replay, and teardown tests.
2. Run three consecutive fixed-seed campaigns; require one genuine unseen fingerprint per run and all ARENA-07 thresholds.
3. Wire the bounded arena, independent report parser, and isolation script in a real offline workflow run step and check it with check-gates-wired.sh.
4. Stop at synthesis evidence; do not invoke promotion or deployment.

### Wave 15: independent review (Plan 06)

1. Review the combined tree only after the final gate and config inventory are
   green.
2. Record one anchored zero counter per P0/P1/P2 severity in each final
   artifact and map ARENA-01..08 to executed evidence.

`wave_0_complete` is never inferred from a file banner or plan numbering; it is
set only by the combined-tree preflight oracle after Plans 00J/00/00A/00B/00C/
00D/00E/00F/00G/00H/00I pass, including exactly 24 direct constructions across
the complete 23-path `SwarmConfig` inventory. Wave 13 is the bounded runner
(Plan 04), wave 14 is final acceptance/CI (Plan 05), and wave 15 is independent
review (Plan 06).

## Validation Architecture

The planning config sets workflow.nyquist_validation to true. Existing infrastructure is Cargo tests, integration tests in crates/swarm-runtime/tests, trybuild UI fixtures, and executable tools/check-*.sh scripts. Quick tests should stay fixture-only and under about 30 seconds; the full seeded benchmark is a phase/CI gate.

### Test Framework

| Property | Value |
|---|---|
| Framework | Cargo test, Rust 2024, trybuild 1.0 |
| Config | Workspace Cargo.toml |
| Quick Red | Registry-bound exact rows `287-00-01`, `287-01-01`, and `287-01-02` in `287-VALIDATION.md`; each uses the shared count helper and `--exact`. |
| Quick arena | Registry-bound exact rows `287-00-02`, `287-03-01`, `287-03-02`, and `287-03-03` in `287-VALIDATION.md`; each expected name is counted independently. |
| Runtime integration | Registry-bound exact rows `287-02-02`, `287-02B-01`, `287-04-01`, `287-04-02`, and `287-04-03` in `287-VALIDATION.md`; each uses the shared count helper and `--exact`. |
| Independent report parser | python3 tools/parse-arena-report.py |
| Isolation gate | CARGO_NET_OFFLINE=true bash tools/check-arena-isolation.sh |
| Full suite | The aggregate `cargo test --workspace --all-targets --locked --offline` appears only in final-audit row `287-05-03` of `287-VALIDATION.md`; every named TDD test remains helper-wrapped. |

### Phase Requirements to Test Map

| Req ID | Behavior | Test type | Automated command | File exists? |
|---|---|---|---|---|
| ARENA-01 | Valid grammar is deterministic and bounded; invalid/live/unknown primitives fail | unit/property | `287-VALIDATION.md` row `287-01-01`: `bash tools/check-arena-test-counts.sh --registry tools/arena-test-registry.json --task 287-01-01 --expect red_grammar_accepts_catalogued_multistage_campaign -- cargo test -p swarm-arena-red --test red_grammar --locked --offline -- --exact red_grammar_accepts_catalogued_multistage_campaign --test-threads=1` | No, preflight/1 |
| ARENA-02 | Events cross ingest, detector, runtime, graph, policy, and rehearsal paths without external effect | integration | `287-VALIDATION.md` row `287-02-02`: `bash tools/check-arena-test-counts.sh --registry tools/arena-test-registry.json --task 287-02-02 --expect blue_runtime_real_phase286_capture -- cargo test -p swarm-arena --test blue_runtime --locked --offline -- --exact blue_runtime_real_phase286_capture --test-threads=1` | No, preflight/2/4 |
| ARENA-03 | Mutation is caused by measured Blue projection and all stop conditions terminate | unit/integration | `287-VALIDATION.md` row `287-01B-01`: `bash tools/check-arena-test-counts.sh --registry tools/arena-test-registry.json --task 287-01B-01 --expect mutation_changes_from_measured_escape_or_falsification -- cargo test -p swarm-arena-red --test mutation_causality --locked --offline -- --exact mutation_changes_from_measured_escape_or_falsification --nocapture --test-threads=1` | No, 1/2/4 |
| ARENA-04 | Candidate IDs and event/graph/falsification/safety lineage round-trip | unit | `287-VALIDATION.md` row `287-03-01`: `bash tools/check-arena-test-counts.sh --registry tools/arena-test-registry.json --task 287-03-01 --expect candidate_selection_is_canonical_and_bounded -- cargo test -p swarm-arena --test candidate_lineage --locked --offline -- --exact candidate_selection_is_canonical_and_bounded --test-threads=1` | No, 3/4 |
| ARENA-05 | Partition dimensions and independent FP/work/safety/withheld gates block unsafe candidates | unit/integration | `287-VALIDATION.md` row `287-03-02`: `bash tools/check-arena-test-counts.sh --registry tools/arena-test-registry.json --task 287-03-02 --expect evaluation_partitions_reject_digest_or_withheld_mutation -- cargo test -p swarm-arena --test evaluation_partitions --locked --offline -- --exact evaluation_partitions_reject_digest_or_withheld_mutation --test-threads=1` | No, preflight/3/4 |
| ARENA-06 | Clean isolation passes; forbidden Red import/dependency and receipt/policy bypass fail | compile-fail/integration/script | `287-VALIDATION.md` row `287-00B-02`: `bash tools/check-arena-test-counts.sh --registry tools/arena-test-registry.json --task 287-00B-02 --expect red_capability_boundary_is_nonvacuous -- cargo test -p swarm-arena-red --test arena_red_isolation --locked --offline -- --exact red_capability_boundary_is_nonvacuous --test-threads=1`, plus `bash tools/check-arena-oracles.sh --self-test` | No, preflight/2/5 |
| ARENA-07 | Three consecutive seeded runs discover unseen evasions; paired medians meet improvement/safety/withheld thresholds | bounded benchmark | `287-VALIDATION.md` row `287-04-02`: `bash tools/check-arena-test-counts.sh --registry tools/arena-test-registry.json --task 287-04-02 --expect acceptance_metrics_meet_arena_07 -- cargo test -p swarm-arena --test adversarial_coevolution_arena --locked --offline -- --exact acceptance_metrics_meet_arena_07 --test-threads=1` | No, 3/4/5 |
| ARENA-08 | Fixed inputs produce byte-identical artifacts; tamper/replay/teardown and bounds fail closed | determinism/negative integration | `287-VALIDATION.md` row `287-04-03`: `bash tools/check-arena-test-counts.sh --registry tools/arena-test-registry.json --task 287-04-03 --expect reproducible_artifacts -- cargo test -p swarm-arena --test arena_teardown --locked --offline -- --exact reproducible_artifacts --test-threads=1` | No, 1/3/4/5 |

### Required negative fixtures

- Real miniature Cargo workspace where Red adds swarm-policy or swarm-response; clean fixture passes and broken fixture fails.
- Compile-fail source attempting swarm_response::adapters::SandboxExecutor or swarm_policy::ActionRequest from Red.
- Enforced governed action without dispatcher admission; must return GovernedActionRequiresAdmission.
- Empty target/evidence or missing policy/receipt/preview; must fail and be excluded from scores.
- Modified withheld manifest or replayed signed sequence; load must fail before evaluation.

### Wave 0 gaps

- crates/swarm-arena-red and crates/swarm-arena
- Phase 286 deterministic graph/containment adapter and virtual clock
- Clock-injected ingest entry point
- Versioned tactic/fixture catalog and immutable partition manifest
- Signed artifact stores and tamper/replay tests
- tools/check-arena-isolation.sh plus CI run entry
- Trybuild source and stderr snapshots

Existing adversary_emulation_integration.rs proves real detector/policy use for static event corpora, but it is not ARENA-03/07 evidence: it has no adaptive mutation, graph/planning result, withheld partition, or paired control.

## Sources

### Primary (HIGH confidence)

- CLAUDE.md — Rust-first production boundary, explicit modes, fail-closed response.
- docs/AGENTS.md — role/capability matrix, Pouncer authority, Kitten evolution boundary.
- .planning/phases/287-adversarial-co-evolution-arena/287-CONTEXT.md — binding shape and thresholds.
- .planning/REQUIREMENTS.md ARENA-01 through ARENA-08 — canonical acceptance contract.
- .planning/ROADMAP.md Phase 287 and .planning/STATE.md — dependency, scope, and evidence boundaries.
- crates/swarm-runtime/src/red_swarm.rs — static Red adapters.
- crates/swarm-runtime/src/replay/types.rs, harness.rs, metrics.rs, validation.rs, verification.rs — replay schema, static harness, separate class metrics, and fail-closed class checks.
- crates/swarm-runtime/src/service/stack.rs and service/runtime_service.rs — real event critical path and rehearsal APIs.
- crates/swarm-ingest-runtime/src/control.rs and ingest/mod.rs — real ingest/detector seam and current clock/action constraints.
- crates/swarm-core/src/signed_state.rs and crates/swarm-crypto/src/lib.rs — signed envelope, sequence checks, canonical bytes, and digests.
- crates/swarm-core/src/types.rs, crates/swarm-policy, crates/swarm-response/src/adapters.rs — typed actions, policy authority, sandbox receipts.
- crates/swarm-runtime/src/mutation/types.rs, mutation/harness.rs, mutation/stores.rs — existing genome/lineage/episode and signed persistence patterns.
- crates/swarm-runtime/src/evasion_coverage.rs and rulesets/evasion/attack-technique-catalog.yaml — current corpus/gap schema.
- crates/swarm-runtime/tests/adversary_emulation_integration.rs — closest real-stack but static integration.
- tools/check-workspace-layering.sh, tools/check-gates-wired.sh, and existing trybuild/negative tests — real clean/broken fixture and gate-wiring patterns.

### Secondary (MEDIUM confidence)

- .planning/phases/286-collective-hypothesis-graph/286-CONTEXT.md — required graph/uncertainty/containment contract, without implementation API.
- docs/benchmarks/ and docs/benchmarks/autonomous-evolution.md — historical static benchmark patterns, not adaptive arena evidence.

### Tertiary (LOW confidence)

- Exact Phase 286 public module names, deterministic method signatures, final tactic grammar fields, and production signer source remain unknown until Phase 286 lands.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — current workspace manifests and APIs were inspected.
- Architecture: HIGH for two-crate isolation and current Blue composition; MEDIUM for the future graph/clock adapter.
- Pitfalls: HIGH — directly evidenced by current replay/evolution, policy/receipt, and fixture-gate code.
- Measurement: HIGH for required thresholds and partition separation; MEDIUM for exact deterministic work-unit weights.

**Research date:** 2026-08-21
**Valid until:** 2026-09-04, or until Phase 286 lands and changes graph/ingest contracts.
