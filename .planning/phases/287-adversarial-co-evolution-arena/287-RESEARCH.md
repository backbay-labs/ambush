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
| ARENA-02 | Blue runs through real ingest, graph, detector, policy, and containment planning; Red has no response/policy authority | Dedicated arena composition crate using real runtime/ingest seams, Phase 286 adapter, dry-run policy, SandboxExecutor, and rehearsal preview |
| ARENA-03 | Red mutates from measured Blue evidence and records causal lineage; all declared stop conditions apply | BlueOutcome-only mutation input, outcome/escape/falsification IDs, changed dimensions, and deterministic stop reasons |
| ARENA-04 | Blue emits evidence-linked detector and response candidates with reproducible IDs | Candidate records hash canonical parent/outcome/corpus inputs and carry graph/event/telemetry/safety lineage |
| ARENA-05 | Historical, benign, counterexample, and withheld competition dimensions stay separate | Immutable partition manifest and digest; separate catch, FP, work/latency, containment-safety, and withheld gates |
| ARENA-06 | Structural and runtime isolation fail closed, including a negative fixture | Forbidden dependency inventory, compile-fail import fixture, live/policy/receipt negative tests, and wired gate |
| ARENA-07 | Reports metrics and meets the five stated thresholds | Paired identical-stream single-agent control, virtual containment time, rehearsal blast radius, unseen fingerprints, improvement, and withheld score |
| ARENA-08 | Fixed inputs produce byte-identical decisions/lineage; runs are bounded and clean | Canonical digests, BTree ordering, injected clock, deterministic signer/sequence, wall guard only, and teardown assertions |
</phase_requirements>

## Summary

The current red seam is static. crates/swarm-runtime/src/red_swarm.rs contains SuiteRedSwarmAdapter, which concatenates event-backed replay scenarios, and MockRedSwarm, which returns a cloned vector. DefaultReplayHarness::run_loaded_scenario is also offline event replay. These are useful immutable fixture loaders and regression references, but they cannot satisfy adaptive mutation, measured Blue feedback, real graph/planning integration, or causal lineage. The arena must not call them as its co-evolution loop, and it must not claim intelligence from a larger agent count.

Use two new workspace seams. swarm-arena-red should be a capability-minimal crate that emits only typed fixture telemetry and campaign decisions. It must not depend on swarm-runtime, swarm-ingest-runtime, swarm-policy, swarm-response, or swarm-agents. swarm-arena should own orchestration and may depend on both the red crate and existing runtime/ingest crates without creating the existing swarm-runtime to swarm-ingest-runtime cycle. Keeping Red in the existing runtime crate is weaker because that crate already links policy and response.

The Blue side must process generated events through real ingest normalization and ConfiguredRuntimeStack/RuntimeService, then hand replay/finding evidence to the Phase 286 graph and containment-planning API. Policy must run in DetectOnly/dry-run mode and containment must be a rehearsal preview with a simulated receipt. Current ingest and async investigation code use wall-clock scheduling, so the arena needs a virtual-clock entry point or deterministic Phase 286 adapter; it must not score wall-clock or async completion order.

**Primary recommendation:** implement one deterministic arena evaluator around a catalog-bounded Red campaign interpreter and the real Blue runtime, with causal Red mutation from persisted Blue outcomes, paired identical-stream single-agent control, immutable partitions, and signed fail-closed artifacts.

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
| swarm-response | 0.1.0 workspace | Blue-side SandboxExecutor and simulated receipts | No external effects |
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
  src/mutation.rs     # BlueOutcome-driven bounded mutation

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

Sort ready events by virtual timestamp, ordering key, stage ordinal, then event ID. Use BTreeMap/BTreeSet for serialized/iterated collections. Derive every mutation choice from seed, parent digest, generation, Blue outcome digest, and mutation ordinal. Record seed, corpus digest, scheduler version, virtual start, and all limits.

Use separate max_generations, max_events, max_stages, max_virtual_ms, max_mutations, plateau_window, and coverage limits. A wall-clock watchdog may abort a hung process, but is guard_only and never scores or selects. Await/abort owned tasks, delete only the run-owned temp root, and assert no leaked files, sockets, child tasks, or mutable withheld handles.

### Pattern 3: Blue-outcome-driven Red loop

~~~text
immutable seed campaign
    -> real Blue run
    -> BlueOutcome (escapes, falsified hypotheses, policy/preview, work)
    -> RedMutationDecision(parent_digest, outcome_digest, cause, dimensions)
    -> validated bounded child campaign
    -> next generation or explicit stop
~~~

Each surviving mutation records parent campaign digest, exact BlueOutcome digest, escape event IDs, falsified-hypothesis IDs, selected dimension, old/new canonical values, mutation ordinal, and stop/budget state. Only timing offsets, ordering, and catalogued tactic composition may change. A test must vary measured Blue outcomes and prove the child changes; a static replay loop must fail.

Stop on generation, event/work, virtual duration, plateau, required coverage, or partition boundary and record the first stop reason.

### Pattern 4: Real Blue runtime with virtual clock

The existing real seam is ConfiguredRuntimeStack::from_components plus process_event_with_finding_observer, as used by tests/adversary_emulation_integration.rs:

~~~rust
config.runtime.mode = RuntimeMode::DetectOnly;
config.runtime.require_durable_live_response = false;
let detector = swarm_ingest_runtime::control::build_composite_detector(&config.detection)?;
let stack = ConfiguredRuntimeStack::from_components(
    config,
    ConfigurableApprovalGate::from_config(&config.policy),
    SandboxExecutor,
    phase_286_graph_strategy,
)?;
let outcome = stack.process_event_with_finding_observer(
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

This reaches substrate readiness, detector evaluation, deposits, enrichment, policy, dry-run response, replay persistence, and the investigation submission seam. Do not call a detector directly as the only Blue proof.

IngestState::process_bridge_event currently obtains now_ms from the wall clock and its detect-only request builder emits no action. The current InvestigationCoordinator also uses wall-clock queue times and spawned workers. Add an injected-clock arena entry point that preserves parse/normalization and the real stack, or use a deterministic Phase 286 graph/planning adapter after normalized ingest. Do not loop through HTTP, use production wall time, or silently substitute SummaryInvestigator if it bypasses Phase 286.

For containment candidates use ActionRequest, the configured policy gate, SwarmRuntime::audit_rehearse_authorize_and_execute_instrumented, or service::preview::build_rehearsal_preview. Require ResponseStatus::Simulated and typed blast-radius/rollback data. Never create an enforced executor or call an external adapter.

### Pattern 5: Identical single-agent control

For every seed, persist one campaign decision digest and run both the learning Blue evaluator and the single-agent control on identical campaign bytes, virtual clock, detector/config, graph input, policy config, signer, and scheduler. The control has one fixed investigator/strategy and no outcome-to-candidate learning; it is not a simplified mock. Reject a comparison when any paired digest differs. Do not use agent count as the primary metric.

### Pattern 6: Immutable evaluation partitions

Create a signed content-addressed manifest with historical_attacks, benign_controls, counterexamples, and withheld_campaigns. Each entry has canonical ID, class, source, content digest, corpus version, and partition digest. Load immutable in-memory data or a read-only run-owned copy; reject duplicates/path aliases/mutation. Withheld runs only after candidate lineage is frozen and emit no Red feedback. Historical suites can be inputs, but the static replay harness remains out of the arena loop.

### Pattern 7: Evidence-only candidate synthesis

Candidate records require candidate kind, canonical ID, parent/campaign/outcome digests, source event IDs, graph edge/hypothesis IDs, telemetry families, expected coverage, policy verdict, approval requirement, rehearsal preview, rollback, blast-radius constraints, and all partition scores. Current EvolutionDetectorGenome supports four families: suspicious process tree, behavioral anomaly, fileless execution, and DNS exfiltration; do not claim arbitrary genome support. Response candidates use only existing ResponseAction and policy/playbook vocabulary. Arena output feeds Phase 288 synthesis and never invokes promotion/canary.

### Pattern 8: Signed artifacts

Use SignedStateEnvelope for campaign decisions, Blue outcomes, mutation decisions, candidates, pair records, and final reports. Existing FileEvolutionEpisodeStore::open_signed and signed population stores are the pattern, but avoid their wall-clock created_at fields. Supply a configured signer; tests use a fixed SigningKey seed. Use fixed stream IDs and explicit monotonic sequences. Verify state kind, stream, signer, schema, signature, payload, and accepted sequence. Sign partition/withheld digests and fail closed on changed indexes or replayed sequences.

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
| Response simulation | Fake receipt/blast arithmetic | SandboxExecutor, rehearsal execution, build_rehearsal_preview | Typed receipt, policy attribution, rollback, blast radius |
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

Do not allow mutation feedback, shared mutable files, aliases, or candidate selection before withheld evaluation. Sign the partition digest.

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
let report = runtime
    .audit_rehearse_authorize_and_execute_instrumented(
        &finding,
        &request,
        &approval_with_virtual_now,
    )
    .await?;
// Assert the actual audit response contains a simulated receipt or a
// fail-closed policy/guard result; never accept a hand-built boolean.
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

1. **Phase 286 graph API:** source is not in this checkout. Define and require a deterministic graph/planning trait with evidence IDs, falsifications, virtual-clock input, and rehearsal output; do not duplicate or bypass it.
2. **Ingest clock:** current process_bridge_event uses wall-clock now_ms and detect-only suppresses action selection. Expose an injected-clock arena entry point that preserves parse/normalization and real runtime processing; never use an HTTP loopback.
3. **Tactic grammar:** current attack-technique-catalog.yaml describes detector gaps, not stage primitives. Add a deny-unknown-fields, versioned technique-to-fixture mapping and digest.
4. **Signer:** require a caller-supplied admitted role key; fixed seed only for reproducibility tests. Generated keys invalidate byte equality.
5. **Resource units:** exact Phase 286 graph counters are unknown. Define versioned deterministic counters for events, detector evaluations, graph work, policy evaluations, persistence bytes, and queue operations; wall-clock is non-gating.

## Plan-Sized Work Decomposition

### Wave 0: prerequisite contracts and fixtures

1. Freeze the Phase 286 graph/planning adapter and virtual-clock contract; construction fails if absent.
2. Add swarm-arena-red and swarm-arena manifests; enforce the Red forbidden-dependency inventory.
3. Define tactic-to-fixture grammar, immutable partition manifest, historical/benign/counterexample/withheld fixtures, and content digests.
4. Expose deterministic ingest entry point with virtual time without changing live ingest.
5. Add clean and deliberately broken isolation fixtures before trusting a passing scan.

### Wave 1: Red grammar and adaptive scheduler

1. Implement typed fixture primitives, catalog validation, deterministic IDs, target namespace checks, virtual clock, and all budgets.
2. Implement hash-derived choices and canonical campaign/decision digests.
3. Implement BlueOutcome input and RedMutationDecision provenance; only timing/order/catalogue dimensions may change.
4. Add property tests for determinism, bounds, no live capability, plateau, and stop reasons.

### Wave 2: Blue runtime and safety evidence

1. Build Blue with build_composite_detector, ingest normalization, ConfiguredRuntimeStack, policy, and SandboxExecutor in DetectOnly.
2. Route replay/finding evidence through Phase 286 graph and containment planning; collect falsifications, policy, simulated receipt, rehearsal preview, and deterministic work.
3. Add fail-closed tests for live governed execution, policy bypass, invalid targets/evidence, missing receipt, and missing preview.
4. Keep Red unable to name action, approval, policy, response, ingest, or runtime capabilities.

### Wave 3: candidates, partitions, and control

1. Emit typed detector/response candidates with event/graph/falsification lineage, telemetry sources, expected coverage, safety constraints, and canonical IDs.
2. Evaluate historical, benign, counterexample, and frozen withheld partitions separately.
3. Run identical-stream single-agent control and persist paired digests; define virtual containment time, preview-derived blast radius, unseen fingerprints, deterministic resource score, and withheld relative score.
4. Persist signed campaign/outcome/mutation/candidate/pair/report envelopes with virtual timestamps and sequences.

### Wave 4: acceptance and CI

1. Add unit/property, real-runtime integration, compile-fail/static isolation, tamper/replay, and teardown tests.
2. Run three consecutive fixed-seed campaigns; require one genuine unseen fingerprint per run and all ARENA-07 thresholds.
3. Wire the bounded arena and isolation script in a real workflow run step and check it with check-gates-wired.sh.
4. Stop at synthesis evidence; do not invoke promotion or deployment.

## Validation Architecture

The planning config sets workflow.nyquist_validation to true. Existing infrastructure is Cargo tests, integration tests in crates/swarm-runtime/tests, trybuild UI fixtures, and executable tools/check-*.sh scripts. Quick tests should stay fixture-only and under about 30 seconds; the full seeded benchmark is a phase/CI gate.

### Test Framework

| Property | Value |
|---|---|
| Framework | Cargo test, Rust 2024, trybuild 1.0 |
| Config | Workspace Cargo.toml |
| Quick Red | cargo test -p swarm-arena-red --lib |
| Quick arena | cargo test -p swarm-arena --lib |
| Runtime integration | cargo test -p swarm-arena --test adversarial_coevolution_arena -- --test-threads=1 |
| Isolation gate | bash tools/check-arena-isolation.sh |
| Full suite | cargo test -p swarm-arena -p swarm-arena-red -p swarm-runtime -p swarm-ingest-runtime -- --test-threads=1 |

### Phase Requirements to Test Map

| Req ID | Behavior | Test type | Automated command | File exists? |
|---|---|---|---|---|
| ARENA-01 | Valid grammar is deterministic and bounded; invalid/live/unknown primitives fail | unit/property | cargo test -p swarm-arena-red grammar scheduler determinism -- --test-threads=1 | No, Wave 0/1 |
| ARENA-02 | Events cross ingest, detector, runtime, graph, policy, and rehearsal paths without external effect | integration | cargo test -p swarm-arena --test adversarial_coevolution_arena blue_uses_real_runtime -- --test-threads=1 | No, Wave 0/2 |
| ARENA-03 | Mutation is caused by measured Blue outcome and all stop conditions terminate | unit/integration | cargo test -p swarm-arena --test adversarial_coevolution_arena adaptive_mutation_is_causal stop_reasons -- --test-threads=1 | No, Wave 1/2 |
| ARENA-04 | Candidate IDs and event/graph/falsification/safety lineage round-trip | unit | cargo test -p swarm-arena synthesis_candidate_ids lineage -- --test-threads=1 | No, Wave 3 |
| ARENA-05 | Partition dimensions and independent FP/work/safety/withheld gates block unsafe candidates | unit/integration | cargo test -p swarm-arena evaluation_partitions candidate_gates -- --test-threads=1 | No, Wave 0/3 |
| ARENA-06 | Clean isolation passes; forbidden Red import/dependency and receipt/policy bypass fail | compile-fail/integration/script | cargo test -p swarm-arena --test arena_isolation_compile_fail && bash tools/check-arena-isolation.sh | No, Wave 0/2 |
| ARENA-07 | Three consecutive seeded runs discover unseen evasions; paired medians meet improvement/safety/withheld thresholds | bounded benchmark | cargo test -p swarm-arena --test adversarial_coevolution_arena acceptance_metrics -- --test-threads=1 | No, Wave 3/4 |
| ARENA-08 | Fixed inputs produce byte-identical artifacts; tamper/replay/teardown and bounds fail closed | determinism/negative integration | cargo test -p swarm-arena --test adversarial_coevolution_arena reproducible_artifacts bounded_teardown -- --test-threads=1 | No, Wave 1/3/4 |

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
