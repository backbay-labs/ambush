# Phase 288: Autonomous Detector And Response Synthesis - Research

**Researched:** 2026-08-21
**Domain:** bounded Rust detector evolution, replay evaluation, and advisory response-plan synthesis
**Confidence:** HIGH for current Rust seams and rollout gates; MEDIUM for future Phase 286/287 graph and arena inputs

<user_constraints>
## User Constraints (from 288-CONTEXT.md)

## Objective

Generate defensive candidates from graph gaps, adversarial escapes, and falsifier findings, then select only candidates that improve measured outcomes without weakening safety. Synthesis is bounded and reviewable; it is not an unrestricted code-generation or autonomous deployment path.

## Required shape

- Detector candidates use the typed hypothesis/evidence vocabulary and identify signal features, detector family, addressed graph edges, and source evidence.
- Response-plan candidates use only the existing typed response library and policy vocabulary. Each names approval requirements, reversibility, blast-radius scope, and rollback expectations; synthesis cannot invent or directly invoke response adapters.
- Candidate evaluation runs historical attacks, benign controls, counterexamples, and withheld campaigns through the real replay/detection path and records catch rate, false positives, latency, resource cost, and causal-evidence coverage.
- Mutation, differential, and metamorphic controls demonstrate that an apparent gain is not an oracle weakening or fixture artifact.
- Promotion requires complete evidence lineage, reproducible evaluation, safety checks, solver/approval artifacts, and explicit operator review. Missing, stale, contradictory, or tampered evidence fails closed.

## Measurement contract

Reports compare candidate quality and safety deltas with the single-agent/baseline strategy, including chain recall, false causal edges, evidence coverage, time to containment, blast radius, latency, and resource use. A candidate must improve at least one target metric by 10%, regress none of the safety ceilings, and pass every withheld-campaign and counterexample gate.

The context file has no separate Claude's Discretion or Deferred Ideas section. No additional discretion or deferred scope is inferred.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| SYNTH-01 | The synthesis lane derives detector candidates from graph gaps, evasion escapes, and falsifier findings using typed templates or bounded mutations; each candidate names the signal features, detector family, hypothesis edges addressed, and source evidence. | Extend the typed genome boundary from four to all ten replay candidate families; add a synthesis envelope carrying features, family, graph-edge IDs, evidence IDs/digests, bounded recipe, and parent genome lineage. Feed graph/arena records through a typed adapter, not raw telemetry or free-form code generation. |
| SYNTH-02 | The lane derives response-plan candidates only from the existing typed response library and policy vocabulary, attaching approval requirements, reversibility, blast-radius scope, and rollback expectations. It cannot invent or directly invoke a response adapter. | Reference configured ResponsePlaybookConfig actions and render them through RuntimeService::playbook_preview and rehearsal_preview. Persist PolicyVerdict, approval summary, ResponseBlastRadiusPreview, ResponseRollbackPreview, and simulated_only evidence; never call ResponseExecutor or mutate policy/adapter configuration. |
| SYNTH-03 | Candidate evaluation runs historical attacks, benign controls, counterexamples, and withheld campaigns through the real replay/detection path, with deterministic reports for catch rate, false-positive rate, latency, resource cost, and causal-evidence coverage. | Reuse DefaultReplayHarness suite execution, detector_factory, detect_only RuntimeService, ReplayScenarioClass invariants, and verification corpus. Add an explicit four-lane synthesis corpus/report with deterministic work/resource and graph-evidence metrics; retain wall-clock latency as a non-gating observation. |
| SYNTH-04 | Mutation, differential, and metamorphic controls prove candidate gains are not artifacts of a weakened oracle: removing a candidate rule, swapping a source adapter, or mutating an expected verdict must produce the documented regression or block the candidate. | Add candidate-minus-rule, source-adapter-equivalence, expected-verdict mutation, and event metamorphic controls around the same replay verifier. Controls must first prove their mutation changed the input, then require the documented regression or fail closed; tampered fixtures and stale lineage must be rejected by digest checks. |
| SYNTH-05 | Promotion remains fail closed and operator-reviewed. A candidate without complete evidence lineage, safety checks, reproducible evaluation, and required solver/approval artifacts is rejected; accepted candidates produce a durable review packet and never silently replace the baseline. | Chain synthesis packet -> replay verification/shadow -> real assurance evaluator -> proof/solver -> canary -> production promotion and operator approval. Require Proved solver status at production promotion, exact baseline/lineage/digest matches, signed packet, quorum/votes where required, and an explicit retained baseline. |
| SYNTH-06 | The synthesis report records candidate quality and safety deltas against the baseline, including attack-chain recall, false causal edges, evidence coverage, time to containment, blast radius, latency, and resource use. A candidate must improve at least one target metric by 10% while regressing none of the safety ceilings and must pass every withheld-campaign and counterexample gate. | Keep detector metrics separate from response efficacy metrics. Compare every metric to the configured baseline and apply the 10% improvement/no-ceiling-regression/withheld-and-counterexample rule only after all controls and evidence gates pass. |
</phase_requirements>

## Summary

The repository already has most of the trusted substrate needed for this phase: typed detector profiles and a candidate factory, bounded mutation/population lineage, a real detect-only replay harness, benign/known-bad verification invariants, assurance and formal-proof artifacts, canary rollback, production promotion, and operator quorum. The largest structural gap is not a new detector engine. EvolutionDetectorGenome currently serializes only SuspiciousProcessTree, BehavioralAnomaly, FilelessExecution, and DnsExfiltration, while DetectorCandidateManifest and detector_factory support ten candidate families. Autonomous synthesis must close that 4-versus-10 gap at the genome/materialization seam with exhaustive typed matches. Runtime-only InfrastructureAnomaly, CloudTrail, and KubernetesAudit are not candidate-manifest families and should remain out of this phase.

The second gap is an evidence/reporting layer above replay. Existing StrategyExperimentMetrics intentionally covers detector catch/false-positive counts and wall-clock observations; it does not represent causal-edge quality, deterministic resource work, withheld campaigns, or response efficacy. Add a bounded synthesis orchestration/report that consumes graph and arena records by typed references, evaluates all four corpus lanes through the existing replay path, renders response plans through existing playbook/rehearsal preview APIs, and joins immutable digests. Keep detector quality (chain recall, catch rate, false causal edges, evidence coverage) separate from response efficacy (time to containment, blast radius, reversibility, approval and rollback posture).

**Primary recommendation:** add a new swarm-runtime synthesis boundary that orchestrates existing mutation, replay, assurance, canary, promotion, policy, and response-preview seams; extend EvolutionDetectorGenome to all ten DetectorCandidateManifest variants; store a signed, digest-addressed synthesis review packet; and make every proposed response plan advisory-only. Do not add an LLM/code-generation path, mutate policy/governance/admission/adapter configuration, or treat a passing boolean in a mutable artifact as evidence.

## Current Repository Facts And Constraints

### Active runtime boundary

CLAUDE.md and docs/AGENTS.md define the Rust crates under crates/ as canonical. Kitten owns bounded detector evolution and rollout preparation. It may materialize, replay-validate, rank, prove, and propose detector candidates; it must not mutate response behavior or bypass canary/promotion gates. Pouncer/Tom own response routing and governance. Direct ingest or a review surface cannot invoke an adapter.

The current lifecycle in docs/EVOLUTION.md is linear: pressure is observed; mutation/materialization artifacts are created; replay validation and ranking produce review-ready candidates; proof artifacts are attached; a verified candidate enters bounded canary; a successful canary enters bounded production promotion; operators inspect evidence and approve explicit actions. Phase 288 adds synthesis evidence to that lifecycle. It does not create a second lifecycle or a silent baseline replacement path.

### The 4-versus-10 detector family gap

DetectorCandidateManifest in crates/swarm-runtime/src/replay/types.rs and build_detector_from_candidate in crates/swarm-runtime/src/detector_factory.rs support these ten typed families:

| Candidate family | Typed profile |
|---|---|
| suspicious_process_tree | SuspiciousProcessTreeProfile |
| fileless_execution | FilelessExecutionProfile |
| behavioral_anomaly | BehavioralAnomalyProfile |
| dns_exfiltration | DnsExfiltrationProfile |
| lateral_movement | LateralMovementProfile |
| credential_access | CredentialAccessProfile |
| suspicious_scripting | SuspiciousScriptingProfile |
| persistence | PersistenceProfile |
| supply_chain | SupplyChainProfile |
| network_connect | NetworkConnectProfile |

EvolutionDetectorGenome in crates/swarm-runtime/src/mutation/types.rs currently has only the first four. Its strategy, from_candidate, to_candidate_manifest, profile_json, thresholds, and exhaustive materialization matches must all be extended. mutation/autonomous.rs currently dispatches bounded perturbation/crossover/seed generation for those four, and mutation/fitness.rs has a legacy override path that materializes only SuspiciousProcessTree. The typed target_genome path must become the only synthesis path for all ten; do not silently fall back to untyped overrides.

RuntimeDetector additionally has InfrastructureAnomaly, CloudTrail, and KubernetesAudit, plus a Noop kill_chain_sequence strategy. Those are runtime/config strategies, not members of the ten-variant candidate manifest. Do not broaden the candidate manifest to thirteen families in this phase. If those families need autonomous synthesis, that is a future manifest/schema decision with its own evidence and fixtures.

### Existing replay and gate behavior

DefaultReplayHarness in crates/swarm-runtime/src/replay/harness.rs evaluates an actual RuntimeService in RuntimeMode::DetectOnly with an in-memory pheromone substrate and SandboxExecutor. run_loaded_scenario drives process_event, inline investigation/correlation, and deterministic summary construction. Candidate experiments compare a configured rollout baseline to build_detector_from_candidate. Verification runs known-bad and benign controls and applies fail-closed scenario-class, class-enforcement, known-bad coverage, canonical-template, false-positive, and total-detection-budget invariants.

ReplayScenarioClass is deliberately not defaulted. Missing class and explicit Mixed are refused because Mixed would be exempt from both adversarial and benign invariants. Preserve this property when adding counterexample and withheld corpus selection.

Replay and canary/promotion code already separates deterministic gates from observations. Counts/rates over fixture content gate; wall-clock detect latency is recorded in ReplayEvaluationObservation, ExperimentObservation, CanaryObservation, and ProductionPromotionObservation but must not decide a verdict. A synthesis resource metric must therefore be a versioned deterministic work model, not a renamed wall-clock measurement.

### Existing assurance, solver, canary, and operator gates

- evolution/assurance.rs owns the private decision/provenance fields of EvolutionProposalAssuranceSummary. Production code must call evaluate_proposal_assurance; it must never construct a Passed summary literal or copy a passing boolean from another artifact.
- evolution/formal_safety.rs persists proof artifacts with manifest, genome, verification, lineage, bundle, solver, and attestation digests. Solver statuses are Proved, Counterexample, Timeout, ResourceLimit, Disabled, and Error.
- promotion.rs deliberately requires exactly EvolutionSolverProofStatus::Proved when require_solver_result_for_promotion is enabled. Missing, Disabled, Counterexample, Timeout, ResourceLimit, and Error all fail. The production gate deliberately does not consult the assurance allowed-status list; that list cannot turn Disabled into proof.
- canary.rs requires enabled canary configuration, assurance, matching experiment/verification/shadow lineage and baseline, passing verification/shadow, and no active run. Threshold rollback uses deterministic candidate-only rate, baseline-miss rate, and total detection budget; latency is observation.
- promotion.rs requires a completed canary with ReadyForPromotionReview, passing assurance and solver gates, baseline identity still active, no active promotion, and explicit approval/quorum/signature handling for the human-approval path. Promotion retains the old detector as fallback and records rollback.
- FileCanaryStore and production promotion stores are plain JSON replacement stores. Their reports are useful handoff artifacts but are not immutable attestations. A Phase 288 packet must bind their IDs and content digests and re-verify them at every handoff.

## Standard Stack

### Core

| Library/module | Verified version | Purpose | Why standard |
|---|---:|---|---|
| Rust workspace / swarm-runtime | Rust edition 2024, crate 0.1.0 | Synthesis orchestration and composition root | CLAUDE.md makes crates/ the canonical production path; existing evolution and replay seams live here |
| swarm-runtime::mutation | crate 0.1.0 | Typed genomes, bounded mutation recipes, population lineage/materialization | Existing Kitten lane already bounds variants and preserves parent genome hashes |
| swarm-runtime::replay | crate 0.1.0 | Detect-only real replay, deterministic reports, verification/shadow/review artifacts | Existing harness exercises RuntimeService rather than a test-only detector stub |
| swarm-runtime::evolution | crate 0.1.0 | Assurance decision, proof/solver artifacts, proposal queue and handoff | Existing private evaluator and proof digests are the trusted authority |
| swarm-runtime::detector_factory | crate 0.1.0 | Build all ten candidate detector families | Keeps candidate execution on the same typed factory used by replay/canary/promotion |
| swarm-whisker profiles | crate 0.1.0 | Typed detector genomes and event evaluation | Profile validation and deny_unknown_fields reject malformed candidate input |
| swarm-core response types/config | crate 0.1.0 | ResponseAction, ResponsePlaybookConfig, rehearsal/blast/rollback vocabulary | Existing action enum and playbook are the only response vocabulary synthesis may reference |
| swarm-policy | crate 0.1.0 | PolicyVerdict, ApprovalGate, ActionRequest semantics | Approval requirements come from the existing policy path, not a new synthesizer policy |
| swarm-response | crate 0.1.0 | Sandbox/dry-run executor boundary and containment rollback types | Response plans can inspect typed rehearsal/rollback data without invoking adapters |
| swarm-crypto | crate 0.1.0 | Canonical JSON bytes, SHA-256, Ed25519 detached signatures | Existing assurance and signed-state artifacts use these primitives |

The locked workspace was verified on 2026-08-21 with cargo tree -p swarm-runtime --locked --depth 1: serde 1.0.228, serde_json 1.0.149, serde_yaml 0.9.34+deprecated, sha2 0.10.9, ed25519-dalek 2.2.0, rand_core 0.6.4, and proptest 1. Internal crates are all 0.1.0. No new external dependency is required.

### Supporting

| Library/module | Verified version | When to use |
|---|---:|---|
| swarm-runtime::canary | crate 0.1.0 | Only after synthesis artifacts, assurance, verification, and shadow are joined; bounded live observation and rollback |
| swarm-runtime::promotion | crate 0.1.0 | Only after canary is complete and ready; solver Proved and operator/quorum path remain mandatory |
| swarm-runtime::service::preview | crate 0.1.0 | Response-plan preview/rehearsal, policy projection, blast radius, rollback; simulated only |
| swarm-spine | crate 0.1.0 | Existing replay, investigation, incident, and audit records used to derive evidence coverage and containment simulation inputs |
| trybuild | 1.0.120 | Structural negative tests where compile-time isolation of adapter/policy authority is useful |
| proptest | 1 | Bounded profile/digest/metamorphic property tests; keep generated inputs within declared fixture budgets |

**Installation:** none. Use the existing locked workspace; do not add a package or runtime.

## Architecture Patterns

### Recommended project structure

    crates/swarm-runtime/src/
    ├── synthesis.rs                    # new phase boundary: schemas, orchestration, metrics, controls, packet
    ├── mutation/
    │   ├── types.rs                    # ten-family EvolutionDetectorGenome and typed lineage
    │   ├── autonomous.rs               # bounded per-family recipes and graph/arena pressure adapter
    │   ├── fitness.rs                  # typed materialization and deterministic work/objective extraction
    │   └── stores.rs                   # reuse signed-state pattern; do not treat plain stores as immutable
    ├── replay/
    │   ├── types.rs                    # reusable candidate/suite reports and four-lane corpus references
    │   ├── harness.rs                  # expose crate-private real suite evaluation seam
    │   ├── metrics.rs                  # detector metrics and deterministic work, not response efficacy
    │   └── verification.rs             # fail-closed corpus/control invariants
    ├── evolution/
    │   ├── assurance.rs                # real assurance evaluator only
    │   └── formal_safety.rs            # proof/solver artifacts and counterexamples
    ├── service/
    │   ├── preview.rs                  # typed rehearsal/blast/rollback preview
    │   └── runtime_service.rs          # playbook preview only; no new execution route
    ├── detector_factory.rs             # exhaustive candidate construction
    ├── canary.rs                       # existing bounded admission
    └── promotion.rs                    # existing Proved/operator-gated promotion

    crates/swarm-runtime/src/synthesis/tests.rs
    crates/swarm-runtime/tests/synthesis_integration.rs
    crates/swarm-runtime/tests/promotion_solver_gate.rs  # existing negative gate to retain

If implementation chooses a submodule directory, keep synthesis.rs as the public crate boundary and place schemas under synthesis/types.rs, stores.rs, controls.rs, and tests.rs. Do not put graph-specific types in swarm-core until Phase 286 exposes a stable cross-crate contract; use a typed adapter trait or narrow input structs at the new boundary.

### Pattern 1: Typed detector genome with exhaustive family coverage

EvolutionDetectorGenome is the mutation representation; DetectorCandidateManifest is the replay/materialization representation. Add the six missing profile variants and update every match together:

    match candidate {
        DetectorCandidateManifest::SuspiciousProcessTree { profile, .. } => {
            EvolutionDetectorGenome::SuspiciousProcessTree { profile: profile.clone() }
        }
        DetectorCandidateManifest::FilelessExecution { profile, .. } => {
            EvolutionDetectorGenome::FilelessExecution { profile: profile.clone() }
        }
        DetectorCandidateManifest::BehavioralAnomaly { profile, .. } => {
            EvolutionDetectorGenome::BehavioralAnomaly { profile: profile.clone() }
        }
        DetectorCandidateManifest::DnsExfiltration { profile, .. } => {
            EvolutionDetectorGenome::DnsExfiltration { profile: profile.clone() }
        }
        DetectorCandidateManifest::LateralMovement { profile, .. } => {
            EvolutionDetectorGenome::LateralMovement { profile: profile.clone() }
        }
        DetectorCandidateManifest::CredentialAccess { profile, .. } => {
            EvolutionDetectorGenome::CredentialAccess { profile: profile.clone() }
        }
        DetectorCandidateManifest::SuspiciousScripting { profile, .. } => {
            EvolutionDetectorGenome::SuspiciousScripting { profile: profile.clone() }
        }
        DetectorCandidateManifest::Persistence { profile, .. } => {
            EvolutionDetectorGenome::Persistence { profile: profile.clone() }
        }
        DetectorCandidateManifest::SupplyChain { profile, .. } => {
            EvolutionDetectorGenome::SupplyChain { profile: profile.clone() }
        }
        DetectorCandidateManifest::NetworkConnect { profile, .. } => {
            EvolutionDetectorGenome::NetworkConnect { profile: profile.clone() }
        }
    }

The reverse match must produce a DetectorCandidateManifest accepted by build_detector_from_candidate. Tests must round-trip all ten variants and assert strategy ID, description, profile JSON, thresholds, candidate digest, and actual factory construction. Runtime-only families must produce an explicit UnsupportedDetector result at the synthesis boundary rather than a Noop candidate.

Use target_genome for all synthesized variants. Retain EvolutionMutationProfileOverrides only for compatibility with old manually-authored SuspiciousProcessTree mutation specs; a synthesis request using an unsupported legacy override must fail closed.

### Pattern 2: Bounded, evidence-addressed synthesis

Introduce a typed synthesis input adapter that accepts only:

- graph gap IDs and typed hypothesis-edge IDs from Phase 286;
- evasion escape IDs and falsifier IDs from Phase 287;
- signal feature names and normalized observation/schema references, not raw telemetry;
- source artifact IDs plus their digests;
- a deterministic seed, generator version, and maximum variant/feature/parent budgets.

The adapter should reject empty source evidence, unknown edge IDs, duplicate/conflicting lineage, cross-family crossover, unbounded lists, and source records whose digest no longer matches. Preserve the existing same-strategy parent restriction unless a future typed cross-family mapping is added; a generic profile merge across detector families is unsafe.

Each DetectorSynthesisCandidate should contain at least:

    candidate_id
    strategy_id
    description
    genome: EvolutionDetectorGenome
    detector_family
    signal_features
    addressed_hypothesis_edge_ids
    source_evidence_ids
    source_artifact_digests
    parent_strategy_ids and parent_genome_sha256 values
    recipe and bounded-mutation parameters
    graph/arena input digest
    corpus/config/ruleset references
    genome_sha256 and candidate_sha256

Candidate ID and content digest must derive from canonical payload bytes that exclude created_at_ms and other display-only timestamps. A changed source evidence list, graph digest, profile, recipe, or baseline lineage must produce a different ID/digest.

### Pattern 3: Response plans are references and previews, never authority

Response synthesis may select or summarize an action sequence already present in ResponsePlaybookConfig, but it must not mint an arbitrary ResponseAction or edit playbook/policy configuration. Resolve a candidate with RuntimeService::playbook_preview using ResponsePlaybookPreviewRequest. For every action, retain:

- the existing ResponseAction and stable action kind;
- ResponsePlaybookPolicyPreview: PolicyVerdict, rule name/reason, lease scope/expiry when previewed;
- ResponseRehearsalPreview with simulated_only=true;
- ResponseBlastRadiusPreview: scope kind/value, impact, affected capabilities, maximum affected scopes;
- ResponseRollbackPreview: required flag and concrete rollback steps;
- configured runtime mode and preview notes.

The plan's approval requirement is the existing PolicyVerdict/governance classification, not a new string policy. ResponseAction::requires_governance_receipt and governed_action_kinds remain the canonical destructive-action classification. A plan with no matching rule, denied policy, missing target scope, invalid rollback metadata, or an action not found in the configured playbook is blocked. Never call RuntimeService::process_event, audit_authorize_and_execute_instrumented, ResponseExecutor, DispatchingExecutor, or an adapter from synthesis.

This preserves the current negative behavior: playbook_action_for_finding returns None for a multi-action rule because the live executor supports one action and dropping the tail would be unsafe. Synthesis can report the full ordered preview as advisory evidence, but it cannot convert that preview into a one-action live request.

### Pattern 4: Four-lane evaluation through the real replay path

Define a versioned SynthesisEvaluationCorpus with four disjoint, digest-addressed selections:

| Lane | Existing source/seam | Required treatment |
|---|---|---|
| Historical attacks | DetectorExperimentManifest.corpus.suite via DefaultReplayHarness | Baseline and candidate run through the same detect-only RuntimeService; report chain recall/catch and regressions by scenario/technique |
| Benign controls | VerificationCorpusManifest.benign_controls via evaluate_verification_path | Count false positives with an enforced benign denominator; preserve class-declared/class-enforced invariants |
| Counterexamples | Replayable fixtures attached to falsifier/proof/verification cases | A counterexample reference without an executable fixture is incomplete evidence and blocks; run candidate and baseline over the same fixture and record whether the documented regression appears |
| Withheld campaigns | Separate operator-owned suite selected by digest and hidden from candidate generation | Candidate input receives only corpus ID/digest and budget; evaluator verifies disjointness from historical/benign/source evidence and gates generalization independently |

Where current DefaultReplayHarness keeps evaluate_suite_selection and run_loaded_scenario private, extract a pub(crate) candidate-suite method rather than creating another runner. It must call the same load/validation, build_detector_from_candidate, build_service, process_event, investigation/correlation, and deterministic-summary path. Do not compare only detector.evaluate output because that skips runtime evidence and policy path.

Reports must retain per-lane artifacts, corpus digest/version, scenario class, source adapter/schema, seed and virtual-time metadata, and exact baseline/candidate IDs. Do not collapse withheld or counterexample results into aggregate catch rate.

### Pattern 5: Separate detector quality from response efficacy

Detector metrics are derived from replay/detection and graph adjudication:

- attack-chain recall and catch rate over adversarial scenarios/techniques;
- false-positive rate and false-causal-edge rate over benign and adjudicated graph controls;
- causal-evidence coverage with an explicit denominator and source-evidence IDs;
- deterministic resource work (for example, event evaluations, findings/deposits, replay bundles, investigation/correlation writes) with a versioned work-model ID;
- latency measurements as observations, with a deterministic event/work budget available if a gate is required.

Response efficacy is derived from containment/rehearsal simulation, not detector counts:

- virtual time to containment or to a bounded containment plan;
- blast-radius scope and affected capabilities;
- reversibility/rollback completeness and predicted rollback cost;
- policy verdict, approval requirements, governance classification, and plan safety;
- response resource work under the same declared deterministic model.

Every report must carry separate DetectorMetrics, ResponseEfficacyMetrics, and their deltas. A response plan cannot claim detector catch-rate improvement, and a detector cannot claim containment-time improvement without a response simulation record. Apply the Measurement contract only after all dimensions exist and all safety controls pass.

### Pattern 6: Immutable, digest-addressed review packet

Build a SynthesisReviewPacket containing the candidate(s), response plan reference/preview, graph/arena lineage, all corpus/config/ruleset digests, detector metrics, response efficacy metrics, differential/metamorphic/mutation control reports, assurance/proof/solver references, and operator decision state. Compute content digest with canonical JSON and sign the packet or an envelope that binds its digest.

Use swarm_crypto::canonical_json_bytes and swarm_crypto::sha256_hex for content IDs. Use the swarm-core SignedStateEnvelope pattern for signer identity, state kind, stream ID, monotonic sequence, and signature verification. Add immutable-per-packet semantics: refuse a second packet with the same packet ID unless the exact content digest is identical, reject stale/replayed sequence, and never silently overwrite a prior packet. Existing FileEvolutionPopulationStore and FileEvolutionEpisodeStore provide signature/sequence examples, but their mutable current-state behavior is not sufficient by itself for immutable review history.

At every load/handoff, verify packet signature and expected signer; packet digest recalculation; candidate genome/candidate ID and parent genome digests; source graph/arena/evidence digests; baseline strategy ID and ExperimentLineage; experiment, verification, shadow, proof, assurance, canary, and promotion artifact digests; corpus version and withheld/counterexample disjointness; freshness/sequence and no duplicate/conflicting IDs; solver status, approval evidence, and operator decision; and all required controls. Any missing, stale, contradictory, or tampered reference returns a blocking error. Do not use an artifact's passed field as a substitute for this revalidation.

### Pattern 7: Plan-sized implementation decomposition

The planner should split the phase into these bounded work packages with a test gate after each:

1. **Wave 0 — contract and corpus fixtures.** Define synthesis input/candidate/response-plan/control/review-packet schemas, four-lane corpus manifest, disjointness/digest rules, deterministic work-model version, and graph/arena adapter traits. Add historical, benign, replayable-counterexample, and withheld fixtures without exposing withheld content to generation. This is a genuine gap: no synthesis schema, withheld suite, or Phase 286/287 stable input API exists in the current checkout.
2. **Wave 1 — ten-family typed genomes.** Extend mutation/types.rs, autonomous.rs, fitness.rs, materialization, and tests for all ten candidate families. Add bounded perturbation/seed/crossover logic per typed profile; preserve same-family parent restriction and max variant budgets. Assert unsupported runtime-only families fail closed.
3. **Wave 2 — detector candidate synthesis and lineage.** Add synthesis.rs orchestration from graph gaps/escapes/falsifiers, stable candidate IDs, feature/family/edge/evidence fields, source digest checks, reproducible seeds, and typed target_genome materialization. Do not use legacy untyped overrides.
4. **Wave 3 — advisory response-plan synthesis.** Resolve only configured playbook actions through service preview/rehearsal. Record policy/approval, blast radius, rollback, simulated-only, and response-plan digests. Add negative tests proving no adapter invocation, no policy mutation, no governance bypass, invalid scope rejection, and multi-action live-request refusal.
5. **Wave 4 — four-lane evaluator and metric separation.** Reuse the real replay suite seam; persist lane-specific reports, detector metrics, response efficacy metrics, deterministic work/resource counters, observations, and baseline deltas. Add class/disjointness checks and fail closed on missing replayable counterexamples.
6. **Wave 5 — differential/metamorphic/mutation controls.** Implement candidate-rule removal, source-adapter swap/equivalence, expected-verdict mutation, event-order/duplicate/normalization metamorphic cases, and candidate-profile mutation. Each control records mutation, expected relation, observed relation, and regression/block result. Validate that the control mutation actually changed the input before judging a result.
7. **Wave 6 — assurance, packet, and rollout handoff.** Mint real assurance and formal proof artifacts; assemble/sign immutable packet; verify all hashes at replay review, canary, and promotion boundaries; require canary readiness, solver Proved, baseline retention, and operator/quorum approval. Never auto-promote or replace baseline.
8. **Wave 7 — integration/observability.** Add render/status/CLI output for detector-versus-response metrics, controls, evidence lineage, and blocked reasons. Run combined-tree tests, fmt, clippy, and tamper/replay negative suites. Avoid claiming hosted/release completion from isolated local tests.

## Don't Hand-Roll

| Problem | Do not build | Use instead | Why |
|---|---|---|---|
| Detector construction | A new detector registry, dynamic code generation, or generic JSON predicate evaluator | EvolutionDetectorGenome -> DetectorCandidateManifest -> detector_factory::build_detector_from_candidate | The factory is exhaustive over the ten supported candidate families and applies profile validation |
| Bounded mutation | Ad hoc string/JSON profile edits or cross-family structural merges | Typed per-profile target_genome recipes in mutation/autonomous.rs with max parents/variants and deterministic seed | Existing profiles have family-specific invariants and normalization |
| Replay | A unit-only detector loop or synthetic score shortcut | DefaultReplayHarness real detect-only RuntimeService path | It preserves investigation, correlation, policy, audit, and deterministic summary behavior |
| Corpus safety | A new class enum with default values or aggregate catch-rate-only score | ReplayScenarioClass and existing verification invariants, plus a four-lane synthesis manifest | Default/mixed classifications can make safety checks vacuous |
| Response planning | New action strings, custom adapter calls, policy cloning, or direct ResponseExecutor access | ResponsePlaybookConfig, ResponseAction, RuntimeService::playbook_preview, rehearsal_preview, PolicyVerdict | Existing typed vocabulary is the authority boundary and provides scope/rollback previews |
| Hashing | Hashing pretty JSON, YAML text, timestamps, or caller-selected IDs | swarm_crypto canonical_json_bytes + sha256_hex; exclude display timestamps from IDs | Canonical bytes make lineage reproducible across serialization/order changes |
| Signatures/state | An unsigned mutable JSON synthesis report | SignedStateEnvelope pattern plus immutable packet IDs, sequence, expected signer, and digest verification | Existing plain mutation/canary/promotion stores can be overwritten and cannot attest content |
| Assurance | Constructing EvolutionProposalAssuranceSummary or copying a status | evolution::evaluate_proposal_assurance through the queue harness | Private decision/provenance fields prevent fabricated passing attestations |
| Solver gating | Treating assurance allowed statuses or Disabled as promotion proof | promotion::promotion_solver_block behavior: only Proved passes | Proposal assurance and production promotion answer different questions |
| Canary/promotion | A parallel synthesis deploy route | Existing DefaultCanaryHarness and DefaultProductionPromotionHarness | They retain baseline, roll back on deterministic thresholds, and preserve operator/quorum gates |
| Containment rollback | A plan-specific inverse action table | ResponseRehearsalPreview / swarm-response containment and rollback types | Each typed action already carries bounded scope and addressable inverse steps |

**Key insight:** the difficult part is evidence identity and separation of authority, not generating a profile. Reusing the existing typed factories, replay path, preview path, and rollout gates prevents a high-scoring candidate from becoming an unreviewed policy or adapter mutation.

## Common Pitfalls

### Pitfall 1: Closing only the obvious four-family match

**What goes wrong:** from_candidate is expanded but to_candidate_manifest, profile_json, autonomous dispatch, materialization, or detector factory tests still handle only four families. A six-family candidate either fails late or is silently reduced to a legacy override.

**Why it happens:** the four existing variants are repeated across several modules, and compile failures are hidden when tests cover only SuspiciousProcessTree.

**How to avoid:** add all ten variants in one change and table-test serialization, reverse conversion, factory construction, profile validation, bounded generation, materialization, and digest lineage. Keep runtime-only strategies explicit unsupported.

**Warning signs:** an exhaustive match still lists four arms, a target_genome branch has a wildcard, or materialization returns UnsupportedDetector for any of the ten candidate IDs.

### Pitfall 2: Graph/arena evidence is descriptive but not bound

**What goes wrong:** a candidate claims to address a graph edge or evasion escape by name, but the referenced source changed or is absent. Operators cannot reproduce why it was generated.

**How to avoid:** require typed source IDs, source digests, graph/arena corpus digests, producer/schema metadata, and deterministic seed/recipe. Recompute every digest before evaluation and handoff.

### Pitfall 3: Response synthesis accidentally becomes a second authority

**What goes wrong:** synthesis creates an ActionRequest, calls an adapter, mutates response playbook/policy rules, or treats a preview lease as execution authority.

**Why it happens:** ResponseAction is cloneable and playbook_preview internally creates an ActionRequest for policy projection.

**How to avoid:** candidate schema may carry only configured actions plus preview metadata. Keep preview calls in detect-only/simulated mode, do not expose the internal request/lease as an executable object, and add a recording executor/negative test proving no adapter call. Existing multi-action refusal remains mandatory.

### Pitfall 4: Aggregate catch rate hides safety regressions

**What goes wrong:** a candidate gains one attack while introducing benign false positives, false causal edges, larger blast radius, or worse withheld generalization; an aggregate score still rises.

**How to avoid:** report detector and response dimensions separately by lane, scenario, technique, edge, and action. Apply all safety ceilings and all counterexample/withheld gates before the 10% improvement rule.

### Pitfall 5: Wall-clock latency is accidentally made gating

**What goes wrong:** a loaded runner rolls back or blocks a candidate because Instant-based detect latency exceeds a budget.

**How to avoid:** keep latency in observation collections. Use a deterministic work-model counter for gating resource cost, with version and denominator recorded. Preserve replay/canary load-invariance tests.

### Pitfall 6: Counterexample or withheld controls are vacuous

**What goes wrong:** a counterexample is only a prose solver model, a withheld path is accidentally included in training/source evidence, or a missing class lets a scenario contribute to neither numerator nor denominator.

**How to avoid:** require executable counterexample fixtures (or mark a non-replayable solver case as blocking), require distinct corpus IDs/digests, reject missing/Mixed classes, and verify source/candidate input cannot read withheld content. Record lane ownership for every scenario.

### Pitfall 7: Digest and artifact ID are checked only at creation

**What goes wrong:** an operator swaps a verification, assurance, or canary artifact after synthesis; the packet still sees a passed boolean and proceeds.

**How to avoid:** store every referenced content digest in the signed packet and rehash loaded artifacts at each boundary. Verify baseline strategy, ExperimentLineage, corpus version, source IDs, signer, sequence, and freshness. Reject stale/contradictory/tampered content.

### Pitfall 8: Solver status is treated as a waiver-able quality flag

**What goes wrong:** Disabled/absent/Timeout solver evidence is allowed through because an assurance allow-list includes it or an operator waiver exists.

**How to avoid:** call the real assurance evaluator, then apply the existing production solver gate independently. Production candidate status must be Proved when required; a waiver cannot conjure proof.

### Pitfall 9: Baseline lineage is rewritten by mutation

**What goes wrong:** a candidate appears to be a child of a winning population genome but its ExperimentLineage.parent_strategy_id no longer matches configured production baseline, so canary/promotion either rejects it or an unsafe shortcut changes baseline scope.

**How to avoid:** retain both explicitly: parent genome IDs/digests in synthesis lineage and configured baseline parent_strategy_id in the experiment manifest. Require exact baseline at replay, canary, and promotion.

### Pitfall 10: Fixed replay signing seed is mistaken for operational identity

**What goes wrong:** deterministic replay signatures are reused as production agent authority.

**How to avoid:** label replay signatures simulation-only. Packet and operational artifacts use an admitted role signer and verify expected AgentId; production response authority remains dispatcher/governance-owned.

### Pitfall 11: Control mutations do not mutate anything

**What goes wrong:** a differential test reports regression even though the candidate rule was not removed, the source adapter did not change semantics, or expected-verdict mutation never reached the verifier.

**How to avoid:** persist before/after input digests, assert they differ, record intended relation, and fail closed when a mutation is a no-op. For metamorphic transformations, state whether equality, subset, or bounded delta is expected.

## Code Examples

These are verified repository patterns to preserve; synthesis-specific types are intentionally shown as pseudostructure rather than pretending they already exist.

### Canonical content digest

Source: crates/swarm-crypto/src/lib.rs, canonical_json_bytes and sha256_hex.

    let canonical = swarm_crypto::canonical_json_bytes(&payload)?;
    let content_sha256 = swarm_crypto::sha256_hex(&canonical);

Do not hash pretty JSON, YAML source, or timestamps that are display metadata.

### Real candidate replay and verification

Source: crates/swarm-runtime/src/replay/harness.rs.

    let (experiment, shadow) = replay_harness
        .evaluate_experiment_and_shadow_path(
            &experiment_path,
            &experiment_results_dir,
            &shadow_results_dir,
        )
        .await?;
    let verification = replay_harness
        .evaluate_verification_path(&experiment_path, &verification_results_dir)
        .await?;
    let review = replay_harness.create_promotion_review_packet(
        &experiment_path,
        &verification_results_dir,
        &verification.record.verification_id,
        &shadow_results_dir,
        &shadow.record.shadow_id,
        &review_results_dir,
    )?;

The synthesis evaluator should expose a crate-private generalized suite method rather than bypassing this detect-only service path.

### Advisory response preview

Source: crates/swarm-runtime/src/service/runtime_service.rs, service/preview.rs, and service/tests_preview.rs.

    let preview = service.playbook_preview(
        ResponsePlaybookPreviewRequest {
            threat_class,
            severity,
            confidence,
            mode,
        },
        prepared_at_ms,
    )?;
    if preview.actions.iter().any(|action| !action.rehearsal.simulated_only) {
        return Err(SynthesisError::ResponsePreviewNotSimulated);
    }

Do not pass an action from this preview to a response executor. The preview is evidence for an advisory ResponsePlanCandidate.

### Signed-state envelope pattern

Source: crates/swarm-core/src/signed_state.rs and crates/swarm-runtime/src/mutation/stores.rs.

    let envelope = SignedStateEnvelope::sign(
        SYNTHESIS_PACKET_STATE_KIND,
        packet.packet_id.clone(),
        signer_agent_id,
        sequence,
        packet.clone(),
        signing_key,
    )?;
    let verified = envelope.verify(SignedStateExpectation {
        state_kind: SYNTHESIS_PACKET_STATE_KIND,
        stream_id: &packet.packet_id,
        expected_signer_agent_id: Some(&expected_signer),
        accepted_sequence,
    })?;

For immutable packets, additionally reject an existing packet ID with a different content digest; existing population/episode replacement semantics alone are not enough.

### Fail-closed solver handoff

Source: crates/swarm-runtime/src/promotion.rs and tests/promotion_solver_gate.rs.

    match assurance.and_then(|summary| summary.solver.status) {
        Some(EvolutionSolverProofStatus::Proved) => continue_rollout(),
        None
        | Some(EvolutionSolverProofStatus::Disabled)
        | Some(EvolutionSolverProofStatus::Counterexample)
        | Some(EvolutionSolverProofStatus::Timeout)
        | Some(EvolutionSolverProofStatus::ResourceLimit)
        | Some(EvolutionSolverProofStatus::Error) => reject_rollout(),
    }

Do not replace this with a check of the assurance allowed-status list.

### Differential and metamorphic control record

The control result should be a typed record, not an unstructured test log:

    ControlResult {
        control_id,
        kind: CandidateRuleRemoved | SourceAdapterSwapped | ExpectedVerdictMutated | EventMetamorphic,
        before_input_sha256,
        after_input_sha256,
        expected_relation,
        observed_relation,
        documented_regression,
        passed,
        source_artifact_digests,
    }

Require before_input_sha256 != after_input_sha256 before evaluating documented_regression. If the expected relation is not observed, block the candidate.

## State Of The Art

| Previous/current approach | Phase 288 approach | Why it matters |
|---|---|---|
| Four mutation genome variants | Ten typed candidate-manifest variants; runtime-only families remain explicit unsupported | Removes late materialization failures and prevents generic untyped mutation |
| Timestamp-oriented autonomous variant IDs and plain mutation artifacts | Canonical payload-derived IDs plus parent/source/corpus digests in a signed immutable packet | Reproducible lineage survives reload and detects swaps/tampering |
| Aggregate replay catch/false-positive metrics | Four independent lanes with detector metrics, response efficacy, controls, withheld generalization, and deterministic work model | A candidate cannot hide safety regressions behind aggregate catch rate |
| Wall-clock latency in older gate designs | Separate observation fields; deterministic work/resource budget for gates | Load and machine variance cannot decide detector safety |
| Public/fabricatable assurance summary shape | Private evaluator/provenance plus real assurance and proof handoff | A caller cannot mint a Passed attestation by serialization |
| Assurance solver allowed-status list | Production promotion accepts only solver Proved when required | Disabled or absent solver evidence remains fail-closed |
| Response action selection from findings | Existing playbook/policy resolution and simulated rehearsal previews | Synthesis can describe a response plan without granting adapter authority |
| Mutable canary/promotion reports | Digest-bind those reports to an immutable synthesis packet and revalidate at each boundary | IDs and passed booleans alone do not prove content identity |

The current state is documented in docs/EVOLUTION.md and the Phase 285/322 changes in .planning/STATE.md. A green isolated branch or local script does not prove combined-tree or hosted/release correctness.

**Deprecated/outdated for this phase:**

- Treating EvolutionMutationProfileOverrides as the general synthesis format: it is SuspiciousProcessTree-only legacy behavior.
- Treating response plans as executable requests: Phase 288 must keep them advisory and preview-backed.
- Allowing a missing, Disabled, or non-Proved solver result through production promotion.
- Using a Mixed or defaulted replay class to satisfy evaluation without an adversarial or benign denominator.

## Open Questions

1. **What exact Phase 286 graph and Phase 287 arena types will be available?**
   - What we know: their contexts require typed hypothesis edges, source evidence, falsifier findings, escape lineage, candidate IDs, and reproducible seeds; no stable implementation API is present in this checkout.
   - What is unclear: module/crate names, field names, and whether graph records are signed or only digest-addressed.
   - Recommendation: define a narrow synthesis input trait/adapter keyed by typed IDs, producer role, schema version, and source digest. Make missing/unknown records blocking. Do not duplicate or guess graph schemas in swarm-runtime.
   - Confidence: MEDIUM.

2. **How should solver/proof counterexamples become replayable campaigns?**
   - What we know: existing VerificationCounterexample and EvolutionSolverCounterexample hold subject/reference/details or name/value models, while replay requires an executable scenario manifest.
   - What is unclear: whether Phase 287 will emit executable counterexample fixtures or only abstract models.
   - Recommendation: require a replayable counterexample fixture digest for SYNTH-03/04. Preserve abstract solver cases as lineage, but block the candidate if the required counterexample lane cannot execute through real replay.
   - Confidence: HIGH for the existing type limitation; MEDIUM for future arena export.

3. **What deterministic resource model should be gated?**
   - What we know: RuntimeMetricsSnapshot exposes stage successes/failures and wall-clock latency; existing replay/canary gates intentionally exclude latency.
   - What is unclear: whether Phase 286/287 define event/finding/graph operation counters.
   - Recommendation: define a versioned synthesis work model using deterministic counts (events, detector evaluations, findings/deposits, replay bundles, graph/evidence operations, response-plan operations). Record wall-clock as observation only. A missing work-model version or counter blocks admission.
   - Confidence: MEDIUM.

4. **Where should the withheld corpus live and who can read it?**
   - What we know: requirement demands withholding and disjoint evaluation, but current replay corpus manifests are repository-readable.
   - What is unclear: whether withheld fixtures are operator-owned, CI-provided, or encrypted/externally mounted.
   - Recommendation: make the evaluator accept a corpus digest and controlled path/handle; never pass withheld scenario content or paths into candidate generation. Verify disjointness and fail closed if corpus is absent or digest-mismatched.
   - Confidence: MEDIUM.

5. **Should Phase 288 expose a new CLI command?**
   - What we know: existing replay/evolution/canary/promotion commands and renderers are operator-facing; no synthesis command exists.
   - What is unclear: desired control-surface naming and whether Phase 287 already adds a candidate route.
   - Recommendation: first add a library harness and durable/rendered packet. Add a CLI only if the existing control surface can expose the same packet and does not create a second authority path.
   - Confidence: LOW.

## Validation Architecture

Validation is enabled by .planning/config.json (workflow.nyquist_validation: true). The workspace has Rust built-in tests, extensive in-module tests, integration tests under crates/swarm-runtime/tests and crates/swarm-response/tests, trybuild as a dev dependency, and no separate Jest/Pytest/Vitest configuration.

### Test Framework

| Property | Value |
|---|---|
| Framework | Rust built-in test harness with Tokio tests; workspace Rust edition 2024 |
| Config file | Cargo.toml workspace/package configuration; no separate test config |
| Quick run command | cargo test -p swarm-runtime synthesis --lib (after the new synthesis test module exists) |
| Focused existing commands | cargo test -p swarm-runtime replay --lib; cargo test -p swarm-runtime service::tests::preview --lib; cargo test -p swarm-runtime --test promotion_solver_gate; cargo test -p swarm-response --test negative_containment_and_rollback |
| Full suite command | cargo test --workspace --all-targets |
| Quality commands | cargo fmt --all -- --check; cargo clippy --workspace --all-targets -- -D warnings |

The quick command is a focused filter intended for per-task feedback; first-run compilation can exceed 30 seconds. Existing replay tests are the reference for deterministic repeatability, class-vacuity controls, and latency load invariance.

### Phase Requirements -> Test Map

| Req ID | Behavior | Test type | Automated command | File exists? |
|---|---|---|---|---|
| SYNTH-01 | All ten candidate manifest/profile variants round-trip through EvolutionDetectorGenome, bounded recipes, canonical digest, materialization, and detector_factory; graph-gap/escape/falsifier references are required and preserved | unit + integration | cargo test -p swarm-runtime synthesis::typed_genome --lib | No; Wave 0/1 |
| SYNTH-02 | Response candidates use only configured ResponseAction/playbook entries; previews expose policy/approval, simulated rehearsal, blast radius, and rollback; invalid scope and adapter/direct-execution paths fail closed | unit + negative integration | cargo test -p swarm-runtime service::tests::preview --lib and cargo test -p swarm-runtime synthesis::response_plan --lib | Existing preview tests; synthesis tests Wave 3 |
| SYNTH-03 | Historical, benign, replayable counterexample, and withheld campaigns run through the real replay/detection path; reports are deterministic and retain catch/FP/latency observation/work/resource/evidence coverage | integration + repeatability | cargo test -p swarm-runtime synthesis::four_lane_evaluation --lib | No; Wave 0/4 |
| SYNTH-04 | Rule removal, source-adapter swap, expected-verdict mutation, event metamorphic transform, and candidate-profile mutation produce documented regressions or block; no-op controls fail | adversarial integration | cargo test -p swarm-runtime synthesis::controls --lib | No; Wave 5 |
| SYNTH-05 | Missing/stale/contradictory/tampered packet lineage, missing assurance/proof, non-Proved solver, failed canary/shadow, baseline mismatch, and absent operator/quorum approval fail closed; accepted packet is durable and retains baseline | integration + negative | cargo test -p swarm-runtime synthesis::handoff --lib and cargo test -p swarm-runtime --test promotion_solver_gate | Existing solver tests; synthesis handoff Wave 6 |
| SYNTH-06 | Detector and response metrics are separate; baseline deltas include chain recall, false causal edges, evidence coverage, containment time, blast radius, latency, and resource work; at least one 10% target gain with no safety ceiling regressions and all withheld/counterexample gates required | integration + threshold property | cargo test -p swarm-runtime synthesis::measurement_contract --lib | No; Wave 4/6 |

### Sampling rate

- Per task commit: cargo test -p swarm-runtime synthesis --lib plus the nearest focused existing replay/service/promotion test.
- Per wave merge: cargo test -p swarm-runtime --all-targets and cargo test -p swarm-response --all-targets.
- Phase gate: cargo test --workspace --all-targets, cargo fmt --all -- --check, and cargo clippy --workspace --all-targets -- -D warnings; then inspect the durable packet and operator evidence before verification.

### Wave 0 gaps

- Synthesis input/candidate/response-plan/control/review-packet types and schema version.
- Stable Phase 286 graph and Phase 287 arena adapter contract; graph/escape/falsifier fixture IDs and source digests.
- Four-lane corpus manifest with executable counterexample fixtures, disjoint withheld suite, class enforcement, and corpus digests.
- Deterministic resource/work model and counters; current wall-clock RuntimeMetricsSnapshot fields are observations only.
- Immutable packet store with canonical digest, Ed25519 signer, expected signer, sequence/replay checks, and reject-on-conflict ID semantics.
- Synthesis test module/integration fixture directory and negative adapter/policy-authority fixture.
- Typed genome coverage for six missing DetectorCandidateManifest families and per-family bounded mutation recipes.

## Sources

### Primary (HIGH confidence)

- .planning/phases/288-autonomous-detector-response-synthesis/288-CONTEXT.md — locked objective, required shape, and measurement contract.
- .planning/REQUIREMENTS.md SYNTH-01..SYNTH-06 — mandatory acceptance behavior and exact 10%/safety/withheld thresholds.
- .planning/ROADMAP.md Phase 288 — dependency on Phase 287, success criteria, and accepted status.
- CLAUDE.md — Rust canonical runtime, explicit runtime modes, fail-closed live response, and workspace commands.
- docs/AGENTS.md — Kitten evolution boundary, Pouncer/Tom governance chain, and prohibition on response/admission bypass.
- docs/EVOLUTION.md — bounded evolution lifecycle, detection-only scope, proof/canary/promotion contract, and no-proof-no-promotion posture.
- crates/swarm-runtime/src/mutation/types.rs — current four-variant EvolutionDetectorGenome and legacy override seam.
- crates/swarm-runtime/src/mutation/autonomous.rs — bounded autonomous recipes, same-family parent selection, and source/population genome hashes.
- crates/swarm-runtime/src/mutation/fitness.rs — typed target_genome materialization, manifest/lineage hashes, and deterministic population objectives.
- crates/swarm-runtime/src/mutation/stores.rs — signed population/episode envelope and sequence verification patterns; plain mutation stores are not immutable.
- crates/swarm-runtime/src/replay/types.rs — ten DetectorCandidateManifest variants, scenario classes, experiment/verification reports, detector metrics, and observations.
- crates/swarm-runtime/src/replay/harness.rs — real detect-only replay, experiment/shadow/verification/review orchestration, and baseline lineage checks.
- crates/swarm-runtime/src/replay/metrics.rs and replay/verification.rs — deterministic detector gates, class/enforcement invariants, counterexamples, and non-gating latency observations.
- crates/swarm-runtime/src/detector_factory.rs — exhaustive ten-family candidate construction and runtime-only strategy distinction.
- crates/swarm-runtime/src/service/runtime_service.rs, service/preview.rs, service/types.rs, and service/tests_preview.rs — playbook policy preview, typed rehearsal, simulated-only blast radius/rollback, and multi-action fail-closed behavior.
- crates/swarm-core/src/types.rs, config/pheromone.rs, and config/response.rs — ResponseAction, playbook, policy-facing and rollback vocabulary.
- crates/swarm-policy/src/lib.rs, static_gate.rs, and configurable_gate.rs — ActionRequest/PolicyVerdict/approval semantics and governed action classification.
- crates/swarm-response/src/containment.rs, rollback.rs, and tests/negative_containment_and_rollback.rs — bounded containment leases and inverse/rollback controls.
- crates/swarm-runtime/src/evolution/assurance.rs, evolution/formal_safety.rs, and evolution/harnesses.rs — private assurance evaluator, proof/solver digest lineage, counterexamples, and queue handoff.
- crates/swarm-runtime/src/canary.rs — assurance/verification/shadow/baseline admission and deterministic threshold versus observation split.
- crates/swarm-runtime/src/promotion.rs and crates/swarm-runtime/tests/promotion_solver_gate.rs — Proved-only solver gate, baseline retention, human approval/quorum, and rollback.
- crates/swarm-crypto/src/lib.rs and crates/swarm-core/src/signed_state.rs — canonical JSON, SHA-256, Ed25519, and signed-state verification.
- Cargo.toml, Cargo.lock, and cargo tree -p swarm-runtime --locked --depth 1 — workspace Rust/dependency versions verified 2026-08-21.

### Secondary (MEDIUM confidence)

- .planning/phases/286-collective-hypothesis-graph/286-CONTEXT.md — planned typed graph/evidence/contradiction/task-ledger inputs; implementation API not yet present.
- .planning/phases/287-adversarial-co-evolution-arena/287-CONTEXT.md — planned deterministic arena escapes, blue candidates, counterexample/withheld evaluation, and isolation constraints; implementation API not yet present.
- .planning/STATE.md — current milestone/evolution history and warnings about combined-tree evidence, solver posture, and signed lineage; live code remains authoritative.

### Tertiary (LOW confidence)

- None. No web-only or unverified ecosystem claims were used. Future Phase 286/287 type names and withheld-corpus ownership remain open questions rather than asserted facts.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — resolved from workspace manifests/lockfile and existing production modules.
- Architecture: HIGH for current module seams and gate behavior; MEDIUM for the new synthesis boundary because no implementation exists yet.
- Detector family resolution: HIGH — ten candidate variants are exhaustive in replay types/factory, four are exhaustive in current mutation genome.
- Response boundary: HIGH — existing playbook/rehearsal APIs and docs/AGENTS.md explicitly prohibit synthesis/Kitten response mutation or adapter authority.
- Evaluation metrics: HIGH for detector replay metrics and latency observation split; MEDIUM for deterministic resource and causal-evidence formulas pending Phase 286/287 outputs.
- Withheld/counterexample contract: HIGH for the requirement and current fail-closed replay constraints; MEDIUM for future fixture delivery.
- Promotion safety: HIGH — assurance evaluator, solver gate, canary, promotion, operator/quorum tests are present and explicit.

**Research date:** 2026-08-21
**Valid until:** 2026-09-04, or until Phase 286/287 land new graph/arena APIs or the replay/promotion contracts change.
