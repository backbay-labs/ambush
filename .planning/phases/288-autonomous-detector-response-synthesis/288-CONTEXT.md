# Phase 288 Context: Autonomous Detector And Response Synthesis

## Objective

Generate defensive candidates from graph gaps, adversarial escapes, and falsifier findings, then select only candidates that improve measured outcomes without weakening safety. Synthesis is bounded and reviewable; it is not an unrestricted code-generation or autonomous deployment path.

## Required shape

- Detector candidates use the typed hypothesis/evidence vocabulary and identify signal features, detector family, addressed graph edges, and source evidence.
- Response-plan candidates use only the existing typed response library and policy vocabulary. Each names approval requirements, reversibility, blast-radius scope, and rollback expectations; synthesis cannot invent or directly invoke response adapters.
- Candidate evaluation runs historical attacks, benign controls, counterexamples, and withheld campaigns through the real replay/detection path and records catch rate, false positives, latency, resource cost, and causal-evidence coverage.
- Mutation, differential, and metamorphic controls demonstrate that an apparent gain is not an oracle weakening or fixture artifact.
- Promotion requires complete evidence lineage, reproducible evaluation, safety checks, solver/approval artifacts, and explicit operator review. Missing, stale, contradictory, or tampered evidence fails closed.

## Locked Phase 287 integration contract

Phase 288 consumes the completed Phase 287 arena; it does not recreate an ingest,
replay, graph, policy, artifact, or pairing seam. The concrete source boundary is
the Arena-owned adapter in `swarm-arena`:

The current public paths are `swarm_arena::blue::{BlueRuntimeAdapter,
BlueOutcome}`, `swarm_ingest_runtime::ingest::ArenaIngestResult`,
`swarm_runtime::hypothesis_graph::service::Phase286InvestigationCapture`,
`swarm_arena::artifacts::ArenaArtifactStore`,
`swarm_arena::evaluation::{Evaluator, PairReport}`,
`swarm_arena::learning::SignedBlueLearnedState`, and the current Blue module's
public `PartitionKind`/`VirtualArenaClock` types. The Phase 286 bridge remains
`swarm_runtime::hypothesis_graph::service::Phase286StrategyBridge`; its stack
composition is the six-argument runtime API named below. A changed or missing
path is a hard dependency failure, not permission to invent a provider trait.

```rust
BlueRuntimeAdapter::run(
    &self,
    campaign: &Campaign,
    learned_state: &SignedBlueLearnedState,
    target: &FixtureTarget,
    partition: PartitionKind,
    clock: &mut VirtualArenaClock,
) -> Result<BlueOutcome, BlueRuntimeError>

BlueOutcome::from_ingest_result(
    ArenaIngestResult,
    Option<DryRunTraversalReceipt>,
) -> Result<BlueOutcome, BlueRuntimeError>

BlueOutcome::red_projection() -> RedOutcomeProjection
Evaluator::compare_learning_and_single_agent(ControlInput) -> PairReport
ArenaArtifactStore::compare_and_append(
    stream,
    expected_generation,
    expected_predecessor_digest,
    fencing_token,
    signed_payload,
)
```

The Blue run must use the exact injected ingest seam from Phase 287:
`FixtureTarget::normalize_event(&FixtureEvent, GraphLogicalTime) ->
Result<TelemetryEvent, FixtureError>` followed by the async
`IngestState::process_bridge_event_at<D,P,E>(&self, TelemetryEvent, &dyn
GraphClock, &ArenaDetectionStrategyAdapter<D>,
&ConfiguredRuntimeStack<P,E,Phase286StrategyBridge>) ->
Result<ArenaIngestResult, String>` with the existing
`DetectionStrategy`/`ApprovalGate`/`ResponseExecutor` bounds, and the graph-only
`ConfiguredRuntimeStack::from_graph_components(config, policy, response, bridge,
authority, signer_binding)` six-argument composition. That stack is
`RuntimeMode::DetectOnly`, graph-enabled, investigation-enabled, and uses the
existing bounded worker/queue/one-submit path. An actionable result carries one
`Phase286InvestigationCapture`; a legal no-action result carries
`NoActionFindingReplay`; `Phase286InvestigationCapture.replay` is the only replay
carrier. Phase 288 must preserve that evidence, not infer a result from IDs or
re-run a generic harness.

The source-adapter mutation has one implementation path: clone the run-owned
config/campaign/target/clock, mutate only the admitted typed `DetectionConfig`,
construct the existing composite detector, wrap it in
`ArenaDetectionStrategyAdapter<D>::new(inner)`, and call the exact
`normalize_event` -> `process_bridge_event_at` seam above. The returned
`ArenaIngestResult` is then wrapped with
`BlueOutcome::from_ingest_result(ArenaIngestResult,
Option<DryRunTraversalReceipt>)`, evaluated by Arena's existing
`ArenaArtifactStore`/`Evaluator` path into a concrete `PairReport`, and only
then converted to Runtime views. This mutation does not inject a detector into
`BlueRuntimeAdapter::run`, use a test-only composition hook, or define a
provider trait; candidate/profile/event/verdict controls continue to use the
real `BlueRuntimeAdapter::run` path.

`crates/swarm-runtime/src/synthesis/arena_input.rs` is the one canonical owner
of the Runtime transfer boundary. It defines `ArenaSynthesisInput`,
`PairReportView`, and `ArenaArtifactView` (plus the typed outcome/no-action
views); `contracts.rs` may define shared source-role and canonicalization
primitives but must not define a second input or concrete Arena record. The
Runtime DTO contains typed views, IDs, digests, and proof fields only. It never
owns or imports `BlueOutcome`, `ArenaIngestResult`,
`Phase286InvestigationCapture`, `ArenaArtifactStore`, or concrete `PairReport`.

The crate graph is explicit: `swarm-arena` may depend on
`swarm-ingest-runtime` for `swarm_ingest_runtime::ingest::ArenaIngestResult`
and on `swarm-runtime` for the public Phase 286 bridge plus the Runtime DTO;
`swarm-runtime` must not depend on `swarm-arena` (directly or through a new
provider/feature edge). `swarm-arena` keeps Blue runs, the Phase 286 bridge, CAS/fencing through
`ArenaArtifactStore`, and `Evaluator::compare_learning_and_single_agent`.
`Phase287ArenaSynthesisAdapter` in `crates/swarm-arena/src/synthesis_adapter.rs`
is the sole conversion seam: it validates the concrete records and full signed
envelope, then emits the Runtime-owned `PairReportView`, `ArenaArtifactView`,
and `ArenaSynthesisInput`. The dependency is one-way (`swarm-arena` may depend
on `swarm-runtime`; Runtime must never depend on or execute Arena), and no
concrete Blue/CAS/pair operation may occur after the DTO crosses that boundary.
Every view preserves the producer role, schema version, canonical ID, content
digest, and the source fields required to reproduce the Arena result without
carrying raw telemetry or authority.

The DTO has an explicit outcome discriminant. `Actionable` requires one
`Phase286InvestigationCapture` and its sole `.replay`; `NoAction` requires
`phase286_capture == None` and `no_action == Some(NoActionFindingReplay)`, keeps
normalized-event/finding/deposit digests, and proves zero policy/receipt/
dispatcher/adapter traversal; `NoFinding` has neither capture nor no-action
evidence and is excluded from action-candidate scoring. A contradictory or
missing branch is rejected, while a valid `NoAction` remains a scoreable
false-positive/causal lane observation rather than being treated as an error.

The signed learned state is validated as a complete envelope before conversion:
kind, signer, stream, sequence, generation, predecessor digest, fencing token,
payload digest, signature, and expected schema must all match the
`SignedStateExpectation`. `SignedBlueLearnedState::verify_bounded` is required;
`SignedBlueLearnedState::empty_frozen()` is the paired control. Digest-only or
event-ID-only changes are not learning evidence.

Every signed synthesis packet/report also requires one present, nonempty
`EvolutionSolverInvariantArtifact` from
`crates/swarm-runtime/src/evolution/types.rs`. Its canonical JSON bytes,
computed canonical SHA-256 digest, existing `attestation_sha256`, and
`EvolutionSolverProofStatus::Proved` status are bound into the signed
packet/report and recomputed before canary and operator/quorum handoff. The
artifact's invariant name, solver, compiled-query digest, attestation, and
status must be nonempty/valid. Define the bound `canonical_solver_bytes`
projection before hashing so its observational `duration_ms` (and any other
wall-clock-only field) cannot affect the solver digest; deterministic status,
query, attestation, budget, and counterexample fields remain bound. Absent, disabled, malformed, stale,
digest-mismatched, or non-Proved invariant evidence fails closed.

The four Phase 288 lane fixtures are an independent oracle and manifest, not a
replacement for Arena evidence. Historical, benign, counterexample, and
withheld rows bind to the Phase 287 partition/campaign digest and are scored by
the actual Arena adapter. Candidate and empty-frozen control runs both invoke
`BlueRuntimeAdapter::run`; the withheld resolver remains evaluator-owned and
opaque until candidate lineage is frozen. A missing or changed upstream record
blocks the phase.

The ten `EvolutionDetectorGenome` families are a materialization contract, not
ten current Phase 287 learned-state families. This phase extends the locked
factory/typed-genome path for all ten, but Blue learned-state admission and
actual Arena evaluation are explicitly limited to the four existing
`DetectorStrategyFamily` values: `SuspiciousProcessTree`, `BehavioralAnomaly`,
`FilelessExecution`, and `DnsExfiltration`. The other six
(`LateralMovement`, `CredentialAccess`, `SuspiciousScripting`, `Persistence`,
`SupplyChain`, and `NetworkConnect`) are factory/materialization and
round-trip-tested only until a later Phase 287 Arena contract adds them; they
must not be smuggled into `SignedBlueLearnedState` or `BlueRuntimeAdapter::run`.

The implementation-tree input for final evidence is frozen by an explicit
allowlist, not by recursively hashing the planning directory. It includes only
the Phase 288 implementation paths:
`crates/swarm-runtime/src/lib.rs`, `crates/swarm-runtime/src/synthesis/**`,
the planned mutation files
`crates/swarm-runtime/src/mutation/{types.rs,autonomous.rs,fitness.rs,tests_core.rs,tests_autonomous.rs}`,
the pure-preview files
`crates/swarm-runtime/src/service/{runtime_service.rs,tests_preview.rs}`,
and the Phase 288 integration tests
`crates/swarm-runtime/tests/{synthesis_contract.rs,negative_synthesis_authority_boundary.rs,synthesis_integration.rs,synthesis_response.rs,synthesis_evaluation.rs,synthesis_controls.rs,synthesis_handoff.rs,synthesis_phase_gate.rs}`,
`crates/swarm-arena/src/{lib.rs,synthesis_adapter.rs}`,
`crates/swarm-arena/tests/{synthesis_adapter.rs,synthesis_evaluation_bridge.rs,synthesis_controls_bridge.rs}`,
the four lane files plus `manifest.yaml` under
`scenarios/autonomous-detector-response-synthesis/`, and the owned gate/parser
sources under `tools/{check-autonomous-detector-response-synthesis.sh,check-phase288-validation-map.py,parse-synthesis-review.py,compute-synthesis-tree-digest.py,compare-synthesis-artifacts.py}`
(plus Cargo manifests/lock only when a plan explicitly changes them). The
digest helper rejects symlinks, duplicate/out-of-scope paths, `.git`, `target`,
caches, worktrees, generated reports, review/verification/validation/summary
documents, `artifacts/synthesis/**`, and run roots. Phase 287 final-gate
evidence is bound separately by an immutable `phase287_evidence_digest` over
the exact retained paths `artifacts/phase287/final-gate/arena-report.json`,
`artifacts/phase287/final-gate/arena-lineage.json`, and
`artifacts/phase287/final-gate/final-gate-evidence.json`:
`SHA256(canonical_json_bytes(report) || "\n" || canonical_json_bytes(lineage)
|| "\n" || canonical_json_bytes(manifest))`. The manifest's
`final_gate_evidence_digest` remains the Phase 287
`SHA256(canonical_json_bytes(report) || "\n" || canonical_json_bytes(lineage))`
value and is passed to `check-phase287-review.py` as
`--final-gate-evidence-digest`; all three retained bytes, the recomputed
`phase287_evidence_digest`, and the four explicit final-evidence CLI paths are
bound into the Phase 288 run manifest, signed packet/report, and review
artifacts. Those upstream reports are observations and never inputs to the
implementation-tree digest. Review and validation documents bind to the frozen
tree digest after it is computed, so they cannot self-reference it.

## Measurement contract

Reports compare candidate quality and safety deltas with the single-agent/baseline strategy, including chain recall, false causal edges, evidence coverage, time to containment, blast radius, latency, and resource use. A candidate must improve at least one target metric by 10%, regress none of the safety ceilings, and pass every withheld-campaign and counterexample gate.

## Upstream contract precedence

The current Phase 287 context, Plans 02–06, and the independent 00I corpus-truth
contract are the authoritative interface/evidence specification for this phase;
older research describing those APIs as unknown is historical only. Phase 288
must not guess module paths, duplicate graph/arena
records, deserialize raw telemetry, or substitute a generic replay fixture. If a
required upstream record, capture, envelope, pairing digest, or partition digest
cannot be resolved, the candidate is blocked and the phase remains incomplete.

The withheld-campaign resolver is evaluator-owned. Synthesis receives only an
opaque handle and digest until candidate lineage is frozen; no checked-in path,
fixture bytes, or resolver capability may cross that boundary. Likewise, the
existing runtime playbook preview must remain pure: policy projection and
rehearsal are allowed, but containment/capability leases, receipts, adapters,
and live execution are not.
