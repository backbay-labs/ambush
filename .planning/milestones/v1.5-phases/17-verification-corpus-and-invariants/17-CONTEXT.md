# Phase 17: Verification Corpus And Invariants - Context

**Gathered:** 2026-04-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Add a repo-owned verification corpus contract for candidate detectors. This phase defines the canonical known-bad coverage inputs, benign controls, threat-class templates, and resource budgets that later verification and shadow workflows will consume. It does not add promotion packets or live canary behavior.

</domain>

<decisions>
## Implementation Decisions

### Corpus Shape
- Introduce a tracked verification corpus manifest under `verifications/` instead of hardcoding invariant inputs in tests.
- Keep the first corpus narrow and aligned with the existing suspicious process-tree detector plus the `hellcat_office_v1` suite.
- Store resource budgets in the manifest itself so later verification commands can enforce repo-owned thresholds.

### Invariant Inputs
- Reuse the existing named replay suite as the known-bad coverage source.
- Reference benign controls explicitly as tracked scenario paths so false-positive checks stay inspectable.
- Add one canonical threat-class template for `execution` rather than inventing unused multi-class scaffolding.

### Integration
- Extend the offline replay module with manifest-loading and validation helpers instead of adding a parallel crate.
- Update existing experiment manifests to reference the canonical verification corpus they expect to pass.
- Document the verification corpus in `docs/CONFIGURATION.md` so future phases can reuse the same contract.

</decisions>

<specifics>
## Specific Ideas

`v1.4` already treats adversarial scenario misses and benign controls as the first practical safety floor. This phase should make that floor explicit and durable in repo-owned manifests so Phase 18 can report invariant-level pass/fail output instead of inferring it from tests.

</specifics>

<canonical_refs>
## Canonical References

### Product Direction
- `.planning/ROADMAP.md`
- `.planning/REQUIREMENTS.md`
- `.planning/PROJECT.md`
- `docs/EVOLUTION.md`

### Existing Code
- `.planning/milestones/v1.4-phases/15-candidate-strategy-evaluation/15-01-SUMMARY.md`
- `.planning/milestones/v1.4-phases/16-experiment-reports-and-offline-safety-gates/16-01-SUMMARY.md`
- `crates/swarm-runtime/src/replay.rs`
- `crates/swarm-runtime/src/bin/swarmctl.rs`
- `scenario-suites/hellcat-office-v1.yaml`
- `scenarios/`
- `experiments/`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DefaultReplayHarness` already loads tracked scenarios and suite manifests deterministically.
- Experiment manifests already provide candidate lineage and baseline-vs-candidate detector settings.
- The suite corpus already distinguishes adversarial and benign scenarios through tracked metadata.

### Established Patterns
- Offline safety inputs live as YAML manifests committed to the repo.
- The replay module validates manifests fail-closed before execution.
- Operator workflows are documented in `docs/CONFIGURATION.md` with concrete CLI examples.

### Integration Points
- Extend `crates/swarm-runtime/src/replay.rs` with verification-corpus manifest types and loaders.
- Add tracked corpus manifests under `verifications/`.
- Update `experiments/*.yaml` so candidates point at the canonical verification corpus.

</code_context>

<deferred>
## Deferred Ideas

- Real Z3 or proof-object integration
- Multi-threat-class verification corpora beyond the current suspicious process-tree detector
- Shadow, canary, and production promotion logic

</deferred>

---
*Phase: 17-verification-corpus-and-invariants*
*Context gathered: 2026-04-03*
