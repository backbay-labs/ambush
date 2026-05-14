# Phase 240: Behavioral Anomaly Genome And Mutation Operators - Context

**Gathered:** 2026-04-13
**Status:** Ready for planning

<domain>
## Phase Boundary

This phase is limited to widening the existing evolution mutation and
materialization lane so `BehavioralAnomalyDetector` can participate alongside
the shipped suspicious process-tree detector. The required outcome is a typed
behavioral-anomaly genome plus bounded perturbation and crossover operators that
fit the current draft -> mutation spec -> materialization -> validation ->
population workflow.

</domain>

<decisions>
## Implementation Decisions

### Chosen Approach
- Introduce a detector-typed genome abstraction inside `swarm-runtime` mutation
  state instead of trying to keep encoding new detectors through the current
  suspicious-process-tree-specific override struct.
- Preserve the existing process-tree override path as a compatibility lane so
  already-shipped mutation specs, materializations, and tests do not regress
  while the new typed genome path is added.
- Add behavioral-anomaly autonomous recipes that stay bounded: control copy,
  numeric perturbation, and list-aware crossover across parent genomes.

### Constraint To Acknowledge
- Draft materialization in `drafting.rs` is still process-tree-specific today.
  For this phase, behavioral anomaly support only needs to land on the mutation
  harness path used by autonomous evolution and bounded benchmark generation.

### Deferred To Later Phases
- Fileless-execution and DNS-exfiltration genomes are Phase 241.
- Multi-detector benchmark orchestration and proof artifacts are Phases 242-243.

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- [crates/swarm-runtime/src/replay/core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/replay/core.inc) already has typed candidate manifests for `suspicious_process_tree`, `behavioral_anomaly`, `fileless_execution`, and `dns_exfiltration`.
- [crates/swarm-runtime/src/detector_factory.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/detector_factory.rs) can already build runtime detectors from those manifest variants.
- [crates/swarm-whisker/src/behavioral_anomaly.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-whisker/src/behavioral_anomaly.rs) exposes a fully typed `BehavioralAnomalyProfile` with validation and profile round-tripping.

### Current Limitation
- [crates/swarm-runtime/src/mutation/types.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/mutation/types.rs),
  [autonomous.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/mutation/autonomous.rs),
  [helpers.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/mutation/helpers.rs),
  and [fitness.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/mutation/fitness.rs)
  are still hard-coded around `SuspiciousProcessTreeProfile`.
- [crates/swarm-runtime/src/drafting.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/drafting.rs) persists materialization reports with a process-tree-only `profile` field.
- [crates/swarm-runtime/src/kitten_agent.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/kitten_agent.rs) currently serializes population candidate strategy details from that same process-tree-only materialization record.

### Integration Points
- `crates/swarm-runtime/src/mutation/types.rs`
- `crates/swarm-runtime/src/mutation/helpers.rs`
- `crates/swarm-runtime/src/mutation/autonomous.rs`
- `crates/swarm-runtime/src/mutation/fitness.rs`
- `crates/swarm-runtime/src/mutation/harness.rs`
- `crates/swarm-runtime/src/drafting.rs`
- `crates/swarm-runtime/src/kitten_agent.rs`
- `crates/swarm-runtime/src/mutation/tests_core.rs`
- `crates/swarm-runtime/src/mutation/tests_autonomous.rs`

</code_context>

<specifics>
## Specific Ideas

- Model the typed genome as an enum backed by the existing repo-owned detector
  profile structs, with a helper that converts to and from
  `DetectorCandidateManifest`.
- Keep `EvolutionMutationProfileOverrides` for the legacy suspicious
  process-tree path, but allow variants to carry a full typed target genome when
  the detector family needs richer mutation than parent/child string edits.
- For behavioral anomaly autonomous recipes, perturb the numeric sensitivity
  fields in bounded steps and use bounded list crossover on the parent/child and
  rare-tool lists so the resulting genome remains valid and explainable.

</specifics>

<deferred>
## Deferred Ideas

- No attempt to retrofit direct operator draft materialization for every
  detector family in this phase.
- No benchmark or proof claims yet; this phase only lands the detector-genome
  mutation plumbing for behavioral anomaly.

</deferred>
