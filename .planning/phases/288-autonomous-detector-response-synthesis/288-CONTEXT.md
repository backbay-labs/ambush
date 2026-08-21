# Phase 288 Context: Autonomous Detector And Response Synthesis

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

