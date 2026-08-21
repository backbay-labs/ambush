# Phase 287 Context: Adversarial Co-evolution Arena

## Objective

Build a bounded Red/Blue Co-evolution Arena that exercises the real Ambush investigation and containment-planning path. Red campaigns should adapt from observed blue behavior; blue should learn from escapes and falsified hypotheses. A larger agent count is not evidence of intelligence—the arena must show measurable improvement and generalization.

## Required shape

- Red agents compose multi-stage campaigns from the catalogued tactic/technique corpus using deterministic seeds, virtual time, event budgets, and isolated fixtures or sandbox targets. They cannot invent unbounded capabilities or access live targets.
- Blue agents investigate generated campaigns through real ingest, graph, detector, policy, and containment-planning boundaries. Red code has no response-adapter or policy-authority capability.
- Red mutation records the blue outcome that caused each surviving change in timing, ordering, or tactic composition. Campaigns terminate on generation, budget, plateau, or coverage bounds.
- Blue emits detector and response candidates from escapes and falsified hypotheses with evidence lineage, affected telemetry, expected coverage, safety constraints, and reproducible candidate IDs.
- Candidates compete on historical attacks, benign controls, counterexamples, and withheld campaigns. False positives, latency/resource cost, containment safety, and withheld generalization are separate dimensions.

## Measurement contract

Report time to containment, containment blast radius, previously unseen evasions, improvement over the single-agent baseline, and withheld-campaign generalization. Acceptance requires at least 15% median containment-time improvement, no increase in median blast radius, at least one previously unseen evasion in three consecutive seeded runs, at least 10% improvement over baseline, and withheld performance no worse than 5% relative to in-sample score.

## Safety boundary

Static and runtime isolation controls must fail closed if red code imports response execution, a blue simulation bypasses policy, or a generated action lacks the receipt/approval boundary. Include a negative fixture that proves the isolation check can fail. Arena results are evidence for synthesis, not permission to deploy a candidate.

