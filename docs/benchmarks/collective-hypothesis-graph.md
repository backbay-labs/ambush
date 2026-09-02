# Collective Hypothesis Graph benchmark

This benchmark tests collective causal reasoning, not detector concurrency or
agent count. The adjudicated corpus and its SHA-256 digests are frozen before
the graph implementation. Implementation code may load and revalidate these
files; it may not rewrite the oracle, baseline, thresholds, or denominators.

## Corpus

- `ambiguous-cross-telemetry.yaml` presents two live hypotheses and both
  corroborating and conflicting evidence from process, identity, Kubernetes,
  CloudTrail, network, and threat-intelligence sources.
- `withheld-kill-chain.yaml` supplies a multi-stage campaign with an intentional
  lateral-movement evidence gap. A correct reconstruction reports
  `missing_evidence`; it does not invent an edge.
- `manifest.yaml` fixes logical time, resource ceilings, 100 task identities,
  the paired single-agent and collective lanes, truth IDs, denominators, and
  acceptance thresholds.
- `collective-hypothesis-graph-baseline.json` binds the exact oracle bytes and
  records the single-agent control values.

The two lanes must receive identical corpus bytes, logical time, limits, and
truth. The collective lane may use hunter, challenger, and falsifier task
capabilities; the control uses one fixed investigator and no learned task
allocation.

## Gating metrics

All values use integer basis points and explicit denominators.

1. Median time to the correct causal hypothesis is fixture logical time from
   seed admission to the first evidence-valid adjudication. Missing convergence
   is censored at the manifest work limit.
2. Attack-chain recall is adjudicated stages recovered divided by five truth
   stages. A missing-evidence record is not a recovered stage.
3. False causal-edge rate is every admitted causal edge absent from the truth
   set divided by all admitted causal edges, including later-rejected edges.
4. Duplicate work is repeated actual task execution divided by 100 logical
   task identities. Losing a claim race without executing is not duplicate
   work.
5. Evidence coverage is adjudicated evidence claims linked to graph or
   kill-chain claims divided by sixteen required claims.

The collective lane passes only with at least 20% lower median hypothesis time,
at least 10 percentage points higher attack-chain recall, at most 10% false
causal edges, at most 5% duplicate work, and at least 90% evidence coverage.
Wall-clock latency and host load are observations only and cannot affect the
verdict.

`tools/check-collective-hypothesis-graph.sh` asserts exact test execution,
validates the report schema and denominators, checks the frozen digests, repeats
the deterministic run, and executes negative oracle and authority mutations.
