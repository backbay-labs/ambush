# Autonomous Evolution Benchmark

**Generated:** 2026-04-12  
**Reference host:** Apple M1 Max, 10 CPU cores, 32 GiB RAM, Darwin 26.4 (kernel 25.4.0)

## Benchmark Scope

This benchmark measures the bounded multi-generation autonomous evolution loop
introduced in Phase 198. The shipped example reuses the existing mutation,
materialization, validation, ranking, and population-refresh seams instead of
inventing a benchmark-only scoring path.

Common benchmark contract:

1. Baseline experiment: `experiments/office-baseline-control.yaml`
2. Detector: `suspicious_process_tree`
3. Tracked corpus: `evasion_breadth_v1@2026-04-10`
4. Fitness dimensions: measured catch-rate, false-positive rate, and latency
   fitness from the Phase 197 autonomous evaluation loop
5. Artifact isolation: the example stages the baseline experiment plus required
   scenario-suite and verification inputs into a temp root so generated mutation
   manifests do not modify the repo `experiments/` tree
6. Phase 199 adds explicit staged-baseline metrics to the persisted benchmark
   report so any published gain is tied to one exact seed experiment rather
   than inferred from later generations alone

Phase 198 stops at raw benchmark execution and durable delta reporting. It does
not publish an improvement claim when the measured run is flat.

## Reference Run

**Measured command:**

```bash
cargo run -p swarm-runtime --release --example evolution_benchmark
```

Reference run profile:

- generations: `3`
- max variants per generation: `2`
- population size: `8`
- Pareto tournament size: `2`

Measured results:

| Gen | Leader Generation | Leader Strategy | Measured Fitness | Delta Prev | Delta First | Catch Rate | FP Rate | Latency Fitness |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | `office_baseline_control_benchmark_g1_seed_control_2` | 0.656 | n/a | n/a | 0.143 | 0.000 | 0.994 |
| 2 | 2 | `office_baseline_control_benchmark_g2_bounded_crossover_2` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |
| 3 | 2 | `office_baseline_control_benchmark_g2_bounded_crossover_2` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |

## Expanded Search Run

**Measured command:**

```bash
STS_EVO_BENCH_GENERATIONS=10 \
STS_EVO_BENCH_MAX_VARIANTS=4 \
STS_EVO_BENCH_POPULATION_SIZE=16 \
STS_EVO_BENCH_PARETO_TOURNAMENT_SIZE=4 \
cargo run -p swarm-runtime --release --example evolution_benchmark
```

Expanded search profile:

- generations: `10`
- max variants per generation: `4`
- population size: `16`
- Pareto tournament size: `4`

Measured results:

| Gen | Leader Generation | Leader Strategy | Measured Fitness | Delta Prev | Delta First | Catch Rate | FP Rate | Latency Fitness |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | `office_baseline_control_benchmark_g1_seed_control_2` | 0.656 | n/a | n/a | 0.143 | 0.000 | 0.994 |
| 2 | 2 | `office_baseline_control_benchmark_g2_bounded_perturbation_1` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |
| 3 | 2 | `office_baseline_control_benchmark_g2_bounded_perturbation_1` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |
| 4 | 4 | `office_baseline_control_benchmark_g4_bounded_perturbation_1` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |
| 5 | 4 | `office_baseline_control_benchmark_g4_bounded_perturbation_1` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |
| 6 | 4 | `office_baseline_control_benchmark_g4_bounded_perturbation_1` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |
| 7 | 4 | `office_baseline_control_benchmark_g4_bounded_perturbation_1` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |
| 8 | 4 | `office_baseline_control_benchmark_g4_bounded_perturbation_1` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |
| 9 | 9 | `office_baseline_control_benchmark_g9_bounded_crossover_2` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |
| 10 | 10 | `office_baseline_control_benchmark_g10_bounded_crossover_3` | 0.656 | 0.000 | 0.000 | 0.143 | 0.000 | 0.994 |

## Conservative Seed Improvement Run

**Measured command:**

```bash
STS_EVO_BENCH_BASELINE_EXPERIMENT=experiments/office-conservative-control.yaml \
STS_EVO_BENCH_LABEL=office_conservative_control \
cargo run -p swarm-runtime --release --example evolution_benchmark
```

Conservative seed profile:

- generations: `3`
- max variants per generation: `2`
- population size: `8`
- Pareto tournament size: `2`
- staged baseline strategy: `office_conservative_control`
- staged baseline measured fitness: `0.633`
- staged baseline catch-rate: `0.086`
- staged baseline false-positive rate: `0.000`
- staged baseline latency fitness: `0.993`

Measured results:

| Gen | Leader Gen | Leader Strategy | Measured Fitness | Delta Prev | Delta First | Delta Baseline | Catch Rate | FP Rate | Latency Fitness |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | `office_conservative_control_benchmark_g1_gap_expansion_2` | 0.656 | n/a | n/a | 0.023 | 0.143 | 0.000 | 0.994 |
| 2 | 2 | `office_conservative_control_benchmark_g2_gap_expansion_2` | 0.656 | 0.000 | 0.000 | 0.023 | 0.143 | 0.000 | 0.994 |
| 3 | 2 | `office_conservative_control_benchmark_g2_gap_expansion_2` | 0.656 | 0.000 | 0.000 | 0.023 | 0.143 | 0.000 | 0.994 |

## Published Result

- The production-like `office_baseline_control` benchmark remains flat even
  across the expanded 10-generation search, so it is still a no-gain baseline
  rather than an improvement claim.
- The conservative seed benchmark provides real bounded headroom without
  inventing a benchmark-only scoring path: the staged baseline starts at
  measured fitness `0.633` and catch-rate `0.086`, while the bounded
  `autonomous_gap_expansion` leader reaches measured fitness `0.656` and
  catch-rate `0.143`.
- That run demonstrates a reproducible absolute catch-rate gain of `0.057`
  against the tracked evasion corpus while holding false-positive rate at
  `0.000` and slightly improving latency fitness from `0.993` to `0.994`.
- The winning recipe is bounded. It expands only missing suspicious
  parent/child process entries derived from the focused evasion scenario set,
  rather than widening thresholds or adding operator-authored detector logic.

## Findings

- The Phase 198 benchmark harness is reproducible and bounded: both runs
  completed from repo-owned inputs and persisted generation-over-generation
  benchmark artifacts without mutating the repo `experiments/` tree.
- The measured result on the current detector and corpus is flat. Catch-rate
  stayed at `0.143`, false-positive rate stayed at `0.000`, latency fitness
  stayed at `0.994`, and measured fitness stayed at `0.656` across both the
  reference run and the expanded 10-generation search run.
- Phase 199 closes with one honest improvement claim tied to the conservative
  seed benchmark: `suspicious_process_tree` improves from catch-rate `0.086`
  to `0.143` and from measured fitness `0.633` to `0.656` through bounded
  autonomous gap expansion.
