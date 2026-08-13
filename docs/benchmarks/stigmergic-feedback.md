# Stigmergic Feedback Benchmark

**Generated:** 2026-04-13
**Tracked baseline:** `docs/benchmarks/stigmergic-feedback-baseline.json`
**Enforced by:** `tools/check-stigmergic-feedback-benchmark.sh`, in the
`proof-surfaces` job of `.github/workflows/ci.yml`

## Benchmark Scope

This proof surface covers the two measurable requirements for `v1.73`:

1. recruitment-driven alert acceleration for a command-and-control replay
2. observation-count bounds for poisoning the learned behavioral baseline

The alert replay uses the shipped `network_connect` detector, signed pheromone
state, and `ConcentrationMonitor` on the runtime path. The sigma-shift proof
uses the shipped `behavioral_anomaly` detector and measures how many distinct
novel flows are required before a held-out flow drops below the aggregate
deviation thresholds used for confidence scoring.

## Commands

```bash
bash tools/check-stigmergic-feedback-benchmark.sh
```

That wrapper runs:

```bash
cargo test -p swarm-whisker --lib -- --exact \
  behavioral_anomaly::tests::behavioral_anomaly_quantifies_distinct_poisoning_observations_required_for_sigma_shifts --nocapture
cargo test -p swarm-runtime --test recruitment_integration -- --exact \
  recruitment_kill_chain_replay_reaches_alert_at_least_twenty_percent_faster --nocapture
```

then asserts that each named test actually executed and that every number below
matches the tracked baseline. Both assertions matter: a libtest name filter that
matches nothing still exits 0, so the bare `cargo test` invocations this wrapper
used to run went green when a test was renamed or deleted.

## Results

### Recruitment Replay

| Mode | Beacon samples to alert | Elapsed seconds to alert |
| --- | ---: | ---: |
| `baseline` | 4 | 180 |
| `recruited` | 3 | 120 |

Recruitment reaches `SwarmMode::Alert` **33.3% faster** on the replayed
command-and-control chain, which clears the required 20% bound.

### Baseline Poisoning Sigma Bounds

| Aggregate deviation band | Distinct poisoning observations required |
| --- | ---: |
| `<= 3 sigma` | 2 |
| `<= 2 sigma` | 4 |
| `<= 1 sigma` | 13 |

Interpretation:

- two distinct poisoning observations are enough to move a held-out novel flow
  below the 3 sigma band
- four are required to move it below 2 sigma
- thirteen are required to move it below 1 sigma

These counts are measured after a sixteen-observation warm baseline on the
`network_connect` behavioral family.

## Notes

- The recruitment replay is intentionally bounded to one threat class:
  `command_and_control`.
- The replay depends on trusted signed seed deposits and the live runtime
  escalation policy, so it measures the same path the operator uses.
- The sigma-count proof uses distinct novel destinations rather than replaying
  the same flow repeatedly; repeating one exact flow would be learned after the
  first observation and would not represent poisoning pressure.
- The sigma counts and the sixteen-observation warm baseline are compared
  against `stigmergic-feedback-baseline.json` on every CI run. The Rust test
  itself asserts only the ordering (`sigma_1 >= sigma_2 >= sigma_3 > 0`), so
  the baseline file — not the test — is what pins the exact values.
