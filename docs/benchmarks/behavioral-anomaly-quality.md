# Behavioral Anomaly Quality Benchmark

Measured on 2026-04-12 with:

```bash
CARGO_TARGET_DIR=/tmp/sts-phase219-target cargo run -p swarm-runtime --release --example behavioral_anomaly_quality_benchmark
```

## Configuration

- Config: `rulesets/default.yaml`
- Behavioral profile: medium threshold `0.70`, high threshold `0.90`,
  high-confidence z-score `3.00`, baseline half-life `3600s`
- Actionable threshold: `0.85`
- Corpus: 16 labeled cases
  - 8 benign stale-normal cases
  - 8 anomalous novel-behavior cases
  - Families covered: process start, network connect, DNS query,
    authentication, registry access, registry persistence, file persistence,
    process memory access

## Measured Result

| Model | TP | FP | TN | FN | Catch rate | False-positive rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `current_deviation_scoring` | 8 | 0 | 8 | 0 | 1.000 | 0.000 |
| `legacy_fixed_arithmetic_control` | 8 | 8 | 0 | 0 | 1.000 | 1.000 |

**Outcome:** the shipped deviation-scoring detector preserved catch rate
`1.000` while reducing actionable false positives from `1.000` to `0.000`
relative to the reconstructed legacy fixed arithmetic control. That exceeds the
Phase 219 requirement for a 30%+ false-positive reduction without catch-rate
loss.

## Case-Level Output

| Case | Family | Label | Description | Current confidence | Current actionable | Legacy confidence | Legacy actionable |
| --- | --- | --- | --- | ---: | :---: | ---: | :---: |
| `process_stale_normal` | `process_start` | `benign` | stale but previously normal Office -> PowerShell launch | 0.781 | no | 0.900 | yes |
| `process_true_anomaly` | `process_start` | `anomalous` | new Office -> rundll32 execution with untrusted path | 0.900 | yes | 0.900 | yes |
| `network_stale_normal` | `network_connect` | `benign` | stale but previously normal svchost outbound flow | 0.781 | no | 0.900 | yes |
| `network_true_anomaly` | `network_connect` | `anomalous` | new svchost outbound flow to rare high port | 0.900 | yes | 0.900 | yes |
| `dns_stale_normal` | `dns_query` | `benign` | stale but previously normal updater DNS request | 0.781 | no | 0.860 | yes |
| `dns_true_anomaly` | `dns_query` | `anomalous` | new TXT-style DNS pattern on same process | 0.900 | yes | 0.860 | yes |
| `auth_stale_normal` | `authentication_event` | `benign` | stale but previously normal Kerberos service auth | 0.781 | no | 0.900 | yes |
| `auth_true_anomaly` | `authentication_event` | `anomalous` | new successful auth path to a different host | 0.900 | yes | 0.900 | yes |
| `registry_access_stale_normal` | `registry_access` | `benign` | stale but previously normal registry query pattern | 0.781 | no | 0.860 | yes |
| `registry_access_true_anomaly` | `registry_access` | `anomalous` | new registry credential material query | 0.900 | yes | 0.860 | yes |
| `registry_persistence_stale_normal` | `registry_persistence` | `benign` | stale but previously normal Run key value write | 0.781 | no | 0.860 | yes |
| `registry_persistence_true_anomaly` | `registry_persistence` | `anomalous` | new persistence Run key write under different hive | 0.900 | yes | 0.860 | yes |
| `file_stale_normal` | `file_persistence` | `benign` | stale but previously normal startup shortcut creation | 0.781 | no | 0.860 | yes |
| `file_true_anomaly` | `file_persistence` | `anomalous` | new startup shortcut path for updater | 0.900 | yes | 0.860 | yes |
| `memory_stale_normal` | `process_memory_access` | `benign` | stale but previously normal memory allocation pattern | 0.781 | no | 0.900 | yes |
| `memory_true_anomaly` | `process_memory_access` | `anomalous` | new RWX memory pattern into lsass | 0.900 | yes | 0.900 | yes |

## Notes

- The benchmark stays on the current shipped detector path. It evaluates the
  widened Phase 218 detector and compares its actionable decisions against a
  reconstructed legacy fixed-arithmetic control derived from the same emitted
  finding evidence.
- The corpus is repo-owned and synthetic. It is intended as a stable
  regression-quality baseline, not as a claim about real-world fleet
  prevalence.
