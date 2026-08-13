# Adversary Emulation Coverage

**Generated:** 2026-04-13
**Command:** `cargo run -q -p swarm-runtime --bin generate_adversary_emulation_report -- --output /tmp/adversary-emulation-report.json`
**Tracked baseline:** `docs/benchmarks/adversary-emulation-baseline.json`
**Enforced by:** `tools/check-adversary-emulation-coverage.sh`, in the
`proof-surfaces` job of `.github/workflows/ci.yml`

## Scope

This proof surface backs `v1.75` Phase 270. It combines the shipped
`scenario-suites/evasion-breadth-v1.yaml` corpus with the repo-owned
technique catalog at `rulesets/evasion/attack-technique-catalog.yaml` and the
runtime-wide detection pipeline.

The coverage report answers three operator questions:

1. which adversarial scenarios the repo ships today
2. which detector lanes each scenario is expected to exercise
3. how much of the mapped MITRE ATT&CK technique set lands in `detected`,
   `partial`, or `not_covered`

## Commands

```bash
bash tools/check-adversary-emulation-coverage.sh
```

That wrapper runs:

```bash
cargo test -p swarm-runtime --test adversary_emulation_integration -- --nocapture
cargo test -p swarm-runtime --lib -- --exact \
  evasion_coverage::tests::repo_adversary_emulation_coverage_report_meets_floor --nocapture
cargo run -q -p swarm-runtime --bin generate_adversary_emulation_report -- --output <tmp>
```

then asserts that each named test actually executed, and compares the generated
report field by field against `adversary-emulation-baseline.json`. The
comparison is what makes the table below falsifiable: the Rust test asserts only
`scenario_count == 7`, `technique_count >= 20` and `coverage_percent >= 0.60`,
so before the baseline existed a corpus that lost two techniques still reported
"Adversary emulation coverage OK: 7 scenarios, 21 techniques, 100.00%" and
exited 0 while this document claimed 23.

### Regenerating the baseline

```bash
cargo run -q -p swarm-runtime --bin generate_adversary_emulation_report -- --output /tmp/report.json
```

Copy the scalar fields, the sorted `techniques` list and the sorted `detected`
subset out of `/tmp/report.json` into
`docs/benchmarks/adversary-emulation-baseline.json`, and update the Results
table below from the same run. Populate the baseline from the report, never from
this table — a baseline seeded from a document is a gate that enforces whatever
the document happened to say.

## Scenario-To-Detector Mapping

| Scenario | Detector lanes |
| --- | --- |
| `evasion_execution_office_chains` | `suspicious_process_tree`, `suspicious_scripting` |
| `evasion_defense_evasion_fileless` | `fileless_execution`, `suspicious_scripting` |
| `evasion_command_and_control_network` | `network_connect` |
| `evasion_data_exfiltration_dns` | `dns_exfiltration` |
| `evasion_lateral_movement_remote_admin` | `lateral_movement` |
| `evasion_credential_access_harvest` | `credential_access` |
| `evasion_persistence_autostart` | `persistence` |

The suite also carries benign controls so the integration test can verify that
the mapped corpus stays realistic instead of only replaying obviously malicious
events.

## Results

| Metric | Value |
| --- | ---: |
| Adversarial scenarios | 7 |
| Unique mapped ATT&CK techniques | 23 |
| `detected` techniques | 4 |
| `partial` techniques | 19 |
| `not_covered` techniques | 0 |
| Overall mapped coverage | 100% |

The checked-in proof exceeds the required floor of 60% mapped technique
coverage.

Every row above was re-measured on 2026-08-13 against a real report run and
matched. All six are now compared exactly on every CI run; before that only the
`7` and the two floors were asserted anywhere in the repository.

## Interpretation

- `detected` means every mapped occurrence for the technique landed in a
  detector outcome with full scenario catch coverage.
- `partial` means at least one mapped occurrence was detected, but the technique
  still carries a deliberate or observed gap in another scenario occurrence.
- `not_covered` means none of the mapped occurrences reached the expected
  detector lanes.

Examples from the generated report:

- `T1204.002`, `T1218.005`, `T1218.011`, and `T1048.003` are currently
  `detected`
- `T1047` is covered through the lateral-movement scenario set and remains part
  of the passing floor test
- the remaining mapped techniques are presently `partial`, which is acceptable
  because the catalog explicitly records deliberate telemetry-bound gaps rather
  than silently treating them as regressions

## Notes

- The repo-owned catalog documents intentional gaps such as APC injection
  timing, WMI subscription persistence, and DoH-style C2 where the current
  telemetry contract is intentionally narrower than ATT&CK.
- The integration suite exercises the full configured detection pipeline rather
  than calling detector helpers in isolation.
- The generated JSON report is the CI-friendly surface; this document is the
  human-readable snapshot of the same proof run.
