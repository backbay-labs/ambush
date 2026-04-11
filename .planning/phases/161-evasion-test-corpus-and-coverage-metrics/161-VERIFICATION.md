# Phase 161 Verification

status: passed

## Result

Phase 161 verification passed.

## Commands

- `cargo fmt --all`
- `cargo test -p swarm-runtime evasion_coverage::tests:: -- --nocapture`
- `cargo test -p swarm-runtime detection::metrics::tests::encode_metrics_renders_evasion_coverage_gauges -- --exact`
- `cargo test -p swarm-runtime platform_evasion_coverage_endpoint -- --nocapture`
- `cargo test -p swarm-runtime ingest::tests::metrics_include_evasion_coverage_gauges -- --exact`
- `cargo check -p swarm-core -p swarm-runtime --tests -j 1 --message-format short`

## Verified Behaviors

- The repo-owned evasion suite now yields at least ten payloads per threat class and loads catalog-backed intentional-gap rationale for supported detectors.
- The runtime encodes per-detector and per-threat-class evasion catch-rate gauges into Prometheus output under the `swarm_evasion_*` metric family.
- The authenticated coverage endpoint returns filtered detector snapshots and rejects unknown detector selectors with a structured bad-request response.
- Mounted or external config paths still resolve the checked-in evasion suite because repo-root discovery now searches plausible ancestors instead of assuming the config lives under `rulesets/`.
