# Phase 223 Verification

status: passed

## Result

Phase 223 verification passed.

## Commands

- `cargo fmt --all`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'control::tests::status_output_uses_live_runtime_origin' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'control::tests::readiness_reports_subject_sources_and_detector_activation' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'control::tests::first_run_reports_blocked_when_readiness_fails' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'control::tests::first_run_completes_detection_approval_and_proof' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'control::tests::playbook_preview_renders_branch_and_policy_summary' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'http::core::tests::status_route_returns_json_when_authorized' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'http::core::tests::status_route_rejects_unsupported_schema_version_header' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'ingest::tests::platform_runtime_status_endpoint_returns_live_status_envelope' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'ingest::tests::platform_runtime_status_surfaces_anti_tamper_report' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'ingest::tests::platform_runtime_status_surfaces_alert_tuning_recommendations' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-runtime --lib 'ingest::tests::platform_runtime_status_rejects_unsupported_schema_version_header' -- --exact --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-cli cli_parses_readiness_command -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo test -p swarm-cli playbook_preview_command_rejects_unsupported_output_schema_version -- --nocapture`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo check -p swarm-runtime -p swarm-cli`
- `CARGO_TARGET_DIR=/tmp/sts-phase223-target cargo run -p swarm-runtime --bin swarmctl -- status --config rulesets/default.yaml --output-schema-version 1 --json`

## Verified Behaviors

- Repo-owned control outputs now carry explicit `schema_version` metadata across
  status, readiness, first-run, playbook-preview, replay, investigation, and
  incident envelopes, and text-mode renderers surface that version explicitly.
- The authenticated operator surface and the scoped platform API now reject
  unsupported requested schema versions through one bounded
  `x-swarm-schema-version` negotiation seam instead of silently serving drifted
  JSON.
- `swarmctl` keeps the current compatibility lane at schema version `1`,
  rejects unsupported requested output versions locally, and the live JSON
  `status` command returns the new top-level `schema_version` field.
