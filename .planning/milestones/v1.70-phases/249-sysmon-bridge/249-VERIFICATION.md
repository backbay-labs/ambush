# Phase 249 Verification

status: passed

## Commands

- `cargo test -p swarm-ingest-json sysmon::tests --lib`
- `cargo test -p swarm-core config::tests::sysmon_and_auditd_bridge_configs_round_trip --lib`

## Verified Behaviors

- Sysmon process-create records normalize into `ProcessStart` payloads with signer context.
- Sysmon network-connect records normalize into `NetworkConnect` payloads.
- Sysmon file-create records normalize into `FilePersistence` payloads.
