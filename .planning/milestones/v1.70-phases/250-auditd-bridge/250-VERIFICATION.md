# Phase 250 Verification

status: passed

## Commands

- `cargo test -p swarm-ingest-json auditd::tests --lib`
- `cargo test -p swarm-core config::tests::sysmon_and_auditd_bridge_configs_round_trip --lib`

## Verified Behaviors

- Auditd auth records normalize into shared `AuthenticationEvent` payloads.
- Auditd `execve` records normalize into `ProcessStart` payloads.
- Auditd syscall-backed network and file records normalize into shared `NetworkConnect` and `FilePersistence` payloads without detector-specific rewrites.
