# Phase 251 Verification

status: passed

## Commands

- `cargo test -p swarm-runtime --test bridge_registry_integration`
- `cargo test -p swarm-ingest-json --lib`
- `cargo test -p swarm-core config::tests:: --lib`
- `cargo check -p swarm-core -p swarm-ingest-json -p swarm-runtime`

## Verified Behaviors

- Windows Event Log, Sysmon, and auditd bridges all construct and run through the shared bridge registry.
- Shared bridge health and `swarm_bridge_events_processed` metrics report the new bridge fleet consistently.
- One end-to-end runtime proof shows Windows Event Log, Sysmon, and auditd events triggering existing detectors through the normal Whisker pipeline.
