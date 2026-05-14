# Phase 278 Verification

status: passed

## Result

Phase 278 verification passed.

## Commands

- `cargo check -p swarm-runtime --bin swarm_detect`
- `cargo check -p swarm-runtime --bin swarm_debug_attest`
- `bash tools/run-integration-proof.sh`

## Verified Behaviors

- The repo-owned compose stack boots the runtime in `live_response` mode with
  verified startup attestation and one configured bridge-backed telemetry
  source.
- One encoded PowerShell process-start fixture triggers `suspicious_process_tree`
  on the shipped runtime path and drives the configured isolation playbook
  action.
- The proof run writes one CrowdStrike RTR mock interaction, one Splunk HEC
  delivery, and one replay bundle containing the executed response receipt.
