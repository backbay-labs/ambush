# Integration Proof

`v1.77` closes on one repo-owned Compose stack that proves the full bridge ->
detect -> respond -> deliver loop against mocked external systems.

## Topology

```text
generic_json bridge
  /runtime-data/input/attack-process.jsonl
        |
        v
swarm_detect (live_response, suspicious_process_tree)
        |
        +--> CrowdStrike RTR adapter
        |      -> crowdstrike-rtr-mock:8080
        |
        +--> Splunk HEC forwarder
               -> splunk-hec-mock:8088
```

The shipped proof assets live under `deploy/integration-proof/`:

- `runtime.yaml`: signed live-response config for the proof stack
- `Dockerfile`: debug-build image that generates local config and binary sidecars
- `compose.yaml`: bounded three-service topology
- `fixtures/attack-process.jsonl`: one encoded PowerShell process-start event
- `mocks/*.py`: deterministic CrowdStrike RTR and Splunk HEC sinks

## Flow

1. `proof-process-bridge` reads the JSON-lines telemetry fixture and normalizes it as a `process_start` event.
2. The bridge event is routed through the same `IngestState` and `RuntimeService` execution path used by the live ingest surface, then copied into the agent telemetry lane after the critical path completes.
3. `suspicious_process_tree` emits one critical execution finding for the encoded PowerShell child launched from `winword`.
4. The response playbook selects `isolate_host(host-1)`.
5. The policy layer allows that action in `live_response` mode.
6. The CrowdStrike RTR adapter exchanges OAuth credentials, then calls the isolate-device endpoint on the RTR mock.
7. The Splunk HEC adapter forwards the enriched finding as newline-delimited HEC events.
8. The runtime persists a replay bundle under `/runtime-data/replay` with the executed receipt details.

## Verification

Run:

```bash
bash tools/run-integration-proof.sh
```

The proof script validates four surfaces:

- `/healthz`: response adapter, SIEM transport, bridge count, and startup attestation readiness
- `/metrics`: bridge event count plus Splunk delivery counters
- mock sinks: OAuth + isolate calls on the RTR mock and one CIM-aligned finding on the HEC mock
- replay bundle: persisted audit receipt shows `crowdstrike_rtr` and `host_isolation`

Set `KEEP_PROOF_STACK=1` to leave the Compose stack running after the proof completes.
