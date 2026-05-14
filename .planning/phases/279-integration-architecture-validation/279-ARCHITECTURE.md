# Integration Architecture

## Shipped Flow

```text
attack-process.jsonl
  -> GenericJsonBridge (proof-process-bridge)
  -> bridge ingest processor
  -> IngestState::process_bridge_event
  -> RuntimeService::process_event_with_finding_observer
  -> suspicious_process_tree finding
  -> response playbook + policy allow
  -> CrowdStrike RTR adapter
  -> Splunk HEC forwarder
  -> replay bundle + health + metrics
  -> telemetry copy into admitted whisker agent lane
```

## Key Runtime Identifiers

- Bridge name: `proof-process-bridge`
- Bridge source id: `generic_json`
- Detector strategy: `suspicious_process_tree`
- Response adapter: `crowdstrike_rtr`
- SIEM transport: `splunk_hec`
- Proof event id: `evt-proof-attack-1`
- Proof host id: `host-1`

## Architecture Notes

- The compose proof uses the same runtime-service execution path as the shipped
  HTTP ingest surface so the bridge-backed scenario exercises response,
  forwarding, replay, and observability together instead of only the agent
  substrate lane.
- Serve-mode bridge events are signed with the persisted whisker identity before
  deposit persistence so admitted-identity enforcement remains active in the
  proof stack.
- After the runtime-service path completes, the same event is copied into the
  shared telemetry channel for background agent processing, keeping the compose
  proof aligned with the live serve-mode topology.
