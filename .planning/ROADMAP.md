# Roadmap: Swarm Team Six

## Milestones

<details>
<summary>Shipped milestones (v1.0 through v1.25) -- see MILESTONES.md and .planning/milestones/</summary>

Phases 1-80 shipped across milestones v1.0 through v1.25. Full history is in `.planning/MILESTONES.md`, and per-milestone roadmap snapshots live in `.planning/milestones/`.

</details>

### v1.26 Detection Breadth And Telemetry Ingestion (In Progress)

**Milestone Goal:** Expand detection from one narrow detector to broad threat coverage, and build real telemetry ingestion so the system can process live events rather than only synthetic fixtures.

## Phases

- [ ] **Phase 81: Detection Strategy Expansion** - Four new detectors covering DNS exfiltration, lateral movement, credential access, and suspicious scripting, with MITRE ATT&CK-tagged scenario fixtures
- [ ] **Phase 82: Telemetry Ingest Server** - HTTP POST JSON ingest endpoint in swarm-detect with normalization and validation
- [ ] **Phase 83: Tetragon Bridge Port** - gRPC bridge crate consuming Tetragon kernel-level process telemetry into normalized TelemetryPayload

## Phase Details

### Phase 81: Detection Strategy Expansion
**Goal**: The runtime can detect DNS exfiltration, lateral movement, credential access, and suspicious scripting threats through the existing DetectionStrategy trait
**Depends on**: Nothing (independent of Phase 82)
**Requirements**: DET-01, DET-02, DET-03, DET-04, DET-05
**Success Criteria** (what must be TRUE):
  1. Running a DNS tunneling scenario through the detection pipeline produces a detection record with the DNS exfiltration detector, flagging high-entropy subdomains or excessive query volume
  2. Running a lateral movement scenario (WMI, PsExec, SSH from unusual source) through the detection pipeline produces a detection record from the lateral movement detector
  3. Running a credential access scenario (LSASS access, SAM registry read, Kerberoasting) through the detection pipeline produces a detection record from the credential access detector
  4. Running a suspicious scripting scenario (encoded commands, download-and-execute, LOLBin abuse) through the detection pipeline produces a detection record from the suspicious scripting detector
  5. Each new detector has at least one MITRE ATT&CK-tagged scenario fixture exercised by an integration test that passes in `cargo test --workspace`
**Plans**: TBD

Plans:
- [ ] 81-01: TBD
- [ ] 81-02: TBD

### Phase 82: Telemetry Ingest Server
**Goal**: Operators can push live telemetry events into swarm-detect over HTTP without requiring the swarmctl workbench
**Depends on**: Nothing (independent of Phase 81)
**Requirements**: INGEST-01, INGEST-02
**Success Criteria** (what must be TRUE):
  1. An HTTP POST to the configurable ingest endpoint with a valid JSON telemetry event returns a success response and the event enters the detection pipeline
  2. An HTTP POST with malformed or schema-invalid JSON returns a structured rejection response and does not enter the detection pipeline
  3. The ingest endpoint coexists with the existing /metrics endpoint on the swarm-detect binary without requiring a separate process
**Plans**: TBD

Plans:
- [ ] 82-01: TBD

### Phase 83: Tetragon Bridge Port
**Goal**: The runtime can consume kernel-level process telemetry from Tetragon over gRPC and route it through the same detection pipeline as HTTP-ingested events
**Depends on**: Phase 82 (ingest normalization contract)
**Requirements**: INGEST-03
**Success Criteria** (what must be TRUE):
  1. A Tetragon bridge crate exists that can connect to a Tetragon gRPC endpoint and receive process execution events
  2. Received Tetragon events are normalized into the existing TelemetryPayload schema and published to the detection pipeline
  3. The bridge handles connection failures and malformed gRPC messages without crashing the swarm-detect process
**Plans**: 1 plan

Plans:
- [ ] 83-01-PLAN.md -- swarm-ingest-tetragon crate with proto compilation, gRPC client, event mapper, and bridge event loop

## Progress

**Execution Order:**
Phases 81 and 82 are independent and can execute in either order. Phase 83 depends on Phase 82.

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 81. Detection Strategy Expansion | v1.26 | 0/? | Not started | - |
| 82. Telemetry Ingest Server | v1.26 | 0/? | Not started | - |
| 83. Tetragon Bridge Port | v1.26 | 0/1 | Planned | - |
