# Phase 274 Context

## Goal

The runtime can detect IAM abuse, resource hijacking, and credential compromise patterns from AWS CloudTrail telemetry and produce signed findings with cloud-specific evidence.

## Repo State

- The bridge architecture already supports multiple telemetry sources and the runtime now has a roadmap-defined place for CloudTrail events after Phase 273.
- Existing detector lanes already emit signed findings, map to shared `ThreatClass` variants, and persist evidence through the normal pheromone and review pipeline.
- Cloud-specific detector coverage is not yet shipped; this phase establishes the first AWS detector on the live runtime path.

## Phase Focus

- Add one `CloudTrailDetector` on the normal `DetectionStrategy` seam instead of creating a cloud-only detection subsystem.
- Map the targeted CloudTrail patterns into existing threat classes and ATT&CK cloud techniques while preserving cloud-specific evidence fields.
- Keep the output compatible with the signed finding, pheromone, and operator-inspection surfaces already used by host telemetry detectors.

## Verification Target

- Repo-owned tests covering IAM abuse, resource hijacking, and credential compromise patterns from representative CloudTrail events.
- Proof that findings carry AWS account ID, principal ARN, triggering event name, and ATT&CK cloud technique metadata on the standard finding envelope.
- End-to-end runtime validation that CloudTrail findings produce signed pheromone deposits and remain visible through the normal operator inspection path.
