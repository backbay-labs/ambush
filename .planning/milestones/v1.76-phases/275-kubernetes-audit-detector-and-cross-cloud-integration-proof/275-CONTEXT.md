# Phase 275 Context

## Goal

The runtime can detect privilege escalation, RBAC abuse, and container escape from Kubernetes audit telemetry, and both cloud detectors are proven end-to-end through the full detection pipeline.

## Repo State

- The milestone intends to close with both CloudTrail and Kubernetes audit telemetry flowing through the same bridge and detector surfaces.
- Existing runtime proof patterns already cover end-to-end signed findings, pheromone deposits, and operator-visible evidence across non-cloud detector families.
- No repo-owned cross-cloud integration proof exists yet for AWS plus Kubernetes telemetry on the shared runtime path.

## Phase Focus

- Add one `KubernetesAuditDetector` using the normal detector seam with bounded patterns for escalation, RBAC abuse, and container-escape indicators.
- Reuse the same signed finding and pheromone flow as the rest of the runtime so cloud detections do not fork the operator workflow.
- Close the milestone with one repo-owned integration proof that AWS and Kubernetes cloud detections compose on the shipped runtime path.

## Verification Target

- Detector tests covering Kubernetes privilege escalation, RBAC abuse, and container-escape indicators with cloud-specific evidence fields.
- Shared runtime proof that both cloud detector families map to existing `ThreatClass` variants and emit signed pheromone deposits.
- End-to-end integration proof that CloudTrail and Kubernetes audit telemetry both traverse ingest, detection, finding, and signed-evidence surfaces successfully.
