# Swarm Team Six Quickstart

> Operator path from zero to first detection with the shipped Docker Compose
> image wrapper.
>
> Last updated: 2026-04-13

This document is part of the active contract set defined in
`docs/REFERENCE-STATUS.md`.

## Goal

Reach one visible detection from a clean checkout in under 15 minutes using the
repo-owned Docker image and `swarmctl`.

The quickstart path uses the signed detect-only bootstrap bundle at
`/app/rulesets/default.yaml`. The built-in quickstart scenario injects one
synthetic process-start event, forces the approval path through the sandboxed
first-run wizard, and prints the resulting finding, receipt-pack ID, and proof
Merkle root in one command.

## Prerequisites

- Docker Engine or Docker Desktop with the Compose plugin
- network access to pull the base `rust:1.94-bookworm` and
  `debian:bookworm-slim` images on the first build

## 1. Build The Runtime Image

```bash
docker compose build swarm-detect
```

## 2. Validate The Shipped Signed Bootstrap Bundle

```bash
docker compose run --rm --entrypoint swarmctl \
  swarm-detect \
  validate --config /app/rulesets/default.yaml
```

Expected outcome:

- `Passed: true`
- no remediation block

## 3. Run One-Command Quickstart

`swarmctl quickstart` needs a voter signing key for the built-in approval step
and an evidence signing key for the exported receipt pack. The bootstrap
detect-only bundle keeps incident storage in memory, so the quickstart report
itself is the supported first-run finding inspection surface.

```bash
docker compose run --rm --entrypoint swarmctl \
  -e RUST_LOG=warn \
  -e SWARM_VOTER_SIGNING_KEY=quickstart-voter-key \
  -e SWARM_EVIDENCE_SIGNING_KEY=quickstart-evidence-key \
  swarm-detect \
  --approval-verdict-results-dir /tmp/approval-verdicts \
  --approval-receipt-pack-results-dir /tmp/approval-receipt-packs \
  --approval-set-results-dir /tmp/approval-sets \
  --approval-ledger-results-dir /tmp/approval-ledgers \
  quickstart --config /app/rulesets/default.yaml
```

Successful output has this shape:

```text
Swarm Team Six Quickstart
Config: /app/rulesets/default.yaml
Validation: true
Readiness: true
Status: completed
Scenario: guided first-run
Run: demo_replay:...
Injected events: 1
Elapsed ms: ...
Incident: incident:evt-first-run-1:...
Trigger strategy: suspicious_process_tree
Threat class: execution
Severity: CRITICAL
Receipt pack: approval-receipt-pack:...
Proof Merkle root: 0x...
Next steps:
- swarmctl status --config /app/rulesets/default.yaml
- review the finding summary above; enable `correlation.enabled=true` with a `local_files` incident store to inspect incidents after quickstart
```

The visible detection proof for this guide is the `Incident`, `Threat class`,
`Severity`, `Receipt pack`, and `Proof Merkle root` block printed by that one
command.

## 4. Optional JSON Output

Use JSON mode when you want to capture the first-run proof in CI or shell
automation.

```bash
docker compose run --rm --entrypoint swarmctl \
  -e RUST_LOG=warn \
  -e SWARM_VOTER_SIGNING_KEY=quickstart-voter-key \
  -e SWARM_EVIDENCE_SIGNING_KEY=quickstart-evidence-key \
  swarm-detect \
  --json \
  --approval-verdict-results-dir /tmp/approval-verdicts \
  --approval-receipt-pack-results-dir /tmp/approval-receipt-packs \
  --approval-set-results-dir /tmp/approval-sets \
  --approval-ledger-results-dir /tmp/approval-ledgers \
  quickstart --config /app/rulesets/default.yaml
```

The JSON payload includes:

- `status`
- `scenario_name`
- `run_id`
- `elapsed_ms`
- `finding.incident_id`
- `finding.strategy_id`
- `finding.threat_class`
- `finding.severity`
- `receipt_pack_id`
- `proof_merkle_root`

## 5. Start The HTTP Runtime Surface

The quickstart proof above is self-contained. To verify the packaged runtime
service separately, start the normal `swarm_detect` container and probe the
health surfaces:

```bash
docker compose up -d swarm-detect
curl -fsS http://127.0.0.1:9090/startupz
curl -fsS http://127.0.0.1:9090/readyz
curl -fsS http://127.0.0.1:9090/healthz
docker compose logs --tail=100 swarm-detect
```

Expected outcome:

- `/startupz`, `/readyz`, and `/healthz` return HTTP `200`
- the runtime logs show the configured detect-only bootstrap profile starting
  without manual config edits

## 6. Clean Up

```bash
docker compose down --remove-orphans
```

## Notes

- The signed detect-only bootstrap bundle is intentionally minimal. It is meant
  for first-run validation, not for durable incident retention.
- The Compose service definition sets `RUST_LOG=info` for the long-running
  runtime. Override it to `warn` on one-shot `swarmctl` container runs so the
  quickstart report stays readable.
- If you want replay, investigation, or incident lookup after quickstart, start
  from `swarmctl init --mode live_response` or explicitly switch the storage
  backends to `local_files`.
- Deployment-specific packaging details for Docker single-container, Docker
  Compose with NATS, Helm, and bare-metal binaries live in
  [docs/DEPLOYMENT.md](DEPLOYMENT.md).
