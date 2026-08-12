# Swarm Team Six Deployment Reference

> Supported packaging paths, prerequisites, config entrypoints, and verification
> steps.
>
> Last updated: 2026-04-13

This document is part of the active contract set defined in
`docs/REFERENCE-STATUS.md`.

## Deployment Matrix

| Path | Primary use | Config entrypoint | Verification |
| --- | --- | --- | --- |
| Docker single-container | Local runtime smoke test | `/app/rulesets/default.yaml` or mounted replacement | `curl /startupz`, `curl /readyz`, `curl /healthz` |
| Docker Compose bootstrap | Operator first-run and packaged local runtime | `docker-compose.yml` + `/app/rulesets/default.yaml` | `swarmctl quickstart` and HTTP health probes |
| Docker Compose with NATS | Local/shared-state JetStream rehearsal | custom config mounted into `swarm-detect` plus `nats` profile | NATS health plus runtime `/readyz` |
| Helm chart | Supported Kubernetes deployment | `deploy/helm/swarm-team-six/values-production.yaml` | `helm template`, `kubectl rollout status`, port-forwarded `/readyz` |
| Bare-metal binaries | Direct host install and service-manager integration | local file from `swarmctl init` | `swarmctl validate` plus host-local `/readyz` |

## 1. Docker Single-Container

### Prerequisites

- Docker Engine or Docker Desktop

### Build

```bash
docker build -t swarm-team-six:local .
```

### Run

```bash
docker run --rm -p 9090:9090 swarm-team-six:local
```

Use a custom config by mounting it over the default bootstrap path:

```bash
docker run --rm -p 9090:9090 \
  -v "$PWD/config/default.yaml:/app/rulesets/default.yaml:ro" \
  swarm-team-six:local
```

### Verify

```bash
curl -fsS http://127.0.0.1:9090/startupz
curl -fsS http://127.0.0.1:9090/readyz
curl -fsS http://127.0.0.1:9090/healthz
```

## 2. Docker Compose Bootstrap

### Prerequisites

- Docker Compose plugin

### Run

```bash
docker compose up --build -d swarm-detect
```

### Verify

```bash
curl -fsS http://127.0.0.1:9090/startupz
curl -fsS http://127.0.0.1:9090/readyz
curl -fsS http://127.0.0.1:9090/healthz
docker compose logs --tail=100 swarm-detect
```

### First Detection

Use the packaged CLI inside the same image wrapper:

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

That is the supported local operator-first path from zero to one visible
detection. The full walkthrough is documented in
[docs/QUICKSTART.md](QUICKSTART.md).

Use `RUST_LOG=warn` on the one-shot CLI container because the long-running
Compose service intentionally defaults to `RUST_LOG=info`.

## 3. Docker Compose With NATS

Use this path when you want JetStream-backed pheromone storage instead of the
default single-container bootstrap.

### Prerequisites

- Docker Compose plugin
- one runtime config that switches the pheromone backend to JetStream

Config snippet:

```yaml
pheromone:
  backend:
    kind: jet_stream
    url: nats://nats:4222
    connect_timeout_ms: 5000
    gc_page_size: 512
```

Mount that config into the runtime service and start the optional `nats`
profile:

```bash
docker compose --profile nats up --build -d swarm-detect nats
```

### Verify

```bash
docker compose --profile nats exec nats wget -qO- http://127.0.0.1:8222/healthz
curl -fsS http://127.0.0.1:9090/readyz
docker compose logs --tail=100 swarm-detect
```

If you prefer an ephemeral local JetStream harness for tests, the repo-owned
wrapper remains:

```bash
bash tools/with-nats-jetstream.sh env | cat
```

## 4. Helm Chart

The supported Kubernetes deployment path is the repo-owned chart at
`deploy/helm/swarm-team-six/` with
`deploy/helm/swarm-team-six/values-production.yaml`.

### Prerequisites

- Helm 3
- a Kubernetes cluster
- a published image reference
- runtime Secret objects for the configured secret and TLS mounts when those
  features are enabled

### Render

```bash
helm template swarm-team-six deploy/helm/swarm-team-six \
  -f deploy/helm/swarm-team-six/values-production.yaml
```

### Install

```bash
helm install swarm-team-six deploy/helm/swarm-team-six \
  -f deploy/helm/swarm-team-six/values-production.yaml \
  --set image.repository=ghcr.io/example/swarm-team-six \
  --set image.tag=latest
```

### Verify

```bash
kubectl rollout status deployment/swarm-team-six-swarm-team-six
kubectl port-forward deployment/swarm-team-six-swarm-team-six 9090:9090
curl -fsS http://127.0.0.1:9090/readyz
```

The production chart mounts:

- `/etc/swarm/config.yaml` from a ConfigMap
- `/var/lib/swarm` as the writable runtime state root
- `/data` for JetStream when `nats.enabled=true`
- `/var/run/swarm-secrets` and `/var/run/swarm-tls` from Secret objects when
  enabled

## 5. Bare-Metal Binaries

### Prerequisites

- Rust toolchain for source builds, or prebuilt `swarm_detect` and `swarmctl`
  binaries

### Build

```bash
cargo build --release -p swarm-runtime-http --bin swarm_detect --bin swarmctl
```

### Initialize And Validate

```bash
./target/release/swarmctl init --mode detect_only --output ./config/default.yaml
./target/release/swarmctl validate --config ./config/default.yaml
./target/release/swarmctl readiness --config ./config/default.yaml
```

### Run

```bash
./target/release/swarm_detect --config ./config/default.yaml --serve --bind 127.0.0.1:9090
```

### Verify

```bash
curl -fsS http://127.0.0.1:9090/startupz
curl -fsS http://127.0.0.1:9090/readyz
curl -fsS http://127.0.0.1:9090/healthz
./target/release/swarmctl status --config ./config/default.yaml
```

## Notes

- `swarmctl serve` is a separate operator-facing surface. Keep it on a private
  network boundary or a separate admin workload when you enable it.
- The bootstrap detect-only bundle is intentionally conservative. Use the
  live-response init template or explicit storage overrides when you need
  durable investigation and incident lookup.
- Recovery drills, PVC boundaries, and JetStream restore guidance live in
  [docs/DR-RUNBOOK.md](DR-RUNBOOK.md).
