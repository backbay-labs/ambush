# Swarm Team Six Deployment Reference

> Supported packaging paths, prerequisites, config entrypoints, and verification
> steps.
>
> Last updated: 2026-09-04

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
| Perch console | Operator console beside a relay | `.env.perch` + `perch.*` chart values | `tools/check-perch-compose.sh`, `helm unittest`; see [Perch](#perch-the-operator-console) |

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
- **Automated promotion of evolved detectors is OFF in every shipped
  configuration, by design.** `promotion.require_solver_result_for_promotion`
  defaults to `true`, and the curated `rulesets/default.yaml` cannot produce the
  `proved` solver result it asks for: its one invariant bundle declares no
  `custom_z3` invariant and `evolution.safety_gate.enable_z3` is `false`. Every
  promotion attempt therefore fails with `no solver result was recorded`, and
  NO PROMOTION REPORT IS PRODUCED AT ALL — `ProductionPromotionReport` is built
  at one site, inside `start_run`, AFTER the solver gate, so a run that the gate
  refuses never reaches it. The literal line
  `Solver result: NO SOLVER RESULT RECORDED` is what a report shows where the
  gate has been explicitly disabled with
  `require_solver_result_for_promotion: false`; do not go looking for it in the
  shipped configuration. This is fail-closed and intended:
  an evolved detector does not reach production without a recorded solver proof.
  Canary admission, rollback, and the operator review surfaces are unaffected.
  To turn automated promotion on you need a deployment-owned admission bundle
  with a `custom_z3` invariant, `enable_z3: true`, and a binary built with
  `--features swarm-runtime/z3`. The step-by-step recipe, what a passing solver
  result looks like, and why the curated ruleset cannot be edited to satisfy its
  own gate are in
  [docs/EVOLUTION.md](EVOLUTION.md#default-promotion-posture-no-proof-no-promotion).

---

## Perch (the operator console)

Two deployments are described here: the dev stack on one machine, and the chart
for a cluster. Both are stated with what has and has not been exercised — a
deployment document whose steps nobody ran is a list of guesses.

### What was exercised, and what was not

| Path | Status |
|---|---|
| The native dev stack (Homebrew Postgres, Redis, a `cargo build` relay, a host-run daemon) | **run end to end.** `docs/PERCH-DEV.md` steps 1–16, including a hold produced, filed, refused and granted |
| `docker compose --profile perch up` | **never run.** This machine's Docker daemon (colima) reports filesystem I/O errors. Every compose line here is validated by `tools/check-perch-compose.sh` and by `docker compose config`, neither of which starts a container |
| `helm lint`, `helm template`, `helm unittest` | **run.** 12 chart tests pass; the chart renders with every Perch value on |
| `helm install` against a cluster | **never run.** No cluster is available here. The chart is proven to render, not to work |

### The dev stack

`docs/PERCH-DEV.md` is the runbook. In short:

```bash
cp .env.perch.example .env.perch     # then fill the two seeds
docker compose up -d postgres redis relay
bash scripts/provision-perch.sh
```

The daemon runs on the **host**, not in the compose network. This is not a
convenience: the relay seeds exactly one community, for the host in its own
`RELAY_URL`, so a containerised daemon reaching `relay:3000` and a desktop
reaching `localhost:3000` would not share a record. `docker-compose.yml` says
so at the `swarm-detect` service, with the measurement.

### What the compose gate enforces

`tools/check-perch-compose.sh`, wired into the `helm` CI job:

- **every published port binds `127.0.0.1`.** A bare `3000:3000` publishes on
  every interface; on a laptop on a conference network that is an
  unauthenticated relay on the internet.
- **every service has a healthcheck.** Without one `depends_on` waits for the
  container rather than the service, and the relay starts against a Postgres
  that is not accepting connections — a failure that looks like a relay bug.
- **no secret is inline.** A credential written into this file is in git
  history forever, and this is the file people copy.

It does **not** check image digests, and does not claim to. Two of the four
services build from source, so there is no reference to pin; and this
repository's Docker daemon does not run, so a digest written in would be
transcribed rather than resolved. A pinned digest nobody verified is worse than
a tag, because it looks verified.

### The chart

`deploy/helm/swarm-team-six`. Three things Perch adds.

### The relay dependency

`ambush` 0.1.8, from `file://../../../workspace/deploy/charts/ambush` —
this repository's own copy, not a registry range. The version installed is the
one this commit was tested against; a range would let a relay the daemon has
never run beside arrive on an upgrade.

It is **off by default** (`ambush.enabled: false`). Most deployments already
have a relay, and a chart that shipped one would install a second.

### The credentials

Three separate values, never one reused:

```yaml
perch:
  enabled: true
  existingSecret: my-perch-secret     # production
```

`PERCH_BRIDGE_NOSTR_SEED` and `PERCH_BRIDGE_SPINE_SEED` derive under different
domain strings, so the transport chain and the record chain share no key
material — a compromise of one must not let anyone forge the other.
`SWARM_OPERATOR_TOKEN` is a third thing again: it authenticates a read, and
signing anything with a credential that also grants approve is the defect B5
closed.

Inline values land in the release manifest, which the cluster stores and anyone
who can read release history can read. Acceptable for an evaluation; use
`existingSecret` for anything else.

They reach the process as **environment**, never as args. An arg is visible in
`ps` to anything sharing the pod's PID namespace and in every
`kubectl describe`.

### Default-deny egress

`networkPolicy.enabled` defaults to **true**. The daemon's job is to watch, and
it reaches three places: the relay it files into, the NATS it reads telemetry
from, and DNS. A watcher that can reach everything is an exfiltration path out
of the cluster it was deployed to protect — the failure that turns a security
tool into the incident.

DNS is allowed explicitly, because without it every other rule fails to resolve
and the daemon reports a relay that is down rather than a policy that is too
tight.

Ingress admits **no namespace** until one is named:

```yaml
networkPolicy:
  operatorNamespaceSelectors:
    - kubernetes.io/metadata.name: perch-operators
  egress:
    - to: [{ podSelector: { matchLabels: { app.kubernetes.io/name: ambush } } }]
      ports: [{ protocol: TCP, port: 3000 }]
```

The operator surface is authenticated, but an authenticated surface reachable
from every pod in the cluster is still a surface reachable from every pod.

### Running the chart's checks

```bash
helm dependency build deploy/helm/swarm-team-six
helm lint deploy/helm/swarm-team-six
helm template ci deploy/helm/swarm-team-six -f deploy/helm/swarm-team-six/ci/perch-values.yaml
helm unittest deploy/helm/swarm-team-six
bash tools/check-perch-compose.sh
```

The render is not redundant with the lint: lint passes a chart whose templates
never execute.
