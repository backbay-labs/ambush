# Deploying Perch

Two deployments are described here: the dev stack on one machine, and the chart
for a cluster. Both are stated with what has and has not been exercised — a
deployment document whose steps nobody ran is a list of guesses.

## What was exercised, and what was not

| Path | Status |
|---|---|
| The native dev stack (Homebrew Postgres, Redis, a `cargo build` relay, a host-run daemon) | **run end to end.** `docs/PERCH-DEV.md` steps 1–16, including a hold produced, filed, refused and granted |
| `docker compose --profile perch up` | **never run.** This machine's Docker daemon (colima) reports filesystem I/O errors. Every compose line here is validated by `tools/check-perch-compose.sh` and by `docker compose config`, neither of which starts a container |
| `helm lint`, `helm template`, `helm unittest` | **run.** 12 chart tests pass; the chart renders with every Perch value on |
| `helm install` against a cluster | **never run.** No cluster is available here. The chart is proven to render, not to work |

## The dev stack

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

## The chart

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

## Running the chart's checks

```bash
helm dependency build deploy/helm/swarm-team-six
helm lint deploy/helm/swarm-team-six
helm template ci deploy/helm/swarm-team-six -f deploy/helm/swarm-team-six/ci/perch-values.yaml
helm unittest deploy/helm/swarm-team-six
bash tools/check-perch-compose.sh
```

The render is not redundant with the lint: lint passes a chart whose templates
never execute.
