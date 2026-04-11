# Phase 134: Helm Deployment And Config CLI Experience - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 134 owns the deployability layer for the current detect server: one repo-owned Helm chart and two operator CLI flows, `swarmctl validate` and `swarmctl init`. This phase does not own bearer auth, TLS, panic elimination, or crate extraction.

</domain>

<decisions>
## Implementation Decisions

### Add `validate` And `init` As Fast Paths Ahead Of Full CLI Harness Bootstrap
- `crates/swarm-runtime/src/cli/core.inc` currently calls `load_config(&cli.config)?` and constructs every replay, evidence, approval, and evolution harness before dispatching any subcommand.
- That eager bootstrap is correct for the existing operator workflows, but it is the wrong shape for `swarmctl init` because init should not require an existing config file, and it is wasteful for `swarmctl validate`.
- The smallest safe change is to route `Command::Validate` and `Command::Init` before the current repo-config and harness initialization path, leaving the rest of the CLI behavior untouched.

### Reuse The Existing Config Loader For Validation, Then Layer Reachability Checks On Top
- `load_config()` already performs schema migration, structural validation, detector-profile validation, and `@secret:` resolution.
- Phase 134 should not create a second config-validation codepath. `swarmctl validate` should call the existing loader, then optionally perform outbound reachability probes against configured HTTP endpoints using a bounded TCP connect.
- Structured JSON output should describe both config validation and endpoint probe results so operators can use it in CI and deployment gates.

### Generate A Repo-Owned Config Template Rather Than Copying `default.yaml` Blindly
- `rulesets/default.yaml` is a good baseline, but it is intentionally minimal and detect-only.
- `swarmctl init --mode detect_only|live_response` should emit a documented `rulesets/custom.yaml` template with inline comments and deployment-oriented defaults for the selected mode.
- The live-response template must be valid under the current config rules, which means choosing a durable pheromone backend by default rather than leaving `in_memory` in place.

### Helm Should Materialize The Existing Runtime Contract, Not Invent A New One
- The current runtime image already ships `swarm_detect`, `swarmctl`, `rulesets/`, and the health endpoints `/startupz`, `/readyz`, `/livez`, and `/prestop`.
- There is no existing chart tree in the repo, so Phase 134 should create one under `deploy/helm/swarm-team-six/` with a generated `config.yaml` ConfigMap, Secret-backed secret files, service wiring, and a PodDisruptionBudget.
- The chart should make JetStream deployment optional through a conditioned NATS dependency, but keep a local-journal path available so operators can deploy without NATS when they only need one durable node.

</decisions>

<code_context>
## Existing Code Insights

### The Runtime Already Exposes The Kubernetes Probe Surface
- `crates/swarm-runtime/src/ingest.rs` already serves `/startupz`, `/readyz`, `/livez`, and `/prestop`.
- The Helm chart can wire native Kubernetes startup, readiness, liveness, and lifecycle behavior without adding new runtime code for probes.

### The Docker Image Already Matches The Desired Deployment Target
- `Dockerfile` builds both `swarm_detect` and `swarmctl`, copies `rulesets/` into `/app/rulesets/`, and starts `/usr/local/bin/swarm_detect --config /app/rulesets/default.yaml --serve --bind 0.0.0.0:9090`.
- The chart only needs to override config path, port, and mounted config or secret locations; no container-image restructuring is required in this phase.

### The Config Model Already Covers The Chart Inputs
- `SwarmConfig` and `rulesets/default.yaml` already model runtime mode, multi-strategy detection, pheromone backend choice, response adapter, SIEM forwarding, notification routing, platform API keys, and operator surface auth.
- Helm values can map directly into those config sections instead of adding a deployment-only abstraction layer.

</code_context>

<specifics>
## Specific Ideas

- Add `swarmctl validate --config <path> [--check-endpoints] [--json]`.
- Add `swarmctl init --mode detect_only|live_response [--output rulesets/custom.yaml]`.
- Create `deploy/helm/swarm-team-six/Chart.yaml`, `values.yaml`, and the template set for deployment, service, config, secrets, helpers, and `PodDisruptionBudget`.
- Mount secret values into `runtime.secret_dir` so config can use `@secret:file-name` references.
- Parameterize:
  - runtime mode
  - detection strategy or strategies
  - pheromone backend including optional JetStream/NATS
  - response adapter
  - SIEM forwarding
  - notification channels

</specifics>

<deferred>
## Deferred Ideas

- Bearer auth and TLS on `/v2/api/*` remain Phase 135 work.
- Extracting the CLI into a separate crate remains Phase 136 work.
- Certificate management, ingress resources, and external secret operators are out of scope for this base chart.

</deferred>
