# Phase 180 Plan 01 Summary

## Delivered

- Added a repo-owned supported production deployment profile in [values-production.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/deploy/helm/swarm-team-six/values-production.yaml) and declared the bundled `nats` dependency in [Chart.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/deploy/helm/swarm-team-six/Chart.yaml) so the chart now ships one explicit secure production baseline instead of implying that the bootstrap values are production-ready.
- Extended [values.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/deploy/helm/swarm-team-six/values.yaml) plus [templates/_helpers.tpl](/Users/connor/Medica/backbay/standalone/swarm-team-six/deploy/helm/swarm-team-six/templates/_helpers.tpl) so the rendered config derives one authoritative runtime state root, normalizes pheromone backend shape by backend kind, and pins identity, replay, investigation, incident, secret, TLS, and dead-letter paths into the packaged deployment contract.
- Hardened the runtime pod in [templates/deployment.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/deploy/helm/swarm-team-six/templates/deployment.yaml) and [templates/service.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/deploy/helm/swarm-team-six/templates/service.yaml) with explicit pod and container security contexts, disabled ambient service-account token mounting, read-only config and TLS mounts, and an opt-in writable scratch volume for read-only-root deployments.
- Updated [CONFIGURATION.md](/Users/connor/Medica/backbay/standalone/swarm-team-six/docs/CONFIGURATION.md) so the supported production profile, runtime and JetStream state roots, mount layout, and current operator-surface exclusion are documented as the baseline for the next recovery and operator-access phases.

## Notes

- The supported production profile intentionally stays in `detect_only` mode and leaves `operator_surface.enabled: false`; Phase 180 defines secure packaging, not the later multi-operator access contract.
- Runtime-owned identity and local artifact paths now resolve under `/var/lib/swarm` in the packaged profile, which removes the previous implicit dependency on config-relative writable paths under `/etc/swarm`.
- The helper now emits backend-kind-specific pheromone config so Helm value merging cannot accidentally produce invalid mixed `local_journal` and `jet_stream` fields.
