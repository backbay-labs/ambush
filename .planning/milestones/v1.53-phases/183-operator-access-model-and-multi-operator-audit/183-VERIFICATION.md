# Phase 183 Verification

status: passed

## Result

Phase 183 verification passed.

## Commands

- `cargo fmt --all`
- `cargo test -p swarm-core operator_surface_principals_require_scopes`
- `cargo test -p swarm-runtime platform_api_bearer_requires_read_scoped_operator_principal`
- `cargo test -p swarm-runtime scoped_operator_principals_gate_actions_and_preserve_actor_identity`
- `cargo test -p swarm-runtime maintenance_endpoints_persist_audit_records`
- `cargo test -p swarm-runtime review_surface_scoped_context_renders_rehearsal_and_exports_signed_proof`
- `cargo test -p swarm-runtime approval_vote_endpoint_resumes_demo_runtime_and_proof_export`
- `helm template swarm-team-six deploy/helm/swarm-team-six -f deploy/helm/swarm-team-six/values-production.yaml >/tmp/swarm-team-six-values-production-rendered.yaml`
- `helm template swarm-team-six deploy/helm/swarm-team-six >/tmp/swarm-team-six-values-bootstrap-rendered.yaml`
- `helm lint deploy/helm/swarm-team-six -f deploy/helm/swarm-team-six/values-production.yaml`
- `helm template swarm-team-six deploy/helm/swarm-team-six -f deploy/helm/swarm-team-six/values-production.yaml --show-only templates/configmap.yaml | sed -n '/^  config.yaml: |$/,$p' | sed '1d;s/^    //' >/tmp/swarm-team-six-values-production-config.yaml`
- `cargo run -p swarm-runtime --bin swarmctl -- validate --config /tmp/swarm-team-six-values-production-config.yaml --json`
- `helm template swarm-team-six deploy/helm/swarm-team-six --show-only templates/configmap.yaml | sed -n '/^  config.yaml: |$/,$p' | sed '1d;s/^    //' >/tmp/swarm-team-six-values-bootstrap-config.yaml`
- `cargo run -p swarm-runtime --bin swarmctl -- validate --config /tmp/swarm-team-six-values-bootstrap-config.yaml --json`

## Verified Behaviors

- Operator auth now supports multiple distinct principals with explicit read, rehearse, approve, and maintenance scope instead of one shared bearer secret.
- Forbidden actions fail closed across the operator and platform surfaces when the authenticated principal lacks the required scope.
- Approval votes and maintenance records now retain the authenticated operator identity in durable audit output instead of attributing actions to one startup-global actor.
- The supported production and bootstrap Helm renders still produce valid runtime configs after the multi-principal operator auth contract landed.

## Notes

- Helm validation must target the rendered `config.yaml` document from `templates/configmap.yaml`; validating the full multi-document manifest would incorrectly fail on Kubernetes YAML rather than the runtime config itself.
