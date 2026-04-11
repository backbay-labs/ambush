# Phase 180: Secure Production Packaging Profile - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 180 establishes one repo-owned secure production deployment profile for the shipped runtime. The output is not a broad platform matrix. It is one supported packaging contract that makes runtime state roots, secret mounts, TLS mounts, and the optional JetStream dependency layout explicit enough for recovery and operator-access work to build on.

</domain>

<decisions>
## Implementation Decisions

- Keep the Phase 134 base Helm chart, but add a separate supported production values profile instead of treating the bootstrap `values.yaml` as production guidance.
- Make one runtime state root authoritative for local durable artifacts that the detect server owns directly.
- Keep the operator surface out of the supported production profile for now; Phase 183 will replace the current loopback-only local contract with a supported operator-access model.
- Harden the production pod packaging with non-root execution, read-only root filesystem, explicit scratch volume, TLS secret mount support, and no ambient service-account token.

</decisions>

<code_context>
## Existing Code Insights

- `deploy/helm/swarm-team-six/templates/_helpers.tpl` already mutates rendered config for mounted secret files and optional JetStream URL wiring, so it is the right place to derive state-root and TLS paths for the packaged profile.
- `crates/swarm-core/src/config.rs` already validates durable live-response backends, non-empty local artifact roots, TLS fields, and loopback-only operator bind addresses, but the chart does not currently package those constraints into a supported production topology.
- `crates/swarm-runtime/src/bin/swarm_detect.rs` always uses persisted agent identity, which means leaving `identity.agent_key_dir` and `identity.registry_dir` on config-relative defaults would push runtime state into the config mount instead of the durable data root.
- `docs/CONFIGURATION.md` documents the chart and the local operator surface, but it still presents the base chart as the deployment path rather than one explicit production profile with clear state-boundary guidance.

</code_context>

<deferred>
## Deferred Ideas

- Multi-operator authentication, scoped approvals, and externally supported operator access remain Phase 183 work.
- Backup, restore, upgrade, rollback, and durability drills remain Phase 181 work.
- Capacity, SLO, and alert baselines remain Phase 182 work.

</deferred>
