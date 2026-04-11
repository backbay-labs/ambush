# Phase 183: Operator Access Model And Multi-Operator Audit - Context

**Gathered:** 2026-04-11
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 183 replaces the current loopback-friendly single shared bearer-token
operator model with a supported multi-operator access contract. The target is
scoped operator permissions and attributable approvals inside the existing
runtime and audit lanes, not a brand-new external IAM plane.

</domain>

<decisions>
## Implementation Decisions

- Extend the existing `operator_surface` and platform API auth seam instead of
  inventing a second operator identity model.
- Keep Providence context tokens read-only and narrowly scoped; they are not the
  mechanism for approval or maintenance authority.
- Preserve the existing approval and evidence lanes, but thread authenticated
  operator identity and scope through them so actions are attributable end to end.
- Use the supported Helm production profile and configuration reference as the
  place to document the operator deployment and secret model once the auth
  contract exists.

</decisions>

<code_context>
## Existing Code Insights

- [config.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-core/src/config.rs)
  currently models `operator_surface.auth` as one `operator_id` plus one
  `token_env`, which is sufficient for loopback local use but not for multiple
  distinct operators or scoped permissions.
- [core.inc](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/http/core.inc)
  currently gates the operator HTTP surface behind one bearer token and reuses a
  separate approval-receipt signer identity when quorum is met, so authenticated
  operator identity is not yet the same thing as approval attribution.
- [platform_api.rs](/Users/connor/Medica/backbay/standalone/swarm-team-six/crates/swarm-runtime/src/ingest/platform_api.rs)
  already has a notion of scoped API keys layered on top of bearer auth for
  read access, which is a useful seam for Phase 183 permission modeling.
- [values-production.yaml](/Users/connor/Medica/backbay/standalone/swarm-team-six/deploy/helm/swarm-team-six/values-production.yaml)
  intentionally keeps `operator_surface.enabled: false` until this phase lands a
  supported non-loopback operator access model.

</code_context>

<deferred>
## Deferred Ideas

- External OIDC, SSO, or cloud-specific IAM federation remain out of scope for
  this phase unless they can be expressed as a reference integration pattern
  without widening the repo-owned runtime contract.
- Fleet-wide operator federation or distributed approval workflows that exceed
  the current bounded runtime audit lane remain later work.

</deferred>

