# Phase 256 Context

## Goal

Publish a machine-readable OpenAPI 3.1 spec for the shipped `/v2/api/` platform surface from one repo-owned source of truth.

## Repo State

- The platform API already exists under the shipped `/v2/api/` surface, but the repo does not yet publish one machine-readable OpenAPI contract for it.
- v1.71 just hardened CI and tagged release automation, so the repo now has a cleaner path to validate and ship generated artifacts.
- `REQUIREMENTS.md` already fixes the phase scope to `APISPEC-01`, which keeps this phase bounded to spec generation rather than client generation or SOAR sync behavior.

## Phase Focus

- Identify the narrowest source-of-truth seam for the current `/v2/api/` request, response, auth, and error contracts.
- Generate or derive a valid OpenAPI 3.1 document without introducing a second hand-maintained API contract.
- Publish the spec at a stable repo-owned path that later phases can consume for client generation and contract verification.

## Verification Target

- Validation proof that the emitted document is a real OpenAPI 3.1 spec.
- Repo-owned coverage check showing the shipped `/v2/api/` routes are represented by the generated contract.
