# Phase 257 Context

## Goal

Ship and test a generated Python client built from the checked-in OpenAPI spec for the `/v2/api/` platform surface.

## Repo State

- Phase 256 is intended to leave one machine-readable OpenAPI 3.1 spec at a stable repo-owned path.
- The repo does not yet ship a generated Python client for the platform API.
- The phase is bounded to `APISPEC-02`, so it should reuse the Phase 256 contract instead of redefining the API by hand.

## Phase Focus

- Select the generation workflow and package shape that fit the existing repo tooling with minimal contract drift risk.
- Generate a Python client directly from the Phase 256 spec and keep the generated output reproducible.
- Add repo-owned verification proving the generated client can authenticate against and consume the shipped `/v2/api/` surface.

## Verification Target

- Reproducible client generation from the checked-in OpenAPI spec.
- Focused tests exercising the generated client against the live or test platform API contract.
