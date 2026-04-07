---
phase: 105-schema-versioning-and-secret-resolution
type: context
created_at: 2026-04-07
depends_on: [104]
---

# Phase 105 Context

## Goal

Make runtime config schema-aware and resolve adapter secrets through a shared contract so config reloads can pick up rotated credentials without restarting the process.

## Why This Phase Exists

The current config loader is a straight YAML deserialize plus semantic validation. That works while the schema is still fluid, but it gives no explicit contract for supported versions or repo-owned backward-compatible transforms. Response adapters also still assume inline token strings, which is incompatible with mounted Kubernetes secrets and secret rotation.

## What Is Already True

- `parse_config` already centralizes config loading and validation for runtime consumers.
- Serve mode already has a file-watch reload loop for config changes and `SIGHUP`.
- Response adapters are built from `ResponseAdapterConfig`, which gives one seam for secret resolution before adapter construction.
- `HttpEdrAdapter` already adds bearer auth and `WebhookAdapter` already owns the outbound request builder.

## Constraints

- Unknown future schema versions must fail closed.
- Backward-compatible transforms must be explicit and observable in logs.
- Secret resolution must not broaden the operator surface or add a remote secret manager dependency.
- Secret reload should reuse the existing runtime reload path instead of creating mutable adapter internals.

## Decisions

- `schema_version` will be required on `SwarmConfig`, with loader support for migrating the immediate legacy repo config shape forward.
- `SwarmSecretProvider` will live in runtime config wiring where config and filesystem semantics already exist.
- `@secret:env:NAME` will resolve from environment variables; other `@secret:` references will resolve as file names under `RuntimeSettings.secret_dir`.
- Secret-file watch events will call the same `reload_from_disk` flow already used for config-file changes.

## Phase Direction

- Add schema versioning and migration first so the loader contract is explicit.
- Then add secret resolution, webhook auth support, and secret-dir watch handling.
- Preserve the current adapter execution semantics; only the config-to-adapter wiring changes.
