---
phase: 105-schema-versioning-and-secret-resolution
plan: 02
subsystem: secrets
tags: [config, secrets, adapters, reload]
requirements-completed: [K8S-03]
one-liner: "Response adapters now resolve `@secret:` references from environment variables or mounted files, and secret-directory changes trigger live runtime reload."
completed: 2026-04-07
---

# Phase 105 Plan 02 Summary

**Response adapters now resolve `@secret:` references from environment variables or mounted files, and secret-directory changes trigger live runtime reload.**

## Accomplishments

- Added a shared `SwarmSecretProvider` contract and `FileEnvSecretProvider` implementation in the runtime config loader.
- Added secret resolution for response-adapter auth tokens through `@secret:env:NAME` and `@secret:file-name` references.
- Resolved `RuntimeSettings.secret_dir` relative to the config file so mounted secret directories remain portable across deployments.
- Extended serve-mode file watching so secret-directory changes call `reload_from_disk()` without process restart.
- Added webhook bearer-auth support and focused tests proving environment and file-backed secret resolution works end to end.

## Files Created Or Modified

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/src/config.rs`
- `crates/swarm-runtime/src/bin/swarm_detect.rs`
- `crates/swarm-response/src/config.rs`
- `crates/swarm-response/src/dispatch.rs`
- `crates/swarm-response/src/webhook.rs`

## Verification

- `cargo test -p swarm-runtime config --lib`
- `cargo test -p swarm-response --lib`
- `cargo clippy -p swarm-core -p swarm-response -p swarm-runtime --tests -- -D warnings`

## Notes

- Secret values are resolved before the final validation pass, which ensures empty or malformed resolved credentials still fail closed.
- The secret provider is intentionally narrow to environment variables and mounted files so production secret rotation has one deterministic contract in this milestone.
