---
phase: 110-notification-channels-and-routing-rules
plan: 01
subsystem: config
tags: [notifications, config, secrets]
requirements-completed: [SIEM-03]
one-liner: "Repo-owned notification channel config, validation, and secret resolution now exist alongside the new SIEM forward surface."
completed: 2026-04-07
---

# Phase 110 Plan 01 Summary

**Repo-owned notification channel config, validation, and secret resolution now exist alongside the new SIEM forward surface.**

## Accomplishments

- Added `notification_channels`, `notification_routing`, `RoutingRule`, `NotificationRateLimitConfig`, and `QuietHoursConfig` to `SwarmConfig`.
- Extended fail-closed validation for notification targets, timeouts, rate limits, UTC hour windows, and rule-to-channel references.
- Extended runtime `@secret:` resolution to `siem_forward.auth_token` and `notification_channels.*.auth_token`.
- Exported the new config types through runtime and response-layer config modules so the surface is consistent across crates.
- Updated the default ruleset with commented SIEM and notification examples.

## Files Created Or Modified

- `crates/swarm-core/src/config.rs`
- `crates/swarm-runtime/src/config.rs`
- `rulesets/default.yaml`

## Verification

- `cargo test -p swarm-core --lib`
- `cargo test -p swarm-runtime --lib`

## Notes

- Notification auth now follows the same repo-owned secret path as the existing outbound adapters instead of inventing a second configuration mechanism.
