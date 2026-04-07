---
phase: 110-notification-channels-and-routing-rules
type: context
created_at: 2026-04-07
depends_on: [109]
---

# Phase 110 Context

## Goal

Add repo-owned notification channel configuration and a rule DSL that routes findings by severity, threat class, and UTC time windows.

## Why This Phase Exists

SIEM delivery covers passive aggregation, but production alerting still needs targeted routing to webhook-style notification channels. The current runtime has no configurable notification map, no time-window-aware routing, and no finding-level match language separate from response execution.

## What Is Already True

- `SwarmConfig` already holds repo-owned outbound configuration for response adapters and the operator surface.
- `WebhookAdapter` already proves the runtime can deliver JSON payloads to generic HTTP endpoints with optional bearer auth.
- The authenticated operator surface already exists and can expose new repo-owned runtime artifacts without adding a second control plane.
- The detection lane already emits fully typed `Severity` and `ThreatClass` values, which gives the routing DSL stable match inputs.

## Constraints

- Notification routing must stay independent from the response-action policy gate; alerting is about operator visibility, not host action authority.
- Channel auth must support the same `@secret:` rotation path as other outbound integrations.
- The routing DSL should be expressive enough for severity, threat-class, and UTC time windows without turning into a general-purpose policy language.
- Channel configuration must remain repo-owned and serializable through `SwarmConfig`.

## Decisions

- `notification_channels` will live as a named map in `SwarmConfig`, while `notification_routing` will hold rule order plus a shared dedup window.
- Rules should match findings by minimum severity, optional threat-class selector, and optional UTC hour window, then fan out to one or more named channels.
- Notification delivery can use direct HTTP posts with bearer auth and repo-owned JSON payloads rather than overloading the existing webhook response adapter.
- Notification-channel auth tokens should resolve through the same secret-provider path already used for response adapters.

## Phase Direction

- Land config and validation first, then add routing evaluation and runtime integration.
- Keep payloads canonical and channel-agnostic so later operator replay can re-send the same suppressed alert body.
