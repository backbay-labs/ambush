# Phase 118: Operational Hardening - Context

**Gathered:** 2026-04-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Close two operational audit findings: independent secret-dir file-watch for hot rotation and size-based dead-letter journal rotation. Pure infrastructure hardening.

</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion

All implementation choices are at Claude's discretion — pure infrastructure phase. The audit findings define the exact changes:
- HARDEN-08: SwarmSecretProvider file-watch monitors secret_dir independently; re-resolves @secret: refs without full config reload
- HARDEN-09: Dead-letter journals rotate when exceeding max_dead_letter_bytes; rotated file gets timestamp suffix

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- SwarmSecretProvider (FileEnvSecretProvider) in swarm-runtime/src/config.rs
- Config file-watch using notify crate in swarm-runtime/src/swarm_detect.rs
- DeadLetterJournal in swarm-response/src/resilience.rs
- RuntimeSettings in swarm-core/src/config.rs

### Established Patterns
- Config reload via tokio watch channel on file change
- @secret:env:VAR and @secret:filename resolution at config load time
- Dead-letter uses append-only JSONL with read_entries(limit)

### Integration Points
- Response adapters (HttpEdrConfig, WebhookConfig) reference @secret: tokens
- NotificationRouter channels reference @secret: auth
- DeadLetterJournal::write() appends to JSONL file
- RuntimeSettings loaded from SwarmConfig YAML

</code_context>

<specifics>
## Specific Ideas

No specific requirements — infrastructure phase driven by audit findings.

</specifics>

<deferred>
## Deferred Ideas

None — both findings are in scope.

</deferred>
