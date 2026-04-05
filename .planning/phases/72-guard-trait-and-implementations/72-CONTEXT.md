# Phase 72 Context: Guard Trait And Implementations

## User Decisions

### Decisions (Locked)

- Port from clawdstrike vendor references, not arc. ClawdStrike guards are security-domain-native and map directly to the swarm response pipeline.
- Guard trait should be **synchronous** (not async). Swarm guards evaluate response actions locally without network calls. The upstream async trait is an artifact of clawdstrike's agent enforcement model.
- GuardContext simplified for swarm: drop org/session/identity/origin/enclave context, keep `agent_id` and `metadata`.
- GuardAction must include swarm's ResponseAction variants (IsolateHost, BlockEgress, RevokeCredential, DeployDecoy, Escalate) alongside clawdstrike's existing file/shell/network types.
- Pipeline combinator must fail closed: any guard rejection stops the pipeline immediately.
- Four concrete guards for this phase: ForbiddenPathGuard, ShellCommandGuard, SecretLeakGuard, EgressAllowlistGuard.
- EgressAllowlistGuard: do NOT depend on hush-proxy DomainPolicy. Implement simple domain matching locally (glob-style wildcards on domain names). The upstream guard delegates to hush-proxy which is not vendored.

### Deferred Ideas

- Spider Sense cosine-similarity detector (depends on embedding infrastructure)
- WASM guard plugin SDK
- Async guards requiring network access
- PromptInjectionGuard, JailbreakGuard (future LLM integration)
- ComputerUseGuard, McpToolGuard (not relevant to swarm response pipeline)
- Policy YAML loading and `extends` inheritance (future config work)
- Merge/intersect config operations (only needed when policy config stacking ships)

### Claude's Discretion

- Internal module organization within swarm-guard (one file per guard vs grouped)
- Severity enum: reuse upstream 4-level (Info/Warning/Error/Critical) or map to swarm-core Severity
- Whether to include Luhn check in SecretLeakGuard (low priority, can simplify)
- Path normalization: port the lexical normalizer, skip the fs-resolving normalizer (guards evaluate action arguments, not real filesystem state)
- Default secret patterns: port the high-value subset (AWS, GitHub, OpenAI, Anthropic, private keys, Slack, Stripe, generic) rather than the full set
- Default forbidden patterns: port the Unix-relevant subset, skip Windows patterns for now

## Key Context

The upstream Guard trait at `vendor/reference/clawdstrike/libs/clawdstrike/src/guards/mod.rs` uses `async_trait`. Swarm guards should be sync because they evaluate string patterns in response action arguments without needing I/O. This simplifies the trait and avoids async runtime requirements in the guard pipeline.

The upstream `GuardAction` enum has variants for file access, file write, network egress, shell commands, MCP tools, and patches. Swarm needs to additionally handle its own `ResponseAction` variants from `swarm-core::types::ResponseAction`.

The upstream `EgressAllowlistGuard` depends on `hush_proxy::policy::DomainPolicy` which is not vendored. The swarm version should implement a simple domain-matching policy inline using glob-style wildcards (exact match, `*.domain.com` prefix wildcards).

## Source Files

- Upstream trait: `vendor/reference/clawdstrike/libs/clawdstrike/src/guards/mod.rs`
- Upstream ForbiddenPath: `vendor/reference/clawdstrike/libs/clawdstrike/src/guards/forbidden_path.rs`
- Upstream ShellCommand: `vendor/reference/clawdstrike/libs/clawdstrike/src/guards/shell_command.rs`
- Upstream SecretLeak: `vendor/reference/clawdstrike/libs/clawdstrike/src/guards/secret_leak.rs`
- Upstream EgressAllowlist: `vendor/reference/clawdstrike/libs/clawdstrike/src/guards/egress_allowlist.rs`
- Upstream PathNormalization: `vendor/reference/clawdstrike/libs/clawdstrike/src/guards/path_normalization.rs`
- Target crate: `crates/swarm-guard/` (currently empty stub)
- Swarm types: `crates/swarm-core/src/types.rs` (ResponseAction, AgentId, etc.)
