<!-- Adapted from ClawdStrike/Arc (Apache-2.0) -->
# SOC2 Type II Compliance Pack

Framework: **SOC2 Type II** — Trust Service Criteria CC6, CC7, CC8.

Guard configurations for AI-agent environments operating under SOC2 audit, with
an emphasis on protecting audit evidence and detecting unauthorized change.
These are **data files** consumed by the Ambush guards lane; no Rust wiring is
added.

## Policies

| Policy | Profile | Use case |
|--------|---------|----------|
| `policies/soc2-strict.yaml` | strict | Production environments under audit |
| `policies/soc2-default.yaml` | default | Development and staging environments |

## What it enforces

- **forbidden_path** — protects audit logs, evidence/compliance directories, Terraform state, and Vault data.
- **secret_leak** — detects API keys, OpenAI/Anthropic/npm/Slack tokens, database URLs, and JWT secrets.
- **egress_allowlist** — default-deny everywhere; strict allows no egress, default permits AI/code-hosting/registry endpoints.
- **shell_command** — blocks log-tampering (truncate, shred, wipe), infrastructure mutation (terraform, kubectl, docker — strict), and exfiltration tooling.
- **mcp_tool** — read-only MCP tool surface under strict; confirmation-gated writes/deletes/`git_push` under default.
- **patch_integrity** — rejects patches that disable logging/audit/monitoring or delete/truncate logs.

## SOC2 mapping

| Criteria | Control | Guard(s) |
|---|---|---|
| CC6.1 | Logical access security | forbidden_path, mcp_tool |
| CC6.3 | Restrict access based on need | egress_allowlist |
| CC7.1 | Detect unauthorized changes | patch_integrity |
| CC7.2 | Monitor system components | secret_leak |
| CC8.1 | Change management | patch_integrity |

## Customization

Add approved monitoring/SIEM services to the egress allowlist in a downstream override:

```yaml
guards:
  egress_allowlist:
    allow:
      - "api.your-monitoring.com"
      - "logs.your-siem.com"
```

## Notes

The upstream pack's `prompt_injection` (default + strict) and `jailbreak`
(strict) guard blocks were dropped — those guards are not present in the Ambush
guards lane this wave (these covered TSC CC7.3 in the original). The upstream
`extends: clawdstrike:*` base reference is commented out; all inherited
path/secret patterns are inlined so each policy is self-contained.
