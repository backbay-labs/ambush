<!-- Adapted from ClawdStrike/Arc (Apache-2.0) -->
# PCI-DSS v4.0 Compliance Pack

Framework: **PCI-DSS v4.0** — Requirements 3, 4, 6, 7, 10.

Guard configurations for AI-agent environments that touch a Cardholder Data
Environment (CDE). These are **data files** consumed by the Ambush guards lane;
no Rust wiring is added.

## Policies

| Policy | Profile | Use case |
|--------|---------|----------|
| `policies/pci-strict.yaml` | strict | Production CDE (Cardholder Data Environment) |
| `policies/pci-default.yaml` | default | Development and staging environments |

## What it enforces

- **forbidden_path** — blocks access to cardholder data, PAN/payment keys, HSM, keystore, tokenization, transaction logs, and DEK/KEK key material.
- **secret_leak** — detects PANs (Visa, Mastercard, Amex), CVV/CVC, magnetic track data, Stripe keys, and hex encryption keys.
- **egress_allowlist** — restricts network egress to PCI-relevant payment processors and card networks; default-deny.
- **shell_command** — blocks database-dump tools (mysqldump, pg_dump, mongodump), network sniffers (tcpdump, tshark, ngrep), and exfiltration tooling.
- **mcp_tool** — read-only MCP tool surface under strict; confirmation-gated writes/deletes under default.
- **patch_integrity** — rejects patches that disable encryption/PCI controls or introduce plaintext passwords.

## PCI-DSS mapping

| Requirement | Control | Guard(s) |
|---|---|---|
| 3.4 | Render PAN unreadable | secret_leak (PAN detection) |
| 3.5 | Protect stored account data | forbidden_path |
| 4.2 | Protect CHD during transmission | egress_allowlist |
| 6.3 | Security in development | patch_integrity |
| 7.1 | Restrict access to system components | mcp_tool |
| 10.2 | Audit trail | patch_integrity (audit protection) |

## Customization

Add your payment-processor endpoints to the egress allowlist in a downstream override:

```yaml
guards:
  egress_allowlist:
    allow:
      - "api.your-processor.com"
```

## Notes

The upstream pack's `prompt_injection` (default + strict) and `jailbreak`
(strict) guard blocks were dropped — those guards are not present in the Ambush
guards lane this wave. The upstream `extends: clawdstrike:*` base reference is
commented out; all inherited path/secret patterns are inlined so each policy is
self-contained.
