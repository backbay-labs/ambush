<!-- Adapted from ClawdStrike/Arc (Apache-2.0) -->
# HIPAA Compliance Pack

Framework: **HIPAA** — 45 CFR 164.312 (Technical Safeguards).

Guard configurations for AI-agent environments that handle Protected Health
Information (PHI). These are **data files** consumed by the Ambush guards lane;
the pack defines guard parameters only and adds no Rust wiring.

## Policies

| Policy | Profile | Use case |
|--------|---------|----------|
| `policies/hipaa-strict.yaml` | strict | Production environments handling PHI |
| `policies/hipaa-default.yaml` | default | Development and staging with PHI test data |

## What it enforces

- **forbidden_path** — blocks access to PHI directories, patient data, EHR exports, medical/health records.
- **secret_leak** — detects SSNs, medical record numbers (MRN), DEA numbers, NPIs, and health-plan IDs alongside standard credential patterns.
- **egress_allowlist** — restricts network egress to HIPAA-relevant interoperability endpoints (HL7, FHIR, approved EHR endpoints); default-deny.
- **shell_command** — blocks data-exfiltration tooling (curl, wget, scp, nc, …) and destructive commands.
- **mcp_tool** — read-only MCP tool surface under strict; confirmation-gated writes/deletes under default.
- **patch_integrity** — rejects patches that disable security/audit controls or skip consent/validation.

## HIPAA mapping

| Section | Control | Guard(s) |
|---|---|---|
| 164.312(a)(1) | Access Control | forbidden_path, path_allowlist* |
| 164.312(b) | Audit Controls | patch_integrity (audit-log protection) |
| 164.312(c)(1) | Integrity | secret_leak, patch_integrity |
| 164.312(d) | Authentication | mcp_tool (tool-level gating) |
| 164.312(e)(1) | Transmission Security | egress_allowlist |

\* `path_allowlist` is part of the guards lane landing this wave; reference it once the guard ships.

## Customization

Append organization-specific FHIR endpoints to the egress allowlist in a downstream override:

```yaml
guards:
  egress_allowlist:
    allow:
      - "fhir.your-ehr.com"
      - "api.your-health-system.org"
```

## Notes

The upstream pack's `prompt_injection` (default + strict) and `jailbreak`
(strict) guard blocks were dropped — those guards are not present in the Ambush
guards lane this wave. The upstream `extends: clawdstrike:*` base reference is
commented out; all inherited path/secret patterns are inlined so each policy is
self-contained.
