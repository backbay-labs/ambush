"""Report templates for executive summary and technical report sections."""

from __future__ import annotations

EXECUTIVE_SUMMARY_TEMPLATE = """\
# Executive Summary

## Engagement Overview

| Field | Value |
|-------|-------|
| Target | {target_url} |
| Engagement ID | {engagement_id} |
| Duration | {duration} |
| Start | {start_time} |
| End | {end_time} |

## Key Metrics

| Metric | Count |
|--------|-------|
| Total Vulnerabilities Found | {vulns_found} |
| Vulnerabilities Exploited | {vulns_exploited} |
| Credentials Harvested | {creds_harvested} |
| Defenses Observed | {defenses_observed} |
| Total Cost | ${total_cost:.4f} |

## Critical Findings

{critical_findings}

## Risk Assessment

{risk_assessment}

## Remediation Priorities

{remediation_priorities}
"""

FINDINGS_TABLE_TEMPLATE = """\
## Findings Summary

| # | Severity | Type | Endpoint | Evidence | Status |
|---|----------|------|----------|----------|--------|
{findings_rows}
"""

FINDING_DETAIL_TEMPLATE = """\
### Finding {index}: {vuln_type}

| Field | Value |
|-------|-------|
| Severity | {severity} |
| Confidence | {confidence:.0%} |
| CVSS | {cvss} |
| CVSS v4 | {cvss_v4} |
| EPSS Score | {epss_score} |
| EPSS Percentile | {epss_percentile} |
| Endpoint | {endpoint} |
| Evidence Level | {evidence_level} |
| Status | {status} |

**Description:** {description}

{prioritization_section}

{payload_section}

{impact_section}

{remediation_section}
"""

OPSEC_SUMMARY_TEMPLATE = """\
## OPSEC Summary

| Metric | Value |
|--------|-------|
| Final Noise Score | {noise_score} |
| Stealth Budget Used | {budget_used} |
| Circuit Breaker State | {circuit_state} |
| Total Signals | {signal_count} |

{opsec_notes}
"""

ATTACK_GRAPH_TEMPLATE = """\
## Attack Graph

```
{graph_text}
```
"""

PHASE_BREAKDOWN_TEMPLATE = """\
## Phase Breakdown

| Phase | Cells | Duration | Cost | Success | Failed |
|-------|-------|----------|------|---------|--------|
{phase_rows}

| **Total** | **{total_cells}** | **{total_duration}** | **${total_cost:.4f}** | **{total_success}** | **{total_failed}** |
"""
