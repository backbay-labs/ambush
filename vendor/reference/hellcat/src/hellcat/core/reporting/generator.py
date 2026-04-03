"""
ReportGenerator - Queries TargetGraph and AuditSession to produce
executive and technical engagement reports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from hellcat.core.audit.session import AuditSession, EngagementSummary
from hellcat.core.reporting._helpers import _parse_meta, _suggest_remediation
from hellcat.core.reporting.ghostwriter import GhostwriterFormatter
from hellcat.core.reporting.templates import (
    ATTACK_GRAPH_TEMPLATE,
    EXECUTIVE_SUMMARY_TEMPLATE,
    FINDING_DETAIL_TEMPLATE,
    FINDINGS_TABLE_TEMPLATE,
    PHASE_BREAKDOWN_TEMPLATE,
)
from hellcat.offensive.target_graph.graph import TargetGraph

logger = structlog.get_logger()

# Severity ordering for sorting
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _build_prioritization_rationale(
    finding: dict[str, Any], meta: dict[str, Any],
) -> str:
    """Build a text rationale explaining why a finding was prioritized."""
    parts: list[str] = []
    severity = finding.get("severity", "info")
    parts.append(f"Severity: {severity.upper()}")

    epss = meta.get("epss_score")
    if epss is not None:
        pct = meta.get("epss_percentile")
        pct_str = f" (percentile {pct:.0%})" if pct is not None else ""
        parts.append(f"EPSS exploit probability: {epss:.4f}{pct_str}")

    v4 = meta.get("cvss_v4_score")
    if v4 is not None:
        parts.append(f"CVSS v4: {v4}")

    kev = meta.get("kev", False)
    if kev:
        parts.append("Listed in CISA KEV catalog (actively exploited)")

    if not parts:
        return ""
    return "**Prioritization:** " + ". ".join(parts) + "."


@dataclass
class ReportBundle:
    """Complete report output from the generator."""

    executive_summary: str
    technical_report: str
    findings: list[dict[str, Any]]
    evidence_files: list[Path] = field(default_factory=list)


class ReportGenerator:
    """Generates engagement reports from TargetGraph and AuditSession data."""

    def generate(
        self,
        graph: TargetGraph,
        audit_session: AuditSession,
        output_dir: Path | None = None,
    ) -> ReportBundle:
        """Generate executive and technical reports.

        Args:
            graph: TargetGraph with engagement data.
            audit_session: AuditSession with metrics.
            output_dir: Optional directory to write report files to.

        Returns:
            ReportBundle with rendered reports and findings.
        """
        summary = audit_session.get_summary()
        stats = graph.get_stats()

        # Collect all findings from TargetGraph
        findings = self._collect_findings(graph)
        credentials = self._collect_credentials(graph)
        defenses = self._collect_defenses(graph)

        executive = self._build_executive_summary(
            summary=summary,
            stats=stats,
            findings=findings,
            credentials=credentials,
            defenses=defenses,
        )

        technical = self._build_technical_report(
            summary=summary,
            stats=stats,
            findings=findings,
            credentials=credentials,
            defenses=defenses,
            graph=graph,
        )

        bundle = ReportBundle(
            executive_summary=executive,
            technical_report=technical,
            findings=findings,
        )

        if output_dir:
            self._write_to_disk(bundle, output_dir)

        logger.info(
            "report.generated",
            findings=len(findings),
            credentials=len(credentials),
            defenses=len(defenses),
        )

        return bundle

    def _collect_findings(self, graph: TargetGraph) -> list[dict[str, Any]]:
        """Query all vulnerability nodes from the graph."""
        rows = graph.conn.execute(
            "SELECT * FROM vulnerabilities ORDER BY severity, confidence DESC"
        ).fetchall()
        findings = [dict(r) for r in rows]
        # Sort by severity rank
        findings.sort(key=lambda f: _SEVERITY_RANK.get(f.get("severity", "info"), 4))
        return findings

    def _collect_credentials(self, graph: TargetGraph) -> list[dict[str, Any]]:
        """Query all credential nodes from the graph."""
        rows = graph.conn.execute("SELECT * FROM credentials").fetchall()
        return [dict(r) for r in rows]

    def _collect_defenses(self, graph: TargetGraph) -> list[dict[str, Any]]:
        """Query all defense nodes from the graph."""
        rows = graph.conn.execute("SELECT * FROM defenses").fetchall()
        return [dict(r) for r in rows]

    def _build_executive_summary(
        self,
        summary: EngagementSummary,
        stats: dict[str, Any],
        findings: list[dict[str, Any]],
        credentials: list[dict[str, Any]],
        defenses: list[dict[str, Any]],
    ) -> str:
        duration = f"{summary.duration_ms / 1000:.1f}s" if summary.duration_ms else "N/A"

        # Critical findings
        critical = [f for f in findings if f.get("severity") in ("critical", "high")]
        if critical:
            lines = []
            for i, f in enumerate(critical, 1):
                lines.append(
                    f"{i}. **{f.get('vuln_type', 'unknown')}** "
                    f"({f.get('severity', '?')}) - {f.get('description', '')[:100]}"
                )
            critical_text = "\n".join(lines)
        else:
            critical_text = "No critical or high-severity findings."

        # Risk assessment
        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        exploited_count = sum(
            1 for f in findings if f.get("status") == "exploited"
        )
        risk_lines = []
        for sev in ("critical", "high", "medium", "low", "info"):
            count = sev_counts.get(sev, 0)
            if count:
                risk_lines.append(f"- **{sev.upper()}**: {count} finding(s)")
        if exploited_count:
            risk_lines.append(f"- **Exploited**: {exploited_count} vulnerability(ies) confirmed exploitable")
        risk_text = "\n".join(risk_lines) if risk_lines else "No significant risk identified."

        # Remediation priorities
        remed_lines = []
        for f in critical:
            remed_lines.append(
                f"- Fix **{f.get('vuln_type', 'unknown')}** at `{f.get('source_location', 'N/A')}`"
            )
        remed_text = "\n".join(remed_lines) if remed_lines else "No immediate remediation required."

        return EXECUTIVE_SUMMARY_TEMPLATE.format(
            target_url=summary.target_url,
            engagement_id=summary.engagement_id,
            duration=duration,
            start_time=summary.start_time,
            end_time=summary.end_time or "in progress",
            vulns_found=len(findings),
            vulns_exploited=exploited_count,
            creds_harvested=len(credentials),
            defenses_observed=len(defenses),
            total_cost=summary.total_cost_usd,
            critical_findings=critical_text,
            risk_assessment=risk_text,
            remediation_priorities=remed_text,
        )

    def _build_technical_report(
        self,
        summary: EngagementSummary,
        stats: dict[str, Any],
        findings: list[dict[str, Any]],
        credentials: list[dict[str, Any]],
        defenses: list[dict[str, Any]],
        graph: TargetGraph,
    ) -> str:
        sections: list[str] = []
        sections.append("# Technical Report\n")

        # Findings table
        sections.append(self._render_findings_table(findings))

        # Per-finding detail
        sections.append("## Detailed Findings\n")
        for i, f in enumerate(findings, 1):
            sections.append(self._render_finding_detail(i, f))

        # Phase breakdown
        if summary.phases:
            sections.append(self._render_phase_breakdown(summary))

        # Attack graph (text-based)
        sections.append(self._render_attack_graph(graph, findings))

        # Defense observations
        if defenses:
            sections.append(self._render_defenses(defenses))

        # Credentials
        if credentials:
            sections.append(self._render_credentials(credentials))

        return "\n".join(sections)

    def _render_findings_table(self, findings: list[dict[str, Any]]) -> str:
        rows = []
        for i, f in enumerate(findings, 1):
            meta = _parse_meta(f)
            evidence = meta.get("validated_level", "N/A")
            rows.append(
                f"| {i} | {f.get('severity', '?')} | {f.get('vuln_type', '?')} "
                f"| {f.get('source_location', 'N/A')[:40]} | {evidence} "
                f"| {f.get('status', '?')} |"
            )
        return FINDINGS_TABLE_TEMPLATE.format(findings_rows="\n".join(rows))

    def _render_finding_detail(self, index: int, finding: dict[str, Any]) -> str:
        meta = _parse_meta(finding)

        # Payload section
        payload = finding.get("witness_payload", "")
        payload_section = ""
        if payload:
            payload_section = f"**Payload:**\n```\n{payload}\n```"

        # Impact section
        impact = meta.get("impact_description", "")
        impact_section = f"**Impact:** {impact}" if impact else ""

        # Remediation
        remed = _suggest_remediation(finding.get("vuln_type", ""))
        remed_section = f"**Remediation:** {remed}" if remed else ""

        # EPSS / CVSS v4 enrichment
        epss_score = meta.get("epss_score")
        epss_percentile = meta.get("epss_percentile")
        cvss_v4_score = meta.get("cvss_v4_score")
        cvss_v4_vector = meta.get("cvss_v4_vector", "")

        epss_str = f"{epss_score:.4f}" if epss_score is not None else "N/A"
        epss_pct_str = f"{epss_percentile:.2%}" if epss_percentile is not None else "N/A"
        cvss_v4_str = (
            f"{cvss_v4_score} ({cvss_v4_vector})" if cvss_v4_score is not None else "N/A"
        )

        # Prioritization rationale
        prioritization_section = _build_prioritization_rationale(finding, meta)

        return FINDING_DETAIL_TEMPLATE.format(
            index=index,
            vuln_type=finding.get("vuln_type", "unknown"),
            severity=finding.get("severity", "unknown"),
            confidence=finding.get("confidence", 0),
            cvss=finding.get("cvss") or "N/A",
            cvss_v4=cvss_v4_str,
            epss_score=epss_str,
            epss_percentile=epss_pct_str,
            endpoint=finding.get("source_location", "N/A"),
            evidence_level=meta.get("validated_level", "N/A"),
            status=finding.get("status", "unknown"),
            description=finding.get("description", "No description"),
            prioritization_section=prioritization_section,
            payload_section=payload_section,
            impact_section=impact_section,
            remediation_section=remed_section,
        )

    def _render_phase_breakdown(self, summary: EngagementSummary) -> str:
        rows = []
        for p in summary.phases:
            duration = f"{p.total_duration_ms / 1000:.1f}s"
            rows.append(
                f"| {p.phase} | {p.cell_count} | {duration} "
                f"| ${p.total_cost_usd:.4f} | {p.success_count} | {p.failure_count} |"
            )

        total_dur = sum(p.total_duration_ms for p in summary.phases)
        return PHASE_BREAKDOWN_TEMPLATE.format(
            phase_rows="\n".join(rows),
            total_cells=summary.total_cells,
            total_duration=f"{total_dur / 1000:.1f}s",
            total_cost=summary.total_cost_usd,
            total_success=summary.total_succeeded,
            total_failed=summary.total_failed,
        )

    def _render_attack_graph(
        self, graph: TargetGraph, findings: list[dict[str, Any]],
    ) -> str:
        """Render a text-based attack graph showing nodes and edges."""
        lines: list[str] = []

        # Group findings by status
        exploited = [f for f in findings if f.get("status") == "exploited"]
        blocked = [f for f in findings if f.get("status") == "blocked"]
        other = [f for f in findings if f.get("status") not in ("exploited", "blocked")]

        if exploited:
            lines.append("[EXPLOITED]")
            for f in exploited:
                lines.append(f"  (+) {f.get('vuln_type', '?')} @ {f.get('source_location', '?')[:30]}")
                # Show chains
                chains = graph.get_exploit_chains(f["id"])
                for chain in chains:
                    chain_str = " -> ".join(nid[:8] for nid in chain)
                    lines.append(f"      chain: {chain_str}")

        if blocked:
            lines.append("[BLOCKED]")
            for f in blocked:
                lines.append(f"  (x) {f.get('vuln_type', '?')} @ {f.get('source_location', '?')[:30]}")

        if other:
            lines.append("[OTHER]")
            for f in other:
                lines.append(f"  (?) {f.get('vuln_type', '?')} [{f.get('status', '?')}]")

        graph_text = "\n".join(lines) if lines else "(no findings)"
        return ATTACK_GRAPH_TEMPLATE.format(graph_text=graph_text)

    def _render_defenses(self, defenses: list[dict[str, Any]]) -> str:
        lines = ["## Defense Observations\n"]
        lines.append("| Type | Strength | Behavior |")
        lines.append("|------|----------|----------|")
        for d in defenses:
            lines.append(
                f"| {d.get('defense_type', '?')} | {d.get('strength', '?')} "
                f"| {d.get('observed_behavior', '')[:60]} |"
            )
        return "\n".join(lines)

    def _render_credentials(self, credentials: list[dict[str, Any]]) -> str:
        lines = ["## Harvested Credentials\n"]
        lines.append("| Username | Type | Access Level | Source |")
        lines.append("|----------|------|--------------|--------|")
        for c in credentials:
            lines.append(
                f"| {c.get('username', '?')} | {c.get('credential_type', '?')} "
                f"| {c.get('access_level', 'N/A')} | {c.get('source', 'N/A')[:40]} |"
            )
        return "\n".join(lines)

    def _write_to_disk(self, bundle: ReportBundle, output_dir: Path) -> None:
        """Write report files to the output directory."""
        output_dir.mkdir(parents=True, exist_ok=True)

        exec_path = output_dir / "executive_summary.md"
        exec_path.write_text(bundle.executive_summary, encoding="utf-8")

        tech_path = output_dir / "technical_report.md"
        tech_path.write_text(bundle.technical_report, encoding="utf-8")

        findings_path = output_dir / "findings.json"
        findings_path.write_text(
            json.dumps(bundle.findings, indent=2, default=str),
            encoding="utf-8",
        )

        gw_formatter = GhostwriterFormatter()
        gw_formatter.format(bundle, output_dir=output_dir)

        logger.info(
            "report.written",
            output_dir=str(output_dir),
            files=[
                "executive_summary.md",
                "technical_report.md",
                "findings.json",
                "ghostwriter_findings.json",
            ],
        )
