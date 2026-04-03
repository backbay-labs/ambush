"""
KnowledgeEnricher - Enrich operator prompts with vulnerability intelligence.

Bridges VulnKnowledgeBase with the prompt pipeline by querying relevant
CVEs and exploit techniques for a target's tech stack and vulnerability type,
then formatting the results as a structured <knowledge_context> block for
prompt injection.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from hellcat.offensive.knowledge.vuln_db import VulnKnowledgeBase
    from hellcat.offensive.tools.osint.base import OsintFinding
    from hellcat.offensive.tools.osint.catalog import SearchEngineCategory

logger = structlog.get_logger()


class KnowledgeEnricher:
    """
    Enriches operator prompts with vulnerability knowledge base data.

    Used by the dispatch pipeline to inject CVE intelligence and exploit
    techniques into operator prompts, improving exploitation success.
    """

    def __init__(self, knowledge_db: VulnKnowledgeBase) -> None:
        self._db = knowledge_db

    def enrich_prompt(
        self,
        operator_name: str,
        target_node: dict | None = None,
        tech_stack: str = "",
    ) -> str:
        """
        Generate a <knowledge_context> block for prompt template interpolation.

        Queries relevant CVEs and exploit techniques based on the operator type,
        target node context, and tech stack.

        Args:
            operator_name: Name of the operator (e.g. "injection-exploit").
            target_node: Optional TargetGraph node dict with vuln_type, etc.
            tech_stack: Optional tech stack string (e.g. "express+mysql").

        Returns:
            Formatted knowledge context string, or empty string if no data.
        """
        vuln_type = self._infer_vuln_type(operator_name, target_node)
        if not vuln_type:
            return ""

        lines: list[str] = [
            "<knowledge_context>",
            f"Vulnerability intelligence for {vuln_type}"
            + (f" targeting {tech_stack}" if tech_stack else "")
            + ":",
            "",
        ]

        # Section 1: Relevant CVEs
        cves = self._db.get_cves_for_vuln_type(vuln_type, limit=5)
        if cves:
            lines.append("## Known CVEs")
            for cve in cves:
                lines.append(
                    f"- {cve.cve_id} (CVSS {cve.cvss}): {cve.description[:200]}"
                )
            lines.append("")

        # Section 2: Exploit techniques for this vuln type
        techniques = self._db.get_techniques_for_vuln_type(vuln_type, limit=10)
        if techniques:
            lines.append("## Exploit Techniques")
            for t in techniques:
                lines.append(
                    f"- **{t.name}** ({t.success_rate:.0%} success): "
                    f"{t.description[:150]}"
                )
                if t.payload_template:
                    payload_display = t.payload_template[:120]
                    if len(t.payload_template) > 120:
                        payload_display += "..."
                    lines.append(f"  Payload: `{payload_display}`")
            lines.append("")

        # Section 3: Tech stack intelligence
        if tech_stack:
            sig = self._db.get_tech_signature(tech_stack)
            if sig:
                lines.append("## Tech Stack Intelligence")
                lines.append(f"- Stack: {sig.tech_stack}")
                if sig.common_vulns:
                    lines.append(f"- Common vulns: {', '.join(sig.common_vulns)}")
                if sig.default_configs:
                    for k, v in sig.default_configs.items():
                        lines.append(f"- {k}: {v}")
                if sig.detection_hints:
                    lines.append(f"- Detection hints: {', '.join(sig.detection_hints)}")
                lines.append("")

        # Only return non-empty context
        if len(lines) <= 3:
            return ""

        lines.append(
            "Use this intelligence to inform your exploitation approach. "
            "Prioritize techniques with higher success rates."
        )
        lines.append("</knowledge_context>")

        context = "\n".join(lines)

        logger.debug(
            "knowledge.prompt_enriched",
            operator=operator_name,
            vuln_type=vuln_type,
            tech_stack=tech_stack,
            cves=len(cves),
            techniques=len(techniques),
        )

        return context

    def enrich_evasion_context(
        self,
        block_classification: dict | None = None,
        response_data: dict | None = None,
    ) -> str:
        """
        Generate a <defense_intelligence> block with matched defense info,
        known bypasses, and recommended evasion techniques.

        Uses VulnKnowledgeBase defense signatures to identify the defense
        from response patterns and provide bypass intelligence.

        Args:
            block_classification: Dict with 'reason', 'confidence', 'evidence' etc.
                from FailureClassifier.
            response_data: Dict with 'headers', 'status_code', 'body_snippet'
                from the blocked response.

        Returns:
            Formatted defense intelligence string, or empty string if no match.
        """
        if not response_data and not block_classification:
            return ""

        # Extract response signals
        headers = {}
        status_code = None
        body_snippet = ""
        if response_data:
            headers = response_data.get("headers", {})
            status_code = response_data.get("status_code")
            body_snippet = response_data.get("body_snippet", "")

        # Identify defense from response patterns
        matches = self._db.identify_defense(
            response_headers=headers,
            status_code=status_code,
            body_snippet=body_snippet,
        )

        if not matches:
            return ""

        lines: list[str] = [
            "<defense_intelligence>",
            "## Identified Defense Systems",
            "",
        ]

        for i, (sig, confidence) in enumerate(matches[:3]):  # top 3 matches
            lines.append(f"### Match {i + 1}: {sig.product}")
            lines.append(f"- Defense type: {sig.defense_type}")
            lines.append(f"- Match confidence: {confidence:.0%}")
            lines.append(f"- Bypass difficulty: {sig.severity}")

            if sig.known_bypasses:
                lines.append("- Known bypasses:")
                for bypass in sig.known_bypasses[:4]:
                    lines.append(f"  - {bypass}")

            if sig.evasion_techniques:
                lines.append(
                    f"- Recommended techniques: {', '.join(sig.evasion_techniques[:5])}"
                )
            lines.append("")

        if block_classification:
            reason = block_classification.get("reason", "unknown")
            conf = block_classification.get("confidence", 0)
            lines.append("## Block Classification")
            lines.append(f"- Reason: {reason}")
            lines.append(f"- Confidence: {conf:.0%}")
            evidence = block_classification.get("evidence", "")
            if evidence:
                lines.append(f"- Evidence: {evidence}")
            lines.append("")

        lines.append(
            "Use the bypass techniques above to craft your evasion strategy. "
            "Start with higher-confidence matches."
        )
        lines.append("</defense_intelligence>")

        context = "\n".join(lines)

        logger.debug(
            "knowledge.evasion_enriched",
            defense_matches=len(matches),
            top_match=matches[0][0].product if matches else None,
            top_confidence=matches[0][1] if matches else 0.0,
        )

        return context

    def enrich_osint_context(
        self,
        target_domain: str,
        osint_findings: list[OsintFinding] | None = None,
        categories: list[SearchEngineCategory] | None = None,
    ) -> str:
        """
        Generate a <osint_intelligence> block with OSINT findings and suggestions.

        Formats collected OSINT findings grouped by finding_type and appends
        catalog suggestions for categories where no API data was collected.

        Args:
            target_domain: The target domain being assessed.
            osint_findings: List of OsintFinding objects from OSINT sources.
            categories: Categories to include suggestions for.

        Returns:
            Formatted OSINT intelligence string for prompt injection,
            or empty string if no findings and no suggestions.
        """
        from hellcat.offensive.tools.osint.catalog import format_osint_suggestions

        findings = osint_findings or []

        # Group findings by finding_type
        grouped: dict[str, list] = {}
        for f in findings:
            grouped.setdefault(f.finding_type, []).append(f)

        lines: list[str] = [
            "<osint_intelligence>",
            f"OSINT intelligence for {target_domain}:",
            "",
        ]

        has_content = False

        # Section: Subdomains
        if "subdomain" in grouped:
            subs = grouped["subdomain"]
            values = list(dict.fromkeys(f.value for f in subs))
            has_content = True
            lines.append(f"## Subdomains ({len(values)} discovered)")
            for v in values[:20]:
                lines.append(f"- {v}")
            if len(values) > 20:
                lines.append(f"- ... and {len(values) - 20} more")
            lines.append("")

        # Section: Certificates
        if "certificate" in grouped:
            certs = grouped["certificate"]
            has_content = True
            lines.append(f"## Certificates ({len(certs)} found)")
            for c in certs[:10]:
                issuer = c.metadata.get("issuer", "")
                not_after = c.metadata.get("not_after", "")
                detail = f" (issuer: {issuer})" if issuer else ""
                detail += f" expires: {not_after}" if not_after else ""
                lines.append(f"- {c.value}{detail}")
            if len(certs) > 10:
                lines.append(f"- ... and {len(certs) - 10} more")
            lines.append("")

        # Section: CVEs
        if "cve" in grouped:
            cves = grouped["cve"]
            has_content = True
            lines.append(f"## CVEs ({len(cves)} found)")
            for c in cves[:10]:
                cvss = c.metadata.get("cvss", "")
                desc = c.metadata.get("description", "")
                score = f" (CVSS {cvss})" if cvss else ""
                short_desc = f": {desc[:150]}" if desc else ""
                lines.append(f"- {c.value}{score}{short_desc}")
            if len(cves) > 10:
                lines.append(f"- ... and {len(cves) - 10} more")
            lines.append("")

        # Section: Services
        if "service" in grouped:
            svcs = grouped["service"]
            has_content = True
            lines.append(f"## Services ({len(svcs)} found)")
            for s in svcs[:10]:
                port = s.metadata.get("port", "")
                product = s.metadata.get("product", "")
                detail = f" port:{port}" if port else ""
                detail += f" ({product})" if product else ""
                lines.append(f"- {s.value}{detail}")
            if len(svcs) > 10:
                lines.append(f"- ... and {len(svcs) - 10} more")
            lines.append("")

        # Section: DNS records
        if "dns_record" in grouped:
            dns = grouped["dns_record"]
            has_content = True
            lines.append(f"## DNS Records ({len(dns)} found)")
            for d in dns[:10]:
                rtype = d.metadata.get("record_type", "")
                prefix = f"[{rtype}] " if rtype else ""
                lines.append(f"- {prefix}{d.value}")
            if len(dns) > 10:
                lines.append(f"- ... and {len(dns) - 10} more")
            lines.append("")

        # Section: Other finding types
        rendered = {
            "subdomain", "certificate", "cve", "service", "dns_record",
        }
        for ftype, items in grouped.items():
            if ftype in rendered:
                continue
            has_content = True
            label = ftype.replace("_", " ").title()
            lines.append(f"## {label} ({len(items)} found)")
            for item in items[:10]:
                lines.append(f"- {item.value}")
            if len(items) > 10:
                lines.append(f"- ... and {len(items) - 10} more")
            lines.append("")

        # Append catalog suggestions for categories without collected data
        suggestions = format_osint_suggestions(
            target_domain, categories=categories,
        )
        if suggestions:
            has_content = True
            lines.append(suggestions)
            lines.append("")

        if not has_content:
            return ""

        lines.append(
            "Use this OSINT intelligence to expand the attack surface "
            "and prioritize targets with known vulnerabilities."
        )
        lines.append("</osint_intelligence>")

        logger.debug(
            "knowledge.osint_enriched",
            target=target_domain,
            finding_types=list(grouped.keys()),
            total_findings=len(findings),
        )

        return "\n".join(lines)

    def _infer_vuln_type(
        self, operator_name: str, target_node: dict | None,
    ) -> str:
        """Infer vulnerability type from operator name and target node."""
        # First try the target node
        if target_node:
            vt = target_node.get("vuln_type", "")
            if vt:
                return vt

        # Map operator names to vuln types
        op_to_vuln: dict[str, str] = {
            "injection-vuln": "sqli",
            "injection-exploit": "sqli",
            "exploit-injection": "sqli",
            "vuln-injection": "sqli",
            "xss-vuln": "xss",
            "xss-exploit": "xss",
            "exploit-xss": "xss",
            "vuln-xss": "xss",
            "auth-vuln": "auth_bypass",
            "auth-exploit": "auth_bypass",
            "exploit-auth": "auth_bypass",
            "vuln-auth": "auth_bypass",
            "authz-vuln": "idor",
            "authz-exploit": "idor",
            "exploit-authz": "idor",
            "vuln-authz": "idor",
            "ssrf-vuln": "ssrf",
            "ssrf-exploit": "ssrf",
            "exploit-ssrf": "ssrf",
            "vuln-ssrf": "ssrf",
        }
        return op_to_vuln.get(operator_name, "")
