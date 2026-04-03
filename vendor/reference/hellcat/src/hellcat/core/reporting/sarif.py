"""
SARIF v2.1.0 formatter for Hellcat engagement reports.

Produces Static Analysis Results Interchange Format (SARIF) output
compatible with GitHub Code Scanning, Azure DevOps, and other SARIF
consumers.
"""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any

import structlog

from hellcat.core.reporting.generator import ReportBundle

logger = structlog.get_logger()

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
    "/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
HELLCAT_VERSION = "0.1.0"

_SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _finding_to_result(finding: dict[str, Any]) -> dict[str, Any]:
    """Map a Hellcat finding dict to a SARIF result object."""
    vuln_type = finding.get("vuln_type", "unknown")
    severity = finding.get("severity", "info")
    description = finding.get("description", "")
    location = finding.get("source_location", "")
    status = finding.get("status", "discovered")
    confidence = finding.get("confidence", 0.5)
    cvss = finding.get("cvss")
    witness = finding.get("witness_payload", "")

    # Parse metadata_json if present
    meta: dict[str, Any] = {}
    meta_raw = finding.get("metadata_json", "{}")
    if isinstance(meta_raw, str):
        with contextlib.suppress(json.JSONDecodeError, TypeError):
            meta = json.loads(meta_raw)
    elif isinstance(meta_raw, dict):
        meta = meta_raw

    result: dict[str, Any] = {
        "ruleId": vuln_type,
        "level": _SEVERITY_TO_LEVEL.get(severity, "note"),
        "message": {"text": description or f"{vuln_type} vulnerability"},
        "locations": [],
        "properties": {
            "severity": severity,
            "confidence": confidence,
            "status": status,
            "operator": meta.get("operator", ""),
            "proof_level": meta.get("validated_level", ""),
        },
    }

    if cvss is not None:
        result["properties"]["cvss"] = cvss

    # EPSS enrichment
    epss_score = meta.get("epss_score")
    if epss_score is not None:
        result["properties"]["epss_score"] = epss_score
    epss_pct = meta.get("epss_percentile")
    if epss_pct is not None:
        result["properties"]["epss_percentile"] = epss_pct

    # CVSS v4 enrichment
    cvss_v4 = meta.get("cvss_v4_score")
    if cvss_v4 is not None:
        result["properties"]["cvss_v4_score"] = cvss_v4
    cvss_v4_vec = meta.get("cvss_v4_vector")
    if cvss_v4_vec:
        result["properties"]["cvss_v4_vector"] = cvss_v4_vec

    if witness:
        result["properties"]["witness_payload"] = witness[:500]

    if location:
        loc: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": location},
            },
        }
        result["locations"].append(loc)

    return result


class SARIFFormatter:
    """Writes ReportBundle as a SARIF v2.1.0 JSON file."""

    def format(
        self, bundle: ReportBundle, output_dir: Path,
    ) -> list[Path]:
        """Write findings as sarif.json in output_dir."""
        output_dir.mkdir(parents=True, exist_ok=True)

        results = [_finding_to_result(f) for f in bundle.findings]

        # Collect unique rule IDs for the rules array
        seen_rules: dict[str, dict[str, Any]] = {}
        for r in results:
            rid = r["ruleId"]
            if rid not in seen_rules:
                seen_rules[rid] = {
                    "id": rid,
                    "shortDescription": {
                        "text": rid.replace("_", " ").title(),
                    },
                }

        sarif: dict[str, Any] = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Hellcat",
                            "version": HELLCAT_VERSION,
                            "informationUri": (
                                "https://github.com/backbay/hellcat"
                            ),
                            "rules": list(seen_rules.values()),
                        },
                    },
                    "results": results,
                },
            ],
        }

        sarif_path = output_dir / "sarif.json"
        sarif_path.write_text(
            json.dumps(sarif, indent=2, default=str),
            encoding="utf-8",
        )

        logger.info("formatter.sarif.written", path=str(sarif_path))
        return [sarif_path]
