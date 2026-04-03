"""
Output formatters for engagement reports.

MarkdownFormatter produces .md files, JSONFormatter produces
machine-readable .json files, SARIFFormatter produces SARIF v2.1.0
JSON files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from hellcat.core.reporting._helpers import _parse_meta
from hellcat.core.reporting.generator import ReportBundle, _build_prioritization_rationale
from hellcat.core.reporting.sarif import SARIFFormatter

logger = structlog.get_logger()


class MarkdownFormatter:
    """Writes ReportBundle as Markdown files."""

    def format(self, bundle: ReportBundle, output_dir: Path) -> list[Path]:
        """Write executive summary and technical report as .md files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []

        exec_path = output_dir / "executive_summary.md"
        exec_path.write_text(bundle.executive_summary, encoding="utf-8")
        files.append(exec_path)

        tech_path = output_dir / "technical_report.md"
        tech_path.write_text(bundle.technical_report, encoding="utf-8")
        files.append(tech_path)

        logger.info("formatter.markdown.written", files=[str(f) for f in files])
        return files


class JSONFormatter:
    """Writes ReportBundle as machine-readable JSON."""

    def format(self, bundle: ReportBundle, output_dir: Path) -> list[Path]:
        """Write findings and report metadata as .json files."""
        output_dir.mkdir(parents=True, exist_ok=True)
        files: list[Path] = []

        enriched = [self._enrich_finding(f) for f in bundle.findings]

        findings_path = output_dir / "findings.json"
        findings_path.write_text(
            json.dumps(enriched, indent=2, default=str),
            encoding="utf-8",
        )
        files.append(findings_path)

        report_path = output_dir / "report.json"
        report_data = {
            "executive_summary": bundle.executive_summary,
            "technical_report": bundle.technical_report,
            "findings_count": len(bundle.findings),
            "evidence_files": [str(p) for p in bundle.evidence_files],
        }
        report_path.write_text(
            json.dumps(report_data, indent=2, default=str),
            encoding="utf-8",
        )
        files.append(report_path)

        logger.info("formatter.json.written", files=[str(f) for f in files])
        return files

    @staticmethod
    def _enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
        """Add EPSS/CVSS v4/prioritization fields to finding dict for JSON output."""
        meta = _parse_meta(finding)
        enriched = dict(finding)
        enriched["epss_score"] = meta.get("epss_score")
        enriched["epss_percentile"] = meta.get("epss_percentile")
        enriched["cvss_v4_score"] = meta.get("cvss_v4_score")
        enriched["cvss_v4_vector"] = meta.get("cvss_v4_vector")
        enriched["prioritization_rationale"] = _build_prioritization_rationale(
            finding, meta,
        )
        return enriched


# ---------------------------------------------------------------------------
# Formatter registry
# ---------------------------------------------------------------------------

_FORMATTERS: dict[str, Any] = {
    "markdown": MarkdownFormatter,
    "json": JSONFormatter,
    "sarif": SARIFFormatter,
}


def get_formatter(
    fmt: str,
) -> MarkdownFormatter | JSONFormatter | SARIFFormatter:
    """Return a formatter instance for the given format name.

    Raises:
        ValueError: If the format is not supported.
    """
    cls = _FORMATTERS.get(fmt)
    if cls is None:
        raise ValueError(
            f"Unknown report format '{fmt}'. "
            f"Supported: {sorted(_FORMATTERS)}"
        )
    return cls()
