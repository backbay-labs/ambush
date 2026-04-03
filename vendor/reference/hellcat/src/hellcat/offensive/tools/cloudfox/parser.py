"""Parser for CloudFox CLI output."""
from __future__ import annotations

import csv
import io
import json
from typing import Any

import structlog

logger = structlog.get_logger()


class CloudFoxParser:
    """Parse CloudFox CSV or JSON output into dicts."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """Parse CloudFox output, trying JSON first then CSV."""
        if not output or not output.strip():
            return []

        # Try JSON first
        try:
            data = json.loads(output)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("results", data.get("data", [data]))
        except (json.JSONDecodeError, ValueError):
            pass

        # Fall back to CSV
        return CloudFoxParser._parse_csv(output)

    @staticmethod
    def _parse_csv(output: str) -> list[dict[str, Any]]:
        """Parse CSV-formatted CloudFox output."""
        results: list[dict[str, Any]] = []
        try:
            reader = csv.DictReader(io.StringIO(output))
            for row in reader:
                results.append(dict(row))
        except Exception:
            logger.debug("cloudfox.csv_parse_failed")
        return results
