"""Parser for PMapper CLI output."""
from __future__ import annotations

import json
from typing import Any

import structlog

logger = structlog.get_logger()


class PMapperParser:
    """Parse PMapper JSON output into dicts."""

    @staticmethod
    def parse(output: str) -> list[dict[str, Any]]:
        """Parse PMapper privesc query output."""
        if not output or not output.strip():
            return []

        try:
            data = json.loads(output)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("results", data.get("paths", [data]))
        except (json.JSONDecodeError, ValueError):
            pass

        # Try line-by-line JSON
        results: list[dict[str, Any]] = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    results.append(obj)
            except (json.JSONDecodeError, ValueError):
                continue
        return results
