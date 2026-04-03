"""Schema helpers for Aegis artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# File lives at: kernel/src/cyntra/trust/aegis/schemas.py
# Repo schemas live at: kernel/schemas/...
SCHEMAS_ROOT = Path(__file__).resolve().parents[4] / "schemas" / "aegis"
SCORECARD_SCHEMA_PATH = SCHEMAS_ROOT / "scorecard.schema.json"
RANGE_MATCH_SCHEMA_PATH = SCHEMAS_ROOT / "range-match-manifest.schema.json"
WORKBENCH_CHALLENGE_SCHEMA_PATH = SCHEMAS_ROOT / "workbench-challenge-manifest.schema.json"


def load_scorecard_schema() -> dict[str, Any]:
    """Load the scorecard JSON schema."""
    with open(SCORECARD_SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


def load_range_match_manifest_schema() -> dict[str, Any]:
    """Load the range match manifest JSON schema."""
    with open(RANGE_MATCH_SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


def load_workbench_challenge_manifest_schema() -> dict[str, Any]:
    """Load the workbench challenge manifest JSON schema."""
    with open(WORKBENCH_CHALLENGE_SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)
