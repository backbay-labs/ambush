#!/usr/bin/env python3
"""Compile detections from ledger events for drill scoring."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any


def _load_ledger_events(ledger_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    events = []
    errors = []

    try:
        with ledger_path.open() as handle:
            for line_num, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    errors.append(f"invalid_json_line:{line_num}")
    except OSError as exc:
        errors.append(f"read_failed:{exc}")

    return events, errors


def compile_detections_from_ledger(
    ledger_path: Path,
    output_path: Path,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Compile detections JSON from ledger.jsonl."""
    events, errors = _load_ledger_events(ledger_path)
    detections = []
    policy_violations = 0
    inferred_run_id = run_id

    for event in events:
        event_type = event.get("type")
        if not inferred_run_id:
            inferred_run_id = event.get("run_id") or inferred_run_id

        if event_type == "shield_alert":
            data = event.get("data", {})
            metadata = data.get("metadata", {}) if isinstance(data.get("metadata"), dict) else {}

            attack_event_id = (
                data.get("attack_event_id")
                or metadata.get("attack_event_id")
                or data.get("event_id")
                or metadata.get("event_id")
            )

            detections.append(
                {
                    "detection_id": event.get("event_id") or data.get("alert_id"),
                    "attack_event_id": attack_event_id,
                    "timestamp": event.get("timestamp"),
                    "rule_id": data.get("rule_id") or metadata.get("rule_id"),
                    "severity": data.get("severity") or metadata.get("severity"),
                    "shield": data.get("shield"),
                    "summary": data.get("summary"),
                    "source_event_id": event.get("event_id"),
                    "details": data,
                }
            )
        elif event_type == "policy_violation":
            policy_violations += 1

    payload = {
        "schema_version": "1.0",
        "run_id": inferred_run_id or "",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "source": str(ledger_path),
        "detections": detections,
        "policy_violations": policy_violations,
        "errors": errors,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2))

    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile detections from ledger.jsonl")
    parser.add_argument("ledger", help="Path to ledger.jsonl")
    parser.add_argument("--output", help="Output path for detections.json")
    parser.add_argument("--run-id", dest="run_id", help="Override run id")

    args = parser.parse_args()
    ledger_path = Path(args.ledger)

    if not ledger_path.exists():
        print(f"Ledger not found: {ledger_path}")
        return 2

    output_path = Path(args.output) if args.output else ledger_path.parent / "detections.json"
    payload = compile_detections_from_ledger(ledger_path, output_path, run_id=args.run_id)

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
