#!/usr/bin/env python3
"""
Drill score gate runner (prototype).

Reads drill spec, ground truth events, and detections (or ledger alerts)
and emits a drill_score.json file with metrics and an overall verdict.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any


def _parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _load_ground_truth(run_dir: Path, path: str | None) -> tuple[list[dict[str, Any]], str | None]:
    if path:
        gt_path = Path(path)
        if not gt_path.is_absolute():
            gt_path = run_dir / gt_path
    else:
        gt_path = run_dir / "ground_truth.json"

    data = _load_json(gt_path)
    if not data:
        return [], None

    events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(events, list):
        return [], str(gt_path)

    return events, str(gt_path)


def _load_detections(
    run_dir: Path,
    path: str | None,
) -> tuple[list[dict[str, Any]], str | None, int | None]:
    if path:
        det_path = Path(path)
        if not det_path.is_absolute():
            det_path = run_dir / det_path
    else:
        det_path = run_dir / "detections.json"

    data = _load_json(det_path)
    if not data:
        return [], None, None

    if isinstance(data, dict):
        detections = data.get("detections")
        policy_violations = data.get("policy_violations")
    else:
        detections = data
        policy_violations = None

    if not isinstance(detections, list):
        return [], str(det_path), policy_violations

    return detections, str(det_path), policy_violations


def _load_ledger(run_dir: Path) -> tuple[list[dict[str, Any]], str | None]:
    ledger_path = run_dir / "ledger.jsonl"
    if not ledger_path.exists():
        return [], None

    events = []
    try:
        with ledger_path.open() as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                events.append(json.loads(line))
    except (OSError, json.JSONDecodeError):
        return [], str(ledger_path)

    return events, str(ledger_path)


def _detections_from_ledger(ledger_events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    detections = []
    policy_violations = 0

    for event in ledger_events:
        event_type = event.get("type")
        if event_type == "shield_alert":
            data = event.get("data", {})
            detections.append(
                {
                    "detection_id": event.get("event_id"),
                    "attack_event_id": data.get("attack_event_id") or data.get("event_id"),
                    "timestamp": event.get("timestamp"),
                }
            )
        elif event_type == "policy_violation":
            policy_violations += 1

    return detections, policy_violations


def _compute_metrics(
    ground_truth: list[dict[str, Any]],
    detections: list[dict[str, Any]],
    policy_violations: int | None,
) -> dict[str, Any]:
    gt_by_id = {event.get("event_id"): event for event in ground_truth if event.get("event_id")}

    detection_count = len(detections)
    matched_by_id: dict[str, dict[str, Any]] = {}
    false_positives = 0

    for detection in detections:
        attack_event_id = detection.get("attack_event_id")
        if attack_event_id and attack_event_id in gt_by_id:
            existing = matched_by_id.get(attack_event_id)
            if not existing:
                matched_by_id[attack_event_id] = detection
            else:
                existing_time = _parse_iso8601(existing.get("timestamp"))
                new_time = _parse_iso8601(detection.get("timestamp"))
                if existing_time is None or (new_time and new_time < existing_time):
                    matched_by_id[attack_event_id] = detection
        else:
            false_positives += 1

    total_attacks = len(gt_by_id)
    coverage = (len(matched_by_id) / total_attacks) if total_attacks else 0.0
    false_positive_rate = (false_positives / detection_count) if detection_count else 0.0

    ttd_values = []
    for attack_event_id, detection in matched_by_id.items():
        event = gt_by_id.get(attack_event_id, {})
        event_time = _parse_iso8601(event.get("timestamp"))
        det_time = _parse_iso8601(detection.get("timestamp"))
        if event_time and det_time:
            ttd_values.append((det_time - event_time).total_seconds())

    ttd_seconds = (sum(ttd_values) / len(ttd_values)) if ttd_values else None

    return {
        "coverage": coverage,
        "false_positive_rate": false_positive_rate,
        "ttd_seconds": ttd_seconds,
        "ttc_seconds": None,
        "policy_violations": policy_violations,
    }


def _normalize_metric(value: float | None, direction: str, max_value: float | None) -> float:
    if value is None:
        return 0.0

    if max_value and max_value > 0:
        normalized = min(value / max_value, 1.0)
    else:
        normalized = value

    if direction == "lower_is_better":
        normalized = 1.0 - normalized

    return max(0.0, min(1.0, normalized))


def _score_from_config(
    metrics: dict[str, Any],
    scoring: dict[str, Any],
) -> tuple[dict[str, Any], float, bool]:
    metric_results = {}
    weighted_sum = 0.0
    weight_total = 0.0
    all_passed = True

    for metric_cfg in scoring.get("metrics", []):
        metric_id = metric_cfg.get("id")
        if not metric_id:
            continue

        value = metrics.get(metric_id)
        direction = metric_cfg.get("direction", "higher_is_better")
        threshold = metric_cfg.get("threshold")
        weight = metric_cfg.get("weight", 0.0)
        max_value = metric_cfg.get("max_value")

        passed = True
        if value is None:
            passed = False
        elif direction == "higher_is_better" and threshold is not None:
            passed = value >= threshold
        elif direction == "lower_is_better" and threshold is not None:
            passed = value <= threshold

        if not passed:
            all_passed = False

        normalized = _normalize_metric(value, direction, max_value)
        weighted_sum += normalized * weight
        weight_total += weight

        metric_results[metric_id] = {
            "value": value,
            "threshold": threshold,
            "weight": weight,
            "passed": passed,
        }

    overall_score = (weighted_sum / weight_total) * 100 if weight_total > 0 else 0.0
    overall_threshold = scoring.get("overall_threshold", 0)
    overall_passed = overall_score >= overall_threshold

    return metric_results, overall_score, all_passed and overall_passed


def main() -> int:
    parser = argparse.ArgumentParser(description="Score a range drill run")
    parser.add_argument("run_dir", help="Path to run directory")
    parser.add_argument("--drill-spec", dest="drill_spec", help="Path to drill spec JSON")
    parser.add_argument("--ground-truth", dest="ground_truth", help="Path to ground truth JSON")
    parser.add_argument("--detections", dest="detections", help="Path to detections JSON")
    parser.add_argument("--run-id", dest="run_id", help="Override run id")
    parser.add_argument("--output", dest="output", help="Output path for drill score JSON")

    args = parser.parse_args()
    run_dir = Path(args.run_dir)

    started_at = datetime.utcnow()
    start_time = time.time()
    errors = []

    if not run_dir.exists():
        print(f"Run dir not found: {run_dir}")
        return 2

    drill_spec_path = Path(args.drill_spec) if args.drill_spec else run_dir / "drill_spec.json"
    drill_spec = _load_json(drill_spec_path)
    if not drill_spec:
        errors.append(f"Missing or invalid drill spec: {drill_spec_path}")
        drill_spec = {}

    scoring_cfg = drill_spec.get("scoring", {}) if isinstance(drill_spec, dict) else {}
    drill_id = drill_spec.get("drill_id") if isinstance(drill_spec, dict) else None
    range_template_ref = drill_spec.get("range_template_ref") if isinstance(drill_spec, dict) else None
    range_template_id = ""
    if isinstance(range_template_ref, dict):
        range_template_id = range_template_ref.get("hash") or range_template_ref.get("uri") or ""

    ground_truth, ground_truth_path = _load_ground_truth(run_dir, args.ground_truth)
    if not ground_truth:
        errors.append("Ground truth events missing")

    detections, detections_path, detections_policy_violations = _load_detections(
        run_dir,
        args.detections,
    )

    ledger_events, ledger_path = _load_ledger(run_dir)
    policy_violations = detections_policy_violations

    if not detections:
        ledger_detections, policy_violations = _detections_from_ledger(ledger_events)
        detections = ledger_detections

    if policy_violations is None:
        policy_violations = 0

    metrics = _compute_metrics(ground_truth, detections, policy_violations)
    metric_results, overall_score, passed = _score_from_config(metrics, scoring_cfg)

    verdict = "pass" if passed else "fail"
    run_id = args.run_id or run_dir.name

    output = {
        "schema_version": "1.0",
        "gate_id": "drill-score",
        "run_id": run_id,
        "drill_id": drill_id or "",
        "range_template_id": range_template_id,
        "verdict": verdict,
        "passed": passed,
        "score": round(overall_score, 4),
        "metrics": metric_results,
        "thresholds": {
            "overall_threshold": scoring_cfg.get("overall_threshold", 0),
        },
        "artifacts": {
            "ground_truth_path": ground_truth_path,
            "detections_path": detections_path,
            "ledger_path": ledger_path,
            "drill_spec_path": str(drill_spec_path) if drill_spec_path.exists() else None,
        },
        "timing": {
            "started_at": started_at.isoformat() + "Z",
            "completed_at": datetime.utcnow().isoformat() + "Z",
            "duration_ms": int((time.time() - start_time) * 1000),
        },
        "errors": errors,
    }

    output_path = Path(args.output) if args.output else run_dir / "drill_score.json"
    output_path.write_text(json.dumps(output, indent=2))

    print(json.dumps(output, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
