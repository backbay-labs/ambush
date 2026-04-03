#!/usr/bin/env python3
"""
Workbench score gate runner (Artifact Arena scoring).

Evaluates workbench challenge submissions (RE/CTF) and produces a score
based on:
- Flag correctness and submission time
- Detector quality (if applicable)
- Writeup quality (optional, manual)

Outputs a workbench_score.json file with metrics and verdict.
"""

from __future__ import annotations

import argparse
import hashlib
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


def _load_challenge_spec(run_dir: Path, path: str | None) -> tuple[dict[str, Any], str | None]:
    """Load challenge specification."""
    if path:
        spec_path = Path(path)
        if not spec_path.is_absolute():
            spec_path = run_dir / spec_path
    else:
        spec_path = run_dir / "challenge_spec.json"
    
    data = _load_json(spec_path)
    if not data:
        return {}, None
    
    return data, str(spec_path)


def _load_submission(run_dir: Path, path: str | None) -> tuple[dict[str, Any], str | None]:
    """Load challenge submission."""
    if path:
        sub_path = Path(path)
        if not sub_path.is_absolute():
            sub_path = run_dir / sub_path
    else:
        sub_path = run_dir / "submission.json"
    
    data = _load_json(sub_path)
    if not data:
        return {}, None
    
    return data, str(sub_path)


def _verify_flag(submitted: str, expected: str, flag_format: str = "plain") -> bool:
    """Verify a flag submission."""
    if flag_format == "hash":
        # Expected is a hash, hash the submission to compare
        submitted_hash = hashlib.sha256(submitted.encode()).hexdigest()
        return submitted_hash.lower() == expected.lower()
    else:
        # Plain text comparison
        return submitted.strip() == expected.strip()


def _compute_solve_time_score(
    solve_time_seconds: float,
    timebox_seconds: int,
    optimal_seconds: int = 300,
) -> float:
    """Compute solve time score (0-1, higher is better)."""
    if solve_time_seconds <= 0:
        return 1.0
    
    if solve_time_seconds <= optimal_seconds:
        # Fast solve bonus
        return 1.0
    
    if solve_time_seconds >= timebox_seconds:
        # Out of time
        return 0.0
    
    # Linear interpolation between optimal and timebox
    remaining = timebox_seconds - optimal_seconds
    elapsed = solve_time_seconds - optimal_seconds
    return max(0.0, 1.0 - (elapsed / remaining))


def _evaluate_detector_quality(
    detector_path: Path | None,
    baseline_samples: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Evaluate detector quality against baseline samples."""
    if not detector_path or not detector_path.exists():
        return {
            "score": 0.0,
            "passed": False,
            "reason": "No detector submitted",
        }
    
    if not baseline_samples:
        return {
            "score": 0.5,
            "passed": True,
            "reason": "No baseline samples to test against",
        }
    
    # TODO: Actually run detector against samples
    # For now, return a stub result
    return {
        "score": 0.75,
        "passed": True,
        "reason": "Detector submitted (evaluation stubbed)",
        "samples_tested": len(baseline_samples),
        "true_positives": 0,
        "false_positives": 0,
        "true_negatives": 0,
        "false_negatives": 0,
    }


def _score_from_config(
    metrics: dict[str, Any],
    scoring: dict[str, Any],
) -> tuple[dict[str, Any], float, bool]:
    """Score metrics against configuration thresholds."""
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
        
        passed = True
        if value is None:
            passed = False
        elif direction == "higher_is_better" and threshold is not None:
            passed = value >= threshold
        elif direction == "lower_is_better" and threshold is not None:
            passed = value <= threshold
        
        if not passed:
            all_passed = False
        
        # Normalize for weighted sum
        normalized = value if value is not None else 0.0
        if direction == "lower_is_better":
            normalized = 1.0 - min(normalized, 1.0)
        
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
    parser = argparse.ArgumentParser(description="Score a workbench challenge")
    parser.add_argument("run_dir", help="Path to run directory")
    parser.add_argument("--challenge-spec", dest="challenge_spec", help="Path to challenge spec JSON")
    parser.add_argument("--submission", dest="submission", help="Path to submission JSON")
    parser.add_argument("--run-id", dest="run_id", help="Override run id")
    parser.add_argument("--output", dest="output", help="Output path for workbench score JSON")

    args = parser.parse_args()
    run_dir = Path(args.run_dir)

    started_at = datetime.utcnow()
    start_time = time.time()
    errors = []

    if not run_dir.exists():
        print(f"Run dir not found: {run_dir}")
        return 2

    # Load challenge spec
    challenge_spec, spec_path = _load_challenge_spec(run_dir, args.challenge_spec)
    if not challenge_spec:
        errors.append(f"Missing or invalid challenge spec: {spec_path}")
        challenge_spec = {}
    
    # Load submission
    submission, submission_path = _load_submission(run_dir, args.submission)
    if not submission:
        errors.append(f"Missing or invalid submission: {submission_path}")
        submission = {}

    # Extract config
    scoring_cfg = challenge_spec.get("scoring", {})
    challenge_id = challenge_spec.get("challenge_id", "")
    timebox_seconds = challenge_spec.get("metadata", {}).get("timebox_seconds", 3600)
    flags = challenge_spec.get("flags", [])
    flag_format = challenge_spec.get("flag_format", "plain")
    
    # Evaluate flags
    submitted_flags = submission.get("flags", [])
    correct_flags = 0
    total_flags = len(flags)
    
    for i, expected_flag in enumerate(flags):
        if i < len(submitted_flags):
            if _verify_flag(submitted_flags[i], expected_flag.get("value", ""), flag_format):
                correct_flags += 1
    
    flag_score = correct_flags / total_flags if total_flags > 0 else 0.0
    
    # Evaluate solve time
    solve_time_seconds = submission.get("solve_time_seconds", timebox_seconds)
    solve_time_score = _compute_solve_time_score(
        solve_time_seconds,
        timebox_seconds,
        optimal_seconds=challenge_spec.get("optimal_seconds", 300),
    )
    
    # Evaluate detector (if applicable)
    detector_path = None
    if submission.get("detector_path"):
        detector_path = run_dir / submission["detector_path"]
    
    detector_result = _evaluate_detector_quality(
        detector_path,
        challenge_spec.get("baseline_samples"),
    )
    detector_score = detector_result.get("score", 0.0)
    
    # Build metrics
    metrics = {
        "flag_score": flag_score,
        "solve_time_score": solve_time_score,
        "detector_score": detector_score,
        "flags_correct": correct_flags,
        "flags_total": total_flags,
        "solve_time_seconds": solve_time_seconds,
    }
    
    # Score against config
    if scoring_cfg.get("metrics"):
        metric_results, overall_score, passed = _score_from_config(metrics, scoring_cfg)
    else:
        # Default scoring: 50% flags, 30% time, 20% detector
        overall_score = (flag_score * 50 + solve_time_score * 30 + detector_score * 20)
        passed = flag_score >= 0.5 and overall_score >= 50
        metric_results = {
            "flag_score": {"value": flag_score, "threshold": 0.5, "weight": 0.5, "passed": flag_score >= 0.5},
            "solve_time_score": {"value": solve_time_score, "threshold": 0.0, "weight": 0.3, "passed": True},
            "detector_score": {"value": detector_score, "threshold": 0.0, "weight": 0.2, "passed": True},
        }
    
    verdict = "pass" if passed else "fail"
    run_id = args.run_id or run_dir.name

    output = {
        "schema_version": "1.0",
        "gate_id": "workbench-score",
        "run_id": run_id,
        "challenge_id": challenge_id,
            "verdict": verdict,
        "passed": passed,
        "score": round(overall_score, 4),
        "metrics": metric_results,
        "raw_metrics": metrics,
        "detector": detector_result,
        "thresholds": {
            "overall_threshold": scoring_cfg.get("overall_threshold", 50),
        },
        "artifacts": {
            "challenge_spec_path": spec_path,
            "submission_path": submission_path,
            "detector_path": str(detector_path) if detector_path else None,
        },
        "timing": {
            "started_at": started_at.isoformat() + "Z",
            "completed_at": datetime.utcnow().isoformat() + "Z",
            "duration_ms": int((time.time() - start_time) * 1000),
            "solve_time_seconds": solve_time_seconds,
        },
        "errors": errors,
    }

    output_path = Path(args.output) if args.output else run_dir / "workbench_score.json"
    output_path.write_text(json.dumps(output, indent=2))
    
    print(json.dumps(output, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
