"""
Match Score Gate for Attack/Defend CTF

Computes final match scorecard from:
1. Match event log (captures, outages, IR actions)
2. Uptime check results
3. Flag capture records

Outputs MatchScorecard JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class MatchEvent:
    """Parsed match event from log."""
    event_type: str
    timestamp: datetime
    team_id: str | None
    service_id: str | None
    details: dict[str, Any]


def load_match_manifest(path: Path) -> dict[str, Any]:
    """Load AttackDefendMatchManifest."""
    with open(path) as f:
        return json.load(f)


def load_event_log(path: Path) -> list[MatchEvent]:
    """Load match event log (JSONL format)."""
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            events.append(MatchEvent(
                event_type=data.get("event_type", ""),
                timestamp=datetime.fromisoformat(data.get("timestamp", "")),
                team_id=data.get("team_id"),
                service_id=data.get("service_id"),
                details=data,
            ))
    return events


def load_uptime_results(path: Path) -> dict[str, dict[str, Any]]:
    """Load uptime check results per team."""
    with open(path) as f:
        return json.load(f)


def load_flag_captures(path: Path) -> list[dict[str, Any]]:
    """Load flag capture records."""
    with open(path) as f:
        return json.load(f)


def compute_team_scores(
    manifest: dict[str, Any],
    events: list[MatchEvent],
    uptime: dict[str, dict[str, Any]],
    captures: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Compute scores for each team."""
    scoring = manifest.get("scoring", {})
    uptime_weight = scoring.get("uptime_weight", 0.4)
    flag_weight = scoring.get("flag_capture_weight", 0.4)
    defense_weight = scoring.get("defense_weight", 0.2)
    rotating_flag_points = scoring.get("rotating_flag_points", 100)
    eviction_points = scoring.get("defense_eviction_points", 50)
    detection_points = scoring.get("defense_detection_points", 25)
    recovery_points = scoring.get("defense_recovery_points", 25)

    teams = {}
    for team_def in manifest.get("teams", []):
        team_id = team_def["team_id"]
        teams[team_id] = {
            "team_id": team_id,
            "team_name": team_def.get("name", team_id),
            "uptime_score": 0.0,
            "flag_score": 0.0,
            "defense_score": 0.0,
            "final_score": 0.0,
            "metrics": {
                "uptime_pct": 0.0,
                "flags_captured": 0,
                "flags_lost": 0,
                "crown_jewels_captured": 0,
                "crown_jewels_lost": 0,
                "evictions": 0,
                "first_detections": 0,
                "recoveries": 0,
                "services_compromised": 0,
                "outage_seconds": 0,
            },
        }

    # Process uptime results
    for team_id, team_uptime in uptime.items():
        if team_id not in teams:
            continue
        teams[team_id]["uptime_score"] = team_uptime.get("total_points", 0)
        teams[team_id]["metrics"]["uptime_pct"] = team_uptime.get("uptime_pct", 0)

    # Process flag captures
    for capture in captures:
        if not capture.get("valid", False):
            continue
        
        submitting = capture.get("submitting_team_id")
        target = capture.get("target_team_id")
        points = capture.get("points", rotating_flag_points)
        is_crown = capture.get("is_crown_jewel", False)

        if submitting in teams:
            teams[submitting]["flag_score"] += points
            teams[submitting]["metrics"]["flags_captured"] += 1
            if is_crown:
                teams[submitting]["metrics"]["crown_jewels_captured"] += 1

        if target in teams:
            teams[target]["metrics"]["flags_lost"] += 1
            if is_crown:
                teams[target]["metrics"]["crown_jewels_lost"] += 1

    # Process events for defense scoring
    for event in events:
        team_id = event.team_id
        if team_id not in teams:
            continue

        if event.event_type == "match.attacker_evicted":
            teams[team_id]["defense_score"] += eviction_points
            teams[team_id]["metrics"]["evictions"] += 1
        elif event.event_type == "match.intrusion_detected":
            teams[team_id]["defense_score"] += detection_points
            teams[team_id]["metrics"]["first_detections"] += 1
        elif event.event_type == "match.service_recovered":
            teams[team_id]["defense_score"] += recovery_points
            teams[team_id]["metrics"]["recoveries"] += 1
        elif event.event_type == "match.service_outage":
            # Track outages (penalty handled elsewhere)
            teams[team_id]["metrics"]["services_compromised"] += 1

    # Compute final weighted scores
    for team in teams.values():
        team["final_score"] = (
            team["uptime_score"] * uptime_weight +
            team["flag_score"] * flag_weight +
            team["defense_score"] * defense_weight
        )

    return teams


def determine_winner(teams: dict[str, dict[str, Any]]) -> str | None:
    """Determine winner, applying tiebreakers if needed."""
    sorted_teams = sorted(teams.values(), key=lambda t: t["final_score"], reverse=True)
    
    if len(sorted_teams) < 2:
        return sorted_teams[0]["team_id"] if sorted_teams else None

    first = sorted_teams[0]
    second = sorted_teams[1]

    if first["final_score"] > second["final_score"]:
        return first["team_id"]

    # Tiebreaker 1: More flags captured
    if first["metrics"]["flags_captured"] != second["metrics"]["flags_captured"]:
        return first["team_id"] if first["metrics"]["flags_captured"] > second["metrics"]["flags_captured"] else second["team_id"]

    # Tiebreaker 2: Higher uptime
    if first["metrics"]["uptime_pct"] != second["metrics"]["uptime_pct"]:
        return first["team_id"] if first["metrics"]["uptime_pct"] > second["metrics"]["uptime_pct"] else second["team_id"]

    # Tiebreaker 3: Fewer flags lost
    if first["metrics"]["flags_lost"] != second["metrics"]["flags_lost"]:
        return first["team_id"] if first["metrics"]["flags_lost"] < second["metrics"]["flags_lost"] else second["team_id"]

    return None  # True tie


def generate_scorecard(
    manifest: dict[str, Any],
    teams: dict[str, dict[str, Any]],
    winner: str | None,
    duration_seconds: int,
    flag_rotations: int,
    uptime_ticks: int,
    events: list[MatchEvent],
) -> dict[str, Any]:
    """Generate MatchScorecard output."""
    return {
        "schema_version": "1.0",
        "match_id": manifest["match_id"],
        "tournament_id": manifest.get("tournament_id", ""),
        "mode": "attack_defend",
        "duration_seconds": duration_seconds,
        "teams": [
            {
                "team_id": t["team_id"],
                "team_name": t["team_name"],
                "final_score": t["final_score"],
                "breakdown": {
                    "uptime_score": t["uptime_score"],
                    "flag_score": t["flag_score"],
                    "defense_score": t["defense_score"],
                },
                "metrics": t["metrics"],
            }
            for t in teams.values()
        ],
        "winner": winner,
        "tiebreaker_applied": winner is None or (
            len(set(t["final_score"] for t in teams.values())) < len(teams)
        ),
        "flag_rotations": flag_rotations,
        "uptime_ticks": uptime_ticks,
        "events_summary": {
            "total_events": len(events),
            "flag_captures": sum(1 for e in events if "flag_captured" in e.event_type),
            "service_outages": sum(1 for e in events if "service_outage" in e.event_type),
            "ir_actions": sum(1 for e in events if any(x in e.event_type for x in ["evicted", "detected", "recovered"])),
        },
    }


def main() -> int:
    """CLI entrypoint for match-score gate."""
    parser = argparse.ArgumentParser(description="Match Score Gate for Attack/Defend CTF")
    parser.add_argument("workdir", help="Working directory with match artifacts")
    parser.add_argument("--manifest", default="match_manifest.json", help="Match manifest file")
    parser.add_argument("--events", default="events.jsonl", help="Event log file")
    parser.add_argument("--uptime", default="uptime_results.json", help="Uptime results file")
    parser.add_argument("--captures", default="flag_captures.json", help="Flag captures file")
    parser.add_argument("--out", default="match_scorecard.json", help="Output scorecard file")
    parser.add_argument("--json", action="store_true", help="Output JSON to stdout")
    parser.add_argument("--dry-run", action="store_true", help="Dry run with stub data")

    args = parser.parse_args()
    workdir = Path(args.workdir)

    if args.dry_run:
        # Generate stub output
        scorecard = {
            "schema_version": "1.0",
            "match_id": "match_dry_run",
            "mode": "attack_defend",
            "duration_seconds": 2700,
            "teams": [
                {
                    "team_id": "team_alpha",
                    "team_name": "Alpha",
                    "final_score": 0,
                    "breakdown": {"uptime_score": 0, "flag_score": 0, "defense_score": 0},
                    "metrics": {},
                },
                {
                    "team_id": "team_beta",
                    "team_name": "Beta",
                    "final_score": 0,
                    "breakdown": {"uptime_score": 0, "flag_score": 0, "defense_score": 0},
                    "metrics": {},
                },
            ],
            "winner": None,
            "verdict": "dry_run",
        }
    else:
        # Load inputs
        manifest_path = workdir / args.manifest
        events_path = workdir / args.events
        uptime_path = workdir / args.uptime
        captures_path = workdir / args.captures

        if not manifest_path.exists():
            print(f"Error: Manifest not found: {manifest_path}", file=sys.stderr)
            return 1

        manifest = load_match_manifest(manifest_path)

        events = []
        if events_path.exists():
            events = load_event_log(events_path)

        uptime = {}
        if uptime_path.exists():
            uptime = load_uptime_results(uptime_path)

        captures = []
        if captures_path.exists():
            captures = load_flag_captures(captures_path)

        # Compute scores
        teams = compute_team_scores(manifest, events, uptime, captures)
        winner = determine_winner(teams)

        # Extract timing from events
        duration_seconds = manifest.get("duration_seconds", 2700)
        flag_rotations = sum(1 for e in events if "flags_rotated" in e.event_type)
        uptime_ticks = len(uptime.get(next(iter(uptime), ""), {}).get("checks", [])) if uptime else 0

        scorecard = generate_scorecard(
            manifest, teams, winner, duration_seconds, flag_rotations, uptime_ticks, events
        )

    # Output
    if args.json:
        print(json.dumps(scorecard, indent=2))
    else:
        out_path = workdir / args.out
        with open(out_path, "w") as f:
            json.dump(scorecard, f, indent=2)
        print(f"Wrote scorecard to {out_path}")

        # Print summary
        print(f"\nMatch: {scorecard['match_id']}")
        for team in scorecard["teams"]:
            print(f"  {team['team_name']}: {team['final_score']:.1f} pts")
        print(f"Winner: {scorecard['winner'] or 'TIE'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
