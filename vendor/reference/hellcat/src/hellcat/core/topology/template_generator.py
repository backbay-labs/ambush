"""
Template Generator - Auto-generate topology templates from archive data.

Scans completed runs in .hellcat/archives/ and .hellcat/runs/, clusters
recurring phase patterns, and emits new topology YAML templates when a
pattern has sufficient frequency and success rate.

Generated templates are written to .hellcat/topologies/auto-{hash}.yaml
with lower priority than manually-created templates.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class PhasePattern:
    """A recurring phase sequence extracted from archive data."""

    phase_names: tuple[str, ...]
    agent_roles: tuple[str, ...]
    synthesis_modes: tuple[str, ...]

    # Aggregated stats
    occurrences: int = 0
    successes: int = 0
    total_duration_ms: int = 0
    total_tokens: int = 0

    # Source runs
    source_run_ids: list[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        return self.successes / self.occurrences if self.occurrences > 0 else 0.0

    @property
    def avg_duration_ms(self) -> int:
        return self.total_duration_ms // max(self.occurrences, 1)

    @property
    def avg_tokens(self) -> int:
        return self.total_tokens // max(self.occurrences, 1)

    @property
    def pattern_hash(self) -> str:
        key = "|".join(self.phase_names) + ":" + "|".join(self.agent_roles)
        return hashlib.sha256(key.encode()).hexdigest()[:12]


@dataclass
class RunRecord:
    """Minimal record of a completed topology run."""

    run_id: str
    topology_name: str
    outcome: str  # "success" | "failure" | "timeout"
    phase_names: list[str]
    agent_roles: list[str]
    synthesis_modes: list[str]
    duration_ms: int
    tokens_used: int
    tags: list[str] = field(default_factory=list)


class TemplateGenerator:
    """
    Generates topology templates from archived run data.

    Scans archive/run directories for completed topology executions,
    clusters by phase pattern, and generates YAML templates for
    patterns that meet frequency and success thresholds.
    """

    def __init__(
        self,
        archives_dir: Path,
        runs_dir: Path,
        topologies_dir: Path,
        *,
        min_occurrences: int = 5,
        min_success_rate: float = 0.7,
        auto_template_priority: int = 50,
    ) -> None:
        self.archives_dir = Path(archives_dir)
        self.runs_dir = Path(runs_dir)
        self.topologies_dir = Path(topologies_dir)
        self.min_occurrences = min_occurrences
        self.min_success_rate = min_success_rate
        self.auto_template_priority = auto_template_priority

    def scan_runs(self) -> list[RunRecord]:
        """Scan archives and runs directories for completed topology runs."""
        records: list[RunRecord] = []

        for search_dir in [self.archives_dir, self.runs_dir]:
            if not search_dir.exists():
                continue
            for run_dir in search_dir.iterdir():
                if not run_dir.is_dir():
                    continue
                record = self._parse_run_dir(run_dir)
                if record is not None:
                    records.append(record)

        logger.info("Scanned %d completed topology runs", len(records))
        return records

    def _parse_run_dir(self, run_dir: Path) -> RunRecord | None:
        """Parse a single run directory into a RunRecord."""
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
            return None

        try:
            manifest = json.loads(manifest_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

        topology_name = manifest.get("topology") or manifest.get("topology_name")
        if not topology_name:
            return None

        outcome = manifest.get("outcome", "unknown")
        if outcome not in ("success", "failure", "timeout"):
            return None

        # Extract phase info from manifest
        phases = manifest.get("phases", [])
        phase_names = []
        agent_roles = []
        synthesis_modes = []
        for phase in phases:
            if isinstance(phase, dict):
                phase_names.append(phase.get("name", "unknown"))
                agent_roles.append(phase.get("agent_role", "executor"))
                synthesis_modes.append(phase.get("synthesis", "merge"))
            elif isinstance(phase, str):
                phase_names.append(phase)
                agent_roles.append("executor")
                synthesis_modes.append("merge")

        if not phase_names:
            # Try extracting from topology name convention: "template:description"
            # or from events stored alongside the manifest
            events_path = run_dir / "events.jsonl"
            if events_path.exists():
                phase_names = self._extract_phases_from_events(events_path)
                agent_roles = ["executor"] * len(phase_names)
                synthesis_modes = ["merge"] * len(phase_names)

        if not phase_names:
            return None

        return RunRecord(
            run_id=run_dir.name,
            topology_name=topology_name,
            outcome=outcome,
            phase_names=phase_names,
            agent_roles=agent_roles,
            synthesis_modes=synthesis_modes,
            duration_ms=int(manifest.get("duration_ms", 0)),
            tokens_used=int(manifest.get("total_tokens", 0)),
            tags=manifest.get("tags", []),
        )

    def _extract_phases_from_events(self, events_path: Path) -> list[str]:
        """Extract phase names from an events JSONL file."""
        phase_names: list[str] = []
        try:
            for line in events_path.read_text().splitlines():
                event = json.loads(line)
                event_type = event.get("type", "")
                data = event.get("data", {})
                if event_type == "topology.started" and "phases" in data:
                    return [p if isinstance(p, str) else p.get("name", "unknown") for p in data["phases"]]
                if event_type == "phase.started":
                    name = data.get("phase_name") or data.get("name")
                    if name and name not in phase_names:
                        phase_names.append(name)
        except (json.JSONDecodeError, OSError):
            pass
        return phase_names

    def cluster_patterns(self, records: list[RunRecord]) -> list[PhasePattern]:
        """Cluster runs by phase pattern and compute aggregate stats."""
        clusters: dict[tuple[str, ...], PhasePattern] = {}

        for record in records:
            key = tuple(record.phase_names)
            if key not in clusters:
                clusters[key] = PhasePattern(
                    phase_names=key,
                    agent_roles=tuple(record.agent_roles),
                    synthesis_modes=tuple(record.synthesis_modes),
                )
            pattern = clusters[key]
            pattern.occurrences += 1
            if record.outcome == "success":
                pattern.successes += 1
            pattern.total_duration_ms += record.duration_ms
            pattern.total_tokens += record.tokens_used
            pattern.source_run_ids.append(record.run_id)

        return list(clusters.values())

    def filter_patterns(self, patterns: list[PhasePattern]) -> list[PhasePattern]:
        """Filter patterns that meet frequency and success thresholds."""
        eligible = []
        for pattern in patterns:
            if pattern.occurrences < self.min_occurrences:
                continue
            if pattern.success_rate < self.min_success_rate:
                continue
            eligible.append(pattern)

        eligible.sort(key=lambda p: (p.success_rate, p.occurrences), reverse=True)
        return eligible

    def generate_template_yaml(self, pattern: PhasePattern) -> dict[str, Any]:
        """Generate a topology template dict from a phase pattern."""
        phases = []
        for i, phase_name in enumerate(pattern.phase_names):
            role = pattern.agent_roles[i] if i < len(pattern.agent_roles) else "executor"
            synthesis = pattern.synthesis_modes[i] if i < len(pattern.synthesis_modes) else "merge"

            phase_def: dict[str, Any] = {
                "name": phase_name,
                "agent_role": role,
                "parallelism": 1,
                "synthesis": synthesis,
                "timeout_ms": 600_000,
            }

            # Wire inputs_from for sequential phases
            if i > 0:
                phase_def["inputs_from"] = [pattern.phase_names[i - 1]]

            phases.append(phase_def)

        # Build trigger based on phase pattern characteristics
        description_keywords = self._infer_keywords(pattern)

        template = {
            "name": f"auto-{pattern.pattern_hash}",
            "description": (
                f"Auto-generated topology from {pattern.occurrences} archived runs "
                f"({pattern.success_rate:.0%} success rate). "
                f"Phases: {' -> '.join(pattern.phase_names)}."
            ),
            "triggers": [
                {
                    "description_contains": description_keywords,
                    "priority": self.auto_template_priority,
                },
            ],
            "phases": phases,
            "constraints": {
                "max_parallel_agents": 4,
                "max_total_tokens": max(pattern.avg_tokens * 2, 500_000),
                "max_duration_ms": max(pattern.avg_duration_ms * 2, 600_000),
            },
            "metadata": {
                "generated": True,
                "generated_at": datetime.now(UTC).isoformat(),
                "generated_from": pattern.source_run_ids[:10],
                "success_rate": round(pattern.success_rate, 3),
                "sample_count": pattern.occurrences,
                "avg_duration_ms": pattern.avg_duration_ms,
                "avg_tokens": pattern.avg_tokens,
            },
        }

        return template

    def _infer_keywords(self, pattern: PhasePattern) -> list[str]:
        """Infer trigger keywords from phase names."""
        keywords: list[str] = []
        name_set = set(pattern.phase_names)

        if "research" in name_set or "investigate" in name_set:
            keywords.extend(["research", "investigate"])
        if "diagnose" in name_set or "fix" in name_set:
            keywords.extend(["fix", "bug", "error"])
        if "implement" in name_set or "implementation" in name_set:
            keywords.extend(["implement", "build"])
        if "review" in name_set or "verify" in name_set:
            keywords.extend(["review", "verify"])
        if "refactor" in name_set or "restructure" in name_set:
            keywords.extend(["refactor", "restructure"])
        if "test" in name_set:
            keywords.append("test")

        if not keywords:
            # Use phase names as keywords
            keywords = [n for n in pattern.phase_names if len(n) > 2]

        return keywords

    def write_template(self, template_dict: dict[str, Any]) -> Path | None:
        """Write a template YAML file, skipping if it already exists."""
        name = template_dict["name"]
        output_path = self.topologies_dir / f"{name}.yaml"

        if output_path.exists():
            logger.debug("Template already exists, skipping: %s", output_path)
            return None

        self.topologies_dir.mkdir(parents=True, exist_ok=True)

        header = (
            f"# {name}.yaml\n"
            f"# Auto-generated topology template from archived runs.\n"
            f"# Priority is lower than manually-created templates.\n"
            f"# Delete this file to prevent it from being used.\n\n"
        )

        with open(output_path, "w") as f:
            f.write(header)
            yaml.dump(template_dict, f, default_flow_style=False, sort_keys=False)

        logger.info("Generated topology template: %s", output_path)
        return output_path

    def generate(self) -> list[Path]:
        """
        Run the full generation pipeline.

        Returns list of newly created template file paths.
        """
        records = self.scan_runs()
        if not records:
            logger.info("No completed runs found, skipping template generation")
            return []

        patterns = self.cluster_patterns(records)
        eligible = self.filter_patterns(patterns)

        if not eligible:
            logger.info(
                "No patterns meet thresholds (min_occurrences=%d, min_success_rate=%.0f%%)",
                self.min_occurrences,
                self.min_success_rate * 100,
            )
            return []

        created: list[Path] = []
        for pattern in eligible:
            template_dict = self.generate_template_yaml(pattern)
            path = self.write_template(template_dict)
            if path is not None:
                created.append(path)

        logger.info(
            "Template generation complete: %d patterns found, %d templates created",
            len(eligible),
            len(created),
        )
        return created
