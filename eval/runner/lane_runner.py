"""Lane runner: spawn ONE agent lane on ONE task and collect its structured findings.

STATUS: interface + a deterministic FakeLaneRunner for testing the pipeline end-to-end
without API keys. The live runner (LiveLaneRunner) is intentionally a stub: wiring it
requires either (a) calling each model provider's API directly with the frozen mission
prompt, or (b) driving the Ambush orchestrator's lane mechanism. Either way it must make
each lane additionally emit `findings/<id>.jsonl` in the schema (extend
src/main/swarm/mission.ts reporting protocol). Keep the mission prompt IDENTICAL across
families (only persona varies within HOMO) so the prompt is not a confound.
"""

from __future__ import annotations

import abc
import copy
from dataclasses import dataclass

from schema import Finding


@dataclass
class Task:
    task_id: str
    repo_path: str
    diff_path: str | None = None      # for the diff-review framing (vulnerable commit)
    language: str = ""


class LaneRunner(abc.ABC):
    @abc.abstractmethod
    def run_lane(self, task: Task, lane_spec: dict) -> list[Finding]:
        """lane_spec = {'model':..., 'persona':..., 'seed':...} -> structured findings."""
        raise NotImplementedError


class LiveLaneRunner(LaneRunner):
    """TODO(eval): call the model provider with the frozen mission prompt and parse the
    emitted findings/<id>.jsonl. Cache by (task_id, model, persona, seed) so arms A2-A6
    are pure post-processing and never re-query a model (design Section 9)."""

    def __init__(self, cache_dir: str = "results/lane_cache"):
        self.cache_dir = cache_dir

    def run_lane(self, task: Task, lane_spec: dict) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError(
            "LiveLaneRunner is a stub. Implement provider calls + JSONL parsing, or "
            "drive the Ambush orchestrator. See lane_runner.py docstring."
        )


class FakeLaneRunner(LaneRunner):
    """Deterministic runner driven by a scripted finding table, for tests and for
    exercising the scoring pipeline before any model access. The script maps
    (task_id, model, persona) -> list[Finding]."""

    def __init__(self, script: dict[tuple[str, str, str], list[Finding]]):
        self.script = script

    def run_lane(self, task: Task, lane_spec: dict) -> list[Finding]:
        key = (task.task_id, lane_spec.get("model", ""), lane_spec.get("persona", ""))
        # Deep-copy so each lane gets its own Finding instances -- the caller stamps a
        # per-lane lane_id, and sharing instances would collapse distinct-lane support.
        return [copy.deepcopy(f) for f in self.script.get(key, [])]
