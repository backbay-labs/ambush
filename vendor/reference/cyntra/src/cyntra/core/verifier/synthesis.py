"""
Speculation Synthesizer - Extract knowledge from all speculation candidates.

Transforms speculate+vote from "pick best, discard rest" to
"pick best AND extract knowledge from all candidates."

Compares tool-call sequences, identifies complementary failures,
novel approaches, and alternative solutions across candidates.
Produces attributed observations for the causal attribution pipeline.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CandidateProfile:
    """Extracted profile of a single speculation candidate."""

    candidate_index: int
    success: bool
    gate_pass_rate: float
    tool_sequence: list[str]
    files_modified: list[str]
    gates_passed: list[str]
    gates_failed: list[str]
    token_usage: int
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SynthesisObservation:
    """A single observation extracted from cross-candidate comparison."""

    observation_type: str  # complementary_failure, novel_approach, alternative_solution, convergent_approach
    description: str
    mechanism_tags: list[str]
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)
    candidate_indices: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SynthesisResult:
    """Result of synthesizing knowledge from speculation candidates."""

    winner_index: int | None
    candidates_count: int
    observations: list[SynthesisObservation]
    candidate_profiles: list[CandidateProfile]
    persisted_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "winner_index": self.winner_index,
            "candidates_count": self.candidates_count,
            "observations": [o.to_dict() for o in self.observations],
            "candidate_profiles": [p.to_dict() for p in self.candidate_profiles],
            "persisted_count": self.persisted_count,
        }


class SpeculationSynthesizer:
    """
    Extract knowledge from all speculation candidates.

    Runs cross-candidate comparison to find:
    - Complementary failures: candidate A failed gate X, B failed gate Y
    - Novel approaches: unique tool sequences not shared by others
    - Alternative solutions: different files modified for same outcome
    - Convergent approaches: multiple candidates used the same strategy
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path

    def synthesize(
        self,
        candidates: list[dict[str, Any]],
        winner_index: int | None = None,
        issue_id: str | None = None,
        run_id: str | None = None,
    ) -> SynthesisResult:
        """
        Analyze all speculation candidates and extract cross-candidate knowledge.

        Args:
            candidates: List of candidate dicts with keys:
                - success (bool), gate_pass_rate (float), tool_sequence (list),
                - files_modified (list), gates_passed (list), gates_failed (list),
                - token_usage (int), duration_ms (int)
            winner_index: Index of the winning candidate (if any)
            issue_id: Issue ID for attribution storage
            run_id: Run ID for attribution storage
        """
        if len(candidates) < 2:
            return SynthesisResult(
                winner_index=winner_index,
                candidates_count=len(candidates),
                observations=[],
                candidate_profiles=[],
            )

        # Build profiles
        profiles = self._build_profiles(candidates)

        # Extract observations
        observations: list[SynthesisObservation] = []
        observations.extend(self._find_complementary_failures(profiles))
        observations.extend(self._find_novel_approaches(profiles))
        observations.extend(self._find_alternative_solutions(profiles))
        observations.extend(self._find_convergent_approaches(profiles))

        result = SynthesisResult(
            winner_index=winner_index,
            candidates_count=len(candidates),
            observations=observations,
            candidate_profiles=profiles,
        )

        # Persist to attributed_observations if DB available
        if self.db_path and observations:
            result.persisted_count = self._persist_observations(
                observations, issue_id=issue_id, run_id=run_id
            )

        logger.info(
            "Speculation synthesis: %d candidates, %d observations, %d persisted",
            len(candidates),
            len(observations),
            result.persisted_count,
        )

        return result

    def _build_profiles(self, candidates: list[dict[str, Any]]) -> list[CandidateProfile]:
        """Build structured profiles from raw candidate dicts."""
        profiles = []
        for i, c in enumerate(candidates):
            profiles.append(
                CandidateProfile(
                    candidate_index=i,
                    success=bool(c.get("success", False)),
                    gate_pass_rate=float(c.get("gate_pass_rate", 0.0)),
                    tool_sequence=list(c.get("tool_sequence", [])),
                    files_modified=list(c.get("files_modified", [])),
                    gates_passed=list(c.get("gates_passed", [])),
                    gates_failed=list(c.get("gates_failed", [])),
                    token_usage=int(c.get("token_usage", 0)),
                    duration_ms=int(c.get("duration_ms", 0)),
                )
            )
        return profiles

    def _find_complementary_failures(
        self, profiles: list[CandidateProfile]
    ) -> list[SynthesisObservation]:
        """Find cases where different candidates failed different gates.

        If candidate A passed gate X but failed gate Y, and candidate B passed
        gate Y but failed gate X, a composite solution might pass both.
        """
        observations = []
        for i, a in enumerate(profiles):
            for j, b in enumerate(profiles):
                if j <= i:
                    continue
                # Gates A passed but B failed
                a_unique_pass = set(a.gates_passed) - set(b.gates_passed)
                b_unique_pass = set(b.gates_passed) - set(a.gates_passed)

                a_unique_fail = set(a.gates_failed) - set(b.gates_failed)
                b_unique_fail = set(b.gates_failed) - set(a.gates_failed)

                # Complementary: A fails what B passes, and B fails what A passes
                complementary_a = a_unique_fail & b_unique_pass
                complementary_b = b_unique_fail & a_unique_pass

                if complementary_a or complementary_b:
                    all_complementary = complementary_a | complementary_b
                    observations.append(
                        SynthesisObservation(
                            observation_type="complementary_failure",
                            description=(
                                f"Candidates {i} and {j} have complementary gate coverage: "
                                f"a composite might pass {', '.join(sorted(all_complementary))}"
                            ),
                            mechanism_tags=["PLANNING/DEPENDENCY_ORDERING"],
                            confidence=0.7,
                            evidence={
                                "candidate_a_unique_passes": sorted(a_unique_pass),
                                "candidate_b_unique_passes": sorted(b_unique_pass),
                                "complementary_gates": sorted(all_complementary),
                            },
                            candidate_indices=[i, j],
                        )
                    )
        return observations

    def _find_novel_approaches(
        self, profiles: list[CandidateProfile]
    ) -> list[SynthesisObservation]:
        """Find candidates that used tool sequences no other candidate used."""
        observations = []

        # Build 3-gram sets for each candidate
        ngram_sets: list[set[tuple[str, ...]]] = []
        for p in profiles:
            ngrams: set[tuple[str, ...]] = set()
            seq = p.tool_sequence
            for n in range(3, min(6, len(seq) + 1)):
                for start in range(len(seq) - n + 1):
                    ngrams.add(tuple(seq[start : start + n]))
            ngram_sets.append(ngrams)

        # Find ngrams unique to each candidate
        for i, my_ngrams in enumerate(ngram_sets):
            others = set()
            for j, other_ngrams in enumerate(ngram_sets):
                if j != i:
                    others |= other_ngrams

            unique = my_ngrams - others
            if unique and profiles[i].success:
                # Novel and successful -- worth learning from
                sample = sorted(unique, key=len)[:3]
                observations.append(
                    SynthesisObservation(
                        observation_type="novel_approach",
                        description=(
                            f"Candidate {i} used unique tool sequences not found in other candidates"
                        ),
                        mechanism_tags=["TOOL_STRATEGY/BATCH_OPERATIONS"],
                        confidence=0.6,
                        evidence={
                            "unique_ngram_count": len(unique),
                            "sample_ngrams": [" -> ".join(ng) for ng in sample],
                            "candidate_success": profiles[i].success,
                        },
                        candidate_indices=[i],
                    )
                )
        return observations

    def _find_alternative_solutions(
        self, profiles: list[CandidateProfile]
    ) -> list[SynthesisObservation]:
        """Find successful candidates that modified different files."""
        observations = []
        successful = [(i, p) for i, p in enumerate(profiles) if p.success]

        if len(successful) < 2:
            return observations

        for idx_a in range(len(successful)):
            for idx_b in range(idx_a + 1, len(successful)):
                i, a = successful[idx_a]
                j, b = successful[idx_b]

                a_files = set(a.files_modified)
                b_files = set(b.files_modified)
                overlap = a_files & b_files
                a_only = a_files - b_files
                b_only = b_files - a_files

                # If they share less than half their files, they took different paths
                total = len(a_files | b_files)
                if total > 0 and len(overlap) / total < 0.5:
                    observations.append(
                        SynthesisObservation(
                            observation_type="alternative_solution",
                            description=(
                                f"Candidates {i} and {j} both succeeded but modified "
                                f"mostly different files ({len(overlap)}/{total} overlap)"
                            ),
                            mechanism_tags=["SCOPE_CONTROL/MINIMAL_DIFF"],
                            confidence=0.65,
                            evidence={
                                "shared_files": sorted(overlap),
                                "a_only_files": sorted(a_only),
                                "b_only_files": sorted(b_only),
                                "overlap_ratio": round(len(overlap) / total, 2) if total else 0,
                            },
                            candidate_indices=[i, j],
                        )
                    )
        return observations

    def _find_convergent_approaches(
        self, profiles: list[CandidateProfile]
    ) -> list[SynthesisObservation]:
        """Find when multiple candidates converged on the same strategy."""
        observations = []
        successful = [(i, p) for i, p in enumerate(profiles) if p.success]

        if len(successful) < 2:
            return observations

        for idx_a in range(len(successful)):
            for idx_b in range(idx_a + 1, len(successful)):
                i, a = successful[idx_a]
                j, b = successful[idx_b]

                a_files = set(a.files_modified)
                b_files = set(b.files_modified)
                total = len(a_files | b_files)

                if total > 0 and len(a_files & b_files) / total >= 0.8:
                    observations.append(
                        SynthesisObservation(
                            observation_type="convergent_approach",
                            description=(
                                f"Candidates {i} and {j} independently converged on "
                                f"modifying the same files ({len(a_files & b_files)}/{total})"
                            ),
                            mechanism_tags=["VERIFICATION/INCREMENTAL_VERIFY"],
                            confidence=0.8,
                            evidence={
                                "shared_files": sorted(a_files & b_files),
                                "overlap_ratio": round(len(a_files & b_files) / total, 2),
                            },
                            candidate_indices=[i, j],
                        )
                    )
        return observations

    def _persist_observations(
        self,
        observations: list[SynthesisObservation],
        issue_id: str | None = None,
        run_id: str | None = None,
    ) -> int:
        """Store synthesis observations to attributed_observations table."""
        if not self.db_path:
            return 0

        try:
            from cyntra.cognition.dynamics.transition_db import TransitionDB

            db = TransitionDB(self.db_path)
        except Exception:
            logger.warning("Could not open TransitionDB for synthesis", exc_info=True)
            return 0

        now = datetime.now(UTC).isoformat()
        count = 0

        try:
            with db.conn:
                for obs in observations:
                    db.conn.execute(
                        """
                        INSERT INTO attributed_observations (
                            run_id, issue_id, outcome,
                            proximal_cause, structural_cause,
                            mechanism_tags, confidence, evidence,
                            created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id or "",
                            issue_id,
                            f"synthesis:{obs.observation_type}",
                            obs.description,
                            f"speculation_synthesis:{obs.observation_type}",
                            json.dumps(obs.mechanism_tags, separators=(",", ":")),
                            obs.confidence,
                            json.dumps(obs.evidence, sort_keys=True, separators=(",", ":")),
                            now,
                        ),
                    )
                    count += 1
        except Exception:
            logger.warning("Failed to persist synthesis observations", exc_info=True)

        return count
