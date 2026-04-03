"""
BenchmarkScorer - Scores benchmark results against success criteria.

Produces solve rates, cost metrics, category breakdowns, and
regression detection against previous runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from hellcat.core.benchmark.challenge import ChallengeSuite

logger = structlog.get_logger()


@dataclass
class ChallengeResult:
    """Result of running a single challenge."""

    challenge_id: str
    challenge_name: str
    category: str
    difficulty: str
    solved: bool
    proof_level: str = ""
    expected_proof_level: str = "L2"
    time_seconds: float = 0.0
    cost_usd: float = 0.0
    vulns_found: int = 0
    error: str | None = None
    points_earned: int = 0
    points_possible: int = 10


@dataclass
class CategoryBreakdown:
    """Solve rate and metrics for a single vulnerability category."""

    category: str
    total: int
    solved: int
    solve_rate: float
    avg_time_seconds: float
    avg_cost_usd: float
    points_earned: int
    points_possible: int


@dataclass
class BenchmarkResult:
    """Complete benchmark run results."""

    suite_name: str
    suite_version: str
    total_challenges: int
    total_solved: int
    solve_rate: float
    total_points_earned: int
    total_points_possible: int
    avg_time_per_challenge: float
    total_cost_usd: float
    avg_cost_per_challenge: float
    proof_level_distribution: dict[str, int]
    category_breakdown: list[CategoryBreakdown]
    challenge_results: list[ChallengeResult]
    regressions: list[str] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)


class BenchmarkScorer:
    """Scores benchmark challenge results and detects regressions."""

    def score(
        self,
        suite: ChallengeSuite,
        results: list[ChallengeResult],
    ) -> BenchmarkResult:
        """Score a set of challenge results against a suite.

        Args:
            suite: The ChallengeSuite that was run.
            results: Per-challenge results.

        Returns:
            BenchmarkResult with all metrics computed.
        """
        total = len(results)
        solved = sum(1 for r in results if r.solved)
        solve_rate = solved / total if total > 0 else 0.0

        total_time = sum(r.time_seconds for r in results)
        avg_time = total_time / total if total > 0 else 0.0

        total_cost = sum(r.cost_usd for r in results)
        avg_cost = total_cost / total if total > 0 else 0.0

        total_points_earned = sum(r.points_earned for r in results)
        total_points_possible = sum(r.points_possible for r in results)

        # Proof level distribution
        proof_dist: dict[str, int] = {}
        for r in results:
            if r.solved and r.proof_level:
                proof_dist[r.proof_level] = proof_dist.get(r.proof_level, 0) + 1

        # Category breakdown
        category_breakdown = self._compute_category_breakdown(results)

        return BenchmarkResult(
            suite_name=suite.name,
            suite_version=suite.version,
            total_challenges=total,
            total_solved=solved,
            solve_rate=solve_rate,
            total_points_earned=total_points_earned,
            total_points_possible=total_points_possible,
            avg_time_per_challenge=avg_time,
            total_cost_usd=total_cost,
            avg_cost_per_challenge=avg_cost,
            proof_level_distribution=proof_dist,
            category_breakdown=category_breakdown,
            challenge_results=results,
        )

    def compare_with_previous(
        self,
        current: BenchmarkResult,
        previous: BenchmarkResult,
    ) -> BenchmarkResult:
        """Compare current results with a previous run and detect regressions.

        Updates current.regressions and current.improvements in place.

        Args:
            current: The current run's results.
            previous: The previous run's results.

        Returns:
            The current result with regressions/improvements populated.
        """
        prev_by_id = {r.challenge_id: r for r in previous.challenge_results}

        regressions: list[str] = []
        improvements: list[str] = []

        for result in current.challenge_results:
            prev = prev_by_id.get(result.challenge_id)
            if prev is None:
                continue
            if prev.solved and not result.solved:
                regressions.append(
                    f"{result.challenge_id} ({result.challenge_name}): "
                    f"was solved, now failed"
                )
            elif not prev.solved and result.solved:
                improvements.append(
                    f"{result.challenge_id} ({result.challenge_name}): "
                    f"was failed, now solved"
                )

        current.regressions = regressions
        current.improvements = improvements

        logger.info(
            "benchmark.comparison",
            regressions=len(regressions),
            improvements=len(improvements),
        )

        return current

    def _compute_category_breakdown(
        self,
        results: list[ChallengeResult],
    ) -> list[CategoryBreakdown]:
        """Group results by category and compute per-category metrics."""
        by_category: dict[str, list[ChallengeResult]] = {}
        for r in results:
            by_category.setdefault(r.category, []).append(r)

        breakdowns = []
        for category in sorted(by_category):
            cat_results = by_category[category]
            total = len(cat_results)
            solved = sum(1 for r in cat_results if r.solved)
            solve_rate = solved / total if total > 0 else 0.0
            avg_time = sum(r.time_seconds for r in cat_results) / total if total > 0 else 0.0
            avg_cost = sum(r.cost_usd for r in cat_results) / total if total > 0 else 0.0
            points_earned = sum(r.points_earned for r in cat_results)
            points_possible = sum(r.points_possible for r in cat_results)

            breakdowns.append(CategoryBreakdown(
                category=category,
                total=total,
                solved=solved,
                solve_rate=solve_rate,
                avg_time_seconds=avg_time,
                avg_cost_usd=avg_cost,
                points_earned=points_earned,
                points_possible=points_possible,
            ))

        return breakdowns
