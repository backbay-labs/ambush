"""
BenchmarkHarness - Manages benchmark runs.

Loads a challenge suite, runs engagements per challenge, collects
results, and scores them through the BenchmarkScorer.
"""

from __future__ import annotations

import time
from pathlib import Path

import structlog

from hellcat.core.benchmark.challenge import Challenge, ChallengeSuite
from hellcat.core.benchmark.report import BenchmarkReporter
from hellcat.core.benchmark.scorer import BenchmarkResult, BenchmarkScorer, ChallengeResult
from hellcat.core.config.engagement import EngagementConfig
from hellcat.core.runner.engagement import EXIT_VULNS_FOUND, EngagementRunner

logger = structlog.get_logger()


class BenchmarkHarness:
    """Manages benchmark suite execution.

    Loads a challenge suite, runs an engagement per challenge, and
    produces scored results.

    Usage::

        harness = BenchmarkHarness(
            suite_path="benchmarks/suites/juice-shop.yaml",
            target_base_url="http://localhost:3000",
        )
        result = harness.run_suite()
    """

    def __init__(
        self,
        suite_path: str | Path,
        target_base_url: str,
        output_dir: str | Path = "./benchmarks/results",
        timeout_per_challenge: int = 600,
        total_timeout: int = 7200,
        dry_run: bool = False,
    ) -> None:
        self.suite = ChallengeSuite.from_yaml(suite_path)
        self.target_base_url = target_base_url.rstrip("/")
        self.output_dir = Path(output_dir)
        self.timeout_per_challenge = timeout_per_challenge
        self.total_timeout = total_timeout
        self.dry_run = dry_run
        self._scorer = BenchmarkScorer()
        self._reporter = BenchmarkReporter()

    def run_suite(self) -> BenchmarkResult:
        """Run all challenges in the suite and return scored results.

        Returns:
            BenchmarkResult with all metrics.
        """
        logger.info(
            "benchmark.suite_start",
            suite=self.suite.name,
            challenges=len(self.suite.challenges),
            target=self.target_base_url,
            dry_run=self.dry_run,
        )

        suite_start = time.monotonic()
        results: list[ChallengeResult] = []

        for i, challenge in enumerate(self.suite.challenges, 1):
            elapsed = time.monotonic() - suite_start
            if elapsed > self.total_timeout:
                logger.warning(
                    "benchmark.suite_timeout",
                    completed=len(results),
                    total=len(self.suite.challenges),
                )
                # Mark remaining as timed out
                for remaining in self.suite.challenges[i - 1:]:
                    results.append(ChallengeResult(
                        challenge_id=remaining.id,
                        challenge_name=remaining.name,
                        category=remaining.category,
                        difficulty=remaining.difficulty,
                        solved=False,
                        error="Suite timeout exceeded",
                        points_possible=remaining.points,
                    ))
                break

            logger.info(
                "benchmark.challenge_start",
                index=f"{i}/{len(self.suite.challenges)}",
                challenge=challenge.name,
                category=challenge.category,
            )

            result = self.run_challenge(challenge)
            results.append(result)

            logger.info(
                "benchmark.challenge_end",
                challenge=challenge.name,
                solved=result.solved,
                time=f"{result.time_seconds:.1f}s",
                cost=f"${result.cost_usd:.4f}",
            )

        scored = self._scorer.score(self.suite, results)

        # Write report
        self._reporter.generate(scored, output_dir=self.output_dir)

        logger.info(
            "benchmark.suite_complete",
            suite=self.suite.name,
            solve_rate=f"{scored.solve_rate:.1%}",
            total_cost=f"${scored.total_cost_usd:.4f}",
        )

        return scored

    def run_challenge(self, challenge: Challenge) -> ChallengeResult:
        """Run a single benchmark challenge.

        Args:
            challenge: The challenge to run.

        Returns:
            ChallengeResult with solve status and metrics.
        """
        target_url = f"{self.target_base_url}{challenge.target_path}"
        challenge_output = self.output_dir / "challenges" / challenge.id

        start = time.monotonic()
        try:
            config = EngagementConfig(
                target_url=target_url,
                output_dir=str(challenge_output),
                timeout_seconds=self.timeout_per_challenge,
                max_concurrency=1,
            )

            runner = EngagementRunner(config)

            eng_result = runner.run_dry() if self.dry_run else runner.run()

            elapsed = time.monotonic() - start

            # Determine if the challenge was solved
            solved = eng_result.exit_code == EXIT_VULNS_FOUND and eng_result.vulns_found > 0

            # Extract cost from summary
            cost = 0.0
            if eng_result.summary:
                cost = eng_result.summary.total_cost_usd

            # Extract proof level from findings
            proof_level = ""
            if eng_result.dispatch_result and eng_result.dispatch_result.collected_findings:
                for finding in eng_result.dispatch_result.collected_findings:
                    level = finding.get("proof_level", "")
                    if level:
                        proof_level = level
                        break

            return ChallengeResult(
                challenge_id=challenge.id,
                challenge_name=challenge.name,
                category=challenge.category,
                difficulty=challenge.difficulty,
                solved=solved,
                proof_level=proof_level,
                expected_proof_level=challenge.expected_proof_level,
                time_seconds=elapsed,
                cost_usd=cost,
                vulns_found=eng_result.vulns_found,
                points_earned=challenge.points if solved else 0,
                points_possible=challenge.points,
            )

        except Exception as exc:
            elapsed = time.monotonic() - start
            logger.error(
                "benchmark.challenge_error",
                challenge=challenge.id,
                error=str(exc),
            )
            return ChallengeResult(
                challenge_id=challenge.id,
                challenge_name=challenge.name,
                category=challenge.category,
                difficulty=challenge.difficulty,
                solved=False,
                time_seconds=elapsed,
                error=str(exc),
                points_possible=challenge.points,
            )
