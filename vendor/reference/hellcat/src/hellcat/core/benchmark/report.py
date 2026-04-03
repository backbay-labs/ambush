"""
BenchmarkReporter - Generates markdown benchmark reports.

Produces summary tables, per-challenge details, category breakdowns,
and ASCII trend visualization.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import structlog

from hellcat.core.benchmark.scorer import BenchmarkResult

logger = structlog.get_logger()


class BenchmarkReporter:
    """Generates human-readable benchmark reports."""

    def generate(
        self,
        result: BenchmarkResult,
        output_dir: Path | None = None,
    ) -> str:
        """Generate a markdown benchmark report.

        Args:
            result: Scored benchmark results.
            output_dir: If provided, write report to this directory.

        Returns:
            Rendered markdown string.
        """
        sections: list[str] = []

        sections.append(self._header(result))
        sections.append(self._summary_table(result))
        sections.append(self._category_breakdown(result))
        sections.append(self._challenge_details(result))

        if result.proof_level_distribution:
            sections.append(self._proof_distribution(result))

        if result.regressions or result.improvements:
            sections.append(self._changes(result))

        report = "\n".join(sections)

        if output_dir:
            self._write(report, result, output_dir)

        return report

    def _header(self, result: BenchmarkResult) -> str:
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
        grade = self._grade(result.solve_rate)

        return (
            f"# Benchmark Report: {result.suite_name} v{result.suite_version}\n\n"
            f"**Date:** {timestamp}  \n"
            f"**Grade:** {grade}  \n"
            f"**Solve Rate:** {result.solve_rate:.1%} "
            f"({result.total_solved}/{result.total_challenges})  \n"
            f"**Points:** {result.total_points_earned}/{result.total_points_possible}  \n"
            f"**Total Cost:** ${result.total_cost_usd:.4f}  \n"
        )

    def _summary_table(self, result: BenchmarkResult) -> str:
        lines = [
            "## Summary\n",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Challenges | {result.total_challenges} |",
            f"| Solved | {result.total_solved} |",
            f"| Solve Rate | {result.solve_rate:.1%} |",
            f"| Avg Time/Challenge | {result.avg_time_per_challenge:.1f}s |",
            f"| Avg Cost/Challenge | ${result.avg_cost_per_challenge:.4f} |",
            f"| Total Cost | ${result.total_cost_usd:.4f} |",
            "",
        ]
        return "\n".join(lines)

    def _category_breakdown(self, result: BenchmarkResult) -> str:
        if not result.category_breakdown:
            return ""

        lines = [
            "## Category Breakdown\n",
            "| Category | Solved | Rate | Avg Time | Avg Cost | Points |",
            "|----------|--------|------|----------|----------|--------|",
        ]
        for cat in result.category_breakdown:
            lines.append(
                f"| {cat.category.upper()} | {cat.solved}/{cat.total} "
                f"| {cat.solve_rate:.0%} | {cat.avg_time_seconds:.1f}s "
                f"| ${cat.avg_cost_usd:.4f} "
                f"| {cat.points_earned}/{cat.points_possible} |"
            )
        lines.append("")

        # ASCII bar chart
        lines.append("```")
        max_label = max(len(cat.category) for cat in result.category_breakdown)
        for cat in result.category_breakdown:
            bar_len = int(cat.solve_rate * 20)
            bar = "#" * bar_len + "." * (20 - bar_len)
            lines.append(
                f"{cat.category.upper():<{max_label}} [{bar}] {cat.solve_rate:.0%}"
            )
        lines.append("```\n")

        return "\n".join(lines)

    def _challenge_details(self, result: BenchmarkResult) -> str:
        lines = [
            "## Challenge Details\n",
            "| # | ID | Name | Category | Difficulty | Solved | Proof | Time | Cost |",
            "|---|-----|------|----------|------------|--------|-------|------|------|",
        ]
        for i, cr in enumerate(result.challenge_results, 1):
            status = "PASS" if cr.solved else "FAIL"
            lines.append(
                f"| {i} | {cr.challenge_id} | {cr.challenge_name[:30]} "
                f"| {cr.category} | {cr.difficulty} | {status} "
                f"| {cr.proof_level or 'N/A'} "
                f"| {cr.time_seconds:.1f}s | ${cr.cost_usd:.4f} |"
            )
        lines.append("")
        return "\n".join(lines)

    def _proof_distribution(self, result: BenchmarkResult) -> str:
        lines = [
            "## Proof Level Distribution\n",
            "| Level | Count |",
            "|-------|-------|",
        ]
        for level in sorted(result.proof_level_distribution):
            count = result.proof_level_distribution[level]
            lines.append(f"| {level} | {count} |")
        lines.append("")
        return "\n".join(lines)

    def _changes(self, result: BenchmarkResult) -> str:
        lines = ["## Changes from Previous Run\n"]

        if result.regressions:
            lines.append("### Regressions\n")
            for r in result.regressions:
                lines.append(f"- {r}")
            lines.append("")

        if result.improvements:
            lines.append("### Improvements\n")
            for imp in result.improvements:
                lines.append(f"- {imp}")
            lines.append("")

        return "\n".join(lines)

    def _grade(self, solve_rate: float) -> str:
        """Convert solve rate to a letter grade."""
        if solve_rate >= 0.95:
            return "A+"
        if solve_rate >= 0.90:
            return "A"
        if solve_rate >= 0.85:
            return "A-"
        if solve_rate >= 0.80:
            return "B+"
        if solve_rate >= 0.75:
            return "B"
        if solve_rate >= 0.70:
            return "B-"
        if solve_rate >= 0.65:
            return "C+"
        if solve_rate >= 0.60:
            return "C"
        if solve_rate >= 0.55:
            return "C-"
        if solve_rate >= 0.50:
            return "D"
        return "F"

    def _write(
        self,
        report: str,
        result: BenchmarkResult,
        output_dir: Path,
    ) -> None:
        """Write the report to disk."""
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        filename = f"{result.suite_name}-{timestamp}.md"
        path = output_dir / filename
        path.write_text(report, encoding="utf-8")

        logger.info(
            "benchmark.report_written",
            path=str(path),
            suite=result.suite_name,
            solve_rate=f"{result.solve_rate:.1%}",
        )
