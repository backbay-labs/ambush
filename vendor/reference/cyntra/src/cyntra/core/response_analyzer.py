"""
Ralph-style Response Analyzer for Cyntra Kernel.

Implements intelligent completion detection and semantic analysis:
- Detects "done" signals in agent responses
- Identifies stuck loops (test-only, repeated patterns)
- Extracts progress indicators
- Recognizes completion confidence levels
- Loads learned anti-patterns to reduce false positives
- Semantic completion matching against issue title

Inspired by: https://github.com/frankbria/ralph-claude-code
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from cyntra.core.memory_integration import KernelMemoryBridge
    from cyntra.core.state.models import Issue

logger = structlog.get_logger()


class CompletionSignal(Enum):
    """Types of completion signals detected."""

    NONE = "none"
    WEAK = "weak"  # Hints at completion
    MODERATE = "moderate"  # Likely done
    STRONG = "strong"  # Explicitly done


class StuckLoopType(Enum):
    """Types of stuck loop patterns."""

    NONE = "none"
    TEST_ONLY = "test_only"  # Only running tests, no implementation
    REPEATED_ERROR = "repeated_error"  # Same error over and over
    NO_PROGRESS = "no_progress"  # Output but no actual changes
    CIRCULAR = "circular"  # Undoing/redoing same changes


@dataclass
class AnalysisResult:
    """Result of analyzing an agent response."""

    completion_signal: CompletionSignal = CompletionSignal.NONE
    completion_confidence: float = 0.0
    stuck_loop: StuckLoopType = StuckLoopType.NONE
    stuck_confidence: float = 0.0

    # Extracted indicators
    tasks_completed: int = 0
    tasks_remaining: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    files_modified: list[str] = field(default_factory=list)
    errors_found: list[str] = field(default_factory=list)

    # Raw signals detected
    done_phrases: list[str] = field(default_factory=list)
    blocking_phrases: list[str] = field(default_factory=list)

    # Enhanced analysis (Full-Scale Ralph)
    anti_pattern_warnings: list[str] = field(default_factory=list)
    pattern_confirmations: list[str] = field(default_factory=list)
    semantic_overlap_score: float = 0.0  # Match with issue title

    def is_done(self, threshold: float = 0.7) -> bool:
        """Check if analysis indicates completion above threshold."""
        return (
            self.completion_signal in (CompletionSignal.STRONG, CompletionSignal.MODERATE)
            and self.completion_confidence >= threshold
            and self.stuck_loop == StuckLoopType.NONE
        )

    def should_continue(self) -> bool:
        """Check if analysis indicates work should continue."""
        return (
            self.completion_signal in (CompletionSignal.NONE, CompletionSignal.WEAK)
            and self.stuck_loop == StuckLoopType.NONE
        )

    def has_learned_warnings(self) -> bool:
        """Check if learned anti-patterns were detected."""
        return len(self.anti_pattern_warnings) > 0


class ResponseAnalyzer:
    """
    Analyzes agent responses for completion signals and stuck loops.

    Uses semantic pattern matching to detect:
    - Explicit completion statements ("All tasks complete", "Done")
    - Implicit completion (all tests passing, no remaining work)
    - Stuck patterns (test-only loops, repeated errors)
    - Progress indicators (files changed, tasks done)

    Enhanced with (Full-Scale Ralph):
    - Learned anti-patterns from sleeptime consolidation
    - Learned false-positive patterns that look like completion
    - Semantic overlap scoring with issue title
    """

    # Phrases indicating strong completion
    STRONG_DONE_PHRASES = [
        r"all\s+tasks?\s+(are\s+)?complete",
        r"implementation\s+is\s+complete",
        r"project\s+(is\s+)?(now\s+)?complete",
        r"all\s+requirements?\s+(have\s+been\s+)?met",
        r"nothing\s+left\s+to\s+do",
        r"all\s+items?\s+done",
        r"successfully\s+completed?\s+all",
        r"finished\s+implementing",
    ]

    # Phrases indicating moderate completion
    MODERATE_DONE_PHRASES = [
        r"task\s+complete",
        r"done\s+with\s+(this|the)",
        r"implementation\s+done",
        r"feature\s+complete",
        r"finished\s+the\s+task",
        r"completed?\s+successfully",
        r"all\s+tests?\s+pass(ing)?",
    ]

    # Phrases indicating weak completion hints
    WEAK_DONE_PHRASES = [
        r"looks\s+good",
        r"should\s+be\s+working",
        r"ready\s+for\s+review",
        r"let\s+me\s+know\s+if",
        r"anything\s+else",
    ]

    # Phrases that block completion (indicates more work needed)
    BLOCKING_PHRASES = [
        r"error",
        r"failed",
        r"fix(ing)?",
        r"bug",
        r"issue",
        r"problem",
        r"need(s)?\s+to",
        r"should\s+add",
        r"todo",
        r"remaining",
        r"next\s+step",
        r"still\s+need",
        r"work\s+in\s+progress",
        r"wip",
        r"not\s+yet",
        r"incomplete",
    ]

    # Test-only loop indicators
    TEST_LOOP_PHRASES = [
        r"running\s+tests?",
        r"pytest",
        r"test\s+(passed|failed)",
        r"assertion",
        r"expect(ed)?",
    ]

    def __init__(
        self,
        learned_context_dir: Path | str | None = None,
        memory_bridge: KernelMemoryBridge | None = None,
    ) -> None:
        """
        Initialize the response analyzer.

        Args:
            learned_context_dir: Path to .cyntra/learned_context/ for loading anti-patterns
            memory_bridge: Optional memory bridge for session-aware analysis
        """
        # Compile regex patterns for performance
        self._strong_done_re = [re.compile(p, re.IGNORECASE) for p in self.STRONG_DONE_PHRASES]
        self._moderate_done_re = [re.compile(p, re.IGNORECASE) for p in self.MODERATE_DONE_PHRASES]
        self._weak_done_re = [re.compile(p, re.IGNORECASE) for p in self.WEAK_DONE_PHRASES]
        self._blocking_re = [re.compile(p, re.IGNORECASE) for p in self.BLOCKING_PHRASES]
        self._test_loop_re = [re.compile(p, re.IGNORECASE) for p in self.TEST_LOOP_PHRASES]

        # Track response history for pattern detection
        self._response_history: list[str] = []
        self._max_history = 10

        # External integrations (Full-Scale Ralph)
        self.learned_context_dir = Path(learned_context_dir) if learned_context_dir else None
        self.memory_bridge = memory_bridge

        # Learned patterns (loaded from sleeptime consolidation)
        self._learned_anti_patterns: list[str] = []
        self._learned_false_positives: list[str] = []
        self._learned_success_patterns: list[str] = []
        self._patterns_loaded_at: float = 0.0

        # Load initial patterns
        self._refresh_learned_patterns()

    def analyze(
        self,
        response: str,
        issue: Issue | None = None,
        files_changed: list[str] | None = None,
    ) -> AnalysisResult:
        """
        Analyze an agent response for completion signals.

        Args:
            response: The agent's text response
            issue: Optional issue context for task-aware analysis
            files_changed: Optional list of files modified

        Returns:
            AnalysisResult with completion and stuck loop analysis
        """
        result = AnalysisResult()

        if not response:
            return result

        # Track history
        self._response_history.append(response[:1000])  # Truncate for memory
        if len(self._response_history) > self._max_history:
            self._response_history.pop(0)

        # Extract file modifications
        result.files_modified = files_changed or self._extract_file_changes(response)

        # Detect completion signals
        self._analyze_completion(response, result)

        # Detect blocking phrases (reduce confidence)
        self._analyze_blockers(response, result)

        # Detect stuck loop patterns
        self._analyze_stuck_loops(response, result)

        # Extract test results
        self._extract_test_results(response, result)

        # Adjust confidence based on context
        self._adjust_for_context(result, issue)

        # Full-Scale Ralph: Learned pattern analysis
        if self.learned_context_dir:
            self._analyze_learned_patterns(response, result)

        # Full-Scale Ralph: Semantic overlap with issue
        self._compute_semantic_overlap(response, issue, result)

        logger.debug(
            "response_analyzer.result",
            completion=result.completion_signal.value,
            completion_confidence=result.completion_confidence,
            stuck_loop=result.stuck_loop.value,
            files_modified=len(result.files_modified),
            semantic_overlap=result.semantic_overlap_score,
            anti_pattern_warnings=len(result.anti_pattern_warnings),
        )

        return result

    def _analyze_completion(self, response: str, result: AnalysisResult) -> None:
        """Detect completion signal strength."""
        # Check strong completion phrases
        strong_matches = []
        for pattern in self._strong_done_re:
            matches = pattern.findall(response)
            strong_matches.extend(matches)

        if strong_matches:
            result.completion_signal = CompletionSignal.STRONG
            result.completion_confidence = min(0.9, 0.6 + 0.1 * len(strong_matches))
            result.done_phrases.extend(strong_matches)
            return

        # Check moderate completion phrases
        moderate_matches = []
        for pattern in self._moderate_done_re:
            matches = pattern.findall(response)
            moderate_matches.extend(matches)

        if moderate_matches:
            result.completion_signal = CompletionSignal.MODERATE
            result.completion_confidence = min(0.7, 0.4 + 0.1 * len(moderate_matches))
            result.done_phrases.extend(moderate_matches)
            return

        # Check weak completion phrases
        weak_matches = []
        for pattern in self._weak_done_re:
            matches = pattern.findall(response)
            weak_matches.extend(matches)

        if weak_matches:
            result.completion_signal = CompletionSignal.WEAK
            result.completion_confidence = min(0.4, 0.2 + 0.05 * len(weak_matches))
            result.done_phrases.extend(weak_matches)

    def _analyze_blockers(self, response: str, result: AnalysisResult) -> None:
        """Detect blocking phrases that indicate more work needed."""
        blocker_matches = []
        for pattern in self._blocking_re:
            matches = pattern.findall(response)
            blocker_matches.extend(matches)

        if blocker_matches:
            result.blocking_phrases.extend(blocker_matches)
            # Reduce completion confidence based on blockers
            penalty = min(0.4, 0.1 * len(blocker_matches))
            result.completion_confidence = max(0, result.completion_confidence - penalty)

            # Downgrade signal strength if many blockers
            if len(blocker_matches) >= 3:
                if result.completion_signal == CompletionSignal.STRONG:
                    result.completion_signal = CompletionSignal.MODERATE
                elif result.completion_signal == CompletionSignal.MODERATE:
                    result.completion_signal = CompletionSignal.WEAK

    def _analyze_stuck_loops(self, response: str, result: AnalysisResult) -> None:
        """Detect stuck loop patterns."""
        # Check for test-only loop
        test_matches = sum(1 for p in self._test_loop_re if p.search(response))
        non_test_content = len(result.files_modified) - sum(
            1 for f in result.files_modified if "test" in f.lower()
        )

        if test_matches >= 3 and non_test_content == 0:
            result.stuck_loop = StuckLoopType.TEST_ONLY
            result.stuck_confidence = min(0.8, 0.3 * test_matches)
            return

        # Check for repeated content in history
        if len(self._response_history) >= 3:
            recent = self._response_history[-3:]
            similarity = self._compute_similarity(recent)
            if similarity > 0.8:
                result.stuck_loop = StuckLoopType.CIRCULAR
                result.stuck_confidence = similarity
                return

        # Check for no-progress pattern
        if len(self._response_history) >= 2 and not result.files_modified:
            # No files changed in recent responses
            result.stuck_loop = StuckLoopType.NO_PROGRESS
            result.stuck_confidence = 0.5

    def _extract_test_results(self, response: str, result: AnalysisResult) -> None:
        """Extract test pass/fail counts from response."""
        # Look for pytest-style output
        passed_match = re.search(r"(\d+)\s+passed", response, re.IGNORECASE)
        failed_match = re.search(r"(\d+)\s+failed", response, re.IGNORECASE)

        if passed_match:
            result.tests_passed = int(passed_match.group(1))
        if failed_match:
            result.tests_failed = int(failed_match.group(1))

        # Look for "all tests pass" style
        if re.search(r"all\s+\d+\s+tests?\s+pass", response, re.IGNORECASE):
            match = re.search(r"all\s+(\d+)\s+tests?", response, re.IGNORECASE)
            if match:
                result.tests_passed = int(match.group(1))

    def _extract_file_changes(self, response: str) -> list[str]:
        """Extract file paths that appear to be modified."""
        files = []

        # Common patterns for file modifications
        patterns = [
            r"(?:created?|modified?|updated?|wrote?|edited?)\s+[`'\"]?([a-zA-Z0-9_./\-]+\.[a-zA-Z0-9]+)[`'\"]?",
            r"[`'\"]([a-zA-Z0-9_./\-]+\.(py|ts|tsx|js|jsx|rs|go|yaml|json|md))[`'\"]",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    files.append(match[0])
                else:
                    files.append(match)

        return list(set(files))

    def _compute_similarity(self, responses: list[str]) -> float:
        """Compute similarity between responses (for circular detection)."""
        if len(responses) < 2:
            return 0.0

        # Simple word-based Jaccard similarity
        def get_words(text: str) -> set[str]:
            return set(re.findall(r"\w+", text.lower()))

        word_sets = [get_words(r) for r in responses]

        # Compare consecutive pairs
        similarities = []
        for i in range(len(word_sets) - 1):
            intersection = len(word_sets[i] & word_sets[i + 1])
            union = len(word_sets[i] | word_sets[i + 1])
            if union > 0:
                similarities.append(intersection / union)

        return sum(similarities) / len(similarities) if similarities else 0.0

    def _adjust_for_context(self, result: AnalysisResult, issue: Issue | None) -> None:
        """Adjust analysis based on issue context."""
        if not issue:
            return

        # Boost completion confidence if all tests pass and no failures
        if result.tests_passed > 0 and result.tests_failed == 0:
            result.completion_confidence = min(1.0, result.completion_confidence + 0.1)

        # Reduce confidence if issue has remaining subtasks
        # (would need issue subtask data to implement)

    def reset_history(self) -> None:
        """Clear response history (e.g., when starting new issue)."""
        self._response_history.clear()

    # =========================================================================
    # Full-Scale Ralph: Learned Pattern Integration
    # =========================================================================

    def _refresh_learned_patterns(self, force: bool = False) -> None:
        """
        Load learned patterns from sleeptime consolidation.

        Reads from .cyntra/learned_context/ directory:
        - failure_modes.md: Anti-patterns that indicate false completion
        - success_patterns.md: Patterns that confirm genuine completion
        - false_positives.md: Phrases that look like completion but aren't

        Args:
            force: Force refresh even if recently loaded
        """
        # Skip if recently loaded (within 60s) unless forced
        if not force and time.time() - self._patterns_loaded_at < 60:
            return

        if not self.learned_context_dir or not self.learned_context_dir.exists():
            return

        try:
            # Load anti-patterns (false completion indicators)
            failure_modes_path = self.learned_context_dir / "failure_modes.md"
            if failure_modes_path.exists():
                self._learned_anti_patterns = self._parse_pattern_file(failure_modes_path)
                logger.debug(
                    "response_analyzer.loaded_anti_patterns",
                    count=len(self._learned_anti_patterns),
                )

            # Load success patterns (genuine completion indicators)
            success_patterns_path = self.learned_context_dir / "success_patterns.md"
            if success_patterns_path.exists():
                self._learned_success_patterns = self._parse_pattern_file(success_patterns_path)
                logger.debug(
                    "response_analyzer.loaded_success_patterns",
                    count=len(self._learned_success_patterns),
                )

            # Load false positive phrases
            false_positives_path = self.learned_context_dir / "false_positives.md"
            if false_positives_path.exists():
                self._learned_false_positives = self._parse_pattern_file(false_positives_path)
                logger.debug(
                    "response_analyzer.loaded_false_positives",
                    count=len(self._learned_false_positives),
                )

            self._patterns_loaded_at = time.time()

        except Exception as e:
            logger.warning("response_analyzer.pattern_load_failed", error=str(e))

    def _parse_pattern_file(self, path: Path) -> list[str]:
        """
        Parse a markdown pattern file into list of patterns.

        Expected format:
        ```
        ## Patterns
        - pattern 1
        - pattern 2
        ```

        Or bullet points anywhere in the file.
        """
        patterns = []
        try:
            content = path.read_text()
            # Extract bullet points (- or *)
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("- ") or line.startswith("* "):
                    pattern = line[2:].strip()
                    # Skip empty or comment-like patterns
                    if pattern and not pattern.startswith("#"):
                        patterns.append(pattern)
        except Exception:
            pass
        return patterns

    def _analyze_learned_patterns(self, response: str, result: AnalysisResult) -> None:
        """
        Check response against learned patterns from sleeptime consolidation.

        Updates result with:
        - anti_pattern_warnings: Detected false-completion patterns
        - pattern_confirmations: Detected genuine-completion patterns
        - Adjusted completion_confidence based on findings
        """
        # Refresh patterns if stale
        self._refresh_learned_patterns()

        response_lower = response.lower()

        # Check for anti-patterns (reduce confidence)
        for pattern in self._learned_anti_patterns:
            if pattern.lower() in response_lower:
                result.anti_pattern_warnings.append(pattern)

        # Check for false positives (phrases that look like completion but aren't)
        for pattern in self._learned_false_positives:
            if pattern.lower() in response_lower:
                result.anti_pattern_warnings.append(f"[false-positive] {pattern}")

        # Check for success patterns (increase confidence)
        for pattern in self._learned_success_patterns:
            if pattern.lower() in response_lower:
                result.pattern_confirmations.append(pattern)

        # Adjust confidence based on learned patterns
        if result.anti_pattern_warnings:
            penalty = min(0.3, 0.1 * len(result.anti_pattern_warnings))
            result.completion_confidence = max(0, result.completion_confidence - penalty)
            logger.debug(
                "response_analyzer.anti_pattern_penalty",
                warnings=result.anti_pattern_warnings,
                penalty=penalty,
            )

        if result.pattern_confirmations:
            boost = min(0.2, 0.05 * len(result.pattern_confirmations))
            result.completion_confidence = min(1.0, result.completion_confidence + boost)
            logger.debug(
                "response_analyzer.success_pattern_boost",
                confirmations=result.pattern_confirmations,
                boost=boost,
            )

    def _compute_semantic_overlap(
        self, response: str, issue: Issue | None, result: AnalysisResult
    ) -> None:
        """
        Compute semantic overlap between response and issue title/description.

        Higher overlap suggests the agent addressed the actual task.
        Low overlap with high completion confidence = potential false positive.

        Updates result.semantic_overlap_score (0.0 - 1.0).
        """
        if not issue:
            return

        # Extract key terms from issue
        issue_text = f"{issue.title} {getattr(issue, 'body', '') or ''}"
        issue_words = set(re.findall(r"\b[a-zA-Z]{3,}\b", issue_text.lower()))

        # Extract key terms from response
        response_words = set(re.findall(r"\b[a-zA-Z]{3,}\b", response.lower()))

        # Remove common stop words
        stop_words = {
            "the", "and", "for", "that", "this", "with", "are", "was", "were",
            "been", "being", "have", "has", "had", "does", "did", "will", "would",
            "could", "should", "may", "might", "must", "shall", "can", "need",
            "also", "just", "only", "into", "from", "here", "there", "when",
            "where", "which", "while", "about", "after", "before", "between",
            "through", "during", "without", "again", "further", "then", "once",
        }
        issue_words -= stop_words
        response_words -= stop_words

        if not issue_words:
            return

        # Compute Jaccard similarity
        intersection = len(issue_words & response_words)
        union = len(issue_words | response_words)

        if union > 0:
            result.semantic_overlap_score = intersection / union

        # Warn if high completion confidence but low semantic overlap
        if (
            result.completion_confidence >= 0.7
            and result.semantic_overlap_score < 0.15
            and len(issue_words) >= 3
        ):
            result.anti_pattern_warnings.append(
                f"[semantic-mismatch] High confidence ({result.completion_confidence:.2f}) "
                f"but low issue overlap ({result.semantic_overlap_score:.2f})"
            )
            # Reduce confidence for potential false positive
            result.completion_confidence = max(0.4, result.completion_confidence - 0.2)
            logger.debug(
                "response_analyzer.semantic_mismatch",
                overlap=result.semantic_overlap_score,
                issue_words=len(issue_words),
            )

    def get_learned_pattern_stats(self) -> dict[str, Any]:
        """Return statistics about loaded learned patterns."""
        return {
            "anti_patterns_count": len(self._learned_anti_patterns),
            "success_patterns_count": len(self._learned_success_patterns),
            "false_positives_count": len(self._learned_false_positives),
            "patterns_loaded_at": self._patterns_loaded_at,
            "learned_context_dir": str(self.learned_context_dir) if self.learned_context_dir else None,
        }


# Convenience function for quick analysis
def analyze_response(
    response: str,
    issue: Issue | None = None,
    files_changed: list[str] | None = None,
) -> AnalysisResult:
    """Quick analysis without maintaining history."""
    analyzer = ResponseAnalyzer()
    return analyzer.analyze(response, issue, files_changed)
