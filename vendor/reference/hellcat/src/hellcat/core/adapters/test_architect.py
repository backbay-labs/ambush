"""
Test Architect Adapter - Generates test scaffolding and expands coverage.

Routed via tags: [test-gen, coverage, testing]
Or explicit dk_tool_hint: test-architect
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog

from hellcat.core.adapters.base import CostEstimate, PatchProof, ToolchainAdapter

logger = structlog.get_logger()


def get_adapter(name: str, config: dict | None = None) -> ToolchainAdapter | None:
    """
    Lazy adapter resolver.

    Defined at module scope so tests can patch `hellcat.adapters.test_architect.get_adapter`
    without introducing an import cycle at import time.
    """
    from hellcat.core.adapters import get_adapter as _get_adapter

    return _get_adapter(name, config)


class TestArchitectAdapter(ToolchainAdapter):
    """
    Adapter for generating and improving test coverage.

    Routes test generation tasks to a backing LLM adapter with
    specialized prompting for test creation.
    """

    name = "test-architect"
    supports_mcp = False
    supports_streaming = False
    __test__ = False  # Avoid pytest collecting this as a test class.

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        # Use underlying model (claude or codex)
        self.backing_adapter_name = self.config.get("backing_adapter", "claude")
        self.backing_model = self.config.get("model", "sonnet")
        self._available: bool | None = None
        self._backing_adapter: ToolchainAdapter | None = None

    @property
    def available(self) -> bool:
        """Check if backing adapter is available."""
        if self._available is None:
            self._backing_adapter = get_adapter(
                self.backing_adapter_name,
                {"model": self.backing_model, "skip_permissions": True},
            )
            self._available = self._backing_adapter is not None and self._backing_adapter.available
        return self._available

    @available.setter
    def available(self, value: bool) -> None:
        # Allow tests to patch `adapter.available` directly.
        self._available = bool(value)

    @available.deleter
    def available(self) -> None:
        # Allow tests to reset patched availability.
        self._available = None
        self._backing_adapter = None

    def execute_sync(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout_seconds: int = 1800,
    ) -> PatchProof:
        """Synchronous execution wrapper."""
        return asyncio.run(
            self.execute(manifest, workcell_path, timedelta(seconds=timeout_seconds))
        )

    async def execute(
        self,
        manifest: dict,
        workcell_path: Path,
        timeout: timedelta,
    ) -> PatchProof:
        """Execute test generation task."""
        started_at = datetime.now(UTC)
        workcell_id = manifest.get("workcell_id", "unknown")
        issue_id = manifest.get("issue", {}).get("id", "unknown")

        logs_dir = workcell_path / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            "test_architect_starting",
            workcell_id=workcell_id,
            issue_id=issue_id,
            backing_adapter=self.backing_adapter_name,
        )

        # Build specialized prompt for test generation
        prompt = self._build_test_architect_prompt(manifest, workcell_path)
        prompt_file = workcell_path / "prompt.md"
        prompt_file.write_text(prompt)

        # Ensure we have backing adapter
        if not self.available or self._backing_adapter is None:
            return self._create_error_proof(manifest, started_at, "No backing adapter available")

        # Create modified manifest for backing adapter
        test_manifest = dict(manifest)
        test_manifest["toolchain"] = self.backing_adapter_name
        test_manifest["toolchain_config"] = dict(manifest.get("toolchain_config", {}))
        test_manifest["toolchain_config"]["model"] = self.backing_model

        try:
            # Delegate to backing adapter
            proof = await self._backing_adapter.execute(
                manifest=test_manifest,
                workcell_path=workcell_path,
                timeout=timeout,
            )

            # Augment proof with test-specific metadata
            proof.metadata = proof.metadata or {}
            proof.metadata["test_architect"] = True
            proof.metadata["backing_adapter"] = self.backing_adapter_name

            # Run coverage check if tests were created
            coverage_result = self._check_coverage(workcell_path)
            if coverage_result:
                proof.metadata["coverage"] = coverage_result

            # Update patch info with test files
            test_files = self._find_test_files(workcell_path)
            if test_files:
                proof.patch = proof.patch or {}
                proof.patch["test_files_created"] = test_files

            logger.info(
                "test_architect_completed",
                workcell_id=workcell_id,
                status=proof.status,
                test_files=len(test_files),
            )

            return proof

        except Exception as e:
            logger.error(
                "test_architect_failed",
                workcell_id=workcell_id,
                error=str(e),
            )
            return self._create_error_proof(manifest, started_at, str(e))

    async def health_check(self) -> bool:
        """Check if adapter is operational."""
        return self.available

    def estimate_cost(self, manifest: dict) -> CostEstimate:
        """Estimate cost for test generation."""
        estimated_tokens = manifest.get("issue", {}).get("dk_estimated_tokens", 30000)
        # Test generation typically uses less tokens than full implementation
        estimated_tokens = int(estimated_tokens * 0.6)

        cost_per_1m = {
            "sonnet": 9.0,
            "haiku": 0.75,
            "opus": 45.0,
            "gpt-5.2": 15.0,
        }.get(self.backing_model, 9.0)

        return CostEstimate(
            estimated_tokens=estimated_tokens,
            estimated_cost_usd=(estimated_tokens / 1_000_000) * cost_per_1m,
            model=f"test-architect({self.backing_model})",
        )

    def _build_test_architect_prompt(self, manifest: dict, workcell_path: Path) -> str:
        """Build specialized prompt for test generation."""
        issue = manifest.get("issue", {})

        # Find relevant source files
        context_files = issue.get("context_files", [])

        # Find existing tests
        existing_tests = self._find_existing_tests(workcell_path, context_files)

        prompt_parts = [
            "# Test Generation Task",
            "",
            "You are a test architect. Your job is to create comprehensive tests.",
            "",
            "## Guidelines",
            "- Create tests that verify the acceptance criteria",
            "- Follow existing test patterns in the codebase",
            "- Aim for high coverage of edge cases",
            "- Use descriptive test names that explain what is being tested",
            "- Include docstrings explaining test purpose",
            "- Use fixtures and parametrization where appropriate",
            "- Test both happy paths and error cases",
            "",
            f"## Issue: {issue.get('title', 'Unknown')}",
            "",
            issue.get("description", "No description provided."),
            "",
        ]

        if issue.get("acceptance_criteria"):
            prompt_parts.append("## Acceptance Criteria to Test")
            for criterion in issue["acceptance_criteria"]:
                prompt_parts.append(f"- {criterion}")
            prompt_parts.append("")

        if context_files:
            prompt_parts.append("## Source Files to Test")
            for f in context_files:
                prompt_parts.append(f"- {f}")
            prompt_parts.append("")

        if existing_tests:
            prompt_parts.append("## Existing Test Files (for pattern reference)")
            for t in existing_tests[:5]:
                prompt_parts.append(f"- {t}")
            prompt_parts.append("")

        prompt_parts.extend(
            [
                "## Required Actions",
                "1. Analyze the source files to understand what needs testing",
                "2. Create test files with comprehensive coverage",
                "3. Generate any needed fixtures or test data",
                "4. Run the tests to verify they pass",
                "5. Report on coverage improvement",
                "",
                "## Test File Naming",
                "- For `src/module.py`, create `tests/test_module.py`",
                "- For `src/package/file.py`, create `tests/package/test_file.py`",
                "",
                "## Test Structure",
                "```python",
                "import pytest",
                "from module import function_to_test",
                "",
                "class TestFunctionName:",
                '    """Tests for function_name."""',
                "",
                "    def test_basic_functionality(self):",
                '        """Test the basic happy path."""',
                "        result = function_to_test(input)",
                "        assert result == expected",
                "",
                "    def test_edge_case(self):",
                '        """Test edge case behavior."""',
                "        ...",
                "",
                "    def test_error_handling(self):",
                '        """Test error conditions."""',
                "        with pytest.raises(ValueError):",
                "            function_to_test(invalid_input)",
                "```",
            ]
        )

        return "\n".join(prompt_parts)

    def _find_existing_tests(self, workcell_path: Path, source_files: list[str]) -> list[str]:
        """Find existing test files related to source files."""
        test_files: list[str] = []

        # Look in tests/ directory
        tests_dir = workcell_path / "tests"
        if tests_dir.exists():
            for test_file in tests_dir.rglob("test_*.py"):
                rel_path = str(test_file.relative_to(workcell_path))
                if rel_path not in test_files:
                    test_files.append(rel_path)

        # Look for *_test.py pattern
        for test_file in workcell_path.rglob("*_test.py"):
            rel_path = str(test_file.relative_to(workcell_path))
            if rel_path not in test_files:
                test_files.append(rel_path)

        return test_files[:10]

    def _find_test_files(self, workcell_path: Path) -> list[str]:
        """Find test files created or modified in this workcell."""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "main...HEAD"],
                cwd=workcell_path,
                capture_output=True,
                text=True,
                timeout=30,
            )
            all_files = result.stdout.strip().split("\n")
            return [
                f for f in all_files if f and ("test_" in f or "_test.py" in f or "/tests/" in f)
            ]
        except Exception:
            return []

    def _check_coverage(self, workcell_path: Path) -> dict[str, Any] | None:
        """Run coverage check and return results."""
        try:
            result = subprocess.run(
                [
                    "pytest",
                    "--cov",
                    "--cov-report=json:coverage.json",
                    "-q",
                    "--tb=no",
                ],
                cwd=workcell_path,
                capture_output=True,
                text=True,
                timeout=300,
            )

            coverage_file = workcell_path / "coverage.json"
            if coverage_file.exists():
                data = json.loads(coverage_file.read_text())
                return {
                    "total_coverage": data.get("totals", {}).get("percent_covered", 0),
                    "files_covered": len(data.get("files", {})),
                    "tests_passed": result.returncode == 0,
                }
        except Exception as e:
            logger.debug("coverage_check_failed", error=str(e))

        return None

    def _create_error_proof(self, manifest: dict, started_at: datetime, error: str) -> PatchProof:
        """Create error proof."""
        return PatchProof(
            schema_version="1.0.0",
            workcell_id=manifest.get("workcell_id", "unknown"),
            issue_id=manifest.get("issue", {}).get("id", "unknown"),
            status="error",
            patch={},
            verification={"all_passed": False, "blocking_failures": ["error"]},
            metadata={
                "error": error,
                "toolchain": self.name,
                "started_at": started_at.isoformat(),
            },
            confidence=0,
            risk_classification="medium",
        )
