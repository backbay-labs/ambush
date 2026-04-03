"""
Integration Gates - Verify new code is actually used.

These gates run automatically and cannot be skipped by agents.
They catch the "built but not wired" failure mode.
"""

from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from cyntra.core.gates.runner import GateResult

logger = structlog.get_logger()


@dataclass
class IntegrationIssue:
    """An integration problem detected by invariant gates."""

    severity: str  # "error" | "warning"
    code: str  # e.g., "UNUSED_EXPORT", "DEAD_COMPONENT"
    message: str
    file: str
    line: int | None = None
    export_name: str | None = None


@dataclass
class IntegrationGateResult:
    """Result of integration gate checks."""

    passed: bool
    issues: list[IntegrationIssue]
    exports_checked: int
    imports_found: int

    def to_gate_result(self, name: str, duration_ms: int) -> dict:
        return {
            "name": name,
            "passed": self.passed,
            "exit_code": 0 if self.passed else 1,
            "duration_ms": duration_ms,
            "failure_summary": self._format_issues() if not self.passed else None,
            "metadata": {
                "exports_checked": self.exports_checked,
                "imports_found": self.imports_found,
                "issues": [
                    {
                        "severity": i.severity,
                        "code": i.code,
                        "message": i.message,
                        "file": i.file,
                        "line": i.line,
                    }
                    for i in self.issues
                ],
            },
        }

    def _format_issues(self) -> str:
        if not self.issues:
            return ""
        lines = []
        for issue in self.issues[:10]:  # Limit to 10
            prefix = "ERROR" if issue.severity == "error" else "WARN"
            lines.append(f"[{prefix}] {issue.code}: {issue.message}")
            lines.append(f"  → {issue.file}:{issue.line or '?'}")
        if len(self.issues) > 10:
            lines.append(f"  ... and {len(self.issues) - 10} more issues")
        return "\n".join(lines)


class IntegrationGate:
    """
    Verify that new exports are actually imported and used somewhere.

    This gate catches the common failure mode where agents create libraries
    but don't wire them into the application.
    """

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    def check_exports_have_importers(
        self,
        changed_files: list[Path],
        file_extensions: tuple[str, ...] = (".ts", ".tsx", ".js", ".jsx"),
    ) -> IntegrationGateResult:
        """
        Check that new exports in changed files are imported somewhere.

        Args:
            changed_files: Files that were modified in this change
            file_extensions: File extensions to check

        Returns:
            IntegrationGateResult with pass/fail and issues
        """
        issues: list[IntegrationIssue] = []
        exports_checked = 0
        imports_found = 0

        for file_path in changed_files:
            if not file_path.suffix in file_extensions:
                continue

            if not file_path.exists():
                continue

            # Extract exports from this file
            exports = self._extract_exports(file_path)
            exports_checked += len(exports)

            for export_name, line_num in exports:
                # Check if this export is imported anywhere
                importers = self._find_importers(export_name, file_path)
                if importers:
                    imports_found += 1
                else:
                    issues.append(
                        IntegrationIssue(
                            severity="error",
                            code="UNUSED_EXPORT",
                            message=f"Export '{export_name}' has no importers - likely missing integration",
                            file=str(file_path.relative_to(self.repo_root)),
                            line=line_num,
                            export_name=export_name,
                        )
                    )

        # Only fail if there are error-level issues
        errors = [i for i in issues if i.severity == "error"]
        passed = len(errors) == 0

        return IntegrationGateResult(
            passed=passed,
            issues=issues,
            exports_checked=exports_checked,
            imports_found=imports_found,
        )

    def check_components_are_rendered(
        self,
        changed_files: list[Path],
    ) -> IntegrationGateResult:
        """
        Check that new React components are rendered somewhere.

        A component that is exported but never used in JSX is likely
        a missed integration.
        """
        issues: list[IntegrationIssue] = []
        components_checked = 0
        components_rendered = 0

        for file_path in changed_files:
            if file_path.suffix not in (".tsx", ".jsx"):
                continue

            if not file_path.exists():
                continue

            # Extract component exports
            components = self._extract_component_exports(file_path)
            components_checked += len(components)

            for component_name, line_num in components:
                # Check if component is used in JSX anywhere
                if self._is_component_rendered(component_name, file_path):
                    components_rendered += 1
                else:
                    issues.append(
                        IntegrationIssue(
                            severity="error",
                            code="UNRENDERED_COMPONENT",
                            message=f"Component '{component_name}' is exported but never rendered",
                            file=str(file_path.relative_to(self.repo_root)),
                            line=line_num,
                            export_name=component_name,
                        )
                    )

        errors = [i for i in issues if i.severity == "error"]
        passed = len(errors) == 0

        return IntegrationGateResult(
            passed=passed,
            issues=issues,
            exports_checked=components_checked,
            imports_found=components_rendered,
        )

    def check_hooks_are_called(
        self,
        changed_files: list[Path],
    ) -> IntegrationGateResult:
        """
        Check that new React hooks are called somewhere.

        A hook that is exported but never called is likely a missed integration.
        """
        issues: list[IntegrationIssue] = []
        hooks_checked = 0
        hooks_called = 0

        for file_path in changed_files:
            if file_path.suffix not in (".ts", ".tsx"):
                continue

            if not file_path.exists():
                continue

            # Extract hook exports (functions starting with "use")
            hooks = self._extract_hook_exports(file_path)
            hooks_checked += len(hooks)

            for hook_name, line_num in hooks:
                # Check if hook is called anywhere
                if self._is_hook_called(hook_name, file_path):
                    hooks_called += 1
                else:
                    issues.append(
                        IntegrationIssue(
                            severity="error",
                            code="UNUSED_HOOK",
                            message=f"Hook '{hook_name}' is exported but never called",
                            file=str(file_path.relative_to(self.repo_root)),
                            line=line_num,
                            export_name=hook_name,
                        )
                    )

        errors = [i for i in issues if i.severity == "error"]
        passed = len(errors) == 0

        return IntegrationGateResult(
            passed=passed,
            issues=issues,
            exports_checked=hooks_checked,
            imports_found=hooks_called,
        )

    def _extract_exports(self, file_path: Path) -> list[tuple[str, int]]:
        """Extract export names and line numbers from a TypeScript/JavaScript file."""
        content = file_path.read_text()
        exports: list[tuple[str, int]] = []

        # Match: export function Name, export const Name, export class Name
        # Also: export { Name }, export default Name
        patterns = [
            r"export\s+(?:async\s+)?function\s+(\w+)",
            r"export\s+const\s+(\w+)",
            r"export\s+class\s+(\w+)",
            r"export\s+interface\s+(\w+)",
            r"export\s+type\s+(\w+)",
            r"export\s+enum\s+(\w+)",
            r"export\s+\{\s*([^}]+)\s*\}",
        ]

        for i, line in enumerate(content.split("\n"), 1):
            for pattern in patterns:
                matches = re.findall(pattern, line)
                for match in matches:
                    # Handle "export { A, B, C }" case
                    if "," in match:
                        for name in match.split(","):
                            name = name.strip().split(" as ")[0].strip()
                            if name and not name.startswith("_"):
                                exports.append((name, i))
                    else:
                        name = match.strip()
                        if name and not name.startswith("_"):
                            exports.append((name, i))

        return exports

    def _extract_component_exports(self, file_path: Path) -> list[tuple[str, int]]:
        """Extract React component exports (PascalCase functions)."""
        exports = self._extract_exports(file_path)
        # Components are PascalCase
        return [(name, line) for name, line in exports if name[0].isupper()]

    def _extract_hook_exports(self, file_path: Path) -> list[tuple[str, int]]:
        """Extract React hook exports (functions starting with 'use')."""
        exports = self._extract_exports(file_path)
        return [(name, line) for name, line in exports if name.startswith("use")]

    def _find_importers(self, export_name: str, source_file: Path) -> list[Path]:
        """Find files that import the given export."""
        # Use ripgrep for fast search
        try:
            # Search for import statements containing the export name
            result = subprocess.run(
                [
                    "rg",
                    "-l",  # Files only
                    "--type", "ts",
                    "--type", "tsx",
                    "--type", "js",
                    "--type", "jsx",
                    f"import.*{export_name}.*from|import.*\\{{[^}}]*{export_name}[^}}]*\\}}.*from",
                    str(self.repo_root),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                importers = []
                for line in result.stdout.strip().split("\n"):
                    if line:
                        importer = Path(line)
                        # Exclude the source file itself
                        if importer.resolve() != source_file.resolve():
                            importers.append(importer)
                return importers

        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fall back to simple grep if rg not available
            pass

        return []

    def _is_component_rendered(self, component_name: str, source_file: Path) -> bool:
        """Check if a component is rendered in JSX anywhere."""
        try:
            # Search for <ComponentName or <ComponentName>
            result = subprocess.run(
                [
                    "rg",
                    "-l",
                    "--type", "tsx",
                    "--type", "jsx",
                    f"<{component_name}[\\s/>]",
                    str(self.repo_root),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0 and result.stdout.strip():
                # Check if any file other than source renders it
                for line in result.stdout.strip().split("\n"):
                    if line and Path(line).resolve() != source_file.resolve():
                        return True

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return False

    def _is_hook_called(self, hook_name: str, source_file: Path) -> bool:
        """Check if a hook is called anywhere."""
        try:
            # Search for hook() calls
            result = subprocess.run(
                [
                    "rg",
                    "-l",
                    "--type", "ts",
                    "--type", "tsx",
                    f"{hook_name}\\(",
                    str(self.repo_root),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0 and result.stdout.strip():
                # Check if any file other than source calls it
                for line in result.stdout.strip().split("\n"):
                    if line and Path(line).resolve() != source_file.resolve():
                        return True

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return False


def run_integration_gates(
    repo_root: Path,
    changed_files: list[Path],
) -> dict[str, IntegrationGateResult]:
    """
    Run all integration gates on changed files.

    Returns dict mapping gate name to result.
    """
    gate = IntegrationGate(repo_root)

    results = {
        "exports_have_importers": gate.check_exports_have_importers(changed_files),
        "components_are_rendered": gate.check_components_are_rendered(changed_files),
        "hooks_are_called": gate.check_hooks_are_called(changed_files),
    }

    return results
