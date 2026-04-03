"""
Doc Sync Sentinel - Keeps documentation in sync with code.

Responsibilities:
- Verify directories in CLAUDE.md project structure exist
- Check file references in documentation
- Sync mise.toml versions with CLAUDE.md
- Validate mise tasks mentioned in docs
- Check Python modules exist
- Detect dead documentation links
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cyntra.core.sentinel.base import (
    BaseSentinel,
    SentinelConfig,
    SentinelSchedule,
)


@dataclass
class DocSyncConfig:
    """Configuration for DocSyncSentinel."""

    # Which checks to run
    check_directory_structure: bool = True
    check_file_references: bool = True
    check_mise_version_sync: bool = True
    check_mise_task_sync: bool = True
    check_module_existence: bool = True
    check_dead_doc_links: bool = True

    # CLAUDE.md location (relative to repo root)
    claude_md_path: str = "CLAUDE.md"
    mise_toml_path: str = ".mise.toml"

    # Directories to validate from project structure
    expected_directories: list[str] = field(
        default_factory=lambda: [
            "apps/desktop",
            "kernel/src/cyntra",
            "kernel/src/cyntra/kernel",
            "kernel/src/cyntra/adapters",
            "kernel/src/cyntra/workcell",
            "kernel/src/cyntra/state",
            "kernel/src/cyntra/fab",
            "fab/gates",
            "fab/lookdev",
            "docs",
        ]
    )

    # Files that should exist
    expected_files: list[str] = field(
        default_factory=lambda: [
            ".cyntra/config.yaml",
            ".beads/issues.jsonl",
        ]
    )

    # Python modules that should be importable (relative paths)
    expected_modules: list[str] = field(
        default_factory=lambda: [
            "kernel/src/cyntra/kernel/scheduler.py",
            "kernel/src/cyntra/kernel/dispatcher.py",
            "kernel/src/cyntra/kernel/verifier.py",
        ]
    )

    # Doc directories to scan for dead links
    doc_directories: list[str] = field(
        default_factory=lambda: ["docs", "kernel"]
    )


class DocSyncSentinel(BaseSentinel):
    """
    Keeps documentation in sync with code changes.

    Responsibilities:
    - Verify directories in CLAUDE.md project structure exist
    - Check file references in documentation
    - Sync mise.toml versions with CLAUDE.md
    - Validate mise tasks mentioned in docs
    - Check Python modules exist
    - Detect dead documentation links
    """

    def __init__(
        self,
        config: SentinelConfig | None = None,
        doc_config: DocSyncConfig | None = None,
        schedule: SentinelSchedule | None = None,
        repo_root: Path | None = None,
    ) -> None:
        super().__init__(config, schedule, repo_root)
        self.doc_config = doc_config or DocSyncConfig()

    @property
    def name(self) -> str:
        return "doc_sync"

    @property
    def description(self) -> str:
        return "Keeps docs in sync with code: CLAUDE.md, API docs, README examples"

    async def execute(self) -> None:
        """Run all configured doc sync checks."""
        self._log.info("starting_doc_sync")

        if self.doc_config.check_directory_structure:
            await self._check_directory_structure()

        if self.doc_config.check_file_references:
            await self._check_file_references()

        if self.doc_config.check_mise_version_sync:
            await self._check_mise_version_sync()

        if self.doc_config.check_mise_task_sync:
            await self._check_mise_task_sync()

        if self.doc_config.check_module_existence:
            await self._check_module_existence()

        if self.doc_config.check_dead_doc_links:
            await self._check_dead_doc_links()

        self._log.info("doc_sync_complete")

    async def _check_directory_structure(self) -> None:
        """Verify directories mentioned in project structure exist."""
        missing = []

        for dir_path in self.doc_config.expected_directories:
            full_path = self.repo_root / dir_path
            if not full_path.is_dir():
                missing.append(dir_path)

        if missing:
            self._log.warning("missing_directories", count=len(missing))
            for dir_path in missing[:5]:
                self.propose_change(
                    change_type="missing_directory",
                    target=f"dir:{dir_path}",
                    description=(
                        f"Directory '{dir_path}' listed in CLAUDE.md does not exist"
                    ),
                )

    async def _check_file_references(self) -> None:
        """Verify files referenced in documentation exist."""
        missing = []

        for file_path in self.doc_config.expected_files:
            full_path = self.repo_root / file_path
            if not full_path.exists():
                missing.append(file_path)

        if missing:
            self._log.warning("missing_files", count=len(missing))
            for file_path in missing[:5]:
                self.propose_change(
                    change_type="missing_file",
                    target=f"file:{file_path}",
                    description=(
                        f"File '{file_path}' referenced in docs does not exist"
                    ),
                )

    async def _check_mise_version_sync(self) -> None:
        """Compare tool versions in CLAUDE.md with .mise.toml."""
        import re

        claude_md_path = self.repo_root / self.doc_config.claude_md_path
        mise_toml_path = self.repo_root / self.doc_config.mise_toml_path

        if not claude_md_path.exists() or not mise_toml_path.exists():
            self._log.debug("mise_sync_skip", reason="files not found")
            return

        # Parse mise.toml for tool versions
        mise_versions: dict[str, str] = {}
        with open(mise_toml_path) as f:
            mise_content = f.read()
            # Parse [tools] section
            tools_match = re.search(
                r'\[tools\](.*?)(?:\n\[|\Z)', mise_content, re.DOTALL
            )
            if tools_match:
                tools_section = tools_match.group(1)
                for line in tools_section.strip().split('\n'):
                    match = re.match(r'(\w+)\s*=\s*"?([^"\n]+)"?', line.strip())
                    if match:
                        tool, version = match.groups()
                        mise_versions[tool.lower()] = version.strip('"')

        # Parse CLAUDE.md for version comments (in the mise current example)
        claude_versions: dict[str, str] = {}
        with open(claude_md_path) as f:
            claude_content = f.read()
            # Look for patterns like "# python  3.12.12"
            version_pattern = r'#\s*(\w+)\s+([\d.]+)'
            for match in re.finditer(version_pattern, claude_content):
                tool, version = match.groups()
                claude_versions[tool.lower()] = version

        # Compare versions
        mismatches = []
        for tool, mise_ver in mise_versions.items():
            claude_ver = claude_versions.get(tool)
            if claude_ver and not mise_ver.startswith(claude_ver.split('.')[0]):
                # Major version mismatch
                mismatches.append((tool, mise_ver, claude_ver))

        if mismatches:
            self._log.warning("mise_version_mismatch", count=len(mismatches))
            for tool, mise_ver, claude_ver in mismatches[:3]:
                self.propose_change(
                    change_type="version_mismatch",
                    target=f"tool:{tool}",
                    description=(
                        f"Tool '{tool}' version mismatch: "
                        f".mise.toml has {mise_ver}, CLAUDE.md shows {claude_ver}"
                    ),
                )

    async def _check_mise_task_sync(self) -> None:
        """Verify mise tasks mentioned in CLAUDE.md exist in .mise.toml."""
        import re

        claude_md_path = self.repo_root / self.doc_config.claude_md_path
        mise_toml_path = self.repo_root / self.doc_config.mise_toml_path

        if not claude_md_path.exists() or not mise_toml_path.exists():
            return

        # Parse mise.toml for task names
        available_tasks: set[str] = set()
        with open(mise_toml_path) as f:
            mise_content = f.read()
            # Find [tasks.X] sections
            for match in re.finditer(r'\[tasks\.(\w+(?:-\w+)*)\]', mise_content):
                available_tasks.add(match.group(1))

        # Parse CLAUDE.md for "mise run X" commands
        referenced_tasks: set[str] = set()
        with open(claude_md_path) as f:
            claude_content = f.read()
            for match in re.finditer(r'mise\s+run\s+(\w+(?:-\w+)*)', claude_content):
                referenced_tasks.add(match.group(1))

        # Find missing tasks
        missing_tasks = referenced_tasks - available_tasks

        if missing_tasks:
            self._log.warning("missing_mise_tasks", count=len(missing_tasks))
            for task in list(missing_tasks)[:5]:
                self.propose_change(
                    change_type="missing_mise_task",
                    target=f"task:{task}",
                    description=(
                        f"Mise task '{task}' referenced in CLAUDE.md "
                        f"but not defined in .mise.toml"
                    ),
                )

    async def _check_module_existence(self) -> None:
        """Verify Python modules mentioned in docs exist."""
        missing = []

        for module_path in self.doc_config.expected_modules:
            full_path = self.repo_root / module_path
            if not full_path.exists():
                missing.append(module_path)

        if missing:
            self._log.warning("missing_modules", count=len(missing))
            for module_path in missing[:5]:
                self.propose_change(
                    change_type="missing_module",
                    target=f"module:{module_path}",
                    description=(
                        f"Python module '{module_path}' mentioned in docs "
                        f"does not exist"
                    ),
                )

    async def _check_dead_doc_links(self) -> None:
        """Find broken links in markdown files."""
        import re

        dead_links: list[tuple[str, str, str]] = []

        for doc_dir in self.doc_config.doc_directories:
            dir_path = self.repo_root / doc_dir
            if not dir_path.exists():
                continue

            # Find all markdown files
            for md_file in dir_path.rglob("*.md"):
                # Skip node_modules and .venv
                if "node_modules" in str(md_file) or ".venv" in str(md_file):
                    continue

                try:
                    content = md_file.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue

                # Find local file links: [text](./path) or [text](path.md)
                link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
                for match in re.finditer(link_pattern, content):
                    link_text, link_target = match.groups()

                    # Skip external URLs and anchors
                    if link_target.startswith(('http://', 'https://', '#', 'mailto:')):
                        continue

                    # Remove anchor from link
                    link_target = link_target.split('#')[0]
                    if not link_target:
                        continue

                    # Resolve relative to the markdown file's directory
                    if link_target.startswith('/'):
                        # Absolute from repo root
                        target_path = self.repo_root / link_target.lstrip('/')
                    else:
                        # Relative to the markdown file
                        target_path = md_file.parent / link_target

                    # Check if target exists
                    if not target_path.exists():
                        rel_md = md_file.relative_to(self.repo_root)
                        dead_links.append((str(rel_md), link_target, link_text))

        if dead_links:
            self._log.warning("dead_links_found", count=len(dead_links))
            for md_file, target, text in dead_links[:5]:
                self.propose_change(
                    change_type="dead_doc_link",
                    target=f"file:{md_file}",
                    description=(
                        f"Dead link in '{md_file}': [{text}]({target})"
                    ),
                )


__all__ = [
    "DocSyncConfig",
    "DocSyncSentinel",
]
