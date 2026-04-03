"""
Workcell template system for scoped workspace creation.

Templates define what files/directories are included in a workcell,
how secrets are injected, and what context is provided to agents.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import structlog
import yaml

logger = structlog.get_logger()


class SecretSource(str, Enum):
    """Where to load secrets from."""

    ENV = "env"
    VAULT = "vault"
    KEYCHAIN = "keychain"
    FILE = "file"


@dataclass
class SecretConfig:
    """Secret injection configuration."""

    source: SecretSource = SecretSource.ENV
    inject: list[str] = field(default_factory=list)
    file_path: str | None = None  # For file source


@dataclass
class SymlinkConfig:
    """Symlink configuration for read-only references."""

    path: str  # Path in workcell
    target: str  # Target path (can use ${REPO_ROOT})


@dataclass
class ContextConfig:
    """Agent context injection configuration."""

    claude_md: str = ""  # Additional CLAUDE.md content
    inject_files: list[str] = field(default_factory=list)  # Files to inject into context


@dataclass
class WorkcellTemplate:
    """
    Defines the composition of a workcell.

    Templates specify:
    - What files are included (sparse checkout)
    - What directories are symlinked (read-only refs)
    - What secrets are injected (runtime only)
    - What setup commands to run
    - What context to provide to agents
    """

    id: str
    description: str = ""

    # File selection
    sparse_checkout: list[str] = field(default_factory=list)
    symlinks: list[SymlinkConfig] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)

    # Secrets (never written to disk)
    secrets: SecretConfig = field(default_factory=SecretConfig)

    # Setup commands
    setup: list[str] = field(default_factory=list)

    # Agent context
    context: ContextConfig = field(default_factory=ContextConfig)

    # Metadata
    extends: str | None = None  # Parent template to inherit from
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: Path) -> WorkcellTemplate:
        """Load template from YAML file."""
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Parse nested configs
        secrets_data = data.pop("secrets", {})
        secrets = SecretConfig(
            source=SecretSource(secrets_data.get("source", "env")),
            inject=secrets_data.get("inject", []),
            file_path=secrets_data.get("file_path"),
        )

        symlinks_data = data.pop("symlinks", [])
        symlinks = [
            SymlinkConfig(path=s["path"], target=s["target"]) for s in symlinks_data
        ]

        context_data = data.pop("context", {})
        context = ContextConfig(
            claude_md=context_data.get("claude_md", ""),
            inject_files=context_data.get("inject_files", []),
        )

        return cls(
            secrets=secrets,
            symlinks=symlinks,
            context=context,
            **data,
        )

    def to_yaml(self) -> str:
        """Serialize template to YAML."""
        data = {
            "id": self.id,
            "description": self.description,
            "sparse_checkout": self.sparse_checkout,
            "symlinks": [{"path": s.path, "target": s.target} for s in self.symlinks],
            "exclude_patterns": self.exclude_patterns,
            "secrets": {
                "source": self.secrets.source.value,
                "inject": self.secrets.inject,
            },
            "setup": self.setup,
            "context": {
                "claude_md": self.context.claude_md,
                "inject_files": self.context.inject_files,
            },
            "tags": self.tags,
        }
        if self.extends:
            data["extends"] = self.extends
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


class WorkcellSecretManager:
    """
    Injects secrets into workcell environment without writing to disk.

    Security principles:
    - Secrets are loaded at runtime, not persisted
    - Audit logging for all secret access
    - Secrets are scoped to workcell process tree
    """

    def __init__(self, source: SecretSource = SecretSource.ENV):
        self.source = source

    def load_secrets(self, keys: list[str]) -> dict[str, str]:
        """Load secrets from configured source."""
        if self.source == SecretSource.ENV:
            return self._load_from_env(keys)
        elif self.source == SecretSource.VAULT:
            return self._load_from_vault(keys)
        elif self.source == SecretSource.KEYCHAIN:
            return self._load_from_keychain(keys)
        elif self.source == SecretSource.FILE:
            raise ValueError("File source requires file_path")
        else:
            raise ValueError(f"Unknown secret source: {self.source}")

    def _load_from_env(self, keys: list[str]) -> dict[str, str]:
        """Load secrets from environment variables."""
        secrets = {}
        for key in keys:
            value = os.environ.get(key)
            if value:
                secrets[key] = value
                logger.debug("secret_loaded", key=key, source="env")
            else:
                logger.warning("secret_not_found", key=key, source="env")
        return secrets

    def _load_from_vault(self, keys: list[str]) -> dict[str, str]:
        """Load secrets from HashiCorp Vault (placeholder)."""
        # TODO: Implement Vault integration
        logger.warning("vault_not_implemented", keys=keys)
        return {}

    def _load_from_keychain(self, keys: list[str]) -> dict[str, str]:
        """Load secrets from system keychain (macOS)."""
        secrets = {}
        for key in keys:
            try:
                result = subprocess.run(
                    ["security", "find-generic-password", "-s", key, "-w"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                secrets[key] = result.stdout.strip()
                logger.debug("secret_loaded", key=key, source="keychain")
            except subprocess.CalledProcessError:
                logger.warning("secret_not_found", key=key, source="keychain")
        return secrets

    def inject_to_env(self, secrets: dict[str, str], env: dict[str, str]) -> None:
        """Inject secrets into environment dict (for subprocess)."""
        env.update(secrets)
        logger.info(
            "secrets_injected",
            count=len(secrets),
            keys=list(secrets.keys()),
        )


class TemplateApplicator:
    """
    Applies workcell templates to create scoped workspaces.

    Handles:
    - Sparse checkout configuration
    - Symlink creation
    - Secret injection
    - Setup command execution
    """

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.templates_dir = repo_root / ".cyntra" / "workcell-templates"
        self.secret_manager = WorkcellSecretManager()

    def load_template(self, template_id: str) -> WorkcellTemplate:
        """Load a template by ID."""
        template_path = self.templates_dir / f"{template_id}.yaml"
        if not template_path.exists():
            raise ValueError(f"Template not found: {template_id}")

        template = WorkcellTemplate.from_yaml(template_path)

        # Handle inheritance
        if template.extends:
            parent = self.load_template(template.extends)
            template = self._merge_templates(parent, template)

        return template

    def _merge_templates(
        self, parent: WorkcellTemplate, child: WorkcellTemplate
    ) -> WorkcellTemplate:
        """Merge child template with parent, child overrides parent."""
        return WorkcellTemplate(
            id=child.id,
            description=child.description or parent.description,
            sparse_checkout=child.sparse_checkout or parent.sparse_checkout,
            symlinks=child.symlinks or parent.symlinks,
            exclude_patterns=child.exclude_patterns or parent.exclude_patterns,
            secrets=SecretConfig(
                source=child.secrets.source,
                inject=list(set(parent.secrets.inject + child.secrets.inject)),
            ),
            setup=parent.setup + child.setup,
            context=ContextConfig(
                claude_md=parent.context.claude_md + "\n\n" + child.context.claude_md,
                inject_files=list(
                    set(parent.context.inject_files + child.context.inject_files)
                ),
            ),
            tags=list(set(parent.tags + child.tags)),
        )

    def apply_sparse_checkout(
        self, workcell_path: Path, template: WorkcellTemplate
    ) -> None:
        """Configure sparse checkout for workcell."""
        if not template.sparse_checkout:
            logger.info("sparse_checkout_skipped", reason="no_patterns")
            return

        # Enable sparse checkout
        subprocess.run(
            ["git", "sparse-checkout", "init", "--cone"],
            cwd=workcell_path,
            check=True,
            capture_output=True,
        )

        # Set patterns
        subprocess.run(
            ["git", "sparse-checkout", "set", *template.sparse_checkout],
            cwd=workcell_path,
            check=True,
            capture_output=True,
        )

        logger.info(
            "sparse_checkout_applied",
            patterns=template.sparse_checkout,
            workcell=str(workcell_path),
        )

    def create_symlinks(
        self, workcell_path: Path, template: WorkcellTemplate
    ) -> None:
        """Create symlinks for read-only references."""
        for symlink in template.symlinks:
            # Resolve ${REPO_ROOT} in target
            target = symlink.target.replace("${REPO_ROOT}", str(self.repo_root))
            target_path = Path(target)

            # Create symlink path
            link_path = workcell_path / symlink.path
            link_path.parent.mkdir(parents=True, exist_ok=True)

            # Remove existing (if any)
            if link_path.exists() or link_path.is_symlink():
                link_path.unlink()

            # Create symlink
            link_path.symlink_to(target_path)

            logger.info(
                "symlink_created",
                link=str(link_path),
                target=str(target_path),
            )

    def run_setup(
        self,
        workcell_path: Path,
        template: WorkcellTemplate,
        env: dict[str, str],
    ) -> None:
        """Run setup commands in workcell."""
        for cmd in template.setup:
            logger.info("setup_command", cmd=cmd)
            try:
                subprocess.run(
                    cmd,
                    shell=True,
                    cwd=workcell_path,
                    env=env,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                logger.error(
                    "setup_command_failed",
                    cmd=cmd,
                    returncode=e.returncode,
                    stderr=e.stderr,
                )
                raise

    def apply_template(
        self,
        workcell_path: Path,
        template: WorkcellTemplate,
        *,
        skip_sparse_checkout: bool = False,
    ) -> dict[str, str]:
        """
        Apply template to workcell.

        Returns environment dict with injected secrets.
        """
        logger.info(
            "applying_template",
            template_id=template.id,
            workcell=str(workcell_path),
        )

        # 1. Configure sparse checkout
        if not skip_sparse_checkout:
            self.apply_sparse_checkout(workcell_path, template)

        # 2. Create symlinks
        self.create_symlinks(workcell_path, template)

        # 3. Load secrets (into env, not filesystem)
        self.secret_manager.source = template.secrets.source
        secrets = self.secret_manager.load_secrets(template.secrets.inject)
        env = os.environ.copy()
        self.secret_manager.inject_to_env(secrets, env)

        # 4. Run setup commands
        self.run_setup(workcell_path, template, env)

        # 5. Write context CLAUDE.md if specified
        if template.context.claude_md:
            claude_md_path = workcell_path / "CLAUDE.md"
            if claude_md_path.exists():
                # Append to existing
                with open(claude_md_path, "a", encoding="utf-8") as f:
                    f.write("\n\n# Template Context\n\n")
                    f.write(template.context.claude_md)
            else:
                # Create new
                with open(claude_md_path, "w", encoding="utf-8") as f:
                    f.write(template.context.claude_md)

        logger.info(
            "template_applied",
            template_id=template.id,
            workcell=str(workcell_path),
        )

        return env


# Common setup commands
AGENT_BROWSER_SETUP = (
    "which agent-browser > /dev/null 2>&1 || "
    "(npm install -g agent-browser && agent-browser install)"
)


# Built-in templates for common use cases
BUILTIN_TEMPLATES = {
    "code": WorkcellTemplate(
        id="code",
        description="Code-first monorepo slice (excludes large fab assets)",
        sparse_checkout=[
            "apps/",
            "crates/",
            "docs/",
            "infra/",
            "kernel/",
            "packages/",
            "research/",
            "scripts/",
            "skills/",
            ".github/",
            ".moon/",
            "AGENTS.md",
            "CLAUDE.md",
            "README.md",
            "pyproject.toml",
            "package.json",
            "uv.lock",
        ],
        secrets=SecretConfig(
            source=SecretSource.ENV,
            inject=["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
        ),
        setup=[
            AGENT_BROWSER_SETUP,
        ],
        tags=["code", "monorepo"],
    ),
    "docs": WorkcellTemplate(
        id="docs",
        description="Docs + kernel gates (minimal checkout)",
        sparse_checkout=[
            "docs/",
            "kernel/",
            ".github/",
            ".moon/",
            "AGENTS.md",
            "CLAUDE.md",
            "README.md",
            "OPENCLAW_ARCHITECTURE.md",
            "pyproject.toml",
            "package.json",
            "uv.lock",
        ],
        secrets=SecretConfig(
            source=SecretSource.ENV,
            inject=["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
        ),
        setup=[
            AGENT_BROWSER_SETUP,
        ],
        tags=["docs"],
    ),
    "bench-evolution": WorkcellTemplate(
        id="bench-evolution",
        description="Bench + evolution workflows (minimal checkout)",
        sparse_checkout=[
            "benches/",
            "benchmarks/",
            "kernel/",
            "crates/",
            "docs/",
            "prompts/",
            "research/",
            "scripts/",
            "skills/",
            ".github/",
            ".moon/",
            "AGENTS.md",
            "CLAUDE.md",
            "README.md",
            "pyproject.toml",
            "package.json",
            "uv.lock",
        ],
        secrets=SecretConfig(
            source=SecretSource.ENV,
            inject=["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
        ),
        setup=[
            AGENT_BROWSER_SETUP,
        ],
        tags=["bench", "evolution"],
    ),
    "full": WorkcellTemplate(
        id="full",
        description="Full repository access (default)",
        sparse_checkout=[],  # Empty = full checkout
        secrets=SecretConfig(
            source=SecretSource.ENV,
            inject=["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
        ),
        setup=[
            AGENT_BROWSER_SETUP,  # For canary tests
        ],
    ),
    "kernel-dev": WorkcellTemplate(
        id="kernel-dev",
        description="Kernel development and testing",
        sparse_checkout=[
            "kernel/",
            "crates/",
            "docs/",
            ".cyntra/",
            "pyproject.toml",
            "Cargo.toml",
        ],
        secrets=SecretConfig(
            source=SecretSource.ENV,
            inject=["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
        ),
        setup=[
            "pip install -e kernel/[dev] --quiet",
            AGENT_BROWSER_SETUP,  # For canary tests
        ],
        context=ContextConfig(
            claude_md="""
You are working in the kernel development workcell.
Focus on: kernel/src/cyntra/, crates/

Run tests: pytest kernel/tests/ -v
Type check: mypy kernel/src/cyntra/
""",
        ),
        tags=["kernel", "python", "rust"],
    ),
    "fab-asset": WorkcellTemplate(
        id="fab-asset",
        description="Fab asset generation and quality gating",
        sparse_checkout=[
            "fab/ci/",
            "fab/pipeline/",
            "fab/projects/",
            "fab/scripts/",
            "fab/test/",
            "fab/gates",
            "fab/lookdev",
            "fab/themes",
            "fab/worlds",
            "fab/library/godot/",
            "fab/library/lookdev/",
            "fab/library/meshes/",
            "fab/library/shared/",
            "fab/library/templates/",
            "fab/library/terraform/",
            "kernel/src/cyntra/fab/",
            "docs/",
        ],
        symlinks=[
            SymlinkConfig(
                path="fab/library/assets",
                target="${REPO_ROOT}/fab/library/assets",
            ),
        ],
        secrets=SecretConfig(
            source=SecretSource.ENV,
            inject=["ANTHROPIC_API_KEY", "REPLICATE_API_TOKEN", "RUNPOD_API_KEY"],
        ),
        setup=[
            "pip install -e kernel/[fab] --quiet",
            AGENT_BROWSER_SETUP,  # For visual QA canary tests
        ],
        context=ContextConfig(
            claude_md="""
You are working in a fab asset workcell.
Focus on: fab/gates/, fab/lookdev/, fab/worlds/

Key docs:
- docs/fab-godot-marker-contract.md

Do NOT modify: apps/, crates/, train/
""",
            inject_files=["docs/fab-godot-marker-contract.md"],
        ),
        tags=["fab", "blender", "godot", "3d"],
    ),
    "fab-playtest": WorkcellTemplate(
        id="fab-playtest",
        description="Fab playtest + QA (minimal checkout)",
        sparse_checkout=[
            "fab/ci/",
            "fab/pipeline/",
            "fab/projects/",
            "fab/scripts/",
            "fab/test/",
            "fab/gates",
            "fab/lookdev",
            "fab/themes",
            "fab/worlds",
            "fab/library/godot/",
            "fab/library/lookdev/",
            "fab/library/meshes/",
            "fab/library/shared/",
            "fab/library/templates/",
            "fab/library/terraform/",
            "kernel/",
            "docs/",
            ".github/",
            ".moon/",
            "AGENTS.md",
            "CLAUDE.md",
            "README.md",
            "pyproject.toml",
            "package.json",
            "uv.lock",
        ],
        symlinks=[
            SymlinkConfig(
                path="fab/library/assets",
                target="${REPO_ROOT}/fab/library/assets",
            ),
        ],
        secrets=SecretConfig(
            source=SecretSource.ENV,
            inject=["ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
        ),
        setup=[
            AGENT_BROWSER_SETUP,
        ],
        tags=["fab", "playtest", "qa"],
    ),
    "app-desktop": WorkcellTemplate(
        id="app-desktop",
        description="Desktop app (Mission Control) development",
        sparse_checkout=[
            "apps/desktop/",
            "docs/desktop-*.md",
        ],
        secrets=SecretConfig(
            source=SecretSource.ENV,
            inject=[],  # No secrets needed for frontend
        ),
        setup=[
            "cd apps/desktop && bun install --silent",
            AGENT_BROWSER_SETUP,  # For canary tests
        ],
        context=ContextConfig(
            claude_md="""
You are working on the desktop app (Mission Control).
Tech stack: Tauri 2.0, React, TypeScript, Bun

Dev: bun run tauri dev
Build: bun run tauri build
""",
        ),
        tags=["desktop", "tauri", "react", "typescript"],
    ),
    "app-backbay": WorkcellTemplate(
        id="app-backbay",
        description="Backbay Imperium frontend development",
        sparse_checkout=[
            "apps/backbay/",
            "packages/",
            "docs/backbay-*.md",
            "kernel/canaries/",
        ],
        secrets=SecretConfig(
            source=SecretSource.ENV,
            inject=["ANTHROPIC_API_KEY"],
        ),
        setup=[
            "cd apps/backbay/client/web && bun install --silent",
            AGENT_BROWSER_SETUP,  # For canary tests
        ],
        context=ContextConfig(
            claude_md="""
You are working on Backbay Imperium frontend.
Tech stack: React, TypeScript, Bun, Vite

Dev: cd apps/backbay/client/web && bun dev
Test: cd apps/backbay/client/web && bun test

Key apps:
- Sigil Forge (Baia) - apps/backbay/client/web/src/components/apps/Baia/
- BayChat - apps/backbay/client/web/src/components/apps/BayChat/
- NPC TV - apps/backbay/client/web/src/components/apps/NpcTv/

Canary tests: kernel/canaries/
Run canary: cyntra canary run <name>
""",
        ),
        tags=["backbay", "react", "typescript", "frontend"],
    ),
}
