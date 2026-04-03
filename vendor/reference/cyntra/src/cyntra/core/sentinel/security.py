"""
Security Sentinel - Periodic security scanning.

Responsibilities:
- Scan for secrets in code (API keys, tokens, passwords)
- Detect insecure patterns (SQL injection, command injection, etc.)
- Check for sensitive files that shouldn't be committed
- Detect hardcoded credentials
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
class SecurityConfig:
    """Configuration for SecuritySentinel."""

    # Which checks to run
    check_secrets: bool = True
    check_insecure_patterns: bool = True
    check_sensitive_files: bool = True
    check_hardcoded_credentials: bool = True

    # Directories to scan (relative to repo root)
    scan_directories: list[str] = field(
        default_factory=lambda: ["kernel", "apps", "fab", "crates"]
    )

    # File extensions to scan for secrets/patterns
    code_extensions: list[str] = field(
        default_factory=lambda: [
            ".py", ".js", ".ts", ".tsx", ".jsx", ".rs", ".go",
            ".java", ".rb", ".php", ".sh", ".bash", ".yaml", ".yml",
            ".json", ".toml", ".env", ".ini", ".cfg", ".conf",
        ]
    )

    # Files/patterns to exclude from scanning
    exclude_patterns: list[str] = field(
        default_factory=lambda: [
            "node_modules", ".venv", "venv", "__pycache__",
            ".git", "target", "dist", "build", ".pytest_cache",
            "*.min.js", "*.bundle.js", "package-lock.json",
            "yarn.lock", "Cargo.lock", "poetry.lock",
        ]
    )

    # Sensitive files that shouldn't be committed
    sensitive_file_patterns: list[str] = field(
        default_factory=lambda: [
            ".env", ".env.local", ".env.production",
            "credentials.json", "secrets.yaml", "secrets.yml",
            "*.pem", "*.key", "id_rsa", "id_ed25519",
            ".npmrc", ".pypirc", "token.txt",
        ]
    )

    # Maximum file size to scan (bytes) - skip large files
    max_file_size: int = 1_000_000  # 1MB


class SecuritySentinel(BaseSentinel):
    """
    Periodic security scanning.

    Responsibilities:
    - Scan for secrets in code (API keys, tokens, passwords)
    - Detect insecure patterns (SQL injection, command injection, etc.)
    - Check for sensitive files that shouldn't be committed
    - Detect hardcoded credentials
    """

    # Secret patterns to detect
    SECRET_PATTERNS = [
        # API Keys
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "API key"),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?', "Secret key"),
        # AWS
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?', "AWS Secret Key"),
        # GitHub
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
        (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
        (r'ghu_[a-zA-Z0-9]{36}', "GitHub User Token"),
        (r'ghs_[a-zA-Z0-9]{36}', "GitHub Server Token"),
        # Slack
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', "Slack Token"),
        # Generic tokens
        (r'(?i)(bearer|token|auth)\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?', "Auth token"),
        # Private keys
        (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private key"),
        # Passwords in config
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "Hardcoded password"),
        # Database URLs with credentials
        (r'(?i)(mysql|postgres|postgresql|mongodb|redis)://[^:]+:[^@]+@', "Database URL with credentials"),
        # JWT
        (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT Token"),
    ]

    # Insecure code patterns
    INSECURE_PATTERNS = [
        # SQL Injection
        (r'(?i)execute\s*\(\s*["\'].*%s', "python", "Potential SQL injection (use parameterized queries)"),
        (r'(?i)cursor\.execute\s*\(\s*f["\']', "python", "Potential SQL injection with f-string"),
        (r'(?i)\.query\s*\(\s*`.*\$\{', "javascript", "Potential SQL injection with template literal"),
        # Command Injection
        (r'(?i)os\.system\s*\(', "python", "os.system() - use subprocess with shell=False"),
        (r'(?i)subprocess\.\w+\([^)]*shell\s*=\s*True', "python", "subprocess with shell=True"),
        (r'(?i)eval\s*\(', "python", "eval() usage - potential code injection"),
        (r'(?i)exec\s*\(', "python", "exec() usage - potential code injection"),
        # XSS
        (r'innerHTML\s*=', "javascript", "innerHTML assignment - potential XSS"),
        (r'dangerouslySetInnerHTML', "javascript", "dangerouslySetInnerHTML - potential XSS"),
        (r'document\.write\s*\(', "javascript", "document.write() - potential XSS"),
        # Insecure random
        (r'(?i)random\.random\s*\(', "python", "random.random() for security - use secrets module"),
        (r'Math\.random\s*\(', "javascript", "Math.random() for security - use crypto.getRandomValues"),
        # Hardcoded IPs/hosts (may indicate dev config in prod)
        (r'(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0):\d+', "any", "Hardcoded localhost - may leak in production"),
        # Insecure deserialization
        (r'pickle\.loads?\s*\(', "python", "pickle.load() - insecure deserialization"),
        (r'yaml\.load\s*\([^)]*Loader\s*=\s*None', "python", "yaml.load without safe Loader"),
        (r'yaml\.load\s*\([^)]*\)', "python", "yaml.load() - use yaml.safe_load()"),
        # Weak crypto
        (r'(?i)(md5|sha1)\s*\(', "any", "Weak hash algorithm - use SHA-256 or better"),
        (r'(?i)DES|RC4|Blowfish', "any", "Weak encryption algorithm"),
    ]

    def __init__(
        self,
        config: SentinelConfig | None = None,
        security_config: SecurityConfig | None = None,
        schedule: SentinelSchedule | None = None,
        repo_root: Path | None = None,
    ) -> None:
        super().__init__(config, schedule, repo_root)
        self.security_config = security_config or SecurityConfig()

    @property
    def name(self) -> str:
        return "security"

    @property
    def description(self) -> str:
        return "Security scanning: secrets, insecure patterns, sensitive files"

    async def execute(self) -> None:
        """Run all configured security checks."""
        self._log.info("starting_security_scan")

        if self.security_config.check_sensitive_files:
            await self._check_sensitive_files()

        if self.security_config.check_secrets:
            await self._scan_for_secrets()

        if self.security_config.check_insecure_patterns:
            await self._scan_for_insecure_patterns()

        if self.security_config.check_hardcoded_credentials:
            await self._check_hardcoded_credentials()

        self._log.info("security_scan_complete")

    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned."""
        # Check exclusions
        path_str = str(file_path)
        for pattern in self.security_config.exclude_patterns:
            if pattern.startswith("*"):
                if path_str.endswith(pattern[1:]):
                    return False
            elif pattern in path_str:
                return False

        # Check extension
        if file_path.suffix not in self.security_config.code_extensions:
            return False

        # Check file size
        try:
            if file_path.stat().st_size > self.security_config.max_file_size:
                return False
        except OSError:
            return False

        return True

    def _get_files_to_scan(self) -> list[Path]:
        """Get list of files to scan."""
        files = []
        for scan_dir in self.security_config.scan_directories:
            dir_path = self.repo_root / scan_dir
            if not dir_path.exists():
                continue

            for file_path in dir_path.rglob("*"):
                if file_path.is_file() and self._should_scan_file(file_path):
                    files.append(file_path)

        return files

    async def _check_sensitive_files(self) -> None:
        """Check for sensitive files that shouldn't be committed."""
        import fnmatch

        found_sensitive: list[tuple[str, str]] = []

        for scan_dir in self.security_config.scan_directories:
            dir_path = self.repo_root / scan_dir
            if not dir_path.exists():
                continue

            for file_path in dir_path.rglob("*"):
                if not file_path.is_file():
                    continue

                # Check exclusions
                path_str = str(file_path)
                skip = False
                for pattern in self.security_config.exclude_patterns:
                    if pattern in path_str:
                        skip = True
                        break
                if skip:
                    continue

                # Check against sensitive patterns
                file_name = file_path.name
                for pattern in self.security_config.sensitive_file_patterns:
                    if fnmatch.fnmatch(file_name, pattern):
                        rel_path = file_path.relative_to(self.repo_root)
                        found_sensitive.append((str(rel_path), pattern))
                        break

        if found_sensitive:
            self._log.warning("sensitive_files_found", count=len(found_sensitive))
            for file_path, pattern in found_sensitive[:5]:
                self.propose_change(
                    change_type="sensitive_file",
                    target=f"file:{file_path}",
                    description=(
                        f"Sensitive file '{file_path}' matches pattern '{pattern}' - "
                        f"should be in .gitignore"
                    ),
                )

    async def _scan_for_secrets(self) -> None:
        """Scan code files for secrets."""
        import re

        secrets_found: list[tuple[str, int, str, str]] = []
        files = self._get_files_to_scan()

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                # Skip comments and empty lines
                stripped = line.strip()
                if not stripped or stripped.startswith('#') or stripped.startswith('//'):
                    continue

                for pattern, secret_type in self.SECRET_PATTERNS:
                    if re.search(pattern, line):
                        rel_path = file_path.relative_to(self.repo_root)
                        # Truncate the line for display
                        display_line = line[:80] + "..." if len(line) > 80 else line
                        secrets_found.append(
                            (str(rel_path), line_num, secret_type, display_line.strip())
                        )
                        break  # One match per line is enough

        if secrets_found:
            self._log.warning("secrets_found", count=len(secrets_found))
            for file_path, line_num, secret_type, _ in secrets_found[:5]:
                self.propose_change(
                    change_type="secret_detected",
                    target=f"file:{file_path}:{line_num}",
                    description=(
                        f"Potential {secret_type} found in '{file_path}' at line {line_num}"
                    ),
                )

    async def _scan_for_insecure_patterns(self) -> None:
        """Scan for insecure code patterns."""
        import re

        issues_found: list[tuple[str, int, str, str]] = []
        files = self._get_files_to_scan()

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            # Determine file type
            ext = file_path.suffix.lower()
            if ext in (".py",):
                file_type = "python"
            elif ext in (".js", ".ts", ".jsx", ".tsx"):
                file_type = "javascript"
            else:
                file_type = "any"

            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith('#') or stripped.startswith('//'):
                    continue

                for pattern, lang, description in self.INSECURE_PATTERNS:
                    # Check if pattern applies to this file type
                    if lang not in ("any", file_type):
                        continue

                    if re.search(pattern, line):
                        rel_path = file_path.relative_to(self.repo_root)
                        issues_found.append(
                            (str(rel_path), line_num, description, line.strip()[:60])
                        )
                        break  # One match per line

        if issues_found:
            self._log.warning("insecure_patterns_found", count=len(issues_found))
            for file_path, line_num, description, _ in issues_found[:5]:
                self.propose_change(
                    change_type="insecure_pattern",
                    target=f"file:{file_path}:{line_num}",
                    description=(
                        f"Insecure pattern in '{file_path}' line {line_num}: {description}"
                    ),
                )

    async def _check_hardcoded_credentials(self) -> None:
        """Check for hardcoded credentials in config files."""
        import re

        # Patterns for credential-like assignments
        credential_patterns = [
            (r'(?i)(password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*["\'][^"\']+["\']',
             "Hardcoded credential"),
            (r'(?i)(username|user|login)\s*[=:]\s*["\'][^"\']+["\'].*'
             r'(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']',
             "Username and password pair"),
        ]

        # Config file extensions
        config_extensions = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env"}

        issues_found: list[tuple[str, int, str]] = []

        for scan_dir in self.security_config.scan_directories:
            dir_path = self.repo_root / scan_dir
            if not dir_path.exists():
                continue

            for file_path in dir_path.rglob("*"):
                if not file_path.is_file():
                    continue

                if file_path.suffix.lower() not in config_extensions:
                    continue

                # Skip excluded
                path_str = str(file_path)
                skip = False
                for pattern in self.security_config.exclude_patterns:
                    if pattern in path_str:
                        skip = True
                        break
                if skip:
                    continue

                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                lines = content.split('\n')
                for line_num, line in enumerate(lines, 1):
                    # Skip lines that look like examples or templates
                    if any(x in line.lower() for x in ["example", "changeme", "xxx", "your_"]):
                        continue

                    for pattern, desc in credential_patterns:
                        if re.search(pattern, line):
                            rel_path = file_path.relative_to(self.repo_root)
                            issues_found.append((str(rel_path), line_num, desc))
                            break

        if issues_found:
            self._log.warning("hardcoded_credentials_found", count=len(issues_found))
            for file_path, line_num, desc in issues_found[:5]:
                    self.propose_change(
                        change_type="hardcoded_credential",
                        target=f"file:{file_path}:{line_num}",
                        description=(
                            f"{desc} in '{file_path}' at line {line_num} - "
                            f"use environment variables instead"
                        ),
                    )


__all__ = [
    "SecurityConfig",
    "SecuritySentinel",
]
