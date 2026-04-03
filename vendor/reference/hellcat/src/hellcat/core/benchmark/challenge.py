"""
Challenge and ChallengeSuite - Benchmark challenge definitions.

A Challenge represents a single known vulnerability to test against.
A ChallengeSuite groups challenges into a named, versioned set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class Category(StrEnum):
    """Vulnerability category for benchmark challenges."""

    SQLI = "sqli"
    XSS = "xss"
    AUTH = "auth"
    AUTHZ = "authz"
    SSRF = "ssrf"
    IDOR = "idor"
    LFI = "lfi"
    XXE = "xxe"
    RCE = "rce"
    CRYPTO = "crypto"
    MISCONFIGURATION = "misconfiguration"
    OTHER = "other"


class Difficulty(StrEnum):
    """Challenge difficulty level."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


@dataclass
class Challenge:
    """A single benchmark challenge representing a known vulnerability.

    Attributes:
        id: Unique challenge identifier.
        name: Human-readable name.
        category: Vulnerability category (sqli, xss, auth, etc.).
        difficulty: Difficulty level (easy, medium, hard).
        target_path: URL path relative to the target base URL.
        description: What the vulnerability is.
        success_criteria: What constitutes a successful "solve".
        expected_proof_level: Minimum proof level required (L1-L4).
        hints: Optional hints for the attacker.
        points: Score value for this challenge.
    """

    id: str
    name: str
    category: str
    difficulty: str
    target_path: str
    description: str
    success_criteria: str
    expected_proof_level: str = "L2"
    hints: list[str] = field(default_factory=list)
    points: int = 10


@dataclass
class ChallengeSuite:
    """A named, versioned collection of benchmark challenges.

    Attributes:
        name: Suite name (e.g., "juice-shop").
        version: Suite version string.
        challenges: List of Challenge instances.
        metadata: Additional metadata about the suite.
    """

    name: str
    version: str
    challenges: list[Challenge]
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ChallengeSuite:
        """Load a ChallengeSuite from a YAML file.

        Args:
            path: Path to the YAML file.

        Returns:
            ChallengeSuite instance.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            ValueError: If the YAML is malformed.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Suite file not found: {path}")

        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise ValueError(f"Suite file must be a YAML mapping, got {type(raw).__name__}")

        challenges_raw = raw.get("challenges", [])
        if not isinstance(challenges_raw, list):
            raise ValueError("'challenges' must be a list")

        challenges = []
        for i, c in enumerate(challenges_raw):
            if not isinstance(c, dict):
                raise ValueError(f"Challenge {i} must be a mapping")
            if "id" not in c:
                raise ValueError(f"Challenge {i} missing required field 'id'")
            if "name" not in c:
                raise ValueError(f"Challenge {i} missing required field 'name'")

            challenges.append(Challenge(
                id=c["id"],
                name=c["name"],
                category=c.get("category", "other"),
                difficulty=c.get("difficulty", "medium"),
                target_path=c.get("target_path", "/"),
                description=c.get("description", ""),
                success_criteria=c.get("success_criteria", ""),
                expected_proof_level=c.get("expected_proof_level", "L2"),
                hints=c.get("hints", []),
                points=c.get("points", 10),
            ))

        return cls(
            name=raw.get("name", path.stem),
            version=raw.get("version", "1.0"),
            challenges=challenges,
            metadata=raw.get("metadata", {}),
        )

    def get_by_category(self, category: str) -> list[Challenge]:
        """Get all challenges in a given category."""
        return [c for c in self.challenges if c.category == category]

    def get_by_difficulty(self, difficulty: str) -> list[Challenge]:
        """Get all challenges at a given difficulty level."""
        return [c for c in self.challenges if c.difficulty == difficulty]

    @property
    def categories(self) -> list[str]:
        """Unique categories in this suite."""
        return sorted({c.category for c in self.challenges})

    @property
    def total_points(self) -> int:
        """Total points available in this suite."""
        return sum(c.points for c in self.challenges)
