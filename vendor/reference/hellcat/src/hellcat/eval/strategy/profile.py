"""
Strategy Profile - Compact representation of model reasoning approach.

A StrategyProfile captures how a model reasoned during task execution,
represented as values across strategy dimensions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from hellcat.eval.strategy.rubric import HELLCAT_V1_RUBRIC, StrategyRubric


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass
class DimensionValue:
    """
    Value for a single dimension in a strategy profile.

    Attributes:
        value: The pattern value (e.g., "top_down", "bottom_up")
        confidence: Confidence in this classification (0.0-1.0)
        evidence: Optional evidence/reason for this classification
    """

    value: str
    confidence: float = 0.5
    evidence: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("Dimension value must be a non-empty string")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0 and 1: {self.confidence}")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "value": self.value,
            "confidence": self.confidence,
        }
        if self.evidence:
            result["evidence"] = self.evidence
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DimensionValue:
        return cls(
            value=data["value"],
            confidence=data.get("confidence", 0.5),
            evidence=data.get("evidence"),
        )


@dataclass
class StrategyProfile:
    """
    Complete strategy profile for a single execution.

    Captures the reasoning strategy used by a model across all dimensions
    defined in a rubric.

    Attributes:
        rubric_version: Version of the rubric used
        dimensions: Mapping of dimension ID to DimensionValue
        workcell_id: Associated workcell (optional)
        issue_id: Associated issue (optional)
        model: Model identifier (optional)
        toolchain: Toolchain used (optional)
        extraction_method: How profile was extracted (self_report, llm_analysis, classifier)
        extracted_at: ISO timestamp of extraction
        notes: Optional notes about the profile
    """

    rubric_version: str
    dimensions: dict[str, DimensionValue]
    workcell_id: str | None = None
    issue_id: str | None = None
    model: str | None = None
    toolchain: str | None = None
    extraction_method: str = "unknown"
    extracted_at: str = field(default_factory=_utc_now)
    notes: str | None = None

    def __post_init__(self) -> None:
        if not self.rubric_version:
            raise ValueError("Rubric version is required")
        if not isinstance(self.dimensions, dict):
            raise ValueError("Dimensions must be a dictionary")
        # Validate extraction method
        valid_methods = {"self_report", "llm_analysis", "classifier", "heuristic", "unknown"}
        if self.extraction_method not in valid_methods:
            raise ValueError(f"Invalid extraction method: {self.extraction_method}")

    def __getitem__(self, key: str) -> DimensionValue:
        return self.dimensions[key]

    def __contains__(self, key: str) -> bool:
        return key in self.dimensions

    def get(self, key: str, default: DimensionValue | None = None) -> DimensionValue | None:
        return self.dimensions.get(key, default)

    def dimension_ids(self) -> list[str]:
        return list(self.dimensions.keys())

    def pattern_for(self, dimension_id: str) -> str | None:
        dv = self.dimensions.get(dimension_id)
        return dv.value if dv else None

    def confidence_for(self, dimension_id: str) -> float:
        dv = self.dimensions.get(dimension_id)
        return dv.confidence if dv else 0.0

    def average_confidence(self) -> float:
        if not self.dimensions:
            return 0.0
        return sum(dv.confidence for dv in self.dimensions.values()) / len(self.dimensions)

    def low_confidence_dimensions(self, threshold: float = 0.5) -> list[str]:
        return [
            dim_id
            for dim_id, dv in self.dimensions.items()
            if dv.confidence < threshold
        ]

    def to_compact_string(self) -> str:
        """
        Convert to a compact one-line string for logging.

        Example: "top_down, local, deductive, linear, continuous, proactive, ..."
        """
        return ", ".join(dv.value for dv in self.dimensions.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "hellcat.strategy_profile.v1",
            "rubric_version": self.rubric_version,
            "workcell_id": self.workcell_id,
            "issue_id": self.issue_id,
            "model": self.model,
            "toolchain": self.toolchain,
            "extraction_method": self.extraction_method,
            "extracted_at": self.extracted_at,
            "average_confidence": self.average_confidence() if self.dimensions else None,
            "notes": self.notes,
            "profile": {
                dim_id: dv.to_dict()
                for dim_id, dv in self.dimensions.items()
            },
        }

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategyProfile:
        profile_data = data.get("profile", {})
        dimensions = {
            dim_id: DimensionValue.from_dict(dv)
            for dim_id, dv in profile_data.items()
        }
        return cls(
            rubric_version=data["rubric_version"],
            dimensions=dimensions,
            workcell_id=data.get("workcell_id"),
            issue_id=data.get("issue_id"),
            model=data.get("model"),
            toolchain=data.get("toolchain"),
            extraction_method=data.get("extraction_method", "unknown"),
            extracted_at=data.get("extracted_at", _utc_now()),
            notes=data.get("notes"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> StrategyProfile:
        return cls.from_dict(json.loads(json_str))

    def validate_against_rubric(self, rubric: StrategyRubric | None = None) -> list[str]:
        """
        Validate profile against a rubric.

        Returns list of validation errors (empty if valid).
        """
        if rubric is None:
            if self.rubric_version == "hellcat-v1":
                rubric = HELLCAT_V1_RUBRIC
            else:
                return [f"Unknown rubric version: {self.rubric_version}"]

        errors: list[str] = []

        # Check rubric version matches
        if rubric.version != self.rubric_version:
            errors.append(
                f"Rubric version mismatch: profile={self.rubric_version}, rubric={rubric.version}"
            )

        # Check all dimensions are valid
        for dim_id, dv in self.dimensions.items():
            dim = rubric.get(dim_id)
            if dim is None:
                errors.append(f"Unknown dimension: {dim_id}")
                continue
            if not dim.is_valid_pattern(dv.value):
                errors.append(
                    f"Invalid pattern for {dim_id}: {dv.value} "
                    f"(expected {dim.pattern_a} or {dim.pattern_b})"
                )

        # Check for missing dimensions (warning, not error)
        # Profiles can have partial dimensions

        return errors

    def compare(self, other: StrategyProfile) -> dict[str, Any]:
        """
        Compare this profile to another.

        Returns comparison metrics.
        """
        if self.rubric_version != other.rubric_version:
            return {
                "compatible": False,
                "error": "Different rubric versions",
            }

        # Find common dimensions
        common_dims = set(self.dimensions.keys()) & set(other.dimensions.keys())
        if not common_dims:
            return {
                "compatible": True,
                "common_dimensions": 0,
                "agreement_rate": 0.0,
                "agreements": [],
                "disagreements": [],
            }

        agreements = []
        disagreements = []

        for dim_id in common_dims:
            self_val = self.dimensions[dim_id].value
            other_val = other.dimensions[dim_id].value
            if self_val == other_val:
                agreements.append(dim_id)
            else:
                disagreements.append({
                    "dimension": dim_id,
                    "self": self_val,
                    "other": other_val,
                })

        return {
            "compatible": True,
            "common_dimensions": len(common_dims),
            "agreement_rate": len(agreements) / len(common_dims),
            "agreements": agreements,
            "disagreements": disagreements,
        }

    @classmethod
    def create_empty(
        cls,
        rubric_version: str = "hellcat-v1",
        workcell_id: str | None = None,
        issue_id: str | None = None,
    ) -> StrategyProfile:
        return cls(
            rubric_version=rubric_version,
            dimensions={},
            workcell_id=workcell_id,
            issue_id=issue_id,
            extraction_method="unknown",
        )

    @classmethod
    def from_pattern_string(
        cls,
        pattern_string: str,
        rubric: StrategyRubric | None = None,
        confidence: float = 0.5,
        **kwargs: Any,
    ) -> StrategyProfile:
        """
        Create profile from a comma-separated pattern string.

        Example: "top_down, local, deductive, linear"

        Patterns are matched to dimensions in order.
        """
        if rubric is None:
            rubric = HELLCAT_V1_RUBRIC

        patterns = [p.strip().lower().replace("-", "_") for p in pattern_string.split(",")]
        dimensions: dict[str, DimensionValue] = {}

        for i, pattern in enumerate(patterns):
            if i >= len(rubric.dimensions):
                break

            dim = rubric.dimensions[i]

            # Match pattern to dimension
            if pattern == dim.pattern_a.lower().replace("-", "_"):
                dimensions[dim.id] = DimensionValue(value=dim.pattern_a, confidence=confidence)
            elif pattern == dim.pattern_b.lower().replace("-", "_"):
                dimensions[dim.id] = DimensionValue(value=dim.pattern_b, confidence=confidence)
            else:
                # Try fuzzy matching
                pattern_clean = pattern.replace("_", "")
                if pattern_clean in dim.pattern_a.lower().replace("_", ""):
                    dimensions[dim.id] = DimensionValue(
                        value=dim.pattern_a, confidence=confidence * 0.8
                    )
                elif pattern_clean in dim.pattern_b.lower().replace("_", ""):
                    dimensions[dim.id] = DimensionValue(
                        value=dim.pattern_b, confidence=confidence * 0.8
                    )
                # If no match, skip this dimension

        return cls(
            rubric_version=rubric.version,
            dimensions=dimensions,
            extraction_method="self_report",
            **kwargs,
        )
